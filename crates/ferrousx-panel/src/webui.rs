//! crates/ferrousx-panel/src/webui.rs
//! Máy chủ Giao diện Quản trị Web Nội bộ (Embedded Zero-Dependency Rust Web Dashboard) đã gia cố bảo mật:
//!   - Bắt buộc xác thực Bearer Token / `X-FerrousX-Token` (so sánh thời gian hằng số với `/etc/ferrousx/admin.token`)
//!   - Chống Brute-Force theo IP với cơ chế khóa tạm thời
//!   - Kiểm tra `Origin` / CSRF trên mọi thao tác thay đổi trạng thái (`POST /api/reload`)
//!   - Đính kèm đầy đủ Security Headers (`Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`)
//!   - Không rò rỉ đường dẫn hệ thống nội bộ khi chưa xác thực

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use ferrousx_config::config::{ConfigManager, ServerConfig};
use ferrousx_core::metrics::EngineRuntimeStats;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use crate::api::{constant_time_eq, load_or_init_admin_token, read_current_admin_token};

/// Giao diện HTML/CSS/JS Tích hợp sẵn (Single-Binary Embedded WebUI) có hỗ trợ nhập Admin Token bảo mật
const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FerrousX Control Plane — Pure Rust Dashboard</title>
    <style>
        :root { --bg: #090d16; --card: #111827; --border: #1f2937; --accent: #10b981; --text: #f3f4f6; --muted: #9ca3af; }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: system-ui, -apple-system, monospace; }
        body { background: var(--bg); color: var(--text); padding: 2rem; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 1rem; margin-bottom: 1.5rem; flex-wrap: wrap; gap: 1rem; }
        .badge { background: rgba(16, 185, 129, 0.15); color: var(--accent); border: 1px solid var(--accent); padding: 0.25rem 0.75rem; border-radius: 4px; font-size: 0.85rem; }
        .auth-bar { display: flex; gap: 0.5rem; align-items: center; }
        .auth-input { background: #1f2937; color: var(--text); border: 1px solid #374151; padding: 0.5rem 0.75rem; border-radius: 4px; width: 260px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1.25rem; margin-bottom: 2rem; }
        .card { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 1.25rem; }
        .card h3 { color: var(--muted); font-size: 0.8rem; text-transform: uppercase; margin-bottom: 0.5rem; }
        .card .val { font-size: 1.6rem; font-weight: 700; color: var(--accent); }
        .btn { background: var(--accent); color: #000; border: none; padding: 0.6rem 1.2rem; border-radius: 4px; font-weight: 700; cursor: pointer; }
        .btn:hover { opacity: 0.9; }
        pre { background: var(--card); border: 1px solid var(--border); padding: 1rem; border-radius: 6px; overflow-x: auto; color: #cbd5e1; }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>FerrousX Native Rust Engine</h1>
            <p style="color: var(--muted); font-size: 0.9rem;">Hardened Zero-Allocation HTTP/1.1 + HTTP/2 + HTTP/3 QUIC + WAF</p>
        </div>
        <div class="auth-bar">
            <input id="admin-token" class="auth-input" type="password" placeholder="Nhập /etc/ferrousx/admin.token" />
            <button class="btn" onclick="refreshStatus()">Xác thực</button>
            <button class="btn" onclick="triggerReload()">⚡ Hot-Reload (RCU)</button>
            <span class="badge" id="auth-state">LOCKED</span>
        </div>
    </div>
    <div class="grid">
        <div class="card"><h3>RCU Config Epoch</h3><div class="val" id="epoch">-</div></div>
        <div class="card"><h3>Active Conns / Requests</h3><div class="val" id="reqs">-</div></div>
        <div class="card"><h3>PHP-FPM / Static / H3</h3><div class="val" id="mix">-</div></div>
        <div class="card"><h3>WAF &amp; Rate-Limit Drops</h3><div class="val" id="waf">-</div></div>
    </div>
    <h3 style="margin-bottom: 0.75rem; color: var(--muted);">TRẠNG THÁI &amp; METRICS THỜI GIAN THỰC:</h3>
    <pre id="raw-json">Vui lòng nhập Admin Token từ /etc/ferrousx/admin.token để truy vấn dữ liệu...</pre>
    <script>
        function getHeaders() {
            const tok = document.getElementById('admin-token').value.trim();
            return tok ? { 'X-FerrousX-Token': tok } : {};
        }
        async function refreshStatus() {
            try {
                const res = await fetch('/api/status', { headers: getHeaders() });
                const data = await res.json();
                if (!res.ok) {
                    document.getElementById('auth-state').innerText = 'UNAUTHORIZED';
                    document.getElementById('raw-json').innerText = JSON.stringify(data, null, 2);
                    return;
                }
                document.getElementById('auth-state').innerText = 'VERIFIED';
                document.getElementById('epoch').innerText = 'v' + data.epoch + ' (' + data.vhosts_count + ' sites)';
                document.getElementById('reqs').innerText = data.active_connections + ' / ' + data.total_requests;
                document.getElementById('mix').innerText = data.php_fpm_requests + ' / ' + data.static_requests + ' / ' + data.http3_requests;
                document.getElementById('waf').innerText = data.waf_blocked + ' / ' + data.rate_limited;
                document.getElementById('raw-json').innerText = JSON.stringify(data, null, 2);
            } catch (e) {}
        }
        async function triggerReload() {
            await fetch('/api/reload', { method: 'POST', headers: getHeaders() });
            await refreshStatus();
        }
    </script>
</body>
</html>"#;

struct WebUiBruteForceTracker {
    attempts: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    max_attempts: u32,
    lockout_dur: Duration,
}

impl WebUiBruteForceTracker {
    fn new(max_attempts: u32, lockout_secs: u64) -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            max_attempts: max_attempts.max(3),
            lockout_dur: Duration::from_secs(lockout_secs.max(30)),
        }
    }

    fn is_locked(&self, ip: IpAddr) -> bool {
        let Ok(mut map) = self.attempts.lock() else {
            return false;
        };
        if let Some((cnt, ts)) = map.get(&ip) {
            if *cnt >= self.max_attempts {
                if ts.elapsed() < self.lockout_dur {
                    return true;
                }
                map.remove(&ip);
            }
        }
        false
    }

    fn record_fail(&self, ip: IpAddr) {
        if let Ok(mut map) = self.attempts.lock() {
            let entry = map.entry(ip).or_insert((0, Instant::now()));
            entry.0 = entry.0.saturating_add(1);
            entry.1 = Instant::now();
        }
    }

    fn record_ok(&self, ip: IpAddr) {
        if let Ok(mut map) = self.attempts.lock() {
            map.remove(&ip);
        }
    }
}

/// Khởi chạy máy chủ HTTP nội bộ phục vụ Web Dashboard của FerrousX
pub async fn start_embedded_webui_server(
    bind_addr: &str,
    config_mgr: Arc<ConfigManager>,
    stats: Arc<EngineRuntimeStats>,
    on_reload: Arc<dyn Fn(&ServerConfig) + Send + Sync>,
) -> Result<()> {
    let addr: SocketAddr = bind_addr.parse()?;
    if !addr.ip().is_loopback() {
        warn!(
            %addr,
            "Embedded WebUI đang bind ngoài Loopback; khuyến nghị đặt dashboard_bind_addr = \"127.0.0.1:9090\" hoặc chặn port bằng tường lửa"
        );
    }
    let listener = TcpListener::bind(addr).await?;

    let cfg = config_mgr.current();
    let admin_token = Arc::new(
        load_or_init_admin_token(&cfg.admin_security.token_file_path)
            .unwrap_or_else(|_| String::new()),
    );
    let tracker = Arc::new(WebUiBruteForceTracker::new(
        cfg.admin_security.max_failed_attempts,
        cfg.admin_security.brute_force_lockout_secs,
    ));

    info!(
        %addr,
        "Embedded Rust WebUI Dashboard đã sẵn sàng tại http://{} (Yêu cầu xác thực Admin Token)",
        addr
    );

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let mgr = Arc::clone(&config_mgr);
                let tok = Arc::clone(&admin_token);
                let trk = Arc::clone(&tracker);
                let st = Arc::clone(&stats);
                let rel = Arc::clone(&on_reload);
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_webui_client(stream, peer_addr.ip(), mgr, tok, trk, st, rel).await
                    {
                        error!(error = %e, "Lỗi xử lý kết nối WebUI");
                    }
                });
            }
            Err(e) => error!(error = %e, "Lỗi accept kết nối WebUI"),
        }
    }
}

/// Trích xuất Token từ header `X-FerrousX-Token` hoặc `Authorization: Bearer <token>`
fn extract_token_from_headers(req_text: &str) -> Option<String> {
    for line in req_text.lines().skip(1) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim();
            let val = v.trim();
            if key.eq_ignore_ascii_case("x-ferrousx-token") && !val.is_empty() {
                return Some(val.to_string());
            }
            if key.eq_ignore_ascii_case("authorization") {
                if let Some(bearer) = val
                    .strip_prefix("Bearer ")
                    .or_else(|| val.strip_prefix("bearer "))
                {
                    if !bearer.trim().is_empty() {
                        return Some(bearer.trim().to_string());
                    }
                }
            }
        }
    }
    None
}

/// Kiểm tra Origin header chống CSRF khi gọi API thay đổi trạng thái (`POST /api/reload`)
fn verify_origin_allowed(req_text: &str, allowed_origins: &[String]) -> bool {
    for line in req_text.lines().skip(1) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            if k.trim().eq_ignore_ascii_case("origin") {
                let origin = v.trim();
                return allowed_origins
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(origin));
            }
        }
    }
    // Cho phép CLI cục bộ (curl trên 127.0.0.1) không gửi Origin header nhưng có gửi đúng Admin Token
    true
}

/// Đọc trọn vẹn phần header HTTP tới `\r\n\r\n` với giới hạn 16 KiB và timeout 5s
async fn read_webui_http_headers(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 2048];
    let res = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                return Some(String::from_utf8_lossy(&buf[..pos + 4]).to_string());
            }
            if buf.len() >= 16 * 1024 {
                return None;
            }
            let n = stream.read(&mut tmp).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&tmp[..n]);
        }
    })
    .await;
    res.ok().flatten()
}

fn route_authenticated_webui_request(
    method: &str,
    path: &str,
    req_str: &str,
    config_mgr: &ConfigManager,
    stats: &EngineRuntimeStats,
    on_reload: &dyn Fn(&ServerConfig),
) -> (&'static str, Option<&'static str>, &'static str, String) {
    let cfg = config_mgr.current();
    match (method, path) {
        ("GET", "/api/status") => {
            let vhosts: Vec<String> = cfg.vhosts.iter().map(|v| v.server_name.clone()).collect();
            let snap = stats.snapshot();
            let json = serde_json::json!({
                "status": "online",
                "engine": "FerrousX Hardened Native Rust",
                "epoch": cfg.version_epoch,
                "workers": snap.active_workers,
                "bind_http_addr": cfg.bind_http_addr,
                "bind_https_addr": cfg.bind_https_addr,
                "bind_udp_addr": cfg.bind_udp_addr,
                "quic_enabled": cfg.enable_http3_quic,
                "waf_enabled": cfg.waf.enabled,
                "waf_mode": format!("{:?}", cfg.waf.mode),
                "vhosts_count": cfg.vhosts.len(),
                "upstreams_count": cfg.upstreams.len(),
                "vhosts": vhosts,
                "uptime_secs": snap.uptime_secs,
                "total_requests": snap.total_requests,
                "active_connections": snap.active_connections,
                "waf_blocked": snap.waf_blocked,
                "rate_limited": snap.rate_limited,
                "upstream_errors": snap.upstream_errors,
                "php_fpm_requests": snap.php_fpm_requests,
                "static_requests": snap.static_requests,
                "http3_requests": snap.http3_requests,
                "bytes_sent": snap.bytes_sent,
                "xdp_passed_clean": snap.xdp_passed_clean,
                "xdp_dropped_ddos": snap.xdp_dropped_ddos,
            });
            ("200 OK", None, "application/json; charset=utf-8", json.to_string())
        }
        (_, "/api/status") => (
            "405 Method Not Allowed",
            Some("GET"),
            "application/json; charset=utf-8",
            r#"{"success":false,"error":"Method Not Allowed"}"#.to_string(),
        ),
        ("POST", "/api/reload") => {
            if !verify_origin_allowed(req_str, &cfg.admin_security.cors_allowed_origins) {
                (
                    "403 Forbidden",
                    None,
                    "application/json; charset=utf-8",
                    r#"{"success":false,"message":"403 Forbidden: Origin Rejected by CSRF/CORS Policy"}"#
                        .to_string(),
                )
            } else {
                match config_mgr.reload_from_disk() {
                    Ok(new_epoch) => {
                        on_reload(&config_mgr.current());
                        let json = serde_json::json!({
                            "success": true,
                            "message": format!("Hot-Reload RCU + SNI thành công! Epoch hiện tại: v{new_epoch}"),
                            "epoch": new_epoch
                        });
                        ("200 OK", None, "application/json; charset=utf-8", json.to_string())
                    }
                    Err(e) => {
                        warn!(error = %e, "WebUI Reload thất bại");
                        let json = serde_json::json!({
                            "success": false,
                            "message": "Không thể nạp cấu hình mới (vui lòng kiểm tra nhật ký hệ thống)"
                        });
                        (
                            "400 Bad Request",
                            None,
                            "application/json; charset=utf-8",
                            json.to_string(),
                        )
                    }
                }
            }
        }
        (_, "/api/reload") => (
            "405 Method Not Allowed",
            Some("POST"),
            "application/json; charset=utf-8",
            r#"{"success":false,"error":"Method Not Allowed"}"#.to_string(),
        ),
        _ => (
            "404 Not Found",
            None,
            "application/json; charset=utf-8",
            r#"{"error":"Not Found"}"#.to_string(),
        ),
    }
}

async fn handle_webui_client(
    mut stream: TcpStream,
    peer_ip: IpAddr,
    config_mgr: Arc<ConfigManager>,
    fallback_token: Arc<String>,
    tracker: Arc<WebUiBruteForceTracker>,
    stats: Arc<EngineRuntimeStats>,
    on_reload: Arc<dyn Fn(&ServerConfig) + Send + Sync>,
) -> Result<()> {
    let Some(req_str) = read_webui_http_headers(&mut stream).await else {
        return Ok(());
    };

    let first_line = req_str.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let Some(method) = parts.next() else {
        return Ok(());
    };
    let Some(raw_target) = parts.next() else {
        return Ok(());
    };
    let path = raw_target.split('?').next().unwrap_or("/");

    // Trang HTML khung giao diện tĩnh (không chứa dữ liệu nhạy cảm cho tới khi nhập Token)
    if path == "/" || path == "/index.html" {
        if method == "GET" || method == "HEAD" {
            let body = if method == "HEAD" {
                &[][..]
            } else {
                DASHBOARD_HTML.as_bytes()
            };
            write_secure_response(
                &mut stream,
                "200 OK",
                None,
                "text/html; charset=utf-8",
                body,
                Some(DASHBOARD_HTML.len()),
            )
            .await?;
        } else {
            write_secure_response(
                &mut stream,
                "405 Method Not Allowed",
                Some("GET, HEAD"),
                "application/json; charset=utf-8",
                br#"{"success":false,"error":"Method Not Allowed"}"#,
                None,
            )
            .await?;
        }
        return Ok(());
    }

    // Mọi endpoint `/api/*` và route khác đều bắt buộc kiểm tra Brute-Force Lockout & Admin Token
    if tracker.is_locked(peer_ip) {
        let body = br#"{"success":false,"error":"429 Too Many Requests: IP Locked Out"}"#;
        write_secure_response(
            &mut stream,
            "429 Too Many Requests",
            None,
            "application/json; charset=utf-8",
            body,
            None,
        )
        .await?;
        return Ok(());
    }

    let cfg = config_mgr.current();
    let expected_token =
        read_current_admin_token(&cfg.admin_security.token_file_path, &fallback_token);
    let provided = extract_token_from_headers(&req_str);
    let is_authenticated = match provided {
        Some(ref tok) if !expected_token.is_empty() => {
            constant_time_eq(tok.as_bytes(), expected_token.as_bytes())
        }
        _ => false,
    };

    if !is_authenticated {
        tracker.record_fail(peer_ip);
        warn!(%peer_ip, path, "Chặn truy cập API WebUI không có Admin Token hợp lệ");
        let body = br#"{"success":false,"error":"401 Unauthorized: Missing or Invalid X-FerrousX-Token"}"#;
        write_secure_response(
            &mut stream,
            "401 Unauthorized",
            None,
            "application/json; charset=utf-8",
            body,
            None,
        )
        .await?;
        return Ok(());
    }
    tracker.record_ok(peer_ip);

    let (status_line, allow_hdr, content_type, body) =
        route_authenticated_webui_request(method, path, &req_str, &config_mgr, &stats, &*on_reload);

    write_secure_response(
        &mut stream,
        status_line,
        allow_hdr,
        content_type,
        body.as_bytes(),
        None,
    )
    .await?;
    Ok(())
}

async fn write_secure_response(
    stream: &mut TcpStream,
    status_line: &str,
    allow_hdr: Option<&str>,
    content_type: &str,
    body: &[u8],
    explicit_content_len: Option<usize>,
) -> Result<()> {
    let content_len = explicit_content_len.unwrap_or(body.len());
    let allow_line = allow_hdr
        .map(|a| format!("Allow: {a}\r\n"))
        .unwrap_or_default();
    let response_head = format!(
        "HTTP/1.1 {status_line}\r\n\
         {allow_line}\
         Content-Type: {content_type}\r\n\
         Content-Length: {content_len}\r\n\
         Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'\r\n\
         X-Frame-Options: DENY\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Referrer-Policy: no-referrer\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
    );

    stream.write_all(response_head.as_bytes()).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    stream.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_webui_routing_methods_and_real_telemetry() {
        let mgr = ConfigManager::default_production_demo();
        let stats = EngineRuntimeStats::new();
        stats.active_workers.store(8, Ordering::Relaxed);
        stats.total_requests.store(1234, Ordering::Relaxed);

        let (status, _, _, body) =
            route_authenticated_webui_request("GET", "/api/status", "", &mgr, &stats, &|_| {});
        assert_eq!(status, "200 OK");
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["workers"], 8);
        assert_eq!(parsed["total_requests"], 1234);

        let (status_405, allow, _, _) =
            route_authenticated_webui_request("POST", "/api/status", "", &mgr, &stats, &|_| {});
        assert_eq!(status_405, "405 Method Not Allowed");
        assert_eq!(allow, Some("GET"));

        let (status_404, _, _, _) =
            route_authenticated_webui_request("GET", "/api/nonexistent", "", &mgr, &stats, &|_| {});
        assert_eq!(status_404, "404 Not Found");

        assert!(!DASHBOARD_HTML.contains("io_uring SQPOLL ACTIVE"));
        assert!(!DASHBOARD_HTML.contains("1,482,900"));
    }
}
