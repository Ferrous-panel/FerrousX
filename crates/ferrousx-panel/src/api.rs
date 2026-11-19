//! crates/ferrousx-panel/src/api.rs
//! Giao diện Điều khiển cục bộ (Unix Domain Socket Control Plane) đã gia cố bảo mật:
//!   - Kiểm tra chống Symlink & phân quyền `0o750` cho thư mục cha `/run/ferrousx`
//!   - Phân quyền Socket `0o600` (hoặc `0o660` khi cấu hình nhóm đọc `allow_read_group_gid`)
//!   - Xác thực `SO_PEERCRED` (`uid`/`gid` nhân Linux) kết hợp Admin Token 256-bit (`/etc/ferrousx/admin.token`)
//!   - Phân quyền RBAC: `FullAdmin` (root/owner/token hợp lệ) vs `ReadOnly` (nhóm giám sát chỉ đọc `status`)
//!   - Giới hạn kích thước gói IPC (64 KiB) và khóa tạm thời chống Brute-Force Token

use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use ferrousx_config::config::{ConfigManager, ServerConfig};
use ferrousx_core::metrics::EngineRuntimeStats;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info, warn};

/// Giới hạn kích thước tối đa của một thông điệp IPC JSON (64 KiB)
const MAX_IPC_PAYLOAD_BYTES: usize = 64 * 1024;

/// Phân quyền RBAC trên Control Plane
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminRole {
    FullAdmin,
    ReadOnly,
}

/// Cấu trúc Gói tin Yêu cầu từ CLI (`ferrousx-ctl`) hoặc Panel Agent
#[derive(Debug, Serialize, Deserialize)]
pub struct IpcRequest {
    pub action: String,
    pub payload: serde_json::Value,
    #[serde(default)]
    pub auth_token: Option<String>,
}

/// Cấu trúc Gói tin Phản hồi về CLI / Panel
#[derive(Debug, Serialize, Deserialize)]
pub struct IpcResponse {
    pub success: bool,
    pub message: String,
    pub data: Option<serde_json::Value>,
    pub latency_us: u64,
}

/// Bộ theo dõi chống Brute-Force Token theo UID
struct BruteForceGuard {
    failures: Mutex<HashMap<u32, (u32, Instant)>>,
    max_attempts: u32,
    lockout_duration: Duration,
}

impl BruteForceGuard {
    fn new(max_attempts: u32, lockout_secs: u64) -> Self {
        Self {
            failures: Mutex::new(HashMap::new()),
            max_attempts: max_attempts.max(3),
            lockout_duration: Duration::from_secs(lockout_secs.max(30)),
        }
    }

    fn is_locked_out(&self, uid: u32) -> bool {
        let Ok(mut map) = self.failures.lock() else {
            return false;
        };
        if let Some((count, last_fail)) = map.get(&uid) {
            if *count >= self.max_attempts {
                if last_fail.elapsed() < self.lockout_duration {
                    return true;
                }
                map.remove(&uid);
            }
        }
        false
    }

    fn record_failure(&self, uid: u32) {
        if let Ok(mut map) = self.failures.lock() {
            let entry = map.entry(uid).or_insert((0, Instant::now()));
            entry.0 = entry.0.saturating_add(1);
            entry.1 = Instant::now();
        }
    }

    fn record_success(&self, uid: u32) {
        if let Ok(mut map) = self.failures.lock() {
            map.remove(&uid);
        }
    }
}

/// So sánh chuỗi thời gian hằng số (Constant-Time Comparison) chống Timing Attack
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() || a.is_empty() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Đọc hoặc khởi tạo tệp Token quản trị 256-bit CSPRNG từ `/dev/urandom` với quyền `0o600`
pub fn load_or_init_admin_token(token_path: &Path) -> Result<String> {
    if let Ok(env_tok) = std::env::var("FERROUSX_ADMIN_TOKEN") {
        let trimmed = env_tok.trim();
        if trimmed.len() >= 32 {
            return Ok(trimmed.to_string());
        }
    }

    if token_path.exists() {
        let meta = std::fs::symlink_metadata(token_path)
            .with_context(|| format!("Không thể kiểm tra metadata tệp token {:?}", token_path))?;
        if meta.file_type().is_symlink() {
            anyhow::bail!("Từ chối đọc tệp Admin Token vì là Symlink: {:?}", token_path);
        }
        // Đảm bảo quyền 0600 trên tệp token
        let _ = std::fs::set_permissions(token_path, std::fs::Permissions::from_mode(0o600));
        let content = std::fs::read_to_string(token_path)
            .with_context(|| format!("Không thể đọc tệp Admin Token {:?}", token_path))?;
        let token = content.trim().to_string();
        if token.len() >= 32 {
            return Ok(token);
        }
    }

    // Tạo mới 32 byte ngẫu nhiên mật mã từ /dev/urandom
    let mut random_bytes = [0u8; 32];
    let mut urandom = std::fs::File::open("/dev/urandom")
        .context("Không thể mở /dev/urandom để sinh khóa CSPRNG 256-bit")?;
    urandom
        .read_exact(&mut random_bytes)
        .context("Không thể đọc đủ 32 byte từ /dev/urandom")?;

    let mut hex_token = String::with_capacity(64);
    for b in random_bytes {
        use std::fmt::Write;
        let _ = write!(&mut hex_token, "{b:02x}");
    }

    if let Some(parent) = token_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(token_path)
    {
        use std::io::Write;
        let _ = std::fs::set_permissions(token_path, std::fs::Permissions::from_mode(0o600));
        let _ = writeln!(file, "{hex_token}");
    }

    Ok(hex_token)
}

/// Đọc trực tiếp Token quản trị hiện hành (hỗ trợ `fx token --rotate` không cần restart daemon)
pub fn read_current_admin_token(token_path: &Path, fallback: &str) -> String {
    if let Ok(env_tok) = std::env::var("FERROUSX_ADMIN_TOKEN") {
        let trimmed = env_tok.trim();
        if trimmed.len() >= 32 {
            return trimmed.to_string();
        }
    }
    if let Ok(meta) = std::fs::symlink_metadata(token_path) {
        if !meta.file_type().is_symlink() {
            if let Ok(content) = std::fs::read_to_string(token_path) {
                let tok = content.trim();
                if tok.len() >= 32 {
                    return tok.to_string();
                }
            }
        }
    }
    fallback.to_string()
}

/// Kiểm tra và gia cố thư mục cha của Unix Socket chống Symlink Attack
fn prepare_secure_socket_directory(socket_path: &Path) -> Result<()> {
    if let Some(parent) = socket_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Không thể tạo thư mục chứa Unix Socket: {:?}", parent)
            })?;
        }
        let meta = std::fs::symlink_metadata(parent)
            .with_context(|| format!("Không thể đọc metadata thư mục {:?}", parent))?;
        if meta.file_type().is_symlink() {
            anyhow::bail!(
                "Phát hiện nguy cơ tấn công Symlink trên thư mục Unix Socket: {:?}",
                parent
            );
        }
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750));
    }

    if socket_path.exists() {
        let meta = std::fs::symlink_metadata(socket_path)?;
        if meta.file_type().is_symlink() {
            anyhow::bail!(
                "Từ chối xóa hoặc ghi đè Symlink tại đường dẫn Unix Socket: {:?}",
                socket_path
            );
        }
        std::fs::remove_file(socket_path)
            .context("Không thể dọn dẹp tệp Unix Socket cũ trước khi khởi động")?;
    }
    Ok(())
}

/// Khởi chạy máy chủ IPC lắng nghe trên Unix Domain Socket
pub async fn start_admin_ipc_server(
    socket_path: PathBuf,
    config_mgr: Arc<ConfigManager>,
    stats: Arc<EngineRuntimeStats>,
    on_reload: Arc<dyn Fn(&ServerConfig) + Send + Sync>,
) -> Result<()> {
    prepare_secure_socket_directory(&socket_path)?;

    let cfg = config_mgr.current();
    let admin_token = Arc::new(
        load_or_init_admin_token(&cfg.admin_security.token_file_path)
            .unwrap_or_else(|_| String::new()),
    );
    let brute_guard = Arc::new(BruteForceGuard::new(
        cfg.admin_security.max_failed_attempts,
        cfg.admin_security.brute_force_lockout_secs,
    ));

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("Không thể gắn kết Admin IPC tại {:?}", socket_path))?;

    // Đặt quyền 0600 mặc định (hoặc 0660 nếu có cấu hình nhóm giám sát)
    let sock_mode = if cfg.admin_security.allow_read_group_gid.is_some() {
        0o660
    } else {
        0o600
    };
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(sock_mode))
        .context("Lỗi thiết lập quyền bảo mật (chmod) cho Admin Socket")?;

    let process_uid = std::fs::metadata("/proc/self")
        .map(|m| m.uid())
        .unwrap_or(0);

    info!(
        path = ?socket_path,
        mode = format!("{sock_mode:#o}"),
        "Trạm Điều khiển IPC (Control Plane) đã kích hoạt với xác thực SO_PEERCRED + Token"
    );

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let mgr_clone = Arc::clone(&config_mgr);
                let token_clone = Arc::clone(&admin_token);
                let guard_clone = Arc::clone(&brute_guard);
                let stats_clone = Arc::clone(&stats);
                let reload_clone = Arc::clone(&on_reload);
                tokio::spawn(async move {
                    if let Err(e) = handle_ipc_connection(
                        stream,
                        mgr_clone,
                        token_clone,
                        guard_clone,
                        process_uid,
                        stats_clone,
                        reload_clone,
                    )
                    .await
                    {
                        error!(error = %e, "Lỗi giao tiếp trên kênh IPC quản trị");
                    }
                });
            }
            Err(e) => {
                error!(error = %e, "Lỗi chấp nhận kết nối IPC mới");
            }
        }
    }
}

/// Xác thực quyền của kết nối Unix Socket dựa trên `SO_PEERCRED` (`uid`/`gid`) và `auth_token`
fn authenticate_ipc_peer(
    peer_uid: u32,
    peer_gid: u32,
    process_uid: u32,
    provided_token: Option<&str>,
    expected_token: &str,
    allow_read_gid: Option<u32>,
    require_peer_uid_auth: bool,
    brute_guard: &BruteForceGuard,
) -> std::result::Result<AdminRole, &'static str> {
    if brute_guard.is_locked_out(peer_uid) {
        return Err("Tài khoản/UID tạm thời bị khóa do sai Token quá số lần quy định");
    }

    // 1. Nếu là root (UID 0) hoặc chính chủ sở hữu tiến trình daemon (process_uid)
    if require_peer_uid_auth && (peer_uid == 0 || peer_uid == process_uid) {
        return Ok(AdminRole::FullAdmin);
    }

    // 2. Kiểm tra Token mật mã 256-bit bằng thuật toán thời gian hằng số
    if let Some(tok) = provided_token {
        if !expected_token.is_empty()
            && constant_time_eq(tok.trim().as_bytes(), expected_token.as_bytes())
        {
            brute_guard.record_success(peer_uid);
            return Ok(AdminRole::FullAdmin);
        } else {
            brute_guard.record_failure(peer_uid);
            return Err("Token xác thực Admin IPC không hợp lệ");
        }
    }

    // 3. Nếu thuộc nhóm GID được phép giám sát -> cấp quyền ReadOnly
    if let Some(allowed_gid) = allow_read_gid {
        if peer_gid == allowed_gid {
            return Ok(AdminRole::ReadOnly);
        }
    }

    Err("Từ chối truy cập IPC: Yêu cầu quyền root/owner hoặc Admin Token hợp lệ")
}

/// Xử lý từng kết nối lệnh từ CLI gửi vào
async fn handle_ipc_connection(
    mut stream: UnixStream,
    config_mgr: Arc<ConfigManager>,
    fallback_token: Arc<String>,
    brute_guard: Arc<BruteForceGuard>,
    process_uid: u32,
    stats: Arc<EngineRuntimeStats>,
    on_reload: Arc<dyn Fn(&ServerConfig) + Send + Sync>,
) -> Result<()> {
    let start_time = Instant::now();

    let (peer_uid, peer_gid) = match stream.peer_cred() {
        Ok(cred) => (cred.uid(), cred.gid()),
        Err(_) => (u32::MAX, u32::MAX),
    };

    // Giới hạn kích thước đọc tối đa 64 KiB để chống OOM DoS trên Unix Socket
    let mut buffer = Vec::with_capacity(1024);
    let mut limited_reader = (&mut stream).take((MAX_IPC_PAYLOAD_BYTES + 1) as u64);
    limited_reader.read_to_end(&mut buffer).await?;

    if buffer.is_empty() {
        return Ok(());
    }
    if buffer.len() > MAX_IPC_PAYLOAD_BYTES {
        let resp = IpcResponse {
            success: false,
            message: "413 Payload Too Large: Gói lệnh IPC vượt quá 64 KiB".to_string(),
            data: None,
            latency_us: start_time.elapsed().as_micros() as u64,
        };
        stream.write_all(&serde_json::to_vec(&resp)?).await?;
        stream.flush().await?;
        return Ok(());
    }

    let req: IpcRequest = match serde_json::from_slice(&buffer) {
        Ok(r) => r,
        Err(e) => {
            let err_resp = IpcResponse {
                success: false,
                message: format!("Cú pháp lệnh JSON bất hợp lệ: {e}"),
                data: None,
                latency_us: start_time.elapsed().as_micros() as u64,
            };
            let out = serde_json::to_vec(&err_resp)?;
            stream.write_all(&out).await?;
            return Ok(());
        }
    };

    let cfg = config_mgr.current();
    let expected_token =
        read_current_admin_token(&cfg.admin_security.token_file_path, &fallback_token);
    let role = match authenticate_ipc_peer(
        peer_uid,
        peer_gid,
        process_uid,
        req.auth_token.as_deref(),
        &expected_token,
        cfg.admin_security.allow_read_group_gid,
        cfg.admin_security.require_peer_uid_auth,
        &brute_guard,
    ) {
        Ok(r) => r,
        Err(reason) => {
            warn!(
                peer_uid,
                peer_gid,
                action = %req.action,
                "Chặn truy cập trái phép vào Admin IPC Socket: {reason}"
            );
            let deny_resp = IpcResponse {
                success: false,
                message: format!("403 Unauthorized: {reason}"),
                data: None,
                latency_us: start_time.elapsed().as_micros() as u64,
            };
            stream.write_all(&serde_json::to_vec(&deny_resp)?).await?;
            stream.flush().await?;
            return Ok(());
        }
    };

    // Kiểm tra phân quyền RBAC: ReadOnly chỉ được phép gọi lệnh `status`
    if role == AdminRole::ReadOnly && req.action.as_str() != "status" {
        warn!(
            peer_uid,
            action = %req.action,
            "Chặn thao tác thay đổi cấu hình từ tài khoản ReadOnly"
        );
        let deny_resp = IpcResponse {
            success: false,
            message: "403 Forbidden: Quyền ReadOnly chỉ được phép truy vấn 'status'".to_string(),
            data: None,
            latency_us: start_time.elapsed().as_micros() as u64,
        };
        stream.write_all(&serde_json::to_vec(&deny_resp)?).await?;
        stream.flush().await?;
        return Ok(());
    }

    // Định tuyến lệnh điều khiển
    let response = match req.action.as_str() {
        "reload" | "panel_sync" | "vhost_add" | "vhost_del" => match config_mgr.reload_from_disk() {
            Ok(new_epoch) => {
                let updated_cfg = config_mgr.current();
                (on_reload)(&updated_cfg);
                IpcResponse {
                    success: true,
                    message: format!(
                        "Đã đồng bộ '{}' và nạp lại cấu hình + SNI (Zero-Downtime RCU). Epoch: v{new_epoch}",
                        req.action
                    ),
                    data: Some(serde_json::json!({
                        "action": req.action,
                        "epoch": new_epoch,
                        "vhosts_count": updated_cfg.vhosts.len(),
                    })),
                    latency_us: start_time.elapsed().as_micros() as u64,
                }
            }
            Err(err) => IpcResponse {
                success: false,
                message: format!("Từ chối nạp cấu hình mới (Giữ nguyên cấu hình cũ): {err}"),
                data: None,
                latency_us: start_time.elapsed().as_micros() as u64,
            },
        },

        "status" => {
            let current_cfg = config_mgr.current();
            let snap = stats.snapshot();
            IpcResponse {
                success: true,
                message: "Hệ thống FerrousX đang hoạt động ổn định".to_string(),
                data: Some(serde_json::json!({
                    "epoch": current_cfg.version_epoch,
                    "vhosts_count": current_cfg.vhosts.len(),
                    "upstreams_count": current_cfg.upstreams.len(),
                    "quic_enabled": current_cfg.enable_http3_quic,
                    "waf_enabled": current_cfg.waf.enabled,
                    "waf_mode": format!("{:?}", current_cfg.waf.mode),
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
                })),
                latency_us: start_time.elapsed().as_micros() as u64,
            }
        }

        "cache" => {
            let snap = stats.snapshot();
            IpcResponse {
                success: true,
                message: "FerrousX đang chạy Pass-Through/FastCGI trực tiếp (không dùng Edge Disk Cache); gửi 'reload' nếu muốn làm mới ETag/Vhost".to_string(),
                data: Some(serde_json::json!({
                    "mode": "direct_pass_through",
                    "static_requests": snap.static_requests,
                    "php_fpm_requests": snap.php_fpm_requests,
                    "bytes_sent": snap.bytes_sent,
                })),
                latency_us: start_time.elapsed().as_micros() as u64,
            }
        }

        "upgrade" => {
            let bin_opt = req.payload.get("binary").and_then(|v| v.as_str());
            match bin_opt {
                Some(raw_path) => {
                    let p = Path::new(raw_path);
                    if !p.is_file() {
                        IpcResponse {
                            success: false,
                            message: format!("Không tìm thấy tệp nhị phân tại: {raw_path}"),
                            data: None,
                            latency_us: start_time.elapsed().as_micros() as u64,
                        }
                    } else {
                        IpcResponse {
                            success: false,
                            message: format!(
                                "Live SCM_RIGHTS exec chưa bật trong daemon hiện tại. Vui lòng kiểm tra bằng '{} -t' rồi chạy `systemctl restart ferrousx.service`.",
                                p.display()
                            ),
                            data: Some(serde_json::json!({ "binary": p.display().to_string() })),
                            latency_us: start_time.elapsed().as_micros() as u64,
                        }
                    }
                }
                None => IpcResponse {
                    success: false,
                    message: "Thiếu tham số 'binary' cho lệnh upgrade".to_string(),
                    data: None,
                    latency_us: start_time.elapsed().as_micros() as u64,
                },
            }
        }

        unknown => {
            warn!(action = %unknown, "Nhận được lệnh IPC không xác định");
            IpcResponse {
                success: false,
                message: format!("Lệnh điều khiển không tồn tại: {unknown}"),
                data: None,
                latency_us: start_time.elapsed().as_micros() as u64,
            }
        }
    };

    let out_bytes = serde_json::to_vec(&response)?;
    stream.write_all(&out_bytes).await?;
    stream.shutdown().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq_security() {
        assert!(constant_time_eq(b"secret_token_12345", b"secret_token_12345"));
        assert!(!constant_time_eq(b"secret_token_12345", b"secret_token_12346"));
        assert!(!constant_time_eq(b"short", b"longer_string"));
        assert!(!constant_time_eq(b"", b""));
    }

    #[test]
    fn test_authenticate_ipc_peer_rbac_and_lockout() {
        let guard = BruteForceGuard::new(3, 60);
        let expected = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        // UID 0 (root) gets FullAdmin
        assert_eq!(
            authenticate_ipc_peer(0, 0, 1000, None, expected, None, true, &guard),
            Ok(AdminRole::FullAdmin)
        );

        // Non-owner with allowed GID gets ReadOnly
        assert_eq!(
            authenticate_ipc_peer(1005, 2000, 1000, None, expected, Some(2000), true, &guard),
            Ok(AdminRole::ReadOnly)
        );

        // Non-owner with valid token gets FullAdmin
        assert_eq!(
            authenticate_ipc_peer(1005, 1005, 1000, Some(expected), expected, None, true, &guard),
            Ok(AdminRole::FullAdmin)
        );

        // 3 failed attempts trigger brute-force lockout
        for _ in 0..3 {
            assert!(authenticate_ipc_peer(
                1009,
                1009,
                1000,
                Some("wrong_token"),
                expected,
                None,
                true,
                &guard
            )
            .is_err());
        }
        assert!(guard.is_locked_out(1009));
    }
}
