//! crates/ferrousx-http/src/server.rs
//! Động cơ phục vụ Triple-Stack:
//!   - TCP HTTP/1.1 (:80)
//!   - TCP HTTPS TLS 1.3/1.2 ALPN h2,http/1.1 (:443) — Bắt buộc cho Cloudflare SSL Full
//!   - UDP HTTP/3 QUIC (:443) + quảng bá Alt-Svc
//! Hỗ trợ:
//!   - Đồng bộ động `/etc/ferrous-panel/admin.json` (`customDomain`, `panelPort`, `securityEntrance`)
//!   - Reverse Proxy chuẩn Cloudflare (`CF-Connecting-IP`, `X-Real-IP`, `X-Forwarded-*`)
//!   - WebSocket Upgrade Tunneling (`Connection: Upgrade`, `Upgrade: websocket`)
//!   - Định tuyến phpMyAdmin (`/phpadmin`, `/phpmyadmin` -> 302 + proxy `127.0.0.1:888`)
//!   - Thực thi PHP-FPM FastCGI chuẩn + bảo vệ Path Traversal cho `/www/wwwroot/<domain>`

use std::net::{IpAddr, SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderName, HeaderValue, Method, Response, StatusCode};
use quinn::{Endpoint, EndpointConfig, ServerConfig as QuinnServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::task::LocalSet;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use ferrousx_config::config::{BackendProtocol, ConfigManager, ServerConfig, VirtualHost};
use ferrousx_proxy::fastcgi::{detect_php_fpm_socket, execute_fastcgi, safe_resolve_under_root};
use ferrousx_proxy::pipeline::{CgiEnvironment, MimeDetector};

/// Khung phản hồi nội bộ thống nhất giữa HTTP/1.1, HTTP/2 và HTTP/3
pub struct HttpResponsePayload {
    pub status: StatusCode,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

/// Ngữ cảnh yêu cầu đầu vào đã chuẩn hóa
struct IncomingRequest {
    method: String,
    raw_target: String,
    path: String,
    query: String,
    host: String,
    headers: Vec<(String, String)>,
    body: Bytes,
    peer_ip: IpAddr,
    is_tls: bool,
}

/// Khởi chạy đồng thời:
///   - TCP HTTP (:80)
///   - TCP HTTPS TLS 1.3/1.2 (:443)
///   - UDP HTTP/3 QUIC (:443) (nếu socket UDP bind thành công)
pub async fn run_dual_stack_worker(
    ctx: ferrousx_core::worker::WorkerContext,
    std_http: StdTcpListener,
    std_https: StdTcpListener,
    std_udp: Option<StdUdpSocket>,
    tls_acceptor: TlsAcceptor,
    quinn_server_cfg: QuinnServerConfig,
) -> Result<()> {
    let worker_id = ctx.worker_id;
    let config_mgr = Arc::clone(&ctx.config_mgr);

    let http_listener = TcpListener::from_std(std_http)
        .context("Không thể chuyển đổi HTTP TcpListener (:80) sang bất đồng bộ")?;
    let https_listener = TcpListener::from_std(std_https)
        .context("Không thể chuyển đổi HTTPS TcpListener (:443) sang bất đồng bộ")?;

    let quic_endpoint = if let Some(udp_sock) = std_udp {
        let runtime = quinn::default_runtime()
            .ok_or_else(|| anyhow::anyhow!("Không tìm thấy Async Runtime tương thích cho Quinn"))?;
        Some(Endpoint::new(
            EndpointConfig::default(),
            Some(quinn_server_cfg),
            udp_sock,
            runtime,
        )?)
    } else {
        None
    };

    info!(
        worker_id,
        core = ctx.core_id.id,
        quic_enabled = quic_endpoint.is_some(),
        "Worker sẵn sàng tiếp nhận lưu lượng Triple-Stack (TCP :80 HTTP + TCP :443 TLS + UDP :443 QUIC)"
    );

    let local_tasks = LocalSet::new();
    local_tasks
        .run_until(async move {
            if let Some(endpoint) = quic_endpoint {
                tokio::try_join!(
                    run_tcp_plain_http_loop(worker_id, http_listener, Arc::clone(&config_mgr)),
                    run_tcp_https_loop(worker_id, https_listener, tls_acceptor, Arc::clone(&config_mgr)),
                    run_udp_h3_quic_loop(worker_id, endpoint, config_mgr),
                )
                .map(|_| ())
            } else {
                tokio::try_join!(
                    run_tcp_plain_http_loop(worker_id, http_listener, Arc::clone(&config_mgr)),
                    run_tcp_https_loop(worker_id, https_listener, tls_acceptor, Arc::clone(&config_mgr)),
                )
                .map(|_| ())
            }
        })
        .await?;

    Ok(())
}

/// Vòng lặp tiếp nhận kết nối TCP HTTP (:80)
async fn run_tcp_plain_http_loop(
    worker_id: usize,
    listener: TcpListener,
    config_mgr: Arc<ConfigManager>,
) -> Result<()> {
    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;
        let _ = tcp_stream.set_nodelay(true);
        let cfg_mgr = Arc::clone(&config_mgr);

        tokio::task::spawn_local(async move {
            if let Err(e) = serve_http1_connection(tcp_stream, peer_addr, false, cfg_mgr).await {
                debug!(worker_id, %peer_addr, error = %e, "Kết thúc phiên HTTP (:80)");
            }
        });
    }
}

/// Vòng lặp tiếp nhận kết nối TCP HTTPS TLS 1.3/1.2 (:443) phục vụ HTTP/2 và HTTP/1.1
async fn run_tcp_https_loop(
    worker_id: usize,
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    config_mgr: Arc<ConfigManager>,
) -> Result<()> {
    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;
        let _ = tcp_stream.set_nodelay(true);

        let acceptor = tls_acceptor.clone();
        let cfg_mgr = Arc::clone(&config_mgr);

        tokio::task::spawn_local(async move {
            match acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => {
                    let (_, server_conn) = tls_stream.get_ref();
                    let negotiated_alpn = server_conn
                        .alpn_protocol()
                        .map(|p| p.to_vec())
                        .unwrap_or_else(|| b"http/1.1".to_vec());

                    if negotiated_alpn.as_slice() == b"h2" {
                        if let Err(e) = serve_http2_connection(tls_stream, peer_addr, cfg_mgr).await {
                            debug!(worker_id, %peer_addr, error = %e, "Kết thúc phiên HTTPS HTTP/2 (:443)");
                        }
                    } else if let Err(e) =
                        serve_http1_connection(tls_stream, peer_addr, true, cfg_mgr).await
                    {
                        debug!(worker_id, %peer_addr, error = %e, "Kết thúc phiên HTTPS HTTP/1.1 (:443)");
                    }
                }
                Err(err) => {
                    debug!(worker_id, %peer_addr, error = %err, "Bắt tay TLS (:443) thất bại");
                }
            }
        });
    }
}

/// Xử lý HTTP/1.1 Keep-Alive, đọc đầy đủ Request Body, và hỗ trợ WebSocket Upgrade Tunneling
async fn serve_http1_connection<S>(
    mut stream: S,
    peer_addr: SocketAddr,
    is_tls: bool,
    config_mgr: Arc<ConfigManager>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut read_buf = BytesMut::with_capacity(16 * 1024);

    loop {
        let cfg = config_mgr.current();
        let header_timeout = Duration::from_millis(cfg.client_header_timeout_ms.max(1000));

        // Đọc cho tới khi gặp \r\n\r\n (tối đa 64KB header)
        let header_end = loop {
            if let Some(pos) = find_double_crlf(&read_buf) {
                break pos;
            }
            if read_buf.len() > 64 * 1024 {
                write_simple_http1_error(&mut stream, StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE, "Header quá lớn").await?;
                return Ok(());
            }
            let n = match tokio::time::timeout(header_timeout, stream.read_buf(&mut read_buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => return Ok(()),
            };
            if n == 0 {
                return Ok(());
            }
        };

        let mut headers_storage = [httparse::EMPTY_HEADER; 96];
        let mut req = httparse::Request::new(&mut headers_storage);
        let parse_status = req.parse(&read_buf[..header_end + 4])?;
        if !parse_status.is_complete() {
            write_simple_http1_error(&mut stream, StatusCode::BAD_REQUEST, "HTTP Request không hợp lệ").await?;
            return Ok(());
        }

        let method = req.method.unwrap_or("GET").to_string();
        let raw_target = req.path.unwrap_or("/").to_string();
        let (path, query) = split_path_and_query(&raw_target);

        let mut host = String::new();
        let mut content_length: usize = 0;
        let mut is_chunked = false;
        let mut conn_close = false;
        let mut is_upgrade_conn = false;
        let mut is_websocket_upgrade = false;
        let mut parsed_headers = Vec::with_capacity(req.headers.len());

        for h in req.headers.iter() {
            let name = h.name.to_string();
            let val = String::from_utf8_lossy(h.value).to_string();
            if name.eq_ignore_ascii_case("host") {
                host = val.clone();
            } else if name.eq_ignore_ascii_case("content-length") {
                content_length = val.trim().parse::<usize>().unwrap_or(0);
            } else if name.eq_ignore_ascii_case("transfer-encoding")
                && val.to_ascii_lowercase().contains("chunked")
            {
                is_chunked = true;
            } else if name.eq_ignore_ascii_case("connection") {
                let low = val.to_ascii_lowercase();
                if low.contains("close") {
                    conn_close = true;
                }
                if low.contains("upgrade") {
                    is_upgrade_conn = true;
                }
            } else if name.eq_ignore_ascii_case("upgrade")
                && val.trim().eq_ignore_ascii_case("websocket")
            {
                is_websocket_upgrade = true;
            }
            parsed_headers.push((name, val));
        }

        // Bỏ phần header khỏi buffer, giữ lại phần body đã đọc kèm
        let _ = read_buf.split_to(header_end + 4);

        // Nếu là WebSocket Upgrade (`Connection: Upgrade` + `Upgrade: websocket`),
        // chuyển giao toàn quyền stream sang đường hầm hai chiều Full-Duplex!
        if is_upgrade_conn && is_websocket_upgrade {
            let incoming = IncomingRequest {
                method,
                raw_target,
                path,
                query,
                host,
                headers: parsed_headers,
                body: Bytes::new(),
                peer_ip: peer_addr.ip(),
                is_tls,
            };
            return handle_websocket_upgrade(stream, read_buf, incoming, &cfg).await;
        }

        if content_length > cfg.client_max_body_size {
            write_simple_http1_error(&mut stream, StatusCode::PAYLOAD_TOO_LARGE, "Body vượt quá client_max_body_size").await?;
            return Ok(());
        }

        // Đọc đủ phần thân Request Body
        let body = if is_chunked {
            read_chunked_http1_body(&mut stream, &mut read_buf, cfg.client_max_body_size).await?
        } else if content_length > 0 {
            while read_buf.len() < content_length {
                let n = stream.read_buf(&mut read_buf).await?;
                if n == 0 {
                    break;
                }
            }
            let take = content_length.min(read_buf.len());
            read_buf.split_to(take).freeze()
        } else {
            Bytes::new()
        };

        let incoming = IncomingRequest {
            method,
            raw_target,
            path,
            query,
            host,
            headers: parsed_headers,
            body,
            peer_ip: peer_addr.ip(),
            is_tls,
        };

        let resp = dispatch_http_request(&incoming, &cfg).await;
        write_http1_response(&mut stream, &resp, &cfg, !conn_close).await?;

        if conn_close {
            return Ok(());
        }
    }
}

/// Phục vụ đa luồng khung (multiplexed frames) HTTP/2 trên kết nối TCP TLS 1.3/1.2 (:443)
async fn serve_http2_connection<S>(
    stream: S,
    peer_addr: SocketAddr,
    config_mgr: Arc<ConfigManager>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
{
    let mut h2_conn = h2::server::handshake(stream).await?;

    while let Some(result) = h2_conn.accept().await {
        let (request, mut respond) = result?;
        let cfg_mgr = Arc::clone(&config_mgr);

        tokio::task::spawn_local(async move {
            let cfg = cfg_mgr.current();
            let (parts, mut body_stream) = request.into_parts();

            let mut body_buf = BytesMut::new();
            while let Some(chunk_res) = body_stream.data().await {
                if let Ok(chunk) = chunk_res {
                    if body_buf.len() + chunk.len() > cfg.client_max_body_size {
                        break;
                    }
                    body_buf.extend_from_slice(&chunk);
                    let _ = body_stream.flow_control().release_capacity(chunk.len());
                }
            }

            let raw_target = parts
                .uri
                .path_and_query()
                .map(|pq| pq.as_str().to_string())
                .unwrap_or_else(|| "/".to_string());
            let (path, query) = split_path_and_query(&raw_target);

            let mut host = parts
                .uri
                .authority()
                .map(|a| a.as_str().to_string())
                .unwrap_or_default();
            let mut headers = Vec::with_capacity(parts.headers.len());
            for (k, v) in parts.headers.iter() {
                let val_str = String::from_utf8_lossy(v.as_bytes()).to_string();
                if k.as_str().eq_ignore_ascii_case("host") && host.is_empty() {
                    host = val_str.clone();
                }
                headers.push((k.as_str().to_string(), val_str));
            }

            let incoming = IncomingRequest {
                method: parts.method.as_str().to_string(),
                raw_target,
                path,
                query,
                host,
                headers,
                body: body_buf.freeze(),
                peer_ip: peer_addr.ip(),
                is_tls: true,
            };

            let resp_payload = dispatch_http_request(&incoming, &cfg).await;
            let mut builder = Response::builder().status(resp_payload.status);
            let https_port = cfg.https_port();
            let alt_svc_val = format!("h3=\":{https_port}\"; ma={}", cfg.alt_svc_max_age);

            if let Some(hmap) = builder.headers_mut() {
                if let Ok(hv) = HeaderValue::from_str(&alt_svc_val) {
                    hmap.append(HeaderName::from_static("alt-svc"), hv);
                }
                hmap.append(
                    HeaderName::from_static("server"),
                    HeaderValue::from_static("FerrousX/0.1 (HTTP/2)"),
                );
                for (k, v) in &resp_payload.headers {
                    if is_hop_by_hop_header(k) {
                        continue;
                    }
                    if let (Ok(hn), Ok(hv)) = (
                        HeaderName::from_bytes(k.as_bytes()),
                        HeaderValue::from_str(v),
                    ) {
                        hmap.append(hn, hv);
                    }
                }
            }

            if let Ok(response) = builder.body(()) {
                let empty_body = resp_payload.body.is_empty() || incoming.method == "HEAD";
                if let Ok(mut send_stream) = respond.send_response(response, empty_body) {
                    if !empty_body {
                        let _ = send_stream.send_data(resp_payload.body, true);
                    }
                }
            }
        });
    }
    Ok(())
}

/// Vòng lặp tiếp nhận kết nối UDP QUIC và phân luồng HTTP/3 (RFC 9114)
async fn run_udp_h3_quic_loop(
    worker_id: usize,
    endpoint: Endpoint,
    config_mgr: Arc<ConfigManager>,
) -> Result<()> {
    while let Some(incoming_handshake) = endpoint.accept().await {
        let cfg_mgr = Arc::clone(&config_mgr);

        tokio::task::spawn_local(async move {
            match incoming_handshake.await {
                Ok(quic_conn) => {
                    let peer_addr = quic_conn.remote_address();
                    if let Err(err) = serve_http3_quic_streams(quic_conn, peer_addr, cfg_mgr).await {
                        debug!(worker_id, error = %err, "Đóng kết nối HTTP/3 QUIC");
                    }
                }
                Err(err) => {
                    warn!(worker_id, error = %err, "Lỗi bắt tay QUIC Initial/0-RTT");
                }
            }
        });
    }
    Ok(())
}

/// Giải mã và phản hồi từng Bidirectional Stream của HTTP/3 trên nền Quinn QUIC
async fn serve_http3_quic_streams(
    quic_conn: quinn::Connection,
    peer_addr: SocketAddr,
    config_mgr: Arc<ConfigManager>,
) -> Result<()> {
    let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
        h3::server::Connection::new(h3_quinn::Connection::new(quic_conn)).await?;

    loop {
        match h3_conn.accept().await {
            Ok(Some((req, mut stream))) => {
                let cfg_mgr = Arc::clone(&config_mgr);
                tokio::task::spawn_local(async move {
                    let cfg = cfg_mgr.current();
                    let (parts, ()) = req.into_parts();

                    let mut body_buf = BytesMut::new();
                    while let Ok(Some(mut chunk)) = stream.recv_data().await {
                        if body_buf.len() + chunk.remaining() > cfg.client_max_body_size {
                            break;
                        }
                        body_buf.extend_from_slice(chunk.chunk());
                        chunk.advance(chunk.remaining());
                    }

                    let raw_target = parts
                        .uri
                        .path_and_query()
                        .map(|pq| pq.as_str().to_string())
                        .unwrap_or_else(|| "/".to_string());
                    let (path, query) = split_path_and_query(&raw_target);
                    let mut host = parts
                        .uri
                        .authority()
                        .map(|a| a.as_str().to_string())
                        .unwrap_or_default();
                    let mut headers = Vec::with_capacity(parts.headers.len());
                    for (k, v) in parts.headers.iter() {
                        let val_str = String::from_utf8_lossy(v.as_bytes()).to_string();
                        if k.as_str().eq_ignore_ascii_case("host") && host.is_empty() {
                            host = val_str.clone();
                        }
                        headers.push((k.as_str().to_string(), val_str));
                    }

                    let incoming = IncomingRequest {
                        method: parts.method.as_str().to_string(),
                        raw_target,
                        path,
                        query,
                        host,
                        headers,
                        body: body_buf.freeze(),
                        peer_ip: peer_addr.ip(),
                        is_tls: true,
                    };

                    let resp_payload = dispatch_http_request(&incoming, &cfg).await;
                    let mut builder = Response::builder().status(resp_payload.status);
                    if let Some(hmap) = builder.headers_mut() {
                        hmap.append(
                            HeaderName::from_static("server"),
                            HeaderValue::from_static("FerrousX/0.1 (QUIC/HTTP3)"),
                        );
                        for (k, v) in &resp_payload.headers {
                            if is_hop_by_hop_header(k) {
                                continue;
                            }
                            if let (Ok(hn), Ok(hv)) = (
                                HeaderName::from_bytes(k.as_bytes()),
                                HeaderValue::from_str(v),
                            ) {
                                hmap.append(hn, hv);
                            }
                        }
                    }

                    if let Ok(resp) = builder.body(()) {
                        if stream.send_response(resp).await.is_ok() {
                            if !resp_payload.body.is_empty() && incoming.method != "HEAD" {
                                let _ = stream.send_data(resp_payload.body).await;
                            }
                            let _ = stream.finish().await;
                        }
                    }
                });
            }
            Ok(None) => break,
            Err(err) => {
                debug!(error = %err, "Ngắt luồng HTTP/3");
                break;
            }
        }
    }
    Ok(())
}

// ============================================================================
// BỘ ĐỊNH TUYẾN CHÍNH (PRODUCTION ROUTER): CLOUDFLARE, PANEL, PHPMYADMIN, PHP-FPM
// ============================================================================

async fn dispatch_http_request(req: &IncomingRequest, cfg: &ServerConfig) -> HttpResponsePayload {
    // 1. Định tuyến phpMyAdmin tương thích Cloudflare (tránh cổng 888 bị Cloudflare chặn)
    if req.path == "/phpadmin" || req.path == "/phpmyadmin" {
        let mut target_loc = format!("{}/", req.path);
        if !req.query.is_empty() {
            target_loc.push('?');
            target_loc.push_str(&req.query);
        }
        return HttpResponsePayload {
            status: StatusCode::FOUND, // 302 Redirect
            headers: vec![
                ("Location".to_string(), target_loc),
                ("Cache-Control".to_string(), "no-store".to_string()),
            ],
            body: Bytes::new(),
        };
    }

    if req.path.starts_with("/phpadmin/") || req.path.starts_with("/phpmyadmin/") {
        return proxy_http1_upstream(&cfg.phpmyadmin_upstream, req, cfg).await;
    }

    // 2. Đồng bộ định tuyến động tới Ferrous-panel từ `/etc/ferrous-panel/admin.json`
    if is_panel_request(req, cfg) {
        let panel_upstream = cfg.panel_admin.panel_upstream_addr();
        return proxy_http1_upstream(&panel_upstream, req, cfg).await;
    }

    // 3. Tìm VirtualHost khớp với Host header hoặc thư mục `/www/wwwroot/<domain>`
    let host_no_port = strip_port(&req.host);
    if let Some(vhost) = match_virtual_host(host_no_port, cfg) {
        // 3a. Kiểm tra các route proxy cấu hình sẵn trong VirtualHost
        for route in &vhost.routes {
            if route.backend_protocol != BackendProtocol::FastCgi
                && route.backend_protocol != BackendProtocol::StaticFile
                && req.path.starts_with(&route.path_prefix)
            {
                if let Some(ref upstream_key) = route.target_upstream {
                    let target_addr = resolve_upstream_addr(upstream_key, cfg);
                    return proxy_http1_upstream(&target_addr, req, cfg).await;
                }
            }
        }

        // 3b. Phục vụ tệp tĩnh + PHP-FPM FastCGI dưới root_dir của VirtualHost
        if let Some(ref root_dir) = vhost.root_dir {
            if root_dir.is_dir() {
                return serve_vhost_site_root(root_dir, vhost.php_fpm_socket.as_deref(), req, cfg)
                    .await;
            }
        }
    }

    // 4. Tự động kiểm tra `/www/wwwroot/<domain>` ngay cả khi chưa thêm vào file .toml
    if !host_no_port.is_empty() && !host_no_port.contains("..") && !host_no_port.contains('/') {
        let dynamic_root = PathBuf::from("/www/wwwroot").join(host_no_port);
        if dynamic_root.is_dir() {
            return serve_vhost_site_root(&dynamic_root, None, req, cfg).await;
        }
    }

    // 5. Fallback mặc định nếu chưa có website nào được trỏ tới
    let payload = format!(
        "{{\"server\":\"FerrousX\",\"engine\":\"io_uring+TLS+QUIC\",\"host\":\"{}\",\"path\":\"{}\",\"epoch\":{}}}",
        host_no_port, req.path, cfg.version_epoch
    );
    HttpResponsePayload {
        status: StatusCode::OK,
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body: Bytes::from(payload),
    }
}

/// Kiểm tra request có thuộc Ferrous-panel hay không (dựa theo admin.json: customDomain, securityEntrance)
fn is_panel_request(req: &IncomingRequest, cfg: &ServerConfig) -> bool {
    let host_no_port = strip_port(&req.host);
    let custom_domain = cfg.panel_admin.custom_domain.trim();
    let entrance = cfg.panel_admin.security_entrance.trim();

    if !custom_domain.is_empty() && host_no_port.eq_ignore_ascii_case(custom_domain) {
        return true;
    }

    if !entrance.is_empty() {
        let normalized = if entrance.starts_with('/') {
            entrance.to_string()
        } else {
            format!("/{entrance}")
        };
        if req.path == normalized || req.path.starts_with(&(normalized.clone() + "/")) {
            return true;
        }
    }

    // Khi customDomain rỗng, cho phép truy cập panel qua bất kỳ Host/IP nào trên các tuyến chuẩn của panel
    if custom_domain.is_empty()
        && (req.path.starts_with("/ferrous-panel")
            || req.path.starts_with("/api/panel")
            || req.path.starts_with("/ws/ssh")
            || req.path.starts_with("/ws/telemetry"))
    {
        return true;
    }

    false
}

/// Phục vụ website Vhost (tệp tĩnh + PHP-FPM FastCGI) kèm chống Path Traversal tuyệt đối
async fn serve_vhost_site_root(
    site_root: &Path,
    preferred_php_sock: Option<&str>,
    req: &IncomingRequest,
    cfg: &ServerConfig,
) -> HttpResponsePayload {
    // 1. Bảo vệ Path Traversal: Không cho phép thoát khỏi `site_root`
    let Some(resolved) = safe_resolve_under_root(site_root, &req.path) else {
        return HttpResponsePayload {
            status: StatusCode::FORBIDDEN,
            headers: vec![("Content-Type".to_string(), "text/plain; charset=utf-8".to_string())],
            body: Bytes::from_static(b"403 Forbidden: Path Traversal Blocked by FerrousX"),
        };
    };

    // 2. Xác định tệp thực thi: tệp .php, tệp tĩnh, thư mục index, hoặc fallback /index.php
    let target_file = if resolved.is_file() {
        resolved
    } else if resolved.is_dir() {
        let idx_php = resolved.join("index.php");
        let idx_html = resolved.join("index.html");
        if idx_php.is_file() {
            idx_php
        } else if idx_html.is_file() {
            idx_html
        } else {
            site_root.join("index.php")
        }
    } else {
        // Nginx try_files $uri $uri/ /index.php?$query_string
        let fallback_php = site_root.join("index.php");
        if fallback_php.is_file() {
            fallback_php
        } else {
            let fallback_html = site_root.join("index.html");
            if fallback_html.is_file() {
                fallback_html
            } else {
                return HttpResponsePayload {
                    status: StatusCode::NOT_FOUND,
                    headers: vec![("Content-Type".to_string(), "text/plain; charset=utf-8".to_string())],
                    body: Bytes::from_static(b"404 Not Found"),
                };
            }
        }
    };

    if !target_file.exists() {
        return HttpResponsePayload {
            status: StatusCode::NOT_FOUND,
            headers: vec![("Content-Type".to_string(), "text/plain; charset=utf-8".to_string())],
            body: Bytes::from_static(b"404 Not Found"),
        };
    }

    let is_php = target_file
        .extension()
        .and_then(|e| e.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("php"))
        .unwrap_or(false);

    if is_php {
        let fpm_target = detect_php_fpm_socket(preferred_php_sock);
        let client_ip = resolve_real_client_ip(req);
        let is_https = is_request_https(req);

        let doc_root_str = site_root.to_string_lossy().to_string();
        let script_filename_str = target_file.to_string_lossy().to_string();
        let script_name = target_file
            .strip_prefix(site_root)
            .map(|p| format!("/{}", p.to_string_lossy().trim_start_matches('/')))
            .unwrap_or_else(|_| "/index.php".to_string());
        let host_name = strip_port(&req.host).to_string();

        let mut params = CgiEnvironment::build_standard_params(
            &req.method,
            &script_name,
            &req.query,
            &doc_root_str,
            &script_filename_str,
            &host_name,
            &client_ip,
            is_https,
        );

        // Chuyển tiếp REQUEST_URI gốc và toàn bộ HTTP_* headers (bao gồm HTTP_COOKIE, CONTENT_TYPE, CONTENT_LENGTH)
        if let Some(entry) = params.iter_mut().find(|(k, _)| *k == "REQUEST_URI") {
            entry.1 = req.raw_target.clone();
        }
        if let Some(entry) = params.iter_mut().find(|(k, _)| *k == "CONTENT_LENGTH") {
            entry.1 = req.body.len().to_string();
        }

        let mut extra_headers: Vec<(String, String)> = Vec::new();
        for (k, v) in &req.headers {
            if k.eq_ignore_ascii_case("content-type") {
                if let Some(entry) = params.iter_mut().find(|(pk, _)| *pk == "CONTENT_TYPE") {
                    entry.1 = v.clone();
                }
            } else {
                let cgi_key = format!("HTTP_{}", k.to_ascii_uppercase().replace('-', "_"));
                extra_headers.push((cgi_key, v.clone()));
            }
        }
        // Truyền nguyên bản Slice cặp (&str, String)
        let mut owned_pairs: Vec<(String, String)> = params
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        owned_pairs.extend(extra_headers);
        let ref_pairs: Vec<(&str, String)> = owned_pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();

        let timeout_dur = Duration::from_millis(cfg.proxy_read_timeout_ms.max(5000));
        return match tokio::time::timeout(
            timeout_dur,
            execute_fastcgi(&fpm_target, &ref_pairs, &req.body),
        )
        .await
        {
            Ok(Ok(fcgi_resp)) => HttpResponsePayload {
                status: fcgi_resp.status,
                headers: fcgi_resp.headers,
                body: fcgi_resp.body,
            },
            Ok(Err(err)) => {
                warn!(socket = %fpm_target, error = %err, "Lỗi thực thi PHP-FPM FastCGI");
                HttpResponsePayload {
                    status: StatusCode::BAD_GATEWAY,
                    headers: vec![("Content-Type".to_string(), "text/plain; charset=utf-8".to_string())],
                    body: Bytes::from(format!("502 Bad Gateway (PHP-FPM): {err}")),
                }
            }
            Err(_) => HttpResponsePayload {
                status: StatusCode::GATEWAY_TIMEOUT,
                headers: vec![("Content-Type".to_string(), "text/plain; charset=utf-8".to_string())],
                body: Bytes::from_static(b"504 Gateway Timeout (PHP-FPM)"),
            },
        };
    }

    // Phục vụ tệp tĩnh với MIME type chuẩn
    match tokio::fs::read(&target_file).await {
        Ok(bytes) => {
            let ext = target_file
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let mime = MimeDetector::get_mime_type(&ext);
            HttpResponsePayload {
                status: StatusCode::OK,
                headers: vec![("Content-Type".to_string(), mime.to_string())],
                body: Bytes::from(bytes),
            }
        }
        Err(_) => HttpResponsePayload {
            status: StatusCode::NOT_FOUND,
            headers: vec![("Content-Type".to_string(), "text/plain; charset=utf-8".to_string())],
            body: Bytes::from_static(b"404 Not Found"),
        },
    }
}

// ============================================================================
// REVERSE PROXY (CLOUDFLARE HEADERS + CHUNKED DECODE + WEBSOCKET TUNNELING)
// ============================================================================

/// Xác định IP thực của Client theo thứ tự ưu tiên:
/// `CF-Connecting-IP` (Cloudflare) -> IP đầu tiên trong `X-Forwarded-For` -> `peer_addr`
fn resolve_real_client_ip(req: &IncomingRequest) -> String {
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("cf-connecting-ip") && !v.trim().is_empty() {
            return v.trim().to_string();
        }
    }
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("x-forwarded-for") {
            if let Some(first) = v.split(',').next() {
                if !first.trim().is_empty() {
                    return first.trim().to_string();
                }
            }
        }
    }
    req.peer_ip.to_string()
}

fn is_request_https(req: &IncomingRequest) -> bool {
    if req.is_tls {
        return true;
    }
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("x-forwarded-proto")
            && v.trim().eq_ignore_ascii_case("https")
        {
            return true;
        }
    }
    false
}

/// Reverse Proxy HTTP/1.1 tới dịch vụ nội bộ (phpMyAdmin `127.0.0.1:888`, Ferrous-panel, Node.js, Python)
async fn proxy_http1_upstream(
    target_addr: &str,
    req: &IncomingRequest,
    cfg: &ServerConfig,
) -> HttpResponsePayload {
    let connect_timeout = Duration::from_millis(cfg.proxy_connect_timeout_ms.max(1000));
    let read_timeout = Duration::from_millis(cfg.proxy_read_timeout_ms.max(5000));

    let raw_upstream_resp = if let Some(sock_path) = target_addr.strip_prefix("unix:") {
        let Ok(Ok(mut stream)) = tokio::time::timeout(connect_timeout, UnixStream::connect(sock_path)).await else {
            return bad_gateway_response(target_addr);
        };
        let wire_req = build_upstream_http1_request(req, false);
        if stream.write_all(&wire_req).await.is_err() {
            return bad_gateway_response(target_addr);
        }
        match tokio::time::timeout(read_timeout, read_full_http1_response(&mut stream)).await {
            Ok(Ok(r)) => r,
            _ => return bad_gateway_response(target_addr),
        }
    } else {
        let Ok(Ok(mut stream)) = tokio::time::timeout(connect_timeout, TcpStream::connect(target_addr)).await else {
            return bad_gateway_response(target_addr);
        };
        let _ = stream.set_nodelay(true);
        let wire_req = build_upstream_http1_request(req, false);
        if stream.write_all(&wire_req).await.is_err() {
            return bad_gateway_response(target_addr);
        }
        match tokio::time::timeout(read_timeout, read_full_http1_response(&mut stream)).await {
            Ok(Ok(r)) => r,
            _ => return bad_gateway_response(target_addr),
        }
    };

    raw_upstream_resp
}

fn bad_gateway_response(target: &str) -> HttpResponsePayload {
    HttpResponsePayload {
        status: StatusCode::BAD_GATEWAY,
        headers: vec![("Content-Type".to_string(), "text/plain; charset=utf-8".to_string())],
        body: Bytes::from(format!("502 Bad Gateway: Không thể kết nối upstream {target}")),
    }
}

/// Đóng gói Request gửi tới Upstream kèm đầy đủ header Proxy chuẩn Cloudflare
fn build_upstream_http1_request(req: &IncomingRequest, keep_upgrade: bool) -> Vec<u8> {
    let real_ip = resolve_real_client_ip(req);
    let proto = if is_request_https(req) { "https" } else { "http" };
    let host_val = if req.host.is_empty() {
        "localhost".to_string()
    } else {
        req.host.clone()
    };

    let existing_xff = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-for"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let new_xff = if existing_xff.is_empty() {
        req.peer_ip.to_string()
    } else {
        format!("{existing_xff}, {}", req.peer_ip)
    };

    let mut out = Vec::with_capacity(1024 + req.body.len());
    out.extend_from_slice(format!("{} {} HTTP/1.1\r\n", req.method, req.raw_target).as_bytes());
    out.extend_from_slice(format!("Host: {host_val}\r\n").as_bytes());
    out.extend_from_slice(format!("X-Real-IP: {real_ip}\r\n").as_bytes());
    out.extend_from_slice(format!("X-Forwarded-For: {new_xff}\r\n").as_bytes());
    out.extend_from_slice(format!("X-Forwarded-Proto: {proto}\r\n").as_bytes());
    out.extend_from_slice(format!("X-Forwarded-Host: {host_val}\r\n").as_bytes());

    for (k, v) in &req.headers {
        let lower = k.to_ascii_lowercase();
        if lower == "host"
            || lower == "x-real-ip"
            || lower == "x-forwarded-for"
            || lower == "x-forwarded-proto"
            || lower == "x-forwarded-host"
            || lower == "content-length"
            || lower == "transfer-encoding"
        {
            continue;
        }
        if !keep_upgrade && (lower == "connection" || lower == "upgrade") {
            continue;
        }
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }

    if !keep_upgrade {
        out.extend_from_slice(b"Connection: close\r\n");
        if !req.body.is_empty() {
            out.extend_from_slice(format!("Content-Length: {}\r\n", req.body.len()).as_bytes());
        }
    }
    out.extend_from_slice(b"\r\n");
    if !req.body.is_empty() {
        out.extend_from_slice(&req.body);
    }
    out
}

/// Đọc phản hồi HTTP/1.1 từ Upstream, tự động giải mã `Transfer-Encoding: chunked` và giữ nguyên multi `Set-Cookie`
async fn read_full_http1_response<S>(stream: &mut S) -> Result<HttpResponsePayload>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut raw = Vec::with_capacity(16 * 1024);
    stream.read_to_end(&mut raw).await?;

    let Some(header_end) = find_double_crlf(&raw) else {
        return Ok(HttpResponsePayload {
            status: StatusCode::BAD_GATEWAY,
            headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
            body: Bytes::from_static(b"502 Invalid Upstream HTTP Response"),
        });
    };

    let mut headers_storage = [httparse::EMPTY_HEADER; 96];
    let mut resp = httparse::Response::new(&mut headers_storage);
    let _ = resp.parse(&raw[..header_end + 4])?;

    let status = resp
        .code
        .and_then(|c| StatusCode::from_u16(c).ok())
        .unwrap_or(StatusCode::OK);

    let mut is_chunked = false;
    let mut headers = Vec::with_capacity(resp.headers.len());
    for h in resp.headers.iter() {
        let name = h.name.to_string();
        let val = String::from_utf8_lossy(h.value).to_string();
        if name.eq_ignore_ascii_case("transfer-encoding")
            && val.to_ascii_lowercase().contains("chunked")
        {
            is_chunked = true;
            continue;
        }
        if name.eq_ignore_ascii_case("connection") || name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        headers.push((name, val));
    }

    let raw_body = &raw[header_end + 4..];
    let body = if is_chunked {
        decode_chunked_body(raw_body)
    } else {
        Bytes::copy_from_slice(raw_body)
    };

    Ok(HttpResponsePayload {
        status,
        headers,
        body,
    })
}

/// Đường hầm WebSocket Upgrade Full-Duplex (`Connection: Upgrade`, `Upgrade: websocket`)
/// phục vụ Web SSH Terminal & Real-Time Telemetry cho Ferrous-panel và vHost
async fn handle_websocket_upgrade<S>(
    mut client_stream: S,
    leftover_buf: BytesMut,
    req: IncomingRequest,
    cfg: &ServerConfig,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let host_no_port = strip_port(&req.host);
    let upstream_addr = if is_panel_request(&req, cfg) {
        cfg.panel_admin.panel_upstream_addr()
    } else if req.path.starts_with("/phpadmin/") || req.path.starts_with("/phpmyadmin/") {
        cfg.phpmyadmin_upstream.clone()
    } else if let Some(vhost) = match_virtual_host(host_no_port, cfg) {
        vhost
            .routes
            .iter()
            .find(|r| req.path.starts_with(&r.path_prefix))
            .and_then(|r| r.target_upstream.as_ref())
            .map(|u| resolve_upstream_addr(u, cfg))
            .unwrap_or_else(|| cfg.panel_admin.panel_upstream_addr())
    } else {
        cfg.panel_admin.panel_upstream_addr()
    };

    let clean_tcp_addr = upstream_addr
        .strip_prefix("http://")
        .or_else(|| upstream_addr.strip_prefix("ws://"))
        .unwrap_or(&upstream_addr)
        .trim_end_matches('/');

    let mut upstream = match TcpStream::connect(clean_tcp_addr).await {
        Ok(s) => s,
        Err(err) => {
            warn!(upstream = %clean_tcp_addr, error = %err, "WebSocket Upstream connect failed");
            write_simple_http1_error(&mut client_stream, StatusCode::BAD_GATEWAY, "WebSocket Upstream Unreachable").await?;
            return Ok(());
        }
    };
    let _ = upstream.set_nodelay(true);

    let handshake_bytes = build_upstream_http1_request(&req, true);
    upstream.write_all(&handshake_bytes).await?;
    if !leftover_buf.is_empty() {
        upstream.write_all(&leftover_buf).await?;
    }
    upstream.flush().await?;

    let _ = tokio::io::copy_bidirectional(&mut client_stream, &mut upstream).await;
    Ok(())
}

// ============================================================================
// HÀM TIỆN ÍCH PHỤ TRỢ
// ============================================================================

fn match_virtual_host<'a>(host_no_port: &str, cfg: &'a ServerConfig) -> Option<&'a VirtualHost> {
    for vhost in &cfg.vhosts {
        if vhost.server_name.eq_ignore_ascii_case(host_no_port)
            || vhost
                .aliases
                .iter()
                .any(|a| a.eq_ignore_ascii_case(host_no_port))
        {
            return Some(vhost);
        }
    }
    cfg.vhosts.iter().find(|v| v.server_name == "_")
}

fn resolve_upstream_addr(upstream_key: &str, cfg: &ServerConfig) -> String {
    if let Some(pool) = cfg.upstreams.get(upstream_key) {
        if let Some(ep) = pool.endpoints.first() {
            return ep.address.clone();
        }
    }
    upstream_key
        .strip_prefix("http://")
        .or_else(|| upstream_key.strip_prefix("https://"))
        .unwrap_or(upstream_key)
        .trim_end_matches('/')
        .to_string()
}

fn strip_port(host: &str) -> &str {
    if let Some(idx) = host.rfind(':') {
        if !host[idx + 1..].contains(']') {
            return &host[..idx];
        }
    }
    host
}

fn split_path_and_query(raw: &str) -> (String, String) {
    if let Some((p, q)) = raw.split_once('?') {
        (p.to_string(), q.to_string())
    } else {
        (raw.to_string(), String::new())
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn is_hop_by_hop_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailers")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
}

fn decode_chunked_body(raw: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(raw.len());
    let mut idx = 0;
    while idx < raw.len() {
        let Some(rel_crlf) = raw[idx..].windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let size_line = std::str::from_utf8(&raw[idx..idx + rel_crlf])
            .unwrap_or("0")
            .split(';')
            .next()
            .unwrap_or("0")
            .trim();
        let Ok(chunk_len) = usize::from_str_radix(size_line, 16) else {
            break;
        };
        idx += rel_crlf + 2;
        if chunk_len == 0 {
            break;
        }
        let end = (idx + chunk_len).min(raw.len());
        out.extend_from_slice(&raw[idx..end]);
        idx = end;
        if idx + 2 <= raw.len() && &raw[idx..idx + 2] == b"\r\n" {
            idx += 2;
        }
    }
    out.freeze()
}

async fn read_chunked_http1_body<S>(
    stream: &mut S,
    read_buf: &mut BytesMut,
    max_size: usize,
) -> Result<Bytes>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut out = BytesMut::new();
    loop {
        while !read_buf.windows(2).any(|w| w == b"\r\n") {
            let n = stream.read_buf(read_buf).await?;
            if n == 0 {
                return Ok(out.freeze());
            }
        }
        let crlf_pos = read_buf.windows(2).position(|w| w == b"\r\n").unwrap();
        let size_line = std::str::from_utf8(&read_buf[..crlf_pos])
            .unwrap_or("0")
            .split(';')
            .next()
            .unwrap_or("0")
            .trim();
        let chunk_len = usize::from_str_radix(size_line, 16).unwrap_or(0);
        let _ = read_buf.split_to(crlf_pos + 2);
        if chunk_len == 0 {
            if read_buf.len() >= 2 && &read_buf[..2] == b"\r\n" {
                let _ = read_buf.split_to(2);
            }
            return Ok(out.freeze());
        }
        if out.len() + chunk_len > max_size {
            anyhow::bail!("Chunked body vượt quá client_max_body_size");
        }
        while read_buf.len() < chunk_len + 2 {
            let n = stream.read_buf(read_buf).await?;
            if n == 0 {
                break;
            }
        }
        let take = chunk_len.min(read_buf.len());
        out.extend_from_slice(&read_buf.split_to(take));
        if read_buf.len() >= 2 && &read_buf[..2] == b"\r\n" {
            let _ = read_buf.split_to(2);
        }
    }
}

async fn write_http1_response<S>(
    stream: &mut S,
    resp: &HttpResponsePayload,
    cfg: &ServerConfig,
    keep_alive: bool,
) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let https_port = cfg.https_port();
    let reason = resp.status.canonical_reason().unwrap_or("OK");
    let mut head = Vec::with_capacity(512);

    head.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", resp.status.as_u16(), reason).as_bytes());
    head.extend_from_slice(b"Server: FerrousX/0.1 (Rust; io_uring; Thread-Per-Core)\r\n");
    head.extend_from_slice(
        format!(
            "Alt-Svc: h3=\":{https_port}\"; ma={}, h3-29=\":{https_port}\"; ma={}\r\n",
            cfg.alt_svc_max_age, cfg.alt_svc_max_age
        )
        .as_bytes(),
    );

    for (k, v) in &resp.headers {
        if is_hop_by_hop_header(k) || k.eq_ignore_ascii_case("content-length") {
            continue;
        }
        head.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }

    head.extend_from_slice(format!("Content-Length: {}\r\n", resp.body.len()).as_bytes());
    if keep_alive {
        head.extend_from_slice(b"Connection: keep-alive\r\n\r\n");
    } else {
        head.extend_from_slice(b"Connection: close\r\n\r\n");
    }

    stream.write_all(&head).await?;
    if !resp.body.is_empty() {
        stream.write_all(&resp.body).await?;
    }
    stream.flush().await?;
    Ok(())
}

async fn write_simple_http1_error<S>(stream: &mut S, status: StatusCode, msg: &str) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let reason = status.canonical_reason().unwrap_or("Error");
    let body = msg.as_bytes();
    let payload = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status.as_u16(),
        reason,
        body.len()
    );
    stream.write_all(payload.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}
