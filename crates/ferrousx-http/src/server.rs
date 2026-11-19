//! crates/ferrousx-http/src/server.rs
//! Động cơ phục vụ Triple-Stack đã gia cố bảo mật Production:
//!   - TCP HTTP/1.1 (:80) — Chống Request Smuggling (CL.TE / TE.CL), Slowloris, Slow POST, CRLF Injection
//!   - TCP HTTPS TLS 1.3/1.2 ALPN h2,http/1.1 (:443) — Giới hạn stream HTTP/2, chống Rapid Reset & Oversized Body
//!   - UDP HTTP/3 QUIC (:443) + quảng bá Alt-Svc — Giới hạn stream QUIC & chống Truncated Body
//! Hỗ trợ:
//!   - Tích hợp trực tiếp ZeroAllocWafEngine (GCRA Sharded IPv4/IPv6 Rate Limiter + DPI L7 WAF)
//!   - Xác thực Trusted Proxy CIDR trước khi tin cậy `CF-Connecting-IP` / `X-Forwarded-For` / `X-Forwarded-Proto`
//!   - Chống SSRF (chặn Cloud Metadata 169.254.169.254, link-local, broadcast) & giới hạn kích thước phản hồi Upstream
//!   - Đồng bộ động `/etc/ferrous-panel/panel.env` & `admin.json`
//!   - WebSocket Upgrade Tunneling (`Connection: Upgrade`, `Upgrade: websocket`)
//!   - Định tuyến phpMyAdmin (`/phpadmin`, `/phpmyadmin` -> 302 + proxy `127.0.0.1:888`)
//!   - Thực thi PHP-FPM FastCGI chuẩn + bảo vệ Path Traversal & Httpoxy cho `/www/wwwroot/<domain>`

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderName, HeaderValue, Response, StatusCode};
use quinn::{Endpoint, EndpointConfig, ServerConfig as QuinnServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::task::LocalSet;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use ferrousx_config::config::{
    is_forbidden_ssrf_ip, validate_upstream_origin, BackendProtocol, CompressionConfig,
    ConfigManager, ServerConfig, VirtualHost, WafMode,
};
use ferrousx_core::metrics::EngineRuntimeStats;
use ferrousx_proxy::fastcgi::{detect_php_fpm_socket, execute_fastcgi, safe_resolve_under_root};
use ferrousx_proxy::pipeline::{
    compress_response_body, CgiEnvironment, ContentEncoding, LiveBackendNode, MimeDetector,
    UpstreamBalancer,
};
use ferrousx_proxy::waf::{WafDecision, ZeroAllocWafEngine};

use crate::acme::AcmeCertManager;

/// Bộ đếm kết nối đồng thời toàn cục và theo từng IP để chống cạn kiệt File Descriptor / DoS
pub struct ActiveConnectionTracker {
    total_active: AtomicUsize,
    per_ip_active: Mutex<HashMap<IpAddr, usize>>,
    stats: Arc<EngineRuntimeStats>,
}

impl ActiveConnectionTracker {
    pub fn new(stats: Arc<EngineRuntimeStats>) -> Arc<Self> {
        Arc::new(Self {
            total_active: AtomicUsize::new(0),
            per_ip_active: Mutex::new(HashMap::with_capacity(1024)),
            stats,
        })
    }

    pub fn try_acquire(
        self: &Arc<Self>,
        ip: IpAddr,
        max_total: usize,
        max_per_ip: usize,
    ) -> Option<ConnectionGuard> {
        let current_total = self.total_active.load(Ordering::Relaxed);
        if max_total > 0 && current_total >= max_total {
            return None;
        }

        if let Ok(mut map) = self.per_ip_active.lock() {
            // Tránh phình bộ nhớ nếu bị flood từ hàng vạn IP giả mạo
            if map.len() >= 65_536 && !map.contains_key(&ip) {
                map.retain(|_, count| *count > 0);
                if map.len() >= 65_536 {
                    return None;
                }
            }
            let entry = map.entry(ip).or_insert(0);
            if max_per_ip > 0 && *entry >= max_per_ip {
                return None;
            }
            *entry += 1;
        }

        self.total_active.fetch_add(1, Ordering::Relaxed);
        self.stats.active_connections.fetch_add(1, Ordering::Relaxed);
        Some(ConnectionGuard {
            tracker: Arc::clone(self),
            ip,
        })
    }
}

pub struct ConnectionGuard {
    tracker: Arc<ActiveConnectionTracker>,
    ip: IpAddr,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.tracker.total_active.fetch_sub(1, Ordering::Relaxed);
        self.tracker
            .stats
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
        if let Ok(mut map) = self.tracker.per_ip_active.lock() {
            if let Some(count) = map.get_mut(&self.ip) {
                if *count <= 1 {
                    map.remove(&self.ip);
                } else {
                    *count -= 1;
                }
            }
        }
    }
}

/// Bộ quản lý cân bằng tải P2C/Round-Robin + CircuitBreaker theo từng Epoch cấu hình
struct UpstreamBalancerRegistry {
    inner: RwLock<(u64, HashMap<String, Arc<UpstreamBalancer>>)>,
}

enum UpstreamPickResult {
    PoolNode(Arc<LiveBackendNode>),
    LiteralAddr(String),
    CircuitBreakerOpen,
}

impl UpstreamBalancerRegistry {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: RwLock::new((0, HashMap::new())),
        })
    }

    fn resolve_target(
        &self,
        upstream_key: &str,
        seed: u64,
        cfg: &ServerConfig,
    ) -> UpstreamPickResult {
        if !cfg.upstreams.contains_key(upstream_key) {
            return UpstreamPickResult::LiteralAddr(resolve_upstream_addr(upstream_key, cfg));
        }

        let now_ms = current_unix_ms();
        let has_endpoints = cfg
            .upstreams
            .get(upstream_key)
            .map(|p| !p.endpoints.is_empty())
            .unwrap_or(false);
        if !has_endpoints {
            return UpstreamPickResult::LiteralAddr(resolve_upstream_addr(upstream_key, cfg));
        }

        if let Ok(guard) = self.inner.read() {
            if guard.0 == cfg.version_epoch {
                if let Some(balancer) = guard.1.get(upstream_key) {
                    return match balancer.pick_healthy_node(seed, now_ms) {
                        Some(node) => UpstreamPickResult::PoolNode(node),
                        None => UpstreamPickResult::CircuitBreakerOpen,
                    };
                }
            }
        }

        if let Ok(mut guard) = self.inner.write() {
            if guard.0 != cfg.version_epoch {
                let mut map = HashMap::with_capacity(cfg.upstreams.len());
                for (name, pool) in &cfg.upstreams {
                    let addrs: Vec<String> =
                        pool.endpoints.iter().map(|e| e.address.clone()).collect();
                    let balancer = UpstreamBalancer::with_circuit_config(
                        pool.algorithm,
                        addrs,
                        cfg.circuit_breaker_max_fails,
                        cfg.circuit_breaker_cooldown_ms,
                    );
                    map.insert(name.clone(), Arc::new(balancer));
                }
                *guard = (cfg.version_epoch, map);
            }
            if let Some(balancer) = guard.1.get(upstream_key) {
                return match balancer.pick_healthy_node(seed, now_ms) {
                    Some(node) => UpstreamPickResult::PoolNode(node),
                    None => UpstreamPickResult::CircuitBreakerOpen,
                };
            }
        }

        UpstreamPickResult::LiteralAddr(resolve_upstream_addr(upstream_key, cfg))
    }
}

#[inline]
fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn compute_request_seed(req: &IncomingRequest) -> u64 {
    let mut hasher = DefaultHasher::new();
    req.peer_ip.hash(&mut hasher);
    req.raw_target.hash(&mut hasher);
    hasher.finish()
}

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

/// Phân loại lỗi đọc Chunked Body để trả đúng mã HTTP (400 vs 413 vs 408)
#[derive(Debug)]
enum ChunkReadError {
    PayloadTooLarge,
    MalformedChunk(&'static str),
    IoError(std::io::Error),
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
    acme_mgr: Arc<AcmeCertManager>,
) -> Result<()> {
    let worker_id = ctx.worker_id;
    let config_mgr = Arc::clone(&ctx.config_mgr);
    let stats = Arc::clone(&ctx.stats);
    let initial_cfg = config_mgr.current();

    let waf_engine = Arc::new(ZeroAllocWafEngine::with_full_config(
        initial_cfg.waf.rate_limit_rps,
        initial_cfg.waf.rate_limit_burst,
        initial_cfg.waf.rate_limit_max_entries,
        initial_cfg.waf.rate_limit_ttl_secs,
        initial_cfg.waf.max_inspect_body_bytes,
        initial_cfg.max_request_line_bytes,
    ));
    let conn_tracker = ActiveConnectionTracker::new(Arc::clone(&stats));
    let upstream_reg = UpstreamBalancerRegistry::new();

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
        numa_node = ctx.numa_node,
        hugepage_pinned = ctx.hugepage_arena.is_some(),
        quic_enabled = quic_endpoint.is_some(),
        waf_enabled = initial_cfg.waf.enabled,
        "Worker sẵn sàng tiếp nhận lưu lượng Triple-Stack (TCP :80 HTTP + TCP :443 TLS + UDP :443 QUIC)"
    );

    let local_tasks = LocalSet::new();
    local_tasks
        .run_until(async move {
            if let Some(endpoint) = quic_endpoint {
                tokio::try_join!(
                    run_tcp_plain_http_loop(
                        worker_id,
                        http_listener,
                        Arc::clone(&config_mgr),
                        Arc::clone(&waf_engine),
                        Arc::clone(&conn_tracker),
                        Arc::clone(&stats),
                        Arc::clone(&acme_mgr),
                        Arc::clone(&upstream_reg),
                    ),
                    run_tcp_https_loop(
                        worker_id,
                        https_listener,
                        tls_acceptor,
                        Arc::clone(&config_mgr),
                        Arc::clone(&waf_engine),
                        Arc::clone(&conn_tracker),
                        Arc::clone(&stats),
                        Arc::clone(&acme_mgr),
                        Arc::clone(&upstream_reg),
                    ),
                    run_udp_h3_quic_loop(
                        worker_id,
                        endpoint,
                        config_mgr,
                        waf_engine,
                        conn_tracker,
                        stats,
                        acme_mgr,
                        upstream_reg,
                    ),
                )
                .map(|_| ())
            } else {
                tokio::try_join!(
                    run_tcp_plain_http_loop(
                        worker_id,
                        http_listener,
                        Arc::clone(&config_mgr),
                        Arc::clone(&waf_engine),
                        Arc::clone(&conn_tracker),
                        Arc::clone(&stats),
                        Arc::clone(&acme_mgr),
                        Arc::clone(&upstream_reg),
                    ),
                    run_tcp_https_loop(
                        worker_id,
                        https_listener,
                        tls_acceptor,
                        config_mgr,
                        waf_engine,
                        conn_tracker,
                        stats,
                        acme_mgr,
                        upstream_reg,
                    ),
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
    waf_engine: Arc<ZeroAllocWafEngine>,
    conn_tracker: Arc<ActiveConnectionTracker>,
    stats: Arc<EngineRuntimeStats>,
    acme_mgr: Arc<AcmeCertManager>,
    upstream_reg: Arc<UpstreamBalancerRegistry>,
) -> Result<()> {
    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;
        let cfg = config_mgr.current();
        let Some(_guard) = conn_tracker.try_acquire(
            peer_addr.ip(),
            cfg.max_concurrent_connections,
            cfg.max_connections_per_ip,
        ) else {
            warn!(worker_id, ip = %peer_addr.ip(), "Từ chối kết nối TCP :80 do vượt ngưỡng kết nối đồng thời");
            drop(tcp_stream);
            continue;
        };

        let _ = tcp_stream.set_nodelay(true);
        let cfg_mgr = Arc::clone(&config_mgr);
        let waf = Arc::clone(&waf_engine);
        let st = Arc::clone(&stats);
        let acme = Arc::clone(&acme_mgr);
        let reg = Arc::clone(&upstream_reg);

        tokio::task::spawn_local(async move {
            let _conn_guard = _guard;
            if let Err(e) =
                serve_http1_connection(tcp_stream, peer_addr, false, cfg_mgr, waf, st, acme, reg)
                    .await
            {
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
    waf_engine: Arc<ZeroAllocWafEngine>,
    conn_tracker: Arc<ActiveConnectionTracker>,
    stats: Arc<EngineRuntimeStats>,
    acme_mgr: Arc<AcmeCertManager>,
    upstream_reg: Arc<UpstreamBalancerRegistry>,
) -> Result<()> {
    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;
        let cfg = config_mgr.current();
        let Some(_guard) = conn_tracker.try_acquire(
            peer_addr.ip(),
            cfg.max_concurrent_connections,
            cfg.max_connections_per_ip,
        ) else {
            warn!(worker_id, ip = %peer_addr.ip(), "Từ chối kết nối TLS :443 do vượt ngưỡng kết nối đồng thời");
            drop(tcp_stream);
            continue;
        };

        let _ = tcp_stream.set_nodelay(true);

        let acceptor = tls_acceptor.clone();
        let cfg_mgr = Arc::clone(&config_mgr);
        let waf = Arc::clone(&waf_engine);
        let st = Arc::clone(&stats);
        let acme = Arc::clone(&acme_mgr);
        let reg = Arc::clone(&upstream_reg);
        let handshake_timeout = Duration::from_millis(cfg.client_header_timeout_ms.max(5000));

        tokio::task::spawn_local(async move {
            let _conn_guard = _guard;
            match tokio::time::timeout(handshake_timeout, acceptor.accept(tcp_stream)).await {
                Ok(Ok(tls_stream)) => {
                    let (_, server_conn) = tls_stream.get_ref();
                    let negotiated_alpn = server_conn
                        .alpn_protocol()
                        .map(|p| p.to_vec())
                        .unwrap_or_else(|| b"http/1.1".to_vec());

                    if negotiated_alpn.as_slice() == b"h2" {
                        if let Err(e) = serve_http2_connection(
                            tls_stream, peer_addr, cfg_mgr, waf, st, acme, reg,
                        )
                        .await
                        {
                            debug!(worker_id, %peer_addr, error = %e, "Kết thúc phiên HTTPS HTTP/2 (:443)");
                        }
                    } else if let Err(e) = serve_http1_connection(
                        tls_stream, peer_addr, true, cfg_mgr, waf, st, acme, reg,
                    )
                    .await
                    {
                        debug!(worker_id, %peer_addr, error = %e, "Kết thúc phiên HTTPS HTTP/1.1 (:443)");
                    }
                }
                Ok(Err(err)) => {
                    debug!(worker_id, %peer_addr, error = %err, "Bắt tay TLS (:443) thất bại");
                }
                Err(_) => {
                    debug!(worker_id, %peer_addr, "Quá thời gian chờ bắt tay TLS (:443)");
                }
            }
        });
    }
}

/// Xử lý HTTP/1.1 Keep-Alive, chống HTTP Request Smuggling (CL.TE / TE.CL / Duplicate CL),
/// Slowloris, Slow POST, và hỗ trợ WebSocket Upgrade Tunneling
async fn serve_http1_connection<S>(
    mut stream: S,
    peer_addr: SocketAddr,
    is_tls: bool,
    config_mgr: Arc<ConfigManager>,
    waf_engine: Arc<ZeroAllocWafEngine>,
    stats: Arc<EngineRuntimeStats>,
    acme_mgr: Arc<AcmeCertManager>,
    upstream_reg: Arc<UpstreamBalancerRegistry>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut read_buf = BytesMut::with_capacity(16 * 1024);
    let mut requests_served: usize = 0;

    loop {
        let cfg = config_mgr.current();
        let header_timeout = if requests_served == 0 {
            Duration::from_millis(cfg.client_header_timeout_ms.max(1000))
        } else {
            Duration::from_millis(cfg.keepalive_timeout_ms.max(1000))
        };
        let max_header_bytes = cfg.max_header_bytes.clamp(4096, 64 * 1024);
        let max_req_line_bytes = cfg.max_request_line_bytes.clamp(1024, 32 * 1024);

        // Áp dụng tổng deadline cho toàn bộ quá trình đọc Header để chống Slowloris (gửi từng byte)
        let header_read_res = tokio::time::timeout(header_timeout, async {
            loop {
                if let Some(pos) = find_double_crlf(&read_buf) {
                    return Ok::<Option<usize>, std::io::Error>(Some(pos));
                }
                if read_buf.len() > max_header_bytes {
                    return Ok(Some(usize::MAX));
                }
                let n = stream.read_buf(&mut read_buf).await?;
                if n == 0 {
                    return Ok(None);
                }
            }
        })
        .await;

        let header_end = match header_read_res {
            Ok(Ok(Some(usize::MAX))) => {
                write_simple_http1_error(
                    &mut stream,
                    StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                    "431 Request Header Fields Too Large",
                )
                .await?;
                return Ok(());
            }
            Ok(Ok(Some(pos))) => pos,
            Ok(Ok(None)) => {
                // Client đóng kết nối; nếu đang gửi dở header thì đóng ngay
                return Ok(());
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                // Nếu đã gửi một phần dữ liệu header nhưng quá hạn -> trả 408 Request Timeout
                if !read_buf.is_empty() {
                    let _ = write_simple_http1_error(
                        &mut stream,
                        StatusCode::REQUEST_TIMEOUT,
                        "408 Request Timeout (Slowloris Shield)",
                    )
                    .await;
                }
                return Ok(());
            }
        };

        // Kiểm tra độ dài Request Line (dòng đầu tiên trước \r\n)
        if let Some(first_crlf) = read_buf[..header_end].windows(2).position(|w| w == b"\r\n") {
            if first_crlf > max_req_line_bytes {
                write_simple_http1_error(
                    &mut stream,
                    StatusCode::URI_TOO_LONG,
                    "414 URI Too Long",
                )
                .await?;
                return Ok(());
            }
        } else if header_end > max_req_line_bytes {
            write_simple_http1_error(&mut stream, StatusCode::URI_TOO_LONG, "414 URI Too Long")
                .await?;
            return Ok(());
        }

        let mut headers_storage = [httparse::EMPTY_HEADER; 96];
        let mut req = httparse::Request::new(&mut headers_storage);
        let parse_status = match req.parse(&read_buf[..header_end + 4]) {
            Ok(status) => status,
            Err(_) => {
                write_simple_http1_error(
                    &mut stream,
                    StatusCode::BAD_REQUEST,
                    "400 Bad Request: Malformed HTTP Header Framing",
                )
                .await?;
                return Ok(());
            }
        };
        if !parse_status.is_complete() {
            write_simple_http1_error(
                &mut stream,
                StatusCode::BAD_REQUEST,
                "400 Bad Request: Incomplete HTTP Headers",
            )
            .await?;
            return Ok(());
        }

        let method = req.method.unwrap_or("").to_string();
        let raw_target = req.path.unwrap_or("").to_string();
        let version = req.version.unwrap_or(1);

        if method.is_empty()
            || raw_target.is_empty()
            || (!raw_target.starts_with('/') && raw_target != "*")
            || raw_target.bytes().any(|b| b < 0x20 || b == 0x7f)
        {
            write_simple_http1_error(
                &mut stream,
                StatusCode::BAD_REQUEST,
                "400 Bad Request: Invalid Request Target",
            )
            .await?;
            return Ok(());
        }

        let (path, query) = split_path_and_query(&raw_target);

        let mut host = String::new();
        let mut host_count: usize = 0;
        let mut parsed_content_length: Option<usize> = None;
        let mut te_count: usize = 0;
        let mut is_chunked = false;
        let mut conn_close = version == 0; // HTTP/1.0 mặc định đóng kết nối nếu không có keep-alive
        let mut is_upgrade_conn = false;
        let mut is_websocket_upgrade = false;
        let mut parsed_headers = Vec::with_capacity(req.headers.len());

        for h in req.headers.iter() {
            let name = h.name;
            // Chặn khoảng trắng hoặc ký tự điều khiển trong tên header (RFC 9112 §5.1)
            if name.is_empty()
                || name
                    .bytes()
                    .any(|b| b <= 0x20 || b == 0x7f || b == b':')
            {
                write_simple_http1_error(
                    &mut stream,
                    StatusCode::BAD_REQUEST,
                    "400 Bad Request: Invalid Header Name",
                )
                .await?;
                return Ok(());
            }
            // Chặn NUL / CR / LF trong giá trị header (chống CRLF Header Injection)
            if h.value.iter().any(|&b| b == 0 || b == b'\r' || b == b'\n') {
                write_simple_http1_error(
                    &mut stream,
                    StatusCode::BAD_REQUEST,
                    "400 Bad Request: Header Value Contains Control Characters",
                )
                .await?;
                return Ok(());
            }

            let val = match std::str::from_utf8(h.value) {
                Ok(s) => s.trim().to_string(),
                Err(_) => {
                    write_simple_http1_error(
                        &mut stream,
                        StatusCode::BAD_REQUEST,
                        "400 Bad Request: Non-UTF8 Header Value",
                    )
                    .await?;
                    return Ok(());
                }
            };

            if name.eq_ignore_ascii_case("host") {
                host_count += 1;
                if host_count > 1 || val.contains('/') || val.contains('\\') || val.contains('@') {
                    write_simple_http1_error(
                        &mut stream,
                        StatusCode::BAD_REQUEST,
                        "400 Bad Request: Duplicate or Malformed Host Header",
                    )
                    .await?;
                    return Ok(());
                }
                host = val.clone();
            } else if name.eq_ignore_ascii_case("content-length") {
                // Chặn Content-Length không phải chuỗi số thập phân thuần túy (ví dụ "+5", "-1", "10, 10", "abc")
                if val.is_empty() || !val.bytes().all(|b| b.is_ascii_digit()) {
                    write_simple_http1_error(
                        &mut stream,
                        StatusCode::BAD_REQUEST,
                        "400 Bad Request: Invalid Content-Length",
                    )
                    .await?;
                    return Ok(());
                }
                let Ok(cl) = val.parse::<usize>() else {
                    write_simple_http1_error(
                        &mut stream,
                        StatusCode::BAD_REQUEST,
                        "400 Bad Request: Content-Length Overflow",
                    )
                    .await?;
                    return Ok(());
                };
                if let Some(prev_cl) = parsed_content_length {
                    // Chặn Duplicate Content-Length có giá trị khác nhau (RFC 9112 §6.3)
                    if prev_cl != cl {
                        write_simple_http1_error(
                            &mut stream,
                            StatusCode::BAD_REQUEST,
                            "400 Bad Request: Conflicting Content-Length Headers",
                        )
                        .await?;
                        return Ok(());
                    }
                }
                parsed_content_length = Some(cl);
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                te_count += 1;
                // Chỉ chấp nhận duy nhất 1 header Transfer-Encoding với giá trị chính xác "chunked"
                if te_count > 1 || !val.eq_ignore_ascii_case("chunked") {
                    write_simple_http1_error(
                        &mut stream,
                        StatusCode::BAD_REQUEST,
                        "400 Bad Request: Unsupported or Duplicate Transfer-Encoding",
                    )
                    .await?;
                    return Ok(());
                }
                is_chunked = true;
            } else if name.eq_ignore_ascii_case("connection") {
                let low = val.to_ascii_lowercase();
                if low.contains("close") {
                    conn_close = true;
                } else if low.contains("keep-alive") && version == 0 {
                    conn_close = false;
                }
                if low.contains("upgrade") {
                    is_upgrade_conn = true;
                }
            } else if name.eq_ignore_ascii_case("upgrade")
                && val.eq_ignore_ascii_case("websocket")
            {
                is_websocket_upgrade = true;
            }
            parsed_headers.push((name.to_string(), val));
        }

        // HTTP/1.1 bắt buộc phải có đúng 1 Host header (RFC 9112 §3.2)
        if version >= 1 && host_count == 0 {
            write_simple_http1_error(
                &mut stream,
                StatusCode::BAD_REQUEST,
                "400 Bad Request: Missing Host Header in HTTP/1.1",
            )
            .await?;
            return Ok(());
        }

        // Chống HTTP Request Smuggling (CL.TE / TE.CL): Cấm tuyệt đối gửi đồng thời Content-Length và Transfer-Encoding!
        if is_chunked && parsed_content_length.is_some() {
            warn!(
                peer = %peer_addr,
                target = %raw_target,
                "Phát hiện và chặn tấn công HTTP Request Smuggling (CL.TE / TE.CL)"
            );
            write_simple_http1_error(
                &mut stream,
                StatusCode::BAD_REQUEST,
                "400 Bad Request: Both Content-Length and Transfer-Encoding Present (Smuggling Blocked)",
            )
            .await?;
            return Ok(());
        }

        let content_length = parsed_content_length.unwrap_or(0);

        // Bỏ phần header khỏi buffer, giữ lại phần body đã đọc kèm
        let _ = read_buf.split_to(header_end + 4);

        // Nếu là WebSocket Upgrade (`Connection: Upgrade` + `Upgrade: websocket`),
        // kiểm tra WAF rồi chuyển giao toàn quyền stream sang đường hầm hai chiều Full-Duplex!
        if is_upgrade_conn && is_websocket_upgrade {
            stats.total_requests.fetch_add(1, Ordering::Relaxed);
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
            if let Some(waf_resp) = check_waf_for_request(&incoming, &cfg, &waf_engine, &stats) {
                let emit_alt = should_emit_alt_svc(&incoming.host, &cfg);
                write_http1_response(&mut stream, &waf_resp, &cfg, false, emit_alt, &stats).await?;
                return Ok(());
            }
            return handle_websocket_upgrade(stream, read_buf, incoming, &cfg, &upstream_reg).await;
        }

        if content_length > cfg.client_max_body_size {
            write_simple_http1_error(
                &mut stream,
                StatusCode::PAYLOAD_TOO_LARGE,
                "413 Payload Too Large: Body Exceeds client_max_body_size",
            )
            .await?;
            return Ok(());
        }

        let body_timeout = Duration::from_millis(cfg.client_body_timeout_ms.max(1000));

        // Đọc đủ phần thân Request Body dưới sự giám sát của client_body_timeout_ms (chống Slow POST)
        let body = if is_chunked {
            match tokio::time::timeout(
                body_timeout,
                read_chunked_http1_body(&mut stream, &mut read_buf, cfg.client_max_body_size),
            )
            .await
            {
                Ok(Ok(bytes)) => bytes,
                Ok(Err(ChunkReadError::PayloadTooLarge)) => {
                    write_simple_http1_error(
                        &mut stream,
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "413 Payload Too Large: Chunked Body Exceeds client_max_body_size",
                    )
                    .await?;
                    return Ok(());
                }
                Ok(Err(ChunkReadError::MalformedChunk(reason))) => {
                    write_simple_http1_error(&mut stream, StatusCode::BAD_REQUEST, reason).await?;
                    return Ok(());
                }
                Ok(Err(ChunkReadError::IoError(e))) => return Err(e.into()),
                Err(_) => {
                    write_simple_http1_error(
                        &mut stream,
                        StatusCode::REQUEST_TIMEOUT,
                        "408 Request Timeout: Slow Chunked Body Read",
                    )
                    .await?;
                    return Ok(());
                }
            }
        } else if content_length > 0 {
            let read_res = tokio::time::timeout(body_timeout, async {
                while read_buf.len() < content_length {
                    let n = stream.read_buf(&mut read_buf).await?;
                    if n == 0 {
                        return Ok::<bool, std::io::Error>(false);
                    }
                }
                Ok(true)
            })
            .await;

            match read_res {
                Ok(Ok(true)) => read_buf.split_to(content_length).freeze(),
                Ok(Ok(false)) => {
                    // Client đóng kết nối trước khi gửi đủ số byte Content-Length -> Từ chối xử lý!
                    write_simple_http1_error(
                        &mut stream,
                        StatusCode::BAD_REQUEST,
                        "400 Bad Request: Unexpected EOF While Reading Request Body",
                    )
                    .await?;
                    return Ok(());
                }
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => {
                    write_simple_http1_error(
                        &mut stream,
                        StatusCode::REQUEST_TIMEOUT,
                        "408 Request Timeout: Slow POST Body Read",
                    )
                    .await?;
                    return Ok(());
                }
            }
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

        let resp = dispatch_http_request(&incoming, &cfg, &waf_engine, &stats, &acme_mgr, &upstream_reg).await;
        // Nếu phản hồi là lỗi giao thức hoặc quá tải (400/408/413/429/431), luôn đóng kết nối
        let force_close = matches!(
            resp.status,
            StatusCode::BAD_REQUEST
                | StatusCode::REQUEST_TIMEOUT
                | StatusCode::PAYLOAD_TOO_LARGE
                | StatusCode::URI_TOO_LONG
                | StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
                | StatusCode::TOO_MANY_REQUESTS
        );
        let keep_alive = !conn_close && !force_close;
        let emit_alt = should_emit_alt_svc(&incoming.host, &cfg);

        write_http1_response(&mut stream, &resp, &cfg, keep_alive, emit_alt, &stats).await?;
        requests_served += 1;

        if !keep_alive {
            return Ok(());
        }
    }
}

/// Phục vụ đa luồng khung (multiplexed frames) HTTP/2 trên kết nối TCP TLS 1.3/1.2 (:443)
async fn serve_http2_connection<S>(
    stream: S,
    peer_addr: SocketAddr,
    config_mgr: Arc<ConfigManager>,
    waf_engine: Arc<ZeroAllocWafEngine>,
    stats: Arc<EngineRuntimeStats>,
    acme_mgr: Arc<AcmeCertManager>,
    upstream_reg: Arc<UpstreamBalancerRegistry>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
{
    let initial_cfg = config_mgr.current();
    let mut h2_builder = h2::server::Builder::new();
    h2_builder
        .max_concurrent_streams(initial_cfg.h2_max_concurrent_streams)
        .max_header_list_size(initial_cfg.h2_max_header_list_size);

    let mut h2_conn = h2_builder.handshake(stream).await?;

    while let Some(result) = h2_conn.accept().await {
        let (request, mut respond) = result?;
        let cfg_mgr = Arc::clone(&config_mgr);
        let waf = Arc::clone(&waf_engine);
        let st = Arc::clone(&stats);
        let acme = Arc::clone(&acme_mgr);
        let reg = Arc::clone(&upstream_reg);

        tokio::task::spawn_local(async move {
            let cfg = cfg_mgr.current();
            let (parts, mut body_stream) = request.into_parts();

            // Kiểm tra sớm Content-Length trong HTTP/2 nếu có
            if let Some(cl_val) = parts.headers.get(http::header::CONTENT_LENGTH) {
                if let Ok(cl_str) = cl_val.to_str() {
                    if let Ok(cl) = cl_str.trim().parse::<usize>() {
                        if cl > cfg.client_max_body_size {
                            send_h2_simple_error(
                                &mut respond,
                                StatusCode::PAYLOAD_TOO_LARGE,
                                b"413 Payload Too Large",
                            );
                            return;
                        }
                    }
                }
            }

            let body_timeout = Duration::from_millis(cfg.client_body_timeout_ms.max(1000));
            let mut body_buf = BytesMut::new();
            let mut body_too_large = false;
            let mut body_err = false;

            let read_res = tokio::time::timeout(body_timeout, async {
                while let Some(chunk_res) = body_stream.data().await {
                    match chunk_res {
                        Ok(chunk) => {
                            if body_buf.len() + chunk.len() > cfg.client_max_body_size {
                                body_too_large = true;
                                break;
                            }
                            body_buf.extend_from_slice(&chunk);
                            let _ = body_stream.flow_control().release_capacity(chunk.len());
                        }
                        Err(_) => {
                            body_err = true;
                            break;
                        }
                    }
                }
            })
            .await;

            if read_res.is_err() {
                send_h2_simple_error(
                    &mut respond,
                    StatusCode::REQUEST_TIMEOUT,
                    b"408 Request Timeout",
                );
                return;
            }
            if body_too_large {
                send_h2_simple_error(
                    &mut respond,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    b"413 Payload Too Large",
                );
                return;
            }
            if body_err {
                send_h2_simple_error(&mut respond, StatusCode::BAD_REQUEST, b"400 Bad Request");
                return;
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

            let resp_payload = dispatch_http_request(&incoming, &cfg, &waf, &st, &acme, &reg).await;
            let mut builder = Response::builder().status(resp_payload.status);
            let https_port = cfg.https_port();
            let emit_alt_svc = should_emit_alt_svc(&incoming.host, &cfg);
            let alt_svc_val = format!("h3=\":{https_port}\"; ma={}", cfg.alt_svc_max_age);

            if let Some(hmap) = builder.headers_mut() {
                if emit_alt_svc {
                    if let Ok(hv) = HeaderValue::from_str(&alt_svc_val) {
                        hmap.append(HeaderName::from_static("alt-svc"), hv);
                    }
                }
                if cfg.server_tokens {
                    hmap.append(
                        HeaderName::from_static("server"),
                        HeaderValue::from_static("FerrousX"),
                    );
                }
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
                        let body_len = resp_payload.body.len() as u64;
                        if send_stream.send_data(resp_payload.body, true).is_ok() {
                            st.bytes_sent.fetch_add(body_len, Ordering::Relaxed);
                        }
                    }
                }
            }
        });
    }
    Ok(())
}

fn send_h2_simple_error(
    respond: &mut h2::server::SendResponse<Bytes>,
    status: StatusCode,
    msg: &'static [u8],
) {
    let mut builder = Response::builder().status(status);
    if let Some(hmap) = builder.headers_mut() {
        hmap.append(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
    }
    if let Ok(resp) = builder.body(()) {
        if let Ok(mut send_stream) = respond.send_response(resp, false) {
            let _ = send_stream.send_data(Bytes::from_static(msg), true);
        }
    }
}

/// Vòng lặp tiếp nhận kết nối UDP QUIC và phân luồng HTTP/3 (RFC 9114)
async fn run_udp_h3_quic_loop(
    worker_id: usize,
    endpoint: Endpoint,
    config_mgr: Arc<ConfigManager>,
    waf_engine: Arc<ZeroAllocWafEngine>,
    conn_tracker: Arc<ActiveConnectionTracker>,
    stats: Arc<EngineRuntimeStats>,
    acme_mgr: Arc<AcmeCertManager>,
    upstream_reg: Arc<UpstreamBalancerRegistry>,
) -> Result<()> {
    while let Some(incoming_handshake) = endpoint.accept().await {
        let peer_addr = incoming_handshake.remote_address();
        let cfg = config_mgr.current();
        let Some(_guard) = conn_tracker.try_acquire(
            peer_addr.ip(),
            cfg.max_concurrent_connections,
            cfg.max_connections_per_ip,
        ) else {
            warn!(worker_id, ip = %peer_addr.ip(), "Từ chối kết nối QUIC :443 do vượt ngưỡng kết nối đồng thời");
            incoming_handshake.refuse();
            continue;
        };

        let cfg_mgr = Arc::clone(&config_mgr);
        let waf = Arc::clone(&waf_engine);
        let st = Arc::clone(&stats);
        let acme = Arc::clone(&acme_mgr);
        let reg = Arc::clone(&upstream_reg);

        tokio::task::spawn_local(async move {
            let _conn_guard = _guard;
            match incoming_handshake.await {
                Ok(quic_conn) => {
                    let remote = quic_conn.remote_address();
                    if let Err(err) =
                        serve_http3_quic_streams(quic_conn, remote, cfg_mgr, waf, st, acme, reg)
                            .await
                    {
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
    waf_engine: Arc<ZeroAllocWafEngine>,
    stats: Arc<EngineRuntimeStats>,
    acme_mgr: Arc<AcmeCertManager>,
    upstream_reg: Arc<UpstreamBalancerRegistry>,
) -> Result<()> {
    let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
        h3::server::Connection::new(h3_quinn::Connection::new(quic_conn)).await?;

    loop {
        match h3_conn.accept().await {
            Ok(Some((req, mut stream))) => {
                let cfg_mgr = Arc::clone(&config_mgr);
                let waf = Arc::clone(&waf_engine);
                let st = Arc::clone(&stats);
                let acme = Arc::clone(&acme_mgr);
                let reg = Arc::clone(&upstream_reg);
                tokio::task::spawn_local(async move {
                    st.http3_requests.fetch_add(1, Ordering::Relaxed);
                    let cfg = cfg_mgr.current();
                    let (parts, ()) = req.into_parts();

                    // Kiểm tra sớm Content-Length trong HTTP/3 nếu có
                    if let Some(cl_val) = parts.headers.get(http::header::CONTENT_LENGTH) {
                        if let Ok(cl_str) = cl_val.to_str() {
                            if let Ok(cl) = cl_str.trim().parse::<usize>() {
                                if cl > cfg.client_max_body_size {
                                    send_h3_simple_error(
                                        &mut stream,
                                        StatusCode::PAYLOAD_TOO_LARGE,
                                        b"413 Payload Too Large",
                                    )
                                    .await;
                                    return;
                                }
                            }
                        }
                    }

                    let body_timeout = Duration::from_millis(cfg.client_body_timeout_ms.max(1000));
                    let mut body_buf = BytesMut::new();
                    let mut body_too_large = false;
                    let mut body_err = false;

                    let read_res = tokio::time::timeout(body_timeout, async {
                        loop {
                            match stream.recv_data().await {
                                Ok(Some(mut chunk)) => {
                                    if body_buf.len() + chunk.remaining() > cfg.client_max_body_size
                                    {
                                        body_too_large = true;
                                        break;
                                    }
                                    body_buf.extend_from_slice(chunk.chunk());
                                    chunk.advance(chunk.remaining());
                                }
                                Ok(None) => break,
                                Err(_) => {
                                    body_err = true;
                                    break;
                                }
                            }
                        }
                    })
                    .await;

                    if read_res.is_err() {
                        send_h3_simple_error(
                            &mut stream,
                            StatusCode::REQUEST_TIMEOUT,
                            b"408 Request Timeout",
                        )
                        .await;
                        return;
                    }
                    if body_too_large {
                        send_h3_simple_error(
                            &mut stream,
                            StatusCode::PAYLOAD_TOO_LARGE,
                            b"413 Payload Too Large",
                        )
                        .await;
                        return;
                    }
                    if body_err {
                        send_h3_simple_error(
                            &mut stream,
                            StatusCode::BAD_REQUEST,
                            b"400 Bad Request",
                        )
                        .await;
                        return;
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

                    let resp_payload = dispatch_http_request(&incoming, &cfg, &waf, &st, &acme, &reg).await;
                    let mut builder = Response::builder().status(resp_payload.status);
                    if let Some(hmap) = builder.headers_mut() {
                        if cfg.server_tokens {
                            hmap.append(
                                HeaderName::from_static("server"),
                                HeaderValue::from_static("FerrousX"),
                            );
                        }
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
                                let body_len = resp_payload.body.len() as u64;
                                if stream.send_data(resp_payload.body).await.is_ok() {
                                    st.bytes_sent.fetch_add(body_len, Ordering::Relaxed);
                                }
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

async fn send_h3_simple_error(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status: StatusCode,
    msg: &'static [u8],
) {
    let mut builder = Response::builder().status(status);
    if let Some(hmap) = builder.headers_mut() {
        hmap.append(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
    }
    if let Ok(resp) = builder.body(()) {
        if stream.send_response(resp).await.is_ok() {
            let _ = stream.send_data(Bytes::from_static(msg)).await;
            let _ = stream.finish().await;
        }
    }
}

// ============================================================================
// KIỂM TRA WAF & RATE LIMITER TRƯỚC KHI ĐỊNH TUYẾN
// ============================================================================

fn check_waf_for_request(
    req: &IncomingRequest,
    cfg: &ServerConfig,
    waf_engine: &ZeroAllocWafEngine,
    stats: &EngineRuntimeStats,
) -> Option<HttpResponsePayload> {
    if !cfg.waf.enabled || cfg.waf.mode == WafMode::Off {
        stats.xdp_metrics.record_pass();
        return None;
    }

    let host_no_port = strip_port(&req.host);
    let effective_mode = if let Some(vhost) = match_virtual_host(host_no_port, cfg) {
        let mode = vhost.waf_mode.unwrap_or(cfg.waf.mode);
        if !vhost.waf_enabled || mode == WafMode::Off {
            stats.xdp_metrics.record_pass();
            return None;
        }
        mode
    } else {
        cfg.waf.mode
    };

    let real_ip_str = resolve_real_client_ip(req, cfg);
    let client_ip = real_ip_str.parse::<IpAddr>().unwrap_or(req.peer_ip);

    let decision = waf_engine.inspect_full_request(
        client_ip,
        &req.method,
        &req.path,
        &req.query,
        &req.headers,
        &req.body,
    );

    match decision {
        WafDecision::Allow => {
            stats.xdp_metrics.record_pass();
            None
        }
        WafDecision::BlockRateLimitedGcra => {
            if effective_mode == WafMode::Monitor {
                warn!(
                    client_ip = %client_ip,
                    path = %req.path,
                    "[WAF Monitor] Phát hiện vượt ngưỡng Rate Limit nhưng cho qua do chế độ Monitor"
                );
                stats.xdp_metrics.record_pass();
                None
            } else {
                stats.rate_limited.fetch_add(1, Ordering::Relaxed);
                stats.xdp_metrics.record_drop();
                Some(HttpResponsePayload {
                    status: StatusCode::TOO_MANY_REQUESTS,
                    headers: vec![
                        (
                            "Content-Type".to_string(),
                            "text/plain; charset=utf-8".to_string(),
                        ),
                        ("Retry-After".to_string(), "5".to_string()),
                    ],
                    body: Bytes::from_static(b"429 Too Many Requests (FerrousX GCRA Shield)"),
                })
            }
        }
        other => {
            let reason = other.as_reason_code();
            if effective_mode == WafMode::Monitor {
                warn!(
                    client_ip = %client_ip,
                    path = %req.path,
                    reason,
                    "[WAF Monitor] Phát hiện mẫu tấn công nhưng cho qua do chế độ Monitor"
                );
                stats.xdp_metrics.record_pass();
                None
            } else {
                stats.waf_blocked.fetch_add(1, Ordering::Relaxed);
                stats.xdp_metrics.record_drop();
                Some(HttpResponsePayload {
                    status: StatusCode::FORBIDDEN,
                    headers: vec![(
                        "Content-Type".to_string(),
                        "text/plain; charset=utf-8".to_string(),
                    )],
                    body: Bytes::from(format!("403 Forbidden: {reason}")),
                })
            }
        }
    }
}

// ============================================================================
// BỘ ĐỊNH TUYẾN CHÍNH (PRODUCTION ROUTER): WAF, CLOUDFLARE, PANEL, PHPMYADMIN, PHP-FPM
// ============================================================================

async fn dispatch_http_request(
    req: &IncomingRequest,
    cfg: &ServerConfig,
    waf_engine: &ZeroAllocWafEngine,
    stats: &EngineRuntimeStats,
    acme_mgr: &AcmeCertManager,
    upstream_reg: &UpstreamBalancerRegistry,
) -> HttpResponsePayload {
    stats.total_requests.fetch_add(1, Ordering::Relaxed);

    // 0. Kiểm tra WAF & Sharded GCRA Rate Limiter
    if let Some(waf_blocked_resp) = check_waf_for_request(req, cfg, waf_engine, stats) {
        return waf_blocked_resp;
    }

    // 1. Định tuyến phpMyAdmin tương thích Cloudflare (khi bật `enable_phpmyadmin_route = true`)
    if cfg.enable_phpmyadmin_route {
        if req.path == "/phpadmin" || req.path == "/phpmyadmin" {
            let mut target_loc = format!("{}/", req.path);
            if !req.query.is_empty() {
                target_loc.push('?');
                target_loc.push_str(&req.query);
            }
            return HttpResponsePayload {
                status: StatusCode::FOUND, // 302 Redirect
                headers: vec![
                    ("Location".to_string(), sanitize_header_value(&target_loc)),
                    ("Cache-Control".to_string(), "no-store".to_string()),
                ],
                body: Bytes::new(),
            };
        }

        if req.path.starts_with("/phpadmin/") || req.path.starts_with("/phpmyadmin/") {
            let resp =
                proxy_http1_upstream(&cfg.phpmyadmin_upstream, req, cfg, true, true, stats).await;
            return maybe_compress_response(req, cfg, resp).await;
        }
    }

    // 2. Đồng bộ định tuyến động tới Ferrous-Panel v2.5.0 từ `/etc/ferrous-panel/panel.env` & `admin.json`
    if is_panel_request(req, cfg) {
        let panel_upstream = cfg.panel_admin.panel_upstream_addr();
        let resp = proxy_http1_upstream(&panel_upstream, req, cfg, true, true, stats).await;
        return maybe_compress_response(req, cfg, resp).await;
    }

    // 3. Tìm VirtualHost khớp với Host header (từ `/etc/ferrousx/sites/*.toml` hoặc `[[vhosts]]`)
    let host_no_port = strip_port(&req.host);
    if let Some(vhost) = match_virtual_host(host_no_port, cfg) {
        // 3a. Phục vụ ACME HTTP-01 Challenge (ưu tiên RAM AcmeCertManager -> fallback /www/acme) trước khi Redirect HTTPS
        let acme_prefix = if vhost.acme_prefix.trim().is_empty() {
            cfg.acme_challenge_prefix.as_str()
        } else {
            vhost.acme_prefix.as_str()
        };
        if !req.is_tls && vhost.acme_serve_before_redirect && req.path.starts_with(acme_prefix) {
            if req.method != "GET" && req.method != "HEAD" {
                return HttpResponsePayload {
                    status: StatusCode::METHOD_NOT_ALLOWED,
                    headers: vec![(
                        "Content-Type".to_string(),
                        "text/plain; charset=utf-8".to_string(),
                    )],
                    body: Bytes::from_static(b"Method Not Allowed"),
                };
            }
            if let Some(key_auth) = acme_mgr.resolve_http01_challenge(&req.path) {
                return HttpResponsePayload {
                    status: StatusCode::OK,
                    headers: vec![(
                        "Content-Type".to_string(),
                        "text/plain; charset=utf-8".to_string(),
                    )],
                    body: Bytes::from(key_auth),
                };
            }
            let acme_root = if vhost.acme_webroot.as_os_str().is_empty() {
                &cfg.acme_webroot
            } else {
                &vhost.acme_webroot
            };
            return serve_static_acme_challenge(acme_root, &req.path).await;
        }

        // 3b. Chuyển hướng HTTP -> HTTPS (khi `[handler] kind = "redirect_https"` hoặc `[ssl] redirect_https = true`)
        if !req.is_tls {
            let redirect_code = if let Some(code) = vhost.redirect_status_code {
                Some(code)
            } else if vhost.ssl_enabled && vhost.redirect_https {
                Some(301)
            } else {
                None
            };
            if let Some(code) = redirect_code {
                let status =
                    StatusCode::from_u16(code).unwrap_or(StatusCode::MOVED_PERMANENTLY);
                let host_target = if host_no_port.is_empty() {
                    vhost.server_name.as_str()
                } else {
                    host_no_port
                };
                let location = sanitize_header_value(&format!(
                    "https://{host_target}{}",
                    req.raw_target
                ));
                return HttpResponsePayload {
                    status,
                    headers: vec![("Location".to_string(), location)],
                    body: Bytes::new(),
                };
            }
        }

        // 3c. Kiểm tra các route proxy cấu hình sẵn trong VirtualHost (`kind = "reverse_proxy"`)
        for route in &vhost.routes {
            if route.backend_protocol != BackendProtocol::FastCgi
                && route.backend_protocol != BackendProtocol::StaticFile
                && req.path.starts_with(&route.path_prefix)
            {
                if let Some(ref upstream_key) = route.target_upstream {
                    let resp = proxy_with_balancer_and_circuit(
                        upstream_key,
                        req,
                        cfg,
                        vhost.pass_host_header,
                        vhost.forwarded_headers,
                        stats,
                        upstream_reg,
                    )
                    .await;
                    return maybe_compress_response(req, cfg, resp).await;
                }
            }
        }

        // 3d. Phục vụ tệp tĩnh / SPA / PHP-FPM FastCGI dưới root_dir của VirtualHost
        if let Some(ref root_dir) = vhost.root_dir {
            if root_dir.is_dir() {
                let resp = serve_vhost_site_root(
                    root_dir,
                    vhost.php_fpm_socket.as_deref(),
                    &vhost.index_files,
                    vhost.spa_fallback,
                    vhost.enable_etag,
                    req,
                    cfg,
                    stats,
                )
                .await;
                return maybe_compress_response(req, cfg, resp).await;
            }
        }
    }

    // 4. Phục vụ ACME HTTP-01 Challenge cấp toàn cục ngay cả khi domain chưa có trong sites/*.toml
    if !req.is_tls && req.path.starts_with(&cfg.acme_challenge_prefix) {
        if let Some(key_auth) = acme_mgr.resolve_http01_challenge(&req.path) {
            return HttpResponsePayload {
                status: StatusCode::OK,
                headers: vec![(
                    "Content-Type".to_string(),
                    "text/plain; charset=utf-8".to_string(),
                )],
                body: Bytes::from(key_auth),
            };
        }
        return serve_static_acme_challenge(&cfg.acme_webroot, &req.path).await;
    }

    // 5. Tự động kiểm tra `/www/wwwroot/<domain>` ngay cả khi chưa thêm vào file .toml
    if !host_no_port.is_empty()
        && !host_no_port.contains("..")
        && !host_no_port.contains('/')
        && !host_no_port.contains('\\')
    {
        let wwwroot_base = if cfg.panel_admin.wwwroot.trim().is_empty() {
            "/www/wwwroot"
        } else {
            cfg.panel_admin.wwwroot.trim()
        };
        let dynamic_root = PathBuf::from(wwwroot_base).join(host_no_port);
        if dynamic_root.is_dir() {
            let default_indices = vec!["index.php".to_string(), "index.html".to_string()];
            let resp = serve_vhost_site_root(
                &dynamic_root,
                None,
                &default_indices,
                false,
                true,
                req,
                cfg,
                stats,
            )
            .await;
            return maybe_compress_response(req, cfg, resp).await;
        }
    }

    // 6. Fallback mặc định nếu chưa có website nào được trỏ tới
    let payload = format!(
        "{{\"server\":\"FerrousX\",\"engine\":\"io_uring+TLS+QUIC\",\"host\":\"{}\",\"path\":\"{}\",\"epoch\":{}}}",
        escape_json_str(host_no_port),
        escape_json_str(&req.path),
        cfg.version_epoch
    );
    HttpResponsePayload {
        status: StatusCode::OK,
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body: Bytes::from(payload),
    }
}

/// Phục vụ tệp xác thực Let's Encrypt ACME HTTP-01 từ `/www/acme/.well-known/acme-challenge/<token>`
async fn serve_static_acme_challenge(acme_webroot: &Path, req_path: &str) -> HttpResponsePayload {
    let Some(resolved) = safe_resolve_under_root(acme_webroot, req_path) else {
        return HttpResponsePayload {
            status: StatusCode::FORBIDDEN,
            headers: vec![(
                "Content-Type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
            body: Bytes::from_static(b"Forbidden"),
        };
    };

    if !resolved.is_file() {
        return HttpResponsePayload {
            status: StatusCode::NOT_FOUND,
            headers: vec![(
                "Content-Type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
            body: Bytes::from_static(b"Not Found"),
        };
    }

    match tokio::fs::read(&resolved).await {
        Ok(bytes) => HttpResponsePayload {
            status: StatusCode::OK,
            headers: vec![(
                "Content-Type".to_string(),
                "application/octet-stream".to_string(),
            )],
            body: Bytes::from(bytes),
        },
        Err(_) => HttpResponsePayload {
            status: StatusCode::NOT_FOUND,
            headers: vec![(
                "Content-Type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
            body: Bytes::from_static(b"Not Found"),
        },
    }
}

/// Kiểm tra request có thuộc Ferrous-Panel hay không (dựa theo panel.env & admin.json: customDomain, securityEntrance)
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

    // Khi customDomain rỗng, cho phép truy cập panel qua bất kỳ Host/IP nào trên các tuyến chuẩn của Ferrous-Panel v2.5.0
    if custom_domain.is_empty()
        && (req.path.starts_with("/ferrous-panel")
            || req.path.starts_with("/api/panel")
            || req.path.starts_with("/api/auth/")
            || req.path.starts_with("/api/system/")
            || req.path.starts_with("/api/sites")
            || req.path.starts_with("/api/databases")
            || req.path.starts_with("/api/ssl")
            || req.path.starts_with("/api/files")
            || req.path.starts_with("/api/firewall")
            || req.path.starts_with("/api/cron")
            || req.path.starts_with("/api/terminal")
            || req.path.starts_with("/ws/ssh")
            || req.path.starts_with("/ws/telemetry"))
    {
        return true;
    }

    false
}

/// Phục vụ website Vhost (tệp tĩnh, SPA fallback, hoặc PHP-FPM FastCGI) kèm chống Path Traversal tuyệt đối
async fn serve_vhost_site_root(
    site_root: &Path,
    preferred_php_sock: Option<&str>,
    index_files: &[String],
    spa_fallback: bool,
    enable_etag: bool,
    req: &IncomingRequest,
    cfg: &ServerConfig,
    stats: &EngineRuntimeStats,
) -> HttpResponsePayload {
    // 0. Chặn truy cập trực tiếp tệp nhạy cảm (.htaccess, .htpasswd, .env, .git) theo đúng chuẩn Ferrous-Panel
    if req
        .path
        .split('/')
        .any(|seg| seg.starts_with(".ht") || seg == ".env" || seg == ".git")
    {
        return HttpResponsePayload {
            status: StatusCode::FORBIDDEN,
            headers: vec![(
                "Content-Type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
            body: Bytes::from_static(b"403 Forbidden"),
        };
    }

    // 1. Bảo vệ Path Traversal: Không cho phép thoát khỏi `site_root` (kể cả qua symlink)
    let Some(resolved) = safe_resolve_under_root(site_root, &req.path) else {
        return HttpResponsePayload {
            status: StatusCode::FORBIDDEN,
            headers: vec![(
                "Content-Type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
            body: Bytes::from_static(b"403 Forbidden: Path Traversal Blocked by FerrousX"),
        };
    };

    let primary_index = index_files
        .first()
        .map(String::as_str)
        .unwrap_or("index.php");

    // 2. Xác định tệp thực thi: tệp .php, tệp tĩnh, thư mục index, SPA fallback, hoặc fallback /index.php
    let target_file = if resolved.is_file() {
        resolved
    } else if resolved.is_dir() || req.path.ends_with('/') {
        let mut found = None;
        for idx in index_files {
            let candidate = resolved.join(idx);
            if candidate.is_file() {
                found = Some(candidate);
                break;
            }
        }
        if let Some(f) = found {
            f
        } else if resolved.join("index.php").is_file() {
            resolved.join("index.php")
        } else if resolved.join("index.html").is_file() {
            resolved.join("index.html")
        } else {
            site_root.join(primary_index)
        }
    } else if spa_fallback {
        let has_extension = Path::new(&req.path).extension().is_some();
        if !has_extension {
            site_root.join(primary_index)
        } else {
            return HttpResponsePayload {
                status: StatusCode::NOT_FOUND,
                headers: vec![(
                    "Content-Type".to_string(),
                    "text/plain; charset=utf-8".to_string(),
                )],
                body: Bytes::from_static(b"404 Not Found"),
            };
        }
    } else {
        // Nginx try_files $uri $uri/ /index.php?$query_string
        let fallback_php = site_root.join("index.php");
        if fallback_php.is_file() {
            fallback_php
        } else {
            let fallback_html = site_root.join(primary_index);
            if fallback_html.is_file() {
                fallback_html
            } else {
                return HttpResponsePayload {
                    status: StatusCode::NOT_FOUND,
                    headers: vec![(
                        "Content-Type".to_string(),
                        "text/plain; charset=utf-8".to_string(),
                    )],
                    body: Bytes::from_static(b"404 Not Found"),
                };
            }
        }
    };

    if !target_file.exists() {
        return HttpResponsePayload {
            status: StatusCode::NOT_FOUND,
            headers: vec![(
                "Content-Type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
            body: Bytes::from_static(b"404 Not Found"),
        };
    }

    let is_php = target_file
        .extension()
        .and_then(|e| e.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("php"))
        .unwrap_or(false);

    if is_php {
        stats.php_fpm_requests.fetch_add(1, Ordering::Relaxed);
        let fpm_target = detect_php_fpm_socket(preferred_php_sock);
        let client_ip = resolve_real_client_ip(req, cfg);
        let is_https = is_request_https(req, cfg);

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

        // Chuyển tiếp REQUEST_URI gốc và toàn bộ HTTP_* headers hợp lệ
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
            } else if k.eq_ignore_ascii_case("proxy") {
                // Chặn tuyệt đối HTTP_PROXY (lỗ hổng Httpoxy CVE-2016-5385)
                continue;
            } else {
                let cgi_key = format!("HTTP_{}", k.to_ascii_uppercase().replace('-', "_"));
                extra_headers.push((cgi_key, v.clone()));
            }
        }

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
                stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                warn!(socket = %fpm_target, error = %err, "Lỗi thực thi PHP-FPM FastCGI");
                HttpResponsePayload {
                    status: StatusCode::BAD_GATEWAY,
                    headers: vec![(
                        "Content-Type".to_string(),
                        "text/plain; charset=utf-8".to_string(),
                    )],
                    body: Bytes::from_static(b"502 Bad Gateway (PHP-FPM)"),
                }
            }
            Err(_) => {
                stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                HttpResponsePayload {
                    status: StatusCode::GATEWAY_TIMEOUT,
                    headers: vec![(
                        "Content-Type".to_string(),
                        "text/plain; charset=utf-8".to_string(),
                    )],
                    body: Bytes::from_static(b"504 Gateway Timeout (PHP-FPM)"),
                }
            }
        };
    }

    // Phục vụ tệp tĩnh với MIME type chuẩn & ETag 304 Not Modified
    let etag = if enable_etag {
        tokio::fs::metadata(&target_file).await.ok().map(|meta| {
            let mtime_nanos = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            format!("\"{:x}-{:x}\"", meta.len(), mtime_nanos)
        })
    } else {
        None
    };

    if let Some(ref tag) = etag {
        let not_modified = req.headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("if-none-match")
                && v.split(',')
                    .map(|p| p.trim().trim_start_matches("W/"))
                    .any(|cand| cand == tag || cand == "*")
        });
        if not_modified {
            stats.static_requests.fetch_add(1, Ordering::Relaxed);
            return HttpResponsePayload {
                status: StatusCode::NOT_MODIFIED,
                headers: vec![("ETag".to_string(), tag.clone())],
                body: Bytes::new(),
            };
        }
    }

    match tokio::fs::read(&target_file).await {
        Ok(bytes) => {
            stats.static_requests.fetch_add(1, Ordering::Relaxed);
            let ext = target_file
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let mime = MimeDetector::get_mime_type(&ext);
            let mut headers = vec![("Content-Type".to_string(), mime.to_string())];
            if let Some(tag) = etag {
                headers.push(("ETag".to_string(), tag));
            }
            HttpResponsePayload {
                status: StatusCode::OK,
                headers,
                body: Bytes::from(bytes),
            }
        }
        Err(_) => HttpResponsePayload {
            status: StatusCode::NOT_FOUND,
            headers: vec![(
                "Content-Type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
            body: Bytes::from_static(b"404 Not Found"),
        },
    }
}

// ============================================================================
// REVERSE PROXY (TRUSTED PROXY CIDR + SSRF SHIELD + BOUNDED BUFFER + WEBSOCKET)
// ============================================================================

/// Xác định IP thực của Client:
/// CHỈ tin cậy `CF-Connecting-IP` hoặc `X-Forwarded-For` khi `req.peer_ip` nằm trong danh sách `trusted_proxies`!
fn resolve_real_client_ip(req: &IncomingRequest, cfg: &ServerConfig) -> String {
    if cfg.is_trusted_proxy(req.peer_ip) {
        for (k, v) in &req.headers {
            if k.eq_ignore_ascii_case("cf-connecting-ip") {
                let candidate = v.trim();
                if candidate.parse::<IpAddr>().is_ok() {
                    return candidate.to_string();
                }
            }
        }
        for (k, v) in &req.headers {
            if k.eq_ignore_ascii_case("x-forwarded-for") {
                if let Some(first) = v.split(',').next() {
                    let candidate = first.trim();
                    if candidate.parse::<IpAddr>().is_ok() {
                        return candidate.to_string();
                    }
                }
            }
        }
    }
    req.peer_ip.to_string()
}

/// Kiểm tra kết nối gốc có phải HTTPS không:
/// CHỈ tin cậy `X-Forwarded-Proto: https` khi `req.peer_ip` thuộc `trusted_proxies`
fn is_request_https(req: &IncomingRequest, cfg: &ServerConfig) -> bool {
    if req.is_tls {
        return true;
    }
    if cfg.is_trusted_proxy(req.peer_ip) {
        for (k, v) in &req.headers {
            if k.eq_ignore_ascii_case("x-forwarded-proto")
                && v.trim().eq_ignore_ascii_case("https")
            {
                return true;
            }
        }
    }
    false
}

/// Kiểm tra địa chỉ TCP upstream có an toàn trước SSRF (Cloud Metadata 169.254.169.254, 0.0.0.0, broadcast)
fn is_safe_tcp_upstream(target_addr: &str) -> bool {
    if validate_upstream_origin(target_addr).is_err() {
        return false;
    }
    if let Ok(sock_addr) = target_addr.parse::<SocketAddr>() {
        if is_forbidden_ssrf_ip(sock_addr.ip()) || sock_addr.port() == 0 {
            return false;
        }
    }
    true
}

/// Reverse Proxy có P2C/Round-Robin Load Balancing + CircuitBreaker
async fn proxy_with_balancer_and_circuit(
    upstream_key: &str,
    req: &IncomingRequest,
    cfg: &ServerConfig,
    pass_host_header: bool,
    forwarded_headers: bool,
    stats: &EngineRuntimeStats,
    upstream_reg: &UpstreamBalancerRegistry,
) -> HttpResponsePayload {
    let seed = compute_request_seed(req);
    match upstream_reg.resolve_target(upstream_key, seed, cfg) {
        UpstreamPickResult::PoolNode(node) => {
            node.active_requests.fetch_add(1, Ordering::Relaxed);
            let resp = proxy_http1_upstream(
                &node.address,
                req,
                cfg,
                pass_host_header,
                forwarded_headers,
                stats,
            )
            .await;
            node.active_requests.fetch_sub(1, Ordering::Relaxed);
            node.total_served.fetch_add(1, Ordering::Relaxed);
            if matches!(
                resp.status,
                StatusCode::BAD_GATEWAY
                    | StatusCode::SERVICE_UNAVAILABLE
                    | StatusCode::GATEWAY_TIMEOUT
            ) {
                node.circuit.on_failure(current_unix_ms());
            } else {
                node.circuit.on_success();
            }
            resp
        }
        UpstreamPickResult::CircuitBreakerOpen => {
            stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
            HttpResponsePayload {
                status: StatusCode::SERVICE_UNAVAILABLE,
                headers: vec![
                    (
                        "Content-Type".to_string(),
                        "text/plain; charset=utf-8".to_string(),
                    ),
                    ("Retry-After".to_string(), "5".to_string()),
                ],
                body: Bytes::from_static(b"503 Service Unavailable: Upstream Circuit Breaker Open"),
            }
        }
        UpstreamPickResult::LiteralAddr(target_addr) => {
            proxy_http1_upstream(
                &target_addr,
                req,
                cfg,
                pass_host_header,
                forwarded_headers,
                stats,
            )
            .await
        }
    }
}

/// Nén phản hồi HTTP bằng Zstd hoặc Brotli qua `async-compression` nếu client hỗ trợ và dữ liệu đủ lớn
async fn maybe_compress_response(
    req: &IncomingRequest,
    cfg: &ServerConfig,
    mut resp: HttpResponsePayload,
) -> HttpResponsePayload {
    if req.method == "HEAD" || resp.status != StatusCode::OK {
        return resp;
    }
    if resp
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
    {
        return resp;
    }

    let comp_cfg = match_virtual_host(strip_port(&req.host), cfg)
        .map(|v| v.compression.clone())
        .unwrap_or_else(CompressionConfig::default);

    if resp.body.len() < comp_cfg.min_length_bytes {
        return resp;
    }

    let content_type = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let ct_low = content_type.to_ascii_lowercase();
    let compressible = ct_low.starts_with("text/")
        || ct_low.contains("application/json")
        || ct_low.contains("application/javascript")
        || ct_low.contains("application/xml")
        || ct_low.contains("image/svg+xml")
        || ct_low.contains("application/wasm");
    if !compressible {
        return resp;
    }

    let accept_enc = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("accept-encoding"))
        .map(|(_, v)| v.to_ascii_lowercase())
        .unwrap_or_default();

    let (encoding, enc_label) = if comp_cfg.enable_zstd && accept_enc.contains("zstd") {
        (ContentEncoding::Zstd, "zstd")
    } else if comp_cfg.enable_brotli && accept_enc.contains("br") {
        (ContentEncoding::Brotli, "br")
    } else {
        return resp;
    };

    if let Some(compressed) = compress_response_body(&resp.body, encoding).await {
        resp.body = compressed;
        resp.headers
            .push(("Content-Encoding".to_string(), enc_label.to_string()));
        resp.headers
            .push(("Vary".to_string(), "Accept-Encoding".to_string()));
    }
    resp
}

/// Reverse Proxy HTTP/1.1 tới dịch vụ nội bộ (phpMyAdmin `127.0.0.1:888`, Ferrous-Panel, Node.js, Python)
async fn proxy_http1_upstream(
    target_addr: &str,
    req: &IncomingRequest,
    cfg: &ServerConfig,
    pass_host_header: bool,
    forwarded_headers: bool,
    stats: &EngineRuntimeStats,
) -> HttpResponsePayload {
    let connect_timeout = Duration::from_millis(cfg.proxy_connect_timeout_ms.max(1000));
    let write_timeout = Duration::from_millis(cfg.proxy_write_timeout_ms.max(1000));
    let read_timeout = Duration::from_millis(cfg.proxy_read_timeout_ms.max(5000));
    let max_resp_bytes = cfg.max_upstream_response_bytes.max(1024 * 1024);

    if let Some(sock_path) = target_addr.strip_prefix("unix:") {
        let Ok(Ok(mut stream)) =
            tokio::time::timeout(connect_timeout, UnixStream::connect(sock_path)).await
        else {
            stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
            return bad_gateway_response();
        };
        let wire_req = build_upstream_http1_request(
            req,
            cfg,
            target_addr,
            pass_host_header,
            forwarded_headers,
            false,
        );
        if tokio::time::timeout(write_timeout, stream.write_all(&wire_req))
            .await
            .map_or(true, |r| r.is_err())
        {
            stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
            return bad_gateway_response();
        }
        match tokio::time::timeout(
            read_timeout,
            read_full_http1_response(&mut stream, max_resp_bytes),
        )
        .await
        {
            Ok(Ok(r)) => r,
            _ => {
                stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                bad_gateway_response()
            }
        }
    } else {
        if !is_safe_tcp_upstream(target_addr) {
            stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
            warn!(target = %target_addr, "Chặn kết nối Upstream không an toàn (SSRF Protection)");
            return HttpResponsePayload {
                status: StatusCode::BAD_GATEWAY,
                headers: vec![(
                    "Content-Type".to_string(),
                    "text/plain; charset=utf-8".to_string(),
                )],
                body: Bytes::from_static(b"502 Bad Gateway: Upstream Target Blocked by SSRF Policy"),
            };
        }

        let Ok(Ok(mut stream)) =
            tokio::time::timeout(connect_timeout, TcpStream::connect(target_addr)).await
        else {
            stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
            return bad_gateway_response();
        };
        // Kiểm tra thêm địa chỉ IP thực tế sau khi phân giải DNS (chống DNS Rebinding vào 169.254.169.254)
        if let Ok(peer_sock) = stream.peer_addr() {
            if is_forbidden_ssrf_ip(peer_sock.ip()) {
                stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                warn!(
                    target = %target_addr,
                    resolved_ip = %peer_sock.ip(),
                    "Chặn DNS Rebinding SSRF vào địa chỉ IP bị cấm"
                );
                return bad_gateway_response();
            }
        }

        let _ = stream.set_nodelay(true);
        let wire_req = build_upstream_http1_request(
            req,
            cfg,
            target_addr,
            pass_host_header,
            forwarded_headers,
            false,
        );
        if tokio::time::timeout(write_timeout, stream.write_all(&wire_req))
            .await
            .map_or(true, |r| r.is_err())
        {
            stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
            return bad_gateway_response();
        }
        match tokio::time::timeout(
            read_timeout,
            read_full_http1_response(&mut stream, max_resp_bytes),
        )
        .await
        {
            Ok(Ok(r)) => r,
            _ => {
                stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                bad_gateway_response()
            }
        }
    }
}

fn bad_gateway_response() -> HttpResponsePayload {
    HttpResponsePayload {
        status: StatusCode::BAD_GATEWAY,
        headers: vec![(
            "Content-Type".to_string(),
            "text/plain; charset=utf-8".to_string(),
        )],
        body: Bytes::from_static(b"502 Bad Gateway"),
    }
}

/// Đóng gói Request gửi tới Upstream kèm đầy đủ header Proxy chuẩn Cloudflare & Ferrous-Panel,
/// chống giả mạo X-Forwarded-For từ client không tin cậy và lọc sạch hop-by-hop headers
fn build_upstream_http1_request(
    req: &IncomingRequest,
    cfg: &ServerConfig,
    upstream_authority: &str,
    pass_host_header: bool,
    forwarded_headers: bool,
    keep_upgrade: bool,
) -> Vec<u8> {
    let real_ip = resolve_real_client_ip(req, cfg);
    let proto = if is_request_https(req, cfg) {
        "https"
    } else {
        "http"
    };
    let raw_host_val = if !pass_host_header {
        upstream_authority.to_string()
    } else if req.host.is_empty() {
        "localhost".to_string()
    } else {
        req.host.clone()
    };
    let host_val = sanitize_header_value(&raw_host_val);

    // Chỉ nối chuỗi X-Forwarded-For cũ nếu request đến từ Trusted Proxy;
    // nếu từ client trực tiếp, ghi đè bằng peer_ip thực tế để chống IP Spoofing!
    let new_xff = if cfg.is_trusted_proxy(req.peer_ip) {
        let existing_xff = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-for"))
            .map(|(_, v)| sanitize_header_value(v))
            .unwrap_or_default();
        if existing_xff.is_empty() {
            req.peer_ip.to_string()
        } else {
            format!("{existing_xff}, {}", req.peer_ip)
        }
    } else {
        req.peer_ip.to_string()
    };

    // Thu thập các header động được liệt kê trong `Connection: <header1>, <header2>` (RFC 9110 §7.6.1)
    let mut dynamic_hop_headers: Vec<String> = Vec::new();
    if !keep_upgrade {
        for (k, v) in &req.headers {
            if k.eq_ignore_ascii_case("connection") {
                for token in v.split(',') {
                    let t = token.trim().to_ascii_lowercase();
                    if !t.is_empty() && t != "close" && t != "keep-alive" {
                        dynamic_hop_headers.push(t);
                    }
                }
            }
        }
    }

    let safe_method = sanitize_header_value(&req.method);
    let safe_target = sanitize_header_value(&req.raw_target);

    let mut out = Vec::with_capacity(1024 + req.body.len());
    out.extend_from_slice(format!("{safe_method} {safe_target} HTTP/1.1\r\n").as_bytes());
    out.extend_from_slice(format!("Host: {host_val}\r\n").as_bytes());
    if forwarded_headers {
        out.extend_from_slice(format!("X-Real-IP: {real_ip}\r\n").as_bytes());
        out.extend_from_slice(format!("X-Forwarded-For: {new_xff}\r\n").as_bytes());
        out.extend_from_slice(format!("X-Forwarded-Proto: {proto}\r\n").as_bytes());
        out.extend_from_slice(format!("X-Forwarded-Host: {host_val}\r\n").as_bytes());
    }

    for (k, v) in &req.headers {
        let lower = k.to_ascii_lowercase();
        if lower == "host"
            || lower == "x-real-ip"
            || lower == "x-forwarded-for"
            || lower == "x-forwarded-proto"
            || lower == "x-forwarded-host"
            || lower == "content-length"
            || lower == "transfer-encoding"
            || lower == "te"
            || lower == "trailer"
            || lower == "trailers"
            || lower == "proxy-authorization"
            || lower == "proxy-authenticate"
            || lower == "keep-alive"
        {
            continue;
        }
        if !keep_upgrade && (lower == "connection" || lower == "upgrade") {
            continue;
        }
        if dynamic_hop_headers.iter().any(|h| h == &lower) {
            continue;
        }
        let clean_k = sanitize_header_name(k);
        let clean_v = sanitize_header_value(v);
        if !clean_k.is_empty() {
            out.extend_from_slice(format!("{clean_k}: {clean_v}\r\n").as_bytes());
        }
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

/// Đọc phản hồi HTTP/1.1 từ Upstream với giới hạn kích thước `max_response_bytes`,
/// tự động giải mã `Transfer-Encoding: chunked` và giữ nguyên multi `Set-Cookie`
async fn read_full_http1_response<S>(
    stream: &mut S,
    max_response_bytes: usize,
) -> Result<HttpResponsePayload>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut raw = Vec::with_capacity(16 * 1024);
    let mut chunk_buf = [0u8; 16 * 1024];

    loop {
        let n = stream.read(&mut chunk_buf).await?;
        if n == 0 {
            break;
        }
        if raw.len() + n > max_response_bytes {
            warn!(
                max_response_bytes,
                "Phản hồi từ Upstream vượt quá ngưỡng max_upstream_response_bytes"
            );
            return Ok(HttpResponsePayload {
                status: StatusCode::BAD_GATEWAY,
                headers: vec![(
                    "Content-Type".to_string(),
                    "text/plain; charset=utf-8".to_string(),
                )],
                body: Bytes::from_static(b"502 Bad Gateway: Upstream Response Too Large"),
            });
        }
        raw.extend_from_slice(&chunk_buf[..n]);
    }

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
        let name = sanitize_header_name(h.name);
        let val = sanitize_header_value(&String::from_utf8_lossy(h.value));
        if name.is_empty() {
            continue;
        }
        if name.eq_ignore_ascii_case("transfer-encoding")
            && val.to_ascii_lowercase().contains("chunked")
        {
            is_chunked = true;
            continue;
        }
        if is_hop_by_hop_header(&name) || name.eq_ignore_ascii_case("content-length") {
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
    upstream_reg: &UpstreamBalancerRegistry,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let host_no_port = strip_port(&req.host);
    let seed = compute_request_seed(&req);
    let upstream_addr = if is_panel_request(&req, cfg) {
        cfg.panel_admin.panel_upstream_addr()
    } else if cfg.enable_phpmyadmin_route
        && (req.path.starts_with("/phpadmin/") || req.path.starts_with("/phpmyadmin/"))
    {
        cfg.phpmyadmin_upstream.clone()
    } else if let Some(vhost) = match_virtual_host(host_no_port, cfg) {
        if let Some(upstream_key) = vhost
            .routes
            .iter()
            .find(|r| req.path.starts_with(&r.path_prefix))
            .and_then(|r| r.target_upstream.as_ref())
        {
            match upstream_reg.resolve_target(upstream_key, seed, cfg) {
                UpstreamPickResult::PoolNode(node) => node.address.clone(),
                UpstreamPickResult::LiteralAddr(addr) => addr,
                UpstreamPickResult::CircuitBreakerOpen => {
                    write_simple_http1_error(
                        &mut client_stream,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "503 Service Unavailable: WebSocket Upstream Circuit Breaker Open",
                    )
                    .await?;
                    return Ok(());
                }
            }
        } else {
            cfg.panel_admin.panel_upstream_addr()
        }
    } else {
        cfg.panel_admin.panel_upstream_addr()
    };

    let clean_tcp_addr = upstream_addr
        .strip_prefix("http://")
        .or_else(|| upstream_addr.strip_prefix("ws://"))
        .unwrap_or(&upstream_addr)
        .trim_end_matches('/');

    if !is_safe_tcp_upstream(clean_tcp_addr) {
        write_simple_http1_error(
            &mut client_stream,
            StatusCode::BAD_GATEWAY,
            "502 Bad Gateway: WebSocket Upstream Blocked by SSRF Policy",
        )
        .await?;
        return Ok(());
    }

    let connect_timeout = Duration::from_millis(cfg.proxy_connect_timeout_ms.max(1000));
    let mut upstream = match tokio::time::timeout(connect_timeout, TcpStream::connect(clean_tcp_addr)).await {
        Ok(Ok(s)) => s,
        _ => {
            warn!(upstream = %clean_tcp_addr, "WebSocket Upstream connect failed");
            write_simple_http1_error(
                &mut client_stream,
                StatusCode::BAD_GATEWAY,
                "WebSocket Upstream Unreachable",
            )
            .await?;
            return Ok(());
        }
    };
    let _ = upstream.set_nodelay(true);

    let handshake_bytes =
        build_upstream_http1_request(&req, cfg, clean_tcp_addr, true, true, true);
    upstream.write_all(&handshake_bytes).await?;
    if !leftover_buf.is_empty() {
        upstream.write_all(&leftover_buf).await?;
    }
    upstream.flush().await?;

    let _ = tokio::io::copy_bidirectional(&mut client_stream, &mut upstream).await;
    Ok(())
}

// ============================================================================
// HÀM TIỆN ÍCH PHỤ TRỢ & SANITIZERS
// ============================================================================

fn sanitize_header_name(raw: &str) -> String {
    raw.chars()
        .filter(|&c| {
            c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'
        })
        .collect()
}

fn sanitize_header_value(raw: &str) -> String {
    raw.chars()
        .filter(|&c| c != '\r' && c != '\n' && c != '\0')
        .collect()
}

fn escape_json_str(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

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
        || name.eq_ignore_ascii_case("trailer")
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
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        if size_line.is_empty() {
            break;
        }
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

/// Bộ giải mã Chunked Body nghiêm ngặt theo RFC 9112 §7.1:
/// - Từ chối kích thước chunk không phải số Hex hợp lệ (không `unwrap_or(0)`)
/// - Kiểm tra chính xác dấu kết thúc `\r\n` sau mỗi chunk
/// - Tiêu thụ sạch trailer headers sau chunk `0` để không để sót byte gây Request Smuggling
async fn read_chunked_http1_body<S>(
    stream: &mut S,
    read_buf: &mut BytesMut,
    max_size: usize,
) -> std::result::Result<Bytes, ChunkReadError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut out = BytesMut::new();
    loop {
        while !read_buf.windows(2).any(|w| w == b"\r\n") {
            if read_buf.len() > 4096 {
                return Err(ChunkReadError::MalformedChunk(
                    "400 Bad Request: Chunk Size Line Too Long",
                ));
            }
            let n = stream
                .read_buf(read_buf)
                .await
                .map_err(ChunkReadError::IoError)?;
            if n == 0 {
                return Err(ChunkReadError::MalformedChunk(
                    "400 Bad Request: Unexpected EOF in Chunked Encoding",
                ));
            }
        }
        let crlf_pos = read_buf.windows(2).position(|w| w == b"\r\n").unwrap();
        let line_str = std::str::from_utf8(&read_buf[..crlf_pos]).map_err(|_| {
            ChunkReadError::MalformedChunk("400 Bad Request: Invalid UTF-8 in Chunk Size Line")
        })?;
        let size_hex = line_str.split(';').next().unwrap_or("").trim();
        if size_hex.is_empty() || !size_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ChunkReadError::MalformedChunk(
                "400 Bad Request: Invalid Chunk Size Hexadecimal",
            ));
        }
        let chunk_len = usize::from_str_radix(size_hex, 16).map_err(|_| {
            ChunkReadError::MalformedChunk("400 Bad Request: Chunk Size Integer Overflow")
        })?;
        let _ = read_buf.split_to(crlf_pos + 2);

        if chunk_len == 0 {
            // Đọc phần kết thúc chunk cuối (có thể là `\r\n` ngay hoặc kèm trailer headers kết thúc bằng `\r\n\r\n`)
            let mut trailer_bytes_consumed = 0usize;
            loop {
                while !read_buf.windows(2).any(|w| w == b"\r\n") {
                    if read_buf.len() + trailer_bytes_consumed > 8192 {
                        return Err(ChunkReadError::MalformedChunk(
                            "400 Bad Request: Chunk Trailers Too Large",
                        ));
                    }
                    let n = stream
                        .read_buf(read_buf)
                        .await
                        .map_err(ChunkReadError::IoError)?;
                    if n == 0 {
                        return Err(ChunkReadError::MalformedChunk(
                            "400 Bad Request: Missing Terminating CRLF After Zero Chunk",
                        ));
                    }
                }
                let pos = read_buf.windows(2).position(|w| w == b"\r\n").unwrap();
                let _ = read_buf.split_to(pos + 2);
                if pos == 0 {
                    // Dòng trống `\r\n` kết thúc toàn bộ chunked body
                    break;
                }
                trailer_bytes_consumed += pos + 2;
                if trailer_bytes_consumed > 8192 {
                    return Err(ChunkReadError::MalformedChunk(
                        "400 Bad Request: Chunk Trailers Exceed Limit",
                    ));
                }
            }
            return Ok(out.freeze());
        }

        if out.len().saturating_add(chunk_len) > max_size {
            return Err(ChunkReadError::PayloadTooLarge);
        }

        while read_buf.len() < chunk_len + 2 {
            let n = stream
                .read_buf(read_buf)
                .await
                .map_err(ChunkReadError::IoError)?;
            if n == 0 {
                return Err(ChunkReadError::MalformedChunk(
                    "400 Bad Request: Unexpected EOF Inside Chunk Payload",
                ));
            }
        }

        out.extend_from_slice(&read_buf.split_to(chunk_len));
        if &read_buf[..2] != b"\r\n" {
            return Err(ChunkReadError::MalformedChunk(
                "400 Bad Request: Missing CRLF After Chunk Data",
            ));
        }
        let _ = read_buf.split_to(2);
    }
}

fn should_emit_alt_svc(host: &str, cfg: &ServerConfig) -> bool {
    if !cfg.enable_http3_quic {
        return false;
    }
    match match_virtual_host(strip_port(host), cfg) {
        Some(vhost) => vhost.enable_http3_alt_svc,
        None => true,
    }
}

async fn write_http1_response<S>(
    stream: &mut S,
    resp: &HttpResponsePayload,
    cfg: &ServerConfig,
    keep_alive: bool,
    emit_alt_svc: bool,
    stats: &EngineRuntimeStats,
) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let https_port = cfg.https_port();
    let reason = resp.status.canonical_reason().unwrap_or("OK");
    let mut head = Vec::with_capacity(512);

    head.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", resp.status.as_u16(), reason).as_bytes());
    if cfg.server_tokens {
        head.extend_from_slice(b"Server: FerrousX\r\n");
    }
    if emit_alt_svc {
        head.extend_from_slice(
            format!(
                "Alt-Svc: h3=\":{https_port}\"; ma={}, h3-29=\":{https_port}\"; ma={}\r\n",
                cfg.alt_svc_max_age, cfg.alt_svc_max_age
            )
            .as_bytes(),
        );
    }

    for (k, v) in &resp.headers {
        if is_hop_by_hop_header(k) || k.eq_ignore_ascii_case("content-length") {
            continue;
        }
        let clean_k = sanitize_header_name(k);
        let clean_v = sanitize_header_value(v);
        if !clean_k.is_empty() {
            head.extend_from_slice(format!("{clean_k}: {clean_v}\r\n").as_bytes());
        }
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
        stats
            .bytes_sent
            .fetch_add(resp.body.len() as u64, Ordering::Relaxed);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_port_and_header_sanitizers() {
        assert_eq!(strip_port("example.com:443"), "example.com");
        assert_eq!(strip_port("[::1]:8080"), "[::1]");
        assert_eq!(
            sanitize_header_value("https://example.com/\r\nSet-Cookie: evil=1"),
            "https://example.com/Set-Cookie: evil=1"
        );
    }

    #[tokio::test]
    async fn test_strict_chunked_decoder_rejects_malformed_hex() {
        let mut cursor = std::io::Cursor::new(b"ZZ\r\nsmuggled\r\n0\r\n\r\n".to_vec());
        let mut buf = BytesMut::new();
        let res = read_chunked_http1_body(&mut cursor, &mut buf, 1024).await;
        assert!(matches!(res, Err(ChunkReadError::MalformedChunk(_))));
    }

    #[tokio::test]
    async fn test_strict_chunked_decoder_valid_chunks() {
        let mut cursor =
            std::io::Cursor::new(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n".to_vec());
        let mut buf = BytesMut::new();
        let res = read_chunked_http1_body(&mut cursor, &mut buf, 1024)
            .await
            .expect("valid chunked body");
        assert_eq!(&res[..], b"hello world");
        assert!(buf.is_empty());
    }
}
