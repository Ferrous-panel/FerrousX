//! crates/ferrousx-http/src/server.rs
//! Động cơ phục vụ Triple-Stack đã gia cố bảo mật Production:
//!   - TCP HTTP/1.1 (:80) — Chống Request Smuggling (CL.TE / TE.CL), Slowloris, Slow POST, Expect 100-continue, CRLF Injection
//!   - TCP HTTPS TLS 1.3/1.2 ALPN h2,http/1.1 (:443) — Giới hạn stream/frame HTTP/2, chống Rapid Reset & Oversized Body
//!   - UDP HTTP/3 QUIC (:443) + quảng bá Alt-Svc (chỉ khi QUIC bind thành công) — Retry address validation & chống Truncated Body
//! Hỗ trợ:
//!   - Tích hợp trực tiếp ZeroAllocWafEngine (GCRA Sharded IPv4/IPv6 /64 Rate Limiter + DPI L7 WAF)
//!   - Xác thực Trusted Proxy CIDR trước khi tin cậy `CF-Connecting-IP` / `X-Forwarded-For` (phải nhất) / `X-Forwarded-Proto`
//!   - Chống SSRF (chặn Cloud Metadata 169.254.169.254, link-local, broadcast) & streaming phản hồi Upstream kèm idle timeout
//!   - Phục vụ file tĩnh streaming 64 KiB chunk (Range/206, ETag, Last-Modified, 304, Cache-Control, dir 301) hoàn toàn bằng `tokio::fs`
//!   - WebSocket Upgrade Tunneling có kiểm tra Origin (chống CSWSH), unix: upstream, connect & idle timeout
//!   - Định tuyến phpMyAdmin (`/phpadmin`, `/phpmyadmin`) cách ly theo host quản trị
//!   - Thực thi PHP-FPM FastCGI chuẩn (`PATH_INFO`/`PATH_TRANSLATED`, chống Httpoxy CVE-2016-5385)

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::SeekFrom;
use std::net::{IpAddr, SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket};
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderName, HeaderValue, Response, StatusCode};
use quinn::{Endpoint, EndpointConfig, ServerConfig as QuinnServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::Semaphore;
use tokio::task::LocalSet;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use ferrousx_config::config::{
    is_forbidden_ssrf_ip, validate_upstream_origin, BackendProtocol, CompressionConfig,
    ConfigManager, RouteRule, ServerConfig, VirtualHost, WafMode,
};
use ferrousx_core::metrics::EngineRuntimeStats;
use ferrousx_proxy::fastcgi::{
    detect_php_fpm_socket, execute_fastcgi, normalize_and_decode_uri_path,
};
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

/// Bộ quản lý cân bằng tải P2C/Round-Robin/Maglev + CircuitBreaker theo từng Epoch cấu hình
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

enum UpstreamIo {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl AsyncRead for UpstreamIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpstreamIo::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            UpstreamIo::Unix(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

/// Phản hồi nội bộ hỗ trợ cả payload đệm nhỏ lẫn streaming file tĩnh & upstream SSE/dữ liệu lớn
enum DispatchResponse {
    Buffered(HttpResponsePayload),
    StaticFile {
        status: StatusCode,
        headers: Vec<(String, String)>,
        path: PathBuf,
        offset: u64,
        len: u64,
    },
    UpstreamStream {
        status: StatusCode,
        headers: Vec<(String, String)>,
        stream: UpstreamIo,
        initial_bytes: Bytes,
        known_content_length: Option<u64>,
        max_bytes: usize,
        read_timeout: Duration,
        upstream_chunked: bool,
    },
}

impl DispatchResponse {
    fn status(&self) -> StatusCode {
        match self {
            Self::Buffered(p) => p.status,
            Self::StaticFile { status, .. } => *status,
            Self::UpstreamStream { status, .. } => *status,
        }
    }
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
#[derive(Debug, PartialEq, Eq)]
enum ChunkReadError {
    PayloadTooLarge,
    MalformedChunk(&'static str),
    Timeout,
    IoError(String),
}

/// Bắt panic ở ranh giới một Future xử lý request (tương thích `panic = "unwind"`, không để 1 request sập cả worker)
async fn catch_unwind_future<F: std::future::Future>(fut: F) -> std::thread::Result<F::Output> {
    let mut fut = std::pin::pin!(fut);
    std::future::poll_fn(|cx| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fut.as_mut().poll(cx))) {
            Ok(Poll::Ready(out)) => Poll::Ready(Ok(out)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(panic_payload) => Poll::Ready(Err(panic_payload)),
        }
    })
    .await
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
    let worker_sem = Arc::new(Semaphore::new(
        initial_cfg.max_connections_per_worker.max(64),
    ));

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

    let quic_enabled = quic_endpoint.is_some();

    info!(
        worker_id,
        core = ctx.core_id.id,
        numa_node = ctx.numa_node,
        hugepage_pinned = ctx.hugepage_arena.is_some(),
        quic_enabled,
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
                        Arc::clone(&worker_sem),
                        Arc::clone(&stats),
                        Arc::clone(&acme_mgr),
                        Arc::clone(&upstream_reg),
                        quic_enabled,
                    ),
                    run_tcp_https_loop(
                        worker_id,
                        https_listener,
                        tls_acceptor,
                        Arc::clone(&config_mgr),
                        Arc::clone(&waf_engine),
                        Arc::clone(&conn_tracker),
                        Arc::clone(&worker_sem),
                        Arc::clone(&stats),
                        Arc::clone(&acme_mgr),
                        Arc::clone(&upstream_reg),
                        quic_enabled,
                    ),
                    run_udp_h3_quic_loop(
                        worker_id,
                        endpoint,
                        config_mgr,
                        waf_engine,
                        conn_tracker,
                        worker_sem,
                        stats,
                        acme_mgr,
                        upstream_reg,
                        quic_enabled,
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
                        Arc::clone(&worker_sem),
                        Arc::clone(&stats),
                        Arc::clone(&acme_mgr),
                        Arc::clone(&upstream_reg),
                        false,
                    ),
                    run_tcp_https_loop(
                        worker_id,
                        https_listener,
                        tls_acceptor,
                        config_mgr,
                        waf_engine,
                        conn_tracker,
                        worker_sem,
                        stats,
                        acme_mgr,
                        upstream_reg,
                        false,
                    ),
                )
                .map(|_| ())
            }
        })
        .await?;

    Ok(())
}

/// Vòng lặp tiếp nhận kết nối TCP HTTP (:80) có backoff chống chết worker khi EMFILE/ECONNABORTED
async fn run_tcp_plain_http_loop(
    worker_id: usize,
    listener: TcpListener,
    config_mgr: Arc<ConfigManager>,
    waf_engine: Arc<ZeroAllocWafEngine>,
    conn_tracker: Arc<ActiveConnectionTracker>,
    worker_sem: Arc<Semaphore>,
    stats: Arc<EngineRuntimeStats>,
    acme_mgr: Arc<AcmeCertManager>,
    upstream_reg: Arc<UpstreamBalancerRegistry>,
    quic_enabled: bool,
) -> Result<()> {
    let mut backoff_ms: u64 = 5;
    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(pair) => {
                backoff_ms = 5;
                pair
            }
            Err(err) => {
                warn!(worker_id, error = %err, backoff_ms, "Lỗi accept tạm thời trên TCP :80; thử lại sau backoff");
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(100);
                continue;
            }
        };

        let Ok(sem_permit) = Arc::clone(&worker_sem).try_acquire_owned() else {
            warn!(worker_id, ip = %peer_addr.ip(), "Từ chối kết nối TCP :80 do vượt worker Semaphore");
            drop(tcp_stream);
            continue;
        };

        let cfg = config_mgr.current();
        let Some(conn_guard) = conn_tracker.try_acquire(
            peer_addr.ip(),
            cfg.max_concurrent_connections,
            cfg.max_connections_per_ip,
        ) else {
            warn!(worker_id, ip = %peer_addr.ip(), "Từ chối kết nối TCP :80 do vượt ngưỡng kết nối đồng thời");
            drop(sem_permit);
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
            let _conn_guard = conn_guard;
            let _sem_permit = sem_permit;
            match catch_unwind_future(serve_http1_connection(
                tcp_stream,
                peer_addr,
                false,
                quic_enabled,
                cfg_mgr,
                waf,
                st,
                acme,
                reg,
            ))
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    debug!(worker_id, %peer_addr, error = %e, "Kết thúc phiên HTTP (:80)");
                }
                Err(_) => {
                    error!(worker_id, %peer_addr, "Phát hiện panic cô lập ở phiên HTTP (:80); worker vẫn tiếp tục chạy");
                }
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
    worker_sem: Arc<Semaphore>,
    stats: Arc<EngineRuntimeStats>,
    acme_mgr: Arc<AcmeCertManager>,
    upstream_reg: Arc<UpstreamBalancerRegistry>,
    quic_enabled: bool,
) -> Result<()> {
    let mut backoff_ms: u64 = 5;
    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(pair) => {
                backoff_ms = 5;
                pair
            }
            Err(err) => {
                warn!(worker_id, error = %err, backoff_ms, "Lỗi accept tạm thời trên TCP :443; thử lại sau backoff");
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(100);
                continue;
            }
        };

        let Ok(sem_permit) = Arc::clone(&worker_sem).try_acquire_owned() else {
            warn!(worker_id, ip = %peer_addr.ip(), "Từ chối kết nối TLS :443 do vượt worker Semaphore");
            drop(tcp_stream);
            continue;
        };

        let cfg = config_mgr.current();
        let Some(conn_guard) = conn_tracker.try_acquire(
            peer_addr.ip(),
            cfg.max_concurrent_connections,
            cfg.max_connections_per_ip,
        ) else {
            warn!(worker_id, ip = %peer_addr.ip(), "Từ chối kết nối TLS :443 do vượt ngưỡng kết nối đồng thời");
            drop(sem_permit);
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
            let _conn_guard = conn_guard;
            let _sem_permit = sem_permit;
            match tokio::time::timeout(handshake_timeout, acceptor.accept(tcp_stream)).await {
                Ok(Ok(tls_stream)) => {
                    let (_, server_conn) = tls_stream.get_ref();
                    let negotiated_alpn = server_conn
                        .alpn_protocol()
                        .map(|p| p.to_vec())
                        .unwrap_or_else(|| b"http/1.1".to_vec());

                    if negotiated_alpn.as_slice() == b"h2" {
                        match catch_unwind_future(serve_http2_connection(
                            tls_stream,
                            peer_addr,
                            quic_enabled,
                            cfg_mgr,
                            waf,
                            st,
                            acme,
                            reg,
                        ))
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => {
                                debug!(worker_id, %peer_addr, error = %e, "Kết thúc phiên HTTPS HTTP/2 (:443)");
                            }
                            Err(_) => {
                                error!(worker_id, %peer_addr, "Phát hiện panic cô lập ở phiên HTTP/2 (:443)");
                            }
                        }
                    } else {
                        match catch_unwind_future(serve_http1_connection(
                            tls_stream,
                            peer_addr,
                            true,
                            quic_enabled,
                            cfg_mgr,
                            waf,
                            st,
                            acme,
                            reg,
                        ))
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => {
                                debug!(worker_id, %peer_addr, error = %e, "Kết thúc phiên HTTPS HTTP/1.1 (:443)");
                            }
                            Err(_) => {
                                error!(worker_id, %peer_addr, "Phát hiện panic cô lập ở phiên HTTPS HTTP/1.1 (:443)");
                            }
                        }
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
/// Slowloris, Slow POST, Expect: 100-continue, và hỗ trợ WebSocket Upgrade Tunneling
#[allow(clippy::too_many_arguments)]
async fn serve_http1_connection<S>(
    mut stream: S,
    peer_addr: SocketAddr,
    is_tls: bool,
    quic_enabled: bool,
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
                return Ok(());
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                if !read_buf.is_empty() {
                    let _ = write_simple_http1_error(
                        &mut stream,
                        StatusCode::REQUEST_TIMEOUT,
                        "408 Request Timeout",
                    )
                    .await;
                }
                return Ok(());
            }
        };

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
        let mut conn_close = version == 0;
        let mut is_upgrade_conn = false;
        let mut is_websocket_upgrade = false;
        let mut expect_100_continue = false;
        let mut expect_invalid = false;
        let mut parsed_headers = Vec::with_capacity(req.headers.len());

        for h in req.headers.iter() {
            let name = h.name;
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
            } else if name.eq_ignore_ascii_case("expect") {
                if val.eq_ignore_ascii_case("100-continue") {
                    expect_100_continue = true;
                } else {
                    expect_invalid = true;
                }
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

        if version >= 1 && host_count == 0 {
            write_simple_http1_error(
                &mut stream,
                StatusCode::BAD_REQUEST,
                "400 Bad Request: Missing Host Header in HTTP/1.1",
            )
            .await?;
            return Ok(());
        }

        if expect_invalid {
            write_simple_http1_error(
                &mut stream,
                StatusCode::EXPECTATION_FAILED,
                "417 Expectation Failed",
            )
            .await?;
            return Ok(());
        }

        // Chống HTTP Request Smuggling (CL.TE / TE.CL)
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
        let _ = read_buf.split_to(header_end + 4);

        if is_upgrade_conn && is_websocket_upgrade {
            stats.total_requests.fetch_add(1, Ordering::Relaxed);
            let incoming = IncomingRequest {
                method: method.clone(),
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
                let emit_alt = quic_enabled && should_emit_alt_svc(&incoming.host, &cfg);
                write_http1_response(
                    &mut stream,
                    &incoming.method,
                    &waf_resp,
                    &cfg,
                    false,
                    emit_alt,
                    &stats,
                )
                .await?;
                return Ok(());
            }
            return handle_websocket_upgrade(stream, read_buf, incoming, &cfg, &upstream_reg).await;
        }

        if content_length > cfg.client_max_body_size {
            write_simple_http1_error(
                &mut stream,
                StatusCode::PAYLOAD_TOO_LARGE,
                "413 Payload Too Large",
            )
            .await?;
            return Ok(());
        }

        // Xử lý `Expect: 100-continue` theo RFC 9110 §10.1.1 trước khi chờ body
        if expect_100_continue && version >= 1 && (is_chunked || content_length > 0) && read_buf.is_empty()
        {
            stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
            stream.flush().await?;
        }

        let body_timeout = Duration::from_millis(cfg.client_body_timeout_ms.max(1000));

        let body = if is_chunked {
            match read_chunked_http1_body(
                &mut stream,
                &mut read_buf,
                cfg.client_max_body_size,
                body_timeout,
            )
            .await
            {
                Ok(bytes) => bytes,
                Err(ChunkReadError::PayloadTooLarge) => {
                    write_simple_http1_error(
                        &mut stream,
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "413 Payload Too Large",
                    )
                    .await?;
                    return Ok(());
                }
                Err(ChunkReadError::MalformedChunk(reason)) => {
                    write_simple_http1_error(&mut stream, StatusCode::BAD_REQUEST, reason).await?;
                    return Ok(());
                }
                Err(ChunkReadError::Timeout) => {
                    write_simple_http1_error(
                        &mut stream,
                        StatusCode::REQUEST_TIMEOUT,
                        "408 Request Timeout",
                    )
                    .await?;
                    return Ok(());
                }
                Err(ChunkReadError::IoError(msg)) => {
                    return Err(anyhow::anyhow!("Chunked body IO error: {msg}"));
                }
            }
        } else if content_length > 0 {
            let mut body_ok = true;
            while read_buf.len() < content_length {
                match tokio::time::timeout(body_timeout, stream.read_buf(&mut read_buf)).await {
                    Ok(Ok(0)) => {
                        write_simple_http1_error(
                            &mut stream,
                            StatusCode::BAD_REQUEST,
                            "400 Bad Request: Unexpected EOF While Reading Request Body",
                        )
                        .await?;
                        return Ok(());
                    }
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => return Err(e.into()),
                    Err(_) => {
                        body_ok = false;
                        break;
                    }
                }
            }
            if !body_ok {
                write_simple_http1_error(
                    &mut stream,
                    StatusCode::REQUEST_TIMEOUT,
                    "408 Request Timeout",
                )
                .await?;
                return Ok(());
            }
            read_buf.split_to(content_length).freeze()
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

        let resp = dispatch_http_request_full(
            &incoming,
            &cfg,
            &waf_engine,
            &stats,
            &acme_mgr,
            &upstream_reg,
        )
        .await;
        let status = resp.status();
        let force_close = matches!(
            status,
            StatusCode::BAD_REQUEST
                | StatusCode::REQUEST_TIMEOUT
                | StatusCode::PAYLOAD_TOO_LARGE
                | StatusCode::URI_TOO_LONG
                | StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
                | StatusCode::EXPECTATION_FAILED
                | StatusCode::TOO_MANY_REQUESTS
        );
        let keep_alive = !conn_close && !force_close;
        let emit_alt = quic_enabled && should_emit_alt_svc(&incoming.host, &cfg);

        write_http1_dispatch_response(
            &mut stream,
            &incoming.method,
            version >= 1,
            resp,
            &cfg,
            keep_alive,
            emit_alt,
            &stats,
        )
        .await?;
        requests_served += 1;

        if !keep_alive {
            return Ok(());
        }
    }
}

/// Phục vụ đa luồng khung (multiplexed frames) HTTP/2 trên kết nối TCP TLS 1.3/1.2 (:443)
#[allow(clippy::too_many_arguments)]
async fn serve_http2_connection<S>(
    stream: S,
    peer_addr: SocketAddr,
    quic_enabled: bool,
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
        .max_header_list_size(initial_cfg.h2_max_header_list_size)
        .max_frame_size(16_384)
        .initial_window_size(65_535)
        .initial_connection_window_size(1024 * 1024);

    let mut h2_conn = h2_builder.handshake(stream).await?;
    let idle_timeout = Duration::from_millis(initial_cfg.keepalive_timeout_ms.max(10_000));

    loop {
        let next_stream = match tokio::time::timeout(idle_timeout, h2_conn.accept()).await {
            Ok(Some(res)) => res,
            Ok(None) => break,
            Err(_) => {
                h2_conn.graceful_shutdown();
                break;
            }
        };
        let (request, mut respond) = next_stream?;
        let cfg_mgr = Arc::clone(&config_mgr);
        let waf = Arc::clone(&waf_engine);
        let st = Arc::clone(&stats);
        let acme = Arc::clone(&acme_mgr);
        let reg = Arc::clone(&upstream_reg);

        tokio::task::spawn_local(async move {
            let cfg = cfg_mgr.current();
            let (parts, mut body_stream) = request.into_parts();

            if let Some(cl_val) = parts.headers.get(http::header::CONTENT_LENGTH) {
                if let Ok(cl_str) = cl_val.to_str() {
                    if let Ok(cl) = cl_str.trim().parse::<usize>() {
                        if cl > cfg.client_max_body_size {
                            drop(body_stream);
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
            let mut total_body_len: usize = 0;
            let mut body_too_large = false;
            let mut body_err = false;
            let mut timed_out = false;

            loop {
                match tokio::time::timeout(body_timeout, body_stream.data()).await {
                    Ok(Some(Ok(chunk))) => {
                        match total_body_len.checked_add(chunk.len()) {
                            Some(new_len) if new_len <= cfg.client_max_body_size => {
                                total_body_len = new_len;
                                body_buf.extend_from_slice(&chunk);
                                let _ = body_stream.flow_control().release_capacity(chunk.len());
                            }
                            _ => {
                                body_too_large = true;
                                break;
                            }
                        }
                    }
                    Ok(Some(Err(_))) => {
                        body_err = true;
                        break;
                    }
                    Ok(None) => break,
                    Err(_) => {
                        timed_out = true;
                        break;
                    }
                }
            }

            if timed_out {
                drop(body_stream);
                send_h2_simple_error(
                    &mut respond,
                    StatusCode::REQUEST_TIMEOUT,
                    b"408 Request Timeout",
                );
                return;
            }
            if body_too_large {
                drop(body_stream);
                send_h2_simple_error(
                    &mut respond,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    b"413 Payload Too Large",
                );
                return;
            }
            if body_err {
                drop(body_stream);
                respond.send_reset(h2::Reason::CANCEL);
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

            let resp_dispatch = match catch_unwind_future(dispatch_http_request_full(
                &incoming, &cfg, &waf, &st, &acme, &reg,
            ))
            .await
            {
                Ok(r) => r,
                Err(_) => {
                    error!(%peer_addr, "Phát hiện panic cô lập khi xử lý HTTP/2 stream");
                    respond.send_reset(h2::Reason::INTERNAL_ERROR);
                    return;
                }
            };

            let emit_alt_svc = quic_enabled && should_emit_alt_svc(&incoming.host, &cfg);
            send_h2_dispatch_response(
                &mut respond,
                &incoming.method,
                resp_dispatch,
                &cfg,
                emit_alt_svc,
                &st,
            )
            .await;
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

/// Vòng lặp tiếp nhận kết nối UDP QUIC và phân luồng HTTP/3 (RFC 9114) kèm stateless Retry validation
#[allow(clippy::too_many_arguments)]
async fn run_udp_h3_quic_loop(
    worker_id: usize,
    endpoint: Endpoint,
    config_mgr: Arc<ConfigManager>,
    waf_engine: Arc<ZeroAllocWafEngine>,
    conn_tracker: Arc<ActiveConnectionTracker>,
    worker_sem: Arc<Semaphore>,
    stats: Arc<EngineRuntimeStats>,
    acme_mgr: Arc<AcmeCertManager>,
    upstream_reg: Arc<UpstreamBalancerRegistry>,
    _quic_enabled: bool,
) -> Result<()> {
    while let Some(incoming_handshake) = endpoint.accept().await {
        if !incoming_handshake.remote_address_validated() {
            let _ = incoming_handshake.retry();
            continue;
        }
        let peer_addr = incoming_handshake.remote_address();
        let Ok(sem_permit) = Arc::clone(&worker_sem).try_acquire_owned() else {
            warn!(worker_id, ip = %peer_addr.ip(), "Từ chối kết nối QUIC :443 do vượt worker Semaphore");
            incoming_handshake.refuse();
            continue;
        };

        let cfg = config_mgr.current();
        let Some(conn_guard) = conn_tracker.try_acquire(
            peer_addr.ip(),
            cfg.max_concurrent_connections,
            cfg.max_connections_per_ip,
        ) else {
            warn!(worker_id, ip = %peer_addr.ip(), "Từ chối kết nối QUIC :443 do vượt ngưỡng kết nối đồng thời");
            drop(sem_permit);
            incoming_handshake.refuse();
            continue;
        };

        let cfg_mgr = Arc::clone(&config_mgr);
        let waf = Arc::clone(&waf_engine);
        let st = Arc::clone(&stats);
        let acme = Arc::clone(&acme_mgr);
        let reg = Arc::clone(&upstream_reg);

        tokio::task::spawn_local(async move {
            let _conn_guard = conn_guard;
            let _sem_permit = sem_permit;
            match incoming_handshake.await {
                Ok(quic_conn) => {
                    let remote = quic_conn.remote_address();
                    match catch_unwind_future(serve_http3_quic_streams(
                        quic_conn, remote, cfg_mgr, waf, st, acme, reg,
                    ))
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => {
                            debug!(worker_id, error = %err, "Đóng kết nối HTTP/3 QUIC");
                        }
                        Err(_) => {
                            error!(worker_id, %remote, "Phát hiện panic cô lập trên kết nối QUIC");
                        }
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

                    if let Some(cl_val) = parts.headers.get(http::header::CONTENT_LENGTH) {
                        if let Ok(cl_str) = cl_val.to_str() {
                            if let Ok(cl) = cl_str.trim().parse::<usize>() {
                                if cl > cfg.client_max_body_size {
                                    stream.stop_sending(h3::error::Code::H3_MESSAGE_ERROR);
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
                    let mut total_body_len: usize = 0;
                    let mut body_too_large = false;
                    let mut body_err = false;
                    let mut timed_out = false;

                    loop {
                        match tokio::time::timeout(body_timeout, stream.recv_data()).await {
                            Ok(Ok(Some(mut chunk))) => {
                                match total_body_len.checked_add(chunk.remaining()) {
                                    Some(new_len) if new_len <= cfg.client_max_body_size => {
                                        total_body_len = new_len;
                                        body_buf.extend_from_slice(chunk.chunk());
                                        chunk.advance(chunk.remaining());
                                    }
                                    _ => {
                                        body_too_large = true;
                                        break;
                                    }
                                }
                            }
                            Ok(Ok(None)) => break,
                            Ok(Err(_)) => {
                                body_err = true;
                                break;
                            }
                            Err(_) => {
                                timed_out = true;
                                break;
                            }
                        }
                    }

                    if timed_out {
                        stream.stop_sending(h3::error::Code::H3_MESSAGE_ERROR);
                        send_h3_simple_error(
                            &mut stream,
                            StatusCode::REQUEST_TIMEOUT,
                            b"408 Request Timeout",
                        )
                        .await;
                        return;
                    }
                    if body_too_large {
                        stream.stop_sending(h3::error::Code::H3_MESSAGE_ERROR);
                        send_h3_simple_error(
                            &mut stream,
                            StatusCode::PAYLOAD_TOO_LARGE,
                            b"413 Payload Too Large",
                        )
                        .await;
                        return;
                    }
                    if body_err {
                        stream.stop_sending(h3::error::Code::H3_MESSAGE_ERROR);
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

                    let resp_dispatch = match catch_unwind_future(dispatch_http_request_full(
                        &incoming, &cfg, &waf, &st, &acme, &reg,
                    ))
                    .await
                    {
                        Ok(r) => r,
                        Err(_) => {
                            error!(%peer_addr, "Phát hiện panic cô lập khi xử lý HTTP/3 stream");
                            stream.stop_sending(h3::error::Code::H3_INTERNAL_ERROR);
                            return;
                        }
                    };
                    send_h3_dispatch_response(
                        &mut stream,
                        &incoming.method,
                        resp_dispatch,
                        &cfg,
                        &st,
                    )
                    .await;
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
                    body: Bytes::from_static(b"429 Too Many Requests"),
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
// HÀM PHỤ TRỢ ĐỊNH TUYẾN, BẢO MẬT ĐƯỜNG DẪN & CHỐNG HOST-ESCAPE
// ============================================================================

/// P0-1: Chỉ chấp nhận tên host hợp lệ (`[a-z0-9]([a-z0-9.-]*[a-z0-9])?`, không `.` đầu/cuối, không `..`, không `\`, không NUL)
fn validate_dynamic_wwwroot_host(host: &str) -> Option<String> {
    let trimmed = host.trim();
    if trimmed.is_empty()
        || trimmed.len() > 253
        || trimmed.starts_with('.')
        || trimmed.ends_with('.')
        || trimmed.starts_with('-')
        || trimmed.ends_with('-')
        || trimmed.contains("..")
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains('\0')
        || trimmed.contains(':')
        || trimmed.contains('@')
    {
        return None;
    }

    let lower = trimmed.to_ascii_lowercase();
    for label in lower.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return None;
        }
    }
    Some(lower)
}

/// P1-2: Kiểm tra đường dẫn nhạy cảm sau khi đã chuẩn hóa URL
fn is_sensitive_path(norm_path: &str) -> bool {
    let segments: Vec<&str> = norm_path.split('/').filter(|s| !s.is_empty()).collect();
    for (idx, seg) in segments.iter().enumerate() {
        let lower = seg.to_ascii_lowercase();
        if lower.starts_with('.') {
            // Chỉ cho phép /.well-known/ ở segment đầu tiên cho ACME HTTP-01
            if !(idx == 0 && lower == ".well-known") {
                return true;
            }
        }
        if matches!(
            lower.as_str(),
            "composer.json"
                | "composer.lock"
                | "package.json"
                | "package-lock.json"
                | "yarn.lock"
                | "pnpm-lock.yaml"
                | "cargo.toml"
                | "cargo.lock"
                | "web.config"
        ) || lower.starts_with("wp-config.php.")
        {
            return true;
        }
        if lower.ends_with(".sql")
            || lower.ends_with(".bak")
            || lower.ends_with(".old")
            || lower.ends_with(".orig")
            || lower.ends_with(".swp")
            || lower.ends_with(".log")
            || lower.ends_with(".ini")
        {
            return true;
        }
    }
    false
}

/// P1-9 / P0-8: So khớp prefix có ranh giới path (`== prefix` hoặc `starts_with(prefix + "/")`)
#[inline]
fn path_matches_prefix(norm_path: &str, prefix: &str) -> bool {
    let trimmed = prefix.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed == "/" {
        return true;
    }
    let clean = trimmed.trim_end_matches('/');
    if norm_path == clean {
        return true;
    }
    norm_path
        .strip_prefix(clean)
        .map(|rest| rest.starts_with('/'))
        .unwrap_or(false)
}

/// P1-9: Chọn route proxy khớp prefix dài nhất có ranh giới path
fn select_longest_proxy_route<'a>(
    routes: &'a [RouteRule],
    norm_path: &str,
) -> Option<&'a RouteRule> {
    routes
        .iter()
        .filter(|r| {
            r.backend_protocol != BackendProtocol::FastCgi
                && r.backend_protocol != BackendProtocol::StaticFile
                && path_matches_prefix(norm_path, &r.path_prefix)
        })
        .max_by_key(|r| {
            let p = r.path_prefix.trim().trim_end_matches('/');
            if p.is_empty() {
                1usize
            } else {
                p.len()
            }
        })
}

fn has_explicit_non_catchall_vhost(host_no_port: &str, cfg: &ServerConfig) -> bool {
    cfg.vhosts.iter().any(|v| {
        v.server_name != "_"
            && (v.server_name.eq_ignore_ascii_case(host_no_port)
                || v.aliases
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(host_no_port)))
    })
}

/// P0-8: Kiểm tra host hiện tại có phải host/IP quản trị hay không (không chiếm route của site khách)
fn is_admin_or_panel_host(host_no_port: &str, cfg: &ServerConfig) -> bool {
    let custom_domain = cfg.panel_admin.custom_domain.trim();
    if !custom_domain.is_empty() {
        return host_no_port.eq_ignore_ascii_case(custom_domain);
    }
    if has_explicit_non_catchall_vhost(host_no_port, cfg) {
        return false;
    }
    let stripped_v6 = host_no_port.trim_start_matches('[').trim_end_matches(']');
    host_no_port.is_empty()
        || host_no_port.eq_ignore_ascii_case("localhost")
        || stripped_v6.parse::<IpAddr>().is_ok()
}

/// P0-8: Kiểm tra request có thuộc Ferrous-Panel hay không
fn is_panel_request(req: &IncomingRequest, norm_path: &str, cfg: &ServerConfig) -> bool {
    let host_no_port = strip_port(&req.host);
    let custom_domain = cfg.panel_admin.custom_domain.trim();
    let entrance = cfg.panel_admin.security_entrance.trim();

    if !custom_domain.is_empty() && host_no_port.eq_ignore_ascii_case(custom_domain) {
        return true;
    }

    if !entrance.is_empty() {
        let normalized_entrance = if entrance.starts_with('/') {
            entrance.to_string()
        } else {
            format!("/{entrance}")
        };
        if path_matches_prefix(norm_path, &normalized_entrance)
            && !has_explicit_non_catchall_vhost(host_no_port, cfg)
        {
            return true;
        }
    }

    // Khi customDomain rỗng: CHỈ khớp các path quản trị đặc trưng trên host/IP quản trị (không chiếm `/api/*` trên mọi host!)
    if custom_domain.is_empty()
        && is_admin_or_panel_host(host_no_port, cfg)
        && (path_matches_prefix(norm_path, "/ferrous-panel")
            || path_matches_prefix(norm_path, "/ws/ssh")
            || path_matches_prefix(norm_path, "/ws/telemetry"))
    {
        return true;
    }

    false
}

/// P0-1 & P1-4: Phân giải an toàn đường dẫn dưới `site_root` bằng API bất đồng bộ `tokio::fs`
async fn safe_resolve_under_root_async(site_root: &Path, norm_path: &str) -> Option<PathBuf> {
    let trimmed = norm_path.trim_start_matches('/');
    let rel_path = Path::new(trimmed);
    for comp in rel_path.components() {
        match comp {
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
            Component::Normal(seg) => {
                let s = seg.to_string_lossy();
                if s.contains('\0') || s == ".." {
                    return None;
                }
            }
            Component::CurDir => {}
        }
    }

    let canonical_root = tokio::fs::canonicalize(site_root).await.ok()?;
    let joined = canonical_root.join(rel_path);

    if let Ok(_meta) = tokio::fs::symlink_metadata(&joined).await {
        let canonical_target = tokio::fs::canonicalize(&joined).await.ok()?;
        if !canonical_target.starts_with(&canonical_root) {
            return None;
        }
        return Some(canonical_target);
    }

    let mut ancestor = joined.parent();
    while let Some(p) = ancestor {
        if tokio::fs::symlink_metadata(p).await.is_ok() {
            let canonical_ancestor = tokio::fs::canonicalize(p).await.ok()?;
            if canonical_ancestor.starts_with(&canonical_root) {
                return Some(joined);
            }
            return None;
        }
        ancestor = p.parent();
    }

    None
}

// ============================================================================
// BỘ ĐỊNH TUYẾN CHÍNH (PRODUCTION ROUTER): WAF, CLOUDFLARE, PANEL, PHPMYADMIN, PHP-FPM
// ============================================================================

#[allow(dead_code)]
async fn dispatch_http_request(
    req: &IncomingRequest,
    cfg: &ServerConfig,
    waf_engine: &ZeroAllocWafEngine,
    stats: &EngineRuntimeStats,
    acme_mgr: &AcmeCertManager,
    upstream_reg: &UpstreamBalancerRegistry,
) -> HttpResponsePayload {
    match dispatch_http_request_full(req, cfg, waf_engine, stats, acme_mgr, upstream_reg).await {
        DispatchResponse::Buffered(p) => p,
        DispatchResponse::StaticFile {
            status,
            mut headers,
            path,
            offset,
            len,
        } => {
            let body = if let Ok(mut f) = tokio::fs::File::open(&path).await {
                if f.seek(SeekFrom::Start(offset)).await.is_ok() {
                    let mut buf = Vec::with_capacity(len.min(4 * 1024 * 1024) as usize);
                    let mut limited = f.take(len);
                    if limited.read_to_end(&mut buf).await.is_ok() {
                        Bytes::from(buf)
                    } else {
                        Bytes::new()
                    }
                } else {
                    Bytes::new()
                }
            } else {
                Bytes::new()
            };
            if !headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            {
                headers.push(("Content-Length".to_string(), body.len().to_string()));
            }
            HttpResponsePayload {
                status,
                headers,
                body,
            }
        }
        DispatchResponse::UpstreamStream {
            status,
            headers,
            mut stream,
            initial_bytes,
            max_bytes,
            read_timeout,
            upstream_chunked,
            ..
        } => {
            let mut raw = Vec::from(initial_bytes.as_ref());
            let mut tmp = [0u8; 16 * 1024];
            loop {
                match tokio::time::timeout(read_timeout, stream.read(&mut tmp)).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => {
                        if raw.len().saturating_add(n) > max_bytes {
                            return bad_gateway_response();
                        }
                        raw.extend_from_slice(&tmp[..n]);
                    }
                    _ => return bad_gateway_response(),
                }
            }
            let body = if upstream_chunked {
                match decode_chunked_body(&raw, max_bytes) {
                    Ok(b) => b,
                    Err(_) => return bad_gateway_response(),
                }
            } else {
                Bytes::from(raw)
            };
            HttpResponsePayload {
                status,
                headers,
                body,
            }
        }
    }
}

async fn dispatch_http_request_full(
    req: &IncomingRequest,
    cfg: &ServerConfig,
    waf_engine: &ZeroAllocWafEngine,
    stats: &EngineRuntimeStats,
    acme_mgr: &AcmeCertManager,
    upstream_reg: &UpstreamBalancerRegistry,
) -> DispatchResponse {
    stats.total_requests.fetch_add(1, Ordering::Relaxed);

    // 0. Kiểm tra WAF & Sharded GCRA Rate Limiter
    if let Some(waf_blocked_resp) = check_waf_for_request(req, cfg, waf_engine, stats) {
        return DispatchResponse::Buffered(waf_blocked_resp);
    }

    // P1-1: Giải mã percent-encoding 1 lần + từ chối %00/%2f/%5c + chuẩn hóa //, ., ..
    let Ok(norm_path) = normalize_and_decode_uri_path(&req.path) else {
        return DispatchResponse::Buffered(HttpResponsePayload {
            status: StatusCode::BAD_REQUEST,
            headers: vec![(
                "Content-Type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
            body: Bytes::from_static(b"400 Bad Request"),
        });
    };

    let host_no_port = strip_port(&req.host);

    // 1. Định tuyến phpMyAdmin chỉ trên host/IP quản trị (P0-8)
    if cfg.enable_phpmyadmin_route && is_admin_or_panel_host(host_no_port, cfg) {
        if norm_path == "/phpadmin" || norm_path == "/phpmyadmin" {
            let mut target_loc = format!("{norm_path}/");
            if !req.query.is_empty() {
                target_loc.push('?');
                target_loc.push_str(&req.query);
            }
            return DispatchResponse::Buffered(HttpResponsePayload {
                status: StatusCode::FOUND,
                headers: vec![
                    ("Location".to_string(), sanitize_header_value(&target_loc)),
                    ("Cache-Control".to_string(), "no-store".to_string()),
                ],
                body: Bytes::new(),
            });
        }

        if norm_path.starts_with("/phpadmin/") || norm_path.starts_with("/phpmyadmin/") {
            let resp =
                proxy_http1_upstream_dispatch(&cfg.phpmyadmin_upstream, req, cfg, true, true, stats)
                    .await;
            return maybe_compress_dispatch_response(req, cfg, resp).await;
        }
    }

    // 2. Đồng bộ định tuyến động tới Ferrous-Panel từ panel.env & admin.json (P0-8)
    if is_panel_request(req, &norm_path, cfg) {
        let panel_upstream = cfg.panel_admin.panel_upstream_addr();
        let resp =
            proxy_http1_upstream_dispatch(&panel_upstream, req, cfg, true, true, stats).await;
        return maybe_compress_dispatch_response(req, cfg, resp).await;
    }

    // 3. Tìm VirtualHost khớp với Host header
    if let Some(vhost) = match_virtual_host(host_no_port, cfg) {
        // 3a. Phục vụ ACME HTTP-01 Challenge trước Redirect HTTPS
        let acme_prefix = if vhost.acme_prefix.trim().is_empty() {
            cfg.acme_challenge_prefix.as_str()
        } else {
            vhost.acme_prefix.as_str()
        };
        if !req.is_tls && vhost.acme_serve_before_redirect && norm_path.starts_with(acme_prefix) {
            if req.method != "GET" && req.method != "HEAD" {
                return DispatchResponse::Buffered(HttpResponsePayload {
                    status: StatusCode::METHOD_NOT_ALLOWED,
                    headers: vec![
                        ("Allow".to_string(), "GET, HEAD".to_string()),
                        (
                            "Content-Type".to_string(),
                            "text/plain; charset=utf-8".to_string(),
                        ),
                    ],
                    body: Bytes::from_static(b"Method Not Allowed"),
                });
            }
            if let Some(key_auth) = acme_mgr.resolve_http01_challenge(&norm_path) {
                return DispatchResponse::Buffered(HttpResponsePayload {
                    status: StatusCode::OK,
                    headers: vec![(
                        "Content-Type".to_string(),
                        "text/plain; charset=utf-8".to_string(),
                    )],
                    body: Bytes::from(key_auth),
                });
            }
            let acme_root = if vhost.acme_webroot.as_os_str().is_empty() {
                &cfg.acme_webroot
            } else {
                &vhost.acme_webroot
            };
            return DispatchResponse::Buffered(
                serve_static_acme_challenge(acme_root, &norm_path).await,
            );
        }

        // 3b. P1-6: Chuyển hướng HTTP -> HTTPS (tôn trọng X-Forwarded-Proto từ trusted_proxies & không phản chiếu Host cho vhost `_`)
        if !is_request_https(req, cfg) {
            let redirect_code = if let Some(code) = vhost.redirect_status_code {
                Some(code)
            } else if vhost.ssl_enabled && vhost.redirect_https {
                Some(301)
            } else {
                None
            };
            if let Some(code) = redirect_code {
                let matched_explicit_host = if vhost.server_name != "_"
                    && vhost.server_name.eq_ignore_ascii_case(host_no_port)
                {
                    Some(host_no_port)
                } else if vhost
                    .aliases
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(host_no_port))
                {
                    Some(host_no_port)
                } else if vhost.server_name != "_" {
                    Some(vhost.server_name.as_str())
                } else {
                    None
                };

                if let Some(host_target) = matched_explicit_host {
                    let status =
                        StatusCode::from_u16(code).unwrap_or(StatusCode::MOVED_PERMANENTLY);
                    let mut target_uri = norm_path.clone();
                    if !req.query.is_empty() {
                        target_uri.push('?');
                        target_uri.push_str(&req.query);
                    }
                    let location = sanitize_header_value(&format!(
                        "https://{host_target}{target_uri}"
                    ));
                    return DispatchResponse::Buffered(HttpResponsePayload {
                        status,
                        headers: vec![("Location".to_string(), location)],
                        body: Bytes::new(),
                    });
                }
            }
        }

        // 3c. P1-9: Định tuyến proxy khớp prefix dài nhất + ranh giới path
        if let Some(route) = select_longest_proxy_route(&vhost.routes, &norm_path) {
            match route.target_upstream {
                Some(ref upstream_key) if !upstream_key.trim().is_empty() => {
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
                    return maybe_compress_dispatch_response(req, cfg, resp).await;
                }
                _ => {
                    warn!(
                        server = %vhost.server_name,
                        prefix = %route.path_prefix,
                        "Proxy route thiếu target_upstream hợp lệ"
                    );
                    stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                    return DispatchResponse::Buffered(bad_gateway_response());
                }
            }
        }

        // 3d. Phục vụ tệp tĩnh / SPA / PHP-FPM FastCGI dưới root_dir của VirtualHost (async tokio::fs)
        if let Some(ref root_dir) = vhost.root_dir {
            if tokio::fs::metadata(root_dir)
                .await
                .map(|m| m.is_dir())
                .unwrap_or(false)
            {
                let resp = serve_vhost_site_root(
                    root_dir,
                    vhost.php_fpm_socket.as_deref(),
                    &vhost.index_files,
                    vhost.spa_fallback,
                    vhost.enable_etag,
                    vhost.cache_control.as_deref(),
                    &norm_path,
                    req,
                    cfg,
                    stats,
                )
                .await;
                return maybe_compress_dispatch_response(req, cfg, resp).await;
            }
        }
    }

    // 4. Phục vụ ACME HTTP-01 Challenge toàn cục
    if !req.is_tls && norm_path.starts_with(&cfg.acme_challenge_prefix) {
        if let Some(key_auth) = acme_mgr.resolve_http01_challenge(&norm_path) {
            return DispatchResponse::Buffered(HttpResponsePayload {
                status: StatusCode::OK,
                headers: vec![(
                    "Content-Type".to_string(),
                    "text/plain; charset=utf-8".to_string(),
                )],
                body: Bytes::from(key_auth),
            });
        }
        return DispatchResponse::Buffered(
            serve_static_acme_challenge(&cfg.acme_webroot, &norm_path).await,
        );
    }

    // 5. P0-1: Tự dò `/www/wwwroot/<domain>` (tắt mặc định via `enable_dynamic_wwwroot_host = false`)
    if cfg.enable_dynamic_wwwroot_host {
        if let Some(safe_host) = validate_dynamic_wwwroot_host(host_no_port) {
            let wwwroot_base = if cfg.panel_admin.wwwroot.trim().is_empty() {
                "/www/wwwroot"
            } else {
                cfg.panel_admin.wwwroot.trim()
            };
            let base_path = Path::new(wwwroot_base);
            let candidate = base_path.join(&safe_host);
            if let (Ok(canon_base), Ok(canon_target)) = (
                tokio::fs::canonicalize(base_path).await,
                tokio::fs::canonicalize(&candidate).await,
            ) {
                if canon_target != canon_base
                    && canon_target.parent() == Some(canon_base.as_path())
                    && tokio::fs::metadata(&canon_target)
                        .await
                        .map(|m| m.is_dir())
                        .unwrap_or(false)
                {
                    let default_indices = vec!["index.php".to_string(), "index.html".to_string()];
                    let resp = serve_vhost_site_root(
                        &canon_target,
                        None,
                        &default_indices,
                        false,
                        true,
                        None,
                        &norm_path,
                        req,
                        cfg,
                        stats,
                    )
                    .await;
                    return maybe_compress_dispatch_response(req, cfg, resp).await;
                }
            }
        }
    }

    // 6. P1-7: Fallback JSON an toàn dùng serde_json::json! (không giả mạo io_uring)
    let payload = serde_json::json!({
        "server": "FerrousX",
        "host": host_no_port,
        "path": norm_path,
        "epoch": cfg.version_epoch
    })
    .to_string();

    DispatchResponse::Buffered(HttpResponsePayload {
        status: StatusCode::OK,
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body: Bytes::from(payload),
    })
}

/// Phục vụ tệp xác thực Let's Encrypt ACME HTTP-01 từ `/www/acme/.well-known/acme-challenge/<token>`
async fn serve_static_acme_challenge(acme_webroot: &Path, norm_path: &str) -> HttpResponsePayload {
    let Some(resolved) = safe_resolve_under_root_async(acme_webroot, norm_path).await else {
        return HttpResponsePayload {
            status: StatusCode::FORBIDDEN,
            headers: vec![(
                "Content-Type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
            body: Bytes::from_static(b"Forbidden"),
        };
    };

    let is_file = tokio::fs::metadata(&resolved)
        .await
        .map(|m| m.is_file())
        .unwrap_or(false);
    if !is_file {
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

/// P0-3: Tách đường dẫn script PHP và PATH_INFO (giống nginx `fastcgi_split_path_info ^(.+\.php)(/.*)$`)
fn split_php_script_and_path_info(norm_path: &str) -> Option<(&str, Option<&str>)> {
    let lower = norm_path.to_ascii_lowercase();
    let mut search_from = 0usize;
    while let Some(rel) = lower[search_from..].find(".php") {
        let end = search_from + rel + 4;
        let rest = &norm_path[end..];
        if rest.is_empty() {
            return Some((&norm_path[..end], None));
        }
        if rest.starts_with('/') {
            return Some((&norm_path[..end], Some(rest)));
        }
        search_from = end;
    }
    None
}

/// P0-3: Xây dựng danh sách FastCGI params & HTTP_* headers an toàn (chống Httpoxy, bỏ header chứa `_`, nối trùng Cookie bằng `; `)
fn build_fastcgi_params_for_request(
    req: &IncomingRequest,
    cfg: &ServerConfig,
    script_name: &str,
    path_info: Option<&str>,
    doc_root_str: &str,
    script_filename_str: &str,
) -> Vec<(String, String)> {
    let client_ip = resolve_real_client_ip(req, cfg);
    let is_https = is_request_https(req, cfg);
    let host_name = strip_port(&req.host).to_string();

    let mut params = CgiEnvironment::build_standard_params(
        &req.method,
        script_name,
        &req.query,
        doc_root_str,
        script_filename_str,
        &host_name,
        &client_ip,
        is_https,
    );

    if let Some(entry) = params.iter_mut().find(|(k, _)| *k == "REQUEST_URI") {
        entry.1 = req.raw_target.clone();
    }
    if let Some(entry) = params.iter_mut().find(|(k, _)| *k == "CONTENT_LENGTH") {
        entry.1 = req.body.len().to_string();
    }

    let mut owned_pairs: Vec<(String, String)> = params
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

    if let Some(pi) = path_info {
        owned_pairs.push(("PATH_INFO".to_string(), pi.to_string()));
        let translated = format!("{}{}", doc_root_str.trim_end_matches('/'), pi);
        owned_pairs.push(("PATH_TRANSLATED".to_string(), translated));
    }

    let mut header_index: HashMap<String, usize> = HashMap::new();
    let mut extra_headers: Vec<(String, String)> = Vec::new();

    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("content-type") {
            if let Some(entry) = owned_pairs.iter_mut().find(|(pk, _)| pk == "CONTENT_TYPE") {
                entry.1 = v.clone();
            }
            continue;
        }
        if k.eq_ignore_ascii_case("content-length") {
            continue;
        }
        // P0-3: Chặn Httpoxy (HTTP_PROXY) và loại bỏ mọi header chứa '_' để tránh xung đột tên CGI
        if k.eq_ignore_ascii_case("proxy") || k.contains('_') {
            continue;
        }

        let cgi_key = format!("HTTP_{}", k.to_ascii_uppercase().replace('-', "_"));
        let sep = if k.eq_ignore_ascii_case("cookie") {
            "; "
        } else {
            ", "
        };

        if let Some(&idx) = header_index.get(&cgi_key) {
            if !extra_headers[idx].1.is_empty() && !v.is_empty() {
                extra_headers[idx].1.push_str(sep);
            }
            extra_headers[idx].1.push_str(v);
        } else {
            header_index.insert(cgi_key.clone(), extra_headers.len());
            extra_headers.push((cgi_key, v.clone()));
        }
    }

    owned_pairs.extend(extra_headers);
    owned_pairs
}

/// Phục vụ website Vhost (tệp tĩnh streaming + Range/ETag/Last-Modified, thư mục 301, SPA fallback, hoặc PHP-FPM FastCGI)
#[allow(clippy::too_many_arguments)]
async fn serve_vhost_site_root(
    site_root: &Path,
    preferred_php_sock: Option<&str>,
    index_files: &[String],
    spa_fallback: bool,
    enable_etag: bool,
    cache_control: Option<&str>,
    norm_path: &str,
    req: &IncomingRequest,
    cfg: &ServerConfig,
    stats: &EngineRuntimeStats,
) -> DispatchResponse {
    // 0. P1-2: Chặn truy cập trực tiếp tệp nhạy cảm (mọi segment bắt đầu bằng `.` trừ `/.well-known/`, cùng danh sách tệp nhạy cảm)
    if is_sensitive_path(norm_path) {
        return DispatchResponse::Buffered(HttpResponsePayload {
            status: StatusCode::FORBIDDEN,
            headers: vec![(
                "Content-Type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
            body: Bytes::from_static(b"403 Forbidden"),
        });
    }

    // 1. Bảo vệ Path Traversal hoàn toàn bất đồng bộ bằng `tokio::fs`
    let Some(resolved) = safe_resolve_under_root_async(site_root, norm_path).await else {
        return DispatchResponse::Buffered(HttpResponsePayload {
            status: StatusCode::FORBIDDEN,
            headers: vec![(
                "Content-Type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
            body: Bytes::from_static(b"403 Forbidden"),
        });
    };

    let resolved_meta = tokio::fs::metadata(&resolved).await.ok();
    let is_resolved_file = resolved_meta.as_ref().map(|m| m.is_file()).unwrap_or(false);
    let is_resolved_dir = resolved_meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);

    // P1-4: Nếu là thư mục mà URI không có `/` cuối -> trả 301 Moved Permanently kèm dấu `/`
    if is_resolved_dir && !norm_path.ends_with('/') {
        let mut loc = format!("{norm_path}/");
        if !req.query.is_empty() {
            loc.push('?');
            loc.push_str(&req.query);
        }
        return DispatchResponse::Buffered(HttpResponsePayload {
            status: StatusCode::MOVED_PERMANENTLY,
            headers: vec![("Location".to_string(), sanitize_header_value(&loc))],
            body: Bytes::new(),
        });
    }

    let primary_index = index_files
        .first()
        .map(String::as_str)
        .unwrap_or("index.php");

    let mut resolved_path_info: Option<String> = None;
    let mut resolved_script_name: Option<String> = None;

    // 2. Xác định tệp thực thi: tệp tĩnh, tệp .php (kể cả PATH_INFO), thư mục index, SPA fallback, hoặc /index.php
    let target_file = if is_resolved_file {
        resolved
    } else if is_resolved_dir || norm_path.ends_with('/') {
        let mut found = None;
        for idx in index_files {
            let candidate = resolved.join(idx);
            if tokio::fs::metadata(&candidate)
                .await
                .map(|m| m.is_file())
                .unwrap_or(false)
            {
                found = Some(candidate);
                break;
            }
        }
        if let Some(f) = found {
            f
        } else if tokio::fs::metadata(resolved.join("index.php"))
            .await
            .map(|m| m.is_file())
            .unwrap_or(false)
        {
            resolved.join("index.php")
        } else if tokio::fs::metadata(resolved.join("index.html"))
            .await
            .map(|m| m.is_file())
            .unwrap_or(false)
        {
            resolved.join("index.html")
        } else {
            site_root.join(primary_index)
        }
    } else if let Some((script_part, Some(pi))) = split_php_script_and_path_info(norm_path) {
        if let Some(script_resolved) = safe_resolve_under_root_async(site_root, script_part).await {
            if tokio::fs::metadata(&script_resolved)
                .await
                .map(|m| m.is_file())
                .unwrap_or(false)
            {
                resolved_script_name = Some(script_part.to_string());
                resolved_path_info = Some(pi.to_string());
                script_resolved
            } else {
                site_root.join(primary_index)
            }
        } else {
            return DispatchResponse::Buffered(HttpResponsePayload {
                status: StatusCode::FORBIDDEN,
                headers: vec![(
                    "Content-Type".to_string(),
                    "text/plain; charset=utf-8".to_string(),
                )],
                body: Bytes::from_static(b"403 Forbidden"),
            });
        }
    } else if spa_fallback {
        let has_extension = Path::new(norm_path).extension().is_some();
        if !has_extension {
            site_root.join(primary_index)
        } else {
            return DispatchResponse::Buffered(HttpResponsePayload {
                status: StatusCode::NOT_FOUND,
                headers: vec![(
                    "Content-Type".to_string(),
                    "text/plain; charset=utf-8".to_string(),
                )],
                body: Bytes::from_static(b"404 Not Found"),
            });
        }
    } else {
        let fallback_php = site_root.join("index.php");
        if tokio::fs::metadata(&fallback_php)
            .await
            .map(|m| m.is_file())
            .unwrap_or(false)
        {
            fallback_php
        } else {
            let fallback_html = site_root.join(primary_index);
            if tokio::fs::metadata(&fallback_html)
                .await
                .map(|m| m.is_file())
                .unwrap_or(false)
            {
                fallback_html
            } else {
                return DispatchResponse::Buffered(HttpResponsePayload {
                    status: StatusCode::NOT_FOUND,
                    headers: vec![(
                        "Content-Type".to_string(),
                        "text/plain; charset=utf-8".to_string(),
                    )],
                    body: Bytes::from_static(b"404 Not Found"),
                });
            }
        }
    };

    let Ok(target_meta) = tokio::fs::metadata(&target_file).await else {
        return DispatchResponse::Buffered(HttpResponsePayload {
            status: StatusCode::NOT_FOUND,
            headers: vec![(
                "Content-Type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
            body: Bytes::from_static(b"404 Not Found"),
        });
    };
    if !target_meta.is_file() {
        return DispatchResponse::Buffered(HttpResponsePayload {
            status: StatusCode::NOT_FOUND,
            headers: vec![(
                "Content-Type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
            body: Bytes::from_static(b"404 Not Found"),
        });
    }

    let is_php = target_file
        .extension()
        .and_then(|e| e.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("php"))
        .unwrap_or(false);

    if is_php {
        stats.php_fpm_requests.fetch_add(1, Ordering::Relaxed);
        let fpm_target = detect_php_fpm_socket(preferred_php_sock);

        let canon_root = tokio::fs::canonicalize(site_root)
            .await
            .unwrap_or_else(|_| site_root.to_path_buf());
        let doc_root_str = canon_root.to_string_lossy().to_string();
        let script_filename_str = target_file.to_string_lossy().to_string();
        let script_name = resolved_script_name.unwrap_or_else(|| {
            target_file
                .strip_prefix(&canon_root)
                .or_else(|_| target_file.strip_prefix(site_root))
                .map(|p| format!("/{}", p.to_string_lossy().trim_start_matches('/')))
                .unwrap_or_else(|_| "/index.php".to_string())
        });

        let owned_pairs = build_fastcgi_params_for_request(
            req,
            cfg,
            &script_name,
            resolved_path_info.as_deref(),
            &doc_root_str,
            &script_filename_str,
        );
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
            Ok(Ok(fcgi_resp)) => DispatchResponse::Buffered(HttpResponsePayload {
                status: fcgi_resp.status,
                headers: fcgi_resp.headers,
                body: fcgi_resp.body,
            }),
            Ok(Err(err)) => {
                stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                warn!(socket = %fpm_target, error = %err, "Lỗi thực thi PHP-FPM FastCGI");
                DispatchResponse::Buffered(bad_gateway_response())
            }
            Err(_) => {
                stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                warn!(socket = %fpm_target, "Hết thời gian chờ PHP-FPM FastCGI");
                DispatchResponse::Buffered(gateway_timeout_response())
            }
        };
    }

    // P1-4: Phục vụ tệp tĩnh streaming 64 KiB + ETag + Last-Modified + 304 + Cache-Control + Range/206
    let file_len = target_meta.len();
    let mtime_secs = target_meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mtime_nanos = target_meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let etag = if enable_etag {
        Some(format!("\"{:x}-{:x}\"", file_len, mtime_nanos))
    } else {
        None
    };
    let last_modified = format_http_date(mtime_secs);
    let cache_ctrl = cache_control.unwrap_or("public, max-age=3600").to_string();

    // Kiểm tra If-None-Match trước, sau đó kiểm tra If-Modified-Since
    let mut cond_not_modified = false;
    if let Some(ref tag) = etag {
        if let Some((_, inm)) = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("if-none-match"))
        {
            if inm
                .split(',')
                .map(|p| p.trim().trim_start_matches("W/"))
                .any(|cand| cand == tag || cand == "*")
            {
                cond_not_modified = true;
            }
        } else if let Some((_, ims)) = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("if-modified-since"))
        {
            if let Some(ims_secs) = parse_http_date(ims) {
                if mtime_secs <= ims_secs {
                    cond_not_modified = true;
                }
            }
        }
    } else if let Some((_, ims)) = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("if-modified-since"))
    {
        if let Some(ims_secs) = parse_http_date(ims) {
            if mtime_secs <= ims_secs {
                cond_not_modified = true;
            }
        }
    }

    if cond_not_modified {
        stats.static_requests.fetch_add(1, Ordering::Relaxed);
        let mut headers = vec![
            ("Last-Modified".to_string(), last_modified),
            ("Cache-Control".to_string(), cache_ctrl),
        ];
        if let Some(tag) = etag {
            headers.push(("ETag".to_string(), tag));
        }
        return DispatchResponse::Buffered(HttpResponsePayload {
            status: StatusCode::NOT_MODIFIED,
            headers,
            body: Bytes::new(),
        });
    }

    let ext = target_file
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mime = MimeDetector::get_mime_type(&ext);

    let mut base_headers = vec![
        ("Content-Type".to_string(), mime.to_string()),
        ("Last-Modified".to_string(), last_modified),
        ("Accept-Ranges".to_string(), "bytes".to_string()),
        ("Cache-Control".to_string(), cache_ctrl),
    ];
    if let Some(tag) = etag {
        base_headers.push(("ETag".to_string(), tag));
    }

    // Kiểm tra Range header (bytes=...)
    if let Some((_, range_val)) = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("range"))
    {
        match parse_single_byte_range(range_val, file_len) {
            RangeParseResult::Satisfiable { start, end } => {
                stats.static_requests.fetch_add(1, Ordering::Relaxed);
                let slice_len = end - start + 1;
                base_headers.push((
                    "Content-Range".to_string(),
                    format!("bytes {start}-{end}/{file_len}"),
                ));
                return DispatchResponse::StaticFile {
                    status: StatusCode::PARTIAL_CONTENT,
                    headers: base_headers,
                    path: target_file,
                    offset: start,
                    len: slice_len,
                };
            }
            RangeParseResult::Unsatisfiable => {
                stats.static_requests.fetch_add(1, Ordering::Relaxed);
                return DispatchResponse::Buffered(HttpResponsePayload {
                    status: StatusCode::RANGE_NOT_SATISFIABLE,
                    headers: vec![
                        ("Content-Range".to_string(), format!("bytes */{file_len}")),
                        (
                            "Content-Type".to_string(),
                            "text/plain; charset=utf-8".to_string(),
                        ),
                    ],
                    body: Bytes::from_static(b"416 Range Not Satisfiable"),
                });
            }
            RangeParseResult::None => {}
        }
    }

    stats.static_requests.fetch_add(1, Ordering::Relaxed);
    DispatchResponse::StaticFile {
        status: StatusCode::OK,
        headers: base_headers,
        path: target_file,
        offset: 0,
        len: file_len,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RangeParseResult {
    None,
    Satisfiable { start: u64, end: u64 },
    Unsatisfiable,
}

fn parse_single_byte_range(header_val: &str, total_len: u64) -> RangeParseResult {
    let trimmed = header_val.trim();
    let Some(spec) = trimmed
        .strip_prefix("bytes=")
        .or_else(|| trimmed.strip_prefix("BYTES="))
    else {
        return RangeParseResult::None;
    };
    let spec = spec.trim();
    // Không hỗ trợ multi-range (trả về None để phục vụ full 200 OK chuẩn mực)
    if spec.contains(',') {
        return RangeParseResult::None;
    }
    if total_len == 0 {
        return RangeParseResult::Unsatisfiable;
    }
    let Some((start_s, end_s)) = spec.split_once('-') else {
        return RangeParseResult::None;
    };
    let start_s = start_s.trim();
    let end_s = end_s.trim();

    if start_s.is_empty() {
        let Ok(suffix) = end_s.parse::<u64>() else {
            return RangeParseResult::None;
        };
        if suffix == 0 {
            return RangeParseResult::Unsatisfiable;
        }
        let start = total_len.saturating_sub(suffix);
        return RangeParseResult::Satisfiable {
            start,
            end: total_len - 1,
        };
    }

    let Ok(start) = start_s.parse::<u64>() else {
        return RangeParseResult::None;
    };
    if start >= total_len {
        return RangeParseResult::Unsatisfiable;
    }

    if end_s.is_empty() {
        return RangeParseResult::Satisfiable {
            start,
            end: total_len - 1,
        };
    }

    let Ok(raw_end) = end_s.parse::<u64>() else {
        return RangeParseResult::None;
    };
    if raw_end < start {
        return RangeParseResult::Unsatisfiable;
    }
    let end = raw_end.min(total_len - 1);
    RangeParseResult::Satisfiable { start, end }
}

// ============================================================================
// ĐỊNH DẠNG & PHÂN TÍCH NGÀY CHUẨN HTTP (IMF-FIXDATE UTC — PURE RUST)
// ============================================================================

fn format_http_date(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let rem = unix_secs.rem_euclid(86_400);
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;

    let dow = (days + 4).rem_euclid(7) as usize;
    let wday = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][dow];

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };

    let mon = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][(m - 1) as usize];

    format!("{wday}, {d:02} {mon} {year:04} {hour:02}:{min:02}:{sec:02} GMT")
}

fn parse_http_date(raw: &str) -> Option<i64> {
    let tokens: Vec<&str> = raw.trim().split_whitespace().collect();
    // IMF-fixdate: "Sun, 06 Nov 1994 08:49:37 GMT"
    if tokens.len() == 6 && tokens[5].eq_ignore_ascii_case("GMT") {
        let day: i64 = tokens[1].parse().ok()?;
        let month = parse_month_abbrev(tokens[2])?;
        let year: i64 = tokens[3].parse().ok()?;
        let mut hms = tokens[4].split(':');
        let hour: i64 = hms.next()?.parse().ok()?;
        let min: i64 = hms.next()?.parse().ok()?;
        let sec: i64 = hms.next()?.parse().ok()?;
        if !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
            return None;
        }
        return Some(unix_from_civil(year, month, day, hour, min, sec));
    }
    None
}

fn parse_month_abbrev(s: &str) -> Option<i64> {
    match s.to_ascii_lowercase().as_str() {
        "jan" => Some(1),
        "feb" => Some(2),
        "mar" => Some(3),
        "apr" => Some(4),
        "may" => Some(5),
        "jun" => Some(6),
        "jul" => Some(7),
        "aug" => Some(8),
        "sep" => Some(9),
        "oct" => Some(10),
        "nov" => Some(11),
        "dec" => Some(12),
        _ => None,
    }
}

fn unix_from_civil(year: i64, month: i64, day: i64, hour: i64, min: i64, sec: i64) -> i64 {
    let y = year - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + hour * 3600 + min * 60 + sec
}

// ============================================================================
// REVERSE PROXY (TRUSTED PROXY CIDR + SSRF SHIELD + STREAMING + WEBSOCKET)
// ============================================================================

/// P0-2: Xác định IP thực của Client:
/// CHỈ tin cậy `CF-Connecting-IP` / `X-Forwarded-For` / `X-Real-IP` khi `req.peer_ip` thuộc `trusted_proxies`.
/// Khi đọc `X-Forwarded-For`, duyệt từ PHẢI SANG TRÁI để tìm IP đầu tiên KHÔNG thuộc `trusted_proxies`.
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
                let mut leftmost_valid: Option<String> = None;
                for part in v.rsplit(',') {
                    let candidate = part.trim();
                    if let Ok(ip) = candidate.parse::<IpAddr>() {
                        leftmost_valid = Some(candidate.to_string());
                        if !cfg.is_trusted_proxy(ip) {
                            return candidate.to_string();
                        }
                    }
                }
                if let Some(ip_str) = leftmost_valid {
                    return ip_str;
                }
            }
        }
        for (k, v) in &req.headers {
            if k.eq_ignore_ascii_case("x-real-ip") {
                let candidate = v.trim();
                if candidate.parse::<IpAddr>().is_ok() {
                    return candidate.to_string();
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
    let trimmed = target_addr.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return false;
    }
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };
    if validate_upstream_origin(&with_scheme).is_err() {
        return false;
    }
    if let Ok(sock_addr) = trimmed.parse::<SocketAddr>() {
        if is_forbidden_ssrf_ip(sock_addr.ip()) || sock_addr.port() == 0 {
            return false;
        }
    }
    true
}

/// Reverse Proxy có P2C/Round-Robin/Maglev Load Balancing + CircuitBreaker
async fn proxy_with_balancer_and_circuit(
    upstream_key: &str,
    req: &IncomingRequest,
    cfg: &ServerConfig,
    pass_host_header: bool,
    forwarded_headers: bool,
    stats: &EngineRuntimeStats,
    upstream_reg: &UpstreamBalancerRegistry,
) -> DispatchResponse {
    let seed = compute_request_seed(req);
    match upstream_reg.resolve_target(upstream_key, seed, cfg) {
        UpstreamPickResult::PoolNode(node) => {
            node.active_requests.fetch_add(1, Ordering::Relaxed);
            let resp = proxy_http1_upstream_dispatch(
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
                resp.status(),
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
            DispatchResponse::Buffered(HttpResponsePayload {
                status: StatusCode::SERVICE_UNAVAILABLE,
                headers: vec![
                    (
                        "Content-Type".to_string(),
                        "text/plain; charset=utf-8".to_string(),
                    ),
                    ("Retry-After".to_string(), "5".to_string()),
                ],
                body: Bytes::from_static(b"503 Service Unavailable"),
            })
        }
        UpstreamPickResult::LiteralAddr(target_addr) => {
            proxy_http1_upstream_dispatch(
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

/// P0-9: Chọn bộ nén tối ưu từ header `Accept-Encoding` có xử lý q-value (`zstd;q=0` => tắt)
fn select_best_compression_encoding(
    accept_enc: &str,
    comp_cfg: &CompressionConfig,
) -> Option<(ContentEncoding, &'static str)> {
    let mut zstd_q: Option<f32> = None;
    let mut br_q: Option<f32> = None;
    let mut star_q: Option<f32> = None;

    for part in accept_enc.split(',') {
        let mut items = part.split(';');
        let name = items.next().unwrap_or("").trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        let mut q = 1.0_f32;
        for param in items {
            let p = param.trim();
            if let Some(val_str) = p.strip_prefix("q=").or_else(|| p.strip_prefix("Q=")) {
                if let Ok(parsed) = val_str.trim().parse::<f32>() {
                    if parsed.is_finite() && (0.0..=1.0).contains(&parsed) {
                        q = parsed;
                    }
                }
            }
        }
        match name.as_str() {
            "zstd" => zstd_q = Some(zstd_q.map_or(q, |prev| prev.max(q))),
            "br" => br_q = Some(br_q.map_or(q, |prev| prev.max(q))),
            "*" => star_q = Some(q),
            _ => {}
        }
    }

    let eff_zstd = if comp_cfg.enable_zstd {
        match zstd_q {
            Some(q) => q,
            None => star_q.unwrap_or(0.0),
        }
    } else {
        0.0
    };
    let eff_br = if comp_cfg.enable_brotli {
        match br_q {
            Some(q) => q,
            None => star_q.unwrap_or(0.0),
        }
    } else {
        0.0
    };

    if eff_zstd <= 0.0 && eff_br <= 0.0 {
        return None;
    }
    if eff_zstd >= eff_br {
        Some((ContentEncoding::Zstd, "zstd"))
    } else {
        Some((ContentEncoding::Brotli, "br"))
    }
}

fn ensure_vary_accept_encoding(headers: &mut Vec<(String, String)>) {
    if let Some((_, val)) = headers
        .iter_mut()
        .find(|(k, _)| k.eq_ignore_ascii_case("vary"))
    {
        if !val
            .split(',')
            .any(|v| v.trim().eq_ignore_ascii_case("accept-encoding"))
        {
            if !val.trim().is_empty() {
                val.push_str(", ");
            }
            val.push_str("Accept-Encoding");
        }
    } else {
        headers.push(("Vary".to_string(), "Accept-Encoding".to_string()));
    }
}

fn is_compressible_content_type(ct: &str) -> bool {
    let ct_low = ct.to_ascii_lowercase();
    ct_low.starts_with("text/")
        || ct_low.contains("application/json")
        || ct_low.contains("application/javascript")
        || ct_low.contains("application/xml")
        || ct_low.contains("image/svg+xml")
        || ct_low.contains("application/wasm")
}

async fn maybe_compress_dispatch_response(
    req: &IncomingRequest,
    cfg: &ServerConfig,
    resp: DispatchResponse,
) -> DispatchResponse {
    if req.method.eq_ignore_ascii_case("HEAD") {
        return resp;
    }

    let comp_cfg = match_virtual_host(strip_port(&req.host), cfg)
        .map(|v| v.compression.clone())
        .unwrap_or_else(CompressionConfig::default);

    let accept_enc = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("accept-encoding"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let Some((encoding, enc_label)) = select_best_compression_encoding(accept_enc, &comp_cfg)
    else {
        return resp;
    };

    match resp {
        DispatchResponse::Buffered(mut p) => {
            p = maybe_compress_buffered_payload(p, &comp_cfg, encoding, enc_label).await;
            DispatchResponse::Buffered(p)
        }
        DispatchResponse::StaticFile {
            status,
            mut headers,
            path,
            offset,
            len,
        } => {
            if status != StatusCode::OK
                || len < comp_cfg.min_length_bytes as u64
                || len > 4 * 1024 * 1024
                || headers
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
            {
                return DispatchResponse::StaticFile {
                    status,
                    headers,
                    path,
                    offset,
                    len,
                };
            }
            let ct = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.as_str())
                .unwrap_or("");
            if !is_compressible_content_type(ct) {
                return DispatchResponse::StaticFile {
                    status,
                    headers,
                    path,
                    offset,
                    len,
                };
            }
            if let Ok(mut f) = tokio::fs::File::open(&path).await {
                if f.seek(SeekFrom::Start(offset)).await.is_ok() {
                    let mut raw = Vec::with_capacity(len as usize);
                    if f.take(len).read_to_end(&mut raw).await.is_ok() {
                        if let Some(compressed) = compress_response_body(&raw, encoding).await {
                            headers.push(("Content-Encoding".to_string(), enc_label.to_string()));
                            ensure_vary_accept_encoding(&mut headers);
                            return DispatchResponse::Buffered(HttpResponsePayload {
                                status,
                                headers,
                                body: compressed,
                            });
                        }
                        return DispatchResponse::Buffered(HttpResponsePayload {
                            status,
                            headers,
                            body: Bytes::from(raw),
                        });
                    }
                }
            }
            DispatchResponse::StaticFile {
                status,
                headers,
                path,
                offset,
                len,
            }
        }
        other => other,
    }
}

async fn maybe_compress_buffered_payload(
    mut resp: HttpResponsePayload,
    comp_cfg: &CompressionConfig,
    encoding: ContentEncoding,
    enc_label: &'static str,
) -> HttpResponsePayload {
    if resp.status != StatusCode::OK || resp.body.len() < comp_cfg.min_length_bytes {
        return resp;
    }
    if resp
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
    {
        return resp;
    }
    let content_type = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    if !is_compressible_content_type(content_type) {
        return resp;
    }

    if let Some(compressed) = compress_response_body(&resp.body, encoding).await {
        resp.body = compressed;
        resp.headers
            .push(("Content-Encoding".to_string(), enc_label.to_string()));
        ensure_vary_accept_encoding(&mut resp.headers);
    }
    resp
}

#[allow(dead_code)]
async fn maybe_compress_response(
    req: &IncomingRequest,
    cfg: &ServerConfig,
    resp: HttpResponsePayload,
) -> HttpResponsePayload {
    if req.method.eq_ignore_ascii_case("HEAD") {
        return resp;
    }
    let comp_cfg = match_virtual_host(strip_port(&req.host), cfg)
        .map(|v| v.compression.clone())
        .unwrap_or_else(CompressionConfig::default);
    let accept_enc = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("accept-encoding"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let Some((encoding, enc_label)) = select_best_compression_encoding(accept_enc, &comp_cfg)
    else {
        return resp;
    };
    maybe_compress_buffered_payload(resp, &comp_cfg, encoding, enc_label).await
}

/// P1-5: Reverse Proxy HTTP/1.1 hỗ trợ streaming, idle timeout theo từng lần đọc, bỏ qua `100 Continue`, không hạ cấp `https://`
async fn proxy_http1_upstream_dispatch(
    target_addr: &str,
    req: &IncomingRequest,
    cfg: &ServerConfig,
    pass_host_header: bool,
    forwarded_headers: bool,
    stats: &EngineRuntimeStats,
) -> DispatchResponse {
    // P1-5: Không âm thầm hạ `https://` hoặc `wss://` xuống TCP thường!
    let lower_target = target_addr.trim().to_ascii_lowercase();
    if lower_target.starts_with("https://") || lower_target.starts_with("wss://") {
        warn!(target = %target_addr, "Upstream TLS (https:// / wss://) chưa hỗ trợ client TLS; từ chối hạ cấp plaintext");
        stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
        return DispatchResponse::Buffered(bad_gateway_response());
    }

    let connect_timeout = Duration::from_millis(cfg.proxy_connect_timeout_ms.max(1000));
    let write_timeout = Duration::from_millis(cfg.proxy_write_timeout_ms.max(1000));
    let read_timeout = Duration::from_millis(cfg.proxy_read_timeout_ms.max(5000));
    let max_resp_bytes = cfg.max_upstream_response_bytes.max(1024 * 1024);

    if let Some(sock_path) = target_addr.strip_prefix("unix:") {
        let Ok(Ok(mut stream)) =
            tokio::time::timeout(connect_timeout, UnixStream::connect(sock_path)).await
        else {
            stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
            return DispatchResponse::Buffered(bad_gateway_response());
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
            return DispatchResponse::Buffered(bad_gateway_response());
        }
        return read_upstream_http1_dispatch(
            UpstreamIo::Unix(stream),
            read_timeout,
            max_resp_bytes,
            stats,
        )
        .await;
    }

    let clean_tcp = target_addr
        .strip_prefix("http://")
        .or_else(|| target_addr.strip_prefix("ws://"))
        .unwrap_or(target_addr)
        .trim_end_matches('/');

    if !is_safe_tcp_upstream(clean_tcp) {
        stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
        warn!(target = %clean_tcp, "Chặn kết nối Upstream không an toàn (SSRF Protection)");
        return DispatchResponse::Buffered(bad_gateway_response());
    }

    let Ok(Ok(mut stream)) =
        tokio::time::timeout(connect_timeout, TcpStream::connect(clean_tcp)).await
    else {
        stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
        return DispatchResponse::Buffered(bad_gateway_response());
    };
    if let Ok(peer_sock) = stream.peer_addr() {
        if is_forbidden_ssrf_ip(peer_sock.ip()) {
            stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
            warn!(
                target = %clean_tcp,
                resolved_ip = %peer_sock.ip(),
                "Chặn DNS Rebinding SSRF vào địa chỉ IP bị cấm"
            );
            return DispatchResponse::Buffered(bad_gateway_response());
        }
    }

    let _ = stream.set_nodelay(true);
    let wire_req = build_upstream_http1_request(
        req,
        cfg,
        clean_tcp,
        pass_host_header,
        forwarded_headers,
        false,
    );
    if tokio::time::timeout(write_timeout, stream.write_all(&wire_req))
        .await
        .map_or(true, |r| r.is_err())
    {
        stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
        return DispatchResponse::Buffered(bad_gateway_response());
    }

    read_upstream_http1_dispatch(
        UpstreamIo::Tcp(stream),
        read_timeout,
        max_resp_bytes,
        stats,
    )
    .await
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

fn gateway_timeout_response() -> HttpResponsePayload {
    HttpResponsePayload {
        status: StatusCode::GATEWAY_TIMEOUT,
        headers: vec![(
            "Content-Type".to_string(),
            "text/plain; charset=utf-8".to_string(),
        )],
        body: Bytes::from_static(b"504 Gateway Timeout"),
    }
}

/// Đọc phản hồi HTTP/1.1 từ Upstream với per-read idle timeout, bỏ qua `100 Continue` (1xx), và stream SSE/payload lớn
async fn read_upstream_http1_dispatch(
    mut stream: UpstreamIo,
    read_timeout: Duration,
    max_response_bytes: usize,
    stats: &EngineRuntimeStats,
) -> DispatchResponse {
    let mut raw = BytesMut::with_capacity(16 * 1024);

    loop {
        while find_double_crlf(&raw).is_none() {
            if raw.len() > 64 * 1024 {
                stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                return DispatchResponse::Buffered(bad_gateway_response());
            }
            match tokio::time::timeout(read_timeout, stream.read_buf(&mut raw)).await {
                Ok(Ok(0)) => {
                    stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                    return DispatchResponse::Buffered(bad_gateway_response());
                }
                Ok(Ok(_)) => {}
                Ok(Err(_)) => {
                    stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                    return DispatchResponse::Buffered(bad_gateway_response());
                }
                Err(_) => {
                    stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                    return DispatchResponse::Buffered(gateway_timeout_response());
                }
            }
        }

        let header_end = find_double_crlf(&raw).unwrap();
        let mut headers_storage = [httparse::EMPTY_HEADER; 96];
        let mut resp = httparse::Response::new(&mut headers_storage);
        let Ok(parsed_status) = resp.parse(&raw[..header_end + 4]) else {
            stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
            return DispatchResponse::Buffered(bad_gateway_response());
        };
        if !parsed_status.is_complete() {
            stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
            return DispatchResponse::Buffered(bad_gateway_response());
        }

        let code = resp.code.unwrap_or(200);
        // P1-5: Bỏ qua phản hồi tạm thời `1xx` (như `100 Continue`, `103 Early Hints`)
        if (100..200).contains(&code) {
            let _ = raw.split_to(header_end + 4);
            continue;
        }

        let status = StatusCode::from_u16(code).unwrap_or(StatusCode::OK);
        let mut is_chunked = false;
        let mut known_content_length: Option<u64> = None;
        let mut is_sse = false;
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
            if name.eq_ignore_ascii_case("content-length") {
                if let Ok(cl) = val.trim().parse::<u64>() {
                    known_content_length = Some(cl);
                }
                continue;
            }
            if name.eq_ignore_ascii_case("content-type")
                && val.to_ascii_lowercase().contains("text/event-stream")
            {
                is_sse = true;
            }
            if is_hop_by_hop_header(&name) {
                continue;
            }
            headers.push((name, val));
        }

        let _ = raw.split_to(header_end + 4);
        let initial_bytes = raw.freeze();

        // Stream trực tiếp nếu là SSE hoặc kích thước lớn (> 256 KiB)
        let should_stream = is_sse
            || known_content_length
                .map(|cl| cl > 256 * 1024)
                .unwrap_or(false);

        if should_stream {
            return DispatchResponse::UpstreamStream {
                status,
                headers,
                stream,
                initial_bytes,
                known_content_length,
                max_bytes: max_response_bytes,
                read_timeout,
                upstream_chunked: is_chunked,
            };
        }

        // Đệm có giới hạn kèm per-read idle timeout cho các phản hồi nhỏ (có hỗ trợ Zstd/Brotli)
        let mut body_acc = BytesMut::from(initial_bytes.as_ref());
        let mut tmp = [0u8; 16 * 1024];

        if let Some(expected_cl) = known_content_length {
            let target_len = expected_cl as usize;
            if target_len > max_response_bytes {
                stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                return DispatchResponse::Buffered(bad_gateway_response());
            }
            while body_acc.len() < target_len {
                match tokio::time::timeout(read_timeout, stream.read(&mut tmp)).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => {
                        match body_acc.len().checked_add(n) {
                            Some(new_len) if new_len <= max_response_bytes => {
                                body_acc.extend_from_slice(&tmp[..n]);
                            }
                            _ => {
                                stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                                return DispatchResponse::Buffered(bad_gateway_response());
                            }
                        }
                    }
                    Ok(Err(_)) => {
                        stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                        return DispatchResponse::Buffered(bad_gateway_response());
                    }
                    Err(_) => {
                        stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                        return DispatchResponse::Buffered(gateway_timeout_response());
                    }
                }
            }
            body_acc.truncate(target_len);
            return DispatchResponse::Buffered(HttpResponsePayload {
                status,
                headers,
                body: body_acc.freeze(),
            });
        }

        // Không có Content-Length (hoặc chunked nhỏ <= ngưỡng): đọc đến EOF/chunk 0 với per-read idle timeout
        if is_chunked {
            match read_chunked_http1_body(&mut stream, &mut body_acc, max_response_bytes, read_timeout)
                .await
            {
                Ok(decoded) => {
                    return DispatchResponse::Buffered(HttpResponsePayload {
                        status,
                        headers,
                        body: decoded,
                    });
                }
                Err(ChunkReadError::Timeout) => {
                    stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                    return DispatchResponse::Buffered(gateway_timeout_response());
                }
                Err(_) => {
                    stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                    return DispatchResponse::Buffered(bad_gateway_response());
                }
            }
        }

        loop {
            match tokio::time::timeout(read_timeout, stream.read(&mut tmp)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => match body_acc.len().checked_add(n) {
                    Some(new_len) if new_len <= max_response_bytes => {
                        body_acc.extend_from_slice(&tmp[..n]);
                    }
                    _ => {
                        stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                        return DispatchResponse::Buffered(bad_gateway_response());
                    }
                },
                Ok(Err(_)) => {
                    stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                    return DispatchResponse::Buffered(bad_gateway_response());
                }
                Err(_) => {
                    stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                    return DispatchResponse::Buffered(gateway_timeout_response());
                }
            }
        }

        return DispatchResponse::Buffered(HttpResponsePayload {
            status,
            headers,
            body: body_acc.freeze(),
        });
    }
}

/// P0-2: Đóng gói Request gửi tới Upstream kèm lọc sạch spoofing headers khi client không phải Trusted Proxy
fn build_upstream_http1_request(
    req: &IncomingRequest,
    cfg: &ServerConfig,
    upstream_authority: &str,
    pass_host_header: bool,
    forwarded_headers: bool,
    keep_upgrade: bool,
) -> Vec<u8> {
    let trusted = cfg.is_trusted_proxy(req.peer_ip);
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

    let new_xff = if trusted {
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
            || lower == "x-forwarded-port"
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
        // P0-2: Xóa hoàn toàn các header giả mạo IP từ client không thuộc trusted_proxies
        if !trusted
            && (lower == "cf-connecting-ip" || lower == "true-client-ip" || lower == "x-client-ip")
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

/// P0-8: Kiểm tra Origin khớp host cho WebSocket tới Panel (chống CSWSH /ws/ssh & /ws/telemetry)
fn verify_panel_websocket_origin(req: &IncomingRequest, cfg: &ServerConfig) -> bool {
    let req_host = strip_port(&req.host);
    let custom_domain = cfg.panel_admin.custom_domain.trim();
    let origin_opt = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("origin"))
        .map(|(_, v)| v.trim());

    let Some(origin) = origin_opt else {
        // Bắt buộc Origin cho Web SSH / Telemetry của trình duyệt
        return !(req.path.starts_with("/ws/ssh") || req.path.starts_with("/ws/telemetry"));
    };

    let origin_authority = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .unwrap_or("")
        .split('/')
        .next()
        .unwrap_or("");
    let origin_host = strip_port(origin_authority);
    if origin_host.is_empty() {
        return false;
    }

    if !custom_domain.is_empty() && origin_host.eq_ignore_ascii_case(custom_domain) {
        return true;
    }
    !req_host.is_empty() && origin_host.eq_ignore_ascii_case(req_host)
}

/// P0-8: Phân giải địa chỉ upstream cho WebSocket (KHÔNG fallback về panel, trả None => 404)
fn resolve_websocket_upstream(
    req: &IncomingRequest,
    norm_path: &str,
    cfg: &ServerConfig,
    upstream_reg: &UpstreamBalancerRegistry,
) -> std::result::Result<Option<String>, StatusCode> {
    let host_no_port = strip_port(&req.host);
    let seed = compute_request_seed(req);

    if is_panel_request(req, norm_path, cfg) {
        if !verify_panel_websocket_origin(req, cfg) {
            return Err(StatusCode::FORBIDDEN);
        }
        return Ok(Some(cfg.panel_admin.panel_upstream_addr()));
    }

    if cfg.enable_phpmyadmin_route
        && is_admin_or_panel_host(host_no_port, cfg)
        && (norm_path.starts_with("/phpadmin/") || norm_path.starts_with("/phpmyadmin/"))
    {
        return Ok(Some(cfg.phpmyadmin_upstream.clone()));
    }

    if let Some(vhost) = match_virtual_host(host_no_port, cfg) {
        if let Some(route) = select_longest_proxy_route(&vhost.routes, norm_path) {
            if !matches!(
                route.backend_protocol,
                BackendProtocol::Http1 | BackendProtocol::WebSocket | BackendProtocol::GrpcH2
            ) {
                return Err(StatusCode::NOT_FOUND);
            }
            let Some(ref upstream_key) = route.target_upstream else {
                return Err(StatusCode::BAD_GATEWAY);
            };
            return match upstream_reg.resolve_target(upstream_key, seed, cfg) {
                UpstreamPickResult::PoolNode(node) => Ok(Some(node.address.clone())),
                UpstreamPickResult::LiteralAddr(addr) => Ok(Some(addr)),
                UpstreamPickResult::CircuitBreakerOpen => Err(StatusCode::SERVICE_UNAVAILABLE),
            };
        }
    }

    Ok(None)
}

/// Đường hầm WebSocket Upgrade Full-Duplex (`Connection: Upgrade`, `Upgrade: websocket`)
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
    let Ok(norm_path) = normalize_and_decode_uri_path(&req.path) else {
        write_simple_http1_error(&mut client_stream, StatusCode::BAD_REQUEST, "400 Bad Request")
            .await?;
        return Ok(());
    };

    let upstream_addr = match resolve_websocket_upstream(&req, &norm_path, cfg, upstream_reg) {
        Ok(Some(addr)) => addr,
        Ok(None) => {
            write_simple_http1_error(&mut client_stream, StatusCode::NOT_FOUND, "404 Not Found")
                .await?;
            return Ok(());
        }
        Err(StatusCode::FORBIDDEN) => {
            write_simple_http1_error(
                &mut client_stream,
                StatusCode::FORBIDDEN,
                "403 Forbidden: Invalid WebSocket Origin",
            )
            .await?;
            return Ok(());
        }
        Err(StatusCode::SERVICE_UNAVAILABLE) => {
            write_simple_http1_error(
                &mut client_stream,
                StatusCode::SERVICE_UNAVAILABLE,
                "503 Service Unavailable",
            )
            .await?;
            return Ok(());
        }
        Err(_) => {
            write_simple_http1_error(&mut client_stream, StatusCode::BAD_GATEWAY, "502 Bad Gateway")
                .await?;
            return Ok(());
        }
    };

    let lower_up = upstream_addr.trim().to_ascii_lowercase();
    if lower_up.starts_with("https://") || lower_up.starts_with("wss://") {
        warn!(upstream = %upstream_addr, "WebSocket TLS upstream chưa hỗ trợ");
        write_simple_http1_error(&mut client_stream, StatusCode::BAD_GATEWAY, "502 Bad Gateway")
            .await?;
        return Ok(());
    }

    let connect_timeout = Duration::from_millis(cfg.proxy_connect_timeout_ms.max(1000));
    let idle_timeout = Duration::from_millis(cfg.proxy_read_timeout_ms.max(60_000));

    if let Some(sock_path) = upstream_addr.strip_prefix("unix:") {
        let mut upstream = match tokio::time::timeout(connect_timeout, UnixStream::connect(sock_path))
            .await
        {
            Ok(Ok(s)) => s,
            _ => {
                warn!(upstream = %sock_path, "WebSocket Unix upstream connect failed");
                write_simple_http1_error(
                    &mut client_stream,
                    StatusCode::BAD_GATEWAY,
                    "502 Bad Gateway",
                )
                .await?;
                return Ok(());
            }
        };
        let handshake_bytes =
            build_upstream_http1_request(&req, cfg, &upstream_addr, true, true, true);
        upstream.write_all(&handshake_bytes).await?;
        if !leftover_buf.is_empty() {
            upstream.write_all(&leftover_buf).await?;
        }
        upstream.flush().await?;
        let _ = tokio::time::timeout(
            idle_timeout,
            tokio::io::copy_bidirectional(&mut client_stream, &mut upstream),
        )
        .await;
        return Ok(());
    }

    let clean_tcp_addr = upstream_addr
        .strip_prefix("http://")
        .or_else(|| upstream_addr.strip_prefix("ws://"))
        .unwrap_or(&upstream_addr)
        .trim_end_matches('/');

    if !is_safe_tcp_upstream(clean_tcp_addr) {
        warn!(upstream = %clean_tcp_addr, "Blocked unsafe WebSocket upstream by SSRF policy");
        write_simple_http1_error(&mut client_stream, StatusCode::BAD_GATEWAY, "502 Bad Gateway")
            .await?;
        return Ok(());
    }

    let mut upstream =
        match tokio::time::timeout(connect_timeout, TcpStream::connect(clean_tcp_addr)).await {
            Ok(Ok(s)) => s,
            _ => {
                warn!(upstream = %clean_tcp_addr, "WebSocket Upstream connect failed");
                write_simple_http1_error(
                    &mut client_stream,
                    StatusCode::BAD_GATEWAY,
                    "502 Bad Gateway",
                )
                .await?;
                return Ok(());
            }
        };
    if let Ok(peer_sock) = upstream.peer_addr() {
        if is_forbidden_ssrf_ip(peer_sock.ip()) {
            warn!(upstream = %clean_tcp_addr, resolved_ip = %peer_sock.ip(), "Blocked WebSocket SSRF DNS rebinding");
            write_simple_http1_error(
                &mut client_stream,
                StatusCode::BAD_GATEWAY,
                "502 Bad Gateway",
            )
            .await?;
            return Ok(());
        }
    }
    let _ = upstream.set_nodelay(true);

    let handshake_bytes =
        build_upstream_http1_request(&req, cfg, clean_tcp_addr, true, true, true);
    upstream.write_all(&handshake_bytes).await?;
    if !leftover_buf.is_empty() {
        upstream.write_all(&leftover_buf).await?;
    }
    upstream.flush().await?;

    let _ = tokio::time::timeout(
        idle_timeout,
        tokio::io::copy_bidirectional(&mut client_stream, &mut upstream),
    )
    .await;
    Ok(())
}

// ============================================================================
// HÀM TIỆN ÍCH PHỤ TRỢ, CHUNKED DECODER & RESPONSE WRITERS
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
    let lower = upstream_key.trim().to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("wss://") {
        return upstream_key.trim().to_string();
    }
    upstream_key
        .strip_prefix("http://")
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

/// P0-4: Giải mã Chunked Body thuần túy trả `Result`, KHÔNG BAO GIỜ panic, dùng `checked_add` chống integer overflow
fn decode_chunked_body(raw: &[u8], max_size: usize) -> std::result::Result<Bytes, ChunkReadError> {
    let mut out = BytesMut::new();
    let mut idx = 0usize;

    loop {
        if idx >= raw.len() {
            return Err(ChunkReadError::MalformedChunk(
                "400 Bad Request: Unexpected EOF in Chunked Body",
            ));
        }
        let search_end = idx.saturating_add(130).min(raw.len());
        let Some(rel_crlf) = raw[idx..search_end].windows(2).position(|w| w == b"\r\n") else {
            return Err(ChunkReadError::MalformedChunk(
                "400 Bad Request: Chunk Size Line Too Long or Missing CRLF",
            ));
        };
        if rel_crlf > 128 {
            return Err(ChunkReadError::MalformedChunk(
                "400 Bad Request: Chunk Size Line Too Long",
            ));
        }

        let line_str = std::str::from_utf8(&raw[idx..idx + rel_crlf]).map_err(|_| {
            ChunkReadError::MalformedChunk("400 Bad Request: Invalid UTF-8 in Chunk Size Line")
        })?;
        let size_hex = line_str.split(';').next().unwrap_or("").trim();
        if size_hex.is_empty()
            || size_hex.len() > 16
            || !size_hex.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(ChunkReadError::MalformedChunk(
                "400 Bad Request: Invalid Chunk Size Hexadecimal",
            ));
        }
        let chunk_len = usize::from_str_radix(size_hex, 16).map_err(|_| {
            ChunkReadError::MalformedChunk("400 Bad Request: Chunk Size Integer Overflow")
        })?;

        idx = idx
            .checked_add(rel_crlf + 2)
            .ok_or(ChunkReadError::PayloadTooLarge)?;

        if chunk_len == 0 {
            let mut trailer_consumed = 0usize;
            loop {
                let Some(rel) = raw[idx..].windows(2).position(|w| w == b"\r\n") else {
                    return Err(ChunkReadError::MalformedChunk(
                        "400 Bad Request: Missing Terminating CRLF After Zero Chunk",
                    ));
                };
                if rel == 0 {
                    return Ok(out.freeze());
                }
                trailer_consumed = trailer_consumed
                    .checked_add(rel + 2)
                    .ok_or(ChunkReadError::MalformedChunk(
                        "400 Bad Request: Chunk Trailers Overflow",
                    ))?;
                if trailer_consumed > 8192 {
                    return Err(ChunkReadError::MalformedChunk(
                        "400 Bad Request: Chunk Trailers Exceed Limit",
                    ));
                }
                idx = idx
                    .checked_add(rel + 2)
                    .ok_or(ChunkReadError::PayloadTooLarge)?;
            }
        }

        let new_out_len = out
            .len()
            .checked_add(chunk_len)
            .ok_or(ChunkReadError::PayloadTooLarge)?;
        if new_out_len > max_size {
            return Err(ChunkReadError::PayloadTooLarge);
        }

        let data_end = idx
            .checked_add(chunk_len)
            .ok_or(ChunkReadError::PayloadTooLarge)?;
        let crlf_end = data_end
            .checked_add(2)
            .ok_or(ChunkReadError::PayloadTooLarge)?;
        if crlf_end > raw.len() {
            return Err(ChunkReadError::MalformedChunk(
                "400 Bad Request: Unexpected EOF Inside Chunk Payload",
            ));
        }
        if &raw[data_end..crlf_end] != b"\r\n" {
            return Err(ChunkReadError::MalformedChunk(
                "400 Bad Request: Missing CRLF After Chunk Data",
            ));
        }
        out.extend_from_slice(&raw[idx..data_end]);
        idx = crlf_end;
    }
}

/// P0-4: Bộ đọc Chunked Body bất đồng bộ nghiêm ngặt theo RFC 9112 §7.1:
/// - Giới hạn dòng chunk-size tối đa 128 byte, tối đa 16 hex digit
/// - Dùng `checked_add` cho mọi phép cộng kích thước
/// - Áp dụng `step_timeout` cho từng lần đọc từ socket
async fn read_chunked_http1_body<S>(
    stream: &mut S,
    read_buf: &mut BytesMut,
    max_size: usize,
    step_timeout: Duration,
) -> std::result::Result<Bytes, ChunkReadError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut out = BytesMut::new();
    loop {
        loop {
            if let Some(crlf_pos) = read_buf.windows(2).position(|w| w == b"\r\n") {
                if crlf_pos > 128 {
                    return Err(ChunkReadError::MalformedChunk(
                        "400 Bad Request: Chunk Size Line Too Long",
                    ));
                }
                break;
            }
            if read_buf.len() > 128 {
                return Err(ChunkReadError::MalformedChunk(
                    "400 Bad Request: Chunk Size Line Too Long",
                ));
            }
            let n = match tokio::time::timeout(step_timeout, stream.read_buf(read_buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(ChunkReadError::IoError(e.to_string())),
                Err(_) => return Err(ChunkReadError::Timeout),
            };
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
        if size_hex.is_empty()
            || size_hex.len() > 16
            || !size_hex.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(ChunkReadError::MalformedChunk(
                "400 Bad Request: Invalid Chunk Size Hexadecimal",
            ));
        }
        let chunk_len = usize::from_str_radix(size_hex, 16).map_err(|_| {
            ChunkReadError::MalformedChunk("400 Bad Request: Chunk Size Integer Overflow")
        })?;
        let _ = read_buf.split_to(crlf_pos + 2);

        if chunk_len == 0 {
            let mut trailer_bytes_consumed = 0usize;
            loop {
                while !read_buf.windows(2).any(|w| w == b"\r\n") {
                    let cur_total = read_buf
                        .len()
                        .checked_add(trailer_bytes_consumed)
                        .unwrap_or(usize::MAX);
                    if cur_total > 8192 {
                        return Err(ChunkReadError::MalformedChunk(
                            "400 Bad Request: Chunk Trailers Too Large",
                        ));
                    }
                    let n = match tokio::time::timeout(step_timeout, stream.read_buf(read_buf))
                        .await
                    {
                        Ok(Ok(n)) => n,
                        Ok(Err(e)) => return Err(ChunkReadError::IoError(e.to_string())),
                        Err(_) => return Err(ChunkReadError::Timeout),
                    };
                    if n == 0 {
                        return Err(ChunkReadError::MalformedChunk(
                            "400 Bad Request: Missing Terminating CRLF After Zero Chunk",
                        ));
                    }
                }
                let pos = read_buf.windows(2).position(|w| w == b"\r\n").unwrap();
                let _ = read_buf.split_to(pos + 2);
                if pos == 0 {
                    break;
                }
                trailer_bytes_consumed = trailer_bytes_consumed
                    .checked_add(pos + 2)
                    .ok_or(ChunkReadError::MalformedChunk(
                        "400 Bad Request: Chunk Trailers Exceed Limit",
                    ))?;
                if trailer_bytes_consumed > 8192 {
                    return Err(ChunkReadError::MalformedChunk(
                        "400 Bad Request: Chunk Trailers Exceed Limit",
                    ));
                }
            }
            return Ok(out.freeze());
        }

        let new_out_len = out
            .len()
            .checked_add(chunk_len)
            .ok_or(ChunkReadError::PayloadTooLarge)?;
        if new_out_len > max_size {
            return Err(ChunkReadError::PayloadTooLarge);
        }

        let needed = chunk_len
            .checked_add(2)
            .ok_or(ChunkReadError::PayloadTooLarge)?;
        while read_buf.len() < needed {
            let n = match tokio::time::timeout(step_timeout, stream.read_buf(read_buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(ChunkReadError::IoError(e.to_string())),
                Err(_) => return Err(ChunkReadError::Timeout),
            };
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

#[inline]
fn should_suppress_body(method: &str, status: StatusCode) -> bool {
    method.eq_ignore_ascii_case("HEAD")
        || status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
}

fn format_http1_head(
    status: StatusCode,
    headers: &[(String, String)],
    content_length: Option<u64>,
    use_chunked: bool,
    cfg: &ServerConfig,
    keep_alive: bool,
    emit_alt_svc: bool,
) -> Vec<u8> {
    let https_port = cfg.https_port();
    let reason = status.canonical_reason().unwrap_or("OK");
    let mut head = Vec::with_capacity(512);

    head.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", status.as_u16(), reason).as_bytes());
    if cfg.server_tokens {
        head.extend_from_slice(b"Server: FerrousX\r\n");
    }
    // P1-8: Bỏ h3-29 khỏi Alt-Svc, chỉ quảng bá h3 chuẩn
    if emit_alt_svc {
        head.extend_from_slice(
            format!("Alt-Svc: h3=\":{https_port}\"; ma={}\r\n", cfg.alt_svc_max_age).as_bytes(),
        );
    }

    for (k, v) in headers {
        if is_hop_by_hop_header(k) || k.eq_ignore_ascii_case("content-length") {
            continue;
        }
        let clean_k = sanitize_header_name(k);
        let clean_v = sanitize_header_value(v);
        if !clean_k.is_empty() {
            head.extend_from_slice(format!("{clean_k}: {clean_v}\r\n").as_bytes());
        }
    }

    let omit_cl = status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED;
    if use_chunked && !omit_cl {
        head.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    } else if !omit_cl {
        if let Some(cl) = content_length {
            head.extend_from_slice(format!("Content-Length: {cl}\r\n").as_bytes());
        }
    }

    if keep_alive {
        head.extend_from_slice(b"Connection: keep-alive\r\n\r\n");
    } else {
        head.extend_from_slice(b"Connection: close\r\n\r\n");
    }
    head
}

/// P1-3: Tôn trọng `HEAD` (giữ đúng Content-Length nhưng không gửi body) & không gửi body cho `1xx`/`204`/`304`
async fn write_http1_response<S>(
    stream: &mut S,
    method: &str,
    resp: &HttpResponsePayload,
    cfg: &ServerConfig,
    keep_alive: bool,
    emit_alt_svc: bool,
    stats: &EngineRuntimeStats,
) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let head = format_http1_head(
        resp.status,
        &resp.headers,
        Some(resp.body.len() as u64),
        false,
        cfg,
        keep_alive,
        emit_alt_svc,
    );
    stream.write_all(&head).await?;
    if !should_suppress_body(method, resp.status) && !resp.body.is_empty() {
        stream.write_all(&resp.body).await?;
        stats
            .bytes_sent
            .fetch_add(resp.body.len() as u64, Ordering::Relaxed);
    }
    stream.flush().await?;
    Ok(())
}

/// Bộ giải mã chunked gia tăng (Incremental Chunked Stream Decoder) dùng cho SSE / streaming từ upstream HTTP/1.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamChunkState {
    ReadingSize,
    ReadingData(usize),
    ReadingDataCrlf,
    ReadingTrailers,
    Done,
}

struct ChunkedStreamDecoder {
    state: StreamChunkState,
    buf: BytesMut,
    emitted_bytes: usize,
    max_bytes: usize,
}

impl ChunkedStreamDecoder {
    fn new(initial: Bytes, max_bytes: usize) -> Self {
        let mut buf = BytesMut::with_capacity(initial.len().max(4096));
        buf.extend_from_slice(&initial);
        Self {
            state: StreamChunkState::ReadingSize,
            buf,
            emitted_bytes: 0,
            max_bytes,
        }
    }

    fn feed(&mut self, bytes: &[u8]) {
        if !bytes.is_empty() && self.state != StreamChunkState::Done {
            self.buf.extend_from_slice(bytes);
        }
    }

    /// Trả về Ok(Some(chunk)) khi có dữ liệu giải mã, Ok(None) khi cần đọc thêm hoặc đã hoàn thành (`is_done()`).
    fn next_decoded(&mut self) -> std::result::Result<Option<Bytes>, &'static str> {
        loop {
            match self.state {
                StreamChunkState::Done => return Ok(None),
                StreamChunkState::ReadingSize => {
                    let Some(crlf_pos) = self.buf.windows(2).position(|w| w == b"\r\n") else {
                        if self.buf.len() > 128 {
                            return Err("Upstream chunk size line too long");
                        }
                        return Ok(None);
                    };
                    if crlf_pos > 128 {
                        return Err("Upstream chunk size line too long");
                    }
                    let line_str = std::str::from_utf8(&self.buf[..crlf_pos])
                        .map_err(|_| "Invalid UTF-8 in upstream chunk size line")?;
                    let size_hex = line_str.split(';').next().unwrap_or("").trim();
                    if size_hex.is_empty()
                        || size_hex.len() > 16
                        || !size_hex.bytes().all(|b| b.is_ascii_hexdigit())
                    {
                        return Err("Malformed upstream chunk size hex");
                    }
                    let chunk_len = usize::from_str_radix(size_hex, 16)
                        .map_err(|_| "Upstream chunk size overflow")?;
                    let _ = self.buf.split_to(crlf_pos + 2);
                    if chunk_len == 0 {
                        self.state = StreamChunkState::ReadingTrailers;
                    } else {
                        self.state = StreamChunkState::ReadingData(chunk_len);
                    }
                }
                StreamChunkState::ReadingData(rem) => {
                    if self.buf.is_empty() {
                        return Ok(None);
                    }
                    let take = rem.min(self.buf.len());
                    let next_total = self
                        .emitted_bytes
                        .checked_add(take)
                        .ok_or("Upstream stream byte counter overflow")?;
                    if next_total > self.max_bytes {
                        return Err("Upstream stream exceeded max_response_bytes");
                    }
                    self.emitted_bytes = next_total;
                    let chunk = self.buf.split_to(take).freeze();
                    if rem == take {
                        self.state = StreamChunkState::ReadingDataCrlf;
                    } else {
                        self.state = StreamChunkState::ReadingData(rem - take);
                    }
                    return Ok(Some(chunk));
                }
                StreamChunkState::ReadingDataCrlf => {
                    if self.buf.len() < 2 {
                        return Ok(None);
                    }
                    if &self.buf[..2] != b"\r\n" {
                        return Err("Missing CRLF after upstream chunk data");
                    }
                    let _ = self.buf.split_to(2);
                    self.state = StreamChunkState::ReadingSize;
                }
                StreamChunkState::ReadingTrailers => {
                    let Some(pos) = self.buf.windows(2).position(|w| w == b"\r\n") else {
                        if self.buf.len() > 8192 {
                            return Err("Upstream chunk trailers too large");
                        }
                        return Ok(None);
                    };
                    let _ = self.buf.split_to(pos + 2);
                    if pos == 0 {
                        self.state = StreamChunkState::Done;
                        return Ok(None);
                    }
                }
            }
        }
    }

    #[inline]
    fn is_done(&self) -> bool {
        self.state == StreamChunkState::Done
    }
}

#[allow(clippy::too_many_arguments)]
async fn write_http1_dispatch_response<S>(
    stream: &mut S,
    method: &str,
    version_is_11: bool,
    resp: DispatchResponse,
    cfg: &ServerConfig,
    keep_alive: bool,
    emit_alt_svc: bool,
    stats: &EngineRuntimeStats,
) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    match resp {
        DispatchResponse::Buffered(p) => {
            write_http1_response(stream, method, &p, cfg, keep_alive, emit_alt_svc, stats).await
        }
        DispatchResponse::StaticFile {
            status,
            headers,
            path,
            offset,
            len,
        } => {
            let head = format_http1_head(
                status,
                &headers,
                Some(len),
                false,
                cfg,
                keep_alive,
                emit_alt_svc,
            );
            stream.write_all(&head).await?;
            if !should_suppress_body(method, status) && len > 0 {
                let mut file = tokio::fs::File::open(&path).await?;
                if offset > 0 {
                    file.seek(SeekFrom::Start(offset)).await?;
                }
                let mut remaining = len;
                let mut buf = [0u8; 64 * 1024];
                while remaining > 0 {
                    let to_read = (remaining as usize).min(buf.len());
                    let n = file.read(&mut buf[..to_read]).await?;
                    if n == 0 {
                        break;
                    }
                    stream.write_all(&buf[..n]).await?;
                    stats.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                    remaining -= n as u64;
                }
            }
            stream.flush().await?;
            Ok(())
        }
        DispatchResponse::UpstreamStream {
            status,
            headers,
            mut stream: up_stream,
            initial_bytes,
            known_content_length,
            max_bytes,
            read_timeout,
            upstream_chunked,
        } => {
            let suppressed = should_suppress_body(method, status);
            let use_chunked = !suppressed && known_content_length.is_none() && version_is_11 && keep_alive;
            let eff_keep_alive = keep_alive && (suppressed || known_content_length.is_some() || use_chunked);
            let head = format_http1_head(
                status,
                &headers,
                known_content_length,
                use_chunked,
                cfg,
                eff_keep_alive,
                emit_alt_svc,
            );
            stream.write_all(&head).await?;
            if suppressed {
                stream.flush().await?;
                return Ok(());
            }

            if upstream_chunked {
                let mut decoder = ChunkedStreamDecoder::new(initial_bytes, max_bytes);
                let mut buf = [0u8; 16 * 1024];
                loop {
                    while let Some(chunk) = match decoder.next_decoded() {
                        Ok(c) => c,
                        Err(_) => break,
                    } {
                        write_http1_stream_chunk(stream, &chunk, use_chunked, stats).await?;
                    }
                    if decoder.is_done() {
                        break;
                    }
                    match tokio::time::timeout(read_timeout, up_stream.read(&mut buf)).await {
                        Ok(Ok(0)) => break,
                        Ok(Ok(n)) => decoder.feed(&buf[..n]),
                        _ => break,
                    }
                }
            } else {
                let mut total_streamed: usize = 0;
                if !initial_bytes.is_empty() {
                    let chunk = &initial_bytes[..initial_bytes.len().min(max_bytes)];
                    write_http1_stream_chunk(stream, chunk, use_chunked, stats).await?;
                    total_streamed = total_streamed.saturating_add(chunk.len());
                }

                let mut buf = [0u8; 16 * 1024];
                loop {
                    if total_streamed >= max_bytes {
                        break;
                    }
                    match tokio::time::timeout(read_timeout, up_stream.read(&mut buf)).await {
                        Ok(Ok(0)) => break,
                        Ok(Ok(n)) => {
                            let allowed = (max_bytes - total_streamed).min(n);
                            write_http1_stream_chunk(stream, &buf[..allowed], use_chunked, stats)
                                .await?;
                            total_streamed = total_streamed.saturating_add(allowed);
                        }
                        _ => break,
                    }
                }
            }
            if use_chunked {
                stream.write_all(b"0\r\n\r\n").await?;
            }
            stream.flush().await?;
            Ok(())
        }
    }
}

async fn write_http1_stream_chunk<S>(
    stream: &mut S,
    chunk: &[u8],
    use_chunked: bool,
    stats: &EngineRuntimeStats,
) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if chunk.is_empty() {
        return Ok(());
    }
    if use_chunked {
        let len_hdr = format!("{:x}\r\n", chunk.len());
        stream.write_all(len_hdr.as_bytes()).await?;
        stream.write_all(chunk).await?;
        stream.write_all(b"\r\n").await?;
    } else {
        stream.write_all(chunk).await?;
    }
    stats.bytes_sent.fetch_add(chunk.len() as u64, Ordering::Relaxed);
    stream.flush().await?;
    Ok(())
}

fn build_h2_or_h3_response(
    status: StatusCode,
    headers: &[(String, String)],
    content_length: Option<u64>,
    cfg: &ServerConfig,
    emit_alt_svc: bool,
) -> http::Result<Response<()>> {
    let mut builder = Response::builder().status(status);
    let https_port = cfg.https_port();
    if let Some(hmap) = builder.headers_mut() {
        if emit_alt_svc {
            if let Ok(hv) = HeaderValue::from_str(&format!(
                "h3=\":{https_port}\"; ma={}",
                cfg.alt_svc_max_age
            )) {
                hmap.append(HeaderName::from_static("alt-svc"), hv);
            }
        }
        if cfg.server_tokens {
            hmap.append(
                HeaderName::from_static("server"),
                HeaderValue::from_static("FerrousX"),
            );
        }
        for (k, v) in headers {
            if is_hop_by_hop_header(k) || k.eq_ignore_ascii_case("content-length") {
                continue;
            }
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) {
                hmap.append(hn, hv);
            }
        }
        let omit_cl = status.is_informational()
            || status == StatusCode::NO_CONTENT
            || status == StatusCode::NOT_MODIFIED;
        if !omit_cl {
            if let Some(cl) = content_length {
                if let Ok(hv) = HeaderValue::from_str(&cl.to_string()) {
                    hmap.append(HeaderName::from_static("content-length"), hv);
                }
            }
        }
    }
    builder.body(())
}

async fn send_h2_dispatch_response(
    respond: &mut h2::server::SendResponse<Bytes>,
    method: &str,
    resp: DispatchResponse,
    cfg: &ServerConfig,
    emit_alt_svc: bool,
    stats: &EngineRuntimeStats,
) {
    match resp {
        DispatchResponse::Buffered(p) => {
            let suppressed = should_suppress_body(method, p.status) || p.body.is_empty();
            if let Ok(response) = build_h2_or_h3_response(
                p.status,
                &p.headers,
                Some(p.body.len() as u64),
                cfg,
                emit_alt_svc,
            ) {
                if let Ok(mut send_stream) = respond.send_response(response, suppressed) {
                    if !suppressed {
                        let body_len = p.body.len() as u64;
                        if send_stream.send_data(p.body, true).is_ok() {
                            stats.bytes_sent.fetch_add(body_len, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
        DispatchResponse::StaticFile {
            status,
            headers,
            path,
            offset,
            len,
        } => {
            let suppressed = should_suppress_body(method, status) || len == 0;
            if let Ok(response) =
                build_h2_or_h3_response(status, &headers, Some(len), cfg, emit_alt_svc)
            {
                if let Ok(mut send_stream) = respond.send_response(response, suppressed) {
                    if !suppressed {
                        if let Ok(mut file) = tokio::fs::File::open(&path).await {
                            if offset == 0 || file.seek(SeekFrom::Start(offset)).await.is_ok() {
                                let mut remaining = len;
                                let mut buf = [0u8; 64 * 1024];
                                while remaining > 0 {
                                    let to_read = (remaining as usize).min(buf.len());
                                    match file.read(&mut buf[..to_read]).await {
                                        Ok(0) | Err(_) => break,
                                        Ok(n) => {
                                            remaining -= n as u64;
                                            let is_end = remaining == 0;
                                            if send_stream
                                                .send_data(Bytes::copy_from_slice(&buf[..n]), is_end)
                                                .is_err()
                                            {
                                                break;
                                            }
                                            stats.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        DispatchResponse::UpstreamStream {
            status,
            headers,
            mut stream: up_stream,
            initial_bytes,
            known_content_length,
            max_bytes,
            read_timeout,
            upstream_chunked,
        } => {
            let suppressed = should_suppress_body(method, status);
            if let Ok(response) =
                build_h2_or_h3_response(status, &headers, known_content_length, cfg, emit_alt_svc)
            {
                if let Ok(mut send_stream) = respond.send_response(response, suppressed) {
                    if !suppressed {
                        if upstream_chunked {
                            let mut decoder = ChunkedStreamDecoder::new(initial_bytes, max_bytes);
                            let mut buf = [0u8; 16 * 1024];
                            loop {
                                let mut send_failed = false;
                                loop {
                                    match decoder.next_decoded() {
                                        Ok(Some(chunk)) => {
                                            let clen = chunk.len() as u64;
                                            if send_stream.send_data(chunk, false).is_err() {
                                                send_failed = true;
                                                break;
                                            }
                                            stats.bytes_sent.fetch_add(clen, Ordering::Relaxed);
                                        }
                                        Ok(None) => break,
                                        Err(_) => {
                                            send_failed = true;
                                            break;
                                        }
                                    }
                                }
                                if send_failed || decoder.is_done() {
                                    break;
                                }
                                match tokio::time::timeout(read_timeout, up_stream.read(&mut buf))
                                    .await
                                {
                                    Ok(Ok(n)) if n > 0 => decoder.feed(&buf[..n]),
                                    _ => break,
                                }
                            }
                        } else {
                            let mut total = 0usize;
                            if !initial_bytes.is_empty() {
                                let take = initial_bytes.len().min(max_bytes);
                                let _ = send_stream.send_data(initial_bytes.slice(..take), false);
                                stats.bytes_sent.fetch_add(take as u64, Ordering::Relaxed);
                                total = total.saturating_add(take);
                            }
                            let mut buf = [0u8; 16 * 1024];
                            loop {
                                if total >= max_bytes {
                                    break;
                                }
                                match tokio::time::timeout(read_timeout, up_stream.read(&mut buf))
                                    .await
                                {
                                    Ok(Ok(n)) if n > 0 => {
                                        let take = (max_bytes - total).min(n);
                                        if send_stream
                                            .send_data(Bytes::copy_from_slice(&buf[..take]), false)
                                            .is_err()
                                        {
                                            break;
                                        }
                                        stats.bytes_sent.fetch_add(take as u64, Ordering::Relaxed);
                                        total = total.saturating_add(take);
                                    }
                                    _ => break,
                                }
                            }
                        }
                        let _ = send_stream.send_data(Bytes::new(), true);
                    }
                }
            }
        }
    }
}

async fn send_h3_dispatch_response(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    method: &str,
    resp: DispatchResponse,
    cfg: &ServerConfig,
    stats: &EngineRuntimeStats,
) {
    match resp {
        DispatchResponse::Buffered(p) => {
            if let Ok(response) = build_h2_or_h3_response(
                p.status,
                &p.headers,
                Some(p.body.len() as u64),
                cfg,
                false,
            ) {
                if stream.send_response(response).await.is_ok() {
                    if !should_suppress_body(method, p.status) && !p.body.is_empty() {
                        let body_len = p.body.len() as u64;
                        if stream.send_data(p.body).await.is_ok() {
                            stats.bytes_sent.fetch_add(body_len, Ordering::Relaxed);
                        }
                    }
                    let _ = stream.finish().await;
                }
            }
        }
        DispatchResponse::StaticFile {
            status,
            headers,
            path,
            offset,
            len,
        } => {
            if let Ok(response) = build_h2_or_h3_response(status, &headers, Some(len), cfg, false) {
                if stream.send_response(response).await.is_ok() {
                    if !should_suppress_body(method, status) && len > 0 {
                        if let Ok(mut file) = tokio::fs::File::open(&path).await {
                            if offset == 0 || file.seek(SeekFrom::Start(offset)).await.is_ok() {
                                let mut remaining = len;
                                let mut buf = [0u8; 64 * 1024];
                                while remaining > 0 {
                                    let to_read = (remaining as usize).min(buf.len());
                                    match file.read(&mut buf[..to_read]).await {
                                        Ok(0) | Err(_) => break,
                                        Ok(n) => {
                                            remaining -= n as u64;
                                            if stream
                                                .send_data(Bytes::copy_from_slice(&buf[..n]))
                                                .await
                                                .is_err()
                                            {
                                                break;
                                            }
                                            stats.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    let _ = stream.finish().await;
                }
            }
        }
        DispatchResponse::UpstreamStream {
            status,
            headers,
            mut stream: up_stream,
            initial_bytes,
            known_content_length,
            max_bytes,
            read_timeout,
            upstream_chunked,
        } => {
            if let Ok(response) =
                build_h2_or_h3_response(status, &headers, known_content_length, cfg, false)
            {
                if stream.send_response(response).await.is_ok() {
                    if !should_suppress_body(method, status) {
                        if upstream_chunked {
                            let mut decoder = ChunkedStreamDecoder::new(initial_bytes, max_bytes);
                            let mut buf = [0u8; 16 * 1024];
                            loop {
                                let mut send_failed = false;
                                loop {
                                    match decoder.next_decoded() {
                                        Ok(Some(chunk)) => {
                                            let clen = chunk.len() as u64;
                                            if stream.send_data(chunk).await.is_err() {
                                                send_failed = true;
                                                break;
                                            }
                                            stats.bytes_sent.fetch_add(clen, Ordering::Relaxed);
                                        }
                                        Ok(None) => break,
                                        Err(_) => {
                                            send_failed = true;
                                            break;
                                        }
                                    }
                                }
                                if send_failed || decoder.is_done() {
                                    break;
                                }
                                match tokio::time::timeout(read_timeout, up_stream.read(&mut buf))
                                    .await
                                {
                                    Ok(Ok(n)) if n > 0 => decoder.feed(&buf[..n]),
                                    _ => break,
                                }
                            }
                        } else {
                            let mut total = 0usize;
                            if !initial_bytes.is_empty() {
                                let take = initial_bytes.len().min(max_bytes);
                                let _ = stream.send_data(initial_bytes.slice(..take)).await;
                                stats.bytes_sent.fetch_add(take as u64, Ordering::Relaxed);
                                total = total.saturating_add(take);
                            }
                            let mut buf = [0u8; 16 * 1024];
                            loop {
                                if total >= max_bytes {
                                    break;
                                }
                                match tokio::time::timeout(read_timeout, up_stream.read(&mut buf))
                                    .await
                                {
                                    Ok(Ok(n)) if n > 0 => {
                                        let take = (max_bytes - total).min(n);
                                        if stream
                                            .send_data(Bytes::copy_from_slice(&buf[..take]))
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }
                                        stats.bytes_sent.fetch_add(take as u64, Ordering::Relaxed);
                                        total = total.saturating_add(take);
                                    }
                                    _ => break,
                                }
                            }
                        }
                    }
                    let _ = stream.finish().await;
                }
            }
        }
    }
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
    use ferrousx_config::config::{ConfigManager, RouteRule, VirtualHost};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn make_req(method: &str, raw_target: &str, host: &str, peer_ip: IpAddr) -> IncomingRequest {
        let (path, query) = split_path_and_query(raw_target);
        IncomingRequest {
            method: method.to_string(),
            raw_target: raw_target.to_string(),
            path,
            query,
            host: host.to_string(),
            headers: Vec::new(),
            body: Bytes::new(),
            peer_ip,
            is_tls: false,
        }
    }

    #[test]
    fn test_strip_port_and_header_sanitizers() {
        assert_eq!(strip_port("example.com:443"), "example.com");
        assert_eq!(strip_port("[::1]:8080"), "[::1]");
        assert_eq!(
            sanitize_header_value("https://example.com/\r\nSet-Cookie: evil=1"),
            "https://example.com/Set-Cookie: evil=1"
        );
    }

    #[test]
    fn test_p0_1_dynamic_wwwroot_host_validation_blocks_dots_and_traversal() {
        assert_eq!(validate_dynamic_wwwroot_host("."), None);
        assert_eq!(validate_dynamic_wwwroot_host(".."), None);
        assert_eq!(validate_dynamic_wwwroot_host(".git"), None);
        assert_eq!(validate_dynamic_wwwroot_host("a/b"), None);
        assert_eq!(validate_dynamic_wwwroot_host("a\\b"), None);
        assert_eq!(validate_dynamic_wwwroot_host("-bad.com"), None);
        assert_eq!(
            validate_dynamic_wwwroot_host("Example.COM"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_p0_2_untrusted_client_cannot_spoof_cf_connecting_ip_or_xff() {
        let cfg = ConfigManager::default_production_demo().current();
        let attacker_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let mut req = make_req("GET", "/index.php", "example.com", attacker_ip);
        req.headers = vec![
            ("CF-Connecting-IP".to_string(), "1.2.3.4".to_string()),
            ("X-Forwarded-For".to_string(), "1.2.3.4".to_string()),
            ("X-Forwarded-Proto".to_string(), "https".to_string()),
        ];

        assert_eq!(resolve_real_client_ip(&req, &cfg), "203.0.113.9");
        assert!(!is_request_https(&req, &cfg));

        let wire = String::from_utf8(build_upstream_http1_request(
            &req,
            &cfg,
            "127.0.0.1:3000",
            true,
            true,
            false,
        ))
        .unwrap();
        assert!(!wire.contains("CF-Connecting-IP: 1.2.3.4"));
        assert!(wire.contains("X-Real-IP: 203.0.113.9"));
        assert!(wire.contains("X-Forwarded-For: 203.0.113.9"));

        // Trusted proxy uses rightmost untrusted XFF entry
        let cf_ip = IpAddr::V4(Ipv4Addr::new(104, 16, 1, 1));
        let mut cf_req = make_req("GET", "/", "example.com", cf_ip);
        cf_req.headers = vec![
            (
                "X-Forwarded-For".to_string(),
                "9.9.9.9, 198.51.100.77, 173.245.48.5".to_string(),
            ),
            ("X-Forwarded-Proto".to_string(), "https".to_string()),
        ];
        assert_eq!(resolve_real_client_ip(&cf_req, &cfg), "198.51.100.77");
        assert!(is_request_https(&cf_req, &cfg));
    }

    #[test]
    fn test_p0_3_fastcgi_httpoxy_cookie_merge_underscore_and_path_info() {
        let cfg = ConfigManager::default_production_demo().current();
        let mut req = make_req(
            "POST",
            "/app.php/users/profile?tab=1",
            "example.com",
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        );
        req.headers = vec![
            ("Proxy".to_string(), "http://evil.attacker:8080".to_string()),
            ("X_Evil".to_string(), "smuggled".to_string()),
            ("Cookie".to_string(), "a=1".to_string()),
            ("Cookie".to_string(), "b=2".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Content-Length".to_string(), "12".to_string()),
        ];
        let (script_part, path_info) = split_php_script_and_path_info("/app.php/users/profile").unwrap();
        assert_eq!(script_part, "/app.php");
        assert_eq!(path_info, Some("/users/profile"));

        let params = build_fastcgi_params_for_request(
            &req,
            &cfg,
            script_part,
            path_info,
            "/www/wwwroot/example.com",
            "/www/wwwroot/example.com/app.php",
        );

        assert!(!params.iter().any(|(k, _)| k == "HTTP_PROXY"));
        assert!(!params.iter().any(|(k, _)| k == "HTTP_X_EVIL"));
        assert!(!params.iter().any(|(k, _)| k == "HTTP_CONTENT_TYPE"));
        assert!(!params.iter().any(|(k, _)| k == "HTTP_CONTENT_LENGTH"));
        assert_eq!(
            params.iter().find(|(k, _)| k == "HTTP_COOKIE").map(|(_, v)| v.as_str()),
            Some("a=1; b=2")
        );
        assert_eq!(
            params.iter().find(|(k, _)| k == "PATH_INFO").map(|(_, v)| v.as_str()),
            Some("/users/profile")
        );
        assert_eq!(
            params
                .iter()
                .find(|(k, _)| k == "PATH_TRANSLATED")
                .map(|(_, v)| v.as_str()),
            Some("/www/wwwroot/example.com/users/profile")
        );
    }

    #[tokio::test]
    async fn test_p0_4_strict_chunked_decoder_rejects_overflow_and_malformed() {
        let mut cursor = std::io::Cursor::new(b"ZZ\r\nsmuggled\r\n0\r\n\r\n".to_vec());
        let mut buf = BytesMut::new();
        let res = read_chunked_http1_body(&mut cursor, &mut buf, 1024, Duration::from_secs(2)).await;
        assert!(matches!(res, Err(ChunkReadError::MalformedChunk(_))));

        // Chunk hợp lệ theo sau bởi chunk overflow FFFFFFFFFFFFFFF0
        let mut ovf_cursor =
            std::io::Cursor::new(b"5\r\nhello\r\nFFFFFFFFFFFFFFF0\r\nworld\r\n0\r\n\r\n".to_vec());
        let mut ovf_buf = BytesMut::new();
        let ovf_res =
            read_chunked_http1_body(&mut ovf_cursor, &mut ovf_buf, 1024, Duration::from_secs(2))
                .await;
        assert_eq!(ovf_res, Err(ChunkReadError::PayloadTooLarge));

        assert!(matches!(
            decode_chunked_body(b"5\r\nhello\r\nFFFFFFFFFFFFFFF0\r\nx\r\n0\r\n\r\n", 1024),
            Err(ChunkReadError::PayloadTooLarge)
        ));
        assert!(matches!(
            decode_chunked_body(b"5\r\nhel", 1024),
            Err(ChunkReadError::MalformedChunk(_))
        ));
    }

    #[tokio::test]
    async fn test_strict_chunked_decoder_valid_chunks() {
        let mut cursor =
            std::io::Cursor::new(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n".to_vec());
        let mut buf = BytesMut::new();
        let res = read_chunked_http1_body(&mut cursor, &mut buf, 1024, Duration::from_secs(2))
            .await
            .expect("valid chunked body");
        assert_eq!(&res[..], b"hello world");
        assert!(buf.is_empty());
    }

    #[test]
    fn test_p0_8_panel_and_websocket_route_isolation() {
        let mut cfg = ConfigManager::default_production_demo().current();
        cfg.panel_admin.custom_domain = String::new();
        cfg.vhosts = vec![VirtualHost {
            server_name: "customer.com".to_string(),
            ..VirtualHost::default_catch_all()
        }];

        // Khi customDomain rỗng, `/api/sites` trên domain khách KHÔNG được chuyển tới panel!
        let customer_req = make_req(
            "GET",
            "/api/sites",
            "customer.com",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        );
        assert!(!is_panel_request(&customer_req, "/api/sites", &cfg));

        // WebSocket không khớp route trả None (404), KHÔNG fallback về panel
        let reg = UpstreamBalancerRegistry::new();
        let ws_res = resolve_websocket_upstream(&customer_req, "/ws/unknown", &cfg, &reg);
        assert_eq!(ws_res, Ok(None));

        // WebSocket tới panel bị chặn nếu Origin khác host (chống CSWSH)
        let mut evil_ws = make_req(
            "GET",
            "/ws/ssh",
            "127.0.0.1",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        );
        evil_ws
            .headers
            .push(("Origin".to_string(), "https://evil.attacker".to_string()));
        assert_eq!(
            resolve_websocket_upstream(&evil_ws, "/ws/ssh", &cfg, &reg),
            Err(StatusCode::FORBIDDEN)
        );
    }

    #[test]
    fn test_p0_9_accept_encoding_qvalue_and_vary() {
        let comp = CompressionConfig::default();
        assert_eq!(select_best_compression_encoding("zstd;q=0, br;q=0.8", &comp), Some((ContentEncoding::Brotli, "br")));
        assert_eq!(select_best_compression_encoding("zstd;q=0, br;q=0", &comp), None);
        assert_eq!(select_best_compression_encoding("br;q=0.5, zstd;q=1.0", &comp), Some((ContentEncoding::Zstd, "zstd")));
    }

    #[test]
    fn test_p1_2_p1_4_p1_9_sensitive_files_range_http_date_and_longest_route() {
        assert!(is_sensitive_path("/.env"));
        assert!(is_sensitive_path("/.env.local"));
        assert!(is_sensitive_path("/.git/config"));
        assert!(is_sensitive_path("/app/.hidden"));
        assert!(is_sensitive_path("/composer.json"));
        assert!(is_sensitive_path("/backup.sql"));
        assert!(is_sensitive_path("/wp-config.php.bak"));
        assert!(!is_sensitive_path("/.well-known/acme-challenge/abc"));
        assert!(!is_sensitive_path("/docs/a..b.txt"));

        assert_eq!(
            parse_single_byte_range("bytes=0-499", 1000),
            RangeParseResult::Satisfiable { start: 0, end: 499 }
        );
        assert_eq!(
            parse_single_byte_range("bytes=-200", 1000),
            RangeParseResult::Satisfiable {
                start: 800,
                end: 999
            }
        );
        assert_eq!(
            parse_single_byte_range("bytes=2000-2500", 1000),
            RangeParseResult::Unsatisfiable
        );

        let ts = 1_700_000_000;
        let formatted = format_http_date(ts);
        assert_eq!(parse_http_date(&formatted), Some(ts));

        let routes = vec![
            RouteRule {
                path_prefix: "/api".to_string(),
                target_upstream: Some("api_v1".to_string()),
                backend_protocol: BackendProtocol::Http1,
                strip_prefix: false,
                timeout_ms: None,
                inject_headers: HashMap::new(),
            },
            RouteRule {
                path_prefix: "/api/v2".to_string(),
                target_upstream: Some("api_v2".to_string()),
                backend_protocol: BackendProtocol::Http1,
                strip_prefix: false,
                timeout_ms: None,
                inject_headers: HashMap::new(),
            },
        ];
        // `/apixyz` KHÔNG khớp `/api`
        assert!(select_longest_proxy_route(&routes, "/apixyz").is_none());
        // `/api/v2/items` khớp prefix dài nhất `/api/v2`
        assert_eq!(
            select_longest_proxy_route(&routes, "/api/v2/items")
                .and_then(|r| r.target_upstream.as_deref()),
            Some("api_v2")
        );
    }

    #[tokio::test]
    async fn test_p1_3_write_http1_head_suppresses_body_keeps_content_length() {
        let cfg = ConfigManager::default_production_demo().current();
        let stats = EngineRuntimeStats::new();
        let resp = HttpResponsePayload {
            status: StatusCode::OK,
            headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
            body: Bytes::from_static(b"hello world"),
        };
        let mut sink = Vec::new();
        write_http1_response(&mut sink, "HEAD", &resp, &cfg, false, false, &stats)
            .await
            .unwrap();
        let text = String::from_utf8(sink).unwrap();
        assert!(text.contains("Content-Length: 11\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
        assert!(!text.contains("hello world"));
    }

    #[test]
    fn test_p1_5_is_safe_tcp_upstream_and_chunked_stream_decoder() {
        assert!(is_safe_tcp_upstream("127.0.0.1:888"));
        assert!(is_safe_tcp_upstream("http://127.0.0.1:8443"));
        assert!(!is_safe_tcp_upstream("169.254.169.254:80"));
        assert!(!is_safe_tcp_upstream("metadata.google.internal:80"));
        assert!(!is_safe_tcp_upstream("0.0.0.0:8080"));

        let mut dec = ChunkedStreamDecoder::new(Bytes::from_static(b"5\r\ndata:"), 1024);
        assert_eq!(dec.next_decoded().unwrap().as_deref(), Some(&b"data:"[..]));
        assert_eq!(dec.next_decoded().unwrap(), None);
        dec.feed(b"\r\n5\r\n ping\r\n0\r\n\r\n");
        assert_eq!(dec.next_decoded().unwrap().as_deref(), Some(&b" ping"[..]));
        assert_eq!(dec.next_decoded().unwrap(), None);
        assert!(dec.is_done());
    }
}
