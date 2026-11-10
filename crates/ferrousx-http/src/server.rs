//! crates/ferrousx-http/src/server.rs
//! Động cơ phục vụ Dual-Stack HTTP/1.1, HTTP/2 (qua TCP + TLS 1.3)
//! và HTTP/3 (qua UDP + QUIC) với đường dẫn xử lý Zero-Allocation.

use std::net::{TcpListener as StdTcpListener, UdpSocket as StdUdpSocket};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bumpalo::Bump;
use bytes::{Bytes, BytesMut};
use http::{HeaderValue, Request, Response, StatusCode};
use quinn::{Endpoint, EndpointConfig, ServerConfig as QuinnServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::LocalSet;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use ferrousx_config::config::ConfigManager;
use ferrousx_core::worker::WorkerContext;

/// Dữ liệu phản hồi chuẩn được ghim sẵn trong bộ nhớ tĩnh (Zero-Copy rodata)
static FAST_PAYLOAD_BODY: &[u8] =
    b"{"server":"FerrousX","engine":"io_uring+QUIC","zero_copy":true}
";

/// Khởi chạy đồng thời cả TCP Listener (H1/H2) và UDP Listener (H3/QUIC) trên 1 lõi CPU
pub async fn run_dual_stack_worker(
    ctx: WorkerContext,
    std_tcp: StdTcpListener,
    std_udp: StdUdpSocket,
    tls_acceptor: TlsAcceptor,
    quinn_server_cfg: QuinnServerConfig,
) -> Result<()> {
    let worker_id = ctx.worker_id;
    let config_mgr = Arc::clone(&ctx.config_mgr);

    let tcp_listener = TcpListener::from_std(std_tcp)
        .context("Không thể chuyển đổi TcpListener sang chế độ bất đồng bộ")?;

    // Khởi tạo Quinn UDP Endpoint ngay trên socket đã bật SO_REUSEPORT + UDP_GRO/GSO
    let runtime = quinn::default_runtime()
        .ok_or_else(|| anyhow::anyhow!("Không tìm thấy Async Runtime tương thích cho Quinn"))?;
    let quic_endpoint = Endpoint::new(
        EndpointConfig::default(),
        Some(quinn_server_cfg),
        std_udp,
        runtime,
    )?;

    info!(
        worker_id,
        core = ctx.core_id.id,
        "Worker sẵn sàng tiếp nhận lưu lượng Dual-Stack (TCP H1/H2 + UDP H3/QUIC)"
    );

    // LocalSet cho phép dùng spawn_local (không đòi hỏi Send/Sync, không tốn chi phí đồng bộ hóa đa luồng)
    let local_tasks = LocalSet::new();
    local_tasks
        .run_until(async move {
            tokio::try_join!(
                run_tcp_h1_h2_loop(worker_id, tcp_listener, tls_acceptor, Arc::clone(&config_mgr)),
                run_udp_h3_quic_loop(worker_id, quic_endpoint, config_mgr),
            )
        })
        .await?;

    Ok(())
}

/// Vòng lặp tiếp nhận kết nối TCP/TLS phục vụ HTTP/1.1 và HTTP/2
async fn run_tcp_h1_h2_loop(
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

        // Chạy ngay trên luồng của lõi hiện tại (Zero Cross-Thread Synchronization)
        tokio::task::spawn_local(async move {
            match acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => {
                    let (_, server_conn) = tls_stream.get_ref();
                    let negotiated_alpn = server_conn
                        .alpn_protocol()
                        .map(|p| p.to_vec())
                        .unwrap_or_else(|| b"http/1.1".to_vec());

                    if negotiated_alpn.as_slice() == b"h2" {
                        if let Err(e) = serve_http2_connection(tls_stream, cfg_mgr).await {
                            debug!(worker_id, %peer_addr, error = %e, "Kết thúc phiên HTTP/2");
                        }
                    } else if let Err(e) = serve_http1_zero_alloc(tls_stream, cfg_mgr).await {
                        debug!(worker_id, %peer_addr, error = %e, "Kết thúc phiên HTTP/1.1");
                    }
                }
                Err(err) => {
                    debug!(worker_id, %peer_addr, error = %err, "Bắt tay TLS 1.3 thất bại");
                }
            }
        });
    }
}

/// Xử lý HTTP/1.1 Keep-Alive trên đường dẫn Zero-Heap-Allocation:
/// Sử dụng mảng Header trên Stack + Bumpalo Arena cho việc ghép chuỗi định tuyến.
async fn serve_http1_zero_alloc<S>(mut stream: S, config_mgr: Arc<ConfigManager>) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut read_buf = BytesMut::with_capacity(8192);
    let mut arena = Bump::with_capacity(16 * 1024);

    loop {
        // Giải phóng toàn bộ cấp phát tạm của request trước chỉ bằng 1 phép gán con trỏ
        arena.reset();

        let n = stream.read_buf(&mut read_buf).await?;
        if n == 0 {
            return Ok(());
        }

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);

        match req.parse(&read_buf)? {
            httparse::Status::Complete(parsed_len) => {
                let path = req.path.unwrap_or("/");
                // Đọc cấu hình hiện hành với chi phí 0 lock qua ArcSwap
                let cfg = config_mgr.current();

                // Cấp phát phản hồi HTTP trực tiếp trong Bumpalo Arena của lõi hiện tại
                let response_bytes = build_arena_http1_response(&arena, path, cfg.alt_svc_max_age);
                stream.write_all(response_bytes).await?;

                let _ = read_buf.split_to(parsed_len);
            }
            httparse::Status::Partial => continue,
        }
    }
}

/// Đóng gói khung phản hồi HTTP/1.1 ngay trong vùng nhớ Arena kèm header Alt-Svc nâng cấp lên HTTP/3
#[inline(always)]
fn build_arena_http1_response<'a>(arena: &'a Bump, path: &str, alt_svc_max_age: u32) -> &'a [u8] {
    use bumpalo::collections::Vec as BumpVec;
    use std::io::Write;

    let mut buf = BumpVec::with_capacity_in(512, arena);
    let _ = write!(
        &mut buf,
        "HTTP/1.1 200 OK
         Server: FerrousX/0.1 (Rust; io_uring; Thread-Per-Core)
         Content-Type: application/json
         Alt-Svc: h3=":8443"; ma={alt_svc_max_age}, h3-29=":8443"; ma={alt_svc_max_age}
         X-Routed-Path: {path}
         Content-Length: {}
         Connection: keep-alive

",
        FAST_PAYLOAD_BODY.len()
    );
    buf.extend_from_slice(FAST_PAYLOAD_BODY);
    buf.into_bump_slice()
}

/// Phục vụ đa luồng khung (multiplexed frames) HTTP/2 trên kết nối TLS 1.3
async fn serve_http2_connection<S>(stream: S, config_mgr: Arc<ConfigManager>) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
{
    let mut h2_conn = h2::server::handshake(stream).await?;

    while let Some(result) = h2_conn.accept().await {
        let (request, mut respond) = result?;
        let cfg_mgr = Arc::clone(&config_mgr);

        tokio::task::spawn_local(async move {
            let cfg = cfg_mgr.current();
            let alt_svc_val = format!("h3=":8443"; ma={}", cfg.alt_svc_max_age);

            let response = Response::builder()
                .status(StatusCode::OK)
                .header("server", "FerrousX/0.1 (HTTP/2)")
                .header("content-type", "application/json")
                .header("alt-svc", alt_svc_val)
                .header("x-request-path", request.uri().path())
                .body(())
                .unwrap();

            if let Ok(mut send_stream) = respond.send_response(response, false) {
                let _ = send_stream.send_data(Bytes::from_static(FAST_PAYLOAD_BODY), true);
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
                    if let Err(err) = serve_http3_quic_streams(quic_conn, cfg_mgr).await {
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
                    let resp = Response::builder()
                        .status(StatusCode::OK)
                        .header("server", "FerrousX/0.1 (QUIC/HTTP3)")
                        .header("content-type", "application/json")
                        .header(
                            "x-config-epoch",
                            HeaderValue::from_str(&cfg.version_epoch.to_string()).unwrap(),
                        )
                        .header("x-h3-path", req.uri().path())
                        .body(())
                        .unwrap();

                    if stream.send_response(resp).await.is_ok() {
                        // Zero-Copy truyền khối dữ liệu tĩnh qua khung DATA của HTTP/3
                        let _ = stream.send_data(Bytes::from_static(FAST_PAYLOAD_BODY)).await;
                        let _ = stream.finish().await;
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
