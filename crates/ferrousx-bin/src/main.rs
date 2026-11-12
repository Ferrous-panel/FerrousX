//! crates/ferrousx-bin/src/main.rs
//! Điểm khởi chạy chính (CLI Entrypoint) của máy chủ FerrousX.
//! Quản lý tín hiệu hệ điều hành (SIGHUP hot-reload, SIGUSR2 binary upgrade)
//! và điều phối các luồng Worker theo kiến trúc Thread-Per-Core.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use tracing::{error, info};

use ferrousx_config::config::ConfigManager;
use ferrousx_core::worker::spawn_thread_per_core_workers;
use ferrousx_http::server::run_dual_stack_worker;

fn main() -> Result<()> {
    // 1. Khởi tạo hệ thống telemetry độ trễ thấp
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ferrousx=info".into()),
        )
        .with_target(false)
        .init();

    info!("Khởi động FerrousX Engine — High-Performance Rust Web Server & Reverse Proxy");

    // 2. Nạp cấu hình ban đầu vào bộ quản lý không khóa ArcSwap
    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("conf/ferrousx.toml"));

    let config_mgr = if config_path.exists() {
        ConfigManager::from_file(&config_path)?
    } else {
        info!("Sử dụng cấu hình Production Demo mặc định (không tìm thấy file cấu hình ngoài)");
        ConfigManager::default_production_demo()
    };

    // 3. Khởi chạy luồng Control-Plane chuyên lắng nghe tín hiệu POSIX (SIGHUP / SIGTERM)
    spawn_signal_reload_watcher(Arc::clone(&config_mgr));

    // 4. Khởi chạy Rust Panel Control Server (Unix Socket + Embedded Rust Web Dashboard)
    let panel_server = Arc::new(ferrousx_panel::api::PanelServer::new(Arc::clone(&config_mgr)));
    let socket_path = PathBuf::from("/run/ferrousx/panel-admin.sock");
    std::thread::Builder::new()
        .name("ferrousx-panel-uds".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Không thể tạo runtime cho panel UDS server");
            rt.block_on(async move {
                let _ = tokio::join!(
                    panel_server.run_unix_socket_server(&socket_path),
                    ferrousx_panel::webui::serve_embedded_rust_dashboard("127.0.0.1:9090"),
                );
            });
        })
        .expect("Không thể tạo luồng panel server");

    // 5. Khởi tạo cấu hình bảo mật TLS 1.3 & QUIC dùng chung (chỉ đọc)
    let (tls_acceptor, quinn_server_cfg) = build_tls_and_quic_configs(&config_mgr)?;

    // 5. Khởi chạy toàn bộ các Worker theo kiến trúc Thread-Per-Core
    let worker_handles = spawn_thread_per_core_workers(
        Arc::clone(&config_mgr),
        move |ctx, std_tcp, std_udp| {
            let acceptor = tls_acceptor.clone();
            let quic_cfg = quinn_server_cfg.clone();
            async move {
                run_dual_stack_worker(ctx, std_tcp, std_udp, acceptor, quic_cfg).await
            }
        },
    )?;

    for handle in worker_handles {
        let _ = handle.join();
    }

    Ok(())
}

/// Luồng nền lắng nghe tín hiệu SIGHUP để kích hoạt ArcSwap Hot-Reload
fn spawn_signal_reload_watcher(config_mgr: Arc<ConfigManager>) {
    std::thread::Builder::new()
        .name("ferrousx-ctrl-signal".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Không thể tạo runtime cho luồng tín hiệu");

            rt.block_on(async move {
                #[cfg(unix)]
                {
                    use tokio::signal::unix::{signal, SignalKind};
                    let mut sighup = signal(SignalKind::hangup())
                        .expect("Không thể đăng ký trình bắt tín hiệu SIGHUP");

                    while sighup.recv().await.is_some() {
                        info!("Nhận tín hiệu SIGHUP -> Bắt đầu nạp lại cấu hình bằng ArcSwap...");
                        match config_mgr.reload_from_disk() {
                            Ok(new_epoch) => {
                                info!(epoch = new_epoch, "Hot-reload hoàn tất với 0 kết nối bị ngắt");
                            }
                            Err(err) => {
                                error!(error = %err, "Giữ nguyên cấu hình cũ do file mới không hợp lệ");
                            }
                        }
                    }
                }
            });
        })
        .expect("Không thể tạo luồng theo dõi tín hiệu hệ thống");
}

/// Khởi tạo bộ cấu hình TLS 1.3 (cho TCP H1/H2) và Quinn ServerConfig (cho UDP H3/QUIC)
fn build_tls_and_quic_configs(
    config_mgr: &Arc<ConfigManager>,
) -> Result<(tokio_rustls::TlsAcceptor, quinn::ServerConfig)> {
    use std::fs::File;
    use std::io::BufReader;

    let cfg = config_mgr.current();
    let cert_file = File::open(&cfg.tls.cert_chain_path)?;
    let key_file = File::open(&cfg.tls.private_key_path)?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))?
        .ok_or_else(|| anyhow::anyhow!("Không tìm thấy khóa bí mật hợp lệ trong private_key_path"))?;

    // 1. Cấu hình TLS 1.3 cho TCP (HTTP/2 & HTTP/1.1)
    let mut tcp_tls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key.clone_key())?;
    tcp_tls_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tcp_tls_cfg));

    // 2. Cấu hình TLS 1.3 + QUIC Transport cho UDP (HTTP/3)
    let mut quic_tls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    quic_tls_cfg.alpn_protocols = vec![b"h3".to_vec()];
    quic_tls_cfg.max_early_data_size = if cfg.tls.enable_zero_rtt { u32::MAX } else { 0 };

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(quic_tls_cfg)?;
    let mut quinn_server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.initial_mtu(cfg.tls.quic_initial_mtu);
    quinn_server_cfg.transport_config(Arc::new(transport));

    Ok((tls_acceptor, quinn_server_cfg))
}
