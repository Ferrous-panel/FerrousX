//! crates/ferrousx-bin/src/main.rs
//! Điểm khởi chạy chính của máy chủ FerrousX Web Server & Reverse Proxy.
//! - Hỗ trợ `-t` / `--test` (kiểm tra cấu hình, thoát 0/1) và `-v` / `--version`
//! - Tự động sinh chứng chỉ TLS tự ký SAN tại `/etc/ferrousx/ssl/fullchain.pem` & `privkey.pem` (chmod 600)
//! - Đồng bộ động `/etc/ferrous-panel/admin.json`, `/etc/ferrousx/ferrousx.toml`, `/www/server/panel/vhost/ferrousx/*.conf`
//!   qua cả POSIX `SIGHUP` lẫn File Watcher (`notify`)
//! - Lắng nghe đồng thời TCP HTTP (:80) + TCP HTTPS TLS 1.3/1.2 (:443) + UDP HTTP/3 QUIC (:443)
//! - Gửi thông báo `READY=1` qua `$NOTIFY_SOCKET` cho systemd `Type=notify`

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use notify::{EventKind, RecursiveMode, Watcher};
use tracing::{error, info, warn};

use ferrousx_config::config::ConfigManager;
use ferrousx_core::worker::spawn_thread_per_core_workers;
use ferrousx_http::server::run_dual_stack_worker;

const DEFAULT_SYSTEM_CONFIG: &str = "/etc/ferrousx/ferrousx.toml";
const LOCAL_DEV_CONFIG: &str = "conf/ferrousx.toml";

struct StartupOptions {
    config_path: PathBuf,
    explicit_config: bool,
    test_only: bool,
}

fn parse_startup_options() -> StartupOptions {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut test_only = false;
    let mut explicit_config = false;
    let mut config_path = if Path::new(DEFAULT_SYSTEM_CONFIG).exists() {
        PathBuf::from(DEFAULT_SYSTEM_CONFIG)
    } else {
        PathBuf::from(LOCAL_DEV_CONFIG)
    };

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-v" | "--version" => {
                println!(
                    "ferrousx-bin {} (FerrousX Triple-Stack Rust Web Server & Reverse Proxy)",
                    env!("CARGO_PKG_VERSION")
                );
                std::process::exit(0);
            }
            "-h" | "--help" => {
                println!(
                    "FerrousX Web Server & Reverse Proxy\n\
                     Cách dùng:\n  \
                       ferrousx-bin [TÙY_CHỌN] [ĐƯỜNG_DẪN_CONFIG]\n\n\
                     Tùy chọn:\n  \
                       -c, --config <FILE>   Đường dẫn tệp cấu hình TOML (mặc định: /etc/ferrousx/ferrousx.toml)\n  \
                       -t, --test            Kiểm tra cú pháp cấu hình và thoát (0 = hợp lệ, 1 = lỗi)\n  \
                       -v, --version         Hiển thị phiên bản và thoát\n  \
                       -h, --help            Hiển thị trợ giúp"
                );
                std::process::exit(0);
            }
            "-t" | "--test" => {
                test_only = true;
            }
            "-c" | "--config" => {
                if let Some(next) = args.get(i + 1) {
                    config_path = PathBuf::from(next);
                    explicit_config = true;
                    i += 1;
                } else {
                    eprintln!("ferrousx-bin: thiếu đường dẫn sau tùy chọn {}", args[i]);
                    std::process::exit(1);
                }
            }
            arg if !arg.starts_with('-') => {
                config_path = PathBuf::from(arg);
                explicit_config = true;
            }
            unknown => {
                eprintln!("ferrousx-bin: tùy chọn không hợp lệ: {unknown}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    StartupOptions {
        config_path,
        explicit_config,
        test_only,
    }
}

fn validate_configuration_for_cli(path: &Path) -> Result<()> {
    let mgr = ConfigManager::from_file(path)?;
    let cfg = mgr.current();

    cfg.effective_http_addr()
        .parse::<SocketAddr>()
        .with_context(|| format!("bind_http_addr không hợp lệ: {}", cfg.effective_http_addr()))?;
    cfg.effective_https_addr()
        .parse::<SocketAddr>()
        .with_context(|| format!("bind_https_addr không hợp lệ: {}", cfg.effective_https_addr()))?;
    cfg.bind_udp_addr
        .parse::<SocketAddr>()
        .with_context(|| format!("bind_udp_addr không hợp lệ: {}", cfg.bind_udp_addr))?;

    Ok(())
}

fn main() -> Result<()> {
    let opts = parse_startup_options();

    if opts.test_only {
        match validate_configuration_for_cli(&opts.config_path) {
            Ok(()) => {
                println!(
                    "ferrousx: the configuration file {} syntax is ok",
                    opts.config_path.display()
                );
                println!(
                    "ferrousx: configuration file {} test is successful",
                    opts.config_path.display()
                );
                std::process::exit(0);
            }
            Err(err) => {
                eprintln!(
                    "ferrousx: configuration file {} test failed: {err}",
                    opts.config_path.display()
                );
                std::process::exit(1);
            }
        }
    }

    // 1. Khởi tạo hệ thống logging độ trễ thấp
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ferrousx=info".into()),
        )
        .with_target(false)
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "Khởi động FerrousX Engine — Triple-Stack Rust Web Server & Reverse Proxy"
    );

    // 2. Nạp cấu hình ban đầu vào bộ quản lý Lock-Free ArcSwap
    let config_mgr = if opts.config_path.exists() {
        info!(path = %opts.config_path.display(), "Đang nạp cấu hình máy chủ");
        ConfigManager::from_file(&opts.config_path)?
    } else if opts.explicit_config {
        anyhow::bail!("Không tìm thấy tệp cấu hình tại {}", opts.config_path.display());
    } else {
        info!("Không tìm thấy tệp cấu hình ngoài, khởi động với cấu hình Production mặc định");
        ConfigManager::default_production_demo()
    };

    // 3. Đảm bảo chứng chỉ TLS tự ký fallback tồn tại trước khi bind cổng :443
    {
        let cfg = config_mgr.current();
        ensure_tls_certificate(
            &cfg.tls.cert_chain_path,
            &cfg.tls.private_key_path,
            &cfg.panel_admin.custom_domain,
        )?;
    }

    // 4. Khởi tạo cấu hình bảo mật TLS 1.3/1.2 (ALPN h2,http/1.1) & QUIC (:443)
    let (tls_acceptor, quinn_server_cfg) = build_tls_and_quic_configs(&config_mgr)?;

    // 5. Khởi chạy Control-Plane lắng nghe SIGHUP & File Watcher (admin.json + vhosts + ferrousx.toml)
    spawn_signal_reload_watcher(Arc::clone(&config_mgr));
    spawn_config_file_watcher(Arc::clone(&config_mgr));

    // 6. Khởi chạy Panel Control Server (Unix Socket + Embedded Rust Web Dashboard)
    let panel_server = Arc::new(ferrousx_panel::api::PanelServer::new(Arc::clone(&config_mgr)));
    let socket_path = config_mgr.current().panel_control_socket.clone();
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

    // 7. Khởi chạy toàn bộ các Worker theo kiến trúc Thread-Per-Core (TCP :80 + TCP :443 + UDP :443)
    let worker_handles = spawn_thread_per_core_workers(
        Arc::clone(&config_mgr),
        move |ctx, std_http, std_https, std_udp| {
            let acceptor = tls_acceptor.clone();
            let quic_cfg = quinn_server_cfg.clone();
            async move {
                run_dual_stack_worker(ctx, std_http, std_https, std_udp, acceptor, quic_cfg).await
            }
        },
    )?;

    // 8. Báo sẵn sàng tới systemd (Type=notify) sau khi mọi socket đã bind thành công
    notify_systemd_ready();

    for handle in worker_handles {
        let _ = handle.join();
    }

    Ok(())
}

/// Sinh chứng chỉ TLS tự ký (Fallback SAN Certificate) bằng Rust thuần nếu chưa tồn tại,
/// đảm bảo cổng 443 luôn khởi động thành công ngay lần chạy đầu tiên (tránh Cloudflare Error 521).
fn ensure_tls_certificate(cert_path: &Path, key_path: &Path, custom_domain: &str) -> Result<()> {
    let cert_ready = cert_path
        .metadata()
        .map(|m| m.len() > 0)
        .unwrap_or(false);
    let key_ready = key_path
        .metadata()
        .map(|m| m.len() > 0)
        .unwrap_or(false);

    if cert_ready && key_ready {
        return Ok(());
    }

    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Không thể tạo thư mục SSL {}", parent.display()))?;
    }
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Không thể tạo thư mục khóa {}", parent.display()))?;
    }

    let mut sans = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];

    if let Ok(hostname) = std::fs::read_to_string("/etc/hostname") {
        let trimmed = hostname.trim();
        if !trimmed.is_empty() && !sans.iter().any(|s| s == trimmed) {
            sans.push(trimmed.to_string());
        }
    }

    let domain = custom_domain.trim();
    if !domain.is_empty() && !sans.iter().any(|s| s.eq_ignore_ascii_case(domain)) {
        sans.push(domain.to_string());
    }

    let certified = rcgen::generate_simple_self_signed(sans)
        .context("Không thể sinh chứng chỉ TLS tự ký fallback bằng rcgen")?;

    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();

    std::fs::write(cert_path, cert_pem.as_bytes())
        .with_context(|| format!("Không thể ghi chứng chỉ TLS tại {}", cert_path.display()))?;
    std::fs::write(key_path, key_pem.as_bytes())
        .with_context(|| format!("Không thể ghi khóa bí mật TLS tại {}", key_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(cert_path, std::fs::Permissions::from_mode(0o644))?;
        std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    info!(
        cert = %cert_path.display(),
        key = %key_path.display(),
        "Đã tự động sinh chứng chỉ TLS SAN dự phòng (chmod 600 cho privkey.pem)"
    );
    Ok(())
}

/// Gửi thông báo READY=1 tới systemd thông qua `$NOTIFY_SOCKET`
fn notify_systemd_ready() {
    #[cfg(target_os = "linux")]
    {
        use std::os::linux::net::SocketAddrExt;
        let Ok(sock_path) = std::env::var("NOTIFY_SOCKET") else {
            return;
        };
        if sock_path.is_empty() {
            return;
        }
        let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() else {
            return;
        };

        let res = if let Some(abstract_name) = sock_path.strip_prefix('@') {
            if let Ok(addr) = std::os::unix::net::SocketAddr::from_abstract_name(abstract_name.as_bytes()) {
                sock.send_to_addr(b"READY=1", &addr)
            } else {
                return;
            }
        } else {
            sock.send_to(b"READY=1", &sock_path)
        };

        if let Err(err) = res {
            warn!(error = %err, "Không thể gửi READY=1 tới $NOTIFY_SOCKET");
        } else {
            info!("Đã gửi thông báo READY=1 tới systemd");
        }
    }
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
                        info!("Nhận tín hiệu SIGHUP -> Đồng bộ lại ferrousx.toml + admin.json + vhosts...");
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

/// Theo dõi thay đổi trực tiếp trên tệp cấu hình chính, `/etc/ferrous-panel/admin.json`,
/// và thư mục vhost `/www/server/panel/vhost/ferrousx/` để tự động nạp lại không cần khởi động lại service.
fn spawn_config_file_watcher(config_mgr: Arc<ConfigManager>) {
    std::thread::Builder::new()
        .name("ferrousx-cfg-watch".into())
        .spawn(move || {
            let (tx, rx) = std::sync::mpsc::channel();
            let mut watcher = match notify::recommended_watcher(tx) {
                Ok(w) => w,
                Err(err) => {
                    warn!(error = %err, "Không thể khởi tạo file watcher cấu hình");
                    return;
                }
            };

            let cfg = config_mgr.current();
            let main_cfg_path = config_mgr.config_path().to_path_buf();
            let admin_json_path = cfg.panel_admin_json_path.clone();
            let vhost_dir = cfg.vhost_conf_dir.clone();

            let mut watch_dirs: Vec<PathBuf> = Vec::new();
            if let Some(parent) = main_cfg_path.parent() {
                if parent.exists() {
                    watch_dirs.push(parent.to_path_buf());
                }
            }
            if let Some(parent) = admin_json_path.parent() {
                if parent.exists() && !watch_dirs.contains(&parent.to_path_buf()) {
                    watch_dirs.push(parent.to_path_buf());
                }
            }
            if vhost_dir.exists() && !watch_dirs.contains(&vhost_dir) {
                watch_dirs.push(vhost_dir.clone());
            }

            for dir in &watch_dirs {
                if let Err(err) = watcher.watch(dir, RecursiveMode::NonRecursive) {
                    warn!(dir = %dir.display(), error = %err, "Không thể theo dõi thư mục cấu hình");
                } else {
                    info!(dir = %dir.display(), "Đang theo dõi thay đổi cấu hình tự động (Hot-Reload)");
                }
            }

            let mut last_reload = Instant::now() - Duration::from_secs(5);
            for res in rx {
                match res {
                    Ok(event) => {
                        let relevant_kind = matches!(
                            event.kind,
                            EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                        );
                        if !relevant_kind {
                            continue;
                        }

                        let is_target_file = event.paths.iter().any(|p| {
                            p == &main_cfg_path
                                || p == &admin_json_path
                                || p.extension().and_then(|e| e.to_str()) == Some("conf")
                        });
                        if !is_target_file {
                            continue;
                        }

                        if last_reload.elapsed() < Duration::from_millis(200) {
                            continue;
                        }
                        last_reload = Instant::now();

                        // Đợi nhẹ để quá trình ghi atomic của Panel hoàn tất
                        std::thread::sleep(Duration::from_millis(60));
                        match config_mgr.reload_from_disk() {
                            Ok(epoch) => {
                                info!(epoch, "Tự động đồng bộ cấu hình mới từ thay đổi tệp tin");
                            }
                            Err(err) => {
                                warn!(error = %err, "Bỏ qua bản ghi cấu hình đang dở dang hoặc không hợp lệ");
                            }
                        }
                    }
                    Err(err) => {
                        warn!(error = %err, "Lỗi bộ theo dõi file notify");
                    }
                }
            }
        })
        .expect("Không thể tạo luồng theo dõi file cấu hình");
}

/// Khởi tạo bộ cấu hình TLS 1.3/1.2 (cho TCP ALPN h2,http/1.1) và Quinn ServerConfig (cho UDP H3/QUIC)
fn build_tls_and_quic_configs(
    config_mgr: &Arc<ConfigManager>,
) -> Result<(tokio_rustls::TlsAcceptor, quinn::ServerConfig)> {
    use std::fs::File;
    use std::io::BufReader;

    let cfg = config_mgr.current();
    let cert_file = File::open(&cfg.tls.cert_chain_path)
        .with_context(|| format!("Không thể mở cert_chain_path: {}", cfg.tls.cert_chain_path.display()))?;
    let key_file = File::open(&cfg.tls.private_key_path)
        .with_context(|| format!("Không thể mở private_key_path: {}", cfg.tls.private_key_path.display()))?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))?
        .ok_or_else(|| anyhow::anyhow!("Không tìm thấy khóa bí mật hợp lệ trong private_key_path"))?;

    // 1. Cấu hình TLS 1.3/1.2 cho TCP (HTTP/2 & HTTP/1.1 — Cloudflare SSL Full tương thích)
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
