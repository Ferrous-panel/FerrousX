//! crates/ferrousx-bin/src/main.rs
//! Điểm khởi chạy chính của máy chủ FerrousX Web Server & Reverse Proxy (100% Pure Rust).
//! Đồng bộ hoàn toàn với Ferrous-Panel v2.5.0 (`https://github.com/Ferrous-panel/Ferrous-Panel`):
//! - Hỗ trợ `--check-config`, `-t`, `--test` (kiểm tra cấu hình, sites/*.toml & TLS certs, thoát 0/1)
//! - Hỗ trợ `--config <FILE>`, `-c <FILE>`, biến môi trường `FERROUSX_CONFIG`, `-v` / `--version`
//! - Dynamic SNI Certificate Resolution (`ResolvesServerCert`) cho từng website trong `/etc/ferrousx/sites/*.toml`
//!   kèm chứng chỉ TLS tự ký SAN dự phòng tại `/etc/ferrousx/ssl/fullchain.pem` & `privkey.pem` (chmod 600)
//!   để cổng `:443` luôn hoạt động ngay lần đầu (tránh Cloudflare Error 521).
//! - Đồng bộ động `/etc/ferrous-panel/panel.env`, `/etc/ferrous-panel/admin.json`, `/etc/ferrousx/ferrousx.toml`,
//!   `/etc/ferrousx/sites/*.toml`, `/www/server/panel/vhost/ferrousx/*.conf` qua POSIX `SIGHUP` và File Watcher (`notify`).
//! - Lắng nghe đồng thời TCP HTTP (:80) + TCP HTTPS TLS 1.3/1.2 (:443) + UDP HTTP/3 QUIC (:443).
//! - Gửi thông báo `READY=1` qua `$NOTIFY_SOCKET` cho systemd `Type=notify`.

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use notify::{EventKind, RecursiveMode, Watcher};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tracing::{error, info, warn};

use ferrousx_config::config::{ConfigManager, ServerConfig};
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

    let mut config_path = if let Ok(env_cfg) = std::env::var("FERROUSX_CONFIG") {
        let trimmed = env_cfg.trim();
        if !trimmed.is_empty() {
            explicit_config = true;
            PathBuf::from(trimmed)
        } else if Path::new(DEFAULT_SYSTEM_CONFIG).exists() {
            PathBuf::from(DEFAULT_SYSTEM_CONFIG)
        } else {
            PathBuf::from(LOCAL_DEV_CONFIG)
        }
    } else if Path::new(DEFAULT_SYSTEM_CONFIG).exists() {
        PathBuf::from(DEFAULT_SYSTEM_CONFIG)
    } else {
        PathBuf::from(LOCAL_DEV_CONFIG)
    };

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "-v" | "--version" => {
                println!(
                    "ferrousx-bin {} (FerrousX Triple-Stack Pure-Rust Web Server & Reverse Proxy)",
                    env!("CARGO_PKG_VERSION")
                );
                std::process::exit(0);
            }
            "-h" | "--help" => {
                println!(
                    "FerrousX Web Server & Reverse Proxy (Pure Rust — Ferrous-Panel Compatible)\n\
                     Cách dùng:\n  \
                       ferrousx-bin [TÙY_CHỌN] [ĐƯỜNG_DẪN_CONFIG]\n\n\
                     Tùy chọn:\n  \
                       -c, --config <FILE>   Đường dẫn tệp cấu hình TOML (mặc định: /etc/ferrousx/ferrousx.toml hoặc $FERROUSX_CONFIG)\n  \
                       -t, --test,\n      \
                       --check-config        Kiểm tra cú pháp master config, sites/*.toml và chứng chỉ TLS (0 = hợp lệ, 1 = lỗi)\n  \
                       -v, --version         Hiển thị phiên bản và thoát\n  \
                       -h, --help            Hiển thị trợ giúp"
                );
                std::process::exit(0);
            }
            "-t" | "--test" | "--check-config" => {
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
            _ if arg.starts_with("--config=") => {
                let val = arg.trim_start_matches("--config=");
                if val.is_empty() {
                    eprintln!("ferrousx-bin: thiếu đường dẫn trong --config=");
                    std::process::exit(1);
                }
                config_path = PathBuf::from(val);
                explicit_config = true;
            }
            _ if !arg.starts_with('-') => {
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

/// Nạp và xác thực cặp chứng chỉ PEM + khóa bí mật bằng `rustls` ring provider
fn load_certified_key(cert_path: &Path, key_path: &Path) -> Result<Arc<CertifiedKey>> {
    let cert_file = File::open(cert_path)
        .with_context(|| format!("cannot open certificate file {}", cert_path.display()))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("invalid PEM certificate chain {}", cert_path.display()))?;
    if certs.is_empty() {
        anyhow::bail!(
            "certificate file contains no certificates: {}",
            cert_path.display()
        );
    }

    let key_file = File::open(key_path)
        .with_context(|| format!("cannot open private key file {}", key_path.display()))?;
    let mut key_reader = BufReader::new(key_file);
    let private_key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .with_context(|| format!("invalid PEM private key {}", key_path.display()))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "private key file contains no supported key: {}",
                key_path.display()
            )
        })?;

    let provider = rustls::crypto::ring::default_provider();
    let signing_key = provider
        .key_provider
        .load_private_key(private_key)
        .map_err(|e| anyhow::anyhow!("failed to load signing key {}: {e}", key_path.display()))?;

    let certified_key = CertifiedKey::new(certs, signing_key);
    certified_key.keys_match().map_err(|e| {
        anyhow::anyhow!(
            "certificate {} does not match key {}: {e}",
            cert_path.display(),
            key_path.display()
        )
    })?;

    Ok(Arc::new(certified_key))
}

/// Bộ phân giải chứng chỉ SNI động (Dynamic SNI Resolver) hỗ trợ cập nhật nguyên tử khi SIGHUP / Hot-Reload.
/// Tự động chọn chứng chỉ Let's Encrypt riêng cho từng domain trong `/etc/ferrousx/sites/*.toml`,
/// và fallback về chứng chỉ SAN mặc định (`/etc/ferrousx/ssl/fullchain.pem`) khi truy cập qua IP hoặc Cloudflare Full SSL.
#[derive(Debug)]
struct DynamicSniResolver {
    sni_map: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    fallback_cert: RwLock<Arc<CertifiedKey>>,
}

impl DynamicSniResolver {
    fn new(
        initial_map: HashMap<String, Arc<CertifiedKey>>,
        fallback_cert: Arc<CertifiedKey>,
    ) -> Self {
        Self {
            sni_map: RwLock::new(initial_map),
            fallback_cert: RwLock::new(fallback_cert),
        }
    }

    fn swap_from_config(&self, cfg: &ServerConfig) {
        if let Ok(map) = build_sni_cert_map(cfg) {
            if let Ok(mut guard) = self.sni_map.write() {
                *guard = map;
            }
        }
        if let Ok(fallback) =
            load_certified_key(&cfg.tls.cert_chain_path, &cfg.tls.private_key_path)
        {
            if let Ok(mut guard) = self.fallback_cert.write() {
                *guard = fallback;
            }
        }
    }
}

impl ResolvesServerCert for DynamicSniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(raw_sni) = client_hello.server_name() {
            let sni = raw_sni.trim().trim_end_matches('.').to_ascii_lowercase();
            if let Ok(guard) = self.sni_map.read() {
                if let Some(cert) = guard.get(&sni) {
                    return Some(Arc::clone(cert));
                }
            }
        }
        self.fallback_cert.read().ok().map(|g| Arc::clone(&g))
    }
}

/// Xây dựng bảng ánh xạ SNI hostname -> CertifiedKey từ tất cả VirtualHost có `ssl_enabled = true`
fn build_sni_cert_map(cfg: &ServerConfig) -> Result<HashMap<String, Arc<CertifiedKey>>> {
    let mut map = HashMap::new();
    for vhost in &cfg.vhosts {
        if vhost.ssl_enabled {
            let cert_path = vhost.ssl_cert_path.as_ref().ok_or_else(|| {
                anyhow::anyhow!("missing ssl.cert_path for site {}", vhost.server_name)
            })?;
            let key_path = vhost.ssl_key_path.as_ref().ok_or_else(|| {
                anyhow::anyhow!("missing ssl.key_path for site {}", vhost.server_name)
            })?;
            let certified = load_certified_key(cert_path, key_path)?;
            map.insert(
                vhost.server_name.to_ascii_lowercase(),
                Arc::clone(&certified),
            );
            for alias in &vhost.aliases {
                map.insert(alias.to_ascii_lowercase(), Arc::clone(&certified));
            }
        }
    }
    Ok(map)
}

fn validate_configuration_for_cli(path: &Path) -> Result<(usize, String, String)> {
    let mgr = ConfigManager::from_file(path)?;
    let cfg = mgr.current();

    let http_addr = cfg
        .effective_http_addr()
        .parse::<SocketAddr>()
        .with_context(|| format!("bind_http_addr không hợp lệ: {}", cfg.effective_http_addr()))?;
    let https_addr = cfg
        .effective_https_addr()
        .parse::<SocketAddr>()
        .with_context(|| {
            format!(
                "bind_https_addr không hợp lệ: {}",
                cfg.effective_https_addr()
            )
        })?;
    cfg.bind_udp_addr
        .parse::<SocketAddr>()
        .with_context(|| format!("bind_udp_addr không hợp lệ: {}", cfg.bind_udp_addr))?;

    // Xác thực toàn bộ cặp chứng chỉ TLS trong sites/*.toml bằng rustls
    let _ = build_sni_cert_map(&cfg)?;

    let site_count = cfg
        .vhosts
        .iter()
        .filter(|v| v.server_name != "_")
        .count();

    Ok((site_count, http_addr.to_string(), https_addr.to_string()))
}

fn main() -> Result<()> {
    // 1. Khởi tạo CryptoProvider ring mặc định cho rustls 0.23 ngay từ đầu (phục vụ cả --check-config)
    let _ = rustls::crypto::ring::default_provider().install_default();

    let opts = parse_startup_options();

    if opts.test_only {
        match validate_configuration_for_cli(&opts.config_path) {
            Ok((site_count, http_bind, https_bind)) => {
                println!(
                    "ferrousx: configuration valid ({} site(s) loaded, http={}, https={})",
                    site_count, http_bind, https_bind
                );
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
                    "ferrousx: configuration check failed: {err:#} (file: {})",
                    opts.config_path.display()
                );
                std::process::exit(1);
            }
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ferrousx=info".into()),
        )
        .with_target(false)
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "Khởi động FerrousX Engine — Triple-Stack Pure-Rust Web Server & Reverse Proxy (Ferrous-Panel v2.5.0 Sync)"
    );

    // 2. Nạp cấu hình ban đầu vào bộ quản lý Lock-Free ArcSwap
    let config_mgr = if opts.config_path.exists() {
        info!(path = %opts.config_path.display(), "Đang nạp cấu hình máy chủ");
        ConfigManager::from_file(&opts.config_path)?
    } else if opts.explicit_config {
        anyhow::bail!(
            "Không tìm thấy tệp cấu hình tại {}",
            opts.config_path.display()
        );
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

    // 4. Khởi tạo cấu hình bảo mật TLS 1.3/1.2 (Dynamic SNI + ALPN h2,http/1.1) & QUIC (:443)
    let (tls_acceptor, quinn_server_cfg, sni_resolver) =
        build_tls_and_quic_configs(&config_mgr)?;

    // 5. Khởi chạy Control-Plane lắng nghe SIGHUP & File Watcher (sites/*.toml + panel.env + admin.json + ferrousx.toml)
    spawn_signal_reload_watcher(Arc::clone(&config_mgr), Arc::clone(&sni_resolver));
    spawn_config_file_watcher(Arc::clone(&config_mgr), Arc::clone(&sni_resolver));

    // 6. Khởi chạy Panel Control Server (Unix Socket + Embedded Rust Web Dashboard)
    let panel_server = Arc::new(ferrousx_panel::api::PanelServer::new(Arc::clone(
        &config_mgr,
    )));
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
            if let Ok(addr) =
                std::os::unix::net::SocketAddr::from_abstract_name(abstract_name.as_bytes())
            {
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

/// Luồng nền lắng nghe tín hiệu SIGHUP để kích hoạt ArcSwap Hot-Reload + Dynamic SNI Cert Swap
fn spawn_signal_reload_watcher(
    config_mgr: Arc<ConfigManager>,
    sni_resolver: Arc<DynamicSniResolver>,
) {
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
                        info!("Nhận tín hiệu SIGHUP -> Đồng bộ lại ferrousx.toml + sites/*.toml + panel.env + admin.json...");
                        match config_mgr.reload_from_disk() {
                            Ok(new_epoch) => {
                                let cfg = config_mgr.current();
                                sni_resolver.swap_from_config(&cfg);
                                info!(
                                    epoch = new_epoch,
                                    vhosts = cfg.vhosts.len(),
                                    "Hot-reload hoàn tất (cấu hình + chứng chỉ SNI) với 0 kết nối bị ngắt"
                                );
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

/// Theo dõi thay đổi trực tiếp trên tệp cấu hình chính, `/etc/ferrousx/sites/*.toml`,
/// `/etc/ferrous-panel/panel.env`, `/etc/ferrous-panel/admin.json`,
/// và thư mục vhost `/www/server/panel/vhost/ferrousx/` để tự động nạp lại không cần khởi động lại service.
fn spawn_config_file_watcher(
    config_mgr: Arc<ConfigManager>,
    sni_resolver: Arc<DynamicSniResolver>,
) {
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
            let sites_dir = cfg.sites_dir.clone();
            let panel_env_path = cfg.panel_env_path.clone();
            let admin_json_path = cfg.panel_admin_json_path.clone();
            let vhost_dir = cfg.vhost_conf_dir.clone();

            let mut watch_dirs: Vec<PathBuf> = Vec::new();
            if let Some(parent) = main_cfg_path.parent() {
                if parent.exists() {
                    watch_dirs.push(parent.to_path_buf());
                }
            }
            if sites_dir.exists() && !watch_dirs.contains(&sites_dir) {
                watch_dirs.push(sites_dir.clone());
            }
            if let Some(parent) = panel_env_path.parent() {
                if parent.exists() && !watch_dirs.contains(&parent.to_path_buf()) {
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
                            let ext = p.extension().and_then(|e| e.to_str());
                            p == &main_cfg_path
                                || p == &panel_env_path
                                || p == &admin_json_path
                                || ext == Some("toml")
                                || ext == Some("conf")
                                || ext == Some("env")
                        });
                        if !is_target_file {
                            continue;
                        }

                        if last_reload.elapsed() < Duration::from_millis(200) {
                            continue;
                        }
                        last_reload = Instant::now();

                        // Đợi nhẹ để quá trình ghi atomic của Ferrous-Panel hoàn tất
                        std::thread::sleep(Duration::from_millis(60));
                        match config_mgr.reload_from_disk() {
                            Ok(epoch) => {
                                let current_cfg = config_mgr.current();
                                sni_resolver.swap_from_config(&current_cfg);
                                info!(epoch, "Tự động đồng bộ cấu hình & chứng chỉ SNI mới từ thay đổi tệp tin");
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

/// Khởi tạo bộ cấu hình TLS 1.3/1.2 (Dynamic SNI cho TCP ALPN h2,http/1.1) và Quinn ServerConfig (cho UDP H3/QUIC)
fn build_tls_and_quic_configs(
    config_mgr: &Arc<ConfigManager>,
) -> Result<(
    tokio_rustls::TlsAcceptor,
    quinn::ServerConfig,
    Arc<DynamicSniResolver>,
)> {
    let cfg = config_mgr.current();
    let fallback_cert = load_certified_key(&cfg.tls.cert_chain_path, &cfg.tls.private_key_path)?;
    let initial_sni_map = build_sni_cert_map(&cfg)?;

    let sni_resolver = Arc::new(DynamicSniResolver::new(initial_sni_map, fallback_cert));

    // 1. Cấu hình TLS 1.3/1.2 cho TCP (HTTP/2 & HTTP/1.1 — Dynamic SNI + Cloudflare SSL Full tương thích)
    let mut tcp_tls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::clone(&sni_resolver) as Arc<dyn ResolvesServerCert>);
    tcp_tls_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tcp_tls_cfg));

    // 2. Cấu hình TLS 1.3 + QUIC Transport cho UDP (HTTP/3 — Dynamic SNI)
    let mut quic_tls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::clone(&sni_resolver) as Arc<dyn ResolvesServerCert>);
    quic_tls_cfg.alpn_protocols = vec![b"h3".to_vec()];
    quic_tls_cfg.max_early_data_size = if cfg.tls.enable_zero_rtt { u32::MAX } else { 0 };

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(quic_tls_cfg)?;
    let mut quinn_server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.initial_mtu(cfg.tls.quic_initial_mtu);
    quinn_server_cfg.transport_config(Arc::new(transport));

    Ok((tls_acceptor, quinn_server_cfg, sni_resolver))
}
