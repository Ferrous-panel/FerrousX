//! crates/ferrousx-config/src/config.rs
//! Engine quản lý cấu hình động, đồng bộ tự động từ `/etc/ferrous-panel/admin.json`
//! và `/www/server/panel/vhost/ferrousx/*.conf`, Lock-Free Hot-Reload với ArcSwap
//! và cơ chế chuyển tiếp Socket File Descriptor (SCM_RIGHTS) qua Unix Domain Socket.

use std::collections::HashMap;
use std::fs;
use std::io::{IoSlice, IoSliceMut};
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::{ArcSwap, Guard};
use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Không thể đọc file cấu hình tại {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Lỗi cú pháp cấu hình TOML: {0}")]
    TomlParse(#[from] toml::de::Error),
    #[error("Cấu hình không hợp lệ: {0}")]
    Validation(String),
    #[error("Lỗi chuyển giao File Descriptor qua Unix Socket: {0}")]
    FdTransfer(#[from] nix::Error),
}

fn default_bind_http_addr() -> String {
    "0.0.0.0:80".to_string()
}

fn default_bind_https_addr() -> String {
    "0.0.0.0:443".to_string()
}

fn default_bind_udp_addr() -> String {
    "0.0.0.0:443".to_string()
}

fn default_panel_control_socket() -> PathBuf {
    PathBuf::from("/run/ferrousx/panel-admin.sock")
}

fn default_panel_admin_json() -> PathBuf {
    PathBuf::from("/etc/ferrous-panel/admin.json")
}

fn default_vhost_conf_dir() -> PathBuf {
    PathBuf::from("/www/server/panel/vhost/ferrousx")
}

fn default_phpmyadmin_upstream() -> String {
    "127.0.0.1:888".to_string()
}

fn default_uring_entries() -> u32 {
    4096
}

fn default_arena_capacity_bytes() -> usize {
    64 * 1024
}

fn default_alt_svc_max_age() -> u32 {
    86400
}

fn default_client_max_body_size() -> usize {
    100 * 1024 * 1024
}

fn default_client_header_timeout_ms() -> u64 {
    5000
}

fn default_client_body_timeout_ms() -> u64 {
    15000
}

fn default_proxy_connect_timeout_ms() -> u64 {
    3000
}

fn default_proxy_read_timeout_ms() -> u64 {
    60000
}

fn default_circuit_breaker_max_fails() -> usize {
    5
}

fn default_circuit_breaker_cooldown_ms() -> u64 {
    5000
}

/// Cấu hình quản trị đọc động từ `/etc/ferrous-panel/admin.json`
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PanelAdminConfig {
    pub custom_domain: String,
    pub panel_port: u16,
    pub security_entrance: String,
    #[serde(alias = "panel_ip", alias = "bindAddress")]
    pub panel_host: String,
}

impl PanelAdminConfig {
    pub fn load_from_path(path: &Path) -> Self {
        if !path.exists() {
            return Self {
                custom_domain: String::new(),
                panel_port: 8888,
                security_entrance: String::new(),
                panel_host: "127.0.0.1".to_string(),
            };
        }

        match fs::read_to_string(path) {
            Ok(raw) => match serde_json::from_str::<PanelAdminConfig>(&raw) {
                Ok(mut parsed) => {
                    if parsed.panel_port == 0 {
                        parsed.panel_port = 8888;
                    }
                    if parsed.panel_host.trim().is_empty() {
                        parsed.panel_host = "127.0.0.1".to_string();
                    }
                    parsed.custom_domain = parsed.custom_domain.trim().to_string();
                    parsed.security_entrance = parsed.security_entrance.trim().to_string();
                    parsed
                }
                Err(err) => {
                    warn!(path = %path.display(), error = %err, "Không thể phân tích JSON của admin.json, dùng mặc định an toàn");
                    Self {
                        custom_domain: String::new(),
                        panel_port: 8888,
                        security_entrance: String::new(),
                        panel_host: "127.0.0.1".to_string(),
                    }
                }
            },
            Err(err) => {
                warn!(path = %path.display(), error = %err, "Không thể đọc admin.json");
                Self {
                    custom_domain: String::new(),
                    panel_port: 8888,
                    security_entrance: String::new(),
                    panel_host: "127.0.0.1".to_string(),
                }
            }
        }
    }

    pub fn panel_upstream_addr(&self) -> String {
        let host = if self.panel_host.trim().is_empty() {
            "127.0.0.1"
        } else {
            self.panel_host.trim()
        };
        let port = if self.panel_port == 0 { 8888 } else { self.panel_port };
        format!("{host}:{port}")
    }
}

/// Cấu hình tổng thể của nút máy chủ FerrousX
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_version_epoch")]
    pub version_epoch: u64,
    #[serde(default)]
    pub worker_threads: usize, // 0 = Tự động phát hiện số lõi vật lý (Thread-Per-Core)
    #[serde(default = "default_bind_http_addr")]
    pub bind_http_addr: String, // VD: "0.0.0.0:80" (HTTP/1.1 & H2C)
    #[serde(default = "default_bind_https_addr")]
    pub bind_https_addr: String, // VD: "0.0.0.0:443" (TCP TLS 1.3/1.2)
    #[serde(default)]
    pub bind_tcp_addr: Option<String>, // Tương thích ngược với cấu hình cũ
    #[serde(default = "default_bind_udp_addr")]
    pub bind_udp_addr: String, // VD: "0.0.0.0:443" (QUIC / HTTP/3)
    #[serde(default = "default_panel_control_socket")]
    pub panel_control_socket: PathBuf,
    #[serde(default = "default_panel_admin_json")]
    pub panel_admin_json_path: PathBuf,
    #[serde(default = "default_vhost_conf_dir")]
    pub vhost_conf_dir: PathBuf,
    #[serde(default = "default_phpmyadmin_upstream")]
    pub phpmyadmin_upstream: String,
    #[serde(default = "default_uring_entries")]
    pub uring_entries: u32,
    #[serde(default)]
    pub sqpoll_idle_ms: Option<u32>,
    #[serde(default = "default_arena_capacity_bytes")]
    pub arena_capacity_bytes: usize,
    #[serde(default = "default_alt_svc_max_age")]
    pub alt_svc_max_age: u32,
    #[serde(default = "default_client_max_body_size")]
    pub client_max_body_size: usize,
    #[serde(default = "default_client_header_timeout_ms")]
    pub client_header_timeout_ms: u64,
    #[serde(default = "default_client_body_timeout_ms")]
    pub client_body_timeout_ms: u64,
    #[serde(default = "default_proxy_connect_timeout_ms")]
    pub proxy_connect_timeout_ms: u64,
    #[serde(default = "default_proxy_read_timeout_ms")]
    pub proxy_read_timeout_ms: u64,
    #[serde(default = "default_circuit_breaker_max_fails")]
    pub circuit_breaker_max_fails: usize,
    #[serde(default = "default_circuit_breaker_cooldown_ms")]
    pub circuit_breaker_cooldown_ms: u64,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub vhosts: Vec<VirtualHost>,
    #[serde(default)]
    pub upstreams: HashMap<String, UpstreamPool>,
    #[serde(skip)]
    pub panel_admin: PanelAdminConfig,
}

fn default_version_epoch() -> u64 {
    1
}

/// Cấu hình chứng chỉ TLS 1.3 & QUIC Transport
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    pub cert_chain_path: PathBuf,
    pub private_key_path: PathBuf,
    pub enable_zero_rtt: bool,
    pub alpn_protocols: Vec<String>,
    pub quic_max_idle_timeout_ms: u64,
    pub quic_initial_mtu: u16,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_chain_path: PathBuf::from("/etc/ferrousx/ssl/fullchain.pem"),
            private_key_path: PathBuf::from("/etc/ferrousx/ssl/privkey.pem"),
            enable_zero_rtt: true,
            alpn_protocols: vec!["h3".into(), "h2".into(), "http/1.1".into()],
            quic_max_idle_timeout_ms: 30_000,
            quic_initial_mtu: 1350,
        }
    }
}

fn default_try_files() -> Vec<String> {
    vec![
        "$uri".to_string(),
        "$uri/".to_string(),
        "/index.php?$query_string".to_string(),
    ]
}

fn default_index_files() -> Vec<String> {
    vec!["index.php".to_string(), "index.html".to_string()]
}

/// Cấu hình từng miền ảo (VirtualHost)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualHost {
    pub server_name: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub root_dir: Option<PathBuf>,
    #[serde(default = "default_true")]
    pub enable_http3_alt_svc: bool,
    #[serde(default = "default_try_files")]
    pub try_files: Vec<String>,
    #[serde(default = "default_index_files")]
    pub index_files: Vec<String>,
    #[serde(default)]
    pub compression: CompressionConfig,
    #[serde(default)]
    pub routes: Vec<RouteRule>,
    #[serde(default)]
    pub php_fpm_socket: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CompressionConfig {
    pub enable_zstd: bool,
    pub enable_brotli: bool,
    pub min_length_bytes: usize,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enable_zstd: true,
            enable_brotli: true,
            min_length_bytes: 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteRule {
    pub path_prefix: String,
    #[serde(default)]
    pub target_upstream: Option<String>,
    pub backend_protocol: BackendProtocol,
    #[serde(default)]
    pub strip_prefix: bool,
    #[serde(default)]
    pub inject_headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendProtocol {
    StaticFile,
    Http1,
    GrpcH2,
    FastCgi,
    WebSocket,
}

/// Cụm máy chủ đích (Upstream Pool) và thuật toán cân bằng tải
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamPool {
    #[serde(default = "default_lb_algo")]
    pub algorithm: LoadBalanceAlgorithm,
    #[serde(default = "default_health_interval")]
    pub health_check_interval_ms: u64,
    #[serde(default = "default_keepalive_pool")]
    pub keepalive_pool_size: usize,
    #[serde(default)]
    pub endpoints: Vec<UpstreamEndpoint>,
}

fn default_lb_algo() -> LoadBalanceAlgorithm {
    LoadBalanceAlgorithm::PowerOfTwoChoices
}
fn default_health_interval() -> u64 {
    2000
}
fn default_keepalive_pool() -> usize {
    256
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceAlgorithm {
    RoundRobin,
    PowerOfTwoChoices,
    MaglevConsistentHash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamEndpoint {
    pub address: String,
    #[serde(default = "default_weight")]
    pub weight: u16,
    #[serde(default = "default_max_conns")]
    pub max_conns: u32,
}

fn default_weight() -> u16 {
    100
}
fn default_max_conns() -> u32 {
    10_000
}

impl ServerConfig {
    /// Trả về địa chỉ TCP HTTP (:80) và TCP HTTPS (:443) hiệu lực
    pub fn effective_http_addr(&self) -> &str {
        if !self.bind_http_addr.trim().is_empty() {
            &self.bind_http_addr
        } else {
            "0.0.0.0:80"
        }
    }

    pub fn effective_https_addr(&self) -> &str {
        if !self.bind_https_addr.trim().is_empty() {
            &self.bind_https_addr
        } else if let Some(ref legacy) = self.bind_tcp_addr {
            if legacy.ends_with(":443") || legacy.ends_with(":8443") {
                return legacy;
            }
            "0.0.0.0:443"
        } else {
            "0.0.0.0:443"
        }
    }

    pub fn https_port(&self) -> u16 {
        self.effective_https_addr()
            .rsplit(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(443)
    }
}

/// Quản lý cấu hình toàn cục không khóa (Lock-Free) dựa trên ArcSwap
pub struct ConfigManager {
    config_path: PathBuf,
    active_config: ArcSwap<ServerConfig>,
}

impl ConfigManager {
    /// Khởi tạo ConfigManager từ đường dẫn file cấu hình
    pub fn from_file(path: impl AsRef<Path>) -> Result<Arc<Self>, ConfigError> {
        let config_path = path.as_ref().to_path_buf();
        let initial_cfg = Self::load_and_validate(&config_path, 1)?;

        Ok(Arc::new(Self {
            config_path,
            active_config: ArcSwap::from_pointee(initial_cfg),
        }))
    }

    /// Khởi tạo cấu hình mặc định phục vụ chạy ngay trên VPS kể cả khi chưa có file toml
    pub fn default_production_demo() -> Arc<Self> {
        let admin_path = default_panel_admin_json();
        let panel_admin = PanelAdminConfig::load_from_path(&admin_path);

        let mut cfg = ServerConfig {
            version_epoch: 1,
            worker_threads: 0,
            bind_http_addr: default_bind_http_addr(),
            bind_https_addr: default_bind_https_addr(),
            bind_tcp_addr: None,
            bind_udp_addr: default_bind_udp_addr(),
            panel_control_socket: default_panel_control_socket(),
            panel_admin_json_path: admin_path,
            vhost_conf_dir: default_vhost_conf_dir(),
            phpmyadmin_upstream: default_phpmyadmin_upstream(),
            uring_entries: default_uring_entries(),
            sqpoll_idle_ms: Some(2000),
            arena_capacity_bytes: default_arena_capacity_bytes(),
            alt_svc_max_age: default_alt_svc_max_age(),
            client_max_body_size: default_client_max_body_size(),
            client_header_timeout_ms: default_client_header_timeout_ms(),
            client_body_timeout_ms: default_client_body_timeout_ms(),
            proxy_connect_timeout_ms: default_proxy_connect_timeout_ms(),
            proxy_read_timeout_ms: default_proxy_read_timeout_ms(),
            circuit_breaker_max_fails: default_circuit_breaker_max_fails(),
            circuit_breaker_cooldown_ms: default_circuit_breaker_cooldown_ms(),
            tls: TlsConfig::default(),
            vhosts: vec![VirtualHost {
                server_name: "_".into(),
                aliases: vec![],
                root_dir: Some(PathBuf::from("/var/www/html")),
                enable_http3_alt_svc: true,
                try_files: default_try_files(),
                index_files: default_index_files(),
                compression: CompressionConfig::default(),
                routes: vec![],
                php_fpm_socket: None,
            }],
            upstreams: HashMap::new(),
            panel_admin,
        };

        Self::merge_panel_vhosts(&mut cfg);

        Arc::new(Self {
            config_path: PathBuf::from("/etc/ferrousx/ferrousx.toml"),
            active_config: ArcSwap::from_pointee(cfg),
        })
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    #[inline(always)]
    pub fn current(&self) -> Guard<Arc<ServerConfig>> {
        self.active_config.load()
    }

    pub fn current_epoch(&self) -> u64 {
        self.active_config.load().version_epoch
    }

    /// API dành riêng cho Ferrous Panel: Thêm hoặc cập nhật nóng 1 VirtualHost (< 50µs)
    pub fn upsert_vhost_from_panel(&self, vhost: VirtualHost) -> u64 {
        let mut cloned: ServerConfig = (**self.active_config.load()).clone();
        cloned.version_epoch += 1;
        if let Some(existing) = cloned
            .vhosts
            .iter_mut()
            .find(|v| v.server_name == vhost.server_name)
        {
            *existing = vhost;
        } else {
            cloned.vhosts.push(vhost);
        }
        let next_epoch = cloned.version_epoch;
        self.active_config.store(Arc::new(cloned));
        next_epoch
    }

    /// Thực thi Graceful Hot-Reload khi nhận tín hiệu SIGHUP hoặc file watcher thay đổi.
    /// Tự động đồng bộ lại `ferrousx.toml`, `/etc/ferrous-panel/admin.json`, và `/www/server/panel/vhost/ferrousx/*.conf`.
    pub fn reload_from_disk(&self) -> Result<u64, ConfigError> {
        let prev_epoch = self.active_config.load().version_epoch;
        let next_epoch = prev_epoch + 1;

        let new_cfg = if self.config_path.exists() {
            Self::load_and_validate(&self.config_path, next_epoch)?
        } else {
            let mut fallback = (**self.active_config.load()).clone();
            fallback.version_epoch = next_epoch;
            fallback.panel_admin = PanelAdminConfig::load_from_path(&fallback.panel_admin_json_path);
            Self::merge_panel_vhosts(&mut fallback);
            fallback
        };

        self.active_config.store(Arc::new(new_cfg));

        info!(
            epoch = next_epoch,
            path = %self.config_path.display(),
            "Hoàn tất hoán đổi nguyên tử ArcSwap cấu hình mới + admin.json + vhosts (Zero-Downtime)"
        );
        Ok(next_epoch)
    }

    pub fn load_and_validate(path: &Path, epoch: u64) -> Result<ServerConfig, ConfigError> {
        let raw = fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;

        let mut cfg: ServerConfig = toml::from_str(&raw)?;
        cfg.version_epoch = epoch;

        if cfg.uring_entries < 128 || !cfg.uring_entries.is_power_of_two() {
            return Err(ConfigError::Validation(
                "uring_entries phải là lũy thừa của 2 và >= 128".into(),
            ));
        }

        // Nạp đồng bộ cấu hình từ /etc/ferrous-panel/admin.json
        cfg.panel_admin = PanelAdminConfig::load_from_path(&cfg.panel_admin_json_path);

        // Quét và hợp nhất toàn bộ tệp vhost trong /www/server/panel/vhost/ferrousx/*.conf
        Self::merge_panel_vhosts(&mut cfg);

        if cfg.vhosts.is_empty() {
            cfg.vhosts.push(VirtualHost {
                server_name: "_".into(),
                aliases: vec![],
                root_dir: Some(PathBuf::from("/var/www/html")),
                enable_http3_alt_svc: true,
                try_files: default_try_files(),
                index_files: default_index_files(),
                compression: CompressionConfig::default(),
                routes: vec![],
                php_fpm_socket: None,
            });
        }
        Ok(cfg)
    }

    /// Đọc các file *.conf trong thư mục vhost của Panel (hỗ trợ cả TOML và cú pháp tương tự Nginx)
    fn merge_panel_vhosts(cfg: &mut ServerConfig) {
        let dir = &cfg.vhost_conf_dir;
        if !dir.is_dir() {
            return;
        }

        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };

        let mut paths: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("conf"))
            .collect();
        paths.sort();

        for conf_path in paths {
            let Ok(content) = fs::read_to_string(&conf_path) else {
                continue;
            };

            // 1. Thử phân tích như bảng TOML VirtualHost hoặc TOML có [[vhosts]]
            #[derive(Deserialize)]
            struct VhostFileWrapper {
                #[serde(default)]
                vhosts: Vec<VirtualHost>,
            }
            if let Ok(wrapper) = toml::from_str::<VhostFileWrapper>(&content) {
                if !wrapper.vhosts.is_empty() {
                    for vh in wrapper.vhosts {
                        Self::upsert_vhost_vec(&mut cfg.vhosts, vh);
                    }
                    continue;
                }
            }
            if let Ok(vh) = toml::from_str::<VirtualHost>(&content) {
                Self::upsert_vhost_vec(&mut cfg.vhosts, vh);
                continue;
            }

            // 2. Phân tích cú pháp block server { server_name ...; root ...; fastcgi_pass ...; proxy_pass ...; }
            if let Some(vh) = Self::parse_nginx_style_vhost(&content) {
                Self::upsert_vhost_vec(&mut cfg.vhosts, vh);
            }
        }
    }

    fn upsert_vhost_vec(vhosts: &mut Vec<VirtualHost>, vhost: VirtualHost) {
        if let Some(existing) = vhosts.iter_mut().find(|v| v.server_name == vhost.server_name) {
            *existing = vhost;
        } else {
            vhosts.push(vhost);
        }
    }

    fn parse_nginx_style_vhost(content: &str) -> Option<VirtualHost> {
        let mut server_names: Vec<String> = Vec::new();
        let mut root_dir: Option<PathBuf> = None;
        let mut php_fpm_socket: Option<String> = None;
        let mut proxy_pass: Option<String> = None;

        for raw_line in content.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim().trim_end_matches(';').trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            match parts[0] {
                "server_name" => {
                    for name in &parts[1..] {
                        if !name.is_empty() {
                            server_names.push((*name).to_string());
                        }
                    }
                }
                "root" => {
                    root_dir = Some(PathBuf::from(parts[1]));
                }
                "fastcgi_pass" => {
                    php_fpm_socket = Some(parts[1].to_string());
                }
                "proxy_pass" => {
                    proxy_pass = Some(parts[1].to_string());
                }
                _ => {}
            }
        }

        if server_names.is_empty() {
            return None;
        }

        let primary = server_names[0].clone();
        let aliases = server_names.into_iter().skip(1).collect();
        let mut routes = Vec::new();
        if let Some(target) = proxy_pass {
            routes.push(RouteRule {
                path_prefix: "/".to_string(),
                target_upstream: Some(target),
                backend_protocol: BackendProtocol::Http1,
                strip_prefix: false,
                inject_headers: HashMap::new(),
            });
        }

        Some(VirtualHost {
            server_name: primary,
            aliases,
            root_dir,
            enable_http3_alt_svc: true,
            try_files: default_try_files(),
            index_files: default_index_files(),
            compression: CompressionConfig::default(),
            routes,
            php_fpm_socket,
        })
    }
}

/// Cơ chế Zero-Downtime Binary Upgrade:
/// Truyền danh sách các Listening Socket File Descriptors từ tiến trình cũ sang tiến trình mới
/// thông qua Unix Domain Socket sử dụng Ancillary Data (SCM_RIGHTS).
pub fn send_listening_fds(uds_stream: &UnixStream, fds: &[RawFd]) -> Result<(), ConfigError> {
    use std::os::unix::io::AsRawFd;
    let payload = b"FERROUSX_FD_HANDOFF_V1";
    let iov = [IoSlice::new(payload)];
    let cmsg = [ControlMessage::ScmRights(fds)];

    sendmsg::<()>(
        uds_stream.as_raw_fd(),
        &iov,
        &cmsg,
        MsgFlags::empty(),
        None,
    )?;
    info!(count = fds.len(), "Đã chuyển giao thành công các socket FD qua SCM_RIGHTS");
    Ok(())
}

/// Nhận lại các Listening Socket File Descriptors ở tiến trình FerrousX mới
pub fn recv_listening_fds(uds_stream: &UnixStream, max_fds: usize) -> Result<Vec<RawFd>, ConfigError> {
    use std::os::unix::io::AsRawFd;
    let mut buf = [0u8; 64];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsg_space = nix::cmsg_space!([RawFd; 32]);

    let msg = recvmsg::<()>(
        uds_stream.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_space),
        MsgFlags::empty(),
    )?;

    let mut received_fds = Vec::with_capacity(max_fds);
    if let Ok(cmsgs) = msg.cmsgs() {
        for cmsg in cmsgs {
            if let ControlMessageOwned::ScmRights(fds) = cmsg {
                received_fds.extend(fds);
            }
        }
    }

    if received_fds.is_empty() {
        warn!("Không nhận được bất kỳ File Descriptor nào từ tiến trình tiền nhiệm");
    }
    Ok(received_fds)
}
