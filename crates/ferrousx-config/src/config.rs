//! crates/ferrousx-config/src/config.rs
//! Engine quản lý cấu hình động, đồng bộ 100% với Ferrous-Panel v2.5.0 (Pure Rust):
//! - Đọc master config `/etc/ferrousx/ferrousx.toml` (hỗ trợ cả `bind_http`/`bind_https` của Ferrous-Panel
//!   và `bind_http_addr`/`bind_https_addr`/`bind_udp_addr` của kiến trúc Triple-Stack).
//! - Tự động nạp và xác thực nghiêm ngặt toàn bộ `/etc/ferrousx/sites/*.toml` (schema chuẩn `FerrousxEngine`
//!   của Ferrous-Panel: `domain`, `server_names`, `root`, `[acme]`, `[ssl]`, `[handler]` với
//!   `static_spa`, `reverse_proxy`, `php_fpm`, `redirect_https`).
//! - Tự động đồng bộ cấu hình Panel từ `/etc/ferrous-panel/panel.env` (`FERROUS_BIND`, `FERROUS_PORT`,
//!   `FERROUS_SECURITY_ENTRANCE`, `FERROUS_CUSTOM_DOMAIN`) và `/etc/ferrous-panel/admin.json`.
//! - Quét tương thích ngược `/www/server/panel/vhost/ferrousx/*.conf`.
//! - Lock-Free Hot-Reload với `ArcSwap` và chuyển giao Socket FD (`SCM_RIGHTS`).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{IoSlice, IoSliceMut};
use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use arc_swap::{ArcSwap, Guard};
use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};

pub const DEFAULT_MASTER_CONFIG: &str = "/etc/ferrousx/ferrousx.toml";
pub const DEFAULT_SITES_DIR: &str = "/etc/ferrousx/sites";
pub const DEFAULT_ACME_WEBROOT: &str = "/www/acme";
pub const DEFAULT_PANEL_ENV: &str = "/etc/ferrous-panel/panel.env";
pub const DEFAULT_PANEL_ADMIN_JSON: &str = "/etc/ferrous-panel/admin.json";

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

fn default_sites_dir() -> PathBuf {
    PathBuf::from(DEFAULT_SITES_DIR)
}

fn default_acme_webroot() -> PathBuf {
    PathBuf::from(DEFAULT_ACME_WEBROOT)
}

fn default_acme_challenge_prefix() -> String {
    "/.well-known/acme-challenge/".to_string()
}

fn default_panel_control_socket() -> PathBuf {
    PathBuf::from("/run/ferrousx/panel-admin.sock")
}

fn default_panel_env_path() -> PathBuf {
    PathBuf::from(DEFAULT_PANEL_ENV)
}

fn default_panel_admin_json() -> PathBuf {
    PathBuf::from(DEFAULT_PANEL_ADMIN_JSON)
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

fn default_max_header_bytes() -> usize {
    16 * 1024
}

fn default_client_max_body_size() -> usize {
    100 * 1024 * 1024
}

fn default_client_header_timeout_ms() -> u64 {
    10_000
}

fn default_client_body_timeout_ms() -> u64 {
    15_000
}

fn default_proxy_connect_timeout_ms() -> u64 {
    5_000
}

fn default_proxy_read_timeout_ms() -> u64 {
    30_000
}

fn default_circuit_breaker_max_fails() -> usize {
    5
}

fn default_circuit_breaker_cooldown_ms() -> u64 {
    5000
}

// ============================================================================
// Cấu hình đồng bộ Ferrous-Panel (/etc/ferrous-panel/panel.env & admin.json)
// ============================================================================

/// Cấu hình quản trị đọc động từ `/etc/ferrous-panel/panel.env` (Ferrous-Panel v2.5.0 Rust)
/// và `/etc/ferrous-panel/admin.json`
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PanelAdminConfig {
    pub custom_domain: String,
    pub panel_port: u16,
    pub security_entrance: String,
    #[serde(alias = "panel_ip", alias = "bindAddress")]
    pub panel_host: String,
    pub data_dir: String,
    pub wwwroot: String,
}

impl PanelAdminConfig {
    /// Nạp đồng bộ cấu hình từ cả `/etc/ferrous-panel/panel.env` (ưu tiên chuẩn Ferrous-Panel v2.5.0)
    /// và `/etc/ferrous-panel/admin.json`.
    pub fn load_from_paths(env_path: &Path, json_path: &Path) -> Self {
        let mut cfg = Self {
            custom_domain: String::new(),
            panel_port: 8443,
            security_entrance: "/panel".to_string(),
            panel_host: "127.0.0.1".to_string(),
            data_dir: "/var/lib/ferrous-panel".to_string(),
            wwwroot: "/www/wwwroot".to_string(),
        };

        // 1. Đọc /etc/ferrous-panel/admin.json nếu tồn tại
        if json_path.exists() {
            if let Ok(raw) = fs::read_to_string(json_path) {
                if let Ok(parsed) = serde_json::from_str::<PanelAdminConfig>(&raw) {
                    if !parsed.custom_domain.trim().is_empty() {
                        cfg.custom_domain = parsed.custom_domain.trim().to_string();
                    }
                    if parsed.panel_port != 0 {
                        cfg.panel_port = parsed.panel_port;
                    }
                    if !parsed.security_entrance.trim().is_empty() {
                        cfg.security_entrance = parsed.security_entrance.trim().to_string();
                    }
                    if !parsed.panel_host.trim().is_empty() {
                        cfg.panel_host = parsed.panel_host.trim().to_string();
                    }
                }
            }
        }

        // 2. Đọc /etc/ferrous-panel/panel.env (Ferrous-Panel v2.5.0 Actix-Web Control Plane)
        if env_path.exists() {
            if let Ok(raw) = fs::read_to_string(env_path) {
                for line in raw.lines() {
                    let trimmed = line.split('#').next().unwrap_or("").trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let Some((k, v)) = trimmed.split_once('=') else {
                        continue;
                    };
                    let key = k.trim();
                    let val = v.trim().trim_matches('"').trim_matches('\'').trim();
                    match key {
                        "FERROUS_BIND" if !val.is_empty() => {
                            cfg.panel_host = if val == "0.0.0.0" {
                                "127.0.0.1".to_string()
                            } else {
                                val.to_string()
                            };
                        }
                        "FERROUS_PORT" => {
                            if let Ok(port) = val.parse::<u16>() {
                                if port != 0 {
                                    cfg.panel_port = port;
                                }
                            }
                        }
                        "FERROUS_SECURITY_ENTRANCE" if !val.is_empty() => {
                            cfg.security_entrance = if val.starts_with('/') {
                                val.to_string()
                            } else {
                                format!("/{val}")
                            };
                        }
                        "FERROUS_CUSTOM_DOMAIN" | "CUSTOM_DOMAIN" if !val.is_empty() => {
                            cfg.custom_domain = val.to_string();
                        }
                        "FERROUS_DATA_DIR" if !val.is_empty() => {
                            cfg.data_dir = val.to_string();
                        }
                        "FERROUS_WWWROOT" if !val.is_empty() => {
                            cfg.wwwroot = val.to_string();
                        }
                        _ => {}
                    }
                }
            }
        }

        cfg
    }

    pub fn load_from_path(json_path: &Path) -> Self {
        Self::load_from_paths(Path::new(DEFAULT_PANEL_ENV), json_path)
    }

    pub fn panel_upstream_addr(&self) -> String {
        let host = if self.panel_host.trim().is_empty() || self.panel_host.trim() == "0.0.0.0" {
            "127.0.0.1"
        } else {
            self.panel_host.trim()
        };
        let port = if self.panel_port == 0 {
            8443
        } else {
            self.panel_port
        };
        format!("{host}:{port}")
    }
}

// ============================================================================
// Schema Site TOML chuẩn của Ferrous-Panel (`/etc/ferrousx/sites/<domain>.toml`)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteConfigToml {
    pub domain: String,
    #[serde(default)]
    pub server_names: Vec<String>,
    pub root: PathBuf,
    #[serde(default)]
    pub acme: AcmeSectionToml,
    #[serde(default)]
    pub ssl: SslSectionToml,
    pub handler: HandlerSectionToml,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AcmeSectionToml {
    pub prefix: String,
    pub webroot: PathBuf,
    pub serve_before_redirect: bool,
}

impl Default for AcmeSectionToml {
    fn default() -> Self {
        Self {
            prefix: default_acme_challenge_prefix(),
            webroot: default_acme_webroot(),
            serve_before_redirect: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SslSectionToml {
    pub enabled: bool,
    pub redirect_https: bool,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HandlerSectionToml {
    StaticSpa {
        #[serde(default = "default_index_html")]
        index_file: String,
        #[serde(default)]
        spa_fallback: bool,
    },
    ReverseProxy {
        upstream: String,
        #[serde(default = "default_true")]
        pass_host_header: bool,
        #[serde(default = "default_true")]
        forwarded_headers: bool,
    },
    PhpFpm {
        #[serde(default)]
        php_version: String,
        fastcgi_socket: PathBuf,
        #[serde(default = "default_index_php")]
        index_file: String,
    },
    RedirectHttps {
        #[serde(default = "default_redirect_status")]
        status_code: u16,
    },
}

fn default_index_html() -> String {
    "index.html".to_string()
}

fn default_index_php() -> String {
    "index.php".to_string()
}

const fn default_redirect_status() -> u16 {
    301
}

// ============================================================================
// Cấu hình tổng thể của nút máy chủ FerrousX (`ferrousx.toml`)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_version_epoch")]
    pub version_epoch: u64,
    #[serde(default)]
    pub worker_threads: usize, // 0 = Tự động phát hiện số lõi vật lý (Thread-Per-Core)
    #[serde(default = "default_bind_http_addr", alias = "bind_http")]
    pub bind_http_addr: String, // VD: "0.0.0.0:80" (HTTP/1.1 & H2C)
    #[serde(default = "default_bind_https_addr", alias = "bind_https")]
    pub bind_https_addr: String, // VD: "0.0.0.0:443" (TCP TLS 1.3/1.2)
    #[serde(default)]
    pub bind_tcp_addr: Option<String>, // Tương thích ngược với cấu hình cũ
    #[serde(default = "default_bind_udp_addr", alias = "bind_udp")]
    pub bind_udp_addr: String, // VD: "0.0.0.0:443" (QUIC / HTTP/3)
    #[serde(default = "default_sites_dir")]
    pub sites_dir: PathBuf, // "/etc/ferrousx/sites" (chuẩn Ferrous-Panel v2.5.0)
    #[serde(default = "default_acme_webroot")]
    pub acme_webroot: PathBuf, // "/www/acme"
    #[serde(default = "default_acme_challenge_prefix")]
    pub acme_challenge_prefix: String, // "/.well-known/acme-challenge/"
    #[serde(default)]
    pub server_tokens: bool,
    #[serde(default = "default_panel_control_socket")]
    pub panel_control_socket: PathBuf,
    #[serde(default = "default_panel_env_path")]
    pub panel_env_path: PathBuf,
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
    #[serde(default = "default_max_header_bytes")]
    pub max_header_bytes: usize,
    #[serde(default = "default_client_max_body_size", alias = "max_body_bytes")]
    pub client_max_body_size: usize,
    #[serde(
        default = "default_client_header_timeout_ms",
        alias = "header_read_timeout_ms"
    )]
    pub client_header_timeout_ms: u64,
    #[serde(default = "default_client_body_timeout_ms")]
    pub client_body_timeout_ms: u64,
    #[serde(
        default = "default_proxy_connect_timeout_ms",
        alias = "upstream_connect_timeout_ms"
    )]
    pub proxy_connect_timeout_ms: u64,
    #[serde(
        default = "default_proxy_read_timeout_ms",
        alias = "request_timeout_ms"
    )]
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

/// Cấu hình từng miền ảo (VirtualHost) hợp nhất giữa `sites/*.toml` và `[[vhosts]]`
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
    // --- Các trường mở rộng đồng bộ 100% với Ferrous-Panel `sites/*.toml` ---
    #[serde(default = "default_acme_challenge_prefix")]
    pub acme_prefix: String,
    #[serde(default = "default_acme_webroot")]
    pub acme_webroot: PathBuf,
    #[serde(default = "default_true")]
    pub acme_serve_before_redirect: bool,
    #[serde(default)]
    pub ssl_enabled: bool,
    #[serde(default)]
    pub redirect_https: bool,
    #[serde(default)]
    pub redirect_status_code: Option<u16>,
    #[serde(default)]
    pub ssl_cert_path: Option<PathBuf>,
    #[serde(default)]
    pub ssl_key_path: Option<PathBuf>,
    #[serde(default)]
    pub spa_fallback: bool,
    #[serde(default = "default_true")]
    pub pass_host_header: bool,
    #[serde(default = "default_true")]
    pub forwarded_headers: bool,
}

fn default_true() -> bool {
    true
}

impl VirtualHost {
    pub fn default_catch_all() -> Self {
        Self {
            server_name: "_".into(),
            aliases: vec![],
            root_dir: Some(PathBuf::from("/var/www/html")),
            enable_http3_alt_svc: true,
            try_files: default_try_files(),
            index_files: default_index_files(),
            compression: CompressionConfig::default(),
            routes: vec![],
            php_fpm_socket: None,
            acme_prefix: default_acme_challenge_prefix(),
            acme_webroot: default_acme_webroot(),
            acme_serve_before_redirect: true,
            ssl_enabled: false,
            redirect_https: false,
            redirect_status_code: None,
            ssl_cert_path: None,
            ssl_key_path: None,
            spa_fallback: false,
            pass_host_header: true,
            forwarded_headers: true,
        }
    }
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

// ============================================================================
// Hàm xác thực nghiêm ngặt tương thích `ferrousx-bin --check-config`
// ============================================================================

pub fn validate_hostname_label(raw: &str) -> Result<String, ConfigError> {
    let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(ConfigError::Validation(format!(
            "invalid hostname '{raw}': length must be 1..=253"
        )));
    }
    if !trimmed.contains('.') && trimmed != "localhost" {
        return Err(ConfigError::Validation(format!(
            "invalid hostname '{raw}': must contain a dot or be 'localhost'"
        )));
    }
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ConfigError::Validation(format!(
                "invalid hostname label in '{raw}'"
            )));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ConfigError::Validation(format!(
                "hostname label cannot start or end with '-' in '{raw}'"
            )));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(ConfigError::Validation(format!(
                "hostname contains invalid characters in '{raw}'"
            )));
        }
    }
    Ok(trimmed)
}

pub fn validate_safe_filename(raw: &str) -> Result<String, ConfigError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return Err(ConfigError::Validation(format!(
            "invalid filename '{raw}': length must be 1..=64"
        )));
    }
    if trimmed.starts_with('.') || trimmed.contains("..") {
        return Err(ConfigError::Validation(format!(
            "invalid filename '{raw}': cannot start with '.' or contain '..'"
        )));
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(ConfigError::Validation(format!(
            "invalid filename '{raw}': disallowed characters"
        )));
    }
    Ok(trimmed.to_string())
}

pub fn validate_absolute_clean_path(path: &Path, label: &str) -> Result<PathBuf, ConfigError> {
    if !path.is_absolute() {
        return Err(ConfigError::Validation(format!(
            "{label} must be an absolute path: {}",
            path.display()
        )));
    }
    let raw_str = path.to_string_lossy();
    if raw_str.contains('\0') {
        return Err(ConfigError::Validation(format!(
            "{label} contains NUL byte"
        )));
    }
    let mut normalized = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::RootDir => normalized.push(comp.as_os_str()),
            Component::Normal(seg) => normalized.push(seg),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(ConfigError::Validation(format!(
                    "{label} cannot contain '..' traversal: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(normalized)
}

pub fn validate_upstream_origin(raw: &str) -> Result<String, ConfigError> {
    let trimmed = raw.trim().trim_end_matches('/');
    let (scheme, rest) = trimmed.split_once("://").ok_or_else(|| {
        ConfigError::Validation(format!("upstream '{raw}' must include scheme http://"))
    })?;
    if !scheme.eq_ignore_ascii_case("http") {
        return Err(ConfigError::Validation(format!(
            "upstream '{raw}' scheme must be 'http'"
        )));
    }
    if rest.is_empty() || rest.contains('/') || rest.contains('?') || rest.contains('#') {
        return Err(ConfigError::Validation(format!(
            "upstream '{raw}' cannot contain paths or query strings"
        )));
    }
    if rest.bytes().any(|b| b.is_ascii_whitespace() || b == b'\0') {
        return Err(ConfigError::Validation(format!(
            "upstream '{raw}' contains illegal whitespace/NUL"
        )));
    }
    let (_host, port_str) = rest.rsplit_once(':').ok_or_else(|| {
        ConfigError::Validation(format!("upstream '{raw}' must include an explicit :port"))
    })?;
    let port: u16 = port_str.parse().map_err(|_| {
        ConfigError::Validation(format!("upstream '{raw}' has invalid port '{port_str}'"))
    })?;
    if port == 0 {
        return Err(ConfigError::Validation(format!(
            "upstream '{raw}' port cannot be 0"
        )));
    }
    Ok(rest.to_string())
}

pub fn validate_pem_cert_and_key_files(cert_path: &Path, key_path: &Path) -> Result<(), ConfigError> {
    let cert_raw = fs::read_to_string(cert_path).map_err(|e| {
        ConfigError::Validation(format!(
            "cannot open certificate file {}: {e}",
            cert_path.display()
        ))
    })?;
    if !cert_raw.contains("-----BEGIN CERTIFICATE-----") {
        return Err(ConfigError::Validation(format!(
            "certificate file contains no PEM certificates: {}",
            cert_path.display()
        )));
    }

    let key_raw = fs::read_to_string(key_path).map_err(|e| {
        ConfigError::Validation(format!(
            "cannot open private key file {}: {e}",
            key_path.display()
        ))
    })?;
    if !key_raw.contains("PRIVATE KEY-----") {
        return Err(ConfigError::Validation(format!(
            "private key file contains no supported PEM key: {}",
            key_path.display()
        )));
    }
    Ok(())
}

// ============================================================================
// Quản lý cấu hình toàn cục không khóa (Lock-Free) dựa trên ArcSwap
// ============================================================================

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
        let env_path = default_panel_env_path();
        let admin_path = default_panel_admin_json();
        let panel_admin = PanelAdminConfig::load_from_paths(&env_path, &admin_path);

        let mut cfg = ServerConfig {
            version_epoch: 1,
            worker_threads: 0,
            bind_http_addr: default_bind_http_addr(),
            bind_https_addr: default_bind_https_addr(),
            bind_tcp_addr: None,
            bind_udp_addr: default_bind_udp_addr(),
            sites_dir: default_sites_dir(),
            acme_webroot: default_acme_webroot(),
            acme_challenge_prefix: default_acme_challenge_prefix(),
            server_tokens: false,
            panel_control_socket: default_panel_control_socket(),
            panel_env_path: env_path,
            panel_admin_json_path: admin_path,
            vhost_conf_dir: default_vhost_conf_dir(),
            phpmyadmin_upstream: default_phpmyadmin_upstream(),
            uring_entries: default_uring_entries(),
            sqpoll_idle_ms: Some(2000),
            arena_capacity_bytes: default_arena_capacity_bytes(),
            alt_svc_max_age: default_alt_svc_max_age(),
            max_header_bytes: default_max_header_bytes(),
            client_max_body_size: default_client_max_body_size(),
            client_header_timeout_ms: default_client_header_timeout_ms(),
            client_body_timeout_ms: default_client_body_timeout_ms(),
            proxy_connect_timeout_ms: default_proxy_connect_timeout_ms(),
            proxy_read_timeout_ms: default_proxy_read_timeout_ms(),
            circuit_breaker_max_fails: default_circuit_breaker_max_fails(),
            circuit_breaker_cooldown_ms: default_circuit_breaker_cooldown_ms(),
            tls: TlsConfig::default(),
            vhosts: vec![VirtualHost::default_catch_all()],
            upstreams: HashMap::new(),
            panel_admin,
        };

        let _ = Self::merge_ferrous_panel_sites_dir(&mut cfg);
        Self::merge_panel_vhosts(&mut cfg);

        Arc::new(Self {
            config_path: PathBuf::from(DEFAULT_MASTER_CONFIG),
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
    /// Tự động đồng bộ lại `ferrousx.toml`, `/etc/ferrousx/sites/*.toml`, `/etc/ferrous-panel/panel.env`,
    /// `/etc/ferrous-panel/admin.json`, và `/www/server/panel/vhost/ferrousx/*.conf`.
    pub fn reload_from_disk(&self) -> Result<u64, ConfigError> {
        let prev_epoch = self.active_config.load().version_epoch;
        let next_epoch = prev_epoch + 1;

        let new_cfg = if self.config_path.exists() {
            Self::load_and_validate(&self.config_path, next_epoch)?
        } else {
            let mut fallback = (**self.active_config.load()).clone();
            fallback.version_epoch = next_epoch;
            fallback.panel_admin = PanelAdminConfig::load_from_paths(
                &fallback.panel_env_path,
                &fallback.panel_admin_json_path,
            );
            Self::merge_ferrous_panel_sites_dir(&mut fallback)?;
            Self::merge_panel_vhosts(&mut fallback);
            fallback
        };

        self.active_config.store(Arc::new(new_cfg));

        info!(
            epoch = next_epoch,
            path = %self.config_path.display(),
            "Hoàn tất hoán đổi nguyên tử ArcSwap cấu hình mới + sites/*.toml + panel.env (Zero-Downtime)"
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

        // Xác thực cổng bind và thông số timeout/size theo đúng chuẩn Ferrous-Panel
        cfg.effective_http_addr()
            .trim()
            .parse::<SocketAddr>()
            .map_err(|e| {
                ConfigError::Validation(format!(
                    "invalid bind_http '{}': {e}",
                    cfg.effective_http_addr()
                ))
            })?;
        cfg.effective_https_addr()
            .trim()
            .parse::<SocketAddr>()
            .map_err(|e| {
                ConfigError::Validation(format!(
                    "invalid bind_https '{}': {e}",
                    cfg.effective_https_addr()
                ))
            })?;
        cfg.bind_udp_addr
            .trim()
            .parse::<SocketAddr>()
            .map_err(|e| {
                ConfigError::Validation(format!("invalid bind_udp '{}': {e}", cfg.bind_udp_addr))
            })?;

        if cfg.client_header_timeout_ms == 0
            || cfg.proxy_read_timeout_ms == 0
            || cfg.proxy_connect_timeout_ms == 0
        {
            return Err(ConfigError::Validation(
                "all timeout_ms values must be greater than zero".to_string(),
            ));
        }

        if cfg.max_header_bytes < 1024 || cfg.client_max_body_size == 0 {
            return Err(ConfigError::Validation(
                "max_header_bytes must be >= 1024 and max_body_bytes > 0".to_string(),
            ));
        }

        if cfg.uring_entries < 128 || !cfg.uring_entries.is_power_of_two() {
            return Err(ConfigError::Validation(
                "uring_entries phải là lũy thừa của 2 và >= 128".into(),
            ));
        }

        cfg.sites_dir = validate_absolute_clean_path(&cfg.sites_dir, "sites_dir")?;
        cfg.acme_webroot = validate_absolute_clean_path(&cfg.acme_webroot, "acme_webroot")?;
        let acme_prefix = cfg.acme_challenge_prefix.trim().to_string();
        if !acme_prefix.starts_with('/') {
            return Err(ConfigError::Validation(
                "acme_challenge_prefix must start with '/'".to_string(),
            ));
        }
        cfg.acme_challenge_prefix = acme_prefix;

        // 1. Nạp đồng bộ cấu hình từ /etc/ferrous-panel/panel.env & admin.json
        cfg.panel_admin =
            PanelAdminConfig::load_from_paths(&cfg.panel_env_path, &cfg.panel_admin_json_path);

        // 2. Quét và xác thực nghiêm ngặt toàn bộ tệp `/etc/ferrousx/sites/*.toml` của Ferrous-Panel v2.5.0
        Self::merge_ferrous_panel_sites_dir(&mut cfg)?;

        // 3. Quét và hợp nhất toàn bộ tệp vhost trong `/www/server/panel/vhost/ferrousx/*.conf`
        Self::merge_panel_vhosts(&mut cfg);

        if cfg.vhosts.is_empty() {
            cfg.vhosts.push(VirtualHost::default_catch_all());
        }
        Ok(cfg)
    }

    /// Đọc và xác thực toàn bộ file `/etc/ferrousx/sites/*.toml` được sinh bởi `FerrousxEngine` của Ferrous-Panel
    fn merge_ferrous_panel_sites_dir(cfg: &mut ServerConfig) -> Result<(), ConfigError> {
        let dir = &cfg.sites_dir;
        if !dir.exists() {
            return Ok(());
        }

        let entries = fs::read_dir(dir).map_err(|source| ConfigError::Io {
            path: dir.clone(),
            source,
        })?;

        let mut site_files: Vec<PathBuf> = Vec::new();
        for entry_res in entries {
            let entry = entry_res.map_err(|source| ConfigError::Io {
                path: dir.clone(),
                source,
            })?;
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("toml") {
                site_files.push(path);
            }
        }
        site_files.sort();

        let mut global_seen_hosts: HashSet<String> = HashSet::new();

        for site_file in site_files {
            let raw_site = fs::read_to_string(&site_file).map_err(|source| ConfigError::Io {
                path: site_file.clone(),
                source,
            })?;
            let parsed_site: SiteConfigToml = toml::from_str(&raw_site).map_err(|err| {
                ConfigError::Validation(format!("failed to parse {}: {err}", site_file.display()))
            })?;

            let vh = Self::validate_and_convert_site_toml(
                parsed_site,
                &site_file,
                cfg,
                &mut global_seen_hosts,
            )?;
            Self::upsert_vhost_vec(&mut cfg.vhosts, vh);
        }

        Ok(())
    }

    fn validate_and_convert_site_toml(
        raw: SiteConfigToml,
        source_file: &Path,
        master: &ServerConfig,
        global_seen_hosts: &mut HashSet<String>,
    ) -> Result<VirtualHost, ConfigError> {
        let primary_domain = validate_hostname_label(&raw.domain)?;
        let mut local_seen = HashSet::new();
        let mut aliases = Vec::new();

        local_seen.insert(primary_domain.clone());
        for alias in &raw.server_names {
            let parsed_alias = validate_hostname_label(alias)?;
            if local_seen.insert(parsed_alias.clone()) {
                aliases.push(parsed_alias);
            }
        }

        // Kiểm tra trùng lặp server_name giữa các file trong sites/*.toml
        for host in std::iter::once(&primary_domain).chain(aliases.iter()) {
            if !global_seen_hosts.insert(host.clone()) {
                return Err(ConfigError::Validation(format!(
                    "duplicate server_name '{host}' declared in {}",
                    source_file.display()
                )));
            }
        }

        let root_dir = validate_absolute_clean_path(&raw.root, "site root")?;
        let acme_webroot = if raw.acme.webroot.as_os_str().is_empty() {
            master.acme_webroot.clone()
        } else {
            validate_absolute_clean_path(&raw.acme.webroot, "acme webroot")?
        };

        let acme_prefix = if raw.acme.prefix.trim().is_empty() {
            master.acme_challenge_prefix.clone()
        } else {
            let p = raw.acme.prefix.trim().to_string();
            if !p.starts_with('/') {
                return Err(ConfigError::Validation(format!(
                    "invalid acme.prefix in {}",
                    source_file.display()
                )));
            }
            p
        };

        if raw.ssl.redirect_https && !raw.ssl.enabled {
            return Err(ConfigError::Validation(format!(
                "ssl.redirect_https = true requires ssl.enabled = true in {}",
                source_file.display()
            )));
        }

        let (ssl_cert_path, ssl_key_path) = if raw.ssl.enabled {
            let cert_p = raw.ssl.cert_path.as_ref().ok_or_else(|| {
                ConfigError::Validation(format!(
                    "ssl.cert_path required when ssl.enabled = true in {}",
                    source_file.display()
                ))
            })?;
            let key_p = raw.ssl.key_path.as_ref().ok_or_else(|| {
                ConfigError::Validation(format!(
                    "ssl.key_path required when ssl.enabled = true in {}",
                    source_file.display()
                ))
            })?;
            let clean_cert = validate_absolute_clean_path(cert_p, "ssl.cert_path")?;
            let clean_key = validate_absolute_clean_path(key_p, "ssl.key_path")?;
            validate_pem_cert_and_key_files(&clean_cert, &clean_key)?;
            (Some(clean_cert), Some(clean_key))
        } else {
            (None, None)
        };

        let mut routes = Vec::new();
        let mut php_fpm_socket = None;
        let mut index_files = default_index_files();
        let mut spa_fallback = false;
        let mut pass_host_header = true;
        let mut forwarded_headers = true;
        let mut redirect_status_code = None;

        match raw.handler {
            HandlerSectionToml::StaticSpa {
                index_file,
                spa_fallback: fallback,
            } => {
                let idx = validate_safe_filename(&index_file)?;
                index_files = vec![idx];
                spa_fallback = fallback;
            }
            HandlerSectionToml::ReverseProxy {
                upstream,
                pass_host_header: pass_host,
                forwarded_headers: fwd_hdrs,
            } => {
                let connect_addr = validate_upstream_origin(&upstream)?;
                pass_host_header = pass_host;
                forwarded_headers = fwd_hdrs;
                routes.push(RouteRule {
                    path_prefix: "/".to_string(),
                    target_upstream: Some(connect_addr),
                    backend_protocol: BackendProtocol::Http1,
                    strip_prefix: false,
                    inject_headers: HashMap::new(),
                });
            }
            HandlerSectionToml::PhpFpm {
                php_version: _,
                fastcgi_socket,
                index_file,
            } => {
                let clean_sock = validate_absolute_clean_path(&fastcgi_socket, "fastcgi_socket")?;
                let idx = validate_safe_filename(&index_file)?;
                php_fpm_socket = Some(clean_sock.to_string_lossy().to_string());
                index_files = vec![idx, "index.html".to_string()];
            }
            HandlerSectionToml::RedirectHttps { status_code } => {
                if !matches!(status_code, 301 | 302 | 307 | 308) {
                    return Err(ConfigError::Validation(format!(
                        "redirect_https status_code must be 301, 302, 307, or 308 in {}",
                        source_file.display()
                    )));
                }
                redirect_status_code = Some(status_code);
            }
        }

        Ok(VirtualHost {
            server_name: primary_domain,
            aliases,
            root_dir: Some(root_dir),
            enable_http3_alt_svc: true,
            try_files: default_try_files(),
            index_files,
            compression: CompressionConfig::default(),
            routes,
            php_fpm_socket,
            acme_prefix,
            acme_webroot,
            acme_serve_before_redirect: raw.acme.serve_before_redirect,
            ssl_enabled: raw.ssl.enabled,
            redirect_https: raw.ssl.redirect_https,
            redirect_status_code,
            ssl_cert_path,
            ssl_key_path,
            spa_fallback,
            pass_host_header,
            forwarded_headers,
        })
    }

    /// Đọc các file *.conf trong thư mục vhost cũ của Panel (hỗ trợ cả TOML và cú pháp tương tự Nginx)
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

            if let Some(vh) = Self::parse_nginx_style_vhost(&content) {
                Self::upsert_vhost_vec(&mut cfg.vhosts, vh);
            }
        }
    }

    fn upsert_vhost_vec(vhosts: &mut Vec<VirtualHost>, vhost: VirtualHost) {
        if let Some(existing) = vhosts
            .iter_mut()
            .find(|v| v.server_name.eq_ignore_ascii_case(&vhost.server_name))
        {
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
            let line = raw_line
                .split('#')
                .next()
                .unwrap_or("")
                .trim()
                .trim_end_matches(';')
                .trim();
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

        let mut vh = VirtualHost::default_catch_all();
        vh.server_name = primary;
        vh.aliases = aliases;
        vh.root_dir = root_dir;
        vh.routes = routes;
        vh.php_fpm_socket = php_fpm_socket;
        Some(vh)
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
    info!(
        count = fds.len(),
        "Đã chuyển giao thành công các socket FD qua SCM_RIGHTS"
    );
    Ok(())
}

/// Nhận lại các Listening Socket File Descriptors ở tiến trình FerrousX mới
pub fn recv_listening_fds(
    uds_stream: &UnixStream,
    max_fds: usize,
) -> Result<Vec<RawFd>, ConfigError> {
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
