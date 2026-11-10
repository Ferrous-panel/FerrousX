//! crates/ferrousx-config/src/config.rs
//! Engine quản lý cấu hình động, Lock-Free Hot-Reload với ArcSwap
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

/// Cấu hình tổng thể của nút máy chủ FerrousX
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub version_epoch: u64,
    pub worker_threads: usize, // 0 = Tự động phát hiện số lõi vật lý (Thread-Per-Core)
    pub bind_tcp_addr: String, // VD: "0.0.0.0:8443"
    pub bind_udp_addr: String, // VD: "0.0.0.0:8443" (QUIC / HTTP/3)
    pub panel_control_socket: PathBuf, // Unix Socket giao tiếp tốc độ cao với Ferrous Panel
    pub uring_entries: u32,    // Độ sâu hàng đợi io_uring SQ/CQ (VD: 4096)
    pub sqpoll_idle_ms: Option<u32>,
    pub arena_capacity_bytes: usize,
    pub alt_svc_max_age: u32,
    pub tls: TlsConfig,
    pub vhosts: Vec<VirtualHost>,
    pub upstreams: HashMap<String, UpstreamPool>,
}

/// Cấu hình chứng chỉ TLS 1.3 & QUIC Transport
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_chain_path: PathBuf,
    pub private_key_path: PathBuf,
    pub enable_zero_rtt: bool,
    pub alpn_protocols: Vec<String>, // ["h3", "h2", "http/1.1"]
    pub quic_max_idle_timeout_ms: u64,
    pub quic_initial_mtu: u16,       // Tối ưu cho UDP GSO/GRO (VD: 1350)
}

/// Cấu hình từng miền ảo (VirtualHost)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualHost {
    pub server_name: String,
    pub aliases: Vec<String>,
    pub root_dir: Option<PathBuf>,
    pub enable_http3_alt_svc: bool,
    pub compression: CompressionConfig,
    pub routes: Vec<RouteRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionConfig {
    pub enable_zstd: bool,
    pub enable_brotli: bool,
    pub min_length_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteRule {
    pub path_prefix: String,
    pub target_upstream: Option<String>,
    pub backend_protocol: BackendProtocol,
    pub strip_prefix: bool,
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
    pub algorithm: LoadBalanceAlgorithm,
    pub health_check_interval_ms: u64,
    pub keepalive_pool_size: usize,
    pub endpoints: Vec<UpstreamEndpoint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceAlgorithm {
    RoundRobin,
    PowerOfTwoChoices, // P2C: Chọn ngẫu nhiên 2 node, lấy node ít kết nối active hơn
    MaglevConsistentHash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamEndpoint {
    pub address: String,
    pub weight: u16,
    pub max_conns: u32,
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

    /// Khởi tạo cấu hình mặc định phục vụ chạy thử nghiệm / benchmark tức thì
    pub fn default_production_demo() -> Arc<Self> {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "core_api_cluster".to_string(),
            UpstreamPool {
                algorithm: LoadBalanceAlgorithm::PowerOfTwoChoices,
                health_check_interval_ms: 2000,
                keepalive_pool_size: 512,
                endpoints: vec![
                    UpstreamEndpoint {
                        address: "10.0.10.11:9000".into(),
                        weight: 100,
                        max_conns: 10_000,
                    },
                    UpstreamEndpoint {
                        address: "10.0.10.12:9000".into(),
                        weight: 100,
                        max_conns: 10_000,
                    },
                ],
            },
        );

        let cfg = ServerConfig {
            version_epoch: 1,
            worker_threads: 0,
            bind_tcp_addr: "0.0.0.0:8443".into(),
            bind_udp_addr: "0.0.0.0:8443".into(),
            panel_control_socket: PathBuf::from("/run/ferrousx/panel-admin.sock"),
            uring_entries: 4096,
            sqpoll_idle_ms: Some(2000),
            arena_capacity_bytes: 64 * 1024, // 64 KiB pre-allocated Bumpalo Arena mỗi worker
            alt_svc_max_age: 86400,
            tls: TlsConfig {
                cert_chain_path: PathBuf::from("/etc/ferrousx/certs/fullchain.pem"),
                private_key_path: PathBuf::from("/etc/ferrousx/certs/privkey.pem"),
                enable_zero_rtt: true,
                alpn_protocols: vec!["h3".into(), "h2".into(), "http/1.1".into()],
                quic_max_idle_timeout_ms: 30_000,
                quic_initial_mtu: 1350,
            },
            vhosts: vec![VirtualHost {
                server_name: "edge.ferrousx.io".into(),
                aliases: vec!["*.ferrousx.io".into()],
                root_dir: Some(PathBuf::from("/var/www/ferrousx/public")),
                enable_http3_alt_svc: true,
                compression: CompressionConfig {
                    enable_zstd: true,
                    enable_brotli: true,
                    min_length_bytes: 1024,
                },
                routes: vec![RouteRule {
                    path_prefix: "/api/v1".into(),
                    target_upstream: Some("core_api_cluster".into()),
                    backend_protocol: BackendProtocol::GrpcH2,
                    strip_prefix: false,
                    inject_headers: HashMap::from([(
                        "X-Proxy-Engine".into(),
                        "FerrousX-io_uring".into(),
                    )]),
                }],
            }],
            upstreams,
        };

        Arc::new(Self {
            config_path: PathBuf::from("/etc/ferrousx/ferrousx.toml"),
            active_config: ArcSwap::from_pointee(cfg),
        })
    }

    /// Hot-path API: Được gọi trên từng HTTP request.
    /// Hoàn toàn Lock-Free (0 RwLock, 0 Mutex contention giữa các lõi CPU).
    #[inline(always)]
    pub fn current(&self) -> Guard<Arc<ServerConfig>> {
        self.active_config.load()
    }

    /// API dành riêng cho Ferrous Panel: Thêm hoặc cập nhật nóng 1 VirtualHost
    /// (đổi phiên bản PHP-FPM, thêm domain, cấu hình Reverse Proxy Node.js/Docker)
    /// chỉ trong <50 micro-giây bằng ArcSwap RCU mà không cần đọc lại toàn bộ đĩa.
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

    /// Thực thi Graceful Hot-Reload khi nhận tín hiệu SIGHUP.
    /// Các kết nối đang xử lý vẫn giữ tham chiếu Arc<ServerConfig> cũ cho tới khi hoàn tất,
    /// trong khi các request mới lập tức nhìn thấy phiên bản cấu hình mới.
    pub fn reload_from_disk(&self) -> Result<u64, ConfigError> {
        let prev_epoch = self.active_config.load().version_epoch;
        let next_epoch = prev_epoch + 1;

        let new_cfg = Self::load_and_validate(&self.config_path, next_epoch)?;
        self.active_config.store(Arc::new(new_cfg));

        info!(
            epoch = next_epoch,
            path = %self.config_path.display(),
            "Hoàn tất hoán đổi nguyên tử ArcSwap cấu hình mới (Zero-Downtime)"
        );
        Ok(next_epoch)
    }

    fn load_and_validate(path: &Path, epoch: u64) -> Result<ServerConfig, ConfigError> {
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
        if cfg.vhosts.is_empty() {
            return Err(ConfigError::Validation(
                "Cần khai báo ít nhất 1 VirtualHost".into(),
            ));
        }
        Ok(cfg)
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
