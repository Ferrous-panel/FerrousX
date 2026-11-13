//! crates/ferrousx-panel/src/api.rs
//! Hệ thống API Quản Trị & Telemetry 100% Rust cho Ferrous Panel.
//! Giao tiếp qua Unix Domain Socket (/run/ferrousx/panel-admin.sock)
//! hỗ trợ cả JSON IPC (`IpcRequest`) lẫn lệnh văn bản trực tiếp.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info};

use ferrousx_config::config::ConfigManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerTelemetry {
    pub worker_id: usize,
    pub core_id: usize,
    pub cpu_percent: f32,
    pub requests_per_sec: u64,
    pub active_connections: u32,
    pub ring_sq_depth: u32,
    pub ring_cq_depth: u32,
    pub arena_allocated_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStatusResponse {
    pub daemon: &'static str,
    pub version: &'static str,
    pub status: &'static str,
    pub uptime_secs: u64,
    pub config_epoch: u64,
    pub num_workers: usize,
    pub http_bind: String,
    pub https_bind: String,
    pub udp_bind: String,
    pub panel_upstream: String,
    pub custom_domain: String,
    pub total_requests: u64,
    pub active_connections: u64,
    pub io_backend: &'static str,
    pub workers: Vec<WorkerTelemetry>,
}

#[derive(Debug, Deserialize)]
struct IpcRequest {
    action: String,
    #[serde(default)]
    #[allow(dead_code)]
    payload: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct IpcResponse {
    success: bool,
    message: String,
    latency_us: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

pub struct PanelServer {
    config_mgr: Arc<ConfigManager>,
    start_time: Instant,
    total_requests: Arc<AtomicU64>,
    active_connections: Arc<AtomicU64>,
}

impl PanelServer {
    pub fn new(config_mgr: Arc<ConfigManager>) -> Self {
        Self {
            config_mgr,
            start_time: Instant::now(),
            total_requests: Arc::new(AtomicU64::new(0)),
            active_connections: Arc::new(AtomicU64::new(0)),
        }
    }

    pub async fn run_unix_socket_server(self: Arc<Self>, socket_path: &Path) -> Result<()> {
        if socket_path.exists() {
            let _ = std::fs::remove_file(socket_path);
        }

        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(socket_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660));
        }

        info!(socket = ?socket_path, "Panel Rust Control Socket Active");

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let server = Arc::clone(&self);
                    tokio::spawn(async move {
                        let _ = server.handle_client_connection(stream).await;
                    });
                }
                Err(err) => {
                    error!(error = %err, "Socket accept error");
                }
            }
        }
    }

    async fn handle_client_connection(&self, mut stream: UnixStream) -> Result<()> {
        let mut buffer = [0u8; 8192];
        let bytes_read = stream.read(&mut buffer).await?;
        if bytes_read == 0 {
            return Ok(());
        }
        let request_str = std::str::from_utf8(&buffer[..bytes_read])?;
        let response_payload = self.process_request(request_str)?;
        stream.write_all(response_payload.as_bytes()).await?;
        stream.shutdown().await?;
        Ok(())
    }

    fn process_request(&self, raw_input: &str) -> Result<String> {
        let trimmed = raw_input.trim();
        let started = Instant::now();

        let action = if trimmed.starts_with('{') {
            match serde_json::from_str::<IpcRequest>(trimmed) {
                Ok(req) => req.action,
                Err(err) => {
                    let resp = IpcResponse {
                        success: false,
                        message: format!("JSON IPC không hợp lệ: {err}"),
                        latency_us: started.elapsed().as_micros() as u64,
                        data: None,
                    };
                    return serde_json::to_string_pretty(&resp).map_err(Into::into);
                }
            }
        } else {
            trimmed.to_ascii_lowercase()
        };

        let resp = match action.as_str() {
            "status" | "info" => {
                let status = self.collect_status();
                let data = serde_json::to_value(status).ok();
                IpcResponse {
                    success: true,
                    message: "FerrousX Engine đang hoạt động ổn định".to_string(),
                    latency_us: started.elapsed().as_micros() as u64,
                    data,
                }
            }
            "reload" | "panel_sync" => match self.config_mgr.reload_from_disk() {
                Ok(epoch) => IpcResponse {
                    success: true,
                    message: format!("Hoán đổi ArcSwap RCU thành công (epoch={epoch})"),
                    latency_us: started.elapsed().as_micros() as u64,
                    data: Some(serde_json::json!({ "epoch": epoch })),
                },
                Err(err) => IpcResponse {
                    success: false,
                    message: format!("Nạp lại cấu hình thất bại (giữ cấu hình cũ): {err}"),
                    latency_us: started.elapsed().as_micros() as u64,
                    data: None,
                },
            },
            other => IpcResponse {
                success: true,
                message: format!("Lệnh '{other}' đã được FerrousX Engine tiếp nhận"),
                latency_us: started.elapsed().as_micros() as u64,
                data: None,
            },
        };

        serde_json::to_string_pretty(&resp).map_err(Into::into)
    }

    fn collect_status(&self) -> ServerStatusResponse {
        let cfg = self.config_mgr.current();
        let detected_cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        let num_workers = if cfg.worker_threads == 0 {
            detected_cores
        } else {
            cfg.worker_threads.min(detected_cores)
        };

        ServerStatusResponse {
            daemon: "FerrousX High-Performance Engine",
            version: env!("CARGO_PKG_VERSION"),
            status: "running (Triple-Stack TCP :80/:443 + UDP :443)",
            uptime_secs: self.start_time.elapsed().as_secs(),
            config_epoch: self.config_mgr.current_epoch(),
            num_workers,
            http_bind: cfg.effective_http_addr().to_string(),
            https_bind: cfg.effective_https_addr().to_string(),
            udp_bind: cfg.bind_udp_addr.clone(),
            panel_upstream: cfg.panel_admin.panel_upstream_addr(),
            custom_domain: cfg.panel_admin.custom_domain.clone(),
            total_requests: self.total_requests.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            io_backend: "Linux Thread-Per-Core + SO_REUSEPORT + Tokio",
            workers: vec![],
        }
    }
}
