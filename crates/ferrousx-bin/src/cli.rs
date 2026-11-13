//! # ferrousx-ctl — Server Terminal Administration CLI & Panel Synchronizer
//!
//! Giao tiếp với FerrousX daemon qua Unix Domain Socket (`/run/ferrousx/panel-admin.sock`)
//! và hỗ trợ fallback tín hiệu POSIX `SIGHUP` trực tiếp tới tiến trình `ferrousx-bin`.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

use ferrousx_config::config::ConfigManager;

#[derive(Parser, Debug)]
#[command(
    name = "ferrousx-ctl",
    author = "FerrousX Systems Team",
    version = env!("CARGO_PKG_VERSION"),
    about = "Công cụ dòng lệnh quản trị Web Server & Reverse Proxy FerrousX qua Terminal"
)]
pub struct CliArgs {
    /// Đường dẫn tới Unix Domain Socket của FerrousX daemon
    #[arg(short, long, default_value = "/run/ferrousx/panel-admin.sock")]
    pub socket: PathBuf,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Hiển thị trạng thái hoạt động của daemon, cấu hình động và các cổng lắng nghe
    Status,

    /// Mở giao diện giám sát thời gian thực per-core
    Top,

    /// Kiểm tra trạng thái Worker trên hệ thống
    Workers,

    /// Tự động quét và đồng bộ cấu hình từ Ferrous Panel (admin.json + vhosts) hoặc cPanel/DirectAdmin
    PanelSync {
        /// Loại panel: 'ferrous', 'cpanel', 'directadmin', 'aapanel', hoặc 'auto'
        #[arg(short, long, default_value = "auto")]
        panel: String,
    },

    /// Quản lý Virtual Host (thêm, sửa, xóa, liệt kê)
    Vhost {
        #[command(subcommand)]
        action: VhostSubcommand,
    },

    /// Xóa bộ nhớ đệm Edge Cache
    Cache {
        #[command(subcommand)]
        action: CacheSubcommand,
    },

    /// Kiểm tra tính hợp lệ cú pháp của tệp cấu hình (tương đương nginx -t)
    Test {
        #[arg(short, long, default_value = "/etc/ferrousx/ferrousx.toml")]
        config: PathBuf,
    },

    /// Kích hoạt nạp lại cấu hình tức thì bằng ArcSwap RCU / SIGHUP (< 50µs)
    Reload,

    /// Nâng cấp file nhị phân mới không làm rơi kết nối qua SCM_RIGHTS
    Upgrade {
        #[arg(short, long)]
        binary: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
pub enum VhostSubcommand {
    /// Liệt kê tất cả Virtual Hosts đang cấu hình
    List {
        #[arg(short, long, default_value = "/etc/ferrousx/ferrousx.toml")]
        config: PathBuf,
    },
    /// Thêm website mới vào bảng định tuyến
    Add {
        domain: String,
        #[arg(long, default_value = "8.3")]
        php: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        alt_svc: bool,
    },
    /// Xóa website khỏi bảng định tuyến
    Del {
        domain: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum CacheSubcommand {
    /// Xóa toàn bộ cache theo tên miền
    PurgeDomain { domain: String },
    /// Xóa theo tag
    PurgeTag { tag: String },
    /// Xem thống kê bộ nhớ đệm
    Stats,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IpcRequest {
    pub action: String,
    pub payload: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IpcResponse {
    pub success: bool,
    pub message: String,
    pub latency_us: u64,
    pub data: Option<serde_json::Value>,
}

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    run_cli()
}

pub fn run_cli() -> Result<(), Box<dyn std::error::Error>> {
    let cli = CliArgs::parse();

    match cli.command {
        Commands::Status => {
            match send_ipc_command(&cli.socket, "status", serde_json::json!({})) {
                Ok(resp) => {
                    println!(
                        "\x1b[1;32m● FerrousX Daemon v{}\x1b[0m — ACTIVE",
                        env!("CARGO_PKG_VERSION")
                    );
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                }
                Err(err) => {
                    eprintln!("\x1b[1;31m● FerrousX Daemon không phản hồi qua socket {:?}: {}\x1b[0m", cli.socket, err);
                    std::process::exit(1);
                }
            }
        }
        Commands::Workers | Commands::Top => {
            let resp = send_ipc_command(&cli.socket, "status", serde_json::json!({}))?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        Commands::PanelSync { panel } => {
            println!("\x1b[1;36m[PANEL-SYNC]\x1b[0m Đang đồng bộ cấu hình panel: {}", panel);
            if (panel == "cpanel" || panel == "auto") && Path::new("/etc/apache2/conf.d").exists() {
                println!("\x1b[1;32m✓\x1b[0m Phát hiện cPanel EasyApache 4.");
            }
            if (panel == "directadmin" || panel == "auto") && Path::new("/usr/local/directadmin").exists() {
                println!("\x1b[1;32m✓\x1b[0m Phát hiện DirectAdmin CustomBuild.");
            }
            if (panel == "ferrous" || panel == "auto") && Path::new("/etc/ferrous-panel/admin.json").exists() {
                println!("\x1b[1;32m✓\x1b[0m Phát hiện Ferrous Panel (/etc/ferrous-panel/admin.json).");
            }
            match send_ipc_command(&cli.socket, "panel_sync", serde_json::json!({ "panel": panel })) {
                Ok(resp) => {
                    println!(
                        "\x1b[1;32m✓\x1b[0m {} ({} µs)",
                        resp.message, resp.latency_us
                    );
                }
                Err(_) => {
                    let count = send_sighup_to_ferrousx_daemon()?;
                    println!("\x1b[1;32m✓\x1b[0m Đã gửi SIGHUP đồng bộ tới {count} tiến trình ferrousx-bin");
                }
            }
        }
        Commands::Reload => {
            match send_ipc_command(&cli.socket, "reload", serde_json::json!({})) {
                Ok(resp) if resp.success => {
                    println!("\x1b[1;32m✓\x1b[0m {}", resp.message);
                }
                Ok(resp) => {
                    eprintln!("\x1b[1;31m✗\x1b[0m {}", resp.message);
                    std::process::exit(1);
                }
                Err(_) => {
                    let count = send_sighup_to_ferrousx_daemon()?;
                    println!("\x1b[1;32m✓\x1b[0m Đã kích hoạt reload cấu hình qua SIGHUP ({count} tiến trình)");
                }
            }
        }
        Commands::Test { config } => {
            println!("Kiểm tra cú pháp cấu hình: {}", config.display());
            match validate_config_file(&config) {
                Ok(()) => {
                    println!(
                        "\x1b[1;32m✓ ferrousx: configuration file {} test is successful\x1b[0m",
                        config.display()
                    );
                }
                Err(err) => {
                    eprintln!(
                        "\x1b[1;31m✗ ferrousx: configuration file {} test failed: {}\x1b[0m",
                        config.display(),
                        err
                    );
                    std::process::exit(1);
                }
            }
        }
        Commands::Vhost { action } => match action {
            VhostSubcommand::List { config } => {
                let mgr = ConfigManager::from_file(&config)?;
                let cfg = mgr.current();
                for vh in &cfg.vhosts {
                    println!(
                        "- {} (aliases: {:?}, root: {:?})",
                        vh.server_name, vh.aliases, vh.root_dir
                    );
                }
            }
            VhostSubcommand::Add { domain, php, root, alt_svc } => {
                let resp = send_ipc_command(
                    &cli.socket,
                    "vhost_add",
                    serde_json::json!({
                        "domain": domain,
                        "php": php,
                        "root": root,
                        "alt_svc": alt_svc,
                    }),
                )?;
                println!("{}", resp.message);
            }
            VhostSubcommand::Del { domain } => {
                let resp = send_ipc_command(
                    &cli.socket,
                    "vhost_del",
                    serde_json::json!({ "domain": domain }),
                )?;
                println!("{}", resp.message);
            }
        },
        Commands::Cache { action } => {
            let payload = match action {
                CacheSubcommand::PurgeDomain { domain } => {
                    serde_json::json!({ "op": "purge_domain", "domain": domain })
                }
                CacheSubcommand::PurgeTag { tag } => {
                    serde_json::json!({ "op": "purge_tag", "tag": tag })
                }
                CacheSubcommand::Stats => serde_json::json!({ "op": "stats" }),
            };
            let resp = send_ipc_command(&cli.socket, "cache", payload)?;
            println!("{}", resp.message);
        }
        Commands::Upgrade { binary } => {
            let resp = send_ipc_command(
                &cli.socket,
                "upgrade",
                serde_json::json!({ "binary": binary }),
            )?;
            println!("{}", resp.message);
        }
    }

    Ok(())
}

fn validate_config_file(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mgr = ConfigManager::from_file(path)?;
    let cfg = mgr.current();
    cfg.effective_http_addr().parse::<SocketAddr>()?;
    cfg.effective_https_addr().parse::<SocketAddr>()?;
    cfg.bind_udp_addr.parse::<SocketAddr>()?;
    Ok(())
}

fn send_ipc_command(
    socket_path: &Path,
    action: &str,
    payload: serde_json::Value,
) -> Result<IpcResponse, Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(socket_path)?;
    let req = IpcRequest {
        action: action.to_string(),
        payload,
    };
    let json_bytes = serde_json::to_vec(&req)?;
    stream.write_all(&json_bytes)?;
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut response_buf = Vec::new();
    stream.read_to_end(&mut response_buf)?;

    let resp: IpcResponse = serde_json::from_slice(&response_buf)?;
    Ok(resp)
}

/// Quét `/proc/<pid>/comm` bằng Rust thuần để gửi `SIGHUP` tới daemon `ferrousx-bin`
fn send_sighup_to_ferrousx_daemon() -> Result<usize, Box<dyn std::error::Error>> {
    let mut signaled = 0usize;
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Err("Không thể đọc /proc để tìm tiến trình ferrousx-bin".into());
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid_str) = name.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<libc::pid_t>() else {
            continue;
        };
        let comm_path = entry.path().join("comm");
        let Ok(comm) = std::fs::read_to_string(comm_path) else {
            continue;
        };
        if comm.trim() == "ferrousx-bin" {
            let ret = unsafe { libc::kill(pid, libc::SIGHUP) };
            if ret == 0 {
                signaled += 1;
            }
        }
    }

    if signaled == 0 {
        return Err("Không tìm thấy tiến trình ferrousx-bin đang chạy để reload".into());
    }
    Ok(signaled)
}
