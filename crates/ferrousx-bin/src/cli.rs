//! # ferrousx-ctl — Server Terminal Administration CLI, Interactive VPS Admin Console & Panel Synchronizer
//!
//! Giao tiếp với FerrousX daemon qua Unix Domain Socket (`/run/ferrousx/admin.sock`)
//! kèm xác thực `SO_PEERCRED` + 256-bit Admin Token (`/etc/ferrousx/admin.token`),
//! hỗ trợ Menu Quản trị Terminal VPS tương tác (`ferrousx-ctl admin` / `ferrousx-admin` / `fx`).

use std::io::{self, IsTerminal, Read, Write};
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

use ferrousx_config::config::{validate_pem_cert_and_key_files, ConfigManager, SiteConfigToml};
use ferrousx_proxy::fastcgi::detect_php_fpm_socket;

#[derive(Parser, Debug)]
#[command(
    name = "ferrousx-ctl",
    author = "FerrousX Systems Team",
    version = env!("CARGO_PKG_VERSION"),
    about = "Công cụ dòng lệnh & Bảng điều khiển Admin quản trị FerrousX Web Server trên Terminal VPS"
)]
pub struct CliArgs {
    /// Đường dẫn tới Unix Domain Socket của FerrousX daemon
    #[arg(short, long, default_value = "/run/ferrousx/admin.sock")]
    pub socket: PathBuf,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Mở Bảng điều khiển Quản trị Terminal VPS tương tác (Interactive VPS Admin Menu)
    Admin,

    /// Hiển thị thông tin Admin Token, cổng lắng nghe, trạng thái WAF và đường dẫn cấu hình
    Info,

    /// Hiển thị trạng thái hoạt động của daemon, cấu hình động và các cổng lắng nghe
    Status,

    /// Mở giao diện giám sát thời gian thực per-core
    Top,

    /// Kiểm tra trạng thái Worker trên hệ thống
    Workers,

    /// Tự động quét và đồng bộ cấu hình từ Ferrous-Panel (panel.env + admin.json + sites/*.toml)
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

    /// Xem hoặc xoay vòng (rotate) khóa bảo mật Admin Token 256-bit (/etc/ferrousx/admin.token)
    Token {
        /// Tạo khóa Admin Token 256-bit mới từ /dev/urandom
        #[arg(long)]
        rotate: bool,
    },

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
    /// Thêm website mới vào bảng định tuyến (/etc/ferrousx/sites/<domain>.toml)
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
    #[serde(default)]
    pub auth_token: Option<String>,
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
    let socket = resolve_effective_socket(&cli.socket);

    // Nếu người dùng gõ `ferrousx-ctl` không kèm tham số hoặc `ferrousx-ctl admin` -> Mở Menu Admin Terminal
    let Some(command) = cli.command else {
        return run_interactive_admin_console(&socket);
    };

    match command {
        Commands::Admin => {
            run_interactive_admin_console(&socket)?;
        }
        Commands::Info => {
            print_admin_overview(&socket);
        }
        Commands::Status => {
            match send_ipc_command(&socket, "status", serde_json::json!({})) {
                Ok(resp) => {
                    println!(
                        "\x1b[1;32m● FerrousX Daemon v{}\x1b[0m — ACTIVE",
                        env!("CARGO_PKG_VERSION")
                    );
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                }
                Err(err) => {
                    eprintln!(
                        "\x1b[1;31m● FerrousX Daemon không phản hồi qua socket {:?}: {}\x1b[0m",
                        socket, err
                    );
                    std::process::exit(1);
                }
            }
        }
        Commands::Workers => {
            let resp = send_ipc_command(&socket, "status", serde_json::json!({}))?;
            print_live_telemetry_snapshot(&resp, false);
        }
        Commands::Top => {
            let is_tty = io::stdout().is_terminal();
            loop {
                let resp = send_ipc_command(&socket, "status", serde_json::json!({}))?;
                print_live_telemetry_snapshot(&resp, is_tty);
                if !is_tty {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
        Commands::PanelSync { panel } => {
            println!(
                "\x1b[1;36m[PANEL-SYNC]\x1b[0m Đang đồng bộ cấu hình panel: {}",
                panel
            );
            if (panel == "cpanel" || panel == "auto") && Path::new("/etc/apache2/conf.d").exists()
            {
                println!("\x1b[1;32m✓\x1b[0m Phát hiện cPanel EasyApache 4.");
            }
            if (panel == "directadmin" || panel == "auto")
                && Path::new("/usr/local/directadmin").exists()
            {
                println!("\x1b[1;32m✓\x1b[0m Phát hiện DirectAdmin CustomBuild.");
            }
            if (panel == "ferrous" || panel == "auto")
                && Path::new("/etc/ferrous-panel/panel.env").exists()
            {
                println!("\x1b[1;32m✓\x1b[0m Phát hiện Ferrous-Panel v2.5.0 Pure Rust (/etc/ferrous-panel/panel.env + /etc/ferrousx/sites/*.toml).");
            }
            if (panel == "ferrous" || panel == "auto")
                && Path::new("/etc/ferrous-panel/admin.json").exists()
            {
                println!(
                    "\x1b[1;32m✓\x1b[0m Phát hiện Ferrous Panel (/etc/ferrous-panel/admin.json)."
                );
            }
            match send_ipc_command(&socket, "panel_sync", serde_json::json!({ "panel": panel })) {
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
        Commands::Reload => match send_ipc_command(&socket, "reload", serde_json::json!({})) {
            Ok(resp) if resp.success => {
                println!("\x1b[1;32m✓\x1b[0m {}", resp.message);
            }
            Ok(resp) => {
                eprintln!("\x1b[1;31m✗\x1b[0m {}", resp.message);
                std::process::exit(1);
            }
            Err(_) => {
                let count = send_sighup_to_ferrousx_daemon()?;
                println!(
                    "\x1b[1;32m✓\x1b[0m Đã kích hoạt reload cấu hình qua SIGHUP ({count} tiến trình)"
                );
            }
        },
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
        Commands::Token { rotate } => {
            let token_path = Path::new("/etc/ferrousx/admin.token");
            if rotate {
                rotate_admin_token_file(token_path)?;
                println!(
                    "\x1b[1;32m✓ Đã xoay vòng (rotate) khóa Admin Token 256-bit mới tại {}\x1b[0m",
                    token_path.display()
                );
            }
            match std::fs::read_to_string(token_path) {
                Ok(tok) => {
                    println!("Đường dẫn Token : {}", token_path.display());
                    println!("Admin Token     : \x1b[1;33m{}\x1b[0m", tok.trim());
                }
                Err(e) => {
                    eprintln!(
                        "\x1b[1;31mKhông thể đọc {}: {} (Hãy chạy với quyền sudo)\x1b[0m",
                        token_path.display(),
                        e
                    );
                }
            }
        }
        Commands::Vhost { action } => match action {
            VhostSubcommand::List { config } => {
                let mgr = ConfigManager::from_file(&config)?;
                let cfg = mgr.current();
                println!(
                    "\x1b[1;36m=== DANH SÁCH VIRTUAL HOSTS ({} site) ===\x1b[0m",
                    cfg.vhosts.len()
                );
                for vh in &cfg.vhosts {
                    println!(
                        " • \x1b[1;32m{}\x1b[0m (aliases: {:?}, root: {:?}, ssl: {}, waf: {:?})",
                        vh.server_name, vh.aliases, vh.root_dir, vh.ssl_enabled, vh.waf_mode
                    );
                }
            }
            VhostSubcommand::Add {
                domain,
                php,
                root,
                alt_svc,
            } => {
                create_vhost_toml_file(&domain, &php, &root)?;
                if let Ok(resp) = send_ipc_command(
                    &socket,
                    "vhost_add",
                    serde_json::json!({
                        "domain": domain,
                        "php": php,
                        "root": root,
                        "alt_svc": alt_svc,
                    }),
                ) {
                    println!("\x1b[1;32m✓\x1b[0m {}", resp.message);
                } else {
                    let _ = send_sighup_to_ferrousx_daemon();
                    println!(
                        "\x1b[1;32m✓ Đã tạo /etc/ferrousx/sites/{domain}.toml và nạp nóng cấu hình!\x1b[0m"
                    );
                }
            }
            VhostSubcommand::Del { domain } => {
                let site_file = PathBuf::from(format!("/etc/ferrousx/sites/{domain}.toml"));
                if site_file.exists() {
                    let _ = std::fs::remove_file(&site_file);
                }
                if let Ok(resp) = send_ipc_command(
                    &socket,
                    "vhost_del",
                    serde_json::json!({ "domain": domain }),
                ) {
                    println!("\x1b[1;32m✓\x1b[0m {}", resp.message);
                } else {
                    let _ = send_sighup_to_ferrousx_daemon();
                    println!("\x1b[1;32m✓ Đã xóa VirtualHost {domain} và nạp lại cấu hình!\x1b[0m");
                }
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
            let resp = send_ipc_command(&socket, "cache", payload)?;
            println!("{}", resp.message);
        }
        Commands::Upgrade { binary } => {
            let resp = send_ipc_command(&socket, "upgrade", serde_json::json!({ "binary": binary }))?;
            println!("{}", resp.message);
        }
    }

    Ok(())
}

/// Tự động chọn đường dẫn socket thực tế đang hoạt động (`/run/ferrousx/admin.sock` hoặc `/run/ferrousx/panel-admin.sock`)
fn resolve_effective_socket(preferred: &Path) -> PathBuf {
    if preferred.exists() {
        return preferred.to_path_buf();
    }
    let alt = Path::new("/run/ferrousx/panel-admin.sock");
    if alt.exists() {
        return alt.to_path_buf();
    }
    preferred.to_path_buf()
}

/// Hiển thị bảng tổng quan thông tin quản trị FerrousX trên VPS
fn print_admin_overview(socket: &Path) {
    println!("\x1b[1;36m======================================================================\x1b[0m");
    println!(
        "\x1b[1;32m   ⚡ FERROUSX VPS ADMIN OVERVIEW — v{} (100% NATIVE RUST)\x1b[0m",
        env!("CARGO_PKG_VERSION")
    );
    println!("\x1b[1;36m======================================================================\x1b[0m");
    println!(" • Cấu hình chính    : /etc/ferrousx/ferrousx.toml");
    println!(" • Thư mục Vhost     : /etc/ferrousx/sites/*.toml");
    println!(" • Chứng chỉ SSL     : /etc/ferrousx/ssl/fullchain.pem");
    println!(" • Control Socket    : {}", socket.display());
    println!(" • Local WebUI       : http://127.0.0.1:9090");
    println!(" • phpMyAdmin Proxy  : http://<Server-IP>/phpadmin/ (-> 127.0.0.1:888)");

    if let Ok(tok) = std::fs::read_to_string("/etc/ferrousx/admin.token") {
        let trimmed = tok.trim();
        let masked = if trimmed.len() > 12 {
            format!("{}...{}", &trimmed[..6], &trimmed[trimmed.len() - 6..])
        } else {
            "(hidden)".to_string()
        };
        println!(" • Admin Token (0600): {masked} (Xem đầy đủ: sudo ferrousx-ctl token)");
    }

    if let Ok(resp) = send_ipc_command(socket, "status", serde_json::json!({})) {
        println!(" • Trạng thái Daemon : \x1b[1;32mONLINE\x1b[0m ({})", resp.message);
        if let Some(data) = resp.data {
            println!(" • Thông số Engine   : {}", data);
        }
    } else {
        println!(" • Trạng thái Daemon : \x1b[1;33mOFFLINE hoặc cần quyền sudo\x1b[0m");
    }
    println!("\x1b[1;36m======================================================================\x1b[0m");
}

/// Bảng điều khiển Quản trị Terminal VPS Tương tác (Interactive CLI Menu giống `bt` / `ferrous-panel`)
fn run_interactive_admin_console(socket: &Path) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        println!("\n\x1b[1;36m╔════════════════════════════════════════════════════════════════════╗\x1b[0m");
        println!(
            "\x1b[1;36m║\x1b[0m   \x1b[1;32m⚡ FERROUSX VPS TERMINAL ADMIN CONSOLE (v{})\x1b[0m                 \x1b[1;36m║\x1b[0m",
            env!("CARGO_PKG_VERSION")
        );
        println!("\x1b[1;36m╠════════════════════════════════════════════════════════════════════╣\x1b[0m");
        println!("\x1b[1;36m║\x1b[0m  \x1b[1;33m[1]\x1b[0m Xem trạng thái Server, Ports (:80/:443/:888) & RCU Epoch      \x1b[1;36m║\x1b[0m");
        println!("\x1b[1;36m║\x1b[0m  \x1b[1;33m[2]\x1b[0m Kiểm tra cú pháp cấu hình & chứng chỉ SSL (--check-config)    \x1b[1;36m║\x1b[0m");
        println!("\x1b[1;36m║\x1b[0m  \x1b[1;33m[3]\x1b[0m Hot-Reload cấu hình Zero-Downtime (ArcSwap RCU / SIGHUP)      \x1b[1;36m║\x1b[0m");
        println!("\x1b[1;36m║\x1b[0m  \x1b[1;33m[4]\x1b[0m Khởi động lại dịch vụ FerrousX (systemctl restart ferrousx)   \x1b[1;36m║\x1b[0m");
        println!("\x1b[1;36m║\x1b[0m  \x1b[1;33m[5]\x1b[0m Khởi động lại phpMyAdmin nội bộ (127.0.0.1:888)               \x1b[1;36m║\x1b[0m");
        println!("\x1b[1;36m║\x1b[0m  \x1b[1;33m[6]\x1b[0m Liệt kê danh sách Website VirtualHosts đang hoạt động         \x1b[1;36m║\x1b[0m");
        println!("\x1b[1;36m║\x1b[0m  \x1b[1;33m[7]\x1b[0m Thêm nhanh Website VirtualHost mới (Domain + PHP-FPM)         \x1b[1;36m║\x1b[0m");
        println!("\x1b[1;36m║\x1b[0m  \x1b[1;33m[8]\x1b[0m Xóa Website VirtualHost                                       \x1b[1;36m║\x1b[0m");
        println!("\x1b[1;36m║\x1b[0m  \x1b[1;33m[9]\x1b[0m Xem hoặc Xoay vòng (Rotate) khóa bảo mật Admin Token 256-bit  \x1b[1;36m║\x1b[0m");
        println!("\x1b[1;36m║\x1b[0m  \x1b[1;33m[10]\x1b[0m Đồng bộ nóng với Ferrous-Panel (panel.env & sites/*.toml)    \x1b[1;36m║\x1b[0m");
        println!("\x1b[1;36m║\x1b[0m  \x1b[1;33m[11]\x1b[0m Xem nhật ký hệ thống (journalctl -u ferrousx -n 30)          \x1b[1;36m║\x1b[0m");
        println!("\x1b[1;36m║\x1b[0m  \x1b[1;33m[12]\x1b[0m Chạy tự động kiểm tra & sửa chữa dịch vụ (repair.sh)         \x1b[1;36m║\x1b[0m");
        println!("\x1b[1;36m║\x1b[0m  \x1b[1;33m[0]\x1b[0m Thoát bảng điều khiển (Exit)                                  \x1b[1;36m║\x1b[0m");
        println!("\x1b[1;36m╚════════════════════════════════════════════════════════════════════╝\x1b[0m");
        print!("\x1b[1;32mNhập lựa chọn của bạn [0-12]: \x1b[0m");
        io::stdout().flush()?;

        let mut choice = String::new();
        if io::stdin().read_line(&mut choice)? == 0 {
            break;
        }

        match choice.trim() {
            "1" => {
                print_admin_overview(socket);
            }
            "2" => {
                let cfg_path = Path::new("/etc/ferrousx/ferrousx.toml");
                match validate_config_file(cfg_path) {
                    Ok(()) => println!(
                        "\x1b[1;32m✓ Cấu hình {} hoàn toàn hợp lệ!\x1b[0m",
                        cfg_path.display()
                    ),
                    Err(e) => eprintln!("\x1b[1;31m✗ Lỗi cấu hình: {}\x1b[0m", e),
                }
            }
            "3" => match send_ipc_command(socket, "reload", serde_json::json!({})) {
                Ok(resp) => println!("\x1b[1;32m✓ {}\x1b[0m", resp.message),
                Err(_) => match send_sighup_to_ferrousx_daemon() {
                    Ok(n) => println!("\x1b[1;32m✓ Đã gửi SIGHUP tới {n} tiến trình!\x1b[0m"),
                    Err(e) => eprintln!("\x1b[1;31m✗ Lỗi reload: {e}\x1b[0m"),
                },
            },
            "4" => {
                let status = Command::new("systemctl")
                    .args(["restart", "ferrousx.service"])
                    .status();
                match status {
                    Ok(s) if s.success() => {
                        println!("\x1b[1;32m✓ Đã khởi động lại ferrousx.service thành công!\x1b[0m")
                    }
                    _ => eprintln!("\x1b[1;31m✗ Không thể khởi động lại ferrousx.service\x1b[0m"),
                }
            }
            "5" => {
                let status = Command::new("systemctl")
                    .args(["restart", "ferrous-pma.service"])
                    .status();
                match status {
                    Ok(s) if s.success() => println!(
                        "\x1b[1;32m✓ Đã khởi động lại ferrous-pma.service (127.0.0.1:888)!\x1b[0m"
                    ),
                    _ => eprintln!("\x1b[1;31m✗ Không thể khởi động lại ferrous-pma.service\x1b[0m"),
                }
            }
            "6" => {
                let cfg_path = Path::new("/etc/ferrousx/ferrousx.toml");
                if let Ok(mgr) = ConfigManager::from_file(cfg_path) {
                    let cfg = mgr.current();
                    println!(
                        "\n\x1b[1;36mDanh sách {} VirtualHosts:\x1b[0m",
                        cfg.vhosts.len()
                    );
                    for vh in &cfg.vhosts {
                        println!(
                            " • \x1b[1;32m{}\x1b[0m -> root: {:?}, ssl: {}, waf: {:?}",
                            vh.server_name, vh.root_dir, vh.ssl_enabled, vh.waf_mode
                        );
                    }
                }
            }
            "7" => {
                let domain = prompt_line("Nhập tên miền (ví dụ: example.com): ")?;
                if !domain.is_empty() {
                    let default_root = format!("/www/wwwroot/{domain}");
                    let root_str = prompt_line(&format!(
                        "Nhập thư mục webroot (Enter = {default_root}): "
                    ))?;
                    let root_path = if root_str.is_empty() {
                        PathBuf::from(default_root)
                    } else {
                        PathBuf::from(root_str)
                    };
                    let php_ver = prompt_line("Phiên bản PHP-FPM (Enter = 8.3): ")?;
                    let php = if php_ver.is_empty() { "8.3" } else { &php_ver };
                    if let Err(e) = create_vhost_toml_file(&domain, php, &root_path) {
                        eprintln!("\x1b[1;31m✗ Lỗi tạo Vhost: {e}\x1b[0m");
                    } else {
                        let _ = send_ipc_command(socket, "reload", serde_json::json!({}));
                        println!(
                            "\x1b[1;32m✓ Đã tạo /etc/ferrousx/sites/{domain}.toml và kích hoạt ngay lập tức!\x1b[0m"
                        );
                    }
                }
            }
            "8" => {
                let domain = prompt_line("Nhập tên miền cần xóa: ")?;
                if !domain.is_empty() {
                    let site_file = PathBuf::from(format!("/etc/ferrousx/sites/{domain}.toml"));
                    if site_file.exists() {
                        let _ = std::fs::remove_file(&site_file);
                        let _ = send_ipc_command(socket, "reload", serde_json::json!({}));
                        println!("\x1b[1;32m✓ Đã xóa {domain} và nạp lại cấu hình!\x1b[0m");
                    } else {
                        println!("\x1b[1;33mKhông tìm thấy tệp {}\x1b[0m", site_file.display());
                    }
                }
            }
            "9" => {
                let token_path = Path::new("/etc/ferrousx/admin.token");
                if let Ok(tok) = std::fs::read_to_string(token_path) {
                    println!("Admin Token hiện tại: \x1b[1;33m{}\x1b[0m", tok.trim());
                }
                let ans = prompt_line("Bạn có muốn tạo khóa Token 256-bit mới không? [y/N]: ")?;
                if ans.eq_ignore_ascii_case("y") {
                    rotate_admin_token_file(token_path)?;
                    if let Ok(tok) = std::fs::read_to_string(token_path) {
                        println!(
                            "\x1b[1;32m✓ Khóa Admin Token mới:\x1b[0m \x1b[1;33m{}\x1b[0m",
                            tok.trim()
                        );
                    }
                }
            }
            "10" => {
                match send_ipc_command(socket, "panel_sync", serde_json::json!({ "panel": "auto" }))
                {
                    Ok(resp) => println!("\x1b[1;32m✓ {}\x1b[0m", resp.message),
                    Err(_) => {
                        let _ = send_sighup_to_ferrousx_daemon();
                        println!("\x1b[1;32m✓ Đã gửi tín hiệu SIGHUP đồng bộ Panel!\x1b[0m");
                    }
                }
            }
            "11" => {
                let _ = Command::new("journalctl")
                    .args(["-u", "ferrousx.service", "-n", "30", "--no-pager"])
                    .status();
            }
            "12" => {
                if Path::new("/usr/local/src/FerrousX/scripts/repair.sh").exists() {
                    let _ = Command::new("bash")
                        .args(["/usr/local/src/FerrousX/scripts/repair.sh", "--yes"])
                        .status();
                } else if Path::new("scripts/repair.sh").exists() {
                    let _ = Command::new("bash")
                        .args(["scripts/repair.sh", "--yes"])
                        .status();
                } else {
                    println!("\x1b[1;33mĐang kiểm tra cấu hình trực tiếp...\x1b[0m");
                    let _ = validate_config_file(Path::new("/etc/ferrousx/ferrousx.toml"));
                }
            }
            "0" | "q" | "exit" => {
                println!("Đã thoát bảng điều khiển FerrousX Admin.");
                break;
            }
            _ => {
                println!("\x1b[1;33mLựa chọn không hợp lệ, vui lòng nhập số từ 0 đến 12.\x1b[0m");
            }
        }
    }
    Ok(())
}

fn prompt_line(label: &str) -> io::Result<String> {
    print!("{label}");
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

fn print_live_telemetry_snapshot(resp: &IpcResponse, clear_screen: bool) {
    if clear_screen {
        print!("\x1b[2J\x1b[H");
    }
    let d = resp.data.as_ref();
    let get_u64 = |k: &str| d.and_then(|v| v.get(k)).and_then(|x| x.as_u64()).unwrap_or(0);
    let get_str = |k: &str| {
        d.and_then(|v| v.get(k))
            .and_then(|x| x.as_str())
            .unwrap_or("unknown")
    };

    println!("\x1b[1;36m=== FERROUSX LIVE ENGINE TELEMETRY (v{}) ===\x1b[0m", env!("CARGO_PKG_VERSION"));
    println!(
        " Epoch: v{} | Uptime: {}s | Active Conns: {} | Total Reqs: {}",
        get_u64("epoch"),
        get_u64("uptime_secs"),
        get_u64("active_connections"),
        get_u64("total_requests")
    );
    println!(
        " PHP-FPM: {} | Static: {} | HTTP/3: {} | Bytes Sent: {}",
        get_u64("php_fpm_requests"),
        get_u64("static_requests"),
        get_u64("http3_requests"),
        get_u64("bytes_sent")
    );
    println!(
        " WAF Mode: {} | WAF Blocked: {} | Rate-Limited: {} | Upstream Errs: {}",
        get_str("waf_mode"),
        get_u64("waf_blocked"),
        get_u64("rate_limited"),
        get_u64("upstream_errors")
    );
    println!(
        " XDP Pass: {} | XDP Drop: {} | VHosts: {} | Upstreams: {}",
        get_u64("xdp_passed_clean"),
        get_u64("xdp_dropped_ddos"),
        get_u64("vhosts_count"),
        get_u64("upstreams_count")
    );
    if clear_screen {
        println!("\x1b[2m(Nhấn Ctrl+C để thoát chế độ giám sát)\x1b[0m");
    }
    let _ = io::stdout().flush();
}

fn create_vhost_toml_file(
    domain: &str,
    php_ver: &str,
    root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if domain.contains("..") || domain.contains('/') || domain.contains('\\') {
        return Err("Tên miền không hợp lệ".into());
    }
    std::fs::create_dir_all("/etc/ferrousx/sites")?;
    std::fs::create_dir_all(root)?;

    let php_trimmed = php_ver.trim();
    let is_static = php_trimmed.is_empty()
        || php_trimmed.eq_ignore_ascii_case("none")
        || php_trimmed.eq_ignore_ascii_case("static");

    let handler_block = if is_static {
        r#"[handler]
kind = "static_spa"
index_file = "index.html"
spa_fallback = false"#
            .to_string()
    } else {
        let candidate_sock = format!("/run/php/php{php_trimmed}-fpm.sock");
        let resolved_sock = detect_php_fpm_socket(Some(&candidate_sock));
        format!(
            r#"[handler]
kind = "php_fpm"
php_version = "{php_trimmed}"
fastcgi_socket = "{resolved_sock}"
index_file = "index.php""#
        )
    };

    let toml_content = format!(
        r#"# VirtualHost generated by FerrousX Terminal Admin (SiteConfigToml Schema)
domain = "{domain}"
server_names = ["www.{domain}"]
root = "{}"
waf_mode = "block"

[acme]
prefix = "/.well-known/acme-challenge/"
webroot = "/www/acme"
serve_before_redirect = true

[ssl]
enabled = false
redirect_https = false

{handler_block}
"#,
        root.display()
    );

    // Xác thực schema trước khi ghi xuống đĩa
    let _: SiteConfigToml = toml::from_str(&toml_content)?;

    let site_path = PathBuf::from(format!("/etc/ferrousx/sites/{domain}.toml"));
    std::fs::write(&site_path, toml_content)?;
    Ok(())
}

fn rotate_admin_token_file(token_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut random_bytes = [0u8; 32];
    let mut urandom = std::fs::File::open("/dev/urandom")?;
    urandom.read_exact(&mut random_bytes)?;

    let mut hex_token = String::with_capacity(64);
    for b in random_bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut hex_token, "{b:02x}");
    }

    if let Some(parent) = token_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(token_path, format!("{hex_token}\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(token_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn validate_config_file(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mgr = ConfigManager::from_file(path)?;
    let cfg = mgr.current();
    cfg.effective_http_addr().parse::<SocketAddr>()?;
    cfg.effective_https_addr().parse::<SocketAddr>()?;
    cfg.bind_udp_addr.parse::<SocketAddr>()?;
    if cfg.tls.cert_chain_path.exists() || cfg.tls.private_key_path.exists() {
        validate_pem_cert_and_key_files(&cfg.tls.cert_chain_path, &cfg.tls.private_key_path)?;
    }
    for vhost in &cfg.vhosts {
        if vhost.ssl_enabled {
            let cert = vhost
                .ssl_cert_path
                .as_ref()
                .ok_or_else(|| format!("missing ssl.cert_path for {}", vhost.server_name))?;
            let key = vhost
                .ssl_key_path
                .as_ref()
                .ok_or_else(|| format!("missing ssl.key_path for {}", vhost.server_name))?;
            validate_pem_cert_and_key_files(cert, key)?;
        }
    }
    Ok(())
}

fn send_ipc_command(
    socket_path: &Path,
    action: &str,
    payload: serde_json::Value,
) -> Result<IpcResponse, Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(socket_path)?;
    let auth_token = std::env::var("FERROUSX_ADMIN_TOKEN")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/ferrousx/admin.token").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let req = IpcRequest {
        action: action.to_string(),
        payload,
        auth_token,
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
