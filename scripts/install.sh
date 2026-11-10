#!/usr/bin/env bash
# ==============================================================================
# FerrousX — Universal Linux Installer (Direct from GitHub Repository)
# Hỗ trợ tự động: Ubuntu, Debian, AlmaLinux, Rocky Linux, RHEL, Alpine, Arch Linux
# Cách dùng:
#   1. Trực tiếp từ GitHub:
#      curl -fsSL https://raw.githubusercontent.com/Ferrous-panel/FerrousX/main/scripts/install.sh | sudo bash
#   2. Hoặc sau khi git clone:
#      git clone https://github.com/Ferrous-panel/FerrousX.git
#      cd FerrousX && sudo ./scripts/install.sh
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}================================================================${NC}"
echo -e "${CYAN}   FerrousX — Trình Cài Đặt Web Server 100% Rust từ GitHub Repo ${NC}"
echo -e "${CYAN}================================================================${NC}"

# 1. Kiểm tra quyền root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[LỖI] Vui lòng chạy tập lệnh với quyền root (hoặc dùng sudo).${NC}"
    exit 1
fi

# 2. Nhận diện hệ điều hành Linux
OS="unknown"
DISTRO="unknown"
VERSION_ID="unknown"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO="$ID"
    VERSION_ID="${VERSION_ID:-}"
elif [ -f /etc/debian_version ]; then
    DISTRO="debian"
elif [ -f /etc/redhat-release ]; then
    DISTRO="rhel"
elif [ -f /etc/alpine-release ]; then
    DISTRO="alpine"
fi

echo -e "${YELLOW}[1/6] Phát hiện hệ điều hành:${NC} ${GREEN}${NAME:-$DISTRO} (Kernel: $(uname -r), Arch: $(uname -m))${NC}"

# 3. Cài đặt các gói phụ thuộc cần thiết (C toolchain & Rust)
echo -e "${YELLOW}[2/6] Đang cài đặt công cụ biên dịch (C Compiler & Build Tools)...${NC}"

case "$DISTRO" in
    ubuntu|debian)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq build-essential pkg-config libssl-dev clang llvm curl git
        ;;
    almalinux|rocky|rhel|centos|fedora|cloudlinux)
        if command -v dnf >/dev/null 2>&1; then
            dnf groupinstall -y "Development Tools" || true
            dnf install -y gcc clang llvm make pkgconfig openssl-devel curl git
        else
            yum groupinstall -y "Development Tools" || true
            yum install -y gcc clang llvm make pkgconfig openssl-devel curl git
        fi
        # Mở cờ SELinux kết nối mạng nếu đang bật SELinux
        if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" != "Disabled" ]; then
            setsebool -P httpd_can_network_connect 1 2>/dev/null || true
        fi
        ;;
    alpine)
        apk update
        apk add --no-cache build-base clang llvm pkgconfig openssl-dev curl git bash
        ;;
    arch|manjaro)
        pacman -Sy --noconfirm base-devel clang llvm openssl curl git
        ;;
    *)
        echo -e "${YELLOW}[CẢNH BÁO] Hệ điều hành chưa được liệt kê sẵn ($DISTRO), tiếp tục với công cụ hiện có...${NC}"
        ;;
esac

# 4. Kiểm tra hoặc cài đặt Rust (Cargo) nếu chưa có
echo -e "${YELLOW}[3/6] Kiểm tra môi trường Rust Toolchain...${NC}"
if ! command -v cargo >/dev/null 2>&1; then
    echo -e "${CYAN}Chưa tìm thấy Rust. Đang cài đặt Rust toolchain chính thức (rustup)...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
    export PATH="$HOME/.cargo/bin:$PATH"
fi

if [ -f "$HOME/.cargo/env" ]; then
    . "$HOME/.cargo/env"
fi

echo -e "${GREEN}✓ Rust Toolchain:${NC} $(rustc --version) / $(cargo --version)"

# 5. Lấy mã nguồn từ GitHub nếu chạy qua curl pipe
TEMP_BUILD_DIR=""
CURRENT_DIR="$(pwd)"

if [ -f "$CURRENT_DIR/Cargo.toml" ] && grep -q "ferrousx" "$CURRENT_DIR/Cargo.toml"; then
    BUILD_ROOT="$CURRENT_DIR"
    echo -e "${GREEN}✓ Đang sử dụng thư mục mã nguồn hiện tại:${NC} $BUILD_ROOT"
else
    TEMP_BUILD_DIR=$(mktemp -d /tmp/ferrousx-build-XXXXXX)
    BUILD_ROOT="$TEMP_BUILD_DIR/ferrousx"
    REPO_URL="${FERROUSX_REPO_URL:-"https://github.com/Ferrous-panel/FerrousX.git"}"
    echo -e "${CYAN}Đang clone mã nguồn từ GitHub repo: ${REPO_URL}...${NC}"
    git clone --depth 1 "$REPO_URL" "$BUILD_ROOT"
fi

# 6. Biên dịch Release tối ưu hóa theo vi kiến trúc CPU máy chủ
echo -e "${YELLOW}[4/6] Đang biên dịch FerrousX Engine & ferrousx-ctl CLI (LTO Fat + Target CPU Native)...${NC}"
cd "$BUILD_ROOT"
RUSTFLAGS="-C target-cpu=native" cargo build --release

# 7. Cài đặt file nhị phân vào /usr/local/bin
echo -e "${YELLOW}[5/6] Đang cài đặt nhị phân vào hệ thống...${NC}"
install -m 755 target/release/ferrousx-bin /usr/local/bin/ferrousx-bin
if [ -f target/release/ferrousx-ctl ]; then
    install -m 755 target/release/ferrousx-ctl /usr/local/bin/ferrousx-ctl
else
    # Liên kết mềm sang ferrousx-bin nếu CLI được tích hợp
    ln -sf /usr/local/bin/ferrousx-bin /usr/local/bin/ferrousx-ctl
fi

# Tạo các thư mục cấu hình và runtime
mkdir -p /etc/ferrousx/ssl
mkdir -p /var/log/ferrousx
mkdir -p /run/ferrousx

# Sao chép tệp cấu hình mẫu nếu chưa tồn tại
if [ ! -f /etc/ferrousx/ferrousx.toml ]; then
    if [ -f conf/ferrousx.toml ]; then
        cp conf/ferrousx.toml /etc/ferrousx/ferrousx.toml
    elif [ -f ferrousx.toml ]; then
        cp ferrousx.toml /etc/ferrousx/ferrousx.toml
    fi
    echo -e "${GREEN}✓ Đã tạo cấu hình mặc định tại /etc/ferrousx/ferrousx.toml${NC}"
fi

# 8. Cấu hình tối ưu hóa nhân Linux (sysctl)
echo -e "${YELLOW}[6/6] Cấu hình tối ưu nhân Linux & Systemd Service...${NC}"
if [ -f conf/99-ferrousx-tuning.conf ]; then
    cp conf/99-ferrousx-tuning.conf /etc/sysctl.d/99-ferrousx-tuning.conf
    sysctl --system >/dev/null 2>&1 || true
    echo -e "${GREEN}✓ Đã áp dụng các thông số sysctl tối ưu hóa (UDP GRO/GSO, TCP BBR, somaxconn)${NC}"
fi

# Cài đặt dịch vụ Systemd (hoặc OpenRC trên Alpine)
if [ "$DISTRO" = "alpine" ]; then
    cat << 'EOF_RC' > /etc/init.d/ferrousx
#!/sbin/openrc-run
description="FerrousX High-Performance Web Server"
command="/usr/local/bin/ferrousx-bin"
command_args="/etc/ferrousx/ferrousx.toml"
pidfile="/run/ferrousx.pid"
depend() {
    need net
    after firewall
}
EOF_RC
    chmod +x /etc/init.d/ferrousx
    rc-update add ferrousx default 2>/dev/null || true
    rc-service ferrousx restart 2>/dev/null || rc-service ferrousx start 2>/dev/null || true
else
    cat << 'EOF_SERVICE' > /etc/systemd/system/ferrousx.service
[Unit]
Description=FerrousX High-Performance Web Server & Reverse Proxy
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/ferrousx-bin /etc/ferrousx/ferrousx.toml
ExecReload=/usr/local/bin/ferrousx-ctl reload
KillMode=mixed
TimeoutStopSec=30
Restart=always
RestartSec=1s
OOMScoreAdjust=-1000

# Tối ưu hóa giới hạn File Descriptor và Bộ nhớ Khóa cho io_uring
LimitNOFILE=2097152
LimitMEMLOCK=infinity
LimitNPROC=512000

# Đặc quyền Linux Kernel tối thiểu (Principle of Least Privilege)
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_BPF CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_BPF CAP_NET_ADMIN
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF_SERVICE

    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable ferrousx >/dev/null 2>&1 || true
        systemctl restart ferrousx >/dev/null 2>&1 || systemctl start ferrousx >/dev/null 2>&1 || true
    else
        echo -e "${YELLOW}[LƯU Ý] Hệ thống không chạy systemd trực tiếp (container/chroot). File service đã sẵn sàng tại /etc/systemd/system/ferrousx.service.${NC}"
    fi
fi

# Dọn dẹp thư mục tạm nếu có
if [ -n "$TEMP_BUILD_DIR" ] && [ -d "$TEMP_BUILD_DIR" ]; then
    rm -rf "$TEMP_BUILD_DIR"
fi

echo -e "\n${GREEN}================================================================${NC}"
echo -e "${GREEN}  ✓ CÀI ĐẶT FERROUSX TỪ GITHUB THÀNH CÔNG!                      ${NC}"
echo -e "${GREEN}================================================================${NC}"
echo -e "• Daemon Binary:      ${CYAN}/usr/local/bin/ferrousx-bin${NC}"
echo -e "• Quản trị CLI:        ${CYAN}/usr/local/bin/ferrousx-ctl${NC}"
echo -e "• Cấu hình chính:     ${CYAN}/etc/ferrousx/ferrousx.toml${NC}"
echo -e "• Unix Control Socket:${CYAN}/run/ferrousx/panel-admin.sock${NC}"
echo -e "\nCác lệnh quản trị nhanh:"
echo -e "  ${YELLOW}ferrousx-ctl status${NC}              # Kiểm tra trạng thái máy chủ"
echo -e "  ${YELLOW}ferrousx-ctl top${NC}                 # Mở TUI realtime monitor"
echo -e "  ${YELLOW}ferrousx-ctl panel-sync --detect${NC} # Quét & đồng bộ cPanel/DirectAdmin"
echo -e "  ${YELLOW}ferrousx-ctl test${NC}                # Kiểm tra cú pháp cấu hình"
echo -e "  ${YELLOW}ferrousx-ctl reload${NC}              # Nạp lại cấu hình < 50µs (Zero-Downtime)"
