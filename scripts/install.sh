#!/usr/bin/env bash
# ==============================================================================
# FerrousX — Universal Linux Installer (Ubuntu 22.04/24.04, Debian, RHEL, Alpine)
# Cài đặt trực tiếp từ GitHub: https://github.com/Ferrous-panel/FerrousX
# - Biên dịch Rust Engine 100% Native (TCP :80 + TCP :443 + UDP :443)
# - Tự động sinh TLS SAN Fallback (/etc/ferrousx/ssl/fullchain.pem & privkey.pem chmod 600)
# - Dừng & tắt Nginx tránh xung đột cổng 80/443
# - Mở tường lửa UFW / iptables / firewalld cho 80/tcp, 443/tcp, 443/udp
# - Cài đặt systemd service cho FerrousX & phpMyAdmin (ferrous-pma.service)
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}================================================================${NC}"
echo -e "${CYAN}   FerrousX — Cài Đặt Web Server & Reverse Proxy 100% Rust      ${NC}"
echo -e "${CYAN}================================================================${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[LỖI] Vui lòng chạy tập lệnh với quyền root (sudo).${NC}"
    exit 1
fi

DISTRO="unknown"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO="${ID:-unknown}"
elif [ -f /etc/debian_version ]; then
    DISTRO="debian"
elif [ -f /etc/redhat-release ]; then
    DISTRO="rhel"
elif [ -f /etc/alpine-release ]; then
    DISTRO="alpine"
fi

echo -e "${YELLOW}[1/7] Hệ điều hành:${NC} ${GREEN}${NAME:-$DISTRO} (Kernel: $(uname -r), Arch: $(uname -m))${NC}"

# 1. Cài đặt gói phụ thuộc biên dịch & openssl
echo -e "${YELLOW}[2/7] Cài đặt công cụ biên dịch & OpenSSL...${NC}"
case "$DISTRO" in
    ubuntu|debian)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq build-essential pkg-config libssl-dev clang llvm curl git openssl ca-certificates
        ;;
    almalinux|rocky|rhel|centos|fedora|cloudlinux)
        if command -v dnf >/dev/null 2>&1; then
            dnf groupinstall -y "Development Tools" || true
            dnf install -y gcc clang llvm make pkgconfig openssl-devel openssl curl git ca-certificates
        else
            yum groupinstall -y "Development Tools" || true
            yum install -y gcc clang llvm make pkgconfig openssl-devel openssl curl git ca-certificates
        fi
        if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" != "Disabled" ]; then
            setsebool -P httpd_can_network_connect 1 2>/dev/null || true
        fi
        ;;
    alpine)
        apk update
        apk add --no-cache build-base clang llvm pkgconfig openssl-dev openssl curl git bash ca-certificates
        ;;
    arch|manjaro)
        pacman -Sy --noconfirm base-devel clang llvm openssl curl git ca-certificates
        ;;
    *)
        echo -e "${YELLOW}[CẢNH BÁO] Distro chưa có trong danh sách sẵn ($DISTRO), tiếp tục với công cụ hiện có...${NC}"
        ;;
esac

# 2. Cài đặt hoặc kiểm tra Rust Toolchain
echo -e "${YELLOW}[3/7] Kiểm tra môi trường Rust Toolchain...${NC}"
if [ -f "$HOME/.cargo/env" ]; then
    . "$HOME/.cargo/env"
fi
if ! command -v cargo >/dev/null 2>&1; then
    echo -e "${CYAN}Đang cài đặt Rust Toolchain chính thức (rustup)...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
    export PATH="$HOME/.cargo/bin:$PATH"
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
fi
echo -e "${GREEN}✓ Rust:${NC} $(rustc --version) / $(cargo --version)"

# 3. Chuẩn bị mã nguồn
TEMP_BUILD_DIR=""
CURRENT_DIR="$(pwd)"
if [ -f "$CURRENT_DIR/Cargo.toml" ] && grep -q "ferrousx" "$CURRENT_DIR/Cargo.toml"; then
    BUILD_ROOT="$CURRENT_DIR"
    echo -e "${GREEN}✓ Sử dụng mã nguồn tại:${NC} $BUILD_ROOT"
else
    TEMP_BUILD_DIR=$(mktemp -d /tmp/ferrousx-build-XXXXXX)
    BUILD_ROOT="$TEMP_BUILD_DIR/ferrousx"
    REPO_URL="${FERROUSX_REPO_URL:-"https://github.com/Ferrous-panel/FerrousX.git"}"
    echo -e "${CYAN}Đang clone mã nguồn từ GitHub: ${REPO_URL}...${NC}"
    git clone --depth 1 "$REPO_URL" "$BUILD_ROOT"
fi

# 4. Biên dịch Release tối ưu
echo -e "${YELLOW}[4/7] Đang biên dịch FerrousX Engine & ferrousx-ctl CLI...${NC}"
cd "$BUILD_ROOT"
RUSTFLAGS="-C target-cpu=native" cargo build --release --workspace

# 5. Cài đặt binary, router script và thư mục hệ thống
echo -e "${YELLOW}[5/7] Cài đặt tệp nhị phân & cấu hình chuẩn Production...${NC}"
install -m 755 target/release/ferrousx-bin /usr/local/bin/ferrousx-bin
install -m 755 target/release/ferrousx-ctl /usr/local/bin/ferrousx-ctl

mkdir -p /etc/ferrousx/ssl \
         /var/log/ferrousx \
         /run/ferrousx \
         /etc/ferrous-panel \
         /www/server/panel/vhost/ferrousx \
         /www/wwwroot/default \
         /usr/local/share/ferrousx

if [ -f scripts/pma-router.php ]; then
    install -m 644 scripts/pma-router.php /usr/local/share/ferrousx/pma-router.php
fi

if [ ! -f /etc/ferrousx/ferrousx.toml ]; then
    cp conf/ferrousx.toml /etc/ferrousx/ferrousx.toml
    echo -e "${GREEN}✓ Đã tạo /etc/ferrousx/ferrousx.toml${NC}"
fi

if [ ! -f /www/wwwroot/default/index.html ]; then
    cat << 'EOF_HTML' > /www/wwwroot/default/index.html
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>FerrousX Web Server</title></head>
<body style="font-family:system-ui,sans-serif;background:#0b1120;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">
  <div style="text-align:center;max-width:520px;padding:2rem;border:1px solid #1e293b;border-radius:12px;background:#111827">
    <h1 style="margin:0 0 .5rem;color:#f59e0b">FerrousX Ready</h1>
    <p style="margin:0;color:#94a3b8">Triple-Stack Rust Web Server &amp; Reverse Proxy (HTTP/1.1, HTTP/2 TLS, HTTP/3 QUIC)</p>
  </div>
</body>
</html>
EOF_HTML
fi

# Sinh chứng chỉ TLS tự ký SAN fallback nếu chưa tồn tại (tránh Cloudflare Error 521)
if [ ! -s /etc/ferrousx/ssl/fullchain.pem ] || [ ! -s /etc/ferrousx/ssl/privkey.pem ]; then
    if command -v openssl >/dev/null 2>&1; then
        HOSTNAME_SAN=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "localhost")
        openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
            -keyout /etc/ferrousx/ssl/privkey.pem \
            -out /etc/ferrousx/ssl/fullchain.pem \
            -subj "/CN=${HOSTNAME_SAN}" \
            -addext "subjectAltName=DNS:localhost,DNS:${HOSTNAME_SAN},IP:127.0.0.1,IP:::1" \
            >/dev/null 2>&1 || true
    fi
fi
[ -f /etc/ferrousx/ssl/privkey.pem ] && chmod 600 /etc/ferrousx/ssl/privkey.pem
[ -f /etc/ferrousx/ssl/fullchain.pem ] && chmod 644 /etc/ferrousx/ssl/fullchain.pem

# Kiểm tra CLI -v và -t trước khi khởi động
/usr/local/bin/ferrousx-bin -v
/usr/local/bin/ferrousx-bin -t -c /etc/ferrousx/ferrousx.toml
/usr/local/bin/ferrousx-ctl test --config /etc/ferrousx/ferrousx.toml

# 6. Tối ưu Kernel, Mở Firewall & Tắt Nginx tránh xung đột cổng 80/443
echo -e "${YELLOW}[6/7] Tối ưu Kernel, mở Firewall (80/443 TCP+UDP) & dọn xung đột Nginx...${NC}"
if [ -f conf/99-ferrousx-tuning.conf ]; then
    cp conf/99-ferrousx-tuning.conf /etc/sysctl.d/99-ferrousx-tuning.conf
    sysctl --system >/dev/null 2>&1 || true
fi

# Mở cổng tường lửa: 80/tcp, 443/tcp, 443/udp
if command -v ufw >/dev/null 2>&1; then
    ufw allow 80/tcp >/dev/null 2>&1 || true
    ufw allow 443/tcp >/dev/null 2>&1 || true
    ufw allow 443/udp >/dev/null 2>&1 || true
    echo -e "${GREEN}✓ Đã mở quy tắc UFW cho 80/tcp, 443/tcp, 443/udp${NC}"
fi
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    firewall-cmd --permanent --add-port=80/tcp --add-port=443/tcp --add-port=443/udp >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    echo -e "${GREEN}✓ Đã mở quy tắc firewalld cho 80/tcp, 443/tcp, 443/udp${NC}"
fi
if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
    iptables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
    iptables -C INPUT -p udp --dport 443 -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport 443 -j ACCEPT 2>/dev/null || true
fi

# Dừng & tắt Nginx trước khi bật FerrousX
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    if systemctl list-unit-files | grep -q '^nginx\.service'; then
        systemctl stop nginx 2>/dev/null || true
        systemctl disable nginx 2>/dev/null || true
        echo -e "${GREEN}✓ Đã dừng & tắt Nginx để giải phóng cổng 80/443${NC}"
    fi
fi

# 7. Cài đặt Systemd Units (FerrousX + phpMyAdmin)
echo -e "${YELLOW}[7/7] Cài đặt & kích hoạt Systemd Services...${NC}"
if [ "$DISTRO" = "alpine" ]; then
    cat << 'EOF_RC' > /etc/init.d/ferrousx
#!/sbin/openrc-run
description="FerrousX High-Performance Web Server"
command="/usr/local/bin/ferrousx-bin"
command_args="-c /etc/ferrousx/ferrousx.toml"
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
    cp scripts/ferrousx.service /etc/systemd/system/ferrousx.service

    # Cài đặt ferrous-pma.service nếu có php & thư mục phpMyAdmin
    PMA_DIR=""
    for candidate in /www/server/phpmyadmin /usr/share/phpmyadmin /var/www/phpmyadmin /var/www/html/phpmyadmin; do
        if [ -d "$candidate" ] && [ -f "$candidate/index.php" ]; then
            PMA_DIR="$candidate"
            break
        fi
    done

    if [ -n "$PMA_DIR" ] && command -v php >/dev/null 2>&1; then
        PHP_BIN=$(command -v php)
        cat << EOF_PMA > /etc/systemd/system/ferrous-pma.service
[Unit]
Description=Ferrous Panel phpMyAdmin Service (Cloudflare Prefix Compatible)
After=network.target network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=${PMA_DIR}
Environment=PHP_CLI_SERVER_WORKERS=4
Environment=FERROUS_PMA_ROOT=${PMA_DIR}
ExecStart=${PHP_BIN} -S 0.0.0.0:888 -t ${PMA_DIR} /usr/local/share/ferrousx/pma-router.php
Restart=always
RestartSec=2s
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF_PMA
    fi

    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl daemon-reload
        systemctl enable ferrousx >/dev/null 2>&1 || true

        if ! systemctl restart ferrousx >/dev/null 2>&1; then
            echo -e "${YELLOW}[THÔNG BÁO] Phát hiện giới hạn sandbox/container với systemd, áp dụng drop-in tương thích container...${NC}"
            mkdir -p /etc/systemd/system/ferrousx.service.d
            cat << 'EOF_COMPAT' > /etc/systemd/system/ferrousx.service.d/container-compat.conf
[Service]
OOMScoreAdjust=0
MemoryDenyWriteExecute=false
ProtectSystem=full
RestrictRealtime=false
PrivateDevices=false
CapabilityBoundingSet=
AmbientCapabilities=
EOF_COMPAT
            systemctl daemon-reload
            systemctl restart ferrousx
        fi

        if [ -f /etc/systemd/system/ferrous-pma.service ]; then
            systemctl enable ferrous-pma >/dev/null 2>&1 || true
            if ! systemctl restart ferrous-pma >/dev/null 2>&1 || ! systemctl is-active --quiet ferrous-pma; then
                echo -e "${YELLOW}[THÔNG BÁO] Kernel container chặn CAP_NET_BIND_SERVICE cho www-data:888 -> Chuyển fallback User=root cho ferrous-pma...${NC}"
                mkdir -p /etc/systemd/system/ferrous-pma.service.d
                cat << 'EOF_PMA_OV' > /etc/systemd/system/ferrous-pma.service.d/root-fallback.conf
[Service]
User=root
Group=root
AmbientCapabilities=
CapabilityBoundingSet=
EOF_PMA_OV
                systemctl daemon-reload
                systemctl restart ferrous-pma || true
            fi
        fi
    else
        echo -e "${YELLOW}[LƯU Ý] Không có systemd đang chạy (container/chroot). File service đã sẵn sàng tại /etc/systemd/system/.${NC}"
    fi
fi

if [ -n "$TEMP_BUILD_DIR" ] && [ -d "$TEMP_BUILD_DIR" ]; then
    rm -rf "$TEMP_BUILD_DIR"
fi

echo -e "\n${GREEN}================================================================${NC}"
echo -e "${GREEN}  ✓ CÀI ĐẶT FERROUSX PRODUCTION THÀNH CÔNG!                     ${NC}"
echo -e "${GREEN}================================================================${NC}"
echo -e "• Daemon Binary:      ${CYAN}/usr/local/bin/ferrousx-bin${NC}"
echo -e "• Quản trị CLI:        ${CYAN}/usr/local/bin/ferrousx-ctl${NC}"
echo -e "• Cấu hình chính:     ${CYAN}/etc/ferrousx/ferrousx.toml${NC}"
echo -e "• Chứng chỉ TLS SAN:  ${CYAN}/etc/ferrousx/ssl/fullchain.pem${NC}"
echo -e "• Thư mục Vhost:      ${CYAN}/www/server/panel/vhost/ferrousx/*.conf${NC}"
echo -e "• Đồng bộ Panel JSON: ${CYAN}/etc/ferrous-panel/admin.json${NC}"
echo -e "\nCác lệnh kiểm tra:"
echo -e "  ${YELLOW}ferrousx-bin -t${NC}                  # Kiểm tra cấu hình"
echo -e "  ${YELLOW}ferrousx-bin -v${NC}                  # Xem phiên bản"
echo -e "  ${YELLOW}ferrousx-ctl reload${NC}              # Hot-reload không gián đoạn (SIGHUP/ArcSwap)"
echo -e "  ${YELLOW}ss -tulnp | grep -E '80|443|888'${NC} # Xác minh TCP :80/:443 + UDP :443"
