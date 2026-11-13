#!/usr/bin/env bash
# ==============================================================================
# FerrousX — Production Repair & Self-Healing Script
# Sửa lỗi nhanh trên VPS Ubuntu 22.04/24.04 & Linux:
#   1. Dừng & vô hiệu hóa Nginx tránh xung đột cổng 80/443
#   2. Sinh chứng chỉ TLS tự ký SAN dự phòng (chmod 600 privkey.pem)
#   3. Bảo đảm các thư mục cấu hình & router phpMyAdmin (/phpadmin/, /phpmyadmin/)
#   4. Mở tường lửa 80/tcp, 443/tcp, 443/udp (ufw / firewalld / iptables)
#   5. Cập nhật systemd units & tự động xử lý fallback container capability
#   6. Kiểm tra ferrousx-bin -t / ferrousx-bin -v và hot-reload / khởi động dịch vụ
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[LỖI] Vui lòng chạy repair.sh với quyền root (sudo).${NC}"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo -e "${CYAN}=== FerrousX Production Repair & Diagnostics ===${NC}"

# 1. Dừng & tắt Nginx nếu đang chiếm cổng 80/443
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    if systemctl list-unit-files | grep -q '^nginx\.service' || systemctl is-active --quiet nginx 2>/dev/null; then
        echo -e "${YELLOW}[1/6] Đang dừng & tắt dịch vụ Nginx để tránh xung đột cổng 80/443...${NC}"
        systemctl stop nginx 2>/dev/null || true
        systemctl disable nginx 2>/dev/null || true
    fi
fi

# 2. Bảo đảm cấu trúc thư mục & cấu hình
echo -e "${YELLOW}[2/6] Kiểm tra thư mục, cấu hình và chứng chỉ TLS dự phòng...${NC}"
mkdir -p /etc/ferrousx/ssl \
         /var/log/ferrousx \
         /run/ferrousx \
         /etc/ferrous-panel \
         /www/server/panel/vhost/ferrousx \
         /www/wwwroot/default \
         /usr/local/share/ferrousx

if [ -f "$SCRIPT_DIR/pma-router.php" ]; then
    install -m 644 "$SCRIPT_DIR/pma-router.php" /usr/local/share/ferrousx/pma-router.php
fi

if [ ! -f /etc/ferrousx/ferrousx.toml ] && [ -f "$PROJECT_ROOT/conf/ferrousx.toml" ]; then
    cp "$PROJECT_ROOT/conf/ferrousx.toml" /etc/ferrousx/ferrousx.toml
fi

if [ ! -s /etc/ferrousx/ssl/fullchain.pem ] || [ ! -s /etc/ferrousx/ssl/privkey.pem ]; then
    if command -v openssl >/dev/null 2>&1; then
        HOSTNAME_SAN=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "localhost")
        openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
            -keyout /etc/ferrousx/ssl/privkey.pem \
            -out /etc/ferrousx/ssl/fullchain.pem \
            -subj "/CN=${HOSTNAME_SAN}" \
            -addext "subjectAltName=DNS:localhost,DNS:${HOSTNAME_SAN},IP:127.0.0.1,IP:::1" \
            >/dev/null 2>&1 || true
        echo -e "${GREEN}✓ Đã tạo chứng chỉ TLS SAN fallback tại /etc/ferrousx/ssl/${NC}"
    fi
fi
[ -f /etc/ferrousx/ssl/privkey.pem ] && chmod 600 /etc/ferrousx/ssl/privkey.pem
[ -f /etc/ferrousx/ssl/fullchain.pem ] && chmod 644 /etc/ferrousx/ssl/fullchain.pem

# 3. Kiểm tra nhị phân & cấu hình (-v, -t)
echo -e "${YELLOW}[3/6] Kiểm tra nhị phân ferrousx-bin & cú pháp cấu hình...${NC}"
if [ -x /usr/local/bin/ferrousx-bin ]; then
    /usr/local/bin/ferrousx-bin -v
    /usr/local/bin/ferrousx-bin -t -c /etc/ferrousx/ferrousx.toml
fi
if [ -x /usr/local/bin/ferrousx-ctl ]; then
    /usr/local/bin/ferrousx-ctl test --config /etc/ferrousx/ferrousx.toml
fi

# 4. Mở cổng Firewall (80/tcp, 443/tcp, 443/udp)
echo -e "${YELLOW}[4/6] Mở tường lửa cho 80/tcp, 443/tcp, 443/udp...${NC}"
if command -v ufw >/dev/null 2>&1; then
    ufw allow 80/tcp >/dev/null 2>&1 || true
    ufw allow 443/tcp >/dev/null 2>&1 || true
    ufw allow 443/udp >/dev/null 2>&1 || true
fi
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    firewall-cmd --permanent --add-port=80/tcp --add-port=443/tcp --add-port=443/udp >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
fi
if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
    iptables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
    iptables -C INPUT -p udp --dport 443 -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport 443 -j ACCEPT 2>/dev/null || true
fi

# 5. Sửa chữa systemd units cho FerrousX & phpMyAdmin
echo -e "${YELLOW}[5/6] Cập nhật & kiểm tra Systemd services...${NC}"
if [ -f "$SCRIPT_DIR/ferrousx.service" ]; then
    cp "$SCRIPT_DIR/ferrousx.service" /etc/systemd/system/ferrousx.service
fi

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

# 6. Khởi động / Reload dịch vụ
echo -e "${YELLOW}[6/6] Khởi động lại dịch vụ FerrousX & phpMyAdmin...${NC}"
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable ferrousx >/dev/null 2>&1 || true
    systemctl reset-failed ferrousx 2>/dev/null || true

    systemctl restart ferrousx >/dev/null 2>&1 || true
    sleep 1
    if ! systemctl is-active --quiet ferrousx; then
        echo -e "${YELLOW}[THÔNG BÁO] Kích hoạt profile tương thích container cho ferrousx.service...${NC}"
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
        systemctl reset-failed ferrousx 2>/dev/null || true
        systemctl restart ferrousx
    fi

    if [ -f /etc/systemd/system/ferrous-pma.service ]; then
        systemctl enable ferrous-pma >/dev/null 2>&1 || true
        systemctl reset-failed ferrous-pma 2>/dev/null || true
        systemctl restart ferrous-pma >/dev/null 2>&1 || true
        sleep 2

        PMA_PORT_OK=0
        if systemctl is-active --quiet ferrous-pma; then
            if ! command -v ss >/dev/null 2>&1 || ss -tln 2>/dev/null | grep -qE ':888[[:space:]]'; then
                PMA_PORT_OK=1
            fi
        fi

        if [ "$PMA_PORT_OK" -eq 0 ]; then
            echo -e "${YELLOW}[THÔNG BÁO] Chuyển fallback User=root cho ferrous-pma.service (cổng 888)...${NC}"
            mkdir -p /etc/systemd/system/ferrous-pma.service.d
            cat << 'EOF_PMA_OV' > /etc/systemd/system/ferrous-pma.service.d/root-fallback.conf
[Service]
User=root
Group=root
AmbientCapabilities=
CapabilityBoundingSet=
EOF_PMA_OV
            systemctl daemon-reload
            systemctl reset-failed ferrous-pma 2>/dev/null || true
            systemctl restart ferrous-pma || true
            sleep 1
        fi
    fi
fi

if command -v ss >/dev/null 2>&1; then
    echo -e "\n${CYAN}Trạng thái cổng đang lắng nghe:${NC}"
    ss -tulpn | grep -E ':(80|443|888)\b' || true
fi

echo -e "${GREEN}✓ Quá trình sửa chữa & đồng bộ FerrousX hoàn tất.${NC}"
