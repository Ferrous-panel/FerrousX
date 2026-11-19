#!/usr/bin/env bash
# ==============================================================================
# FERROUSX VPS TERMINAL ADMIN CLI (ferrousx-admin / fx)
# Lệnh quản trị nhanh trên Terminal VPS (tương tự lệnh 'bt' / 'ferrous-panel'):
#   - Gõ `fx` hoặc `ferrousx-admin` để mở Bảng điều khiển Admin tương tác (1-14)
#   - Hoặc dùng lệnh nhanh:
#       fx status | fx info | fx reload | fx restart | fx stop | fx start
#       fx test   | fx token [--rotate] | fx vhost list | fx vhost add <domain>
#       fx logs   | fx pma-restart | fx repair | fx harden
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

CONFIG_FILE="/etc/ferrousx/ferrousx.toml"
TOKEN_FILE="/etc/ferrousx/admin.token"
SITES_DIR="/etc/ferrousx/sites"

show_overview() {
    echo -e "${CYAN}======================================================================${NC}"
    echo -e "${GREEN}   ⚡ FERROUSX VPS ADMIN OVERVIEW (100% NATIVE RUST ENGINE)${NC}"
    echo -e "${CYAN}======================================================================${NC}"
    if systemctl is-active --quiet ferrousx.service 2>/dev/null; then
        echo -e " • Trạng thái FerrousX : ${GREEN}ACTIVE (RUNNING)${NC}"
    else
        echo -e " • Trạng thái FerrousX : ${RED}INACTIVE / STOPPED${NC}"
    fi
    if systemctl is-active --quiet ferrous-pma.service 2>/dev/null; then
        echo -e " • phpMyAdmin Nội bộ   : ${GREEN}ACTIVE (127.0.0.1:888 -> /phpadmin/)${NC}"
    else
        echo -e " • phpMyAdmin Nội bộ   : ${YELLOW}STANDBY / NOT INSTALLED${NC}"
    fi
    echo -e " • Cấu hình chính      : ${CONFIG_FILE}"
    echo -e " • Thư mục VirtualHost : ${SITES_DIR}/*.toml"
    echo -e " • Chứng chỉ TLS       : /etc/ferrousx/ssl/fullchain.pem"
    echo -e " • Local Web Dashboard : http://127.0.0.1:9090"
    if [[ -f "$TOKEN_FILE" ]]; then
        tok="$(tr -d ' \r\n' < "$TOKEN_FILE" 2>/dev/null || true)"
        echo -e " • Admin Token (0600)  : ${YELLOW}${tok}${NC}"
    fi
    echo -e "${CYAN}----------------------------------------------------------------------${NC}"
    echo -e " • Các cổng đang lắng nghe (80 / 443 / 888 / 9090):"
    ss -tulpn 2>/dev/null | grep -E ':(80|443|888|9090)\b' || echo "   (Cần quyền root/sudo để xem chi tiết socket)"
    echo -e "${CYAN}======================================================================${NC}"
}

rotate_token() {
    mkdir -p /etc/ferrousx
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$TOKEN_FILE"
    echo "" >> "$TOKEN_FILE"
    chmod 600 "$TOKEN_FILE"
    chown ferrousx:ferrousx "$TOKEN_FILE" 2>/dev/null || true
    echo -e "${GREEN}✓ Đã tạo khóa Admin Token 256-bit mới tại ${TOKEN_FILE}:${NC}"
    cat "$TOKEN_FILE"
}

case "${1:-menu}" in
    status|info)
        show_overview
        if command -v ferrousx-ctl >/dev/null 2>&1; then
            ferrousx-ctl status 2>/dev/null || true
        fi
        ;;
    test|check)
        /usr/local/bin/ferrousx-bin --check-config --config "$CONFIG_FILE"
        ;;
    reload)
        if command -v ferrousx-ctl >/dev/null 2>&1; then
            ferrousx-ctl reload
        else
            systemctl reload ferrousx.service || killall -HUP ferrousx-bin
        fi
        ;;
    restart)
        systemctl restart ferrousx.service
        echo -e "${GREEN}✓ Đã khởi động lại dịch vụ ferrousx.service${NC}"
        ;;
    start)
        systemctl start ferrousx.service
        echo -e "${GREEN}✓ Đã khởi động dịch vụ ferrousx.service${NC}"
        ;;
    stop)
        systemctl stop ferrousx.service
        echo -e "${YELLOW}✓ Đã dừng dịch vụ ferrousx.service${NC}"
        ;;
    pma-restart)
        systemctl restart ferrous-pma.service
        echo -e "${GREEN}✓ Đã khởi động lại dịch vụ ferrous-pma.service (127.0.0.1:888)${NC}"
        ;;
    token)
        if [[ "${2:-}" == "--rotate" ]]; then
            rotate_token
        elif [[ -f "$TOKEN_FILE" ]]; then
            echo -e "Admin Token (${TOKEN_FILE}): ${YELLOW}$(cat "$TOKEN_FILE")${NC}"
        else
            rotate_token
        fi
        ;;
    logs|log)
        journalctl -u ferrousx.service -n "${2:-50}" --no-pager
        ;;
    vhost)
        shift
        exec /usr/local/bin/ferrousx-ctl vhost "$@"
        ;;
    panel-sync|sync)
        exec /usr/local/bin/ferrousx-ctl panel-sync --panel "${2:-auto}"
        ;;
    repair)
        if [[ -f /usr/local/src/FerrousX/scripts/repair.sh ]]; then
            exec bash /usr/local/src/FerrousX/scripts/repair.sh --yes
        else
            /usr/local/bin/ferrousx-bin --check-config --config "$CONFIG_FILE"
            systemctl restart ferrousx.service
        fi
        ;;
    harden)
        if [[ -f /usr/local/src/FerrousX/scripts/security-hardening.sh ]]; then
            exec bash /usr/local/src/FerrousX/scripts/security-hardening.sh
        fi
        ;;
    menu|admin)
        if command -v ferrousx-ctl >/dev/null 2>&1; then
            exec /usr/local/bin/ferrousx-ctl admin
        else
            show_overview
        fi
        ;;
    --help|-h|help)
        echo "Cách dùng lệnh quản trị FerrousX trên Terminal VPS:"
        echo "  fx                         : Mở Menu Quản trị Tương tác (Interactive Admin Console)"
        echo "  fx info | fx status        : Xem tổng quan Server, Ports, SSL & Admin Token"
        echo "  fx test                    : Kiểm tra cú pháp cấu hình & chứng chỉ SSL"
        echo "  fx reload                  : Hot-Reload cấu hình Zero-Downtime (< 50µs RCU)"
        echo "  fx restart | start | stop  : Quản lý systemd service ferrousx"
        echo "  fx pma-restart             : Khởi động lại phpMyAdmin nội bộ (127.0.0.1:888)"
        echo "  fx vhost list              : Liệt kê danh sách Website VirtualHosts"
        echo "  fx vhost add <domain> --root /www/wwwroot/<domain> --php 8.3"
        echo "  fx vhost del <domain>      : Xóa Website VirtualHost"
        echo "  fx token [--rotate]        : Xem hoặc đổi khóa Admin Token 256-bit"
        echo "  fx logs [N]                : Xem N dòng nhật ký mới nhất của FerrousX"
        echo "  fx repair                  : Tự động kiểm tra và sửa chữa dịch vụ"
        ;;
    *)
        exec /usr/local/bin/ferrousx-ctl "$@"
        ;;
esac
