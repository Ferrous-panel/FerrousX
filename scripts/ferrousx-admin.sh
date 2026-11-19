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

ENV_FILE="${FERROUSX_ENV_FILE:-/etc/ferrousx/ferrousx.env}"

# Nạp an toàn các biến môi trường từ /etc/ferrousx/ferrousx.env (không dùng eval, không chạy lệnh nhúng)
load_ferrousx_env_safe() {
    local file="$1"
    [[ -f "$file" && ! -L "$file" && -r "$file" ]] || return 0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$line" || "$line" == \#* ]] && continue
        line="${line#export }"
        [[ "$line" == *=* ]] || continue
        local k="${line%%=*}"
        local v="${line#*=}"
        k="${k//[[:space:]]/}"
        [[ "$k" =~ ^[A-Z][A-Z0-9_]*$ ]] || continue
        v="${v#"${v%%[![:space:]]*}"}"
        v="${v%"${v##*[![:space:]]}"}"
        if [[ "$v" == \"*\" && "$v" == *\" && ${#v} -ge 2 ]]; then
            v="${v:1:${#v}-2}"
        elif [[ "$v" == \'*\' && "$v" == *\' && ${#v} -ge 2 ]]; then
            v="${v:1:${#v}-2}"
        fi
        # Không ghi đè biến đã được truyền trực tiếp qua Process ENV
        if [[ -z "${!k:-}" ]]; then
            export "$k=$v"
        fi
    done < "$file"
}

load_ferrousx_env_safe "$ENV_FILE"

CONFIG_FILE="${FERROUSX_CONFIG:-/etc/ferrousx/ferrousx.toml}"
TOKEN_FILE="${FERROUSX_ADMIN_TOKEN_FILE:-/etc/ferrousx/admin.token}"
SITES_DIR="${FERROUSX_SITES_DIR:-/etc/ferrousx/sites}"
DASHBOARD_ADDR="${FERROUSX_DASHBOARD_ADDR:-127.0.0.1:9090}"

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
    echo -e " • Biến môi trường     : ${ENV_FILE}"
    echo -e " • Thư mục VirtualHost : ${SITES_DIR}/*.toml"
    echo -e " • Chứng chỉ TLS       : /etc/ferrousx/ssl/fullchain.pem"
    echo -e " • Local Web Dashboard : http://${DASHBOARD_ADDR}"
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

manage_env_vars() {
    local subcmd="${1:-show}"
    case "$subcmd" in
        show|list)
            echo -e "${CYAN}=== BIẾN MÔI TRƯỜNG FERROUSX (${ENV_FILE}) ===${NC}"
            if [[ -f "$ENV_FILE" ]]; then
                while IFS= read -r line || [[ -n "$line" ]]; do
                    if [[ "$line" =~ ^[[:space:]]*(export[[:space:]]+)?([A-Z0-9_]*(TOKEN|SECRET|PASSWORD|KEY)[A-Z0-9_]*)= ]]; then
                        local k="${BASH_REMATCH[2]}"
                        if [[ "$k" != *_FILE && "$k" != *_KEY ]]; then
                            echo "${k}=(masked)"
                            continue
                        fi
                    fi
                    echo "$line"
                done < "$ENV_FILE"
            else
                echo -e "${YELLOW}Chưa có tệp ${ENV_FILE}. Chạy 'sudo fx env init' để tự động khởi tạo.${NC}"
            fi
            ;;
        init|sync)
            mkdir -p "$(dirname "$ENV_FILE")"
            if [[ ! -f "$ENV_FILE" ]]; then
                install -m 0640 /dev/null "$ENV_FILE"
                cat << 'EOF' > "$ENV_FILE"
# FERROUSX RUNTIME ENVIRONMENT VARIABLES
FERROUSX_CONFIG="/etc/ferrousx/ferrousx.toml"
FERROUSX_ENV_FILE="/etc/ferrousx/ferrousx.env"
FERROUSX_SITES_DIR="/etc/ferrousx/sites"
FERROUSX_ACME_WEBROOT="/www/acme"
FERROUSX_CONTROL_SOCKET="/run/ferrousx/panel-admin.sock"
FERROUSX_ADMIN_TOKEN_FILE="/etc/ferrousx/admin.token"
FERROUSX_BIND_HTTP="0.0.0.0:80"
FERROUSX_BIND_HTTPS="0.0.0.0:443"
FERROUSX_BIND_UDP="0.0.0.0:443"
FERROUSX_WORKERS="0"
FERROUSX_ENABLE_HTTP3="true"
FERROUSX_WAF_MODE="block"
FERROUSX_SERVER_TOKENS="false"
FERROUSX_ENABLE_DYNAMIC_WWWROOT="false"
FERROUSX_ENABLE_DASHBOARD="true"
FERROUSX_DASHBOARD_ADDR="127.0.0.1:9090"
FERROUSX_ENABLE_PHPMYADMIN="true"
FERROUSX_PHPMYADMIN_UPSTREAM="127.0.0.1:888"
FERROUSX_PANEL_ENV="/etc/ferrous-panel/panel.env"
FERROUSX_PANEL_ADMIN_JSON="/etc/ferrous-panel/admin.json"
RUST_LOG="ferrousx=info"
EOF
            fi
            chmod 0640 "$ENV_FILE"
            chown ferrousx:ferrousx "$ENV_FILE" 2>/dev/null || true
            echo -e "${GREEN}✓ Đã khởi tạo & đồng bộ biến môi trường tại ${ENV_FILE} (mode 0640).${NC}"
            ;;
        set)
            local kv="${2:-}"
            if [[ -z "$kv" || "$kv" != *=* ]]; then
                echo -e "${RED}Cách dùng: sudo fx env set KEY=VALUE${NC}" >&2
                exit 1
            fi
            local key="${kv%%=*}"
            local val="${kv#*=}"
            if [[ ! "$key" =~ ^[A-Z][A-Z0-9_]*$ ]]; then
                echo -e "${RED}Tên biến môi trường không hợp lệ: ${key}${NC}" >&2
                exit 1
            fi
            if [[ "$val" == *$'\n'* || "$val" == *$'\r'* ]]; then
                echo -e "${RED}Giá trị biến môi trường không được chứa ký tự xuống dòng.${NC}" >&2
                exit 1
            fi
            mkdir -p "$(dirname "$ENV_FILE")"
            [[ -f "$ENV_FILE" ]] || install -m 0640 /dev/null "$ENV_FILE"
            local tmp_file
            tmp_file="$(mktemp "$(dirname "$ENV_FILE")/.ferrousx.env.XXXXXX")"
            grep -vE "^[[:space:]]*(export[[:space:]]+)?${key}=" "$ENV_FILE" > "$tmp_file" || true
            printf '%s="%s"\n' "$key" "${val//\"/\\\"}" >> "$tmp_file"
            chmod 0640 "$tmp_file"
            chown ferrousx:ferrousx "$tmp_file" 2>/dev/null || true
            mv -f "$tmp_file" "$ENV_FILE"
            echo -e "${GREEN}✓ Đã cập nhật ${key} trong ${ENV_FILE}.${NC}"
            echo -e "  Chạy 'sudo fx reload' (hoặc 'sudo fx restart' nếu đổi cổng bind) để áp dụng."
            ;;
        *)
            echo "Cách dùng: fx env [show | init | set KEY=VALUE]" >&2
            exit 1
            ;;
    esac
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
    env)
        shift
        manage_env_vars "$@"
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
        echo "  fx env [show|init|set K=V] : Xem, tự động tạo hoặc cập nhật biến môi trường"
        echo "  fx logs [N]                : Xem N dòng nhật ký mới nhất của FerrousX"
        echo "  fx repair                  : Tự động kiểm tra và sửa chữa dịch vụ"
        ;;
    *)
        exec /usr/local/bin/ferrousx-ctl "$@"
        ;;
esac
