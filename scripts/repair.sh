#!/usr/bin/env bash
# ==============================================================================
# FERROUSX PRODUCTION REPAIR & VERIFICATION SCRIPT (100% NATIVE RUST)
# Sửa lỗi và kiểm tra toàn diện nhưng KHÔNG làm giảm bảo mật hệ thống:
#   - Hỗ trợ --dry-run, --check, --rollback, --yes
#   - Tự động sao lưu trước khi sửa chữa tại /var/backups/ferrousx/<timestamp>
#   - Giữ nguyên Systemd Sandboxing (không tạo drop-in tắt MemoryDenyWriteExecute)
#   - Đảm bảo phpMyAdmin chỉ bind trên Loopback 127.0.0.1:888 với User=www-data
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${CYAN}[REPAIR]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[FIXED]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err()   { echo -e "${RED}[ERROR]${NC} $1" >&2; }

DRY_RUN=0
CHECK_ONLY=0
ROLLBACK_MODE=0
AUTO_YES=0

for arg in "$@"; do
    case "$arg" in
        --dry-run)  DRY_RUN=1 ;;
        --check)    CHECK_ONLY=1 ;;
        --rollback) ROLLBACK_MODE=1 ;;
        --yes|-y)   AUTO_YES=1 ;;
        --help|-h)
            echo "Cách dùng: sudo bash scripts/repair.sh [--dry-run] [--check] [--rollback] [--yes]"
            exit 0
            ;;
        *)
            log_err "Tham số không hợp lệ: $arg"
            exit 1
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$CHECK_ONLY" -eq 1 ]]; then
    exec bash "${SCRIPT_DIR}/install.sh" --check
fi
if [[ "$ROLLBACK_MODE" -eq 1 ]]; then
    exec bash "${SCRIPT_DIR}/install.sh" --rollback
fi

if [[ "$EUID" -ne 0 && "$DRY_RUN" -eq 0 ]]; then
    log_err "Vui lòng chạy script với quyền root: sudo bash scripts/repair.sh"
    exit 1
fi

PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BACKUP_BASE="/var/backups/ferrousx"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)_repair"
BACKUP_DIR="${BACKUP_BASE}/${TIMESTAMP}"

run_cmd() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo -e "${YELLOW}[DRY-RUN]${NC} $*"
    else
        "$@"
    fi
}

# 1. Sao lưu cấu hình hiện tại trước khi sửa chữa
log_info "Sao lưu cấu hình hiện tại vào ${BACKUP_DIR}..."
run_cmd mkdir -p "$BACKUP_DIR"
if [[ "$DRY_RUN" -eq 0 && -d /etc/ferrousx ]]; then
    mkdir -p "${BACKUP_DIR}/etc_ferrousx"
    cp -a /etc/ferrousx/. "${BACKUP_DIR}/etc_ferrousx/" || true
fi

# 2. Xóa bỏ các systemd drop-in kém an toàn từng được tạo bởi phiên bản cũ (nếu có)
if [[ -d /etc/systemd/system/ferrousx.service.d || -d /etc/systemd/system/ferrous-pma.service.d ]]; then
    log_info "Gỡ bỏ các drop-in làm yếu Systemd Sandboxing hoặc chạy root-fallback..."
    run_cmd rm -rf /etc/systemd/system/ferrousx.service.d /etc/systemd/system/ferrous-pma.service.d
fi

# 3. Đảm bảo chứng chỉ TLS dự phòng & Admin Token có quyền chuẩn 0600
SSL_CERT="/etc/ferrousx/ssl/fullchain.pem"
SSL_KEY="/etc/ferrousx/ssl/privkey.pem"
ADMIN_TOKEN_FILE="/etc/ferrousx/admin.token"

run_cmd mkdir -p /etc/ferrousx/ssl /etc/ferrousx/sites /www/acme/.well-known/acme-challenge /run/ferrousx
if [[ ! -s "$SSL_CERT" || ! -s "$SSL_KEY" ]]; then
    log_info "Tái tạo chứng chỉ TLS SAN dự phòng..."
    if [[ "$DRY_RUN" -eq 0 ]]; then
        install -m 0600 /dev/null "$SSL_KEY"
        openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
            -keyout "$SSL_KEY" \
            -out "$SSL_CERT" \
            -subj "/C=VN/ST=Hanoi/L=Hanoi/O=FerrousX/CN=localhost"
    fi
fi
[[ -f "$SSL_KEY" ]] && run_cmd chmod 0600 "$SSL_KEY"
[[ -f "$SSL_CERT" ]] && run_cmd chmod 0644 "$SSL_CERT"

if [[ ! -s "$ADMIN_TOKEN_FILE" ]]; then
    log_info "Khởi tạo Admin Token 256-bit tại ${ADMIN_TOKEN_FILE}..."
    if [[ "$DRY_RUN" -eq 0 ]]; then
        install -m 0600 /dev/null "$ADMIN_TOKEN_FILE"
        head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$ADMIN_TOKEN_FILE"
        echo "" >> "$ADMIN_TOKEN_FILE"
    fi
fi
[[ -f "$ADMIN_TOKEN_FILE" ]] && run_cmd chmod 0600 "$ADMIN_TOKEN_FILE"

# 4. Cập nhật systemd service chuẩn bảo mật
run_cmd install -m 0644 "${PROJECT_ROOT}/scripts/pma-router.php" /etc/ferrousx/pma-router.php
run_cmd install -m 0644 "${PROJECT_ROOT}/scripts/ferrous-pma.service" /etc/systemd/system/ferrous-pma.service
run_cmd install -m 0644 "${PROJECT_ROOT}/scripts/ferrousx.service" /etc/systemd/system/ferrousx.service
run_cmd chown -R ferrousx:ferrousx /etc/ferrousx /var/log/ferrousx /var/cache/ferrousx /run/ferrousx 2>/dev/null || true

run_cmd systemctl daemon-reload

# 5. Kiểm tra cấu hình trước khi khởi động lại dịch vụ
if command -v ferrousx-bin >/dev/null 2>&1; then
    run_cmd ferrousx-bin --check-config --config /etc/ferrousx/ferrousx.toml
fi

if [[ -d /usr/share/phpmyadmin ]] && command -v php >/dev/null 2>&1; then
    run_cmd systemctl reset-failed ferrous-pma.service || true
    run_cmd systemctl restart ferrous-pma.service || true
fi

run_cmd systemctl reset-failed ferrousx.service || true
run_cmd systemctl restart ferrousx.service

log_ok "Hoàn tất sửa chữa và xác minh bảo mật FerrousX (Sao lưu tại: ${BACKUP_DIR})."
