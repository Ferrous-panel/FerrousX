#!/usr/bin/env bash
# ==============================================================================
# FERROUSX PRODUCTION INSTALLER — UBUNTU 22.04 / 24.04 LTS & DEBIAN 12
# 100% Native Rust Web Server & Reverse Proxy (Ferrous-Panel v2.5.0 Ready)
# Hỗ trợ:
#   --dry-run   : Mô phỏng các bước cài đặt mà không thay đổi hệ thống
#   --check     : Kiểm tra trạng thái môi trường, cổng mạng, quyền tệp và cấu hình
#   --rollback  : Khôi phục cấu hình & trạng thái dịch vụ từ bản sao lưu gần nhất
#   --yes / -y  : Tự động xác nhận khi xử lý xung đột cổng 80/443 với Nginx/Apache
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${CYAN}[INFO]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
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
            echo "Cách dùng: sudo bash scripts/install.sh [--dry-run] [--check] [--rollback] [--yes]"
            exit 0
            ;;
        *)
            log_err "Tham số không hợp lệ: $arg"
            exit 1
            ;;
    esac
done

if [[ "$EUID" -ne 0 && "$DRY_RUN" -eq 0 && "$CHECK_ONLY" -eq 0 ]]; then
    log_err "Vui lòng chạy script cài đặt với quyền root (sudo bash scripts/install.sh)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BACKUP_BASE="/var/backups/ferrousx"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="${BACKUP_BASE}/${TIMESTAMP}"

run_cmd() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo -e "${YELLOW}[DRY-RUN]${NC} $*"
    else
        "$@"
    fi
}

# ==============================================================================
# CHẾ ĐỘ KIỂM TRA (--check)
# ==============================================================================
if [[ "$CHECK_ONLY" -eq 1 ]]; then
    log_info "Đang kiểm tra trạng thái bảo mật và tương thích hệ thống FerrousX..."
    echo " - Kernel: $(uname -srm)"
    if [[ -f /etc/ferrousx/ferrousx.toml ]]; then
        log_ok "Tìm thấy /etc/ferrousx/ferrousx.toml"
    else
        log_warn "Chưa có /etc/ferrousx/ferrousx.toml"
    fi
    if [[ -f /etc/ferrousx/admin.token ]]; then
        mode="$(stat -c '%a' /etc/ferrousx/admin.token 2>/dev/null || echo 'unknown')"
        log_ok "Tìm thấy /etc/ferrousx/admin.token (mode: ${mode})"
    else
        log_warn "Chưa khởi tạo /etc/ferrousx/admin.token"
    fi
    if command -v ferrousx-bin >/dev/null 2>&1; then
        ferrousx-bin -v || true
        if [[ -f /etc/ferrousx/ferrousx.toml ]]; then
            ferrousx-bin --check-config --config /etc/ferrousx/ferrousx.toml || true
        fi
    else
        log_warn "Chưa cài đặt binary /usr/local/bin/ferrousx-bin"
    fi
    exit 0
fi

# ==============================================================================
# CHẾ ĐỘ KHÔI PHỤC (--rollback)
# ==============================================================================
if [[ "$ROLLBACK_MODE" -eq 1 ]]; then
    if [[ ! -d "$BACKUP_BASE" ]]; then
        log_err "Không tìm thấy thư mục sao lưu tại ${BACKUP_BASE}"
        exit 1
    fi
    LATEST_BACKUP="$(find "$BACKUP_BASE" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1)"
    if [[ -z "$LATEST_BACKUP" ]]; then
        log_err "Không có bản sao lưu nào trong ${BACKUP_BASE}"
        exit 1
    fi
    log_info "Đang khôi phục hệ thống từ bản sao lưu: ${LATEST_BACKUP}"
    if [[ -d "${LATEST_BACKUP}/etc_ferrousx" ]]; then
        run_cmd cp -a "${LATEST_BACKUP}/etc_ferrousx/." /etc/ferrousx/
    fi
    if [[ -f "${LATEST_BACKUP}/ferrousx.service" ]]; then
        run_cmd cp -a "${LATEST_BACKUP}/ferrousx.service" /etc/systemd/system/ferrousx.service
    fi
    if [[ -f "${LATEST_BACKUP}/ferrous-pma.service" ]]; then
        run_cmd cp -a "${LATEST_BACKUP}/ferrous-pma.service" /etc/systemd/system/ferrous-pma.service
    fi
    run_cmd systemctl daemon-reload
    if [[ -f "${LATEST_BACKUP}/nginx_was_active" ]]; then
        run_cmd systemctl stop ferrousx.service || true
        run_cmd systemctl unmask nginx || true
        run_cmd systemctl enable --now nginx || true
        log_ok "Đã khôi phục dịch vụ Nginx như trước khi cài đặt."
    else
        run_cmd systemctl restart ferrousx.service || true
    fi
    log_ok "Hoàn tất Rollback từ ${LATEST_BACKUP}"
    exit 0
fi

echo -e "${CYAN}======================================================================${NC}"
echo -e "${CYAN}   FERROUSX HARDENED INSTALLER — NATIVE RUST WEB SERVER & PROXY       ${NC}"
echo -e "${CYAN}======================================================================${NC}"

# 0. Tạo bản sao lưu trạng thái trước khi thay đổi hệ thống
log_info "Khởi tạo bản sao lưu cấu hình tại ${BACKUP_DIR}..."
run_cmd mkdir -p "$BACKUP_DIR"
if [[ "$DRY_RUN" -eq 0 ]]; then
    if [[ -d /etc/ferrousx ]]; then
        mkdir -p "${BACKUP_DIR}/etc_ferrousx"
        cp -a /etc/ferrousx/. "${BACKUP_DIR}/etc_ferrousx/" || true
    fi
    [[ -f /etc/systemd/system/ferrousx.service ]] && cp -a /etc/systemd/system/ferrousx.service "${BACKUP_DIR}/ferrousx.service"
    [[ -f /etc/systemd/system/ferrous-pma.service ]] && cp -a /etc/systemd/system/ferrous-pma.service "${BACKUP_DIR}/ferrous-pma.service"
    if systemctl is-active --quiet nginx 2>/dev/null; then
        touch "${BACKUP_DIR}/nginx_was_active"
    fi
fi

# 1. Cài đặt gói phụ trợ cần thiết trên Ubuntu / Debian
if command -v apt-get >/dev/null 2>&1; then
    log_info "Kiểm tra và cài đặt gói hệ thống thiết yếu..."
    run_cmd env DEBIAN_FRONTEND=noninteractive apt-get update -y -qq
    run_cmd env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        curl ca-certificates build-essential pkg-config libssl-dev openssl psmisc iproute2
fi

# 2. Kiểm tra xung đột cổng 80/443 (Nginx / Apache2) có kiểm soát
if systemctl is-active --quiet nginx 2>/dev/null || systemctl is-active --quiet apache2 2>/dev/null; then
    log_warn "Phát hiện Nginx hoặc Apache2 đang chiếm cổng 80/443."
    if [[ "$AUTO_YES" -eq 1 || ! -t 0 ]]; then
        log_info "Tự động dừng Nginx/Apache2 để nhường cổng 80/443 cho FerrousX (đã lưu trạng thái Rollback)..."
        run_cmd systemctl stop nginx apache2 2>/dev/null || true
        run_cmd systemctl disable nginx apache2 2>/dev/null || true
    else
        read -r -p "Bạn có muốn dừng Nginx/Apache2 để FerrousX lắng nghe trên cổng 80/443 không? [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            run_cmd systemctl stop nginx apache2 2>/dev/null || true
            run_cmd systemctl disable nginx apache2 2>/dev/null || true
        else
            log_err "Hủy cài đặt do cổng 80/443 đang bị chiếm dụng."
            exit 1
        fi
    fi
fi

# 3. Tạo User/Group hệ thống không đặc quyền `ferrousx` và cấu trúc thư mục phân quyền chặt
log_info "Thiết lập tài khoản dịch vụ 'ferrousx' (Least Privilege) và thư mục chuẩn..."
if ! id -u ferrousx >/dev/null 2>&1; then
    run_cmd useradd --system --no-create-home --shell /usr/sbin/nologin --user-group ferrousx
fi
if getent group www-data >/dev/null 2>&1; then
    run_cmd usermod -aG www-data ferrousx || true
fi

run_cmd mkdir -p \
    /etc/ferrousx/ssl \
    /etc/ferrousx/sites \
    /etc/ferrousx/conf.d \
    /etc/ferrous-panel \
    /www/acme/.well-known/acme-challenge \
    /www/server/panel/vhost/ferrousx \
    /www/wwwroot/default \
    /var/log/ferrousx \
    /var/cache/ferrousx \
    /run/ferrousx

if [[ "$DRY_RUN" -eq 0 && ! -f /www/wwwroot/default/index.html ]]; then
    cat << 'EOF' > /www/wwwroot/default/index.html
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>FerrousX Native Rust Web Server</title>
    <style>
        body { background:#090d16; color:#f3f4f6; font-family:system-ui,sans-serif; display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }
        .box { background:#111827; border:1px solid #1f2937; padding:2.5rem; border-radius:12px; max-width:560px; text-align:center; }
        h1 { color:#10b981; margin-top:0; }
        code { background:#1f2937; padding:0.2rem 0.5rem; border-radius:4px; color:#38bdf8; }
    </style>
</head>
<body>
    <div class="box">
        <h1>⚡ FerrousX Engine Active</h1>
        <p>Máy chủ 100% Native Rust đang phục vụ đồng thời <code>TCP :80</code>, <code>TCP TLS :443</code> và <code>UDP QUIC :443</code>.</p>
    </div>
</body>
</html>
EOF
fi

# 4. Sinh chứng chỉ TLS SAN tự ký dự phòng (chmod 0644 cert, 0600 privkey)
SSL_CERT="/etc/ferrousx/ssl/fullchain.pem"
SSL_KEY="/etc/ferrousx/ssl/privkey.pem"
if [[ ! -s "$SSL_CERT" || ! -s "$SSL_KEY" ]]; then
    log_info "Đang khởi tạo chứng chỉ TLS SAN dự phòng (ECDSA P-256 / RSA-2048)..."
    SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || echo '127.0.0.1')"
    [[ -z "$SERVER_IP" ]] && SERVER_IP="127.0.0.1"
    if [[ "$DRY_RUN" -eq 0 ]]; then
        openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
            -keyout "$SSL_KEY" \
            -out "$SSL_CERT" \
            -subj "/C=VN/ST=Hanoi/L=Hanoi/O=FerrousX/CN=localhost" \
            -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:${SERVER_IP}" 2>/dev/null || \
        openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
            -keyout "$SSL_KEY" \
            -out "$SSL_CERT" \
            -subj "/C=VN/ST=Hanoi/L=Hanoi/O=FerrousX/CN=localhost"
        chmod 600 "$SSL_KEY"
        chmod 644 "$SSL_CERT"
    fi
    log_ok "Đã tạo chứng chỉ TLS tại ${SSL_CERT} và khóa bí mật ${SSL_KEY} (chmod 600)."
fi

# 5. Khởi tạo Admin Token 256-bit CSPRNG tại /etc/ferrousx/admin.token (chmod 0600)
ADMIN_TOKEN_FILE="/etc/ferrousx/admin.token"
if [[ ! -s "$ADMIN_TOKEN_FILE" ]]; then
    log_info "Sinh khóa quản trị 256-bit CSPRNG tại ${ADMIN_TOKEN_FILE} (chmod 0600)..."
    if [[ "$DRY_RUN" -eq 0 ]]; then
        head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$ADMIN_TOKEN_FILE"
        echo "" >> "$ADMIN_TOKEN_FILE"
        chmod 600 "$ADMIN_TOKEN_FILE"
        chown ferrousx:ferrousx "$ADMIN_TOKEN_FILE"
    fi
fi

# 6. Biên dịch hoặc cài đặt Binary Native Rust (`ferrousx-bin` & `ferrousx-ctl`)
build_or_install_rust_binaries() {
    if [[ -f "${PROJECT_ROOT}/target/release/ferrousx-bin" && -f "${PROJECT_ROOT}/target/release/ferrousx-ctl" ]]; then
        log_info "Cài đặt binary Rust từ target/release..."
        run_cmd install -m 0755 "${PROJECT_ROOT}/target/release/ferrousx-bin" /usr/local/bin/ferrousx-bin
        run_cmd install -m 0755 "${PROJECT_ROOT}/target/release/ferrousx-ctl" /usr/local/bin/ferrousx-ctl
        return 0
    fi

    if ! command -v cargo >/dev/null 2>&1; then
        if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
            export PATH="$HOME/.cargo/bin:$PATH"
        else
            log_info "Đang cài đặt trình biên dịch Rust (rustup stable)..."
            if [[ "$DRY_RUN" -eq 0 ]]; then
                curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
                export PATH="$HOME/.cargo/bin:$PATH"
            fi
        fi
    fi

    log_info "Đang biên dịch FerrousX 100% Native Rust ở chế độ Release..."
    if [[ "$DRY_RUN" -eq 0 ]]; then
        cd "$PROJECT_ROOT"
        cargo build --release --workspace
        install -m 0755 "${PROJECT_ROOT}/target/release/ferrousx-bin" /usr/local/bin/ferrousx-bin
        install -m 0755 "${PROJECT_ROOT}/target/release/ferrousx-ctl" /usr/local/bin/ferrousx-ctl
    fi
}

build_or_install_rust_binaries
run_cmd ln -sf /usr/local/bin/ferrousx-bin /usr/local/bin/ferrousx

# 7. Cài đặt cấu hình `/etc/ferrousx/ferrousx.toml` & phân quyền chuẩn
if [[ ! -f /etc/ferrousx/ferrousx.toml ]]; then
    run_cmd install -m 0640 "${PROJECT_ROOT}/conf/ferrousx.toml" /etc/ferrousx/ferrousx.toml
fi

run_cmd chown -R ferrousx:ferrousx /etc/ferrousx /var/log/ferrousx /var/cache/ferrousx /run/ferrousx
run_cmd chmod 0750 /etc/ferrousx /etc/ferrousx/ssl /var/log/ferrousx /var/cache/ferrousx /run/ferrousx
[[ -f "$SSL_KEY" ]] && run_cmd chmod 0600 "$SSL_KEY"
[[ -f "$ADMIN_TOKEN_FILE" ]] && run_cmd chmod 0600 "$ADMIN_TOKEN_FILE"
run_cmd chown -R www-data:www-data /www/wwwroot /www/acme 2>/dev/null || true

# 8. Cài đặt dịch vụ phpMyAdmin nội bộ trên Loopback 127.0.0.1:888 (User=www-data, KHÔNG BAO GIỜ chạy root hoặc 0.0.0.0)
run_cmd install -m 0644 "${PROJECT_ROOT}/scripts/pma-router.php" /etc/ferrousx/pma-router.php
run_cmd install -m 0644 "${PROJECT_ROOT}/scripts/ferrous-pma.service" /etc/systemd/system/ferrous-pma.service
# Xóa bỏ mọi drop-in cũ không an toàn nếu từng tồn tại
run_cmd rm -rf /etc/systemd/system/ferrous-pma.service.d /etc/systemd/system/ferrousx.service.d

# 9. Cài đặt và khởi động `ferrousx.service` với đầy đủ Systemd Sandboxing
run_cmd install -m 0644 "${PROJECT_ROOT}/scripts/ferrousx.service" /etc/systemd/system/ferrousx.service
run_cmd systemctl daemon-reload

log_info "Kiểm tra cú pháp cấu hình trước khi khởi chạy..."
run_cmd /usr/local/bin/ferrousx-bin --check-config --config /etc/ferrousx/ferrousx.toml

if [[ -d /usr/share/phpmyadmin ]] && command -v php >/dev/null 2>&1; then
    run_cmd systemctl enable ferrous-pma.service
    run_cmd systemctl reset-failed ferrous-pma.service || true
    run_cmd systemctl restart ferrous-pma.service || true
fi

run_cmd systemctl enable ferrousx.service
run_cmd systemctl reset-failed ferrousx.service || true
run_cmd systemctl restart ferrousx.service

# 10. Cấu hình tường lửa UFW an toàn (chỉ mở 80/tcp, 443/tcp, 443/udp; đóng cổng nội bộ 888/tcp)
if command -v ufw >/dev/null 2>&1; then
    run_cmd ufw allow 80/tcp >/dev/null 2>&1 || true
    run_cmd ufw allow 443/tcp >/dev/null 2>&1 || true
    run_cmd ufw allow 443/udp >/dev/null 2>&1 || true
    run_cmd ufw delete allow 888/tcp >/dev/null 2>&1 || true
fi

echo -e "${GREEN}======================================================================${NC}"
echo -e "${GREEN} ✓ CÀI ĐẶT & GIA CỐ BẢO MẬT FERROUSX THÀNH CÔNG!${NC}"
echo -e "${GREEN} - Bản sao lưu Rollback : ${BACKUP_DIR}${NC}"
echo -e "${GREEN} - Admin Token (0600)   : /etc/ferrousx/admin.token${NC}"
echo -e "${GREEN} - phpMyAdmin nội bộ    : 127.0.0.1:888 (qua /phpadmin/ trên :80/:443)${NC}"
echo -e "${GREEN}======================================================================${NC}"
