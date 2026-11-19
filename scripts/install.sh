#!/usr/bin/env bash
# ==============================================================================
# FERROUSX 1-LINE UNIVERSAL LINUX INSTALLER (ALL LINUX DISTRIBUTIONS)
# Hỗ trợ:
#   - Ubuntu / Debian / Kali / Mint (apt-get)
#   - RHEL / AlmaLinux / Rocky Linux / CentOS / Fedora / Amazon Linux (dnf / yum)
#   - Arch Linux / Manjaro (pacman)
#   - Alpine Linux (apk)
#   - openSUSE / SLES (zypper)
# Cài đặt bằng 1 lệnh duy nhất:
#   curl -fsSL https://raw.githubusercontent.com/Ferrous-panel/FerrousX/main/scripts/install.sh | sudo bash
# Cài đặt sẵn lệnh quản trị Terminal VPS:
#   fx | ferrousx-admin | ferrousx-ctl
# Tùy chọn:
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
REPO_URL="https://github.com/Ferrous-panel/FerrousX.git"
DEFAULT_SRC_DIR="/usr/local/src/FerrousX"

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

run_cmd() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo -e "${YELLOW}[DRY-RUN]${NC} $*"
    else
        "$@"
    fi
}

# ==============================================================================
# NHẬN DIỆN BẢN PHÂN PHỐI LINUX & TRÌNH QUẢN LÝ GÓI ĐA NỀN TẢNG
# ==============================================================================
DISTRO_ID="linux"
if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID:-linux}"
fi

install_system_dependencies() {
    log_info "Nhận diện hệ điều hành (${DISTRO_ID}) và cài đặt công cụ hệ thống..."
    if command -v apt-get >/dev/null 2>&1; then
        run_cmd env DEBIAN_FRONTEND=noninteractive apt-get update -y -qq
        run_cmd env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            curl git ca-certificates build-essential pkg-config libssl-dev openssl psmisc iproute2
    elif command -v dnf >/dev/null 2>&1; then
        run_cmd dnf install -y -q \
            curl git ca-certificates gcc gcc-c++ make pkgconf-pkg-config openssl-devel openssl psmisc iproute
    elif command -v yum >/dev/null 2>&1; then
        run_cmd yum install -y -q \
            curl git ca-certificates gcc gcc-c++ make pkgconfig openssl-devel openssl psmisc iproute
    elif command -v pacman >/dev/null 2>&1; then
        run_cmd pacman -Sy --noconfirm --needed \
            curl git ca-certificates base-devel pkgconf openssl psmisc iproute2
    elif command -v zypper >/dev/null 2>&1; then
        run_cmd zypper --non-interactive install \
            curl git ca-certificates gcc gcc-c++ make pkg-config libopenssl-devel openssl psmisc iproute2
    elif command -v apk >/dev/null 2>&1; then
        run_cmd apk add --no-cache \
            bash curl git ca-certificates build-base pkgconf openssl-dev openssl psmisc iproute2
    else
        log_warn "Không nhận diện được trình quản lý gói chuẩn; giả định hệ thống đã có gcc, make, openssl."
    fi
}

BACKUP_BASE="/var/backups/ferrousx"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="${BACKUP_BASE}/${TIMESTAMP}"

# ==============================================================================
# CHẾ ĐỘ KIỂM TRA (--check)
# ==============================================================================
if [[ "$CHECK_ONLY" -eq 1 ]]; then
    log_info "Đang kiểm tra trạng thái bảo mật và tương thích hệ thống FerrousX (${DISTRO_ID})..."
    echo " - Kernel: $(uname -srm)"
    if [[ -f /etc/ferrousx/ferrousx.toml ]]; then
        log_ok "Tìm thấy /etc/ferrousx/ferrousx.toml"
    else
        log_warn "Chưa có /etc/ferrousx/ferrousx.toml"
    fi
    if [[ -f /etc/ferrousx/ferrousx.env ]]; then
        env_mode="$(stat -c '%a' /etc/ferrousx/ferrousx.env 2>/dev/null || echo 'unknown')"
        log_ok "Tìm thấy /etc/ferrousx/ferrousx.env (mode: ${env_mode})"
    else
        log_warn "Chưa khởi tạo /etc/ferrousx/ferrousx.env"
    fi
    if [[ -f /etc/profile.d/ferrousx.sh ]]; then
        log_ok "Tìm thấy /etc/profile.d/ferrousx.sh (tự động nạp biến môi trường & PATH)"
    else
        log_warn "Chưa cài đặt /etc/profile.d/ferrousx.sh"
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
echo -e "${CYAN}   FERROUSX 1-LINE UNIVERSAL INSTALLER — ALL LINUX DISTROS (RUST)     ${NC}"
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

# 1. Cài đặt gói hệ thống đa nền tảng (Ubuntu/Debian/Alma/Rocky/CentOS/Fedora/Arch/Alpine/openSUSE)
install_system_dependencies

# 2. Xác định thư mục mã nguồn (Hỗ trợ cả chạy trực tiếp từ repo hoặc chạy 1 lệnh `curl ... | sudo bash`)
SCRIPT_SOURCE="${BASH_SOURCE[0]:-}"
if [[ -n "$SCRIPT_SOURCE" && -f "$SCRIPT_SOURCE" ]]; then
    CANDIDATE_ROOT="$(cd "$(dirname "$SCRIPT_SOURCE")/.." && pwd)"
else
    CANDIDATE_ROOT=""
fi

if [[ -n "$CANDIDATE_ROOT" && -f "${CANDIDATE_ROOT}/Cargo.toml" ]]; then
    PROJECT_ROOT="$CANDIDATE_ROOT"
else
    log_info "Chế độ cài đặt 1 lệnh (One-Liner Bootstrap): Đang tải mã nguồn FerrousX về ${DEFAULT_SRC_DIR}..."
    PROJECT_ROOT="$DEFAULT_SRC_DIR"
    if [[ "$DRY_RUN" -eq 0 ]]; then
        mkdir -p "$(dirname "$DEFAULT_SRC_DIR")"
        if [[ -d "${DEFAULT_SRC_DIR}/.git" ]]; then
            git -C "$DEFAULT_SRC_DIR" fetch --depth 1 origin main || true
            git -C "$DEFAULT_SRC_DIR" reset --hard origin/main || true
        else
            rm -rf "$DEFAULT_SRC_DIR"
            git clone --depth 1 "$REPO_URL" "$DEFAULT_SRC_DIR"
        fi
    fi
fi

# 3. Kiểm tra xung đột cổng 80/443 (Nginx / Apache2 / httpd) có kiểm soát
if systemctl is-active --quiet nginx 2>/dev/null || systemctl is-active --quiet apache2 2>/dev/null || systemctl is-active --quiet httpd 2>/dev/null; then
    log_warn "Phát hiện Nginx hoặc Apache (apache2/httpd) đang chiếm cổng 80/443."
    if [[ "$AUTO_YES" -eq 1 || ! -t 0 ]]; then
        log_info "Tự động dừng Nginx/Apache để nhường cổng 80/443 cho FerrousX (đã lưu trạng thái Rollback)..."
        run_cmd systemctl stop nginx apache2 httpd 2>/dev/null || true
        run_cmd systemctl disable nginx apache2 httpd 2>/dev/null || true
    else
        read -r -p "Bạn có muốn dừng Nginx/Apache để FerrousX lắng nghe trên cổng 80/443 không? [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            run_cmd systemctl stop nginx apache2 httpd 2>/dev/null || true
            run_cmd systemctl disable nginx apache2 httpd 2>/dev/null || true
        else
            log_err "Hủy cài đặt do cổng 80/443 đang bị chiếm dụng."
            exit 1
        fi
    fi
fi

# 4. Tạo User/Group hệ thống không đặc quyền `ferrousx` và `www-data` tương thích mọi bản Linux
log_info "Thiết lập tài khoản dịch vụ 'ferrousx' và 'www-data' (Least Privilege)..."
if ! getent group www-data >/dev/null 2>&1; then
    run_cmd groupadd --system www-data 2>/dev/null || true
fi
if ! id -u www-data >/dev/null 2>&1; then
    run_cmd useradd --system --no-create-home --shell /usr/sbin/nologin -g www-data www-data 2>/dev/null || true
fi
if ! id -u ferrousx >/dev/null 2>&1; then
    run_cmd useradd --system --no-create-home --shell /usr/sbin/nologin --user-group ferrousx
fi
run_cmd usermod -aG www-data ferrousx 2>/dev/null || true

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

# 5. Sinh chứng chỉ TLS SAN tự ký dự phòng (chmod 0644 cert, 0600 privkey)
SSL_CERT="/etc/ferrousx/ssl/fullchain.pem"
SSL_KEY="/etc/ferrousx/ssl/privkey.pem"
if [[ ! -s "$SSL_CERT" || ! -s "$SSL_KEY" ]]; then
    log_info "Đang khởi tạo chứng chỉ TLS SAN dự phòng (ECDSA P-256 / RSA-2048)..."
    SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || echo '127.0.0.1')"
    [[ -z "$SERVER_IP" ]] && SERVER_IP="127.0.0.1"
    if [[ "$DRY_RUN" -eq 0 ]]; then
        install -m 0600 /dev/null "$SSL_KEY"
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

# 6. Khởi tạo Admin Token 256-bit CSPRNG tại /etc/ferrousx/admin.token (chmod 0600)
ADMIN_TOKEN_FILE="/etc/ferrousx/admin.token"
if [[ ! -s "$ADMIN_TOKEN_FILE" ]]; then
    log_info "Sinh khóa quản trị 256-bit CSPRNG tại ${ADMIN_TOKEN_FILE} (chmod 0600)..."
    if [[ "$DRY_RUN" -eq 0 ]]; then
        install -m 0600 -o ferrousx -g ferrousx /dev/null "$ADMIN_TOKEN_FILE"
        head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$ADMIN_TOKEN_FILE"
        echo "" >> "$ADMIN_TOKEN_FILE"
    fi
fi

# 7. Biên dịch hoặc cài đặt Binary Native Rust (`ferrousx-bin` & `ferrousx-ctl`) + Lệnh Admin Terminal (`fx`, `ferrousx-admin`)
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
                RUSTUP_INIT="$(mktemp /tmp/rustup-init.XXXXXX.sh)"
                curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs -o "$RUSTUP_INIT"
                if [[ ! -s "$RUSTUP_INIT" ]]; then
                    rm -f "$RUSTUP_INIT"
                    log_err "Tải trình cài đặt rustup thất bại hoặc tệp rỗng."
                    exit 1
                fi
                sh "$RUSTUP_INIT" -y --profile minimal
                rm -f "$RUSTUP_INIT"
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

# Cài đặt công cụ quản trị Terminal VPS: `ferrousx-admin` và lệnh tắt `fx`
if [[ -f "${PROJECT_ROOT}/scripts/ferrousx-admin.sh" ]]; then
    run_cmd install -m 0755 "${PROJECT_ROOT}/scripts/ferrousx-admin.sh" /usr/local/bin/ferrousx-admin
    run_cmd ln -sf /usr/local/bin/ferrousx-admin /usr/local/bin/fx
else
    run_cmd ln -sf /usr/local/bin/ferrousx-ctl /usr/local/bin/ferrousx-admin
    run_cmd ln -sf /usr/local/bin/ferrousx-ctl /usr/local/bin/fx
fi

# 8. Cài đặt cấu hình `/etc/ferrousx/ferrousx.toml`, tự động tạo biến môi trường `/etc/ferrousx/ferrousx.env` & `/etc/profile.d/ferrousx.sh`
if [[ ! -f /etc/ferrousx/ferrousx.toml ]]; then
    run_cmd install -m 0640 "${PROJECT_ROOT}/conf/ferrousx.toml" /etc/ferrousx/ferrousx.toml
fi

ensure_ferrousx_env_files() {
    local env_file="/etc/ferrousx/ferrousx.env"
    local profile_file="/etc/profile.d/ferrousx.sh"

    log_info "Tự động thiết lập biến môi trường hệ thống (${env_file} & ${profile_file})..."
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo -e "${YELLOW}[DRY-RUN]${NC} Khởi tạo/đồng bộ ${env_file} (0640) và ${profile_file} (0644)"
        return 0
    fi

    if [[ ! -f "$env_file" ]]; then
        install -m 0640 -o ferrousx -g ferrousx /dev/null "$env_file"
        cat << 'EOF' > "$env_file"
# ==============================================================================
# FERROUSX RUNTIME ENVIRONMENT VARIABLES (Tự động khởi tạo bởi install.sh)
# Systemd nạp tệp này tự động qua EnvironmentFile=-/etc/ferrousx/ferrousx.env
# ==============================================================================
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
    else
        # Bổ sung tự động các biến môi trường còn thiếu mà không ghi đè cấu hình của người dùng
        local defaults=(
            'FERROUSX_CONFIG="/etc/ferrousx/ferrousx.toml"'
            'FERROUSX_ENV_FILE="/etc/ferrousx/ferrousx.env"'
            'FERROUSX_SITES_DIR="/etc/ferrousx/sites"'
            'FERROUSX_ACME_WEBROOT="/www/acme"'
            'FERROUSX_CONTROL_SOCKET="/run/ferrousx/panel-admin.sock"'
            'FERROUSX_ADMIN_TOKEN_FILE="/etc/ferrousx/admin.token"'
            'FERROUSX_WAF_MODE="block"'
            'FERROUSX_ENABLE_DASHBOARD="true"'
            'FERROUSX_DASHBOARD_ADDR="127.0.0.1:9090"'
            'RUST_LOG="ferrousx=info"'
        )
        for entry in "${defaults[@]}"; do
            local key="${entry%%=*}"
            if ! grep -qE "^[[:space:]]*(export[[:space:]]+)?${key}=" "$env_file"; then
                echo "$entry" >> "$env_file"
            fi
        done
    fi
    chmod 0640 "$env_file"
    chown ferrousx:ferrousx "$env_file" 2>/dev/null || true

    # Cài đặt profile tự động xuất biến môi trường & PATH (/usr/local/bin + ~/.cargo/bin) cho mọi phiên Shell
    if [[ -d /etc/profile.d ]]; then
        cat << 'EOF' > "$profile_file"
# FerrousX Automatic Environment & PATH Profile (Managed by install.sh / repair.sh)
case ":$PATH:" in
    *":/usr/local/bin:"*) ;;
    *) export PATH="/usr/local/bin:$PATH" ;;
esac
if [ -d "$HOME/.cargo/bin" ]; then
    case ":$PATH:" in
        *":$HOME/.cargo/bin:"*) ;;
        *) export PATH="$HOME/.cargo/bin:$PATH" ;;
    esac
fi

export FERROUSX_CONFIG="${FERROUSX_CONFIG:-/etc/ferrousx/ferrousx.toml}"
export FERROUSX_ENV_FILE="${FERROUSX_ENV_FILE:-/etc/ferrousx/ferrousx.env}"
export FERROUSX_ADMIN_TOKEN_FILE="${FERROUSX_ADMIN_TOKEN_FILE:-/etc/ferrousx/admin.token}"
export FERROUSX_CONTROL_SOCKET="${FERROUSX_CONTROL_SOCKET:-/run/ferrousx/panel-admin.sock}"
export RUST_LOG="${RUST_LOG:-ferrousx=info}"
EOF
        chmod 0644 "$profile_file"
    fi
    log_ok "Đã tự động cấu hình biến môi trường tại ${env_file} và ${profile_file}."
}

ensure_ferrousx_env_files

run_cmd chown -R ferrousx:ferrousx /etc/ferrousx /var/log/ferrousx /var/cache/ferrousx /run/ferrousx
run_cmd chmod 0750 /etc/ferrousx /etc/ferrousx/ssl /var/log/ferrousx /var/cache/ferrousx /run/ferrousx
[[ -f /etc/ferrousx/ferrousx.env ]] && run_cmd chmod 0640 /etc/ferrousx/ferrousx.env
[[ -f "$SSL_KEY" ]] && run_cmd chmod 0600 "$SSL_KEY"
[[ -f "$ADMIN_TOKEN_FILE" ]] && run_cmd chmod 0600 "$ADMIN_TOKEN_FILE"
run_cmd chown -R www-data:www-data /www/wwwroot /www/acme 2>/dev/null || true

# 9. Cài đặt dịch vụ phpMyAdmin nội bộ trên Loopback 127.0.0.1:888 (User=www-data, KHÔNG BAO GIỜ chạy root hoặc 0.0.0.0)
run_cmd install -m 0644 "${PROJECT_ROOT}/scripts/pma-router.php" /etc/ferrousx/pma-router.php
run_cmd install -m 0644 "${PROJECT_ROOT}/scripts/ferrous-pma.service" /etc/systemd/system/ferrous-pma.service
run_cmd rm -rf /etc/systemd/system/ferrous-pma.service.d /etc/systemd/system/ferrousx.service.d

# 10. Cài đặt và khởi động `ferrousx.service` với đầy đủ Systemd Sandboxing
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

# 11. Cấu hình tường lửa đa nền tảng (UFW trên Debian/Ubuntu & firewalld trên RHEL/Alma/Rocky/Fedora)
if command -v ufw >/dev/null 2>&1; then
    run_cmd ufw allow 80/tcp >/dev/null 2>&1 || true
    run_cmd ufw allow 443/tcp >/dev/null 2>&1 || true
    run_cmd ufw allow 443/udp >/dev/null 2>&1 || true
    run_cmd ufw delete allow 888/tcp >/dev/null 2>&1 || true
elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    run_cmd firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1 || true
    run_cmd firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1 || true
    run_cmd firewall-cmd --permanent --add-port=443/udp >/dev/null 2>&1 || true
    run_cmd firewall-cmd --permanent --remove-port=888/tcp >/dev/null 2>&1 || true
    run_cmd firewall-cmd --reload >/dev/null 2>&1 || true
fi

echo -e "${GREEN}======================================================================${NC}"
echo -e "${GREEN} ✓ CÀI ĐẶT & GIA CỐ BẢO MẬT FERROUSX THÀNH CÔNG (${DISTRO_ID})!${NC}"
echo -e "${GREEN} - Lệnh Admin Terminal  : sudo fx  (hoặc: sudo ferrousx-admin)${NC}"
echo -e "${GREEN} - Lệnh CLI Điều khiển  : sudo ferrousx-ctl status | reload | test${NC}"
echo -e "${GREEN} - Admin Token (0600)   : /etc/ferrousx/admin.token${NC}"
echo -e "${GREEN} - phpMyAdmin nội bộ    : 127.0.0.1:888 (truy cập qua /phpadmin/)${NC}"
echo -e "${GREEN} - Bản sao lưu Rollback : ${BACKUP_DIR}${NC}"
echo -e "${GREEN}======================================================================${NC}"
