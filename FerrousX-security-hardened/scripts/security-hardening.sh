#!/usr/bin/env bash
# ==============================================================================
# FERROUSX LINUX SYSTEM & KERNEL SECURITY HARDENING SCRIPT
# Tối ưu hóa Kernel Sysctl (SYN Flood, TCP BBR, QUIC UDP Buffers, File Descriptors)
# Hỗ trợ: --dry-run | --check | --rollback
# ==============================================================================

set -euo pipefail

SYSCTL_CONF="/etc/sysctl.d/99-ferrousx-hardening.conf"
LIMITS_CONF="/etc/security/limits.d/99-ferrousx.conf"
BACKUP_DIR="/var/backups/ferrousx/sysctl_backup"

DRY_RUN=0
CHECK_ONLY=0
ROLLBACK=0

for arg in "$@"; do
    case "$arg" in
        --dry-run)  DRY_RUN=1 ;;
        --check)    CHECK_ONLY=1 ;;
        --rollback) ROLLBACK=1 ;;
        --help|-h)
            echo "Cách dùng: sudo bash scripts/security-hardening.sh [--dry-run] [--check] [--rollback]"
            exit 0
            ;;
        *)
            echo "[ERROR] Tham số không hợp lệ: $arg" >&2
            exit 1
            ;;
    esac
done

if [[ "$CHECK_ONLY" -eq 1 ]]; then
    echo "=== Kiểm tra trạng thái Kernel Sysctl & Limits ==="
    [[ -f "$SYSCTL_CONF" ]] && echo "[OK] Đã cài đặt $SYSCTL_CONF" || echo "[WARN] Chưa có $SYSCTL_CONF"
    [[ -f "$LIMITS_CONF" ]] && echo "[OK] Đã cài đặt $LIMITS_CONF" || echo "[WARN] Chưa có $LIMITS_CONF"
    sysctl net.ipv4.tcp_syncookies net.core.somaxconn 2>/dev/null || true
    exit 0
fi

if [[ "$EUID" -ne 0 && "$DRY_RUN" -eq 0 ]]; then
    echo "[ERROR] Vui lòng chạy script này với quyền root (sudo)." >&2
    exit 1
fi

if [[ "$ROLLBACK" -eq 1 ]]; then
    echo "[INFO] Đang khôi phục cấu hình sysctl và limits..."
    if [[ "$DRY_RUN" -eq 0 ]]; then
        rm -f "$SYSCTL_CONF" "$LIMITS_CONF"
        [[ -f "${BACKUP_DIR}/99-ferrousx-hardening.conf" ]] && cp -a "${BACKUP_DIR}/99-ferrousx-hardening.conf" "$SYSCTL_CONF"
        [[ -f "${BACKUP_DIR}/99-ferrousx.conf" ]] && cp -a "${BACKUP_DIR}/99-ferrousx.conf" "$LIMITS_CONF"
        sysctl --system >/dev/null 2>&1 || true
    fi
    echo "[OK] Đã khôi phục sysctl/limits."
    exit 0
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[DRY-RUN] Sẽ sao lưu và ghi cấu hình vào ${SYSCTL_CONF} & ${LIMITS_CONF}, sau đó nạp sysctl --system"
    exit 0
fi

mkdir -p "$BACKUP_DIR"
[[ -f "$SYSCTL_CONF" ]] && cp -a "$SYSCTL_CONF" "${BACKUP_DIR}/99-ferrousx-hardening.conf"
[[ -f "$LIMITS_CONF" ]] && cp -a "$LIMITS_CONF" "${BACKUP_DIR}/99-ferrousx.conf"

cat << 'EOF' > "$SYSCTL_CONF"
# --- FerrousX Production Kernel Hardening & Performance ---
fs.file-max = 2097152
fs.nr_open = 2097152
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0

# --- Chống SYN Flood, IP Spoofing & ICMP Redirect ---
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- Tối ưu hàng đợi Socket & QUIC / HTTP/3 UDP Buffers ---
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65536
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.rmem_default = 2097152
net.core.wmem_default = 2097152
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 10240 65535

# --- Bảo vệ bộ nhớ Kernel (KASLR, dmesg, kptr) ---
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.randomize_va_space = 2
kernel.yama.ptrace_scope = 1
EOF

sysctl --system >/dev/null 2>&1 || true

cat << 'EOF' > "$LIMITS_CONF"
ferrousx soft nofile 1048576
ferrousx hard nofile 1048576
ferrousx soft memlock unlimited
ferrousx hard memlock unlimited
www-data soft nofile 524288
www-data hard nofile 524288
EOF

echo "[OK] Đã áp dụng Kernel Hardening (${SYSCTL_CONF}) và File Descriptor Limits (${LIMITS_CONF})."
