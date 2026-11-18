# Hướng dẫn Triển khai Production FerrousX (PRODUCTION_DEPLOYMENT.md)

Hướng dẫn này trình bày quy trình chuẩn để triển khai và vận hành **FerrousX Web Server & Reverse Proxy** trên **Ubuntu Server 22.04 / 24.04 LTS (x86_64)** kết hợp Cloudflare Proxy, PHP-FPM và Ferrous-Panel v2.5.0.

---

## 1. Yêu cầu Hệ thống

- **Hệ điều hành:** Ubuntu Server 22.04 LTS hoặc 24.04 LTS (`x86_64`, Kernel Linux `>= 5.15`, khuyến nghị `>= 6.8` cho `io_uring` và eBPF).
- **Phần cứng:** Tối thiểu 1 vCPU, 1 GB RAM (VPS tiêu chuẩn không cần GPU).
- **Cổng mạng cần mở trên Firewall / Security Group:**
  - `80/tcp` (HTTP/1.1 & ACME HTTP-01 Challenge)
  - `443/tcp` (HTTPS TLS 1.3/1.2 ALPN `h2, http/1.1` — **Bắt buộc cho Cloudflare SSL Full/Strict**)
  - `443/udp` (HTTP/3 QUIC RFC 9114)
- **Cổng nội bộ (KHÔNG mở ra Internet):**
  - `127.0.0.1:888` (phpMyAdmin nội bộ, truy cập qua `/phpadmin/` trên cổng `80`/`443`)
  - `127.0.0.1:9090` (FerrousX Embedded Control Plane WebUI)
  - `127.0.0.1:9999` (Ferrous-Panel Core Backend)

---

## 2. Quy trình Cài đặt An toàn

### Bước 1: Kiểm tra trước cài đặt (`--check` & `--dry-run`)
```bash
sudo bash scripts/install.sh --check
sudo bash scripts/install.sh --dry-run
```

### Bước 2: Áp dụng Gia cố Kernel & Sysctl
```bash
sudo bash scripts/security-hardening.sh --dry-run
sudo bash scripts/security-hardening.sh
```

### Bước 3: Thực thi Cài đặt Chính thức
```bash
sudo bash scripts/install.sh --yes
```
Quá trình cài đặt sẽ tự động:
1. Tạo bản sao lưu trạng thái cũ tại `/var/backups/ferrousx/<timestamp>/`.
2. Tạo tài khoản hệ thống không đặc quyền `ferrousx`.
3. Khởi tạo chứng chỉ TLS SAN dự phòng tại `/etc/ferrousx/ssl/fullchain.pem` (`0644`) và `/etc/ferrousx/ssl/privkey.pem` (`0600`).
4. Sinh khóa quản trị 256-bit CSPRNG tại `/etc/ferrousx/admin.token` (`0600`).
5. Biên dịch và cài đặt `/usr/local/bin/ferrousx-bin` cùng `/usr/local/bin/ferrousx-ctl`.
6. Khởi chạy `ferrousx.service` và `ferrous-pma.service` (`127.0.0.1:888`) với đầy đủ Systemd Sandboxing.

---

## 3. Kiểm tra Trạng thái Sau Triển khai

```bash
# 1. Kiểm tra cú pháp cấu hình & chứng chỉ TLS
ferrousx-bin --check-config --config /etc/ferrousx/ferrousx.toml

# 2. Kiểm tra các cổng đang lắng nghe
ss -tulpn | grep -E ':(80|443|888|9090)\b'

# 3. Kiểm tra trạng thái qua Control Plane IPC (tự động đọc /etc/ferrousx/admin.token)
sudo ferrousx-ctl status

# 4. Nạp lại cấu hình không gián đoạn (Zero-Downtime RCU Hot-Reload)
sudo ferrousx-ctl reload
```
