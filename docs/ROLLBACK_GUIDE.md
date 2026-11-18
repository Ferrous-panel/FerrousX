# Hướng dẫn Khôi phục Khẩn cấp (ROLLBACK_GUIDE.md)

Tài liệu này hướng dẫn quy trình khôi phục (Rollback) nhanh chóng khi cần quay lại cấu hình trước đó hoặc khôi phục dịch vụ Nginx/Apache ban đầu trên VPS Production.

---

## 1. Cơ chế Sao lưu Tự động của FerrousX

Mỗi khi bạn chạy `scripts/install.sh`, `scripts/repair.sh` hoặc `scripts/security-hardening.sh`, hệ thống đều tự động tạo một bản chụp (snapshot) có đóng dấu thời gian tại:

- **Cấu hình & Systemd Units:** `/var/backups/ferrousx/<YYYYMMDD_HHMMSS>/`
  - `etc_ferrousx/`: Toàn bộ bản sao của `/etc/ferrousx/` (`ferrousx.toml`, `sites/*.toml`, `ssl/`, `admin.token`).
  - `ferrousx.service` & `ferrous-pma.service`: Các tệp unit systemd trước khi cập nhật.
  - `nginx_was_active`: Cờ đánh dấu nếu dịch vụ Nginx đang hoạt động trước khi cài đặt FerrousX.
- **Cấu hình Kernel Sysctl:** `/var/backups/ferrousx/sysctl_backup/`

---

## 2. Khôi phục Tự động Bằng Một Lệnh (`--rollback`)

### 2.1. Khôi phục Cấu hình FerrousX & Dịch vụ WebTrước đó
```bash
sudo bash scripts/install.sh --rollback
```
Lệnh này sẽ:
1. Tìm bản sao lưu gần nhất trong `/var/backups/ferrousx/`.
2. Khôi phục nguyên trạng thư mục `/etc/ferrousx/` và các tệp `/etc/systemd/system/ferrous*.service`.
3. Chạy `systemctl daemon-reload`.
4. Nếu trước khi cài đặt FerrousX máy chủ đang chạy Nginx (`nginx_was_active`), script sẽ dừng `ferrousx.service`, bỏ mask và khởi động lại `nginx.service`.

### 2.2. Khôi phục Cấu hình Kernel Sysctl & Limits
```bash
sudo bash scripts/security-hardening.sh --rollback
```

---

## 3. Khôi phục Thủ công Từng Phần (Granular Rollback)

Nếu chỉ muốn khôi phục một tệp cấu hình `/etc/ferrousx/ferrousx.toml` từ một thời điểm cụ thể mà không dừng dịch vụ:

```bash
# 1. Liệt kê các bản sao lưu hiện có
ls -la /var/backups/ferrousx/

# 2. Sao chép lại cấu hình từ bản sao lưu mong muốn
sudo cp -a /var/backups/ferrousx/<TIMESTAMP>/etc_ferrousx/ferrousx.toml /etc/ferrousx/ferrousx.toml

# 3. Kiểm tra tính hợp lệ của cấu hình trước khi nạp
sudo ferrousx-bin --check-config --config /etc/ferrousx/ferrousx.toml

# 4. Kích hoạt Zero-Downtime Hot-Reload (RCU)
sudo ferrousx-ctl reload
```
