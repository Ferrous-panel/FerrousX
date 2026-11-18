# Nhật ký Thay đổi (CHANGELOG.md)

## [0.1.0-security-hardened] — 2026-11-18

### Bảo mật Cốt lõi (Security Fixes — P0 / Critical & High)
- **[FX-001] Chống HTTP/1.1 Request Smuggling (CL.TE / TE.CL / Duplicate CL)**: Từ chối ngay với mã `400 Bad Request` và đóng kết nối khi request chứa đồng thời `Content-Length` và `Transfer-Encoding`, hoặc có nhiều header `Content-Length` khác giá trị, hoặc `Content-Length` không phải chuỗi số thập phân thuần túy (`crates/ferrousx-http/src/server.rs`).
- **[FX-002] Gia cố Bộ phân tích Chunked Body & Chống Slowloris / Slow POST**: Loại bỏ hoàn toàn `unwrap_or(0)` khi phân tích kích thước chunk hex; kiểm tra nghiêm ngặt dấu kết thúc `\r\n`, tiêu thụ sạch trailer headers và áp dụng `client_header_timeout_ms` / `client_body_timeout_ms` cho toàn bộ chu kỳ đọc (`crates/ferrousx-http/src/server.rs`).
- **[FX-003] Sửa lỗi Cắt cụt Âm thầm (Silent Body Truncation) trên HTTP/2 & HTTP/3**: Trả về `413 Payload Too Large` ngay khi kích thước thân yêu cầu vượt quá `client_max_body_size` thay vì `break` và chuyển tiếp dữ liệu bị cắt cụt (`crates/ferrousx-http/src/server.rs`).
- **[FX-004] Tích hợp Trực tiếp `ZeroAllocWafEngine` vào Luồng Phục vụ**: Kích hoạt kiểm tra WAF (chế độ `Block` / `Monitor` / `Off`) và GCRA Rate Limiter trên mọi kết nối HTTP/1.1, HTTP/2, HTTP/3 và WebSocket Upgrade (`crates/ferrousx-http/src/server.rs`, `crates/ferrousx-proxy/src/waf.rs`).
- **[FX-005] Xác thực Đa lớp cho Admin IPC Socket & Embedded WebUI**:
  - Đặt quyền `0600` cho `/run/ferrousx/admin.sock`, kiểm tra chống tấn công Symlink trên thư mục cha, xác thực `SO_PEERCRED` (`uid`/`gid`) kết hợp khóa 256-bit CSPRNG tại `/etc/ferrousx/admin.token` (`0600`), hỗ trợ RBAC (`FullAdmin` vs `ReadOnly`) và khóa tạm thời chống Brute-Force (`crates/ferrousx-panel/src/api.rs`).
  - Bắt buộc xác thực Token, kiểm tra `Origin`/CSRF và bổ sung `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` cho Embedded WebUI (`crates/ferrousx-panel/src/webui.rs`).
- **[FX-006] Cô lập Dịch vụ phpMyAdmin về Loopback `127.0.0.1:888` & Loại bỏ `User=root`**:
  - Chuyển `ferrous-pma.service` từ `0.0.0.0:888` về `127.0.0.1:888`, chạy dưới quyền `User=www-data` với `CAP_NET_BIND_SERVICE` và đầy đủ Systemd Sandboxing (`scripts/ferrous-pma.service`).
  - Gia cố `scripts/pma-router.php` kiểm tra `REMOTE_ADDR` phải thuộc Loopback (`127.0.0.1` / `::1`) và chặn thư mục `/setup/`.

### Bảo mật Mạng, Proxy & FastCGI (P1 / High)
- **[FX-007] Nâng cấp Sharded IPv4/IPv6 GCRA Rate Limiter**: Chia 64 phân vùng độc lập, hỗ trợ cả IPv4 và IPv6, giới hạn cứng dung lượng bảng băm (`rate_limit_max_entries = 65536`) và thu hồi tự động theo TTL (`crates/ferrousx-proxy/src/waf.rs`).
- **[FX-008] Xác thực Trusted Proxy CIDR**: Chỉ tin cậy `CF-Connecting-IP`, `X-Forwarded-For`, `X-Forwarded-Proto` khi `peer_ip` khớp với danh sách CIDR `trusted_proxies` (`crates/ferrousx-config/src/config.rs`, `crates/ferrousx-http/src/server.rs`).
- **[FX-009] Chống SSRF & Giới hạn Bộ đệm Phản hồi Upstream**: Chặn kết nối tới `169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`, `0.0.0.0`, link-local, broadcast (kể cả qua DNS Rebinding) và giới hạn phản hồi upstream ở mức `max_upstream_response_bytes` (64 MiB).
- **[FX-010] Chống FastCGI Path Traversal & Httpoxy (`CVE-2016-5385`)**: Loại bỏ fallback `joined.starts_with(site_root)` chưa canonicalize, lọc bỏ biến `HTTP_PROXY` và giới hạn kích thước phản hồi FastCGI ở mức 64 MiB (`crates/ferrousx-proxy/src/fastcgi.rs`).
- **[FX-011] Khôi phục Systemd Sandboxing & Gia cố Script Cài đặt/Sửa chữa**: Xóa bỏ hoàn toàn đoạn mã tạo `container-compat.conf` và `root-fallback.conf` trong `scripts/install.sh` và `scripts/repair.sh`; bổ sung cờ `--dry-run`, `--check`, `--rollback` và sao lưu tự động vào `/var/backups/ferrousx/<timestamp>`.

### Gia cố TLS 1.3, QUIC & Kết nối (P2 / Medium)
- **[FX-012] Tắt Mặc định TLS 1.3 0-RTT & Giới hạn Luồng QUIC**: Đặt `enable_zero_rtt = false` (`max_early_data_size = 0`) mặc định để chống 0-RTT Replay Attack; giới hạn `max_concurrent_bidi_streams` và `max_idle_timeout` cho Quinn QUIC (`crates/ferrousx-bin/src/main.rs`).
- **[FX-013] Giới hạn Kết nối Đồng thời (`ActiveConnectionTracker`)**: Giới hạn tổng số kết nối đồng thời (`max_concurrent_connections`) và số kết nối trên mỗi IP (`max_connections_per_ip`) bằng RAII guard (`crates/ferrousx-http/src/server.rs`).
