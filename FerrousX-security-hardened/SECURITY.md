# Chính sách Bảo mật FerrousX (SECURITY.md)

## 1. Các Phiên bản Được Hỗ trợ (Supported Versions)

| Phiên bản | Trạng thái Hỗ trợ Bảo mật | Môi trường Mục tiêu |
| :--- | :--- | :--- |
| **0.1.x (Security-Hardened)** | Được hỗ trợ đầy đủ (Active Security Support) | Ubuntu Server 22.04 / 24.04 LTS (x86_64) |
| **< 0.1.0-hardened** | Ngừng hỗ trợ (Yêu cầu nâng cấp ngay) | N/A |

## 2. Kiến trúc Bảo mật Cốt lõi

FerrousX được thiết kế theo nguyên tắc **Defense-in-Depth (Phòng thủ Nhiều Lớp)**:

1. **HTTP/1.1, HTTP/2 & HTTP/3 Framing Hardening**:
   - Từ chối tuyệt đối các yêu cầu chứa đồng thời `Content-Length` và `Transfer-Encoding` (`400 Bad Request`, đóng kết nối ngay) để triệt tiêu tấn công **CL.TE / TE.CL HTTP Request Smuggling**.
   - Từ chối nhiều header `Content-Length` xung đột giá trị hoặc kích thước chunked không phải số thập lục phân hợp lệ.
   - Giới hạn số luồng đồng thời HTTP/2 (`h2_max_concurrent_streams = 128`) kèm lá chắn **CVE-2023-44487 (HTTP/2 Rapid Reset)** và giới hạn luồng QUIC (`quic_max_concurrent_bidi_streams = 100`).
   - Trả về đúng mã `413 Payload Too Large` khi thân yêu cầu vượt quá `client_max_body_size` trên cả HTTP/1.1, HTTP/2 và HTTP/3 (không bao giờ cắt cụt âm thầm).
2. **TLS 1.3 & QUIC Cryptographic Hardening**:
   - Mặc định tắt TLS 1.3 Early Data (`enable_zero_rtt = false`, `max_early_data_size = 0`) để chống tấn công phát lại (**0-RTT Replay Attack**).
   - Tự động kiểm tra và siết quyền khóa bí mật TLS (`privkey.pem`) về `0600` và từ chối nạp khóa qua symlink.
3. **Sharded IPv4/IPv6 GCRA Rate Limiter & L7 WAF**:
   - Bộ giới hạn tốc độ GCRA chia 64 phân vùng (64 shards) hỗ trợ cả IPv4 và IPv6, giới hạn cứng số lượng bản ghi (`rate_limit_max_entries = 65536`) và tự động thu hồi theo TTL (`rate_limit_ttl_secs = 300`).
   - Kiểm tra sâu (L7 DPI) trên URI, Query, Headers và 64 KiB đầu của Body chống SQLi, XSS, Path Traversal, Command Injection, Log4Shell (`${jndi:`), Shellshock và CRLF Injection.
4. **Reverse Proxy & FastCGI Isolation**:
   - Chỉ tin cậy `CF-Connecting-IP`, `X-Forwarded-For` và `X-Forwarded-Proto` khi địa chỉ IP kết nối trực tiếp nằm trong danh sách `trusted_proxies` (Loopback + Cloudflare Edge CIDRs).
   - Chặn kết nối SSRF tới Cloud Metadata (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`), `0.0.0.0`, link-local và broadcast.
   - Chặn lỗ hổng **Httpoxy (`CVE-2016-5385`)** bằng cách lọc bỏ `HTTP_PROXY` trước khi truyền vào PHP-FPM FastCGI, và chuẩn hóa đường dẫn thực (`canonicalize`) để ngăn chặn Path Traversal qua symlink.
5. **Control Plane & phpMyAdmin Isolation**:
   - Admin Unix Socket (`/run/ferrousx/admin.sock`) đặt quyền `0600`, kiểm tra `SO_PEERCRED` (`uid`/`gid`) kết hợp khóa `admin.token` 256-bit CSPRNG (`/etc/ferrousx/admin.token`, quyền `0600`) với thuật toán so sánh thời gian hằng số.
   - Dịch vụ phpMyAdmin nội bộ (`ferrous-pma.service`) chỉ lắng nghe trên Loopback `127.0.0.1:888` dưới quyền `User=www-data` với `CAP_NET_BIND_SERVICE`.

## 3. Quy trình Báo cáo Lỗ hổng Bảo mật

Nếu bạn phát hiện lỗ hổng bảo mật trong FerrousX, vui lòng không mở Public Issue. Hãy gửi báo cáo chi tiết (kèm PoC và cấu hình tái hiện) tới nhóm bảo mật của Ferrous-Panel qua kênh GitHub Security Advisories tại `https://github.com/Ferrous-panel/FerrousX/security/advisories`.
