# Nhật ký Bản vá Bảo mật Chi tiết (SECURITY_PATCHLOG.md)

Tài liệu này ghi nhận chi tiết các thay đổi mã nguồn theo từng file và hàm trong đợt nâng cấp **FerrousX Security Hardening & Production Patch**.

---

## 1. `crates/ferrousx-config/src/config.rs`

- **Các cấu trúc mới được bổ sung:**
  - `WafMode` (`Off`, `Monitor`, `Block`): Cho phép cấu hình chế độ WAF toàn cục hoặc riêng cho từng VirtualHost.
  - `WafConfig`: Cấu hình `enabled`, `mode`, `rate_limit_rps` (150), `rate_limit_burst` (75), `rate_limit_max_entries` (65536), `rate_limit_ttl_secs` (300), `max_inspect_body_bytes` (65536).
  - `AdminSecurityConfig`: Cấu hình `token_file_path` (`/etc/ferrousx/admin.token`), `session_ttl_secs` (1800), `max_failed_attempts` (5), `brute_force_lockout_secs` (300), `cors_allowed_origins`, `allow_read_group_gid`, `require_peer_uid_auth`.
- **Các hàm bảo mật mới:**
  - `ServerConfig::is_trusted_proxy(&self, peer_ip: IpAddr) -> bool` & `ip_in_cidr(ip: IpAddr, cidr_or_ip: &str) -> bool`: Kiểm tra địa chỉ IP kết nối trực tiếp có thuộc danh sách CIDR `trusted_proxies` (Loopback + Cloudflare Edge IPv4/IPv6) hay không.
  - `is_forbidden_ssrf_ip(ip: IpAddr) -> bool` & `validate_upstream_origin(addr: &str) -> Result<()>`: Chặn kết nối SSRF tới AWS/GCP/Azure Cloud Metadata (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`), `0.0.0.0`, link-local (`169.254.0.0/16`, `fe80::/10`), multicast và broadcast.
- **Gia cố mặc định:**
  - `TlsSecurityConfig::enable_zero_rtt`: Đổi mặc định từ `true` sang `false` để chống 0-RTT Replay Attack.
  - `server_tokens`: Đổi mặc định sang `false`.

---

## 2. `crates/ferrousx-http/src/server.rs`

- **Bộ giới hạn kết nối (`ActiveConnectionTracker` & `ConnectionGuard`):**
  - Theo dõi tổng số kết nối đang mở (`max_concurrent_connections`) và số kết nối trên mỗi IP (`max_connections_per_ip`) bằng RAII guard tự động giảm bộ đếm khi kết nối đóng.
- **HTTP/1.1 Framing & Request Smuggling Shield (`serve_http1_connection` & `read_chunked_http1_body`):**
  - Áp dụng tổng thời gian chờ `client_header_timeout_ms` cho toàn bộ chu kỳ đọc header (chống Slowloris) và `client_body_timeout_ms` cho toàn bộ chu kỳ đọc body (chống Slow POST).
  - Từ chối ngay với `400 Bad Request` (`Connection: close`) nếu request có đồng thời `Content-Length` và `Transfer-Encoding` (chống `CL.TE` / `TE.CL` Request Smuggling).
  - Từ chối nếu có nhiều header `Content-Length` khác giá trị hoặc `Content-Length` chứa ký tự không phải chữ số thập phân.
  - Từ chối nếu có nhiều header `Transfer-Encoding` hoặc giá trị khác `"chunked"`.
  - Kiểm tra nghiêm ngặt dòng kích thước chunk hex trong `read_chunked_http1_body` (trả lỗi `ChunkReadError::MalformedChunk` thay vì `unwrap_or(0)`), kiểm tra `\r\n` sau mỗi chunk và tiêu thụ sạch trailer headers.
- **HTTP/2 & HTTP/3 Oversized Body Fix (`serve_http2_connection` & `serve_http3_quic_streams`):**
  - Cấu hình `h2::server::Builder` với `max_concurrent_streams` và `max_header_list_size`.
  - Khi kích thước body vượt quá `cfg.client_max_body_size`, trả về ngay `413 Payload Too Large` (`send_h2_simple_error` / `send_h3_simple_error`) và dừng xử lý thay vì cắt cụt âm thầm.
- **Tích hợp WAF (`check_waf_for_request`):**
  - Kiểm tra mọi request HTTP/1.1, HTTP/2, HTTP/3 và WebSocket Upgrade qua `ZeroAllocWafEngine::inspect_full_request`.
- **Reverse Proxy & FastCGI (`resolve_real_client_ip`, `proxy_http1_upstream`, `read_full_http1_response`):**
  - Chỉ tin cậy `CF-Connecting-IP`, `X-Forwarded-For`, `X-Forwarded-Proto` khi `cfg.is_trusted_proxy(req.peer_ip)` trả về `true`.
  - Kiểm tra địa chỉ upstream và `stream.peer_addr()` với `is_forbidden_ssrf_ip` (chống SSRF & DNS Rebinding).
  - Giới hạn bộ đệm đọc phản hồi upstream ở mức `cfg.max_upstream_response_bytes` (64 MiB).

---

## 3. `crates/ferrousx-proxy/src/waf.rs` & `crates/ferrousx-proxy/src/fastcgi.rs`

- **`waf.rs`:**
  - Nâng cấp `GcraRateLimiter` lên kiến trúc 64 phân vùng (`SHARD_COUNT = 64`), hỗ trợ cả `IpAddr::V4` và `IpAddr::V6`, giới hạn cứng số bản ghi mỗi shard và tự động thu hồi theo TTL / LRU.
  - Mở rộng `ZeroAllocWafEngine::inspect_full_request` kiểm tra URI, Query, Headers (chặn CRLF/NUL, Log4Shell `${jndi:`, Shellshock, scanner signatures) và 64 KiB đầu của Body.
- **`fastcgi.rs`:**
  - Loại bỏ hoàn toàn nhánh fallback chưa `canonicalize()` trong `safe_resolve_under_root`, đảm bảo mọi đường dẫn tệp và thư mục cha đều phải nằm dưới `canonical_root`.
  - Bổ sung `sanitize_fastcgi_params` loại bỏ `HTTP_PROXY` (chống Httpoxy `CVE-2016-5385`), lọc ký tự điều khiển NUL/CRLF và giới hạn phản hồi FastCGI ở mức `MAX_FASTCGI_RESPONSE_BYTES` (64 MiB).

---

## 4. `crates/ferrousx-panel/src/api.rs`, `webui.rs` & `crates/ferrousx-bin/src/{main.rs,cli.rs}`

- **`api.rs` & `cli.rs`:**
  - Kiểm tra chống Symlink trên `/run/ferrousx` (`0o750`) và đặt quyền socket `/run/ferrousx/admin.sock` ở mức `0o600`.
  - Tự động sinh khóa 256-bit CSPRNG từ `/dev/urandom` lưu tại `/etc/ferrousx/admin.token` (`0o600`).
  - Xác thực `stream.peer_cred()` (`uid`/`gid`) kết hợp `auth_token` (so sánh thời gian hằng số `constant_time_eq`), phân quyền RBAC (`FullAdmin` vs `ReadOnly`) và khóa Brute-Force.
- **`webui.rs`:**
  - Bắt buộc xác thực Token trên `/api/status` và `/api/reload`, kiểm tra `Origin` chống CSRF và đính kèm `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`.
- **`main.rs`:**
  - Tự động kiểm tra và siết quyền khóa bí mật TLS (`privkey.pem`) về `0o600`.
  - Cấu hình `TransportConfig` của Quinn QUIC với `max_concurrent_bidi_streams`, `max_concurrent_uni_streams` và `max_idle_timeout`.

---

## 5. `scripts/{install.sh,repair.sh,security-hardening.sh,ferrousx.service,ferrous-pma.service,pma-router.php}`

- **`ferrous-pma.service` & `pma-router.php`:**
  - Cô lập dịch vụ phpMyAdmin về `127.0.0.1:888` dưới quyền `User=www-data` với `CAP_NET_BIND_SERVICE` và đầy đủ Systemd Sandboxing.
  - Kiểm tra `REMOTE_ADDR` trong `pma-router.php` chỉ chấp nhận `127.0.0.1` / `::1` và chặn `/setup/`.
- **`install.sh` & `repair.sh`:**
  - Xóa bỏ hoàn toàn đoạn mã tạo `container-compat.conf` và `root-fallback.conf`.
  - Bổ sung `--dry-run`, `--check`, `--rollback`, `--yes` và sao lưu tự động tại `/var/backups/ferrousx/<timestamp>`.
