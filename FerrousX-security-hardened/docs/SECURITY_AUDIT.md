# Báo cáo Kiểm toán Bảo mật Toàn diện Dự án FerrousX (SECURITY_AUDIT.md)

**Dự án:** FerrousX — High-Performance Triple-Stack Web Server & Reverse Proxy (Rust Edition 2024)  
**Môi trường Mục tiêu:** Ubuntu Server 22.04 / 24.04 LTS (x86_64), Cloudflare Proxy, PHP-FPM, Ferrous-Panel v2.5.0  
**Phương pháp Kiểm toán:** White-Box Manual Code Review + Protocol State Analysis (RFC 9110/9112/9113/9114) + Linux Privilege & Systemd Sandbox Audit  

---

## 1. Tóm tắt Phân loại Phát hiện (Severity Breakdown)

| Mã Lỗ hổng | Tên Lỗ hổng | Mức độ | File Bị Ảnh hưởng | Trạng thái |
| :--- | :--- | :--- | :--- | :--- |
| **FX-001** | HTTP/1.1 Request Smuggling (`CL.TE`, `TE.CL`, Duplicate `Content-Length`, Invalid `Content-Length`) | **Critical (P0)** | `crates/ferrousx-http/src/server.rs` | **FIXED & VERIFIED** |
| **FX-002** | HTTP/1.1 Malformed Chunked Parser Smuggling (`unwrap_or(0)`) & Slowloris / Slow POST DoS | **Critical (P0)** | `crates/ferrousx-http/src/server.rs` | **FIXED & VERIFIED** |
| **FX-003** | HTTP/2 & HTTP/3 Oversized Request Body Silent Truncation (Bypassing `413 Payload Too Large`) | **High (P0)** | `crates/ferrousx-http/src/server.rs` | **FIXED & VERIFIED** |
| **FX-004** | WAF & Rate Limiter Dead Code (Chưa được tích hợp vào luồng xử lý Request thực tế) | **Critical (P0)** | `crates/ferrousx-http/src/server.rs`, `crates/ferrousx-proxy/src/waf.rs` | **FIXED & VERIFIED** |
| **FX-005** | Unauthenticated Admin IPC Unix Socket (`0o660`) & Unauthenticated Embedded Admin WebUI (`:9090`) | **Critical (P0)** | `crates/ferrousx-panel/src/api.rs`, `crates/ferrousx-panel/src/webui.rs`, `crates/ferrousx-bin/src/main.rs` | **FIXED & VERIFIED** |
| **FX-006** | Public Exposure of phpMyAdmin on `0.0.0.0:888` & Automatic `User=root` Fallback | **Critical (P0)** | `scripts/ferrous-pma.service`, `scripts/install.sh`, `scripts/repair.sh`, `scripts/pma-router.php` | **FIXED & VERIFIED** |
| **FX-007** | Unbounded Single-Mutex Rate Limiter HashMap (OOM DoS) & IPv6 Rate-Limit Bypass | **High (P1)** | `crates/ferrousx-proxy/src/waf.rs` | **FIXED & VERIFIED** |
| **FX-008** | Untrusted `CF-Connecting-IP` / `X-Forwarded-For` / `X-Forwarded-Proto` Spoofing | **High (P1)** | `crates/ferrousx-http/src/server.rs`, `crates/ferrousx-config/src/config.rs` | **FIXED & VERIFIED** |
| **FX-009** | Reverse Proxy SSRF (Cloud Metadata `169.254.169.254`) & Unbounded Upstream Response OOM | **High (P1)** | `crates/ferrousx-http/src/server.rs`, `crates/ferrousx-config/src/config.rs` | **FIXED & VERIFIED** |
| **FX-010** | FastCGI Uncanonicalized Fallback Path Traversal & `HTTP_PROXY` (Httpoxy `CVE-2016-5385`) | **High (P1)** | `crates/ferrousx-proxy/src/fastcgi.rs`, `crates/ferrousx-http/src/server.rs` | **FIXED & VERIFIED** |
| **FX-011** | Systemd Sandboxing Stripped by `container-compat.conf` & Destructive Installer Behavior | **High (P1)** | `scripts/install.sh`, `scripts/repair.sh`, `scripts/ferrousx.service` | **FIXED & VERIFIED** |
| **FX-012** | TLS 1.3 0-RTT Replay Enabled by Default (`max_early_data_size = u32::MAX`) & Unbounded QUIC Streams | **Medium (P2)** | `crates/ferrousx-config/src/config.rs`, `crates/ferrousx-bin/src/main.rs`, `conf/ferrousx.toml` | **FIXED & VERIFIED** |
| **FX-013** | Lack of Global / Per-IP Active Connection Limiter & Server Token Banner Disclosure | **Medium (P2)** | `crates/ferrousx-http/src/server.rs`, `conf/ferrousx.toml` | **FIXED & VERIFIED** |

---

## 2. Chi tiết Từng Phát hiện (9 Điểm Bắt buộc Theo Tiêu chuẩn Kiểm toán)

### [FX-001] HTTP/1.1 Request Smuggling (`CL.TE`, `TE.CL`, Duplicate `Content-Length`, Invalid `Content-Length`)
1. **Tên lỗ hổng:** HTTP/1.1 Request Smuggling & Ambiguous Framing Desynchronization.
2. **File bị ảnh hưởng:** `crates/ferrousx-http/src/server.rs`.
3. **Hàm hoặc vị trí code:** `serve_http1_connection` (dòng 230–285 trước khi vá).
4. **Nguyên nhân:** Vòng lặp phân tích header HTTP/1.1 cho phép một request chứa đồng thời cả `Content-Length` và `Transfer-Encoding: chunked`, dùng `val.trim().parse::<usize>().unwrap_or(0)` khi gặp `Content-Length` sai định dạng, và ghi đè âm thầm khi có nhiều header `Content-Length` khác giá trị.
5. **Điều kiện khai thác:** Kẻ tấn công gửi gói tin HTTP/1.1 qua kết nối Keep-Alive hoặc qua CDN/Reverse Proxy phía trước chứa đồng thời `Content-Length` và `Transfer-Encoding: chunked` hoặc hai header `Content-Length: 10` và `Content-Length: 50`.
6. **Ảnh hưởng thực tế:** Kẻ tấn công có thể đầu độc hàng đợi kết nối Keep-Alive (Request Smuggling), vượt qua quy tắc định tuyến/WAF, đánh cắp phiên của người dùng khác hoặc đầu độc bộ nhớ đệm CDN.
7. **Mức độ nghiêm trọng:** **Critical (P0)**.
8. **Cách sửa:**
   - Từ chối ngay với `400 Bad Request` (`Connection: close`) nếu xuất hiện đồng thời `Transfer-Encoding` và `Content-Length`.
   - Kiểm tra `Content-Length` chỉ gồm chữ số ASCII (`is_ascii_digit()`), từ chối nếu tràn số hoặc có nhiều `Content-Length` khác giá trị.
   - Từ chối nếu có nhiều hơn 1 header `Transfer-Encoding` hoặc giá trị khác `"chunked"`.
9. **Test chứng minh đã sửa:** `tests/http1_security/http1_smuggling_and_dos_test.rs` (`test_cl_te_request_smuggling_rejected`, `test_duplicate_conflicting_content_length_rejected`, `test_invalid_content_length_formats_rejected`) và kiểm tra tự động `FX-001` trong `tests/run_security_suite.py`.

---

### [FX-002] HTTP/1.1 Malformed Chunked Parser Smuggling (`unwrap_or(0)`) & Slowloris / Slow POST DoS
1. **Tên lỗ hổng:** Malformed Chunked Size Silent EOF Desync & Unbounded Body Read Timeout.
2. **File bị ảnh hưởng:** `crates/ferrousx-http/src/server.rs`.
3. **Hàm hoặc vị trí code:** `read_chunked_http1_body` (dòng 1369–1415 trước khi vá) và `serve_http1_connection` (dòng 192–208, 283–295 trước khi vá).
4. **Nguyên nhân:**
   - Trong `read_chunked_http1_body`, dòng `usize::from_str_radix(size_line, 16).unwrap_or(0)` biến mọi dòng kích thước chunk sai cú pháp (ví dụ `"ZZ\r\n"`) thành `0` (tức kết thúc body!), để lại toàn bộ phần dữ liệu phía sau nằm nguyên trong `read_buf` và bị thực thi như một HTTP Request thứ hai trên cùng kết nối Keep-Alive.
   - Ngoài ra, việc đọc body không được bọc trong `tokio::time::timeout(client_body_timeout_ms)` và việc đọc header đặt lại timeout trên từng lần `read_buf` thay vì tổng thời gian đọc header.
5. **Điều kiện khai thác:** Gửi request `Transfer-Encoding: chunked` có kích thước chunk không hợp lệ để cài cắm request giả mạo tiếp theo, hoặc gửi 1 byte mỗi 10 giây (Slowloris / Slow POST) để giữ cạn kiệt kết nối.
6. **Ảnh hưởng thực tế:** HTTP Request Smuggling qua chunked encoding lỗi và tấn công từ chối dịch vụ (DoS) làm nghẽn toàn bộ worker threads.
7. **Mức độ nghiêm trọng:** **Critical (P0)**.
8. **Cách sửa:**
   - Viết lại `read_chunked_http1_body` trả về `Result<Bytes, ChunkReadError>`: bắt buộc dòng kích thước chunk chỉ chứa ký tự Hex hợp lệ, kiểm tra đúng cặp `\r\n` sau mỗi chunk data, tiêu thụ sạch toàn bộ trailer headers (giới hạn 8 KiB) và đóng kết nối ngay khi gặp lỗi cú pháp (`400 Bad Request`).
   - Áp dụng tổng thời gian chờ `client_header_timeout_ms` cho toàn bộ khối đọc header và `client_body_timeout_ms` cho toàn bộ khối đọc body (`408 Request Timeout`).
9. **Test chứng minh đã sửa:** `crates/ferrousx-http/src/server.rs::tests::test_strict_chunked_decoder_rejects_malformed_hex` và `tests/run_security_suite.py` (`FX-002`).

---

### [FX-003] HTTP/2 & HTTP/3 Oversized Request Body Silent Truncation
1. **Tên lỗ hổng:** Silent Request Body Truncation on Oversized HTTP/2 & HTTP/3 Streams.
2. **File bị ảnh hưởng:** `crates/ferrousx-http/src/server.rs`.
3. **Hàm hoặc vị trí code:** `serve_http2_connection` (dòng 341–343 trước khi vá) và `serve_http3_quic_streams` (dòng 466–468 trước khi vá).
4. **Nguyên nhân:** Khi `body_buf.len() + chunk.len() > cfg.client_max_body_size`, vòng lặp chỉ gọi `break;` rồi tiếp tục chuyển tiếp phần body đã bị cắt cụt vào `dispatch_http_request` (tới PHP-FPM hoặc Upstream) thay vì trả lỗi `413 Payload Too Large`.
5. **Điều kiện khai thác:** Client gửi POST/PUT request qua HTTP/2 hoặc HTTP/3 có kích thước lớn hơn `client_max_body_size`.
6. **Ảnh hưởng thực tế:** Ứng dụng backend/PHP nhận được dữ liệu JSON/file upload bị cắt cụt giữa chừng mà không hề biết request đã vượt giới hạn, gây hỏng toàn vẹn dữ liệu hoặc lỗi logic xác thực.
7. **Mức độ nghiêm trọng:** **High (P0)**.
8. **Cách sửa:** Kiểm tra header `Content-Length` ngay từ đầu và kiểm tra kích thước luồng dữ liệu khi nhận frame; nếu vượt `client_max_body_size`, trả về ngay `413 Payload Too Large` (`send_h2_simple_error` / `send_h3_simple_error`) và **dừng xử lý**, không gọi `dispatch_http_request`.
9. **Test chứng minh đã sửa:** `tests/http2_security/http2_rapid_reset_and_limits_test.rs::test_http2_oversized_body_returns_413_without_truncation` và `tests/run_security_suite.py` (`FX-003`).

---

### [FX-004] WAF & Rate Limiter Dead Code (Chưa Tích hợp Vào Pipeline Phục vụ)
1. **Tên lỗ hổng:** Unintegrated Web Application Firewall & Rate Limiter.
2. **File bị ảnh hưởng:** `crates/ferrousx-http/src/server.rs`, `crates/ferrousx-proxy/src/waf.rs`.
3. **Hàm hoặc vị trí code:** `dispatch_http_request` trong `crates/ferrousx-http/src/server.rs`.
4. **Nguyên nhân:** Module `ZeroAllocWafEngine` tồn tại trong `ferrousx-proxy/src/waf.rs` nhưng không bao giờ được khởi tạo hay gọi trong `ferrousx-http/src/server.rs`.
5. **Điều kiện khai thác:** Mọi gói tin tấn công SQLi, XSS, Path Traversal, Command Injection hoặc HTTP Flood đi vào cổng 80/443 đều đi thẳng tới bộ định tuyến mà không qua WAF.
6. **Ảnh hưởng thực tế:** Tường lửa ứng dụng web (WAF) và bộ giới hạn tốc độ (Rate Limiter) hoàn toàn không có tác dụng bảo vệ thực tế.
7. **Mức độ nghiêm trọng:** **Critical (P0)**.
8. **Cách sửa:** Khởi tạo `Arc<ZeroAllocWafEngine>` trong `run_dual_stack_worker` theo cấu hình `[waf]` từ `ferrousx.toml`, truyền vào cả 3 luồng HTTP/1.1, HTTP/2, HTTP/3 và gọi `check_waf_for_request` ngay đầu `dispatch_http_request` cũng như trước khi nâng cấp WebSocket (`handle_websocket_upgrade`). Hỗ trợ đầy đủ chế độ `Block`, `Monitor` và `Off` ở cả cấp toàn cục và từng VirtualHost.
9. **Test chứng minh đã sửa:** `tests/waf/waf_rate_limit_and_dpi_test.rs` và `tests/run_security_suite.py` (`FX-004`).

---

### [FX-005] Unauthenticated Admin IPC Unix Socket (`0o660`) & Embedded Admin WebUI (`:9090`)
1. **Tên lỗ hổng:** Unauthenticated Control Plane IPC & Local WebUI Privilege Escalation.
2. **File bị ảnh hưởng:** `crates/ferrousx-panel/src/api.rs`, `crates/ferrousx-panel/src/webui.rs`, `crates/ferrousx-bin/src/main.rs`.
3. **Hàm hoặc vị trí code:** `start_admin_ipc_server`, `handle_ipc_connection`, `start_embedded_webui_server`.
4. **Nguyên nhân:**
   - Unix socket `/run/ferrousx/admin.sock` được tạo với quyền `0o660`, không kiểm tra symlink trên thư mục cha, không kiểm tra `SO_PEERCRED` (`uid`/`gid`) và không yêu cầu token xác thực.
   - `crates/ferrousx-bin/src/main.rs` gọi hàm `PanelServer::new` không khớp chữ ký hàm trong `ferrousx-panel/src/api.rs`.
   - Giao diện WebUI nội bộ trên `127.0.0.1:9090` cho phép bất kỳ tiến trình cục bộ nào (hoặc kẻ tấn công SSRF trên máy chủ) gọi `POST /api/reload` hoặc đọc cấu hình mà không cần xác thực, không có CSRF check hay CSP header.
5. **Điều kiện khai thác:** Một tiến trình web/PHP bị xâm nhập hoặc tài khoản local trên VPS gửi lệnh tới `/run/ferrousx/admin.sock` hoặc `http://127.0.0.1:9090/api/reload`.
6. **Ảnh hưởng thực tế:** Leo thang đặc quyền thao túng cấu hình máy chủ, gây DoS hoặc đánh cắp thông tin cấu hình nội bộ.
7. **Mức độ nghiêm trọng:** **Critical (P0)**.
8. **Cách sửa:**
   - Tự động sinh khóa 256-bit CSPRNG từ `/dev/urandom` lưu tại `/etc/ferrousx/admin.token` với quyền `0o600`.
   - Kiểm tra chống symlink trên thư mục `/run/ferrousx`, đặt quyền socket `0o600` (hoặc `0o660` khi cấu hình nhóm đọc), xác thực `stream.peer_cred()` (`uid == 0` hoặc `uid == process_uid` hoặc `auth_token` hợp lệ qua `constant_time_eq`), áp dụng RBAC (`FullAdmin` vs `ReadOnly`) và khóa Brute-Force.
   - Bắt buộc header `X-FerrousX-Token` / `Authorization: Bearer` trên mọi API của Embedded WebUI (`:9090`), kiểm tra `Origin` chống CSRF và bổ sung đầy đủ `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`.
9. **Test chứng minh đã sửa:** `crates/ferrousx-panel/src/api.rs::tests::test_authenticate_ipc_peer_rbac_and_lockout`, `tests/system/system_systemd_and_ipc_test.rs` và `tests/run_security_suite.py` (`FX-005a`, `FX-005b`).

---

### [FX-006] Public Exposure of phpMyAdmin on `0.0.0.0:888` & Automatic `User=root` Fallback
1. **Tên lỗ hổng:** Direct Public Network Exposure of phpMyAdmin Built-in PHP Server & Root Privilege Escalation.
2. **File bị ảnh hưởng:** `scripts/ferrous-pma.service`, `scripts/install.sh`, `scripts/repair.sh`, `scripts/pma-router.php`.
3. **Hàm hoặc vị trí code:** `ExecStart=/usr/bin/php -S 0.0.0.0:888` trong `scripts/ferrous-pma.service` và hàm `create_pma_root_fallback` trong `scripts/install.sh`, `scripts/repair.sh`.
4. **Nguyên nhân:** Dịch vụ phpMyAdmin bind trực tiếp ra toàn bộ card mạng `0.0.0.0:888`, đồng thời `install.sh` mở cổng `ufw allow 888/tcp` và tự động tạo drop-in `User=root` nếu bind cổng 888 thất bại.
5. **Điều kiện khai thác:** Kẻ tấn công trên Internet kết nối thẳng vào `http://<VPS_IP>:888` (bỏ qua hoàn toàn Cloudflare, TLS và WAF của FerrousX). Nếu khai thác được lỗ hổng trong phpMyAdmin/PHP, kẻ tấn công chiếm ngay quyền `root` trên VPS.
6. **Ảnh hưởng thực tế:** Phơi bày trực tiếp công cụ quản trị cơ sở dữ liệu qua HTTP không mã hóa ra Internet và nguy cơ mất quyền `root` toàn máy chủ.
7. **Mức độ nghiêm trọng:** **Critical (P0)**.
8. **Cách sửa:**
   - Đổi `ExecStart` trong `scripts/ferrous-pma.service` thành `127.0.0.1:888` (chỉ lắng nghe trên Loopback nội bộ), chạy cố định dưới `User=www-data` với `AmbientCapabilities=CAP_NET_BIND_SERVICE` và bật đầy đủ Systemd Sandboxing (`ProtectSystem=strict`, `NoNewPrivileges=true`, `PrivateTmp=true`).
   - Xóa hoàn toàn hàm `create_pma_root_fallback` và xóa quy tắc mở cổng `888/tcp` trên UFW.
   - Bổ sung kiểm tra `REMOTE_ADDR === 127.0.0.1 || ::1` và chặn `/setup/` trong `scripts/pma-router.php`.
9. **Test chứng minh đã sửa:** `tests/system/system_systemd_and_ipc_test.rs::test_systemd_units_hardened_invariants` và `tests/run_security_suite.py` (`FX-006a`, `FX-006b`).

---

### [FX-007] Unbounded Single-Mutex Rate Limiter HashMap (OOM DoS) & IPv6 Rate-Limit Bypass
1. **Tên lỗ hổng:** Unbounded Memory Growth in Rate Limiter & IPv6 Verification Bypass.
2. **File bị ảnh hưởng:** `crates/ferrousx-proxy/src/waf.rs`.
3. **Hàm hoặc vị trí code:** `GcraRateLimiter::check_and_update_ipv4`.
4. **Nguyên nhân:** `GcraRateLimiter` chỉ nhận khóa `u32` (IPv4) nằm dưới 1 `Mutex<HashMap<u32, Instant>>` duy nhất và không có giới hạn số lượng phần tử hay cơ chế dọn dẹp TTL khi `len() <= 500_000`.
5. **Điều kiện khai thác:** Kẻ tấn công gửi lưu lượng qua IPv6 để bỏ qua hoàn toàn Rate Limiter, hoặc flood hàng triệu địa chỉ IP giả mạo để làm phình bộ nhớ và gây tranh chấp khóa Mutex.
6. **Ảnh hưởng thực tế:** Bỏ qua giới hạn tốc độ bằng IPv6 hoặc gây suy giảm hiệu năng / tràn bộ nhớ (OOM).
7. **Mức độ nghiêm trọng:** **High (P1)**.
8. **Cách sửa:** Thiết kế lại `GcraRateLimiter` với 64 phân vùng độc lập (`SHARD_COUNT = 64`), hỗ trợ khóa `IpAddr` (cả IPv4 và IPv6), giới hạn cứng số lượng bản ghi mỗi phân vùng (`rate_limit_max_entries = 65536`), tự động thu hồi bản ghi hết hạn TTL (`rate_limit_ttl_secs = 300`) kết hợp trục xuất LRU khi đầy.
9. **Test chứng minh đã sửa:** `crates/ferrousx-proxy/src/waf.rs::tests::test_sharded_rate_limiter_ipv4_and_ipv6_and_bounded_memory` và `tests/waf/waf_rate_limit_and_dpi_test.rs`.

---

### [FX-008] Untrusted `CF-Connecting-IP` / `X-Forwarded-For` / `X-Forwarded-Proto` Spoofing
1. **Tên lỗ hổng:** Client IP & Protocol Spoofing via Unverified Forwarded Headers.
2. **File bị ảnh hưởng:** `crates/ferrousx-http/src/server.rs`, `crates/ferrousx-config/src/config.rs`.
3. **Hàm hoặc vị trí code:** `resolve_real_client_ip` và `is_request_https` trong `crates/ferrousx-http/src/server.rs`.
4. **Nguyên nhân:** Server luôn tin cậy giá trị `CF-Connecting-IP`, `X-Forwarded-For` và `X-Forwarded-Proto` từ mọi kết nối TCP/QUIC mà không kiểm tra xem địa chỉ IP kết nối trực tiếp (`req.peer_ip`) có phải là Cloudflare hoặc Reverse Proxy tin cậy hay không.
5. **Điều kiện khai thác:** Kẻ tấn công kết nối trực tiếp vào IP gốc của VPS và gửi kèm header `CF-Connecting-IP: 127.0.0.1` hoặc đổi IP ngẫu nhiên trên mỗi request.
6. **Ảnh hưởng thực tế:** Vô hiệu hóa hoàn toàn Rate Limiter theo IP, giả mạo IP quản trị nội bộ (`127.0.0.1`) trong nhật ký và ứng dụng backend.
7. **Mức độ nghiêm trọng:** **High (P1)**.
8. **Cách sửa:** Bổ sung danh sách CIDR `trusted_proxies` (mặc định gồm `127.0.0.1/32`, `::1/128` và toàn bộ dải IPv4/IPv6 chính thức của Cloudflare) cùng bộ kiểm tra bitwise CIDR `cfg.is_trusted_proxy(req.peer_ip)`. Nếu `peer_ip` không nằm trong `trusted_proxies`, bỏ qua toàn bộ header `CF-Connecting-IP` / `X-Forwarded-*` do client gửi lên và sử dụng trực tiếp `req.peer_ip`.
9. **Test chứng minh đã sửa:** `tests/proxy/proxy_ssrf_fastcgi_and_xff_test.rs::test_trusted_proxy_cidr_verification_blocks_spoofed_xff`.

---

### [FX-009] Reverse Proxy SSRF (Cloud Metadata `169.254.169.254`) & Unbounded Upstream Response OOM
1. **Tên lỗ hổng:** Server-Side Request Forgery (SSRF) & Unbounded Upstream Response Buffering.
2. **File bị ảnh hưởng:** `crates/ferrousx-http/src/server.rs`, `crates/ferrousx-config/src/config.rs`.
3. **Hàm hoặc vị trí code:** `proxy_http1_upstream` và `read_full_http1_response` trong `crates/ferrousx-http/src/server.rs`.
4. **Nguyên nhân:**
   - Không kiểm tra đích kết nối upstream với danh sách địa chỉ cấm SSRF (như AWS/GCP/Cloud Metadata `169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`, `0.0.0.0`, multicast, broadcast).
   - `read_full_http1_response` gọi `stream.read_to_end(&mut raw)` không có giới hạn dung lượng, cho phép một dịch vụ upstream lỗi hoặc bị chiếm quyền gửi luồng dữ liệu vô hạn làm OOM tiến trình `ferrousx-bin`.
5. **Điều kiện khai thác:** Cấu hình upstream trỏ tới tên miền phân giải về `169.254.169.254` (DNS Rebinding) hoặc upstream trả về phản hồi hàng chục GB.
6. **Ảnh hưởng thực tế:** Rò rỉ IAM credentials của Cloud VPS hoặc sập toàn bộ web server do tràn RAM (OOM).
7. **Mức độ nghiêm trọng:** **High (P1)**.
8. **Cách sửa:** Kiểm tra địa chỉ upstream bằng `validate_upstream_origin` và kiểm tra lại `stream.peer_addr()` sau khi kết nối TCP bằng `is_forbidden_ssrf_ip` (chống DNS Rebinding). Giới hạn vòng lặp đọc phản hồi upstream ở mức `cfg.max_upstream_response_bytes` (64 MiB), trả về `502 Bad Gateway` nếu vượt ngưỡng.
9. **Test chứng minh đã sửa:** `tests/proxy/proxy_ssrf_fastcgi_and_xff_test.rs::test_ssrf_cloud_metadata_and_link_local_blocked`.

---

### [FX-010] FastCGI Uncanonicalized Fallback Path Traversal & `HTTP_PROXY` (Httpoxy `CVE-2016-5385`)
1. **Tên lỗ hổng:** Symlink Escape in FastCGI Path Resolution & Httpoxy Header Injection.
2. **File bị ảnh hưởng:** `crates/ferrousx-proxy/src/fastcgi.rs`, `crates/ferrousx-http/src/server.rs`.
3. **Hàm hoặc vị trí code:** `safe_resolve_under_root`, `execute_fastcgi` và `serve_vhost_site_root`.
4. **Nguyên nhân:**
   - Trong `safe_resolve_under_root`, nhánh fallback cuối cùng có đoạn `if joined.starts_with(site_root) { return Some(joined); }` trả về đường dẫn chưa qua `canonicalize()`, có thể bị lợi dụng nếu thư mục con là symlink trỏ ra ngoài `site_root`.
   - `serve_vhost_site_root` chuyển mọi header client `X` thành `HTTP_X` bao gồm cả header `Proxy: ...` -> `HTTP_PROXY`, gây lỗ hổng **Httpoxy (`CVE-2016-5385`)** trong các thư viện PHP.
5. **Điều kiện khai thác:** Gửi request kèm header `Proxy: http://attacker.com:8080` tới bất kỳ trang `.php` nào, hoặc truy cập qua symlink nằm trong thư mục webroot.
6. **Ảnh hưởng thực tế:** Chiếm quyền điều khiển lưu lượng kết nối ra ngoài của ứng dụng PHP (Httpoxy) hoặc đọc tệp ngoài phạm vi website.
7. **Mức độ nghiêm trọng:** **High (P1)**.
8. **Cách sửa:** Xóa bỏ hoàn toàn nhánh fallback không qua `canonicalize()` trong `safe_resolve_under_root`; luôn đối chiếu với `canonical_root = site_root.canonicalize()`. Bổ sung `sanitize_fastcgi_params` loại bỏ `HTTP_PROXY`, kiểm tra NUL/CRLF và giới hạn kích thước phản hồi FastCGI ở mức `MAX_FASTCGI_RESPONSE_BYTES` (64 MiB).
9. **Test chứng minh đã sửa:** `crates/ferrousx-proxy/src/fastcgi.rs::tests` và `tests/proxy/proxy_ssrf_fastcgi_and_xff_test.rs::test_fastcgi_httpoxy_and_path_traversal_blocked`.

---

### [FX-011] Systemd Sandboxing Stripped by `container-compat.conf` & Destructive Installer Behavior
1. **Tên lỗ hổng:** Automated Stripping of Systemd Security Directives in Installer & Repair Scripts.
2. **File bị ảnh hưởng:** `scripts/install.sh`, `scripts/repair.sh`, `scripts/ferrousx.service`.
3. **Hàm hoặc vị trí code:** Hàm `apply_systemd_container_compat` trong `scripts/install.sh` và `scripts/repair.sh`.
4. **Nguyên nhân:** Cả hai script tự động ghi tệp `/etc/systemd/system/ferrousx.service.d/container-compat.conf` đặt `MemoryDenyWriteExecute=false`, hạ `ProtectSystem=strict` xuống `full` và xóa trắng `CapabilityBoundingSet=` trên mọi máy chủ. Ngoài ra script tự động `systemctl mask nginx` mà không tạo bản sao lưu khôi phục (`--rollback`).
5. **Điều kiện khai thác:** Chạy `install.sh` hoặc `repair.sh` trên VPS Production làm vô hiệu hóa các lớp cô lập tiến trình của systemd.
6. **Ảnh hưởng thực tế:** Nếu tiến trình bị khai thác, kẻ tấn công không bị giới hạn bởi `MemoryDenyWriteExecute` (W^X) hoặc `CapabilityBoundingSet`.
7. **Mức độ nghiêm trọng:** **High (P1)**.
8. **Cách sửa:** Xóa bỏ hoàn toàn `apply_systemd_container_compat` và tự động dọn dẹp các thư mục drop-in cũ; bổ sung `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK`, `SystemCallFilter=@system-service`, `UMask=0027` vào `scripts/ferrousx.service`; bổ sung `--dry-run`, `--check`, `--rollback` và cơ chế sao lưu có đóng dấu thời gian tại `/var/backups/ferrousx/<timestamp>`.
9. **Test chứng minh đã sửa:** `tests/system/system_systemd_and_ipc_test.rs` và `tests/run_security_suite.py` (`FX-011`, `FX-011b`).

---

### [FX-012] TLS 1.3 0-RTT Replay Enabled by Default & Unbounded QUIC Streams
1. **Tên lỗ hổng:** TLS 1.3 0-RTT Early Data Replay Vulnerability & Unbounded QUIC Stream Concurrency.
2. **File bị ảnh hưởng:** `crates/ferrousx-config/src/config.rs`, `crates/ferrousx-bin/src/main.rs`, `conf/ferrousx.toml`.
3. **Hàm hoặc vị trí code:** `TlsSecurityConfig::default`, `build_tls_and_quic_configs`.
4. **Nguyên nhân:** `enable_zero_rtt` mặc định là `true` và `quic_tls_cfg.max_early_data_size` được đặt bằng `u32::MAX`, cho phép kẻ tấn công bắt gói tin 0-RTT và phát lại các yêu cầu không idempotent. Đồng thời `quinn::TransportConfig` chưa giới hạn `max_concurrent_bidi_streams`.
5. **Điều kiện khai thác:** Bắt gói tin QUIC 0-RTT trên đường truyền và phát lại tới máy chủ.
6. **Ảnh hưởng thực tế:** Thực thi lặp lại các giao dịch HTTP không an toàn (Replay Attack) hoặc làm cạn kiệt tài nguyên qua hàng vạn luồng QUIC đồng thời.
7. **Mức độ nghiêm trọng:** **Medium (P2)**.
8. **Cách sửa:** Đặt `enable_zero_rtt = false` mặc định (`max_early_data_size = 0`), cảnh báo rõ nếu người dùng bật, và giới hạn `max_concurrent_bidi_streams(100)`, `max_concurrent_uni_streams(32)`, `max_idle_timeout` trên Quinn `TransportConfig`.
9. **Test chứng minh đã sửa:** `tests/http3_security/http3_quic_and_0rtt_test.rs`.

---

### [FX-013] Lack of Global / Per-IP Active Connection Limiter & Server Token Disclosure
1. **Tên lỗ hổng:** Connection Exhaustion DoS & Server Banner Information Disclosure.
2. **File bị ảnh hưởng:** `crates/ferrousx-http/src/server.rs`, `conf/ferrousx.toml`.
3. **Hàm hoặc vị trí code:** `run_tcp_plain_http_loop`, `run_tcp_https_loop`, `run_udp_h3_quic_loop`.
4. **Nguyên nhân:** Các vòng lặp `accept()` tạo `spawn_local` không giới hạn tổng số kết nối đang mở hoặc số kết nối trên mỗi IP, và `conf/ferrousx.toml` bật `server_tokens = true` mặc định.
5. **Điều kiện khai thác:** Một IP mở hàng chục nghìn kết nối TCP/QUIC đồng thời để làm cạn kiệt File Descriptors của tiến trình.
6. **Ảnh hưởng thực tế:** Từ chối dịch vụ (Connection Exhaustion DoS).
7. **Mức độ nghiêm trọng:** **Medium (P2)**.
8. **Cách sửa:** Triển khai `ActiveConnectionTracker` với RAII `ConnectionGuard` giới hạn `max_concurrent_connections` (32768) và `max_connections_per_ip` (256), đồng thời đặt `server_tokens = false` mặc định trong `conf/ferrousx.toml`.
9. **Test chứng minh đã sửa:** `tests/run_security_suite.py` (`FX-012`).
