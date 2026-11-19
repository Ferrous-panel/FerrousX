# PROMPT SỬA LỖI FERROUSX (dán vào Google AI Studio)

Bạn là kỹ sư Rust senior chuyên về máy chủ web và bảo mật. Dưới đây là báo cáo lỗi từ đợt review tĩnh repo FerrousX (workspace Rust, edition 2024). Hãy sửa LẦN LƯỢT theo thứ tự ưu tiên P0 → P1 → P2.

## Quy tắc bắt buộc
- Chỉ sửa đúng các mục được liệt kê. Không refactor, không đổi tên public API, không đụng phần giao diện React/TS.
- Giữ 100% Rust cho production. Không thêm phụ thuộc mới trừ khi thật sự cần (nếu thêm, nêu rõ lý do).
- Sau mỗi mục: code phải qua `cargo check --workspace` và `cargo clippy`. Mỗi mục phải có ít nhất 1 unit test hoặc integration test chứng minh lỗi đã hết.
- Không "làm giả" tính năng. Nếu tính năng chưa nối vào server thì nối thật, hoặc xóa tuyên bố sai. Không để số liệu giả trong dashboard.
- Với mỗi mục, trả về: (1) nguyên nhân gốc, (2) diff đã sửa, (3) test, (4) rủi ro còn lại.

---

## P0: Bảo mật và sập tiến trình

### P0-1. `Host: .` làm lộ toàn bộ `/www/wwwroot`
File: `crates/ferrousx-http/src/server.rs`, hàm `dispatch_http_request`, bước 5 (tự dò `/www/wwwroot/<host>`).
Lỗi: chỉ chặn `..` và `/`. Host `.` hợp lệ nên `dynamic_root` trỏ vào cả `/www/wwwroot`.
Sửa: chỉ chấp nhận host khớp regex tên miền hợp lệ (`[a-z0-9]([a-z0-9.-]*[a-z0-9])?`, không bắt đầu bằng `.` hoặc `-`, không có `..`, không `\`, không NUL), chuyển về chữ thường, và sau `canonicalize` phải là thư mục con TRỰC TIẾP của wwwroot. Thêm tùy chọn cấu hình để tắt hẳn tính năng tự dò này (mặc định TẮT).
Test: `Host: .`, `Host: ..`, `Host: .git`, `Host: a/b`, `Host: a\b` đều không phục vụ file.

### P0-2. Giả mạo IP client và `X-Forwarded-Proto`
File: `server.rs`, `resolve_real_client_ip`, `is_request_https`, `build_upstream_http1_request`.
Lỗi: tin `CF-Connecting-IP` / `X-Forwarded-For` / `X-Forwarded-Proto` từ bất kỳ ai.
Sửa: thêm cấu hình `trusted_proxies` (danh sách CIDR, kèm tùy chọn nạp dải IP Cloudflare). Chỉ đọc các header đó khi `peer_ip` nằm trong danh sách. Ngược lại dùng `peer_ip` và XÓA các header đó trước khi chuyển tiếp. Khi dùng `X-Forwarded-For`, lấy phần tử phải nhất không thuộc trusted_proxies, không lấy phần tử đầu tiên.
Test: client ngoài danh sách gửi `CF-Connecting-IP: 1.2.3.4` thì `REMOTE_ADDR` vẫn là IP thật.

### P0-3. httpoxy và header CGI
File: `server.rs` (đoạn dựng `extra_headers` cho FastCGI).
Sửa: bỏ header `Proxy`; gộp header trùng tên (đặc biệt nhiều header `cookie` của HTTP/2 phải nối bằng `; `, các header khác nối bằng `, `); bỏ header có tên chứa `_` (tránh `X_Foo` trùng `X-Foo`); không chuyển `Content-Length`/`Content-Type` thành `HTTP_*`.
Thêm `PATH_INFO`/`PATH_TRANSLATED` bằng cách tách theo `.php` (giống `fastcgi_split_path_info`).
Test: gửi `Proxy: http://evil` thì PHP không thấy `HTTP_PROXY`; hai header `cookie` được nối đúng.

### P0-4. Tràn số và body chunked sai
File: `server.rs`, `read_chunked_http1_body`, `decode_chunked_body`; `Cargo.toml` (profile release).
Lỗi: `out.len() + chunk_len` có thể tràn (release đang `overflow-checks = false`); chunk-size lỗi bị coi là `0`; EOF giữa chừng vẫn coi là body hợp lệ; dòng chunk-size không giới hạn độ dài; không timeout khi đọc body; `idx + chunk_len` có thể làm `raw[idx..end]` panic (process abort vì `panic = "abort"`).
Sửa:
- Dùng `checked_add`/`saturating_add` ở mọi phép cộng kích thước. Đặt `overflow-checks = true` cho release.
- Chunk-size không hợp lệ hoặc quá 16 hex digit thì trả 400 và đóng kết nối. EOF sớm thì trả 400.
- Giới hạn dòng chunk-size (tối đa 128 byte) và tổng buffer. Xử lý trailer đúng RFC 9112.
- Thêm `body_timeout` cấu hình được (đọc body và mỗi chunk).
- Viết lại `decode_chunked_body` trả `Result`, không bao giờ panic.
Test: chunk size `FFFFFFFFFFFFFFF0` sau một chunk hợp lệ phải bị từ chối; fuzz nhanh bằng `proptest` hoặc `cargo-fuzz`.

### P0-5. Smuggling qua Content-Length / Transfer-Encoding (HTTP/1)
File: `server.rs`, `serve_http1_connection`.
Sửa: từ chối (400) khi có đồng thời `Content-Length` và `Transfer-Encoding`; nhiều `Content-Length` khác nhau; giá trị không phải số; `Transfer-Encoding` khác đúng `chunked`. Body ngắn hơn `Content-Length` (EOF sớm) thì trả 400, không chuyển body cắt cụt. Trả `413` thay vì đóng im lặng khi chunked vượt giới hạn. Xử lý `Expect: 100-continue`. HTTP/1.0 mặc định đóng kết nối.

### P0-6. HTTP/2 và HTTP/3 cắt body thay vì trả 413
File: `server.rs`, `serve_http2_connection`, `serve_http3_quic_streams`.
Lỗi: vượt `client_max_body_size` thì `break` rồi vẫn xử lý request với body cắt cụt; lỗi đọc stream bị bỏ qua.
Sửa: vượt giới hạn thì trả 413 và reset stream; lỗi đọc thì reset stream, không dispatch. Cấu hình tường minh `max_concurrent_streams`, `max_header_list_size`, `max_frame_size`, keep-alive/idle timeout cho h2. Cấu hình QUIC: giới hạn bidi streams, bật `use_retry` (address validation) và `max_idle_timeout`.

### P0-7. Accept loop làm chết cả worker
File: `server.rs`, `run_tcp_plain_http_loop`, `run_tcp_https_loop`, `run_dual_stack_worker`.
Lỗi: `listener.accept().await?` — lỗi tạm thời (EMFILE, ECONNABORTED) làm `try_join!` kết thúc toàn bộ worker.
Sửa: bắt lỗi, `warn!`, ngủ ngắn (backoff 5–100 ms) rồi tiếp tục. Thêm giới hạn kết nối đồng thời mỗi worker (Semaphore) và timeout bắt tay TLS.

### P0-8. Chiếm route và WebSocket tới panel
File: `server.rs`, `is_panel_request`, `handle_websocket_upgrade`, `dispatch_http_request`.
Sửa:
- Khi `customDomain` rỗng, KHÔNG route các path `/api/*` của panel trên mọi host. Chỉ route theo host panel hoặc `securityEntrance`. Dùng so khớp có ranh giới path (`== prefix` hoặc `starts_with(prefix + "/")`).
- WebSocket không khớp route nào thì trả 404, KHÔNG fallback sang panel upstream. Chỉ chấp nhận route có `backend_protocol` là proxy. Kiểm tra `Origin` phải khớp host panel khi tunnel tới panel (chống CSWSH cho `/ws/ssh`). Thêm connect timeout và idle timeout cho tunnel; hỗ trợ upstream `unix:`.
- Route `/phpmyadmin` chỉ áp dụng cho host/IP quản trị, không chiếm path của site khách.

### P0-9. Nối thật WAF / rate limit / nén (hoặc gỡ tuyên bố)
Files: `crates/ferrousx-proxy/src/{waf.rs,pipeline.rs}`, `server.rs`.
Lỗi: `ZeroAllocWafEngine`, `GcraRateLimiter`, `Http2CveShield`, middleware pipeline, `CircuitBreaker`, `UpstreamBalancer`, nén br/zstd đều không được gọi.
Sửa:
- Gọi WAF + rate limit trong `dispatch_http_request` trước khi định tuyến (kể cả IPv6: key theo `IpAddr`, IPv6 gom theo /64).
- Rate limiter: dùng `Mutex`/shard theo core thay vì một `RwLock` toàn cục; có dọn dẹp bảng TAT định kỳ để không phình bộ nhớ; sửa comment "8 byte/IP".
- WAF: giải mã percent-encoding (một lần, không đệ quy), so khớp không phân biệt hoa thường (`%2E%2E`), chuẩn hóa path trước khi kiểm tra; không chặn nhầm tên file hợp lệ như `a..b.txt`.
- Nén Brotli/Zstd thật: parse `Accept-Encoding` có q-value, thêm `Vary: Accept-Encoding`, chỉ nén MIME text/json/js/svg và body > ngưỡng.
- Cân bằng tải: dùng cả pool, bỏ qua node không healthy (`healthy` phải là `AtomicBool`), failover; `MaglevConsistentHash` hiện chỉ là round-robin: cài đặt thật hoặc gỡ tên đó.
- Circuit breaker half-open chỉ cho đúng 1 request thăm dò.
- Nếu không nối được mục nào thì xóa code chết và sửa README/docs cho đúng thực tế.

---

## P1: Sai khác so với nginx / lỗi chức năng

### P1-1. Percent-decoding và chuẩn hóa URL
Hiện không có bước giải mã `%xx` nào, nên `/anh%20dep.jpg` hoặc tên file tiếng Việt cho 404.
Sửa: một hàm chuẩn hóa duy nhất: giải mã `%xx` một lần, từ chối `%00` và `%2f` trong segment, loại `.`/`..`, gộp `//`, rồi mới đưa vào `safe_resolve_under_root`, kiểm tra file nhạy cảm và WAF. Sửa `safe_resolve_under_root` để không từ chối nhầm `a..b`.

### P1-2. Chặn file nhạy cảm đúng cách
Hiện chỉ chặn `.ht*` và `.env`. Sửa: mặc định chặn mọi segment bắt đầu bằng `.` (trừ `/.well-known/`), cộng danh sách cấu hình: `.env*`, `.git`, `composer.json/lock`, `*.sql`, `*.bak`, `*.log`, `*.ini`, `wp-config.php.*`.

### P1-3. HTTP/1 `HEAD`
`write_http1_response` vẫn gửi body cho HEAD. Truyền method vào, không gửi body nhưng giữ `Content-Length` đúng. Không gửi body cho 1xx/204/304.

### P1-4. Phục vụ file tĩnh đúng cách
Hiện `tokio::fs::read` nạp cả file vào RAM. Sửa: stream theo khối, hỗ trợ `Range`/`206`, `ETag`, `Last-Modified`, `If-None-Match`/`If-Modified-Since`, `Cache-Control` theo cấu hình. Dùng API `tokio::fs`, không dùng `std::fs` đồng bộ trong đường xử lý request (`exists`, `is_file`, `canonicalize`). `MimeDetector` cần không phân biệt hoa thường, thêm các loại còn thiếu (`map`, `webmanifest`, `csv`, ...). Thư mục không có `/` cuối thì redirect 301.

### P1-5. Reverse proxy streaming
`read_full_http1_response` đọc hết bằng `read_to_end`, không giới hạn kích thước, timeout áp lên cả quá trình tải. Sửa: đọc header rồi stream body (hoặc giới hạn kích thước rõ ràng), timeout theo từng lần đọc (idle), hỗ trợ SSE. Bỏ qua phản hồi `100 Continue`. Không hạ `https://` upstream xuống TCP thường một cách im lặng: hoặc hỗ trợ TLS tới upstream, hoặc báo lỗi cấu hình.

### P1-6. Chuyển hướng HTTPS sau Cloudflare
Redirect hiện bỏ qua `X-Forwarded-Proto`. Chỉ khi peer thuộc `trusted_proxies` mới tin header này để tránh vòng lặp redirect với Cloudflare Flexible. Location phải dùng host đã khớp vhost (không phản chiếu Host tùy ý của vhost `_`).

### P1-7. Fallback JSON bị chèn ký tự
Bước 6 của `dispatch_http_request` ghép `host`/`path` thẳng vào JSON. Dùng `serde_json::json!`, và bỏ `"engine":"io_uring+..."` vì code không dùng io_uring.

### P1-8. Rò rỉ thông tin trong lỗi
Lỗi 502 hiện in địa chỉ socket/upstream và nội dung lỗi nội bộ ra client. Chỉ log phía server, trả thông điệp chung. Header `Server` phải tôn trọng `server_tokens` ở cả HTTP/2 và HTTP/3; bỏ `h3-29` khỏi Alt-Svc; không quảng bá Alt-Svc khi UDP/QUIC không bind được.

### P1-9. Routing vhost
Route khớp theo thứ tự cấu hình, prefix không có ranh giới (`/api` khớp `/apixyz`). Sửa: khớp ranh giới path và chọn prefix dài nhất. Route không có `target_upstream` không được âm thầm bỏ qua.

---

## P2: Panel API, build, tài liệu

### P2-1. `crates/ferrousx-panel/src/api.rs`
- Đặt quyền socket 0o660 TRƯỚC khi nhận kết nối (dùng umask tạm hoặc tạo thư mục 0o750), tránh cửa sổ race.
- Đọc theo khung (xuống dòng hoặc độ dài) thay vì một lần `read` 8192 byte; thêm timeout; giới hạn kích thước.
- Lệnh không biết phải trả `success: false`, không phải "đã tiếp nhận".
- Chuẩn hóa `action` (lowercase) cho cả JSON; `total_requests`, `active_connections`, `workers` hiện luôn rỗng/0: nối với số liệu thật hoặc bỏ trường.

### P2-2. `crates/ferrousx-panel/src/webui.rs`
Dashboard đang hiển thị số liệu giả (1,482,900 RPS, 0.32 ms, 8.2 MB, 42 µs) và nhãn "io_uring SQPOLL ACTIVE". Thay bằng số liệu thật từ telemetry hoặc xóa. Kiểm tra method/path, thêm xác thực hoặc chỉ bind 127.0.0.1.

### P2-3. FastCGI (`crates/ferrousx-proxy/src/fastcgi.rs`)
- Không chấp nhận EOF giữa chừng như thành công; giới hạn tổng kích thước STDOUT; timeout theo bước.
- `parse_cgi_output`: tách header/body bằng dấu phân cách XUẤT HIỆN TRƯỚC (hiện có thể cắt sai nếu body chứa `\r\n\r\n`).
- Gọi `read_exact` an toàn với `request_id`/version; cân nhắc `FCGI_KEEP_CONN` để tái dùng kết nối.
- `encode_fastcgi_params_record` trong `pipeline.rs` cắt `content_len as u16` khi params > 65535: xóa bản trùng, dùng một bản duy nhất có chia chunk.

### P2-4. Build và release
- `.cargo/config.toml`: bỏ `target-cpu=native` khỏi cấu hình mặc định (chỉ dùng trong script build cục bộ), release CI dùng `x86-64-v2/v3` có kiểm tra.
- `Cargo.toml`: `overflow-checks = true` cho release; cân nhắc `panic = "unwind"` + `catch_unwind` ở ranh giới request để một request lỗi không giết cả server.
- `numa.rs`: mmap không căn 2 MiB thật (chỉ căn 4 KiB) nên `MADV_HUGEPAGE` kém hiệu quả: cấp dư rồi căn thủ công; nhánh non-unix đang `mem::forget` gây rò rỉ; kiểm tra tràn số khi làm tròn kích thước.
- Rà soát `.github/workflows/release.yml` và các script trong `scripts/` (`install.sh`, `repair.sh`, `security-hardening.sh`, `pma-router.php`) về quyền file, `curl | sh`, và lưu bí mật.

## Định dạng trả lời
Trả lời theo từng mục (P0-1, P0-2, ...). Với mỗi mục đưa diff dạng unified và test đi kèm. Cuối cùng liệt kê các mục bạn KHÔNG làm được hoặc cần quyết định của tôi.
