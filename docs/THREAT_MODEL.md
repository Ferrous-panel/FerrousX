# Mô hình Đe dọa & Bề mặt Tấn công FerrousX (THREAT_MODEL.md)

Tài liệu này phân tích toàn bộ bề mặt tấn công (Attack Surface), ranh giới tin cậy (Trust Boundaries) và các biện pháp giảm thiểu rủi ro (Mitigations) của FerrousX trên môi trường Production VPS Ubuntu 24.04 LTS.

---

## 1. Sơ đồ Ranh giới Tin cậy (Trust Boundaries)

```text
[Internet / Untrusted Clients / Cloudflare Edge]
       │
       │  (Ranh giới Tin cậy 1: Public Network Sockets — TCP :80, TCP :443, UDP :443)
       ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ Tiến trình: ferrousx-bin (User=ferrousx, Systemd Sandbox, W^X Memory)      │
│  ├─ 1. ActiveConnectionTracker (Global & Per-IP Connection Cap)            │
│  ├─ 2. Trusted Proxy CIDR Verifier (CF-Connecting-IP / X-Forwarded-For)    │
│  ├─ 3. Strict Protocol Framing (HTTP/1.1 Smuggling Shield, H2/H3 Limits)   │
│  └─ 4. ZeroAllocWafEngine (64-Shard GCRA Rate Limiter + L7 DPI WAF)        │
└──────┬──────────────────────────┬───────────────────────────┬──────────────┘
       │                          │                           │
       │ (Ranh giới 2: FastCGI)   │ (Ranh giới 3: Loopback)   │ (Ranh giới 4: Control Plane)
       ▼                          ▼                           ▼
┌─────────────────────┐  ┌─────────────────────────┐  ┌──────────────────────────┐
│ PHP-FPM Unix Socket │  │ Upstream Backends       │  │ Admin IPC & Local WebUI  │
│ /run/php/php*-fpm   │  │ - Ferrous-Panel (:9999) │  │ - /run/ferrousx/admin.sock│
│ - Canonical Root    │  │ - phpMyAdmin (127.0.0.1 │  │   (0600 + SO_PEERCRED)   │
│ - Httpoxy Filtered  │  │   :888, User=www-data)  │  │ - 127.0.0.1:9090 (Token) │
└─────────────────────┘  └─────────────────────────┘  └──────────────────────────┘
```

---

## 2. Phân tích 8 Bề mặt Tấn công Trọng yếu (STRIDE Analysis)

| # | Bề mặt Tấn công | Mối đe dọa Chính (STRIDE) | Cơ chế Phòng vệ Đã Triển khai trong FerrousX |
| :--- | :--- | :--- | :--- |
| **1** | **Public HTTP/1.1, HTTP/2, HTTP/3 Listeners (`:80`, `:443`)** | **Tampering / DoS**: Request Smuggling (`CL.TE`/`TE.CL`), Slowloris, Slow POST, HTTP/2 Rapid Reset (`CVE-2023-44487`), QUIC Stream Exhaustion. | - Từ chối kết hợp `Content-Length` + `Transfer-Encoding` (`400 Bad Request`).<br>- Bộ giải mã chunked hex nghiêm ngặt, tổng deadline `client_header_timeout_ms` & `client_body_timeout_ms`.<br>- Giới hạn `h2_max_concurrent_streams = 128`, `Http2CveShield` và `quic_max_concurrent_bidi_streams = 100`. |
| **2** | **TLS Termination & SNI Resolver (`:443`)** | **Replay / Information Disclosure**: TLS 1.3 0-RTT Replay Attack, rò rỉ khóa bí mật `privkey.pem`, downgrade cipher. | - Mặc định tắt 0-RTT (`enable_zero_rtt = false`, `max_early_data_size = 0`).<br>- Chỉ sử dụng `rustls` ring provider (TLS 1.3 & TLS 1.2 AEAD ECDHE).<br>- Kiểm tra chống symlink và ép quyền `0600` trên mọi tệp `privkey.pem`. |
| **3** | **Reverse Proxy Upstream Engine** | **Spoofing / Elevation / DoS**: Giả mạo `CF-Connecting-IP` / `X-Forwarded-For`, SSRF vào Cloud Metadata `169.254.169.254`, DNS Rebinding, Upstream Response OOM. | - Chỉ nhận `CF-Connecting-IP`/`X-Forwarded-*` khi `peer_ip` khớp CIDR `trusted_proxies`.<br>- Chặn IP SSRF trước và sau phân giải DNS (`is_forbidden_ssrf_ip`).<br>- Giới hạn phản hồi upstream ở mức `max_upstream_response_bytes` (64 MiB). |
| **4** | **PHP-FPM FastCGI Bridge** | **Information Disclosure / Tampering**: Path Traversal qua `..` hoặc Symlink, Httpoxy (`HTTP_PROXY`), CRLF Header Injection. | - Chuẩn hóa đường dẫn thực (`canonicalize`) đối chiếu với `canonical_root` trong `safe_resolve_under_root`.<br>- Loại bỏ biến `HTTP_PROXY` và lọc ký tự NUL/CRLF trong `sanitize_fastcgi_params`. |
| **5** | **Admin Unix Socket (`/run/ferrousx/admin.sock`)** | **Elevation of Privilege**: Tiến trình cục bộ không có quyền gửi lệnh `reload`/`upgrade`, tấn công Symlink trên `/run/ferrousx`. | - Kiểm tra chống Symlink trên `/run/ferrousx` (`0750`), đặt quyền socket `0600`.<br>- Xác thực `SO_PEERCRED` (`uid`/`gid`) + khóa 256-bit `/etc/ferrousx/admin.token` (`constant_time_eq`) + RBAC + Brute-Force Lockout. |
| **6** | **Embedded Admin WebUI (`127.0.0.1:9090`)** | **Spoofing / Tampering**: Truy cập API không xác thực, CSRF từ trình duyệt quản trị viên, XSS. | - Bắt buộc header `X-FerrousX-Token` / `Authorization: Bearer`.<br>- Kiểm tra `Origin` chống CSRF trên `POST /api/reload`.<br>- Đính kèm `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`. |
| **7** | **Config Loader & Hot-Reload (`SIGHUP` / File Watcher)** | **Denial of Service / Tampering**: Nạp cấu hình lỗi làm sập dịch vụ đang chạy, Path Traversal qua tên miền Vhost. | - Kiểm tra toàn diện cú pháp TOML và chứng chỉ TLS trước khi hoán đổi con trỏ nguyên tử `ArcSwap` (nếu lỗi, giữ nguyên Epoch cấu hình cũ với 0 kết nối bị ngắt). |
| **8** | **Systemd Services & Installer Scripts** | **Elevation of Privilege**: Chạy dịch vụ với quyền `root`, phơi bày phpMyAdmin trên `0.0.0.0:888`, tắt Systemd Sandboxing. | - `ferrousx.service` chạy dưới `User=ferrousx` với `ProtectSystem=strict`, `NoNewPrivileges=true`, `MemoryDenyWriteExecute=true`.<br>- `ferrous-pma.service` chỉ bind `127.0.0.1:888` dưới `User=www-data`. |
