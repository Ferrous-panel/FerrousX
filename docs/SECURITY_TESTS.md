# Tài liệu Kiểm thử Bảo mật Tự động (SECURITY_TESTS.md)

Tài liệu này mô tả cấu trúc bộ kiểm thử bảo mật của FerrousX và hướng dẫn chạy xác minh trên môi trường CI/CD hoặc máy chủ Ubuntu 24.04 LTS.

---

## 1. Cấu trúc Bộ Kiểm thử Bảo mật (`/tests/`)

| Thư mục / Tệp Kiểm thử | Phạm vi Kiểm thử | Các Mã Lỗ hổng Được Kiểm chứng |
| :--- | :--- | :--- |
| `tests/http1_security/http1_smuggling_and_dos_test.rs` | Kiểm thử chống `CL.TE` / `TE.CL` Request Smuggling, Duplicate `Content-Length`, Invalid `Content-Length`, CRLF/NUL Header Injection. | `FX-001`, `FX-002` |
| `tests/http2_security/http2_rapid_reset_and_limits_test.rs` | Kiểm thử lá chắn `CVE-2023-44487` (HTTP/2 Rapid Reset) và kiểm tra trả mã `413 Payload Too Large` khi vượt `client_max_body_size`. | `FX-003` |
| `tests/http3_security/http3_quic_and_0rtt_test.rs` | Kiểm thử tắt mặc định TLS 1.3 0-RTT (`enable_zero_rtt = false`) và giới hạn luồng đồng thời QUIC (`quic_max_concurrent_bidi_streams`). | `FX-003`, `FX-012` |
| `tests/waf/waf_rate_limit_and_dpi_test.rs` | Kiểm thử Sharded GCRA Rate Limiter (IPv4 + IPv6, giới hạn bộ nhớ, TTL eviction) và L7 DPI WAF (SQLi, XSS, Path Traversal, Log4Shell). | `FX-004`, `FX-007` |
| `tests/proxy/proxy_ssrf_fastcgi_and_xff_test.rs` | Kiểm thử chặn SSRF (`169.254.169.254`, `fd00:ec2::254`, `0.0.0.0`), xác thực CIDR `trusted_proxies`, chặn FastCGI Path Traversal & Httpoxy (`HTTP_PROXY`). | `FX-008`, `FX-009`, `FX-010` |
| `tests/system/system_systemd_and_ipc_test.rs` | Kiểm thử Constant-Time Admin Token, RBAC (`FullAdmin` vs `ReadOnly`), cô lập Loopback `127.0.0.1:888` của `ferrous-pma.service` và Systemd Sandboxing. | `FX-005`, `FX-006`, `FX-011` |
| `tests/run_security_suite.py` | Trình chạy kiểm thử bất biến bảo mật tự động (Python + Bash): kiểm tra cú pháp bash, `--dry-run`, `--check` và toàn bộ 22 bất biến bảo mật từ `FX-001` đến `FX-013`. | `FX-001` .. `FX-013` |

---

## 2. Các Unit Test Nội bộ trong từng Crate

Ngoài thư mục `/tests/`, các crate cốt lõi đều tích hợp sẵn bộ `#[cfg(test)] mod tests`:
- `crates/ferrousx-config/src/config.rs`:
  - `test_trusted_proxy_cidr_matching`
  - `test_ssrf_ip_and_upstream_validation`
  - `test_zero_rtt_disabled_by_default`
- `crates/ferrousx-http/src/server.rs`:
  - `test_strip_port_and_header_sanitizers`
  - `test_strict_chunked_decoder_rejects_malformed_hex`
  - `test_strict_chunked_decoder_valid_chunks`
- `crates/ferrousx-proxy/src/waf.rs`:
  - `test_sharded_rate_limiter_ipv4_and_ipv6_and_bounded_memory`
  - `test_waf_blocks_attacks_and_allows_normal_requests`
- `crates/ferrousx-proxy/src/fastcgi.rs`:
  - `test_safe_resolve_under_root_blocks_traversal`
  - `test_sanitize_fastcgi_params_blocks_httpoxy_and_crlf`
- `crates/ferrousx-panel/src/api.rs`:
  - `test_constant_time_eq_security`
  - `test_authenticate_ipc_peer_rbac_and_lockout`

---

## 3. Hướng dẫn Chạy Kiểm thử

### 3.1. Chạy Bộ Kiểm thử Bất biến Bảo mật & Script (Python + Bash)
```bash
python3 tests/run_security_suite.py
```

### 3.2. Chạy Toàn bộ Unit & Integration Tests trên Rust Toolchain
```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

### 3.3. Kiểm tra Cú pháp Cấu hình Production & Chứng chỉ TLS
```bash
./target/release/ferrousx-bin --check-config --config conf/ferrousx.toml
```
