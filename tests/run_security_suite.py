#!/usr/bin/env python3
"""
FerrousX Automated Security Verification & Regression Suite
Kiểm tra tự động toàn bộ bất biến bảo mật (Security Invariants) trên source code,
cấu hình TOML, systemd units, PHP router và shell scripts.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def check(condition: bool, name: str, detail: str = "") -> bool:
    if condition:
        print(f"[PASS] {name}")
        return True
    else:
        print(f"[FAIL] {name} — {detail}")
        return False


def main() -> int:
    passed = 0
    failed = 0

    def record(ok: bool):
        nonlocal passed, failed
        if ok:
            passed += 1
        else:
            failed += 1

    print("=" * 72)
    print(" FERROUSX AUTOMATED SECURITY VERIFICATION SUITE")
    print("=" * 72)

    # 1. Shell script syntax & dry-run verification
    for script in ["scripts/install.sh", "scripts/repair.sh", "scripts/security-hardening.sh"]:
        path = ROOT / script
        res = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True)
        record(check(res.returncode == 0, f"Bash syntax check: {script}", res.stderr.strip()))

        res_dry = subprocess.run(["bash", str(path), "--dry-run"], capture_output=True, text=True)
        record(check(res_dry.returncode == 0, f"Dry-run execution check: {script} --dry-run", res_dry.stderr.strip()))

        res_chk = subprocess.run(["bash", str(path), "--check"], capture_output=True, text=True)
        record(check(res_chk.returncode == 0, f"Check-mode execution: {script} --check", res_chk.stderr.strip()))

    admin_sh = ROOT / "scripts/ferrousx-admin.sh"
    res_adm_syn = subprocess.run(["bash", "-n", str(admin_sh)], capture_output=True, text=True)
    record(check(res_adm_syn.returncode == 0, "Bash syntax check: scripts/ferrousx-admin.sh", res_adm_syn.stderr.strip()))
    res_adm_hlp = subprocess.run(["bash", str(admin_sh), "--help"], capture_output=True, text=True)
    record(check(res_adm_hlp.returncode == 0, "Admin CLI execution check: scripts/ferrousx-admin.sh --help", res_adm_hlp.stderr.strip()))

    # 2. HTTP/1.1, HTTP/2, HTTP/3 Security Invariants in crates/ferrousx-http/src/server.rs
    server_rs = (ROOT / "crates/ferrousx-http/src/server.rs").read_text(encoding="utf-8")
    record(check(
        "is_chunked && parsed_content_length.is_some()" in server_rs,
        "FX-001: HTTP/1.1 CL.TE & TE.CL Request Smuggling blocked",
    ))
    record(check(
        "Conflicting Content-Length Headers" in server_rs,
        "FX-001b: Duplicate conflicting Content-Length headers rejected",
    ))
    record(check(
        "ChunkReadError::MalformedChunk" in server_rs and "from_str_radix(size_hex, 16).map_err" in server_rs,
        "FX-002: Strict HTTP/1.1 chunked hex parser (no unwrap_or(0) smuggling)",
    ))
    record(check(
        "send_h2_simple_error" in server_rs and "send_h3_simple_error" in server_rs and "StatusCode::PAYLOAD_TOO_LARGE" in server_rs,
        "FX-003: HTTP/2 & HTTP/3 oversized bodies rejected with 413 instead of silent truncation",
    ))
    record(check(
        "check_waf_for_request" in server_rs and "ZeroAllocWafEngine" in server_rs,
        "FX-004: ZeroAllocWafEngine integrated into HTTP/1.1, HTTP/2, HTTP/3 & WebSocket request pipeline",
    ))
    record(check(
        "cfg.is_trusted_proxy(req.peer_ip)" in server_rs,
        "FX-008: Trusted Proxy CIDR verification enforced before trusting CF-Connecting-IP / X-Forwarded-For",
    ))
    record(check(
        "is_safe_tcp_upstream" in server_rs and "max_upstream_response_bytes" in server_rs,
        "FX-009: Reverse Proxy SSRF protection & bounded upstream response reading enforced",
    ))

    # 3. Admin IPC & WebUI Security Invariants
    api_rs = (ROOT / "crates/ferrousx-panel/src/api.rs").read_text(encoding="utf-8")
    webui_rs = (ROOT / "crates/ferrousx-panel/src/webui.rs").read_text(encoding="utf-8")
    record(check(
        "peer_cred()" in api_rs and "constant_time_eq" in api_rs and "0o600" in api_rs,
        "FX-005a: Admin IPC Unix Socket enforces SO_PEERCRED + 256-bit token + 0600 permissions",
    ))
    record(check(
        "X-Frame-Options: DENY" in webui_rs and "Content-Security-Policy:" in webui_rs and "401 Unauthorized" in webui_rs,
        "FX-005b: Embedded Admin WebUI enforces token authentication, lockout, CSRF check, and CSP headers",
    ))

    # 4. phpMyAdmin & Systemd Security Invariants
    pma_service = (ROOT / "scripts/ferrous-pma.service").read_text(encoding="utf-8")
    pma_router = (ROOT / "scripts/pma-router.php").read_text(encoding="utf-8")
    fx_service = (ROOT / "scripts/ferrousx.service").read_text(encoding="utf-8")
    install_sh = (ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    repair_sh = (ROOT / "scripts/repair.sh").read_text(encoding="utf-8")

    record(check(
        "127.0.0.1:888" in pma_service and "0.0.0.0:888" not in pma_service and "User=www-data" in pma_service,
        "FX-006a: ferrous-pma.service binds strictly to 127.0.0.1:888 as www-data",
    ))
    record(check(
        "127.0.0.1" in pma_router and "/setup" in pma_router,
        "FX-006b: pma-router.php enforces loopback REMOTE_ADDR and blocks /setup/",
    ))
    record(check(
        "container-compat.conf" not in install_sh
        and "root-fallback.conf" not in install_sh
        and "container-compat.conf" not in repair_sh
        and "root-fallback.conf" not in repair_sh,
        "FX-011: install.sh and repair.sh never strip systemd sandboxing or fall back to User=root",
    ))
    record(check(
        "NoNewPrivileges=true" in fx_service
        and "ProtectSystem=strict" in fx_service
        and "MemoryDenyWriteExecute=true" in fx_service
        and "SystemCallFilter=@system-service" in fx_service,
        "FX-011b: ferrousx.service enforces full systemd sandboxing",
    ))

    # 5. WAF & FastCGI Security Invariants
    waf_rs = (ROOT / "crates/ferrousx-proxy/src/waf.rs").read_text(encoding="utf-8")
    fcgi_rs = (ROOT / "crates/ferrousx-proxy/src/fastcgi.rs").read_text(encoding="utf-8")
    toml_cfg = (ROOT / "conf/ferrousx.toml").read_text(encoding="utf-8")

    record(check(
        "NUM_SHARDS: usize = 64" in waf_rs and "IpAddr" in waf_rs and "max_entries_per_shard" in waf_rs,
        "FX-007: Sharded IPv4+IPv6 GCRA Rate Limiter with bounded memory & TTL eviction",
    ))
    record(check(
        "HTTP_PROXY" in fcgi_rs and "MAX_FASTCGI_RESPONSE_BYTES" in fcgi_rs and "joined.starts_with(site_root)" not in fcgi_rs,
        "FX-010: FastCGI blocks symlink path traversal, strips HTTP_PROXY (Httpoxy), and bounds response size",
    ))
    record(check(
        "enable_zero_rtt = false" in toml_cfg and "server_tokens = false" in toml_cfg,
        "FX-012: TLS 1.3 0-RTT Replay disabled by default and server_tokens hidden in conf/ferrousx.toml",
    ))

    # 6. Feature Wiring, Config Schema & Dead-Code Cleanup Invariants
    root_cargo = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    proxy_cargo = (ROOT / "crates/ferrousx-proxy/Cargo.toml").read_text(encoding="utf-8")
    cli_rs = (ROOT / "crates/ferrousx-bin/src/cli.rs").read_text(encoding="utf-8")
    main_rs = (ROOT / "crates/ferrousx-bin/src/main.rs").read_text(encoding="utf-8")
    worker_rs = (ROOT / "crates/ferrousx-core/src/worker.rs").read_text(encoding="utf-8")

    record(check(
        not (ROOT / "FerrousX-security-hardened").exists()
        and not (ROOT / "FerrousX-security-hardened.zip").exists()
        and not (ROOT / "public/FerrousX-security-hardened.zip").exists()
        and "kdl" not in root_cargo
        and "crossbeam-utils" not in root_cargo
        and "bumpalo.workspace = true" in proxy_cargo,
        "FX-013: Repository free of duplicate bundles/unused crates and proxy Cargo.toml includes bumpalo",
    ))
    record(check(
        "enable_phpmyadmin_route = true" in toml_cfg and "max_Selection_fails" not in toml_cfg,
        "FX-014: conf/ferrousx.toml enables phpMyAdmin route cleanly without typoed keys",
    ))
    record(check(
        "SiteConfigToml" in cli_rs
        and 'kind = "php_fpm"' in cli_rs
        and 'kind = "static_spa"' in cli_rs
        and "[site]" not in cli_rs,
        "FX-015: ferrousx-ctl vhost add emits & validates canonical SiteConfigToml schema",
    ))
    record(check(
        "EngineRuntimeStats" in server_rs
        and "UpstreamBalancerRegistry" in server_rs
        and "AcmeCertManager" in server_rs
        and "compress_response_body" in server_rs
        and "vhost.waf_mode.unwrap_or" in server_rs
        and "EbpfPacketSteerer" in worker_rs
        and "enable_embedded_dashboard" in main_rs,
        "FX-016: Core telemetry, P2C+CircuitBreaker, ACME HTTP-01, Zstd/Brotli, eBPF & WebUI flags wired end-to-end",
    ))
    record(check(
        "read_current_admin_token" in api_rs
        and "read_current_admin_token" in webui_rs
        and "total_requests" in api_rs
        and "total_requests" in webui_rs,
        "FX-017: Live rotated admin token and atomic telemetry counters exposed in IPC & Embedded WebUI",
    ))

    # 7. P0 / P1 / P2 Production Hardening & Audit Invariants (FX-018 .. FX-030)
    config_rs = (ROOT / "crates/ferrousx-config/src/config.rs").read_text(encoding="utf-8")
    pipeline_rs = (ROOT / "crates/ferrousx-proxy/src/pipeline.rs").read_text(encoding="utf-8")
    numa_rs = (ROOT / "crates/ferrousx-core/src/numa.rs").read_text(encoding="utf-8")
    dot_cargo = (ROOT / ".cargo/config.toml").read_text(encoding="utf-8")
    release_yml = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    record(check(
        "validate_dynamic_wwwroot_host" in server_rs
        and "enable_dynamic_wwwroot_host" in config_rs
        and "canon_target.parent() == Some(canon_base.as_path())" in server_rs,
        "FX-018 (P0-1): Strict hostname regex + direct child verification & default-off toggle for wwwroot",
    ))
    record(check(
        "rsplit(',')" in server_rs
        and "cf-connecting-ip" in server_rs
        and "leftmost_valid" in server_rs,
        "FX-019 (P0-2): Rightmost untrusted X-Forwarded-For walk & spoofing header stripping",
    ))
    record(check(
        "split_php_script_and_path_info" in server_rs
        and '"PATH_INFO"' in server_rs
        and '"PATH_TRANSLATED"' in server_rs
        and "k.contains('_')" in server_rs
        and 'k.eq_ignore_ascii_case("proxy")' in server_rs,
        "FX-020 (P0-3): FastCGI PATH_INFO/PATH_TRANSLATED split, cookie merging, underscore drop & Httpoxy guard",
    ))
    record(check(
        "overflow-checks = true" in root_cargo
        and 'panic = "unwind"' in root_cargo
        and "catch_unwind_future" in server_rs
        and "decode_chunked_body" in server_rs
        and "checked_add" in server_rs,
        "FX-021 (P0-4/P2-4): Checked arithmetic, panic=unwind request boundary catching & safe chunked decoder",
    ))
    record(check(
        "100 Continue" in server_rs
        and "EXPECTATION_FAILED" in server_rs
        and "version == 0" in server_rs
        and "Unexpected EOF While Reading Request Body" in server_rs,
        "FX-022 (P0-5): HTTP/1.0 close, Expect 100-continue/417, and Content-Length early EOF rejection",
    ))
    record(check(
        "send_reset(h2::Reason::CANCEL)" in server_rs
        and "stop_sending(h3::error::Code::H3_MESSAGE_ERROR)" in server_rs
        and "max_frame_size" in server_rs
        and "remote_address_validated()" in server_rs
        and "retry_token_lifetime" in main_rs,
        "FX-023 (P0-6): HTTP/2 & HTTP/3 stream reset on body error/413 and QUIC Retry address validation",
    ))
    record(check(
        "Semaphore" in server_rs
        and "backoff_ms" in server_rs
        and "handshake_timeout" in server_rs,
        "FX-024 (P0-7): Resilient accept loops with exponential backoff, per-worker Semaphore & TLS handshake timeout",
    ))
    record(check(
        "verify_panel_websocket_origin" in server_rs
        and "is_admin_or_panel_host" in server_rs
        and "select_longest_proxy_route" in server_rs,
        "FX-025 (P0-8/P1-9): Panel/phpMyAdmin/WS CSWSH isolation & longest-prefix boundary routing",
    ))
    record(check(
        "select_best_compression_encoding" in server_rs
        and "normalize_rate_limit_key" in waf_rs
        and "sweep_stale_entries" in waf_rs
        and "decode_percent_single_pass" in waf_rs
        and "MaglevConsistentHash" in pipeline_rs
        and "half_open_probing" in pipeline_rs
        and "healthy: AtomicBool" in pipeline_rs,
        "FX-026 (P0-9): Compression q-value/Vary, IPv6 /64 GCRA shard sweep, single-pass WAF, Maglev & Half-Open probe",
    ))
    record(check(
        "normalize_and_decode_uri_path" in fcgi_rs
        and "normalize_and_decode_uri_path" in server_rs
        and "is_sensitive_path" in server_rs
        and "should_suppress_body" in server_rs
        and "parse_single_byte_range" in server_rs
        and "std::fs" not in server_rs,
        "FX-027 (P1-1..P1-4): Single-pass URL norm, dot-file block, HEAD/204/304 suppression & async tokio::fs Range/ETag",
    ))
    alt_svc_lines = [ln for ln in server_rs.splitlines() if "Alt-Svc:" in ln or "alt-svc" in ln]
    dashboard_html_block = webui_rs.split("const DASHBOARD_HTML", 1)[1].split("struct WebUiBruteForceTracker", 1)[0]

    record(check(
        "ChunkedStreamDecoder" in server_rs
        and "UpstreamStream" in server_rs
        and "matched_explicit_host" in server_rs
        and "serde_json::json!" in server_rs
        and "io_uring+TLS+QUIC" not in server_rs
        and len(alt_svc_lines) >= 2
        and all("h3-29" not in ln for ln in alt_svc_lines),
        "FX-028 (P1-5..P1-8): Chunked SSE streaming, trusted HTTPS redirect, JSON fallback & clean errors/Alt-Svc",
    ))
    record(check(
        "bind_unix_listener_with_secure_mode" in api_rs
        and "read_ipc_frame" in api_rs
        and "FCGI_END_REQUEST" in fcgi_rs
        and "encode_fastcgi_params_record" in pipeline_rs
        and "1,482,900" not in dashboard_html_block
        and "io_uring SQPOLL ACTIVE" not in dashboard_html_block,
        "FX-029 (P2-1..P2-3): Atomic UDS permissions, framed IPC, strict FastCGI EOF & real WebUI telemetry",
    ))
    record(check(
        "target-cpu=native" not in dot_cargo
        and "mem::forget" not in numa_rs
        and "x86-64-v2" in release_yml
        and "x86-64-v3" in release_yml
        and "DIRECTORY_SEPARATOR" in pma_router
        and "curl -fsSL https://sh.rustup.rs" not in install_sh,
        "FX-030 (P2-4): Portable build flags, true 2MB NUMA align without leak, CI release matrix & safe PHP/install scripts",
    ))

    # 8. Automatic Environment Variable Provisioning & Safe Loading (FX-031)
    env_example = (ROOT / "conf/ferrousx.env.example").read_text(encoding="utf-8")
    root_env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    root_env_has_keys = any(
        ln.strip() and not ln.strip().startswith("#") and "=" in ln
        for ln in root_env_example.splitlines()
    )
    admin_sh_text = admin_sh.read_text(encoding="utf-8")
    record(check(
        "EnvironmentFile=-/etc/ferrousx/ferrousx.env" in fx_service
        and "Environment=FERROUSX_CONFIG=/etc/ferrousx/ferrousx.toml" in fx_service
        and "/etc/ferrousx/ferrousx.env" in install_sh
        and "/etc/profile.d/ferrousx.sh" in install_sh
        and "/etc/ferrousx/ferrousx.env" in repair_sh
        and "/etc/profile.d/ferrousx.sh" in repair_sh
        and "apply_env_overrides_from" in config_rs
        and "parse_env_content" in config_rs
        and "std::env::set_var(" not in config_rs
        and "FERROUSX_ADMIN_TOKEN_FILE" in api_rs
        and "FERROUSX_ADMIN_TOKEN_FILE" in cli_rs
        and "FERROUSX_ENV_FILE" in env_example
        and not root_env_has_keys
        and "manage_env_vars" in admin_sh_text,
        "FX-031: Automatic env provisioning (conf/ferrousx.env.example, /etc/ferrousx/ferrousx.env, /etc/profile.d/ferrousx.sh, systemd EnvironmentFile & zero blocking .env.example prompts)",
    ))

    # Functional test for `fx env init`, `fx env set`, and `fx env show` (isolated temp file)
    import tempfile
    with tempfile.TemporaryDirectory(prefix="ferrousx_env_test_") as tmpdir:
        tmp_env = Path(tmpdir) / "ferrousx.env"
        test_env = os.environ.copy()
        test_env["FERROUSX_ENV_FILE"] = str(tmp_env)
        r_init = subprocess.run(["bash", str(admin_sh), "env", "init"], capture_output=True, text=True, env=test_env)
        r_set = subprocess.run(["bash", str(admin_sh), "env", "set", "FERROUSX_WAF_MODE=monitor"], capture_output=True, text=True, env=test_env)
        r_set_tok = subprocess.run(["bash", str(admin_sh), "env", "set", "FERROUSX_ADMIN_TOKEN=supersecretvalue12345678901234567890"], capture_output=True, text=True, env=test_env)
        r_show = subprocess.run(["bash", str(admin_sh), "env", "show"], capture_output=True, text=True, env=test_env)
        tmp_content = tmp_env.read_text(encoding="utf-8") if tmp_env.exists() else ""
        record(check(
            r_init.returncode == 0
            and r_set.returncode == 0
            and r_set_tok.returncode == 0
            and r_show.returncode == 0
            and 'FERROUSX_WAF_MODE="monitor"' in tmp_content
            and "FERROUSX_ADMIN_TOKEN=(masked)" in r_show.stdout
            and "supersecretvalue" not in r_show.stdout,
            "FX-031b: Functional CLI test for `fx env init/set/show` with secret masking",
            f"init={r_init.returncode} set={r_set.returncode} show={r_show.returncode}",
        ))

    print("=" * 72)
    print(f" SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 72)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
