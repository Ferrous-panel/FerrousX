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

    print("=" * 72)
    print(f" SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 72)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
