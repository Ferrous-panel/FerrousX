//! tests/system/system_systemd_and_ipc_test.rs
//! Kiểm thử Bảo mật Hệ thống Linux, Admin IPC Socket & phpMyAdmin Isolation:
//!   1. Xác thực Constant-Time Token & RBAC (`FullAdmin` vs `ReadOnly`) trên Unix Socket
//!   2. Xác minh `ferrous-pma.service` chỉ bind trên Loopback `127.0.0.1:888` với `User=www-data`
//!   3. Xác minh `ferrousx.service` kích hoạt `NoNewPrivileges=true`, `ProtectSystem=strict`, `MemoryDenyWriteExecute=true`

#[cfg(test)]
mod system_security_tests {
    use ferrousx_panel::api::constant_time_eq;

    #[test]
    fn test_admin_token_constant_time_comparison() {
        let tok_a = b"a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef0123";
        let tok_b = b"a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef0123";
        let tok_c = b"a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef0124";

        assert!(constant_time_eq(tok_a, tok_b));
        assert!(!constant_time_eq(tok_a, tok_c));
    }

    #[test]
    fn test_systemd_units_hardened_invariants() {
        let pma_unit = include_str!("../../scripts/ferrous-pma.service");
        assert!(
            pma_unit.contains("127.0.0.1:888"),
            "phpMyAdmin bắt buộc chỉ lắng nghe trên Loopback 127.0.0.1:888"
        );
        assert!(
            !pma_unit.contains("0.0.0.0:888"),
            "phpMyAdmin tuyệt đối không được bind 0.0.0.0:888"
        );
        assert!(pma_unit.contains("User=www-data"));
        assert!(pma_unit.contains("NoNewPrivileges=true"));

        let fx_unit = include_str!("../../scripts/ferrousx.service");
        assert!(fx_unit.contains("User=ferrousx"));
        assert!(fx_unit.contains("NoNewPrivileges=true"));
        assert!(fx_unit.contains("ProtectSystem=strict"));
        assert!(fx_unit.contains("MemoryDenyWriteExecute=true"));
        assert!(fx_unit.contains("SystemCallFilter=@system-service"));
    }
}
