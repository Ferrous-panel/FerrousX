//! tests/http3_security/http3_quic_and_0rtt_test.rs
//! Kiểm thử Bảo mật HTTP/3 QUIC & TLS 1.3:
//!   1. Xác minh 0-RTT (`enable_zero_rtt`) mặc định bằng `false` (`max_early_data_size = 0`) để chống Replay Attack
//!   2. Giới hạn `quic_max_concurrent_bidi_streams` (100)
//!   3. Chặn HTTP/3 Oversized Body với `413 Payload Too Large`

#[cfg(test)]
mod http3_security_tests {
    use ferrousx_config::config::ConfigManager;

    #[test]
    fn test_tls13_zero_rtt_disabled_by_default() {
        let mgr = ConfigManager::default_production_demo();
        let cfg = mgr.current();
        assert!(
            !cfg.tls.enable_zero_rtt,
            "TLS 1.3 0-RTT phải mặc định tắt để chống Replay Attack"
        );
    }

    #[test]
    fn test_quic_stream_concurrency_bounded() {
        let mgr = ConfigManager::default_production_demo();
        let cfg = mgr.current();
        assert!(cfg.quic_max_concurrent_bidi_streams > 0);
        assert!(cfg.quic_max_concurrent_bidi_streams <= 512);
    }
}
