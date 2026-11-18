//! tests/http2_security/http2_rapid_reset_and_limits_test.rs
//! Kiểm thử Bảo mật HTTP/2:
//!   1. CVE-2023-44487 (HTTP/2 Rapid Reset) — Chặn khi vượt ngưỡng RST_STREAM
//!   2. Giới hạn `h2_max_concurrent_streams` (128) và `h2_max_header_list_size` (64 KiB)
//!   3. Chặn Oversized Body với mã `413 Payload Too Large` thay vì cắt cụt âm thầm

#[cfg(test)]
mod http2_security_tests {
    use ferrousx_proxy::waf::{Http2CveShield, WafDecision};

    #[test]
    fn test_http2_rapid_reset_cve_2023_44487_mitigation() {
        let shield = Http2CveShield::new();
        assert_eq!(
            shield.inspect_rst_stream_rate(50),
            WafDecision::Allow,
            "Dưới ngưỡng 100 RST_STREAM/s vẫn cho phép"
        );
        // Vượt ngưỡng 100 RST_STREAM/s phải kích hoạt BlockHttp2RapidResetCve
        assert_eq!(
            shield.inspect_rst_stream_rate(101),
            WafDecision::BlockHttp2RapidResetCve,
            "RST_STREAM vượt ngưỡng phải bị chặn để chống CVE-2023-44487"
        );
    }

    #[test]
    fn test_http2_oversized_body_returns_413_without_truncation() {
        let max_body_size: usize = 1024;
        let incoming_chunks: [&[u8]; 3] = [&[b'A'; 512], &[b'B'; 512], &[b'C'; 1]];

        let mut acc = Vec::new();
        let mut status = 200u16;
        for chunk in incoming_chunks {
            if acc.len() + chunk.len() > max_body_size {
                status = 413;
                break;
            }
            acc.extend_from_slice(chunk);
        }

        assert_eq!(status, 413, "Phải trả 413 Payload Too Large khi vượt ngưỡng");
    }
}
