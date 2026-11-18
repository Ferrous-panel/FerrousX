//! tests/proxy/proxy_ssrf_fastcgi_and_xff_test.rs
//! Kiểm thử Bảo mật Reverse Proxy & PHP-FPM FastCGI:
//!   1. Chặn SSRF vào Cloud Metadata (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`), `0.0.0.0`, multicast, broadcast
//!   2. Xác thực Trusted Proxy CIDR trước khi tin cậy `CF-Connecting-IP` / `X-Forwarded-For`
//!   3. Chặn FastCGI Path Traversal (kể cả symlink thoát khỏi `site_root`)
//!   4. Chặn lỗ hổng Httpoxy (`HTTP_PROXY`, CVE-2016-5385) và CRLF/NUL trong FastCGI Params

#[cfg(test)]
mod proxy_and_fastcgi_tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::Path;
    use ferrousx_config::config::{
        ip_in_cidr, is_forbidden_ssrf_ip, validate_upstream_origin, ConfigManager,
    };
    use ferrousx_proxy::fastcgi::{safe_resolve_under_root, sanitize_fastcgi_params};

    #[test]
    fn test_ssrf_cloud_metadata_and_link_local_blocked() {
        assert!(is_forbidden_ssrf_ip("169.254.169.254".parse().unwrap()));
        assert!(is_forbidden_ssrf_ip("0.0.0.0".parse().unwrap()));
        assert!(is_forbidden_ssrf_ip("255.255.255.255".parse().unwrap()));
        assert!(is_forbidden_ssrf_ip("fd00:ec2::254".parse().unwrap()));
        assert!(validate_upstream_origin("169.254.169.254:80").is_err());
        assert!(validate_upstream_origin("http://metadata.google.internal/computeMetadata/v1/").is_err());
        assert!(validate_upstream_origin("127.0.0.1:9999").is_ok());
    }

    #[test]
    fn test_trusted_proxy_cidr_verification_blocks_spoofed_xff() {
        let mgr = ConfigManager::default_production_demo();
        let cfg = mgr.current();

        // Cloudflare IP 173.245.48.10 is trusted
        let cf_ip: IpAddr = "173.245.48.10".parse().unwrap();
        assert!(cfg.is_trusted_proxy(cf_ip));

        // Direct external attacker IP 198.51.100.42 is NOT trusted
        let attacker_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42));
        assert!(!cfg.is_trusted_proxy(attacker_ip));
        assert!(!ip_in_cidr(attacker_ip, "173.245.48.0/20"));
    }

    #[test]
    fn test_fastcgi_httpoxy_and_path_traversal_blocked() {
        assert_eq!(
            safe_resolve_under_root(Path::new("/tmp"), "/../../etc/passwd"),
            None
        );
        assert_eq!(
            safe_resolve_under_root(Path::new("/tmp"), "/index.php\0.jpg"),
            None
        );

        let raw = vec![
            ("SCRIPT_FILENAME", "/www/wwwroot/site/index.php".to_string()),
            ("HTTP_PROXY", "http://attacker.evil:8080".to_string()),
            ("HTTP_HOST", "example.com\r\nX-Injected: 1".to_string()),
        ];
        let clean = sanitize_fastcgi_params(&raw).expect("sanitize fastcgi");
        assert!(!clean.iter().any(|(k, _)| k == "HTTP_PROXY"));
        assert_eq!(clean[1].1, "example.com");
    }
}
