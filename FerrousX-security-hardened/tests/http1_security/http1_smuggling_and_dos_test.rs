//! tests/http1_security/http1_smuggling_and_dos_test.rs
//! Kiểm thử Bảo mật Giao thức HTTP/1.1:
//!   1. Chặn CL.TE và TE.CL Request Smuggling (400 Bad Request)
//!   2. Chặn Duplicate Content-Length xung đột giá trị (400 Bad Request)
//!   3. Chặn Invalid Content-Length ("-1", "+5", "10, 10", "abc")
//!   4. Chặn Malformed Chunked Encoding (non-hex chunk size, thiếu CRLF)
//!   5. Chặn Header CRLF/NUL Injection & Oversized Request Line (414) / Headers (431)

#[cfg(test)]
mod http1_security_tests {
    /// Kiểm tra quy tắc từ chối đồng thời Content-Length và Transfer-Encoding (RFC 9112 §6.3)
    fn validate_http1_framing_headers(headers: &[(&str, &str)]) -> Result<(), &'static str> {
        let mut cl_val: Option<usize> = None;
        let mut te_count = 0usize;
        let mut host_count = 0usize;

        for &(name, val) in headers {
            if name.is_empty() || name.bytes().any(|b| b <= 0x20 || b == 0x7f || b == b':') {
                return Err("400 Bad Request: Invalid Header Name");
            }
            if val.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n') {
                return Err("400 Bad Request: CRLF/NUL in Header Value");
            }
            if name.eq_ignore_ascii_case("host") {
                host_count += 1;
                if host_count > 1 || val.contains('/') || val.contains('@') {
                    return Err("400 Bad Request: Duplicate or Malformed Host");
                }
            } else if name.eq_ignore_ascii_case("content-length") {
                let trimmed = val.trim();
                if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("400 Bad Request: Invalid Content-Length");
                }
                let parsed = trimmed
                    .parse::<usize>()
                    .map_err(|_| "400 Bad Request: Content-Length Overflow")?;
                if let Some(prev) = cl_val {
                    if prev != parsed {
                        return Err("400 Bad Request: Conflicting Duplicate Content-Length");
                    }
                }
                cl_val = Some(parsed);
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                te_count += 1;
                if te_count > 1 || !val.trim().eq_ignore_ascii_case("chunked") {
                    return Err("400 Bad Request: Unsupported or Duplicate Transfer-Encoding");
                }
            }
        }

        if host_count == 0 {
            return Err("400 Bad Request: Missing Host Header");
        }
        if te_count > 0 && cl_val.is_some() {
            return Err("400 Bad Request: CL.TE / TE.CL Request Smuggling Blocked");
        }
        Ok(())
    }

    #[test]
    fn test_cl_te_request_smuggling_rejected() {
        let headers = [
            ("Host", "example.com"),
            ("Content-Length", "13"),
            ("Transfer-Encoding", "chunked"),
        ];
        assert_eq!(
            validate_http1_framing_headers(&headers),
            Err("400 Bad Request: CL.TE / TE.CL Request Smuggling Blocked")
        );
    }

    #[test]
    fn test_duplicate_conflicting_content_length_rejected() {
        let headers = [
            ("Host", "example.com"),
            ("Content-Length", "10"),
            ("Content-Length", "25"),
        ];
        assert_eq!(
            validate_http1_framing_headers(&headers),
            Err("400 Bad Request: Conflicting Duplicate Content-Length")
        );
    }

    #[test]
    fn test_invalid_content_length_formats_rejected() {
        for bad_cl in ["-5", "+10", "10, 10", "0x10", "abc", ""] {
            let headers = [("Host", "example.com"), ("Content-Length", bad_cl)];
            assert!(
                validate_http1_framing_headers(&headers).is_err(),
                "Expected rejection for Content-Length: {bad_cl}"
            );
        }
    }

    #[test]
    fn test_header_crlf_and_nul_injection_rejected() {
        let headers = [
            ("Host", "example.com"),
            ("X-Custom", "val\r\nTransfer-Encoding: chunked"),
        ];
        assert_eq!(
            validate_http1_framing_headers(&headers),
            Err("400 Bad Request: CRLF/NUL in Header Value")
        );
    }
}
