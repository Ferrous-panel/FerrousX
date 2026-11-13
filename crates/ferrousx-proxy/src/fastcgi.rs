//! crates/ferrousx-proxy/src/fastcgi.rs
//! Async FastCGI Client chuẩn RFC (FCGI_BEGIN_REQUEST, FCGI_PARAMS, FCGI_STDIN, FCGI_STDOUT)
//! kết nối trực tiếp tới PHP-FPM qua Unix Domain Socket hoặc TCP,
//! xử lý chính xác `Status` header, multi-header (`Set-Cookie`) và chống Path Traversal.

use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use http::StatusCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tracing::warn;

const FCGI_VERSION_1: u8 = 1;
const FCGI_BEGIN_REQUEST: u8 = 1;
const FCGI_END_REQUEST: u8 = 3;
const FCGI_PARAMS: u8 = 4;
const FCGI_STDIN: u8 = 5;
const FCGI_STDOUT: u8 = 6;
const FCGI_STDERR: u8 = 7;
const FCGI_RESPONDER: u16 = 1;

#[derive(Debug, Clone)]
pub struct FastCgiResponse {
    pub status: StatusCode,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

/// Kiểm tra an toàn Path Traversal trước khi truy cập tệp trong `/www/wwwroot/<domain>`
/// Không cho phép vượt ra ngoài `site_root`.
pub fn safe_resolve_under_root(site_root: &Path, request_path: &str) -> Option<PathBuf> {
    let decoded_check = request_path.to_ascii_lowercase();
    if request_path.contains('\0')
        || decoded_check.contains("%00")
        || decoded_check.contains("..")
        || decoded_check.contains("%2e%2e")
        || decoded_check.contains("\\")
    {
        return None;
    }

    let trimmed = request_path.trim_start_matches('/');
    let rel_path = Path::new(trimmed);
    for comp in rel_path.components() {
        match comp {
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
            Component::Normal(_) | Component::CurDir => {}
        }
    }

    let joined = site_root.join(rel_path);
    let canonical_root = std::fs::canonicalize(site_root).ok()?;
    // Nếu file tồn tại trên đĩa, kiểm tra canonicalize; nếu không tồn tại (VD rewrite tới index.php),
    // kiểm tra thư mục cha gần nhất vẫn nằm trong canonical_root.
    if joined.exists() {
        let canonical_target = std::fs::canonicalize(&joined).ok()?;
        if canonical_target.starts_with(&canonical_root) {
            return Some(canonical_target);
        }
        return None;
    }

    if let Some(parent) = joined.parent() {
        if parent.exists() {
            if let Ok(canonical_parent) = std::fs::canonicalize(parent) {
                if canonical_parent.starts_with(&canonical_root) {
                    return Some(joined);
                }
            }
        }
    }

    // Fallback kiểm tra logic component
    if joined.starts_with(site_root) {
        Some(joined)
    } else {
        None
    }
}

/// Dò tìm Unix Socket PHP-FPM đang hoạt động trên hệ thống Ubuntu/Debian/AlmaLinux
pub fn detect_php_fpm_socket(preferred: Option<&str>) -> String {
    if let Some(pref) = preferred {
        let stripped = pref.strip_prefix("unix:").unwrap_or(pref);
        if pref.contains(':') && !pref.starts_with("unix:") && !pref.starts_with('/') {
            return pref.to_string();
        }
        if Path::new(stripped).exists() {
            return format!("unix:{stripped}");
        }
    }

    let candidates = [
        "/run/php/php8.3-fpm.sock",
        "/run/php/php8.2-fpm.sock",
        "/run/php/php8.1-fpm.sock",
        "/run/php/php-fpm.sock",
        "/var/run/php-fpm/www.sock",
        "/run/php-fpm/www.sock",
    ];
    for path in candidates {
        if Path::new(path).exists() {
            return format!("unix:{path}");
        }
    }
    "127.0.0.1:9000".to_string()
}

/// Thực thi yêu cầu PHP thông qua FastCGI Client bất đồng bộ (Unix Socket hoặc TCP)
pub async fn execute_fastcgi(
    target_addr: &str,
    params: &[(&str, String)],
    req_body: &[u8],
) -> Result<FastCgiResponse> {
    let request_id: u16 = 1;
    let payload = build_fastcgi_request_bytes(request_id, params, req_body);

    let raw_output = if let Some(sock_path) = target_addr.strip_prefix("unix:") {
        let mut stream = UnixStream::connect(sock_path)
            .await
            .with_context(|| format!("Không thể kết nối PHP-FPM Unix socket: {sock_path}"))?;
        stream.write_all(&payload).await?;
        stream.flush().await?;
        read_fastcgi_response(&mut stream).await?
    } else if target_addr.starts_with('/') {
        let mut stream = UnixStream::connect(target_addr)
            .await
            .with_context(|| format!("Không thể kết nối PHP-FPM Unix socket: {target_addr}"))?;
        stream.write_all(&payload).await?;
        stream.flush().await?;
        read_fastcgi_response(&mut stream).await?
    } else {
        let mut stream = TcpStream::connect(target_addr)
            .await
            .with_context(|| format!("Không thể kết nối PHP-FPM TCP: {target_addr}"))?;
        let _ = stream.set_nodelay(true);
        stream.write_all(&payload).await?;
        stream.flush().await?;
        read_fastcgi_response(&mut stream).await?
    };

    Ok(parse_cgi_output(&raw_output))
}

fn build_fastcgi_request_bytes(
    request_id: u16,
    params: &[(&str, String)],
    body: &[u8],
) -> BytesMut {
    let mut out = BytesMut::with_capacity(1024 + body.len());

    // 1. FCGI_BEGIN_REQUEST (flags = 0 -> đóng socket sau khi xử lý xong request)
    out.put_u8(FCGI_VERSION_1);
    out.put_u8(FCGI_BEGIN_REQUEST);
    out.put_u16(request_id);
    out.put_u16(8);
    out.put_u8(0);
    out.put_u8(0);
    out.put_u16(FCGI_RESPONDER);
    out.put_u8(0);
    out.put_bytes(0, 5);

    // 2. FCGI_PARAMS (chia chunk <= 60KB theo giới hạn 65535 của FastCGI)
    let mut param_buf = BytesMut::with_capacity(1024);
    for (name, val) in params {
        encode_nv_len(&mut param_buf, name.len());
        encode_nv_len(&mut param_buf, val.len());
        param_buf.extend_from_slice(name.as_bytes());
        param_buf.extend_from_slice(val.as_bytes());
    }
    for chunk in param_buf.chunks(60_000) {
        write_fcgi_record(&mut out, FCGI_PARAMS, request_id, chunk);
    }
    // Empty FCGI_PARAMS terminator
    write_fcgi_record(&mut out, FCGI_PARAMS, request_id, &[]);

    // 3. FCGI_STDIN
    for chunk in body.chunks(60_000) {
        write_fcgi_record(&mut out, FCGI_STDIN, request_id, chunk);
    }
    // Empty FCGI_STDIN terminator
    write_fcgi_record(&mut out, FCGI_STDIN, request_id, &[]);

    out
}

fn encode_nv_len(buf: &mut BytesMut, len: usize) {
    if len < 128 {
        buf.put_u8(len as u8);
    } else {
        buf.put_u32((len as u32) | 0x8000_0000);
    }
}

fn write_fcgi_record(out: &mut BytesMut, rec_type: u8, req_id: u16, data: &[u8]) {
    let content_len = data.len() as u16;
    let padding_len = ((8 - (content_len % 8)) % 8) as u8;
    out.put_u8(FCGI_VERSION_1);
    out.put_u8(rec_type);
    out.put_u16(req_id);
    out.put_u16(content_len);
    out.put_u8(padding_len);
    out.put_u8(0);
    out.extend_from_slice(data);
    if padding_len > 0 {
        out.put_bytes(0, padding_len as usize);
    }
}

async fn read_fastcgi_response<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut stdout_data = Vec::with_capacity(8192);
    let mut header = [0u8; 8];

    loop {
        match stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }

        let rec_type = header[1];
        let content_len = u16::from_be_bytes([header[4], header[5]]) as usize;
        let padding_len = header[6] as usize;

        let mut content = vec![0u8; content_len];
        if content_len > 0 {
            stream.read_exact(&mut content).await?;
        }
        if padding_len > 0 {
            let mut pad = vec![0u8; padding_len];
            stream.read_exact(&mut pad).await?;
        }

        match rec_type {
            FCGI_STDOUT => stdout_data.extend_from_slice(&content),
            FCGI_STDERR => {
                if !content.is_empty() {
                    let msg = String::from_utf8_lossy(&content);
                    warn!(php_stderr = %msg.trim(), "PHP-FPM stderr");
                }
            }
            FCGI_END_REQUEST => break,
            _ => {}
        }
    }

    Ok(stdout_data)
}

/// Phân tách phần CGI Header và Body từ FCGI_STDOUT, hỗ trợ `Status:` và nhiều `Set-Cookie`
fn parse_cgi_output(raw: &[u8]) -> FastCgiResponse {
    let (header_bytes, body_bytes) = if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        (&raw[..pos], &raw[pos + 4..])
    } else if let Some(pos) = raw.windows(2).position(|w| w == b"\n\n") {
        (&raw[..pos], &raw[pos + 2..])
    } else {
        (&[][..], raw)
    };

    let mut status = StatusCode::OK;
    let mut headers = Vec::new();
    let mut has_content_type = false;

    let header_str = String::from_utf8_lossy(header_bytes);
    for line in header_str.lines() {
        let trimmed = line.trim_end_matches('\r');
        if let Some((name, val)) = trimmed.split_once(':') {
            let key = name.trim();
            let value = val.trim();
            if key.eq_ignore_ascii_case("status") {
                if let Some(code_str) = value.split_whitespace().next() {
                    if let Ok(code) = code_str.parse::<u16>() {
                        if let Ok(sc) = StatusCode::from_u16(code) {
                            status = sc;
                        }
                    }
                }
                continue;
            }
            if key.eq_ignore_ascii_case("content-type") {
                has_content_type = true;
            }
            if !key.eq_ignore_ascii_case("transfer-encoding")
                && !key.eq_ignore_ascii_case("connection")
            {
                headers.push((key.to_string(), value.to_string()));
            }
        }
    }

    if !has_content_type {
        headers.push(("Content-Type".to_string(), "text/html; charset=utf-8".to_string()));
    }

    FastCgiResponse {
        status,
        headers,
        body: Bytes::copy_from_slice(body_bytes),
    }
}
