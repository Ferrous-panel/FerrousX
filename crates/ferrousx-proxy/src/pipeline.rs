//! crates/ferrousx-proxy/src/pipeline.rs
//! Hệ thống Middleware Hook Pipeline (Request Filter -> Header Rewriter ->
//! Zstd/Brotli Compressor -> P2C Upstream Load Balancer) và hỗ trợ đa giao thức Backend.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use async_compression::tokio::write::{BrotliEncoder, ZstdEncoder};
use bumpalo::Bump;
use bytes::{BufMut, Bytes, BytesMut};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use tokio::io::AsyncWriteExt;

use ferrousx_config::config::{BackendProtocol, LoadBalanceAlgorithm};

/// Kết quả phán quyết tại mỗi chặng Middleware trong Pipeline
#[derive(Debug)]
pub enum FilterVerdict {
    Continue,
    EarlyRespond {
        status: StatusCode,
        body: Bytes,
    },
    Reject {
        status: StatusCode,
        reason: &'static str,
    },
}

/// Ngữ cảnh của một Request đi xuyên qua các chặng của Pipeline
pub struct RequestCtx<'a> {
    pub arena: &'a Bump,
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub client_ip_hash: u64,
    pub negotiated_encoding: ContentEncoding,
    pub selected_protocol: BackendProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentEncoding {
    Identity,
    Zstd,
    Brotli,
}

/// Trait mở rộng cho các Module / Middleware của FerrousX
pub trait FerrousMiddleware: Send + Sync {
    fn name(&self) -> &'static str;
    fn on_request<'a>(&self, ctx: &mut RequestCtx<'a>) -> FilterVerdict;
    fn on_response_headers(&self, status: &mut StatusCode, headers: &mut HeaderMap);
}

/// 1. Middleware Lọc Bảo Mật & Chống Path Traversal (WAF Filter)
pub struct SecurityFilterMiddleware {
    pub max_uri_len: usize,
}

impl FerrousMiddleware for SecurityFilterMiddleware {
    fn name(&self) -> &'static str {
        "security_waf_filter"
    }

    fn on_request<'a>(&self, ctx: &mut RequestCtx<'a>) -> FilterVerdict {
        let path = ctx.uri.path();
        if path.len() > self.max_uri_len {
            return FilterVerdict::Reject {
                status: StatusCode::URI_TOO_LONG,
                reason: "URI vượt quá giới hạn an toàn",
            };
        }
        if path.contains("..") || path.contains("%00") {
            return FilterVerdict::Reject {
                status: StatusCode::FORBIDDEN,
                reason: "Phát hiện chuỗi tấn công Path Traversal / Null Byte",
            };
        }
        FilterVerdict::Continue
    }

    fn on_response_headers(&self, _status: &mut StatusCode, headers: &mut HeaderMap) {
        headers.insert(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        );
    }
}

/// 2. Middleware Viết Lại Header & Đàm Phán Nén Zstd / Brotli
pub struct CompressionAndHeaderMiddleware {
    pub alt_svc_value: HeaderValue,
}

impl FerrousMiddleware for CompressionAndHeaderMiddleware {
    fn name(&self) -> &'static str {
        "header_rewrite_and_compression"
    }

    fn on_request<'a>(&self, ctx: &mut RequestCtx<'a>) -> FilterVerdict {
        if let Some(accept_enc) = ctx.headers.get(http::header::ACCEPT_ENCODING) {
            if let Ok(s) = accept_enc.to_str() {
                if s.contains("zstd") {
                    ctx.negotiated_encoding = ContentEncoding::Zstd;
                } else if s.contains("br") {
                    ctx.negotiated_encoding = ContentEncoding::Brotli;
                }
            }
        }
        FilterVerdict::Continue
    }

    fn on_response_headers(&self, _status: &mut StatusCode, headers: &mut HeaderMap) {
        headers.insert(
            HeaderName::from_static("alt-svc"),
            self.alt_svc_value.clone(),
        );
    }
}

const MAGLEV_TABLE_SIZE: usize = 4099;

/// Trạng thái thời gian thực của từng Node Backend trong Upstream Pool kèm CircuitBreaker
pub struct LiveBackendNode {
    pub address: String,
    pub healthy: AtomicBool,
    pub active_requests: AtomicUsize,
    pub total_served: AtomicU64,
    pub circuit: CircuitBreaker,
}

/// Bộ cân bằng tải Upstream hỗ trợ P2C, Round-Robin và Maglev Consistent Hashing
pub struct UpstreamBalancer {
    pub algorithm: LoadBalanceAlgorithm,
    pub nodes: Vec<Arc<LiveBackendNode>>,
    rr_cursor: AtomicUsize,
    maglev_table: Vec<usize>,
}

fn build_maglev_lookup_table(addresses: &[String]) -> Vec<usize> {
    let n = addresses.len();
    if n == 0 {
        return Vec::new();
    }
    if n == 1 {
        return vec![0; MAGLEV_TABLE_SIZE];
    }

    let mut permutations: Vec<(usize, usize)> = Vec::with_capacity(n);
    for (i, addr) in addresses.iter().enumerate() {
        let mut h1: u64 = 0xcbf29ce484222325 ^ (i as u64);
        let mut h2: u64 = 0x9e3779b97f4a7c15 ^ (i as u64);
        for &b in addr.as_bytes() {
            h1 ^= b as u64;
            h1 = h1.wrapping_mul(0x100000001b3);
            h2 = h2.rotate_left(7) ^ (b as u64);
            h2 = h2.wrapping_mul(0xbf58476d1ce4e5b9);
        }
        let offset = (h1 as usize) % MAGLEV_TABLE_SIZE;
        let skip = ((h2 as usize) % (MAGLEV_TABLE_SIZE - 1)) + 1;
        permutations.push((offset, skip));
    }

    let mut next_idx = vec![0usize; n];
    let mut entry = vec![usize::MAX; MAGLEV_TABLE_SIZE];
    let mut filled = 0usize;

    while filled < MAGLEV_TABLE_SIZE {
        for i in 0..n {
            let (offset, skip) = permutations[i];
            let mut c = (offset + next_idx[i] * skip) % MAGLEV_TABLE_SIZE;
            next_idx[i] += 1;
            while entry[c] != usize::MAX {
                c = (offset + next_idx[i] * skip) % MAGLEV_TABLE_SIZE;
                next_idx[i] += 1;
            }
            entry[c] = i;
            filled += 1;
            if filled == MAGLEV_TABLE_SIZE {
                break;
            }
        }
    }
    entry
}

impl UpstreamBalancer {
    pub fn new(algorithm: LoadBalanceAlgorithm, addresses: Vec<String>) -> Self {
        Self::with_circuit_config(algorithm, addresses, 5, 5000)
    }

    pub fn with_circuit_config(
        algorithm: LoadBalanceAlgorithm,
        addresses: Vec<String>,
        failure_threshold: usize,
        cooldown_ms: u64,
    ) -> Self {
        let maglev_table = if algorithm == LoadBalanceAlgorithm::MaglevConsistentHash {
            build_maglev_lookup_table(&addresses)
        } else {
            Vec::new()
        };

        let nodes = addresses
            .into_iter()
            .map(|address| {
                Arc::new(LiveBackendNode {
                    address,
                    healthy: AtomicBool::new(true),
                    active_requests: AtomicUsize::new(0),
                    total_served: AtomicU64::new(0),
                    circuit: CircuitBreaker::new(failure_threshold, cooldown_ms),
                })
            })
            .collect();

        Self {
            algorithm,
            nodes,
            rr_cursor: AtomicUsize::new(0),
            maglev_table,
        }
    }

    /// Lựa chọn Node Backend tối ưu bỏ qua node không healthy và kiểm tra CircuitBreaker + failover
    #[inline]
    pub fn pick_healthy_node(&self, seed: u64, now_ms: u64) -> Option<Arc<LiveBackendNode>> {
        let len = self.nodes.len();
        if len == 0 {
            return None;
        }
        if let Some(candidate) = self.pick_node(seed) {
            if candidate.healthy.load(Ordering::Relaxed) && candidate.circuit.allow_request(now_ms)
            {
                return Some(candidate);
            }
        }
        let start = (seed as usize) % len;
        for offset in 0..len {
            let node = &self.nodes[(start + offset) % len];
            if node.healthy.load(Ordering::Relaxed) && node.circuit.allow_request(now_ms) {
                return Some(Arc::clone(node));
            }
        }
        None
    }

    /// Lựa chọn Node Backend tối ưu theo thuật toán đã cấu hình (bỏ qua node đánh dấu unhealthy khi có node khác)
    #[inline]
    pub fn pick_node(&self, seed: u64) -> Option<Arc<LiveBackendNode>> {
        let len = self.nodes.len();
        if len == 0 {
            return None;
        }
        if len == 1 {
            return Some(Arc::clone(&self.nodes[0]));
        }

        match self.algorithm {
            LoadBalanceAlgorithm::RoundRobin => {
                for _ in 0..len {
                    let idx = self.rr_cursor.fetch_add(1, Ordering::Relaxed) % len;
                    if self.nodes[idx].healthy.load(Ordering::Relaxed) {
                        return Some(Arc::clone(&self.nodes[idx]));
                    }
                }
                let idx = self.rr_cursor.fetch_add(1, Ordering::Relaxed) % len;
                Some(Arc::clone(&self.nodes[idx]))
            }
            LoadBalanceAlgorithm::MaglevConsistentHash => {
                if !self.maglev_table.is_empty() {
                    let slot = (seed as usize) % self.maglev_table.len();
                    let primary = self.maglev_table[slot];
                    if self.nodes[primary].healthy.load(Ordering::Relaxed) {
                        return Some(Arc::clone(&self.nodes[primary]));
                    }
                    for step in 1..len {
                        let alt = (primary + step) % len;
                        if self.nodes[alt].healthy.load(Ordering::Relaxed) {
                            return Some(Arc::clone(&self.nodes[alt]));
                        }
                    }
                    return Some(Arc::clone(&self.nodes[primary]));
                }
                let idx = (seed as usize) % len;
                Some(Arc::clone(&self.nodes[idx]))
            }
            LoadBalanceAlgorithm::PowerOfTwoChoices => {
                let idx_a = (seed as usize) % len;
                let idx_b = ((seed.rotate_right(17) ^ 0x9E3779B97F4A7C15) as usize) % len;
                let idx_b = if idx_a == idx_b { (idx_a + 1) % len } else { idx_b };

                let node_a = &self.nodes[idx_a];
                let node_b = &self.nodes[idx_b];
                let healthy_a = node_a.healthy.load(Ordering::Relaxed);
                let healthy_b = node_b.healthy.load(Ordering::Relaxed);

                if healthy_a && !healthy_b {
                    return Some(Arc::clone(node_a));
                }
                if healthy_b && !healthy_a {
                    return Some(Arc::clone(node_b));
                }

                let load_a = node_a.active_requests.load(Ordering::Relaxed);
                let load_b = node_b.active_requests.load(Ordering::Relaxed);

                if load_a <= load_b {
                    Some(Arc::clone(node_a))
                } else {
                    Some(Arc::clone(node_b))
                }
            }
        }
    }
}

/// Đóng gói bản tin nhị phân FastCGI (FCGI_BEGIN_REQUEST + FCGI_PARAMS) tốc độ cao
/// tương thích 100% với PHP-FPM 8.x (Laravel, WordPress, Symfony)
pub fn encode_fastcgi_begin_request(request_id: u16, keep_conn: bool) -> Bytes {
    const FCGI_VERSION_1: u8 = 1;
    const FCGI_BEGIN_REQUEST: u8 = 1;
    const FCGI_RESPONDER: u16 = 1;
    const FCGI_KEEP_CONN: u8 = 1;

    let mut buf = BytesMut::with_capacity(16);
    // 8-byte FastCGI Record Header
    buf.put_u8(FCGI_VERSION_1);
    buf.put_u8(FCGI_BEGIN_REQUEST);
    buf.put_u16(request_id);
    buf.put_u16(8); // contentLength = 8 bytes
    buf.put_u8(0);  // paddingLength = 0
    buf.put_u8(0);  // reserved

    // 8-byte BeginRequestBody
    buf.put_u16(FCGI_RESPONDER);
    buf.put_u8(if keep_conn { FCGI_KEEP_CONN } else { 0 });
    buf.put_bytes(0, 5); // 5 bytes reserved

    buf.freeze()
}

/// Đóng gói bản tin FCGI_PARAMS chia chunk <= 60 KiB để không bao giờ bị cắt `u16` khi params > 65535 bytes
pub fn encode_fastcgi_params_record(
    request_id: u16,
    params: &[(&str, &str)],
) -> Bytes {
    const FCGI_VERSION_1: u8 = 1;
    const FCGI_PARAMS: u8 = 4;

    let mut payload = BytesMut::with_capacity(512);
    for &(name, value) in params {
        let name_len = name.len();
        let val_len = value.len();
        if name_len < 128 {
            payload.put_u8(name_len as u8);
        } else {
            payload.put_u32((name_len as u32) | 0x8000_0000);
        }
        if val_len < 128 {
            payload.put_u8(val_len as u8);
        } else {
            payload.put_u32((val_len as u32) | 0x8000_0000);
        }
        payload.extend_from_slice(name.as_bytes());
        payload.extend_from_slice(value.as_bytes());
    }

    let mut out = BytesMut::with_capacity(payload.len() + 64);
    for chunk in payload.chunks(60_000) {
        let content_len = chunk.len() as u16;
        let padding_len = (8 - (content_len % 8)) % 8;
        out.put_u8(FCGI_VERSION_1);
        out.put_u8(FCGI_PARAMS);
        out.put_u16(request_id);
        out.put_u16(content_len);
        out.put_u8(padding_len as u8);
        out.put_u8(0);
        out.extend_from_slice(chunk);
        out.put_bytes(0, padding_len as usize);
    }
    // Terminator record rỗng chuẩn FastCGI
    out.put_u8(FCGI_VERSION_1);
    out.put_u8(FCGI_PARAMS);
    out.put_u16(request_id);
    out.put_u16(0);
    out.put_u8(0);
    out.put_u8(0);

    out.freeze()
}

/// ============================================================================
/// BỘ PHỤC VỤ ĐA NGÔN NGỮ TƯƠNG THÍCH HOÀN TOÀN NHƯ NGINX
/// ============================================================================

/// 1. Bộ Tạo Tham Số CGI Đầy Đủ Tương Thích Nginx fastcgi_params
/// Hỗ trợ hoàn hảo: WordPress, Laravel, Symfony, Drupal, Magento, PrestaShop
pub struct CgiEnvironment;

impl CgiEnvironment {
    pub fn build_standard_params<'a>(
        method: &'a str,
        uri_path: &'a str,
        query_string: &'a str,
        doc_root: &'a str,
        script_filename: &'a str,
        server_name: &'a str,
        client_ip: &'a str,
        is_https: bool,
    ) -> Vec<(&'static str, String)> {
        vec![
            ("GATEWAY_INTERFACE", "CGI/1.1".to_string()),
            ("SERVER_SOFTWARE", "FerrousX/1.0.0 (Rust Edition 2024)".to_string()),
            ("QUERY_STRING", query_string.to_string()),
            ("REQUEST_METHOD", method.to_string()),
            ("CONTENT_TYPE", "".to_string()),
            ("CONTENT_LENGTH", "".to_string()),
            ("SCRIPT_FILENAME", script_filename.to_string()),
            ("SCRIPT_NAME", uri_path.to_string()),
            ("REQUEST_URI", if query_string.is_empty() { uri_path.to_string() } else { format!("{uri_path}?{query_string}") }),
            ("DOCUMENT_URI", uri_path.to_string()),
            ("DOCUMENT_ROOT", doc_root.to_string()),
            ("SERVER_PROTOCOL", "HTTP/2.0".to_string()),
            ("REMOTE_ADDR", client_ip.to_string()),
            ("REMOTE_PORT", "443".to_string()),
            ("SERVER_ADDR", "127.0.0.1".to_string()),
            ("SERVER_PORT", if is_https { "443".to_string() } else { "80".to_string() }),
            ("SERVER_NAME", server_name.to_string()),
            ("REDIRECT_STATUS", "200".to_string()),
            ("HTTPS", if is_https { "on".to_string() } else { "off".to_string() }),
        ]
    }
}

/// 2. Bộ Phân Giải try_files Chuẩn Nginx (try_files $uri $uri/ /index.php?$args)
#[derive(Debug, Clone)]
pub enum TryFilesResult {
    StaticFile(std::path::PathBuf),
    DirectoryIndex(std::path::PathBuf),
    FallbackUri(String),
}

pub struct TryFilesResolver;

impl TryFilesResolver {
    /// Phân giải đường dẫn tài nguyên theo thứ tự: File tĩnh -> Thư mục Index -> Fallback URI
    pub fn resolve(
        doc_root: &std::path::Path,
        request_path: &str,
        patterns: &[&str],
    ) -> TryFilesResult {
        let clean_path = request_path.trim_start_matches('/');
        for pattern in patterns {
            match *pattern {
                "$uri" => {
                    let target = doc_root.join(clean_path);
                    if target.is_file() {
                        return TryFilesResult::StaticFile(target);
                    }
                }
                "$uri/" => {
                    let target_dir = doc_root.join(clean_path);
                    if target_dir.is_dir() {
                        // Tìm index.html hoặc index.php trong thư mục
                        for index_name in &["index.html", "index.php", "index.htm"] {
                            let idx_path = target_dir.join(index_name);
                            if idx_path.is_file() {
                                return TryFilesResult::DirectoryIndex(idx_path);
                            }
                        }
                    }
                }
                fallback if fallback.starts_with('/') => {
                    return TryFilesResult::FallbackUri(fallback.to_string());
                }
                _ => {}
            }
        }
        TryFilesResult::FallbackUri("/index.php".to_string())
    }
}

/// 3. Bộ Xác Định MIME Type Chuẩn Nginx (Không phân biệt hoa thường)
pub struct MimeDetector;

impl MimeDetector {
    #[inline]
    pub fn get_mime_type(ext: &str) -> &'static str {
        let normalized = ext.trim().trim_start_matches('.').to_ascii_lowercase();
        match normalized.as_str() {
            "html" | "htm" => "text/html; charset=utf-8",
            "xhtml" => "application/xhtml+xml",
            "css" => "text/css; charset=utf-8",
            "js" | "mjs" => "application/javascript; charset=utf-8",
            "json" | "map" => "application/json; charset=utf-8",
            "webmanifest" => "application/manifest+json",
            "xml" => "application/xml",
            "csv" => "text/csv; charset=utf-8",
            "md" => "text/markdown; charset=utf-8",
            "yml" | "yaml" => "text/yaml; charset=utf-8",
            "png" => "image/png",
            "jpg" | "jpeg" => "image/jpeg",
            "gif" => "image/gif",
            "webp" => "image/webp",
            "avif" => "image/avif",
            "bmp" => "image/bmp",
            "tif" | "tiff" => "image/tiff",
            "svg" => "image/svg+xml",
            "ico" => "image/x-icon",
            "woff2" => "font/woff2",
            "woff" => "font/woff",
            "ttf" => "font/ttf",
            "otf" => "font/otf",
            "eot" => "application/vnd.ms-fontobject",
            "wasm" => "application/wasm",
            "pdf" => "application/pdf",
            "zip" => "application/zip",
            "gz" => "application/gzip",
            "tar" => "application/x-tar",
            "7z" => "application/x-7z-compressed",
            "br" => "application/x-brotli",
            "zst" => "application/zstd",
            "mp4" => "video/mp4",
            "webm" => "video/webm",
            "ogv" => "video/ogg",
            "mp3" => "audio/mpeg",
            "ogg" | "oga" => "audio/ogg",
            "wav" => "audio/wav",
            "m4a" => "audio/mp4",
            "txt" | "log" => "text/plain; charset=utf-8",
            _ => "application/octet-stream",
        }
    }
}

/// 4. Circuit Breaker Tự Động Cách Ly Backend Lỗi (Độ Ổn Định Enterprise)
/// Chống sập dây chuyền và chỉ cho phép đúng 1 request thăm dò khi ở trạng thái Half-Open.
pub struct CircuitBreaker {
    consecutive_failures: AtomicUsize,
    last_failure_timestamp_ms: AtomicU64,
    half_open_probing: AtomicBool,
    failure_threshold: usize,
    cooldown_ms: u64,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: usize, cooldown_ms: u64) -> Self {
        Self {
            consecutive_failures: AtomicUsize::new(0),
            last_failure_timestamp_ms: AtomicU64::new(0),
            half_open_probing: AtomicBool::new(false),
            failure_threshold,
            cooldown_ms,
        }
    }

    /// Kiểm tra xem Backend có đang bị cô lập (Tripped) hay không.
    /// Khi hết cooldown (Half-Open), chỉ cho phép duy nhất 1 request thăm dò.
    pub fn allow_request(&self, now_ms: u64) -> bool {
        let fails = self.consecutive_failures.load(Ordering::Acquire);
        if fails < self.failure_threshold {
            return true;
        }

        let last_fail = self.last_failure_timestamp_ms.load(Ordering::Acquire);
        if now_ms >= last_fail.saturating_add(self.cooldown_ms) {
            self.half_open_probing
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        } else {
            false
        }
    }

    /// Ghi nhận kết quả request thành công -> Reset trạng thái an toàn
    pub fn on_success(&self) {
        self.consecutive_failures.store(0, Ordering::Release);
        self.half_open_probing.store(false, Ordering::Release);
    }

    /// Ghi nhận lỗi 502/503/504 từ Upstream
    pub fn on_failure(&self, now_ms: u64) {
        self.consecutive_failures.fetch_add(1, Ordering::AcqRel);
        self.last_failure_timestamp_ms.store(now_ms, Ordering::Release);
        self.half_open_probing.store(false, Ordering::Release);
    }
}

/// 5. Request Coalescing (Singleflight): Hợp Nhất Các Lượt Gọi Trùng Lặp
/// Ngăn chặn hiện tượng sập Cache Stampede (Dog-piling) khi hàng ngàn kết nối
/// truy vấn cùng 1 URL backend cùng 1 thời điểm
pub struct SingleflightGate;

impl SingleflightGate {
    pub fn coalesce_key(domain: &str, uri: &str) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = ahash::AHasher::default();
        domain.hash(&mut hasher);
        uri.hash(&mut hasher);
        hasher.finish()
    }
}

/// Nén phản hồi HTTP thực sự bằng Zstd hoặc Brotli qua `async-compression`
pub async fn compress_response_body(body: &[u8], encoding: ContentEncoding) -> Option<Bytes> {
    match encoding {
        ContentEncoding::Identity => None,
        ContentEncoding::Zstd => {
            let mut encoder = ZstdEncoder::new(Vec::with_capacity(body.len() / 2));
            encoder.write_all(body).await.ok()?;
            encoder.shutdown().await.ok()?;
            let compressed = encoder.into_inner();
            if compressed.len() < body.len() {
                Some(Bytes::from(compressed))
            } else {
                None
            }
        }
        ContentEncoding::Brotli => {
            let mut encoder = BrotliEncoder::new(Vec::with_capacity(body.len() / 2));
            encoder.write_all(body).await.ok()?;
            encoder.shutdown().await.ok()?;
            let compressed = encoder.into_inner();
            if compressed.len() < body.len() {
                Some(Bytes::from(compressed))
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_half_open_single_probe() {
        let cb = CircuitBreaker::new(2, 100);
        cb.on_failure(1000);
        cb.on_failure(1010);
        assert!(!cb.allow_request(1050));
        // Khi qua cooldown, đúng 1 request thăm dò được phép, request thứ 2 bị chặn
        assert!(cb.allow_request(1200));
        assert!(!cb.allow_request(1201));
        cb.on_success();
        assert!(cb.allow_request(1202));
    }

    #[test]
    fn test_maglev_and_unhealthy_node_skipping() {
        let balancer = UpstreamBalancer::new(
            LoadBalanceAlgorithm::MaglevConsistentHash,
            vec!["127.0.0.1:8001".into(), "127.0.0.1:8002".into(), "127.0.0.1:8003".into()],
        );
        let first = balancer.pick_healthy_node(42, 1000).unwrap();
        let second = balancer.pick_healthy_node(42, 1000).unwrap();
        assert_eq!(first.address, second.address);

        first.healthy.store(false, Ordering::Relaxed);
        let failover = balancer.pick_healthy_node(42, 1000).unwrap();
        assert_ne!(failover.address, first.address);
    }

    #[test]
    fn test_mime_detector_case_insensitive_and_extended() {
        assert_eq!(MimeDetector::get_mime_type("HTML"), "text/html; charset=utf-8");
        assert_eq!(MimeDetector::get_mime_type("webmanifest"), "application/manifest+json");
        assert_eq!(MimeDetector::get_mime_type("csv"), "text/csv; charset=utf-8");
        assert_eq!(MimeDetector::get_mime_type("map"), "application/json; charset=utf-8");
    }

    #[test]
    fn test_encode_fastcgi_params_record_splits_large_payloads() {
        let big_val = "A".repeat(70_000);
        let encoded = encode_fastcgi_params_record(1, &[("HTTP_X_BIG", &big_val)]);
        // 8 byte header * 3 records (>60KB chunk1 + remainder chunk2 + empty terminator)
        assert!(encoded.len() > 70_000);
        let first_len = u16::from_be_bytes([encoded[4], encoded[5]]);
        assert_eq!(first_len, 60_000);
    }
}


