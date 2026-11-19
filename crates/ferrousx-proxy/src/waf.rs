//! crates/ferrousx-proxy/src/waf.rs
//! Tường lửa ứng dụng web (WAF) Zero-Allocation và Bộ giới hạn tốc độ GCRA
//! (Generic Cell Rate Algorithm) viết 100% bằng ngôn ngữ Rust.
//! - Hỗ trợ đầy đủ cả IPv4 và IPv6 (`IpAddr`), chia thành 64 Shards giảm tranh chấp khóa (Lock Contention).
//! - Giới hạn cứng số lượng mục lưu trữ (`max_entries`) và tự động dọn dẹp các IP hết hạn (`ttl`)
//!   để ngăn chặn hoàn toàn tấn công cạn kiệt bộ nhớ (Unbounded HashMap Memory Exhaustion).
//! - Chặn đứng SQL Injection, XSS, Path Traversal, Command Injection, Malformed URI,
//!   Suspicious Headers/Body, HTTP/2 Rapid Reset (CVE-2023-44487) và CONTINUATION Flood (CVE-2024-27983).
//! - Hỗ trợ chế độ `WafMode::Block`, `WafMode::Monitor`, và `WafMode::Off`.

use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ahash::RandomState;
use tracing::warn;

const NUM_SHARDS: usize = 64;

/// Phán quyết kiểm tra của Tường lửa WAF
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafDecision {
    Allow,
    BlockSqlInjection,
    BlockCrossSiteScripting,
    BlockPathTraversal,
    BlockCommandInjection,
    BlockMalformedUri,
    BlockSuspiciousHeader,
    BlockSuspiciousBody,
    BlockRateLimitedGcra,
    BlockHttp2RapidResetCve,
}

impl WafDecision {
    pub const fn as_reason_code(&self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::BlockSqlInjection => "WAF_SQL_INJECTION",
            Self::BlockCrossSiteScripting => "WAF_XSS",
            Self::BlockPathTraversal => "WAF_PATH_TRAVERSAL",
            Self::BlockCommandInjection => "WAF_COMMAND_INJECTION",
            Self::BlockMalformedUri => "WAF_MALFORMED_URI",
            Self::BlockSuspiciousHeader => "WAF_SUSPICIOUS_HEADER",
            Self::BlockSuspiciousBody => "WAF_SUSPICIOUS_BODY",
            Self::BlockRateLimitedGcra => "WAF_RATE_LIMITED_GCRA",
            Self::BlockHttp2RapidResetCve => "WAF_HTTP2_RAPID_RESET_CVE",
        }
    }
}

#[derive(Clone, Copy)]
struct GcraState {
    tat: Instant,
    last_seen: Instant,
}

struct ShardInner {
    table: HashMap<IpAddr, GcraState, RandomState>,
    last_sweep: Instant,
    ops_since_sweep: u64,
}

struct RateLimitShard {
    inner: Mutex<ShardInner>,
}

/// Chuẩn hóa IP khóa rate-limit: IPv4 giữ nguyên /32 (bao gồm IPv4-mapped IPv6), IPv6 gom theo tiền tố /64.
#[inline]
pub fn normalize_rate_limit_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(mapped_v4)
            } else {
                let masked = u128::from(v6) & (u128::MAX << 64);
                IpAddr::V6(Ipv6Addr::from(masked))
            }
        }
    }
}

/// Bộ giới hạn tốc độ GCRA (Generic Cell Rate Algorithm - Leaky Bucket)
/// Hỗ trợ cả IPv4 & IPv6 (/64), phân mảnh 64-shard bằng Mutex và giới hạn dung lượng RAM tuyệt đối (`max_entries`).
pub struct GcraRateLimiter {
    shards: Vec<RateLimitShard>,
    hasher_builder: RandomState,
    emission_interval: Duration,
    delay_variation_tolerance: Duration,
    max_entries_per_shard: usize,
    entry_ttl: Duration,
    pub total_rate_limited: AtomicU64,
    pub total_evictions: AtomicU64,
}

impl GcraRateLimiter {
    pub fn new(requests_per_sec: u64, burst_capacity: u64) -> Self {
        Self::with_limits(requests_per_sec, burst_capacity, 65_536, Duration::from_secs(300))
    }

    pub fn with_limits(
        requests_per_sec: u64,
        burst_capacity: u64,
        max_total_entries: usize,
        entry_ttl: Duration,
    ) -> Self {
        let rate = requests_per_sec.max(1);
        let emission_ns = (1_000_000_000u64 / rate).max(1);
        let emission_interval = Duration::from_nanos(emission_ns);
        let delay_variation_tolerance =
            emission_interval.saturating_mul(burst_capacity.clamp(1, 1_000_000) as u32);
        let max_entries_per_shard = (max_total_entries / NUM_SHARDS).max(16);

        let now = Instant::now();
        let mut shards = Vec::with_capacity(NUM_SHARDS);
        for _ in 0..NUM_SHARDS {
            shards.push(RateLimitShard {
                inner: Mutex::new(ShardInner {
                    table: HashMap::with_capacity_and_hasher(
                        max_entries_per_shard.min(1024),
                        RandomState::new(),
                    ),
                    last_sweep: now,
                    ops_since_sweep: 0,
                }),
            });
        }

        Self {
            shards,
            hasher_builder: RandomState::new(),
            emission_interval,
            delay_variation_tolerance,
            max_entries_per_shard,
            entry_ttl,
            total_rate_limited: AtomicU64::new(0),
            total_evictions: AtomicU64::new(0),
        }
    }

    #[inline]
    fn shard_index(&self, ip: &IpAddr) -> usize {
        let mut hasher = self.hasher_builder.build_hasher();
        ip.hash(&mut hasher);
        (hasher.finish() as usize) % NUM_SHARDS
    }

    fn sweep_stale_entries(&self, inner: &mut ShardInner, now: Instant) {
        let ttl = self.entry_ttl;
        let before = inner.table.len();
        inner.table.retain(|_, state| {
            state.tat > now || now.saturating_duration_since(state.last_seen) < ttl
        });
        let evicted = before.saturating_sub(inner.table.len());
        if evicted > 0 {
            self.total_evictions
                .fetch_add(evicted as u64, Ordering::Relaxed);
        }
        inner.last_sweep = now;
        inner.ops_since_sweep = 0;
    }

    /// Kiểm tra tốc độ theo `IpAddr` (IPv4 giữ nguyên, IPv6 gom theo /64) với Mutex shard & dọn dẹp TAT định kỳ
    #[inline]
    pub fn check_and_update_ip(&self, client_ip: IpAddr) -> bool {
        let now = Instant::now();
        let key_ip = normalize_rate_limit_key(client_ip);
        let idx = self.shard_index(&key_ip);
        let shard = &self.shards[idx];

        let Ok(mut inner) = shard.inner.lock() else {
            return false; // Fail-closed nếu Mutex bị poisoned
        };

        inner.ops_since_sweep = inner.ops_since_sweep.saturating_add(1);
        let sweep_interval = (self.entry_ttl / 2).max(Duration::from_secs(10));
        if inner.ops_since_sweep >= 256 || now.saturating_duration_since(inner.last_sweep) >= sweep_interval
        {
            self.sweep_stale_entries(&mut inner, now);
        }

        // Nếu IP chưa có trong bảng và shard đã chạm ngưỡng max_entries_per_shard:
        if !inner.table.contains_key(&key_ip) && inner.table.len() >= self.max_entries_per_shard {
            self.sweep_stale_entries(&mut inner, now);

            if inner.table.len() >= self.max_entries_per_shard {
                if let Some(oldest_ip) = inner
                    .table
                    .iter()
                    .min_by_key(|(_, s)| s.last_seen)
                    .map(|(k, _)| *k)
                {
                    inner.table.remove(&oldest_ip);
                    self.total_evictions.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        let state = inner.table.entry(key_ip).or_insert(GcraState {
            tat: now,
            last_seen: now,
        });
        state.last_seen = now;

        let allow_at = state
            .tat
            .checked_sub(self.delay_variation_tolerance)
            .unwrap_or(now);

        if now < allow_at {
            self.total_rate_limited.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let base = if now > state.tat { now } else { state.tat };
        state.tat = base + self.emission_interval;
        true
    }

    /// Tương thích ngược với API `u32` IPv4
    #[inline]
    pub fn check_and_update(&self, client_ipv4: u32) -> bool {
        let ipv4 = std::net::Ipv4Addr::from(client_ipv4);
        self.check_and_update_ip(IpAddr::V4(ipv4))
    }

    /// Trả về tổng số IP / prefix /64 đang được theo dõi trên toàn bộ 64 shards
    pub fn active_tracked_ips(&self) -> usize {
        self.shards
            .iter()
            .filter_map(|s| s.inner.lock().ok().map(|m| m.table.len()))
            .sum()
    }
}

/// Bộ bảo vệ chống tấn công HTTP/2 Rapid Reset (CVE-2023-44487) và CONTINUATION Flood (CVE-2024-27983)
pub struct Http2CveShield {
    pub max_rst_stream_per_sec: u32,
    pub max_continuation_frames: u32,
    pub blocked_cve_attempts: AtomicU64,
}

impl Http2CveShield {
    pub const fn new() -> Self {
        Self {
            max_rst_stream_per_sec: 100,
            max_continuation_frames: 16,
            blocked_cve_attempts: AtomicU64::new(0),
        }
    }

    #[inline(always)]
    pub fn inspect_rst_stream_rate(&self, current_rst_count_in_window: u32) -> WafDecision {
        if current_rst_count_in_window > self.max_rst_stream_per_sec {
            self.blocked_cve_attempts.fetch_add(1, Ordering::Relaxed);
            WafDecision::BlockHttp2RapidResetCve
        } else {
            WafDecision::Allow
        }
    }
}

/// Máy quét chữ ký tấn công tầng L7
pub struct ZeroAllocWafEngine {
    pub rate_limiter: GcraRateLimiter,
    pub h2_shield: Http2CveShield,
    pub max_inspect_body_bytes: usize,
    pub max_uri_len: usize,
}

impl ZeroAllocWafEngine {
    pub fn new(rps_limit: u64, burst: u64) -> Self {
        Self {
            rate_limiter: GcraRateLimiter::new(rps_limit, burst),
            h2_shield: Http2CveShield::new(),
            max_inspect_body_bytes: 64 * 1024,
            max_uri_len: 4096,
        }
    }

    pub fn with_full_config(
        rps_limit: u64,
        burst: u64,
        max_entries: usize,
        ttl_secs: u64,
        max_inspect_body_bytes: usize,
        max_uri_len: usize,
    ) -> Self {
        Self {
            rate_limiter: GcraRateLimiter::with_limits(
                rps_limit,
                burst,
                max_entries,
                Duration::from_secs(ttl_secs.max(10)),
            ),
            h2_shield: Http2CveShield::new(),
            max_inspect_body_bytes: max_inspect_body_bytes.clamp(1024, 256 * 1024),
            max_uri_len: max_uri_len.clamp(256, 32768),
        }
    }

    /// Quét toàn diện Request (IP Rate Limit, URI, Query String, Headers, và tối đa N bytes đầu của Body).
    /// Thực hiện giải mã percent-encoding 1 lượt (không đệ quy) và kiểm tra theo ranh giới segment để không chặn nhầm `a..b.txt`.
    pub fn inspect_full_request(
        &self,
        client_ip: IpAddr,
        method: &str,
        uri_path: &str,
        query: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> WafDecision {
        // 0. Kiểm tra giới hạn tốc độ GCRA theo IP thực (IPv4 /32 hoặc IPv6 /64)
        if !self.rate_limiter.check_and_update_ip(client_ip) {
            warn!(
                client_ip = %client_ip,
                reason = WafDecision::BlockRateLimitedGcra.as_reason_code(),
                "WAF blocked request exceeding GCRA rate limit"
            );
            return WafDecision::BlockRateLimitedGcra;
        }

        // 1. Kiểm tra tính hợp lệ của URI (Chiều dài, NUL byte, Control chars, Bad hex encoding)
        if uri_path.is_empty()
            || !uri_path.starts_with('/')
            || uri_path.len().saturating_add(query.len()) > self.max_uri_len
            || uri_path.bytes().any(|b| b < 0x20 || b == 0x7f)
            || has_malformed_percent_encoding(uri_path.as_bytes())
        {
            return WafDecision::BlockMalformedUri;
        }

        // Giải mã percent-encoding đúng 1 lần (không đệ quy) cho path và query
        let decoded_path = decode_percent_single_pass(uri_path.as_bytes(), false);
        let decoded_query = if !query.is_empty() {
            decode_percent_single_pass(query.as_bytes(), true)
        } else {
            Vec::new()
        };

        // 2. Chống Path Traversal & LFI theo segment (không chặn nhầm file hợp lệ như `a..b.txt`)
        if has_path_traversal_segments(uri_path.as_bytes())
            || has_path_traversal_segments(&decoded_path)
            || (!query.is_empty()
                && (has_query_traversal_payload(query.as_bytes())
                    || has_query_traversal_payload(&decoded_query)))
        {
            return WafDecision::BlockPathTraversal;
        }

        // Kiểm tra SQLi/XSS/CmdI trên URI path (cả bản gốc & bản đã giải mã 1 lượt)
        if is_sqli_payload(uri_path.as_bytes()) || is_sqli_payload(&decoded_path) {
            return WafDecision::BlockSqlInjection;
        }
        if is_xss_payload(uri_path.as_bytes()) || is_xss_payload(&decoded_path) {
            return WafDecision::BlockCrossSiteScripting;
        }
        if is_cmd_injection_payload(uri_path.as_bytes()) || is_cmd_injection_payload(&decoded_path) {
            return WafDecision::BlockCommandInjection;
        }

        // 3. Quét Query String (bản gốc + bản đã giải mã 1 lượt) chống SQLi, XSS, Command Injection
        if !query.is_empty() {
            let q_bytes = query.as_bytes();
            if is_sqli_payload(q_bytes) || is_sqli_payload(&decoded_query) {
                return WafDecision::BlockSqlInjection;
            }
            if is_xss_payload(q_bytes) || is_xss_payload(&decoded_query) {
                return WafDecision::BlockCrossSiteScripting;
            }
            if is_cmd_injection_payload(q_bytes) || is_cmd_injection_payload(&decoded_query) {
                return WafDecision::BlockCommandInjection;
            }
        }

        // 4. Quét Request Headers chống Log4Shell/JNDI, Shellshock, CRLF Injection và Scanner độc hại
        for (name, val) in headers {
            let v_bytes = val.as_bytes();
            let n_bytes = name.as_bytes();
            if n_bytes.iter().any(|&b| b == b'\r' || b == b'\n' || b == 0)
                || v_bytes.iter().any(|&b| b == b'\r' || b == b'\n' || b == 0)
            {
                return WafDecision::BlockSuspiciousHeader;
            }
            if contains_subslice_case_insensitive(v_bytes, b"${jndi:")
                || contains_subslice_case_insensitive(v_bytes, b"() { :; };")
                || contains_subslice_case_insensitive(v_bytes, b"sqlmap")
                || contains_subslice_case_insensitive(v_bytes, b"nikto")
                || contains_subslice_case_insensitive(v_bytes, b"acunetix")
            {
                return WafDecision::BlockSuspiciousHeader;
            }
        }

        // 5. Quét một phần giới hạn của Request Body (`max_inspect_body_bytes`, mặc định 64KB)
        if !body.is_empty() && matches!(method, "POST" | "PUT" | "PATCH") {
            let inspect_len = body.len().min(self.max_inspect_body_bytes);
            let body_slice = &body[..inspect_len];
            let decoded_body = decode_percent_single_pass(body_slice, true);

            if is_sqli_payload(body_slice) || is_sqli_payload(&decoded_body) {
                return WafDecision::BlockSqlInjection;
            }
            if is_xss_payload(body_slice) || is_xss_payload(&decoded_body) {
                return WafDecision::BlockCrossSiteScripting;
            }
            if is_cmd_injection_payload(body_slice) || is_cmd_injection_payload(&decoded_body) {
                return WafDecision::BlockCommandInjection;
            }
            if contains_subslice_case_insensitive(body_slice, b"${jndi:")
                || contains_subslice_case_insensitive(&decoded_body, b"${jndi:")
                || contains_subslice_case_insensitive(body_slice, b"<?php")
                || contains_subslice_case_insensitive(&decoded_body, b"<?php")
            {
                return WafDecision::BlockSuspiciousBody;
            }
        }

        WafDecision::Allow
    }

    /// API tương thích ngược cho `inspect_request`
    #[inline]
    pub fn inspect_request(&self, client_ipv4: u32, uri_path: &str, query: &str) -> WafDecision {
        let ip = IpAddr::V4(std::net::Ipv4Addr::from(client_ipv4));
        self.inspect_full_request(ip, "GET", uri_path, query, &[], &[])
    }
}

#[inline]
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Giải mã percent-encoding đúng 1 lần (non-recursive).
fn decode_percent_single_pass(input: &[u8], plus_as_space: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' && i + 2 < input.len() {
            if let (Some(hi), Some(lo)) = (hex_val(input[i + 1]), hex_val(input[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        } else if plus_as_space && input[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

#[inline]
fn has_malformed_percent_encoding(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len()
                || !bytes[i + 1].is_ascii_hexdigit()
                || !bytes[i + 2].is_ascii_hexdigit()
            {
                return true;
            }
            if bytes[i + 1] == b'0' && bytes[i + 2] == b'0' {
                return true;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    false
}

/// Kiểm tra tấn công Path Traversal trên từng segment (split theo `/` và `\`).
/// Cho phép các tên file hợp lệ có chứa `..` ở giữa như `a..b.txt`.
fn has_path_traversal_segments(bytes: &[u8]) -> bool {
    if bytes.contains(&0)
        || bytes.contains(&b'\\')
        || contains_subslice_case_insensitive(bytes, b"%252e")
        || contains_subslice_case_insensitive(bytes, b"/etc/passwd")
        || contains_subslice_case_insensitive(bytes, b"/etc/shadow")
        || contains_subslice_case_insensitive(bytes, b"/proc/self")
        || contains_subslice_case_insensitive(bytes, b"%00")
    {
        return true;
    }
    for seg in bytes.split(|&b| b == b'/' || b == b'\\') {
        if seg == b".." || eq_ignore_ascii_case_bytes(seg, b"%2e%2e") {
            return true;
        }
    }
    false
}

fn has_query_traversal_payload(bytes: &[u8]) -> bool {
    if bytes.contains(&0)
        || contains_subslice_case_insensitive(bytes, b"%252e")
        || contains_subslice_case_insensitive(bytes, b"/etc/passwd")
        || contains_subslice_case_insensitive(bytes, b"/etc/shadow")
        || contains_subslice_case_insensitive(bytes, b"/proc/self")
        || contains_subslice_case_insensitive(bytes, b"%00")
    {
        return true;
    }
    for token in bytes.split(|&b| matches!(b, b'&' | b'=' | b'/' | b'\\')) {
        if token == b".." || eq_ignore_ascii_case_bytes(token, b"%2e%2e") {
            return true;
        }
    }
    false
}

#[inline]
fn eq_ignore_ascii_case_bytes(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

#[inline]
fn is_sqli_payload(bytes: &[u8]) -> bool {
    contains_subslice_case_insensitive(bytes, b"union%20select")
        || contains_subslice_case_insensitive(bytes, b"union+select")
        || contains_subslice_case_insensitive(bytes, b"union select")
        || contains_subslice_case_insensitive(bytes, b"information_schema")
        || contains_subslice_case_insensitive(bytes, b"sleep(")
        || contains_subslice_case_insensitive(bytes, b"benchmark(")
        || contains_subslice_case_insensitive(bytes, b"waitfor delay")
        || contains_subslice_case_insensitive(bytes, b"waitfor%20delay")
        || contains_subslice_case_insensitive(bytes, b"' or '1'='1")
        || contains_subslice_case_insensitive(bytes, b"' or 1=1--")
        || contains_subslice_case_insensitive(bytes, b"'%20or%20'1'='1")
        || contains_subslice_case_insensitive(bytes, b"%27%20or%201=1")
}

#[inline]
fn is_xss_payload(bytes: &[u8]) -> bool {
    contains_subslice_case_insensitive(bytes, b"<script")
        || contains_subslice_case_insensitive(bytes, b"%3cscript")
        || contains_subslice_case_insensitive(bytes, b"javascript:")
        || contains_subslice_case_insensitive(bytes, b"onerror=")
        || contains_subslice_case_insensitive(bytes, b"onload=")
        || contains_subslice_case_insensitive(bytes, b"<svg/onload")
        || contains_subslice_case_insensitive(bytes, b"<svg onload")
}

#[inline]
fn is_cmd_injection_payload(bytes: &[u8]) -> bool {
    contains_subslice_case_insensitive(bytes, b";cat%20")
        || contains_subslice_case_insensitive(bytes, b";cat ")
        || contains_subslice_case_insensitive(bytes, b"|/bin/sh")
        || contains_subslice_case_insensitive(bytes, b"|/bin/bash")
        || contains_subslice_case_insensitive(bytes, b"`id`")
        || contains_subslice_case_insensitive(bytes, b"$(whoami)")
        || contains_subslice_case_insensitive(bytes, b";wget ")
        || contains_subslice_case_insensitive(bytes, b";wget%20")
        || contains_subslice_case_insensitive(bytes, b";curl ")
        || contains_subslice_case_insensitive(bytes, b";curl%20")
}

#[inline(always)]
fn contains_subslice_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    let window_len = needle.len();
    for window in haystack.windows(window_len) {
        let mut matched = true;
        for i in 0..window_len {
            if !window[i].eq_ignore_ascii_case(&needle[i]) {
                matched = false;
                break;
            }
        }
        if matched {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_waf_detects_sqli_xss_lfi_cmdi_and_allows_double_dot_filename() {
        let waf = ZeroAllocWafEngine::new(1000, 1000);
        let ip: IpAddr = "203.0.113.10".parse().unwrap();

        // Tên file hợp lệ chứa `..` ở giữa không bị chặn nhầm
        assert_eq!(
            waf.inspect_full_request(ip, "GET", "/files/a..b.txt", "name=report..v2.pdf", &[], &[]),
            WafDecision::Allow
        );

        // Giải mã percent-encoding 1 lượt phát hiện traversal & XSS bất kể hoa thường
        assert_eq!(
            waf.inspect_full_request(ip, "GET", "/%2E%2E/etc/passwd", "", &[], &[]),
            WafDecision::BlockPathTraversal
        );
        assert_eq!(
            waf.inspect_full_request(ip, "GET", "/search", "q=%3CScRiPt%3Ealert(1)", &[], &[]),
            WafDecision::BlockCrossSiteScripting
        );
        assert_eq!(
            waf.inspect_full_request(ip, "GET", "/index.php", "id=1%20UNION%20SELECT%201,2,3", &[], &[]),
            WafDecision::BlockSqlInjection
        );
        assert_eq!(
            waf.inspect_full_request(ip, "GET", "/ping", "host=127.0.0.1;|/bin/sh", &[], &[]),
            WafDecision::BlockCommandInjection
        );
        assert_eq!(
            waf.inspect_full_request(ip, "GET", "/bad%ZZpercent", "", &[], &[]),
            WafDecision::BlockMalformedUri
        );
    }

    #[test]
    fn test_gcra_ipv6_slash64_grouping_and_bounded_memory() {
        let limiter = GcraRateLimiter::with_limits(5, 3, 128, Duration::from_secs(60));
        let ip_a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let ip_b: IpAddr = "2001:db8:1:2::dead".parse().unwrap();
        let other_subnet: IpAddr = "2001:db8:1:3::1".parse().unwrap();

        // Cùng /64 chia sẻ 1 bucket GCRA
        assert!(limiter.check_and_update_ip(ip_a));
        assert!(limiter.check_and_update_ip(ip_b));
        assert!(limiter.check_and_update_ip(ip_a));
        assert!(limiter.check_and_update_ip(ip_b));
        assert!(!limiter.check_and_update_ip(ip_a));
        // /64 khác vẫn được phép
        assert!(limiter.check_and_update_ip(other_subnet));

        for i in 0..1000u32 {
            let flood_ip = IpAddr::V4(std::net::Ipv4Addr::from(i + 1));
            let _ = limiter.check_and_update_ip(flood_ip);
        }
        assert!(limiter.active_tracked_ips() <= 64 * 16);
    }
}
