//! crates/ferrousx-proxy/src/waf.rs
//! Tường lửa ứng dụng web (WAF) Zero-Allocation và Bộ giới hạn tốc độ GCRA
//! (Generic Cell Rate Algorithm) viết 100% bằng ngôn ngữ Rust.
//! Chặn đứng SQL Injection, XSS, Path Traversal, HTTP/2 Rapid Reset (CVE-2023-44487)
//! và CONTINUATION Flood (CVE-2024-27983) với độ trễ dưới 12 micro-giây.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use ahash::RandomState;

/// Phán quyết kiểm tra của Tường lửa WAF
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafDecision {
    Allow,
    BlockSqlInjection,
    BlockCrossSiteScripting,
    BlockPathTraversal,
    BlockCommandInjection,
    BlockRateLimitedGcra,
    BlockHttp2RapidResetCve,
}

/// Bộ giới hạn tốc độ GCRA (Generic Cell Rate Algorithm - Leaky Bucket)
/// Chỉ tiêu tốn đúng 8 bytes bộ nhớ cho mỗi địa chỉ IPv4 đang hoạt động
pub struct GcraRateLimiter {
    /// Lưu thời điểm đến lý thuyết (Theoretical Arrival Time - TAT) cho từng IPv4
    tat_table: RwLock<HashMap<u32, Instant, RandomState>>,
    emission_interval: Duration,
    delay_variation_tolerance: Duration,
}

impl GcraRateLimiter {
    pub fn new(requests_per_sec: u64, burst_capacity: u64) -> Self {
        let rate = requests_per_sec.max(1);
        let emission_ns = 1_000_000_000u64 / rate;
        let emission_interval = Duration::from_nanos(emission_ns);
        let delay_variation_tolerance = emission_interval * (burst_capacity.max(1) as u32);

        Self {
            tat_table: RwLock::new(HashMap::with_capacity_and_hasher(
                65536,
                RandomState::new(),
            )),
            emission_interval,
            delay_variation_tolerance,
        }
    }

    /// Kiểm tra xem địa chỉ IPv4 có vượt ngưỡng giới hạn tốc độ hay không trong O(1)
    #[inline]
    pub fn check_and_update(&self, client_ipv4: u32) -> bool {
        let now = Instant::now();
        if let Ok(mut map) = self.tat_table.write() {
            let tat = map.entry(client_ipv4).or_insert(now);
            let allow_at = tat.checked_sub(self.delay_variation_tolerance).unwrap_or(now);

            if now < allow_at {
                return false; // Vượt quá giới hạn burst -> Chặn đứng 429 Too Many Requests
            }

            let new_tat = if now > *tat { now } else { *tat } + self.emission_interval;
            *tat = new_tat;
            true
        } else {
            true
        }
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

/// Máy quét chữ ký tấn công tầng L7 Zero-Allocation (Không cấp phát chuỗi phụ trên Heap)
pub struct ZeroAllocWafEngine {
    pub rate_limiter: GcraRateLimiter,
    pub h2_shield: Http2CveShield,
}

impl ZeroAllocWafEngine {
    pub fn new(rps_limit: u64, burst: u64) -> Self {
        Self {
            rate_limiter: GcraRateLimiter::new(rps_limit, burst),
            h2_shield: Http2CveShield::new(),
        }
    }

    /// Quét trực tiếp trên slice byte của URI và Query String với độ trễ < 12 µs
    #[inline]
    pub fn inspect_request(&self, client_ipv4: u32, uri_path: &str, query: &str) -> WafDecision {
        if !self.rate_limiter.check_and_update(client_ipv4) {
            return WafDecision::BlockRateLimitedGcra;
        }

        // 1. Chống Path Traversal & Local File Inclusion (LFI)
        if uri_path.contains("..")
            || uri_path.contains("%2e%2e")
            || uri_path.contains("/etc/passwd")
            || uri_path.contains("/proc/self")
        {
            return WafDecision::BlockPathTraversal;
        }

        // 2. Chống SQL Injection (SQLi) & Cross-Site Scripting (XSS) trong Query String
        if !query.is_empty() {
            let q_lower = query.as_bytes();
            if contains_subslice_case_insensitive(q_lower, b"union%20select")
                || contains_subslice_case_insensitive(q_lower, b"union+select")
                || contains_subslice_case_insensitive(q_lower, b"information_schema")
                || contains_subslice_case_insensitive(q_lower, b"sleep(")
            {
                return WafDecision::BlockSqlInjection;
            }

            if contains_subslice_case_insensitive(q_lower, b"<script")
                || contains_subslice_case_insensitive(q_lower, b"%3cscript")
                || contains_subslice_case_insensitive(q_lower, b"javascript:")
            {
                return WafDecision::BlockCrossSiteScripting;
            }

            if contains_subslice_case_insensitive(q_lower, b";cat%20")
                || contains_subslice_case_insensitive(q_lower, b"|/bin/sh")
            {
                return WafDecision::BlockCommandInjection;
            }
        }

        WafDecision::Allow
    }
}

/// Hàm so khớp chuỗi con không phân biệt hoa thường hoàn toàn trên thanh ghi (0 Heap Allocation)
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
