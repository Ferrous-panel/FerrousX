//! crates/ferrousx-core/src/metrics.rs
//! Bộ đếm hiệu năng thời gian thực không khóa (Lock-Free Atomic Runtime Metrics)
//! dùng chung cho các Worker HTTP/1.1/2/3, WAF, Reverse Proxy, FastCGI và Control Plane.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::ebpf::XdpPerCpuMetrics;

pub struct EngineRuntimeStats {
    pub started_at: Instant,
    pub active_workers: AtomicUsize,
    pub total_requests: AtomicU64,
    pub active_connections: AtomicUsize,
    pub waf_blocked: AtomicU64,
    pub rate_limited: AtomicU64,
    pub upstream_errors: AtomicU64,
    pub php_fpm_requests: AtomicU64,
    pub static_requests: AtomicU64,
    pub http3_requests: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub xdp_metrics: XdpPerCpuMetrics,
}

impl EngineRuntimeStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            started_at: Instant::now(),
            active_workers: AtomicUsize::new(0),
            total_requests: AtomicU64::new(0),
            active_connections: AtomicUsize::new(0),
            waf_blocked: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            upstream_errors: AtomicU64::new(0),
            php_fpm_requests: AtomicU64::new(0),
            static_requests: AtomicU64::new(0),
            http3_requests: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            xdp_metrics: XdpPerCpuMetrics::new(),
        })
    }

    pub fn snapshot(&self) -> EngineStatsSnapshot {
        EngineStatsSnapshot {
            uptime_secs: self.started_at.elapsed().as_secs(),
            active_workers: self.active_workers.load(Ordering::Relaxed),
            total_requests: self.total_requests.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            waf_blocked: self.waf_blocked.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            upstream_errors: self.upstream_errors.load(Ordering::Relaxed),
            php_fpm_requests: self.php_fpm_requests.load(Ordering::Relaxed),
            static_requests: self.static_requests.load(Ordering::Relaxed),
            http3_requests: self.http3_requests.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            xdp_passed_clean: self.xdp_metrics.xdp_passed_clean.load(Ordering::Relaxed),
            xdp_dropped_ddos: self.xdp_metrics.xdp_dropped_ddos.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EngineStatsSnapshot {
    pub uptime_secs: u64,
    pub active_workers: usize,
    pub total_requests: u64,
    pub active_connections: usize,
    pub waf_blocked: u64,
    pub rate_limited: u64,
    pub upstream_errors: u64,
    pub php_fpm_requests: u64,
    pub static_requests: u64,
    pub http3_requests: u64,
    pub bytes_sent: u64,
    pub xdp_passed_clean: u64,
    pub xdp_dropped_ddos: u64,
}
