//! crates/ferrousx-proxy/src/lib.rs
//! Pipeline Reverse Proxy: Singleflight request coalescing, Circuit Breaker,
//! Zero-Alloc WAF, GCRA Leaky-Bucket Rate Limiter, FastCGI Async Client UDS
//! và nén động Brotli/Zstandard.

pub mod fastcgi;
pub mod pipeline;
pub mod waf;

pub use fastcgi::*;
pub use pipeline::*;
pub use waf::*;
