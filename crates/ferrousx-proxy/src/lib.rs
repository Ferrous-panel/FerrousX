//! crates/ferrousx-proxy/src/lib.rs
//! Pipeline Reverse Proxy: Singleflight request coalescing, Circuit Breaker,
//! Zero-Alloc WAF, GCRA Leaky-Bucket Rate Limiter, FastCGI UDS streaming
//! và nén động Brotli/Zstandard.

pub mod pipeline;
pub mod waf;

pub use pipeline::*;
pub use waf::*;
