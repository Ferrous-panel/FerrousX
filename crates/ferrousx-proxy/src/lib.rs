//! crates/ferrousx-proxy/src/lib.rs
//! Pipeline Reverse Proxy: Singleflight request coalescing, Circuit Breaker,
//! FastCGI UDS streaming và nén động Brotli/Zstandard.

pub mod pipeline;

pub use pipeline::*;
