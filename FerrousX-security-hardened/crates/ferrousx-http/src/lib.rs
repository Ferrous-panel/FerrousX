//! crates/ferrousx-http/src/lib.rs
//! Bộ xử lý giao thức Dual-Stack HTTP/1.1, HTTP/2 (TLS 1.3 rustls),
//! HTTP/3 QUIC (UDP GRO/GSO qua quinn/h3) và tự động cấp phát ACME Auto-HTTPS / OCSP Stapling.

pub mod acme;
pub mod server;

pub use acme::*;
pub use server::*;
