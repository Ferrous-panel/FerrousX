//! crates/ferrousx-http/src/lib.rs
//! Bộ xử lý giao thức Dual-Stack HTTP/1.1, HTTP/2 (TLS 1.3 rustls)
//! và HTTP/3 QUIC (UDP GRO/GSO qua quinn/h3).

pub mod server;

pub use server::*;
