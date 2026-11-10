//! crates/ferrousx-panel/src/lib.rs
//! Panel API Server và bộ giải mã giao thức điều khiển 100% bằng Rust.
//! Cung cấp Unix Domain Socket IPC và endpoint REST cho Ferrous Panel.

pub mod api;

pub use api::*;
