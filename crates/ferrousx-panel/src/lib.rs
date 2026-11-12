//! crates/ferrousx-panel/src/lib.rs
//! Panel API Server, Embedded Rust Web UI và bộ giải mã giao thức điều khiển 100% bằng Rust.
//! Cung cấp Unix Domain Socket IPC và giao diện Web quản trị nhúng tĩnh cho Ferrous Panel.

pub mod api;
pub mod webui;

pub use api::*;
pub use webui::*;
