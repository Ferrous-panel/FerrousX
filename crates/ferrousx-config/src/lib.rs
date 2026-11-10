//! crates/ferrousx-config/src/lib.rs
//! Bộ phân tích cú pháp cấu hình TOML/KDL và quản lý con trỏ nguyên tử không khóa
//! (Lock-Free ArcSwap RCU) phục vụ hot-reload dưới 50 micro-giây.

pub mod config;

pub use config::*;
