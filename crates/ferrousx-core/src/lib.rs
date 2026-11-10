//! crates/ferrousx-core/src/lib.rs
//! Lõi xử lý luồng sự kiện đa nhân (Thread-Per-Core), CPU Affinity,
//! bộ cấp phát bộ nhớ Arena (Bumpalo) và Linux io_uring kernel-bypass.

pub mod worker;

pub use worker::*;
