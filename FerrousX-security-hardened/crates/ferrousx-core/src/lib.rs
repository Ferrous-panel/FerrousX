//! crates/ferrousx-core/src/lib.rs
//! Lõi xử lý luồng sự kiện đa nhân (Thread-Per-Core), CPU Affinity,
//! bộ cấp phát bộ nhớ Arena (Bumpalo), 2MB HugePages NUMA Allocator,
//! eBPF/XDP Packet Steering và Linux io_uring kernel-bypass.

pub mod ebpf;
pub mod numa;
pub mod worker;

pub use ebpf::*;
pub use numa::*;
pub use worker::*;
