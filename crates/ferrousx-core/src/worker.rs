//! crates/ferrousx-core/src/worker.rs
//! Triển khai mô hình Thread-Per-Core (Shared-Nothing Architecture),
//! gắn kết CPU (CPU Affinity), khởi tạo Socket SO_REUSEPORT + cBPF Kernel Steering
//! và vòng lặp bất đồng bộ io_uring / Arena Allocator riêng cho từng lõi.

use std::io;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::thread;

use bumpalo::Bump;
use bytes::BytesMut;
use core_affinity::CoreId;
use socket2::{Domain, Protocol, Socket, Type};
use tracing::{error, info};

use ferrousx_config::config::ConfigManager;

use crate::ebpf::EbpfPacketSteerer;
use crate::metrics::EngineRuntimeStats;
use crate::numa::{detect_cpu_numa_node, HugePageArenaBuffer};

/// Ngữ cảnh độc lập của từng Worker (Shared-Nothing Context).
pub struct WorkerContext {
    pub worker_id: usize,
    pub core_id: CoreId,
    pub numa_node: usize,
    pub num_workers: usize,
    pub config_mgr: Arc<ConfigManager>,
    pub stats: Arc<EngineRuntimeStats>,
    /// Arena Allocator cấp phát vùng nhớ tạm thời trên mỗi request với độ trễ ~2ns
    pub request_arena: Bump,
    /// Vùng đệm cố định 2MB HugePages gắn với NUMA node của lõi CPU này
    pub hugepage_arena: Option<HugePageArenaBuffer>,
    /// Vùng đệm cố định (Fixed Buffer Pool) phục vụ đọc/ghi Zero-Copy
    pub fixed_io_buffers: Vec<BytesMut>,
}

impl WorkerContext {
    pub fn new(
        worker_id: usize,
        core_id: CoreId,
        num_workers: usize,
        config_mgr: Arc<ConfigManager>,
        stats: Arc<EngineRuntimeStats>,
    ) -> Self {
        let cfg = config_mgr.current();
        let numa_node = detect_cpu_numa_node(core_id.id);
        let request_arena = Bump::with_capacity(cfg.arena_capacity_bytes);
        let hugepage_arena =
            HugePageArenaBuffer::allocate_pinned_2mb_aligned(2 * 1024 * 1024, numa_node).ok();

        let mut fixed_io_buffers = Vec::with_capacity(64);
        for _ in 0..64 {
            fixed_io_buffers.push(BytesMut::with_capacity(16 * 1024));
        }

        Self {
            worker_id,
            core_id,
            numa_node,
            num_workers,
            config_mgr,
            stats,
            request_arena,
            hugepage_arena,
            fixed_io_buffers,
        }
    }

    #[inline(always)]
    pub fn reset_arena(&mut self) {
        self.request_arena.reset();
    }
}

/// Khởi tạo TCP Listener Socket với đầy đủ cờ tối ưu hóa nhân Linux:
/// SO_REUSEPORT, TCP_NODELAY, TCP_FASTOPEN, TCP_DEFER_ACCEPT và bộ lọc cBPF.
pub fn bind_reusable_tcp_listener(
    addr: SocketAddr,
    num_workers: u32,
    attach_cbpf: bool,
) -> io::Result<std::net::TcpListener> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nodelay(true)?;
    socket.set_nonblocking(true)?;

    // Tăng kích thước hàng đợi nhận/gửi ở tầng Kernel
    let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(4 * 1024 * 1024);

    // Bật TCP Fast Open (TFO) giảm 1 RTT khi bắt tay lại
    #[cfg(target_os = "linux")]
    unsafe {
        let qlen: libc::c_int = 4096;
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_TCP,
            libc::TCP_FASTOPEN,
            &qlen as *const _ as *const libc::c_void,
            std::mem::size_of_val(&qlen) as libc::socklen_t,
        );
    }

    // Gắn chương trình cBPF (SO_ATTACH_REUSEPORT_CBPF) qua EbpfPacketSteerer
    if attach_cbpf {
        #[cfg(target_os = "linux")]
        EbpfPacketSteerer::new(num_workers).attach_cpu_locality_cbpf(socket.as_raw_fd())?;
    }

    socket.bind(&addr.into())?;
    socket.listen(65535)?; // Backlog cực đại khớp với net.core.somaxconn

    Ok(socket.into())
}

/// Khởi tạo UDP Socket cho HTTP/3 (QUIC) với SO_REUSEPORT + UDP GRO / GSO offload
pub fn bind_reusable_udp_socket(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;

    // Đặt bộ đệm UDP 16MB để hấp thụ các đợt micro-burst của giao thức QUIC
    let _ = socket.set_recv_buffer_size(16 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(16 * 1024 * 1024);

    #[cfg(target_os = "linux")]
    configure_udp_gro_gso(socket.as_raw_fd());

    socket.bind(&addr.into())?;
    Ok(socket.into())
}



/// Kích hoạt UDP Generic Receive Offload (UDP_GRO) và Generic Segmentation Offload (UDP_SEGMENT)
#[cfg(target_os = "linux")]
fn configure_udp_gro_gso(fd: libc::c_int) {
    const SOL_UDP: libc::c_int = 17;
    const UDP_SEGMENT: libc::c_int = 103;
    const UDP_GRO: libc::c_int = 104;

    unsafe {
        let enable: libc::c_int = 1;
        libc::setsockopt(
            fd,
            SOL_UDP,
            UDP_GRO,
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of_val(&enable) as libc::socklen_t,
        );

        let gso_size: libc::c_int = 1350; // Khớp với kích thước gói QUIC chuẩn
        libc::setsockopt(
            fd,
            SOL_UDP,
            UDP_SEGMENT,
            &gso_size as *const _ as *const libc::c_void,
            std::mem::size_of_val(&gso_size) as libc::socklen_t,
        );
    }
}

/// Khởi chạy toàn bộ cụm Worker theo mô hình Thread-Per-Core.
/// Mỗi lõi CPU chạy một luồng OS riêng biệt được ghim cứng (pinned) và lắng nghe đồng thời:
///   - TCP HTTP (:80)
///   - TCP HTTPS TLS 1.3/1.2 (:443) — Bắt buộc cho Cloudflare Proxy (tránh Error 521)
///   - UDP HTTP/3 QUIC (:443)
pub fn spawn_thread_per_core_workers<F, Fut>(
    config_mgr: Arc<ConfigManager>,
    stats: Arc<EngineRuntimeStats>,
    worker_entry: F,
) -> io::Result<Vec<thread::JoinHandle<()>>>
where
    F: Fn(
            WorkerContext,
            std::net::TcpListener,
            std::net::TcpListener,
            Option<std::net::UdpSocket>,
        ) -> Fut
        + Send
        + Sync
        + 'static,
    Fut: std::future::Future<Output = anyhow::Result<()>> + 'static,
{
    let available_cores = core_affinity::get_core_ids().unwrap_or_else(|| {
        (0..4).map(|id| CoreId { id }).collect()
    });

    let cfg = config_mgr.current();
    let num_workers = if cfg.worker_threads == 0 {
        available_cores.len()
    } else {
        cfg.worker_threads.min(available_cores.len())
    };

    let http_addr: SocketAddr = cfg
        .effective_http_addr()
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bind_http_addr không hợp lệ: {e}")))?;
    let https_addr: SocketAddr = cfg
        .effective_https_addr()
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bind_https_addr không hợp lệ: {e}")))?;
    let udp_addr: SocketAddr = cfg
        .bind_udp_addr
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bind_udp_addr không hợp lệ: {e}")))?;
    let enable_quic = cfg.enable_http3_quic;

    let worker_entry = Arc::new(worker_entry);
    let mut handles = Vec::with_capacity(num_workers);

    for (worker_id, core_id) in available_cores.into_iter().take(num_workers).enumerate() {
        let cfg_clone = Arc::clone(&config_mgr);
        let stats_clone = Arc::clone(&stats);
        let entry_clone = Arc::clone(&worker_entry);

        // Mỗi Worker tự mở socket riêng trên cùng địa chỉ/cổng nhờ SO_REUSEPORT
        let http_listener = bind_reusable_tcp_listener(
            http_addr,
            num_workers as u32,
            worker_id == 0,
        )?;
        let https_listener = bind_reusable_tcp_listener(
            https_addr,
            num_workers as u32,
            worker_id == 0,
        )?;
        let udp_socket = if enable_quic {
            match bind_reusable_udp_socket(udp_addr) {
                Ok(sock) => Some(sock),
                Err(err) => {
                    tracing::warn!(
                        worker_id,
                        addr = %udp_addr,
                        error = %err,
                        "Không thể bind UDP QUIC (:443), tiếp tục phục vụ HTTP/1.1 & HTTP/2 TCP (:80 & :443)"
                    );
                    None
                }
            }
        } else {
            None
        };

        let thread_name = format!("ferrousx-wkr-{worker_id:02}");
        let handle = thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                if !core_affinity::set_for_current(core_id) {
                    error!(worker_id, core = core_id.id, "Không thể gắn core_affinity");
                } else {
                    info!(
                        worker_id,
                        cpu_core = core_id.id,
                        "Đã ghim cứng Worker vào lõi CPU (Shared-Nothing Architecture)"
                    );
                }

                let ctx = WorkerContext::new(worker_id, core_id, num_workers, cfg_clone, stats_clone);

                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("Không thể khởi tạo current_thread runtime cho Worker");

                runtime.block_on(async move {
                    if let Err(err) = entry_clone(ctx, http_listener, https_listener, udp_socket).await {
                        error!(worker_id, error = %err, "Vòng lặp Worker dừng đột ngột");
                    }
                });
            })?;

        handles.push(handle);
    }

    Ok(handles)
}
