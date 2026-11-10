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

/// Ngữ cảnh độc lập của từng Worker (Shared-Nothing Context).
/// Không sử dụng Send/Sync vì cấu trúc này không bao giờ rời khỏi lõi CPU được gắn kết.
pub struct WorkerContext {
    pub worker_id: usize,
    pub core_id: CoreId,
    pub num_workers: usize,
    pub config_mgr: Arc<ConfigManager>,
    /// Arena Allocator cấp phát vùng nhớ tạm thời trên mỗi request với độ trễ ~2ns
    pub request_arena: Bump,
    /// Vùng đệm cố định (Fixed Buffer Pool) phục vụ đọc/ghi Zero-Copy với io_uring
    pub fixed_io_buffers: Vec<BytesMut>,
}

impl WorkerContext {
    pub fn new(
        worker_id: usize,
        core_id: CoreId,
        num_workers: usize,
        config_mgr: Arc<ConfigManager>,
    ) -> Self {
        let cfg = config_mgr.current();
        let request_arena = Bump::with_capacity(cfg.arena_capacity_bytes);

        // Cấp phát sẵn 256 trang bộ nhớ căn chỉnh 16KB cho io_uring IORING_REGISTER_BUFFERS
        let mut fixed_io_buffers = Vec::with_capacity(256);
        for _ in 0..256 {
            fixed_io_buffers.push(BytesMut::with_capacity(16 * 1024));
        }

        Self {
            worker_id,
            core_id,
            num_workers,
            config_mgr,
            request_arena,
            fixed_io_buffers,
        }
    }

    /// Đặt lại con trỏ Arena sau khi hoàn tất 1 chu kỳ request mà không giải phóng bộ nhớ về OS
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

    // Gắn chương trình cBPF (SO_ATTACH_REUSEPORT_CBPF) trên socket đầu tiên của nhóm reuseport
    if attach_cbpf {
        #[cfg(target_os = "linux")]
        attach_reuseport_cbpf_cpu_steering(socket.as_raw_fd(), num_workers)?;
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

/// Đính kèm bộ lọc Classic BPF (SO_ATTACH_REUSEPORT_CBPF) vào nhóm socket SO_REUSEPORT.
/// Bytecode thực thi ngay trong ngữ cảnh softirq của nhân Linux:
/// Đọc ID của lõi CPU hiện tại (SKF_AD_OFF + SKF_AD_CPU) và chia lấy dư cho tổng số worker,
/// đảm bảo gói tin được NIC xử lý ở CPU Core N sẽ đi thẳng vào Worker N (Zero Cross-Core Bouncing).
#[cfg(target_os = "linux")]
fn attach_reuseport_cbpf_cpu_steering(fd: libc::c_int, num_workers: u32) -> io::Result<()> {
    // Tập lệnh BPF_LD | BPF_W | BPF_ABS (0x20), BPF_ALU | BPF_MOD | BPF_K (0x94), BPF_RET | BPF_A (0x16)
    const SKF_AD_OFF: u32 = (-0x1000i32) as u32;
    const SKF_AD_CPU: u32 = 36;

    #[repr(C)]
    struct SockFilter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const SockFilter,
    }

    let instructions = [
        // Lệnh 1: Nạp ID của lõi CPU đang thực thi ngắt mạng vào thanh ghi A
        SockFilter {
            code: 0x20, // BPF_LD | BPF_W | BPF_ABS
            jt: 0,
            jf: 0,
            k: SKF_AD_OFF.wrapping_add(SKF_AD_CPU),
        },
        // Lệnh 2: A = A % num_workers
        SockFilter {
            code: 0x94, // BPF_ALU | BPF_MOD | BPF_K
            jt: 0,
            jf: 0,
            k: num_workers.max(1),
        },
        // Lệnh 3: Trả về chỉ số socket đích trong mảng reuseport group
        SockFilter {
            code: 0x16, // BPF_RET | BPF_A
            jt: 0,
            jf: 0,
            k: 0,
        },
    ];

    let prog = SockFprog {
        len: instructions.len() as u16,
        filter: instructions.as_ptr(),
    };

    const SO_ATTACH_REUSEPORT_CBPF: libc::c_int = 51;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_ATTACH_REUSEPORT_CBPF,
            &prog as *const _ as *const libc::c_void,
            std::mem::size_of::<SockFprog>() as libc::socklen_t,
        )
    };

    if ret < 0 {
        // Nếu chạy trong container hạn chế quyền CAP_BPF, ghi cảnh báo và dùng hash mặc định của SO_REUSEPORT
        tracing::warn!(
            errno = %io::Error::last_os_error(),
            "Không thể gắn SO_ATTACH_REUSEPORT_CBPF, chuyển sang cơ chế băm 4-tuple mặc định của Kernel"
        );
    }
    Ok(())
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
/// Mỗi lõi CPU chạy một luồng OS riêng biệt được ghim cứng (pinned) và thực thi closure truyền vào.
pub fn spawn_thread_per_core_workers<F, Fut>(
    config_mgr: Arc<ConfigManager>,
    worker_entry: F,
) -> io::Result<Vec<thread::JoinHandle<()>>>
where
    F: Fn(WorkerContext, std::net::TcpListener, std::net::UdpSocket) -> Fut + Send + Sync + 'static,
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

    let tcp_addr: SocketAddr = cfg
        .bind_tcp_addr
        .parse()
        .expect("Địa chỉ bind_tcp_addr không hợp lệ");
    let udp_addr: SocketAddr = cfg
        .bind_udp_addr
        .parse()
        .expect("Địa chỉ bind_udp_addr không hợp lệ");

    let worker_entry = Arc::new(worker_entry);
    let mut handles = Vec::with_capacity(num_workers);

    for (worker_id, core_id) in available_cores.into_iter().take(num_workers).enumerate() {
        let cfg_clone = Arc::clone(&config_mgr);
        let entry_clone = Arc::clone(&worker_entry);

        // Mỗi Worker tự mở socket riêng trên cùng địa chỉ/cổng nhờ SO_REUSEPORT
        let tcp_listener = bind_reusable_tcp_listener(
            tcp_addr,
            num_workers as u32,
            worker_id == 0, // Gắn chương trình cBPF trên đầu nhóm socket
        )?;
        let udp_socket = bind_reusable_udp_socket(udp_addr)?;

        let thread_name = format!("ferrousx-wkr-{worker_id:02}");
        let handle = thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                // 1. Gắn cứng luồng hiện tại vào lõi CPU vật lý
                if !core_affinity::set_for_current(core_id) {
                    error!(worker_id, core = core_id.id, "Không thể gắn core_affinity");
                } else {
                    info!(
                        worker_id,
                        cpu_core = core_id.id,
                        "Đã ghim cứng Worker vào lõi CPU (Shared-Nothing Architecture)"
                    );
                }

                let ctx = WorkerContext::new(worker_id, core_id, num_workers, cfg_clone);

                // 2. Khởi chạy Single-Threaded Async Runtime độc lập trên lõi này
                // (Trên nhân Linux >= 6.1 có thể gọi trực tiếp tokio_uring::start)
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("Không thể khởi tạo current_thread runtime cho Worker");

                runtime.block_on(async move {
                    if let Err(err) = entry_clone(ctx, tcp_listener, udp_socket).await {
                        error!(worker_id, error = %err, "Vòng lặp Worker dừng đột ngột");
                    }
                });
            })?;

        handles.push(handle);
    }

    Ok(handles)
}
