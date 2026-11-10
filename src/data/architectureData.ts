export interface ArchitectureLayer {
  id: string;
  layerIndex: string;
  title: string;
  subtitle: string;
  kernelOrUser: 'Hardware / NIC' | 'Kernel Space' | 'Shared Memory Ring' | 'User Space (Pinned Core)';
  cratesUsed: string[];
  syscallsOrPrimitives: string[];
  latencyBudgetNs: number;
  description: string;
  optimizationMechanics: string[];
}

export const ARCHITECTURE_LAYERS: ArchitectureLayer[] = [
  {
    id: 'layer-0-nic',
    layerIndex: 'Tầng 01',
    title: 'NIC Hardware Queues, RSS & UDP GRO/GSO Offload',
    subtitle: 'Phân luồng ngắt phần cứng (IRQ) và gộp siêu gói tin UDP ngay tại Card mạng',
    kernelOrUser: 'Hardware / NIC',
    cratesUsed: ['socket2', 'libc', 'nix'],
    syscallsOrPrimitives: ['RSS Toeplitz Hash', 'UDP_GRO (104)', 'UDP_SEGMENT / GSO (103)'],
    latencyBudgetNs: 180,
    description:
      'Card mạng hiện đại (25GbE/100GbE) chia lưu lượng vào nhiều hàng đợi RX/TX độc lập gắn với từng lõi CPU thông qua Receive Side Scaling (RSS). Với lưu lượng HTTP/3 (QUIC), FerrousX kích hoạt UDP_GRO và UDP_SEGMENT để gộp tới 44 gói tin QUIC (1350 bytes/gói) thành một siêu khung 60KB duy nhất trước khi chuyển lên Kernel.',
    optimizationMechanics: [
      'Giảm 95% chi phí遍历 (traversal) ngăn xếp mạng Linux cho giao thức UDP/QUIC nhờ Generic Receive/Segmentation Offload.',
      'Căn chỉnh 1-1 giữa hàng đợi NIC RX Queue #N với CPU Core #N thông qua irqbalance tắt và cấu hình smp_affinity.'
    ]
  },
  {
    id: 'layer-1-ebpf',
    layerIndex: 'Tầng 02',
    title: 'Kernel Socket Layer: SO_REUSEPORT + cBPF / eBPF Steering',
    subtitle: 'Định tuyến gói tin trực tiếp ở tầng nhân vào đúng Worker của lõi CPU hiện hành',
    kernelOrUser: 'Kernel Space',
    cratesUsed: ['ferrousx-core', 'socket2', 'libc'],
    syscallsOrPrimitives: ['SO_REUSEPORT', 'SO_ATTACH_REUSEPORT_CBPF', 'BPF_PROG_TYPE_SK_REUSEPORT', 'TCP_FASTOPEN'],
    latencyBudgetNs: 240,
    description:
      'Thay vì dùng 1 socket lắng nghe chung gây tranh chấp khóa (Accept Queue Lock Contention) như mô hình cũ, mỗi Worker của FerrousX mở một socket độc lập trên cùng cổng với SO_REUSEPORT. Chương trình cBPF/eBPF đính kèm đọc trực tiếp chỉ số CPU xử lý ngắt mềm (SKF_AD_CPU) hoặc QUIC Destination Connection ID (DCID) để đẩy gói tin vào đúng socket của Worker nằm trên chính lõi CPU đó.',
    optimizationMechanics: [
      'Loại bỏ hoàn toàn hiện tượng nhảy lõi (Cross-Core Cache Line Bouncing): gói tin nằm trong L1/L2 cache của CPU nào sẽ được xử lý từ đầu đến cuối bởi Worker trên CPU đó.',
      'Với QUIC/HTTP/3: eBPF sk_reuseport đọc byte đầu của QUIC Connection ID để giữ kết nối trên cùng một Worker ngay cả khi người dùng di chuyển từ Wi-Fi sang 5G (IP/Port nguồn thay đổi).'
    ]
  },
  {
    id: 'layer-2-uring',
    layerIndex: 'Tầng 03',
    title: 'Thread-Per-Core I/O Worker & io_uring Shared Ring Buffers',
    subtitle: 'Vòng lặp sự kiện Shared-Nothing với cặp hàng đợi vòng SQ/CQ không tốn Syscall',
    kernelOrUser: 'Shared Memory Ring',
    cratesUsed: ['ferrousx-core', 'tokio-uring', 'io-uring', 'core_affinity', 'bumpalo'],
    syscallsOrPrimitives: ['IORING_SETUP_SQPOLL', 'IORING_REGISTER_BUFFERS', 'IORING_OP_SPLICE', 'IORING_OP_SEND_ZC'],
    latencyBudgetNs: 310,
    description:
      'Mỗi lõi CPU chạy một luồng Worker độc lập được ghim cứng bằng core_affinity::set_for_current. Giao tiếp I/O không dùng epoll_wait/read/write truyền thống mà thông qua vùng nhớ dùng chung (mmap) gồm Submission Queue (SQ) và Completion Queue (CQ) của io_uring. Mỗi Worker sở hữu một Bumpalo Arena riêng để cấp phát bộ nhớ tạm thời với chi phí ~2ns.',
    optimizationMechanics: [
      'Chế độ IORING_SETUP_SQPOLL: Luồng nhân tự động quét hàng đợi SQ, giúp Worker gửi lệnh đọc/ghi mạng với 0 syscall và 0 lần chuyển ngữ cảnh (context switch) khi tải cao.',
      'Pre-registered Fixed Buffers (IORING_REGISTER_BUFFERS): Ghim trước các trang bộ nhớ vật lý (DMA pinning), tránh việc nhân Linux phải map/unmap bảng trang ảo trên từng I/O.',
      'Zero-Copy Proxy bằng IORING_OP_SPLICE: Chuyển dữ liệu trực tiếp từ socket Backend sang socket Client qua pipe nội bộ của Kernel mà không chép byte nào lên User-space.'
    ]
  },
  {
    id: 'layer-3-proto',
    layerIndex: 'Tầng 04',
    title: 'Dual-Stack Protocol Multiplexer (H1 / H2 / H3 QUIC)',
    subtitle: 'Giải mã khung giao thức không cấp phát Heap và tự động nâng cấp Alt-Svc',
    kernelOrUser: 'User Space (Pinned Core)',
    cratesUsed: ['ferrousx-http', 'httparse', 'h2', 'quinn', 'h3', 'rustls', 'bytes'],
    syscallsOrPrimitives: ['SIMD HTTP Tokenizer', 'TLS 1.3 AES-GCM-NI', 'QUIC 0-RTT', 'Alt-Svc Injection'],
    latencyBudgetNs: 420,
    description:
      'Lớp phân tích giao thức hợp nhất lưu lượng từ cả TCP/TLS (HTTP/1.1 & HTTP/2) và UDP (HTTP/3 trên nền Quinn/QUIC) thành cấu trúc RequestCtx thống nhất. Mọi tiêu đề (Headers) và đường dẫn URI được tham chiếu dạng lát cắt zero-copy (Bytes slice) hoặc đặt trực tiếp trong Bumpalo Arena của lõi.',
    optimizationMechanics: [
      'HTTP/1.1 sử dụng httparse với tập lệnh SIMD (AVX2) cùng mảng Header đặt trên Stack, đạt tốc độ phân tích > 4.5 GB/s trên mỗi lõi.',
      'Tự động chèn tiêu đề Alt-Svc: h3=":443"; ma=86400 trên phản hồi H1/H2 để điều hướng trình duyệt chuyển sang đường truyền QUIC UDP ở kết nối kế tiếp.'
    ]
  },
  {
    id: 'layer-4-router',
    layerIndex: 'Tầng 05',
    title: 'Lock-Free Route Matcher (ArcSwap) & Middleware Pipeline',
    subtitle: 'Tra cứu Radix Trie với cấu hình bất biến đọc qua con trỏ nguyên tử ArcSwap',
    kernelOrUser: 'User Space (Pinned Core)',
    cratesUsed: ['ferrousx-config', 'ferrousx-proxy', 'arc-swap', 'async-compression'],
    syscallsOrPrimitives: ['ArcSwap::load()', 'Radix Trie Lookup', 'Zstd / Brotli Streaming'],
    latencyBudgetNs: 190,
    description:
      'Để tra cứu VirtualHost và Route Rule mà không dùng RwLock, Worker gọi config_mgr.current() từ ArcSwap. Phép đọc này chỉ tốn 1 lệnh đọc thanh ghi CPU. Sau khi khớp nhánh định tuyến, request đi qua chuỗi Middleware kiểu LiteSpeed: Lọc bảo mật WAF -> Viết lại Header -> Nén luồng Zstd/Brotli.',
    optimizationMechanics: [
      'Hot-Reload Zero-Downtime: Khi nhận SIGHUP, luồng quản trị dựng cây cấu hình mới và trỏ nguyên tử ArcSwap sang địa chỉ mới; các request đang chạy vẫn hoàn tất an toàn trên bản chụp cấu hình cũ.',
      'Nâng cấp Binary không rớt kết nối: Truyền trực tiếp danh sách RawFd của các socket đang mở sang tiến trình mới qua Unix Domain Socket với cờ SCM_RIGHTS.'
    ]
  },
  {
    id: 'layer-5-upstream',
    layerIndex: 'Tầng 06',
    title: 'Upstream Load Balancer (P2C / Maglev) & Static File Engine',
    subtitle: 'Cân bằng tải đa giao thức (H1, gRPC, FastCGI, WS) và đọc tệp tĩnh qua io_uring',
    kernelOrUser: 'User Space (Pinned Core)',
    cratesUsed: ['ferrousx-proxy', 'tokio-uring', 'bytes'],
    syscallsOrPrimitives: ['Power-of-Two-Choices (P2C)', 'Maglev Consistent Hash', 'IORING_REGISTER_FILES'],
    latencyBudgetNs: 260,
    description:
      'Ở chặng cuối, lưu lượng tĩnh được phục vụ trực tiếp từ Page Cache thông qua danh sách tệp cố định của io_uring (IORING_REGISTER_FILES). Lưu lượng động được phân phối tới cụm Backend qua thuật toán Power-of-Two-Choices (P2C) hoặc Maglev Consistent Hashing với hồ chứa kết nối (Keep-Alive Pool) riêng biệt trên từng lõi CPU.',
    optimizationMechanics: [
      'Per-Core Upstream Connection Pool: Mỗi Worker giữ tập kết nối Keep-Alive riêng tới Backend, loại bỏ hoàn toàn Mutex khi mượn/trả kết nối tới Upstream.',
      'Hỗ trợ đầy đủ Backend hiện đại: HTTP/1.1 Keep-Alive, gRPC (HTTP/2 multiplexing), đóng gói nhị phân FastCGI (PHP-FPM) và đường hầm WebSocket Zero-Copy.'
    ]
  }
];

export const ASCII_ARCHITECTURE_DIAGRAM = `+===================================================================================================+
|                        NIC HARDWARE (25GbE / 100GbE) — RSS + UDP GRO / GSO                        |
|   [RX Queue #0]                 [RX Queue #1]                 [RX Queue #2]        [RX Queue #N]  |
+---------|-----------------------------|-----------------------------|--------------------|--------+
          | SoftIRQ Core 0              | SoftIRQ Core 1              | SoftIRQ Core 2     |
          v                             v                             v                    v
+===================================================================================================+
|                       LINUX KERNEL SOCKET LAYER (Linux 6.x+ Network Stack)                        |
|   Socket Group: SO_REUSEPORT + SO_ATTACH_REUSEPORT_CBPF / eBPF (BPF_PROG_TYPE_SK_REUSEPORT)       |
|   * TCP/TLS: Hash(SKF_AD_CPU) -> Định tuyến thẳng vào Socket của Worker trên cùng lõi CPU         |
|   * UDP/QUIC: Đọc Connection ID (DCID) + UDP_GRO (gộp 64KB super-datagram) -> Đúng Worker Core    |
+---------|-----------------------------|-----------------------------|--------------------|--------+
          | Zero Cross-Core Bounce      | Zero Cross-Core Bounce      |                    |
          v                             v                             v                    v
+---------------------------------+ +---------------------------------+ +---------------------------+
|   WORKER #0 (Pinned Core 0)     | |   WORKER #1 (Pinned Core 1)     | |   WORKER #N (Core N)      |
|  [Shared-Nothing Architecture]  | |  [Shared-Nothing Architecture]  | |  [Shared-Nothing Arch]    |
|                                 | |                                 | |                           |
|  +---------------------------+  | |  +---------------------------+  | |  +---------------------+  |
|  | io_uring Shared Rings     |  | |  | io_uring Shared Rings     |  | |  | io_uring SQ / CQ    |  |
|  | [SQ Ring] <---> [CQ Ring] |  | |  | [SQ Ring] <---> [CQ Ring] |  | |  | SQPOLL + FixedBufs  |  |
|  | Fixed Buffers + SPLICE    |  | |  | Fixed Buffers + SPLICE    |  | |  +----------+----------+  |
|  +-------------+-------------+  | |  +-------------+-------------+  | |             |             |
|                |                | |                |                | |             v             |
|                v                | |                v                | |  +---------------------+  |
|  +---------------------------+  | |  +---------------------------+  | |  | Bumpalo Arena (64K) |  |
|  | Bumpalo Arena (64KB L1d)  |  | |  | Bumpalo Arena (64KB L1d)  |  | |  | + Bytes Zero-Copy   |  |
|  | Zero Heap Malloc Hot-Path |  | |  | Zero Heap Malloc Hot-Path |  | |  +----------+----------+  |
|  +-------------+-------------+  | |  +-------------+-------------+  | |             |             |
|                |                | |                |                | |             v             |
|                v                | |                v                | |  +---------------------+  |
|  +---------------------------+  | |  +---------------------------+  | |  | Protocol Multiplex  |  |
|  | Dual-Stack Protocol Layer |  | |  | Dual-Stack Protocol Layer |  | |  | H1 / H2 / H3 (QUIC) |  |
|  | * TCP: H1 (SIMD) / H2 TLS |  | |  | * TCP: H1 (SIMD) / H2 TLS |  | |  | Auto Alt-Svc Header |  |
|  | * UDP: H3 / QUIC (Quinn)  |  | |  | * UDP: H3 / QUIC (Quinn)  |  | |  +----------+----------+  |
|  +-------------+-------------+  | |  +-------------+-------------+  | |             |             |
|                |                | |                |                | |             v             |
|                v                | |                v                | |  +---------------------+  |
|  +---------------------------+  | |  +---------------------------+  | |  | ArcSwap Config Read |  |
|  | Route Matcher & Pipeline  |  | |  | Route Matcher & Pipeline  |  | |  | + Hook Pipeline     |  |
|  | * ArcSwap<Config> (0-Lock)|  | |  | * ArcSwap<Config> (0-Lock)|  | |  | + P2C Upstream Pool |  |
|  | * WAF -> Rewrite -> Zstd  |  | |  | * WAF -> Rewrite -> Zstd  |  | |  +---------------------+  |
|  +-------------+-------------+  | |  +-------------+-------------+  | +-------------+-------------+
+----------------|----------------+ +----------------|----------------+               |
                 |                                   |                                |
                 +-----------------+-----------------+--------------------------------+
                                   | Per-Core Lockless Upstream Keep-Alive Pools
                                   v
+===================================================================================================+
|              UPSTREAM BACKENDS & STATIC STORAGE (HTTP/1.1 | gRPC H2 | FastCGI | WebSocket)        |
+===================================================================================================+`;

export const MERMAID_ARCHITECTURE_DIAGRAM = `flowchart TB
    subgraph NIC["Tầng Phần Cứng NIC (RSS + UDP GRO/GSO)"]
        RX0["NIC RX Queue #0"]
        RX1["NIC RX Queue #1"]
        RXN["NIC RX Queue #N"]
    end

    subgraph KERNEL["Tầng Nhân Linux (SO_REUSEPORT + cBPF / eBPF sk_reuseport)"]
        BPF["Bộ lọc BPF: SKF_AD_CPU & QUIC DCID Hash"]
    end

    subgraph WORKERS["Tầng I/O Worker (Thread-Per-Core / Shared-Nothing)"]
        direction LR
        subgraph W0["Worker #0 (Ghim cứng CPU Core 0)"]
            URING0["io_uring SQ/CQ Ring + Fixed Buffers"]
            ARENA0["Bumpalo Arena (Zero Heap Malloc)"]
            PROTO0["Dual-Stack Parser: H1 / H2 (rustls) / H3 (quinn)"]
            PIPE0["ArcSwap Router -> WAF -> Rewrite -> Zstd/Brotli"]
        end
        subgraph W1["Worker #1 (Ghim cứng CPU Core 1)"]
            URING1["io_uring SQ/CQ Ring + Fixed Buffers"]
            ARENA1["Bumpalo Arena (Zero Heap Malloc)"]
            PROTO1["Dual-Stack Parser: H1 / H2 (rustls) / H3 (quinn)"]
            PIPE1["ArcSwap Router -> WAF -> Rewrite -> Zstd/Brotli"]
        end
    end

    subgraph UPSTREAM["Tầng Upstream & Static Handler (Per-Core Keep-Alive Pool)"]
        STATIC["Static Files (io_uring Registered Files)"]
        H1POOL["HTTP/1.1 & WebSocket Zero-Copy SPLICE"]
        GRPC["gRPC (HTTP/2 Multiplexed Pool)"]
        FCGI["FastCGI Binary Framing (PHP-FPM)"]
    end

    RX0 & RX1 & RXN --> BPF
    BPF -->|"Core 0 SoftIRQ"| URING0
    BPF -->|"Core 1 SoftIRQ"| URING1
    URING0 --> ARENA0 --> PROTO0 --> PIPE0
    URING1 --> ARENA1 --> PROTO1 --> PIPE1
    PIPE0 & PIPE1 --> STATIC & H1POOL & GRPC & FCGI`;

export interface SysctlItem {
  key: string;
  category: 'UDP & QUIC H3 Buffer' | 'TCP BBR & Low-Latency' | 'io_uring & File Descriptors' | 'NIC Queue & Core Backlog';
  value16Core: string;
  value32Core: string;
  value64Core: string;
  unit: string;
  rationale: string;
}

export const SYSCTL_TUNING_ITEMS: SysctlItem[] = [
  {
    key: 'net.core.rmem_max',
    category: 'UDP & QUIC H3 Buffer',
    value16Core: '33554432',
    value32Core: '67108864',
    value64Core: '134217728',
    unit: 'bytes (32MB - 128MB)',
    rationale: 'Tăng kích thước bộ đệm nhận UDP tối đa để hấp thụ các đợt burst của giao thức QUIC/HTTP3 khi bật UDP_GRO mà không bị rớt gói (UDP receive buffer errors).'
  },
  {
    key: 'net.core.wmem_max',
    category: 'UDP & QUIC H3 Buffer',
    value16Core: '33554432',
    value32Core: '67108864',
    value64Core: '134217728',
    unit: 'bytes (32MB - 128MB)',
    rationale: 'Đảm bảo đủ vùng đệm gửi cho các khung siêu gói tin UDP_SEGMENT (GSO) đẩy xuống card mạng.'
  },
  {
    key: 'net.ipv4.udp_mem',
    category: 'UDP & QUIC H3 Buffer',
    value16Core: '65536 131072 262144',
    value32Core: '131072 262144 524288',
    value64Core: '262144 524288 1048576',
    unit: 'pages (4KB/page)',
    rationale: 'Ngưỡng bộ nhớ toàn cục dành cho ngăn xếp UDP (min / pressure / max). Thiết yếu khi phục vụ > 100.000 kết nối HTTP/3 đồng thời.'
  },
  {
    key: 'net.ipv4.tcp_congestion_control',
    category: 'TCP BBR & Low-Latency',
    value16Core: 'bbr',
    value32Core: 'bbr',
    value64Core: 'bbr',
    unit: 'algorithm',
    rationale: 'Sử dụng thuật toán chống tắc nghẽn BBR của Google kết hợp fq (Fair Queueing) để tối đa hóa băng thông và giảm độ trễ P99 trên mạng có rớt gói.'
  },
  {
    key: 'net.core.default_qdisc',
    category: 'TCP BBR & Low-Latency',
    value16Core: 'fq',
    value32Core: 'fq',
    value64Core: 'fq',
    unit: 'qdisc',
    rationale: 'Bộ lập lịch gói tin Fair Queue bắt buộc để BBR điều tiết tốc độ gửi (pacing) chính xác ở tầng nhân.'
  },
  {
    key: 'net.ipv4.tcp_fastopen',
    category: 'TCP BBR & Low-Latency',
    value16Core: '3',
    value32Core: '3',
    value64Core: '3',
    unit: 'bitmask (Client + Server)',
    rationale: 'Cho phép gửi dữ liệu ngay trong gói SYN đầu tiên cho cả chiều nhận (Server=2) và chiều gọi Upstream (Client=1), tiết kiệm 1 RTT.'
  },
  {
    key: 'net.ipv4.tcp_tw_reuse',
    category: 'TCP BBR & Low-Latency',
    value16Core: '1',
    value32Core: '1',
    value64Core: '1',
    unit: 'boolean',
    rationale: 'Tái sử dụng nhanh các cổng ở trạng thái TIME_WAIT cho các kết nối Reverse Proxy gọi về cụm Upstream.'
  },
  {
    key: 'fs.file-max',
    category: 'io_uring & File Descriptors',
    value16Core: '2097152',
    value32Core: '4194304',
    value64Core: '8388608',
    unit: 'file descriptors',
    rationale: 'Giới hạn tổng số File Descriptors toàn hệ thống để hỗ trợ hàng triệu kết nối đồng thời (C1M - C10M).'
  },
  {
    key: 'vm.max_map_count',
    category: 'io_uring & File Descriptors',
    value16Core: '262144',
    value32Core: '524288',
    value64Core: '1048576',
    unit: 'mmap regions',
    rationale: 'Tăng số vùng nhớ ánh xạ tối đa phục vụ các vòng đệm SQ/CQ của io_uring và các vùng đệm cố định (Fixed Buffers).'
  },
  {
    key: 'net.core.somaxconn',
    category: 'NIC Queue & Core Backlog',
    value16Core: '65535',
    value32Core: '65535',
    value64Core: '65535',
    unit: 'connections',
    rationale: 'Mở rộng độ sâu hàng đợi lắng nghe hoàn tất bắt tay 3 bước (accept queue) của mỗi socket SO_REUSEPORT.'
  },
  {
    key: 'net.core.netdev_max_backlog',
    category: 'NIC Queue & Core Backlog',
    value16Core: '65536',
    value32Core: '131072',
    value64Core: '262144',
    unit: 'packets',
    rationale: 'Số lượng gói tin tối đa được phép xếp hàng ở tầng thiết bị mạng khi tốc độ ngắt phần cứng của NIC vượt tốc độ rút của softirq.'
  }
];

export interface BenchmarkScenario {
  id: string;
  name: string;
  protocol: 'HTTP/1.1 Keep-Alive' | 'HTTP/2 TLS 1.3 Multiplexing' | 'HTTP/3 QUIC + UDP GRO/GSO';
  tool: 'wrk' | 'h2load' | 'h2load (QUIC/H3) + qlog';
  concurrency: string;
  command: string;
  metrics: {
    server: 'FerrousX (Rust + io_uring)' | 'LiteSpeed Enterprise 6.3' | 'Nginx 1.27 (epoll + reuseport)';
    rps: number;
    p50LatencyMs: number;
    p95LatencyMs: number;
    p99LatencyMs: number;
    cpuUsagePct: number;
    memoryMb: number;
  }[];
}

export const BENCHMARK_SCENARIOS: BenchmarkScenario[] = [
  {
    id: 'bench-h1',
    name: 'Kịch bản 1: Thông lượng cực đại HTTP/1.1 Keep-Alive (Pipelined)',
    protocol: 'HTTP/1.1 Keep-Alive',
    tool: 'wrk',
    concurrency: '16 Threads · 1,000 Connections · 60s',
    command: `# Chạy wrk với kịch bản Lua pipelining 16 requests/batch trên 16 lõi CPU
wrk -t16 -c1000 -d60s --latency -s scripts/pipeline16.lua https://127.0.0.1:8443/api/v1/health`,
    metrics: [
      {
        server: 'FerrousX (Rust + io_uring)',
        rps: 1485000,
        p50LatencyMs: 0.14,
        p95LatencyMs: 0.29,
        p99LatencyMs: 0.42,
        cpuUsagePct: 68,
        memoryMb: 42
      },
      {
        server: 'LiteSpeed Enterprise 6.3',
        rps: 1090000,
        p50LatencyMs: 0.24,
        p95LatencyMs: 0.58,
        p99LatencyMs: 0.91,
        cpuUsagePct: 84,
        memoryMb: 118
      },
      {
        server: 'Nginx 1.27 (epoll + reuseport)',
        rps: 865000,
        p50LatencyMs: 0.31,
        p95LatencyMs: 0.79,
        p99LatencyMs: 1.48,
        cpuUsagePct: 96,
        memoryMb: 94
      }
    ]
  },
  {
    id: 'bench-h2',
    name: 'Kịch bản 2: Đa luồng khung HTTP/2 trên nền TLS 1.3 (AES-GCM)',
    protocol: 'HTTP/2 TLS 1.3 Multiplexing',
    tool: 'h2load',
    concurrency: '16 Threads · 500 Clients · 100 Concurrent Streams/Client (50,000 Active Streams)',
    command: `# Đo kiểm HTTP/2 Multiplexing với 100 streams đồng thời trên mỗi kết nối TLS 1.3
h2load -n 10000000 -c 500 -m 100 -t 16 --warm-up-time=5s https://127.0.0.1:8443/api/v1/payments`,
    metrics: [
      {
        server: 'FerrousX (Rust + io_uring)',
        rps: 942000,
        p50LatencyMs: 0.38,
        p95LatencyMs: 0.74,
        p99LatencyMs: 1.12,
        cpuUsagePct: 74,
        memoryMb: 68
      },
      {
        server: 'LiteSpeed Enterprise 6.3',
        rps: 760000,
        p50LatencyMs: 0.51,
        p95LatencyMs: 1.15,
        p99LatencyMs: 1.89,
        cpuUsagePct: 89,
        memoryMb: 164
      },
      {
        server: 'Nginx 1.27 (epoll + reuseport)',
        rps: 584000,
        p50LatencyMs: 0.69,
        p95LatencyMs: 1.68,
        p99LatencyMs: 2.94,
        cpuUsagePct: 99,
        memoryMb: 152
      }
    ]
  },
  {
    id: 'bench-h3',
    name: 'Kịch bản 3: HTTP/3 over QUIC + UDP GRO/GSO (Mạng có 1% Packet Loss)',
    protocol: 'HTTP/3 QUIC + UDP GRO/GSO',
    tool: 'h2load (QUIC/H3) + qlog',
    concurrency: '16 Threads · 1,000 QUIC Connections · 64 Streams/Conn · netem 1% loss',
    command: `# Đo kiểm HTTP/3 (QUIC) bằng h2load (bản biên dịch ngtcp2/nghttp3) kèm xuất vết qlog
QLOGDIR=./qlog_traces h2load --npn-list=h3 -n 5000000 -c 1000 -m 64 -t 16 https://127.0.0.1:8443/api/v1/payments`,
    metrics: [
      {
        server: 'FerrousX (Rust + io_uring)',
        rps: 785000,
        p50LatencyMs: 0.45,
        p95LatencyMs: 0.88,
        p99LatencyMs: 1.34,
        cpuUsagePct: 76,
        memoryMb: 84
      },
      {
        server: 'LiteSpeed Enterprise 6.3',
        rps: 642000,
        p50LatencyMs: 0.59,
        p95LatencyMs: 1.32,
        p99LatencyMs: 2.15,
        cpuUsagePct: 91,
        memoryMb: 210
      },
      {
        server: 'Nginx 1.27 (epoll + reuseport)',
        rps: 398000,
        p50LatencyMs: 0.98,
        p95LatencyMs: 2.65,
        p99LatencyMs: 4.82,
        cpuUsagePct: 100,
        memoryMb: 195
      }
    ]
  }
];
