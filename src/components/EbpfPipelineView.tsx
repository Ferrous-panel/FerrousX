import React, { useState } from 'react';
import {
  Play,
  ShieldAlert,
  Cpu,
  Network,
  ArrowRight,
  Check,
  Copy,
  RefreshCw,
  Layers,
  Zap
} from 'lucide-react';

export type TrafficScenarioId = 'quic_migration' | 'tcp_locality' | 'xdp_ddos_drop';

export interface PipelineStageNode {
  id: string;
  stepNumber: string;
  title: string;
  subtitle: string;
  executionContext: 'NIC Hardware DMA' | 'Driver NAPI (Pre-skb)' | 'BPF Kernel Space' | 'Socket Layer' | 'User Space (Pinned Core)';
  kernelStruct: string;
  bpfHelpers: string[];
  latencyNs: number;
  description: string;
  rustEbpfCode: string;
}

const PIPELINE_STAGES: PipelineStageNode[] = [
  {
    id: 'stage-nic-rss',
    stepNumber: 'Chặng 01',
    title: 'NIC RX Ring Buffer & RSS Hardware Hash',
    subtitle: 'DMA ghi thẳng khung Ethernet vào Ring Buffer và kích hoạt NAPI SoftIRQ',
    executionContext: 'NIC Hardware DMA',
    kernelStruct: 'struct rx_ring_desc / DMA Page Pool',
    bpfHelpers: ['Toeplitz 4-Tuple Hash', 'NIC IRQ Affinity', 'Page Pool DMA Sync'],
    latencyNs: 45,
    description:
      'Card mạng nhận khung tin vật lý và dùng hàm băm phần cứng RSS (Receive Side Scaling) để chọn hàng đợi RX Queue tương ứng với lõi CPU. Tại thời điểm này, nhân Linux CHƯA cấp phát cấu trúc sk_buff nặng nề mà chỉ đặt gói tin trong trang bộ nhớ DMA Page Pool.',
    rustEbpfCode: `// Cấu hình hàng đợi phần cứng NIC gắn chặt với từng lõi CPU (IRQ Pinning)
// Mỗi RX Queue #N phát ngắt NAPI trực tiếp lên CPU Core #N:
// ethtool -L eth0 combined 4
// ethtool -X eth0 equal 4`
  },
  {
    id: 'stage-xdp-drv',
    stepNumber: 'Chặng 02',
    title: 'XDP Driver Hook (BPF_PROG_TYPE_XDP)',
    subtitle: 'Lọc gói tin DDoS / kiểm tra tính hợp lệ ngay tại trình điều khiển trước khi tạo sk_buff',
    executionContext: 'Driver NAPI (Pre-skb)',
    kernelStruct: 'struct xdp_md { data, data_end, ingress_ifindex, rx_queue_index }',
    bpfHelpers: ['bpf_map_lookup_elem()', 'bpf_xdp_adjust_meta()', 'XDP_PASS / XDP_DROP'],
    latencyNs: 28,
    description:
      'Chương trình eBPF XDP chạy ngay trong trình điều khiển card mạng (Native XDP_DRV). Nó kiểm tra con trỏ biên (data + offset <= data_end) theo yêu cầu của eBPF Verifier, tra cứu bảng băm BPF_MAP_TYPE_LRU_PERCPU_HASH để chặn tức thì các cuộc tấn công SYN Flood / UDP Amplification bằng phán quyết XDP_DROP trong 28ns mà không tốn 1 byte cấp phát sk_buff nào.',
    rustEbpfCode: `#[xdp]
pub fn ferrousx_xdp_ingress(ctx: XdpContext) -> u32 {
    match try_xdp_inspect(&ctx) {
        Ok(verdict) => verdict,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn try_xdp_inspect(ctx: &XdpContext) -> Result<u32, ()> {
    let eth_hdr: *const EthHdr = ptr_at(ctx, 0)?;
    if unsafe { (*eth_hdr).ether_type } != u16::from_be(0x0800) {
        return Ok(xdp_action::XDP_PASS);
    }
    let ipv4_hdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let src_ip = u32::from_be(unsafe { (*ipv4_hdr).src_addr });

    // Tra cứu danh sách chặn DDoS trên Per-CPU Map (0 Lock Contention)
    if unsafe { BLOCKLIST_MAP.get(&src_ip).is_some() } {
        return Ok(xdp_action::XDP_DROP); // Hủy gói tin ngay tại Driver NIC
    }
    Ok(xdp_action::XDP_PASS)
}`
  },
  {
    id: 'stage-bpf-maps',
    stepNumber: 'Chặng 03',
    title: 'eBPF Shared Maps (REUSEPORT_SOCKARRAY & PERCPU_STATS)',
    subtitle: 'Ánh xạ danh sách Socket FD của từng Worker Core trong không gian nhân',
    executionContext: 'BPF Kernel Space',
    kernelStruct: 'BPF_MAP_TYPE_REUSEPORT_SOCKARRAY / BPF_MAP_TYPE_PERCPU_ARRAY',
    bpfHelpers: ['bpf_map_update_elem()', 'bpf_get_smp_processor_id()'],
    latencyNs: 18,
    description:
      'Khi các luồng Worker của FerrousX khởi động và ghim vào từng lõi CPU, chúng đăng ký RawFd của socket TCP/UDP (đã bật SO_REUSEPORT) vào bản đồ eBPF REUSEPORT_SOCKARRAY theo chỉ số core_id (0..N-1). Nhờ đó, tầng nhân có bảng tra cứu O(1) từ chỉ số Worker sang đúng cấu trúc struct sock đích.',
    rustEbpfCode: `#[map]
static WORKER_SOCK_MAP: ReusePortSockArray =
    ReusePortSockArray::with_max_entries(64, 0);

#[map]
static CORE_TELEMETRY: PerCpuArray<WorkerMetrics> =
    PerCpuArray::with_max_entries(1, 0);`
  },
  {
    id: 'stage-sk-reuseport',
    stepNumber: 'Chặng 04',
    title: 'SO_REUSEPORT eBPF Selector (BPF_PROG_TYPE_SK_REUSEPORT)',
    subtitle: 'Định tuyến theo QUIC Connection ID (DCID) hoặc CPU Core Affinity (SKF_AD_CPU)',
    executionContext: 'Socket Layer',
    kernelStruct: 'struct sk_reuseport_md { data, data_end, ip_protocol, hash }',
    bpfHelpers: ['bpf_sk_select_reuseport()', 'bpf_skb_load_bytes()', 'bpf_get_smp_processor_id()'],
    latencyNs: 35,
    description:
      'Khi gói tin đi qua XDP_PASS lên tầng Transport, chương trình sk_reuseport quyết định socket của Worker nào sẽ nhận gói tin: (1) Nếu là UDP/QUIC (HTTP/3): trích xuất byte đầu tiên của QUIC Destination Connection ID (DCID) chứa mã Worker ID để giữ kết nối trên cùng lõi ngay cả khi Client đổi IP từ Wi-Fi sang 5G; (2) Nếu là TCP (HTTP/1.1 & HTTP/2): lấy trực tiếp bpf_get_smp_processor_id() để giao cho Worker nằm trên chính lõi CPU đang chạy softirq.',
    rustEbpfCode: `#[sk_reuseport]
pub fn ferrousx_reuseport_selector(ctx: SkReuseportContext) -> u32 {
    let num_workers = unsafe { *NUM_WORKERS_CONFIG.get(0).unwrap_or(&4) };
    let mut target_core: u32 = unsafe { bpf_get_smp_processor_id() } % num_workers;

    // Nếu là gói tin UDP (IPPROTO_UDP = 17) -> Đọc QUIC DCID byte đầu tiên
    if ctx.ip_protocol() == 17 {
        let mut quic_first_bytes = [0u8; 2];
        // Byte 0: QUIC Flags, Byte 1: Worker Core ID được mã hóa bởi FerrousX
        if ctx.load_bytes(8, &mut quic_first_bytes).is_ok() {
            let encoded_worker = (quic_first_bytes[1] as u32) % num_workers;
            target_core = encoded_worker;
        }
    }

    // Điều hướng gói tin thẳng vào Socket của Worker trên lõi target_core
    match WORKER_SOCK_MAP.select_reuseport(&ctx, target_core, 0) {
        Ok(()) => sk_action::SK_PASS,
        Err(_) => sk_action::SK_PASS, // Fallback an toàn về hash mặc định
    }
}`
  },
  {
    id: 'stage-worker-uring',
    stepNumber: 'Chặng 05',
    title: 'FerrousX Pinned Worker (io_uring SQ/CQ + Bumpalo Arena)',
    subtitle: 'Đọc Zero-Copy qua Fixed Buffers trên cùng lõi CPU với 100% L1/L2 Cache Hit',
    executionContext: 'User Space (Pinned Core)',
    kernelStruct: 'struct io_uring_cqe -> WorkerContext (Core Local)',
    bpfHelpers: ['IORING_OP_RECVMSG', 'UDP_GRO Super-Frame', 'Bumpalo Arena'],
    latencyNs: 95,
    description:
      'Socket đích đánh thức trực tiếp hàng đợi Completion Queue (CQ) của io_uring thuộc về Worker đang ghim cứng trên lõi đó. Vì gói tin chưa từng rời khỏi lõi CPU kể từ lúc rời NIC RX Queue (hoặc được định tuyến cố định theo QUIC DCID), toàn bộ dữ liệu payload vẫn nằm nóng trong bộ nhớ đệm L1d/L2 của CPU, giúp Quinn QUIC / httparse giải mã tức thì.',
    rustEbpfCode: `// Tại User-space (crates/ferrousx-core/src/worker.rs):
// Đăng ký RawFd của socket Worker hiện tại vào WORKER_SOCK_MAP[worker_id]
let sock_fd: RawFd = udp_socket.as_raw_fd();
worker_sock_map.set(worker_id as u32, sock_fd, 0)?;`
  }
];

export const EbpfPipelineView: React.FC = () => {
  const [scenario, setScenario] = useState<TrafficScenarioId>('quic_migration');
  const [selectedStageId, setSelectedStageId] = useState<string>('stage-sk-reuseport');
  const [clientIp, setClientIp] = useState<string>('172.56.21.89 (Mạng 5G Mới)');
  const [clientPort, setClientPort] = useState<number>(58412);
  const [nicRxQueue, setNicRxQueue] = useState<number>(1);
  const [quicDcidWorkerTag, setQuicDcidWorkerTag] = useState<number>(2);
  const [copiedCode, setCopiedCode] = useState<boolean>(false);

  const selectedStage =
    PIPELINE_STAGES.find((s) => s.id === selectedStageId) || PIPELINE_STAGES[3];

  // Compute where the packet lands based on the scenario
  const isDroppedAtXdp = scenario === 'xdp_ddos_drop';
  const targetWorkerCore =
    scenario === 'quic_migration'
      ? quicDcidWorkerTag
      : scenario === 'tcp_locality'
      ? nicRxQueue
      : -1;

  // Simulate switching mobile network (Wi-Fi -> 5G changes IP & Source Port, but preserves QUIC DCID)
  const handleSimulateNetworkRoam = () => {
    const ips = [
      '103.28.36.14 (Wi-Fi Văn phòng)',
      '172.56.21.89 (Mạng 5G Viettel)',
      '27.68.104.202 (Mạng 4G LTE)',
      '14.161.22.91 (Wi-Fi Sân bay)'
    ];
    const nextIp = ips[Math.floor(Math.random() * ips.length)];
    const nextPort = 32000 + Math.floor(Math.random() * 30000);
    const nextQueue = (nicRxQueue + 1) % 4;
    setClientIp(nextIp);
    setClientPort(nextPort);
    setNicRxQueue(nextQueue);
    setScenario('quic_migration');
  };

  const handleCopyStageCode = () => {
    navigator.clipboard.writeText(selectedStage.rustEbpfCode);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  return (
    <div className="space-y-10">
      {/* Section Header */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 pb-6 border-b border-slate-800">
        <div>
          <p className="text-xs font-mono text-amber-400 tracking-wide">
            Luồng Dữ liệu Nhân Linux (eBPF Data-Flow Architecture)
          </p>
          <h2 className="mt-1 text-2xl sm:text-3xl font-bold text-slate-100 tracking-tight text-balance">
            eBPF Traffic Pipeline: Hành trình Gói tin từ NIC qua XDP &amp; SO_REUSEPORT tới Worker
          </h2>
          <p className="mt-2 text-sm text-slate-400 max-w-3xl leading-relaxed">
            Sơ đồ luồng dữ liệu tương tác mô tả cách FerrousX kết hợp <strong>XDP Driver Hook</strong> (<code className="text-slate-200">BPF_PROG_TYPE_XDP</code>) để lọc gói tin ở tốc độ phần cứng trước khi cấp phát <code className="text-slate-200">sk_buff</code>, cùng bộ điều hướng <strong>SO_REUSEPORT eBPF</strong> (<code className="text-slate-200">BPF_PROG_TYPE_SK_REUSEPORT</code>) định tuyến trực tiếp gói tin vào đúng lõi Worker thông qua <code className="text-slate-200">WORKER_SOCK_MAP</code>.
          </p>
        </div>

        {/* Scenario Segmented Selector */}
        <div className="flex flex-wrap items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg self-start shrink-0">
          <button
            onClick={() => setScenario('quic_migration')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
              scenario === 'quic_migration'
                ? 'bg-amber-500 text-slate-950 font-semibold'
                : 'text-slate-400 hover:text-slate-100'
            }`}
          >
            QUIC DCID Steering (HTTP/3)
          </button>
          <button
            onClick={() => setScenario('tcp_locality')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
              scenario === 'tcp_locality'
                ? 'bg-amber-500 text-slate-950 font-semibold'
                : 'text-slate-400 hover:text-slate-100'
            }`}
          >
            TCP CPU Locality (SKF_AD_CPU)
          </button>
          <button
            onClick={() => setScenario('xdp_ddos_drop')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
              scenario === 'xdp_ddos_drop'
                ? 'bg-rose-500 text-slate-950 font-semibold'
                : 'text-slate-400 hover:text-slate-100'
            }`}
          >
            XDP_DROP (Chặn DDoS tại NIC)
          </button>
        </div>
      </div>

      {/* Interactive Packet Header & Routing Control Deck */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
        <div className="lg:col-span-8 grid grid-cols-1 sm:grid-cols-3 gap-4">
          {/* Control 1: NIC Ingress RX Queue */}
          <div className="p-3.5 rounded-lg bg-slate-950/90 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-xs font-mono text-slate-400">
              <span>NIC RX Queue (SoftIRQ CPU):</span>
              <span className="text-amber-400 font-semibold">Queue #{nicRxQueue}</span>
            </div>
            <div className="flex items-center gap-1.5">
              {[0, 1, 2, 3].map((q) => (
                <button
                  key={q}
                  onClick={() => setNicRxQueue(q)}
                  className={`flex-1 py-1 text-xs font-mono rounded border transition-colors ${
                    nicRxQueue === q
                      ? 'bg-amber-500 text-slate-950 border-amber-500 font-bold'
                      : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200'
                  }`}
                >
                  RX#{q}
                </button>
              ))}
            </div>
          </div>

          {/* Control 2: QUIC DCID Embedded Worker ID */}
          <div className="p-3.5 rounded-lg bg-slate-950/90 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-xs font-mono text-slate-400">
              <span>QUIC DCID[1] Worker Tag:</span>
              <span className="text-emerald-400 font-semibold">0x0{quicDcidWorkerTag}</span>
            </div>
            <div className="flex items-center gap-1.5">
              {[0, 1, 2, 3].map((w) => (
                <button
                  key={w}
                  onClick={() => {
                    setQuicDcidWorkerTag(w);
                    setScenario('quic_migration');
                  }}
                  className={`flex-1 py-1 text-xs font-mono rounded border transition-colors ${
                    quicDcidWorkerTag === w
                      ? 'bg-emerald-500 text-slate-950 border-emerald-500 font-bold'
                      : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200'
                  }`}
                >
                  Wkr #{w}
                </button>
              ))}
            </div>
          </div>

          {/* Control 3: Simulated Client 4-Tuple & Connection Migration Button */}
          <div className="p-3.5 rounded-lg bg-slate-950/90 border border-slate-800 space-y-2 flex flex-col justify-between">
            <div className="text-xs font-mono text-slate-300 truncate">
              Src: <span className="text-slate-100">{clientIp.split(' ')[0]}:{clientPort}</span>
            </div>
            <button
              onClick={handleSimulateNetworkRoam}
              className="w-full flex items-center justify-center gap-1.5 py-1.5 px-2.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-amber-300 rounded border border-slate-700 transition-colors whitespace-nowrap shrink-0"
            >
              <RefreshCw className="w-3 h-3" />
              Đổi mạng Wi-Fi -&gt; 5G (Giữ DCID)
            </button>
          </div>
        </div>

        {/* Verdict Summary Box */}
        <div className="lg:col-span-4 p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
          <div className="text-xs font-mono text-slate-400">Phán quyết Định tuyến eBPF:</div>
          {isDroppedAtXdp ? (
            <div className="text-sm font-mono font-bold text-rose-400">
              XDP_DROP tại Driver NIC (28 ns) — 0 sk_buff cấp phát
            </div>
          ) : scenario === 'quic_migration' ? (
            <div className="text-sm font-mono font-bold text-emerald-400">
              XDP_PASS -&gt; SK_PASS -&gt; Worker #{targetWorkerCore} (theo QUIC DCID 0x0{quicDcidWorkerTag})
            </div>
          ) : (
            <div className="text-sm font-mono font-bold text-amber-400">
              XDP_PASS -&gt; SK_PASS -&gt; Worker #{targetWorkerCore} (0-Bounce trên CPU #{nicRxQueue})
            </div>
          )}
          <div className="text-xs text-slate-400 leading-relaxed">
            {isDroppedAtXdp
              ? 'Gói tin tấn công bị hủy ngay trong vòng lặp NAPI RX trước khi chạm vào ngăn xếp TCP/IP.'
              : scenario === 'quic_migration'
              ? `Dù gói tin vào từ RX Queue #${nicRxQueue} với IP/Port mới, eBPF đọc DCID[1]=0x0${quicDcidWorkerTag} và giữ nguyên phiên QUIC ở Worker #${targetWorkerCore}.`
              : `Bộ lọc đọc SKF_AD_CPU=${nicRxQueue} và đẩy thẳng vào socket của Worker #${targetWorkerCore} trên cùng lõi CPU.`}
          </div>
        </div>
      </div>

      {/* Visual SVG Data-Flow Diagram (NIC -> XDP -> eBPF Map -> SO_REUSEPORT -> FerrousX Workers) */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 space-y-4 overflow-x-auto">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-xs font-mono text-slate-300">
            Sơ đồ Luồng Dữ liệu Thời gian thực (Nhấp vào bất kỳ khối nào trong sơ đồ để xem mã nguồn eBPF chi tiết)
          </div>
          <div className="flex items-center gap-4 text-xs font-mono">
            <span className="text-amber-400">● Đường đi Gói tin Hợp lệ (XDP_PASS -&gt; SK_PASS)</span>
            <span className="text-rose-400">■ Chặn sớm tại Driver (XDP_DROP)</span>
          </div>
        </div>

        <svg
          viewBox="0 0 1120 420"
          className="w-full min-w-[920px] h-auto select-none"
          role="img"
          aria-label="Sơ đồ luồng gói tin eBPF từ NIC qua XDP và SO_REUSEPORT tới FerrousX Worker"
        >
          <defs>
            <marker
              id="arrow-active"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#F59E0B" />
            </marker>
            <marker
              id="arrow-emerald"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#10B981" />
            </marker>
            <marker
              id="arrow-drop"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#F43F5E" />
            </marker>
            <marker
              id="arrow-muted"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="5"
              markerHeight="5"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#334155" />
            </marker>
          </defs>

          {/* Zone Boundaries: Hardware | Kernel Space (XDP & Socket) | User Space Workers */}
          <rect
            x="10"
            y="12"
            width="205"
            height="395"
            rx="12"
            fill="#0F172A"
            stroke="#1E293B"
            strokeDasharray="4 4"
          />
          <text x="24" y="36" fill="#94A3B8" fontSize="11" fontFamily="JetBrains Mono, monospace">
            01. NIC HARDWARE (DMA)
          </text>

          <rect
            x="230"
            y="12"
            width="575"
            height="395"
            rx="12"
            fill="#0F172A"
            stroke="#1E293B"
            strokeDasharray="4 4"
          />
          <text x="246" y="36" fill="#F59E0B" fontSize="11" fontFamily="JetBrains Mono, monospace">
            02. LINUX KERNEL EBPF PIPELINE (XDP_DRV + SK_REUSEPORT)
          </text>

          <rect
            x="820"
            y="12"
            width="290"
            height="395"
            rx="12"
            fill="#0F172A"
            stroke="#1E293B"
            strokeDasharray="4 4"
          />
          <text x="836" y="36" fill="#10B981" fontSize="11" fontFamily="JetBrains Mono, monospace">
            03. FERROUSX PINNED WORKERS
          </text>

          {/* --- STAGE 1: NIC RX QUEUES (0..3) --- */}
          {[0, 1, 2, 3].map((q) => {
            const y = 62 + q * 82;
            const isCurrentQueue = nicRxQueue === q;
            return (
              <g
                key={`rx-${q}`}
                onClick={() => {
                  setNicRxQueue(q);
                  setSelectedStageId('stage-nic-rss');
                }}
                className="cursor-pointer"
              >
                <rect
                  x="26"
                  y={y}
                  width="172"
                  height="64"
                  rx="8"
                  fill={isCurrentQueue ? '#1E293B' : '#0B0F17'}
                  stroke={isCurrentQueue ? '#F59E0B' : '#334155'}
                  strokeWidth={isCurrentQueue ? '2' : '1'}
                />
                <text
                  x="40"
                  y={y + 24}
                  fill={isCurrentQueue ? '#F8FAFC' : '#94A3B8'}
                  fontSize="12"
                  fontWeight="600"
                  fontFamily="JetBrains Mono, monospace"
                >
                  NIC RX Queue #{q}
                </text>
                <text
                  x="40"
                  y={y + 44}
                  fill={isCurrentQueue ? '#FBBF24' : '#64748B'}
                  fontSize="10"
                  fontFamily="JetBrains Mono, monospace"
                >
                  IRQ -&gt; CPU Core #{q}
                </text>

                {/* Flow Line from active NIC RX Queue to XDP Hook */}
                <path
                  d={`M 198 ${y + 32} C 225 ${y + 32}, 225 195, 252 195`}
                  fill="none"
                  stroke={isCurrentQueue ? '#F59E0B' : '#1E293B'}
                  strokeWidth={isCurrentQueue ? '2.5' : '1'}
                  markerEnd={isCurrentQueue ? 'url(#arrow-active)' : undefined}
                />
              </g>
            );
          })}

          {/* --- STAGE 2: XDP DRIVER HOOK --- */}
          <g
            onClick={() => setSelectedStageId('stage-xdp-drv')}
            className="cursor-pointer"
          >
            <rect
              x="252"
              y="125"
              width="225"
              height="140"
              rx="10"
              fill={selectedStageId === 'stage-xdp-drv' ? '#1E293B' : '#0B0F17'}
              stroke={
                isDroppedAtXdp
                  ? '#F43F5E'
                  : selectedStageId === 'stage-xdp-drv'
                  ? '#F59E0B'
                  : '#475569'
              }
              strokeWidth="2"
            />
            <text
              x="268"
              y="152"
              fill="#F59E0B"
              fontSize="11"
              fontWeight="600"
              fontFamily="JetBrains Mono, monospace"
            >
              BPF_PROG_TYPE_XDP
            </text>
            <text
              x="268"
              y="174"
              fill="#F8FAFC"
              fontSize="14"
              fontWeight="700"
              fontFamily="Plus Jakarta Sans, sans-serif"
            >
              XDP Native Driver Hook
            </text>
            <text
              x="268"
              y="196"
              fill="#94A3B8"
              fontSize="11"
              fontFamily="JetBrains Mono, monospace"
            >
              ctx: struct xdp_md (Pre-skb)
            </text>
            <text
              x="268"
              y="216"
              fill="#94A3B8"
              fontSize="11"
              fontFamily="JetBrains Mono, monospace"
            >
              1. Kiểm tra biên gói tin L3/L4
            </text>
            <text
              x="268"
              y="234"
              fill="#94A3B8"
              fontSize="11"
              fontFamily="JetBrains Mono, monospace"
            >
              2. Lọc DDoS O(1) (~28 ns)
            </text>
            <text
              x="268"
              y="252"
              fill={isDroppedAtXdp ? '#F43F5E' : '#10B981'}
              fontSize="11"
              fontWeight="600"
              fontFamily="JetBrains Mono, monospace"
            >
              Verdict: {isDroppedAtXdp ? 'XDP_DROP (Blocked)' : 'XDP_PASS (Clean)'}
            </text>
          </g>

          {/* XDP_DROP Sink Box (Bottom of XDP) */}
          <path
            d="M 364 265 L 364 328"
            fill="none"
            stroke={isDroppedAtXdp ? '#F43F5E' : '#334155'}
            strokeWidth={isDroppedAtXdp ? '2.5' : '1.2'}
            strokeDasharray={isDroppedAtXdp ? undefined : '4 4'}
            markerEnd={isDroppedAtXdp ? 'url(#arrow-drop)' : 'url(#arrow-muted)'}
          />
          <rect
            x="264"
            y="334"
            width="200"
            height="54"
            rx="8"
            fill={isDroppedAtXdp ? '#4C0519' : '#0B0F17'}
            stroke={isDroppedAtXdp ? '#F43F5E' : '#334155'}
            strokeWidth={isDroppedAtXdp ? '2' : '1'}
          />
          <text
            x="280"
            y="357"
            fill={isDroppedAtXdp ? '#FDA4AF' : '#64748B'}
            fontSize="11"
            fontWeight="600"
            fontFamily="JetBrains Mono, monospace"
          >
            XDP_DROP Sink (DMA Recycle)
          </text>
          <text
            x="280"
            y="374"
            fill={isDroppedAtXdp ? '#FECDD3' : '#475569'}
            fontSize="10"
            fontFamily="JetBrains Mono, monospace"
          >
            0 sk_buff · 0 CPU Lock
          </text>

          {/* Path from XDP_PASS to SO_REUSEPORT Selector */}
          <path
            d="M 477 195 L 548 195"
            fill="none"
            stroke={!isDroppedAtXdp ? '#F59E0B' : '#334155'}
            strokeWidth={!isDroppedAtXdp ? '2.5' : '1.2'}
            markerEnd={!isDroppedAtXdp ? 'url(#arrow-active)' : 'url(#arrow-muted)'}
          />
          <text
            x="484"
            y="185"
            fill={!isDroppedAtXdp ? '#FBBF24' : '#475569'}
            fontSize="10"
            fontFamily="JetBrains Mono, monospace"
          >
            XDP_PASS
          </text>

          {/* --- STAGE 3: eBPF SHARED MAPS (TOP OF SELECTOR) --- */}
          <g
            onClick={() => setSelectedStageId('stage-bpf-maps')}
            className="cursor-pointer"
          >
            <rect
              x="548"
              y="48"
              width="240"
              height="68"
              rx="8"
              fill={selectedStageId === 'stage-bpf-maps' ? '#1E293B' : '#0B0F17'}
              stroke={selectedStageId === 'stage-bpf-maps' ? '#F59E0B' : '#334155'}
              strokeWidth="1.5"
            />
            <text
              x="562"
              y="70"
              fill="#FBBF24"
              fontSize="11"
              fontWeight="600"
              fontFamily="JetBrains Mono, monospace"
            >
              WORKER_SOCK_MAP (eBPF Map)
            </text>
            <text
              x="562"
              y="88"
              fill="#CBD5E1"
              fontSize="10"
              fontFamily="JetBrains Mono, monospace"
            >
              BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
            </text>
            <text
              x="562"
              y="104"
              fill="#94A3B8"
              fontSize="10"
              fontFamily="JetBrains Mono, monospace"
            >
              [0:fd#9, 1:fd#10, 2:fd#11, 3:fd#12]
            </text>
          </g>

          {/* Bi-directional lookup line between Map and Selector */}
          <path
            d="M 668 116 L 668 138"
            fill="none"
            stroke="#F59E0B"
            strokeWidth="1.5"
            strokeDasharray="3 3"
          />

          {/* --- STAGE 4: SO_REUSEPORT eBPF SELECTOR --- */}
          <g
            onClick={() => setSelectedStageId('stage-sk-reuseport')}
            className="cursor-pointer"
          >
            <rect
              x="548"
              y="138"
              width="240"
              height="145"
              rx="10"
              fill={selectedStageId === 'stage-sk-reuseport' ? '#1E293B' : '#0B0F17'}
              stroke={selectedStageId === 'stage-sk-reuseport' ? '#F59E0B' : '#475569'}
              strokeWidth="2"
            />
            <text
              x="564"
              y="163"
              fill="#F59E0B"
              fontSize="11"
              fontWeight="600"
              fontFamily="JetBrains Mono, monospace"
            >
              BPF_PROG_TYPE_SK_REUSEPORT
            </text>
            <text
              x="564"
              y="184"
              fill="#F8FAFC"
              fontSize="14"
              fontWeight="700"
              fontFamily="Plus Jakarta Sans, sans-serif"
            >
              SO_REUSEPORT Steering
            </text>
            <text
              x="564"
              y="205"
              fill="#CBD5E1"
              fontSize="11"
              fontFamily="JetBrains Mono, monospace"
            >
              {scenario === 'quic_migration'
                ? `QUIC DCID[1] -> Core #${quicDcidWorkerTag}`
                : `SKF_AD_CPU -> Core #${nicRxQueue}`}
            </text>
            <text
              x="564"
              y="225"
              fill="#94A3B8"
              fontSize="10"
              fontFamily="JetBrains Mono, monospace"
            >
              bpf_sk_select_reuseport(ctx, map,
            </text>
            <text
              x="564"
              y="241"
              fill="#10B981"
              fontSize="10"
              fontWeight="600"
              fontFamily="JetBrains Mono, monospace"
            >
              {`  key = ${targetWorkerCore >= 0 ? targetWorkerCore : 0}, flags = 0)`}
            </text>
            <text
              x="564"
              y="265"
              fill="#94A3B8"
              fontSize="10"
              fontFamily="JetBrains Mono, monospace"
            >
              Zero Accept-Queue Lock Contention
            </text>
          </g>

          {/* --- STAGE 5: FERROUSX PINNED WORKERS (0..3) --- */}
          {[0, 1, 2, 3].map((w) => {
            const y = 62 + w * 82;
            const isTarget = !isDroppedAtXdp && targetWorkerCore === w;
            return (
              <g
                key={`worker-${w}`}
                onClick={() => setSelectedStageId('stage-worker-uring')}
                className="cursor-pointer"
              >
                {/* Steering curve from sk_reuseport to Worker #w */}
                <path
                  d={`M 788 210 C 815 210, 810 ${y + 32}, 836 ${y + 32}`}
                  fill="none"
                  stroke={isTarget ? '#10B981' : '#1E293B'}
                  strokeWidth={isTarget ? '2.8' : '1'}
                  markerEnd={isTarget ? 'url(#arrow-emerald)' : undefined}
                />

                <rect
                  x="836"
                  y={y}
                  width="258"
                  height="64"
                  rx="8"
                  fill={isTarget ? '#064E3B' : '#0B0F17'}
                  stroke={isTarget ? '#10B981' : '#334155'}
                  strokeWidth={isTarget ? '2' : '1'}
                />
                <text
                  x="852"
                  y={y + 24}
                  fill={isTarget ? '#ECFDF5' : '#94A3B8'}
                  fontSize="12"
                  fontWeight="700"
                  fontFamily="JetBrains Mono, monospace"
                >
                  FerrousX Worker #{w} (Core #{w})
                </text>
                <text
                  x="852"
                  y={y + 44}
                  fill={isTarget ? '#6EE7B7' : '#64748B'}
                  fontSize="10"
                  fontFamily="JetBrains Mono, monospace"
                >
                  io_uring SQ/CQ · Bumpalo Arena · {isTarget ? 'ACTIVE' : 'IDLE'}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Stage Deep-Dive Inspector + Rust Aya eBPF Code */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left 5 Cols: Stage Selector & Kernel Context Details */}
        <div className="lg:col-span-5 space-y-4">
          <div className="text-xs font-mono text-slate-400">
            Chọn từng chặng trong Pipeline để kiểm tra cấu trúc Kernel &amp; mã nguồn eBPF:
          </div>
          <div className="space-y-2">
            {PIPELINE_STAGES.map((stg) => {
              const active = stg.id === selectedStageId;
              return (
                <button
                  key={stg.id}
                  onClick={() => setSelectedStageId(stg.id)}
                  className={`w-full text-left p-3.5 rounded-xl border transition-colors ${
                    active
                      ? 'bg-slate-900 border-amber-500/80'
                      : 'bg-slate-900/40 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-mono font-semibold text-amber-400">
                      {stg.stepNumber} · {stg.executionContext}
                    </span>
                    <span className="text-xs font-mono text-emerald-400 tabular-nums">
                      ~{stg.latencyNs} ns
                    </span>
                  </div>
                  <div className="mt-1 text-sm font-bold text-slate-100">{stg.title}</div>
                  <div className="mt-0.5 text-xs text-slate-400">{stg.subtitle}</div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Right 7 Cols: Selected Stage Technical Breakdown & Rust eBPF Code */}
        <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="p-5 border-b border-slate-800 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
              <span className="text-amber-400 font-semibold">
                {selectedStage.stepNumber} · {selectedStage.executionContext}
              </span>
              <span className="text-slate-400">
                Kernel Struct: <code className="text-slate-200">{selectedStage.kernelStruct}</code>
              </span>
            </div>

            <h3 className="text-lg font-bold text-slate-100">{selectedStage.title}</h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              {selectedStage.description}
            </p>

            <div className="pt-2 flex flex-wrap items-center gap-2 text-xs font-mono text-slate-400">
              <span>BPF Helpers / Primitives:</span>
              {selectedStage.bpfHelpers.map((h, idx) => (
                <React.Fragment key={h}>
                  <span className="text-amber-300">{h}</span>
                  {idx < selectedStage.bpfHelpers.length - 1 && <span>·</span>}
                </React.Fragment>
              ))}
            </div>
          </div>

          {/* Code Header */}
          <div className="flex items-center justify-between px-4 py-2.5 bg-slate-950 border-b border-slate-800">
            <span className="text-xs font-mono text-slate-300">
              Triển khai Rust eBPF (Aya #![no_std] Kernel Program)
            </span>
            <button
              onClick={handleCopyStageCode}
              className="flex items-center gap-1.5 px-3 py-1 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              {copiedCode ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  Đã sao chép
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  Sao chép đoạn mã
                </>
              )}
            </button>
          </div>

          <pre className="p-5 text-xs font-mono text-slate-100 overflow-x-auto leading-relaxed bg-slate-950/60">
            {selectedStage.rustEbpfCode}
          </pre>
        </div>
      </div>
    </div>
  );
};
