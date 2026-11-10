import React, { useState } from 'react';
import { Play, RotateCcw, RefreshCw, ArrowUpRight, Cpu, Layers, Zap } from 'lucide-react';

interface CoreWorkerState {
  coreId: number;
  sqRingUsed: number;
  cqRingReady: number;
  arenaUsedBytes: number;
  arenaCapacityBytes: number;
  configEpochRead: number;
  inFlightRequests: number;
  completedRequests: number;
  lastQuicDcid: string;
}

export const InteractiveSimView: React.FC = () => {
  const [ioEngine, setIoEngine] = useState<'io_uring_sqpoll' | 'legacy_epoll'>('io_uring_sqpoll');
  const [protocolMode, setProtocolMode] = useState<'h3_quic_gro' | 'h2_tls13' | 'h1_keepalive'>('h3_quic_gro');
  const [configEpoch, setConfigEpoch] = useState<number>(1);
  const [previousEpochDraining, setPreviousEpochDraining] = useState<number | null>(null);
  const [binaryGeneration, setBinaryGeneration] = useState<number>(1);
  const [udsTransferLog, setUdsTransferLog] = useState<string>(
    'Sẵn sàng: Tiến trình PID 4102 đang nắm giữ fd=3 (TCP :8443) và fd=4 (UDP :8443)'
  );

  const [cores, setCores] = useState<CoreWorkerState[]>([
    {
      coreId: 0,
      sqRingUsed: 12,
      cqRingReady: 12,
      arenaUsedBytes: 14336,
      arenaCapacityBytes: 65536,
      configEpochRead: 1,
      inFlightRequests: 18,
      completedRequests: 1420,
      lastQuicDcid: '0x00_9f4a2c11'
    },
    {
      coreId: 1,
      sqRingUsed: 16,
      cqRingReady: 15,
      arenaUsedBytes: 18432,
      arenaCapacityBytes: 65536,
      configEpochRead: 1,
      inFlightRequests: 22,
      completedRequests: 1580,
      lastQuicDcid: '0x01_7b81d04e'
    },
    {
      coreId: 2,
      sqRingUsed: 10,
      cqRingReady: 10,
      arenaUsedBytes: 11264,
      arenaCapacityBytes: 65536,
      configEpochRead: 1,
      inFlightRequests: 14,
      completedRequests: 1390,
      lastQuicDcid: '0x02_3c90e82a'
    },
    {
      coreId: 3,
      sqRingUsed: 14,
      cqRingReady: 14,
      arenaUsedBytes: 16384,
      arenaCapacityBytes: 65536,
      configEpochRead: 1,
      inFlightRequests: 19,
      completedRequests: 1510,
      lastQuicDcid: '0x03_5a12f79b'
    }
  ]);

  // Simulate dispatching a batch of incoming packets through eBPF sk_reuseport -> Pinned Core
  const handleDispatchPacketBatch = () => {
    setCores((prev) =>
      prev.map((c) => {
        const addedReqs = protocolMode === 'h3_quic_gro' ? 32 : 16;
        const addedArena = addedReqs * 384; // Zero-heap bump allocation (~384B per request ctx)
        const nextArena =
          c.arenaUsedBytes + addedArena >= c.arenaCapacityBytes
            ? addedArena
            : c.arenaUsedBytes + addedArena;
        const randomHex = Math.floor(Math.random() * 0xffffffff)
          .toString(16)
          .padStart(8, '0');

        return {
          ...c,
          sqRingUsed: Math.min(64, ((c.sqRingUsed + 8) % 48) + 8),
          cqRingReady: Math.min(64, ((c.cqRingReady + 8) % 48) + 8),
          arenaUsedBytes: nextArena,
          configEpochRead: configEpoch,
          inFlightRequests: addedReqs,
          completedRequests: c.completedRequests + addedReqs,
          lastQuicDcid: `0x0${c.coreId}_${randomHex}`
        };
      })
    );
    setPreviousEpochDraining(null);
  };

  // Reset Bumpalo Arena pointers in O(1) (1 CPU instruction per core)
  const handleResetAllArenas = () => {
    setCores((prev) =>
      prev.map((c) => ({
        ...c,
        sqRingUsed: 0,
        cqRingReady: 0,
        arenaUsedBytes: 0,
        inFlightRequests: 0
      }))
    );
  };

  // Simulate SIGHUP Lock-Free ArcSwap atomic pointer swap
  const handleTriggerArcSwapReload = () => {
    const oldEpoch = configEpoch;
    const nextEpoch = oldEpoch + 1;
    setPreviousEpochDraining(oldEpoch);
    setConfigEpoch(nextEpoch);

    // Cores 0 and 2 pick up new epoch immediately; Cores 1 and 3 finish draining old epoch
    setCores((prev) =>
      prev.map((c, idx) => ({
        ...c,
        configEpochRead: idx % 2 === 0 ? nextEpoch : oldEpoch
      }))
    );
  };

  // Simulate SIGUSR2 Unix Domain Socket SCM_RIGHTS FD Handoff
  const handleTriggerUdsUpgrade = () => {
    const nextGen = binaryGeneration + 1;
    const oldPid = 4000 + binaryGeneration * 102;
    const newPid = 4000 + nextGen * 102;
    setBinaryGeneration(nextGen);
    setUdsTransferLog(
      `[SCM_RIGHTS Handoff Thành công] Tiến trình cũ (PID ${oldPid}) đã truyền nguyên vẹn 8 RawFd (SO_REUSEPORT TCP/UDP) qua /run/ferrousx.sock sang Tiến trình mới (PID ${newPid}) — 0 gói SYN/QUIC bị rớt.`
    );
  };

  const syscallsPerBatch = ioEngine === 'io_uring_sqpoll' ? 0 : 96;
  const heapMallocsPerReq = ioEngine === 'io_uring_sqpoll' ? 0 : 14;
  const crossCoreLocks = ioEngine === 'io_uring_sqpoll' ? 0 : 32;
  const p99LatencyUs =
    ioEngine === 'io_uring_sqpoll'
      ? protocolMode === 'h3_quic_gro'
        ? 340
        : 290
      : 1480;

  return (
    <div className="space-y-10">
      {/* Section Header */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 pb-6 border-b border-slate-800">
        <div>
          <p className="text-xs font-mono text-amber-400 tracking-wide">
            Mô phỏng Thực thi Tương tác (Interactive Systems Sandbox)
          </p>
          <h2 className="mt-1 text-2xl sm:text-3xl font-bold text-slate-100 tracking-tight text-balance">
            Mô phỏng Hàng đợi Vòng io_uring, Bumpalo Arena &amp; Hoán đổi Nguyên tử ArcSwap
          </h2>
          <p className="mt-2 text-sm text-slate-400 max-w-3xl leading-relaxed">
            Thử nghiệm trực tiếp cách FerrousX định tuyến gói tin vào từng lõi CPU qua bộ lọc <code className="text-slate-200">cBPF/eBPF</code>, cấp phát bộ nhớ tuần tự trên <code className="text-slate-200">Bumpalo Arena</code> không chạm vào Heap, và nạp lại cấu hình không khóa bằng <code className="text-slate-200">ArcSwap</code>.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            onClick={handleDispatchPacketBatch}
            className="flex items-center gap-2 px-4 py-2 text-xs font-semibold bg-amber-500 hover:bg-amber-400 text-slate-950 rounded-lg transition-colors whitespace-nowrap shrink-0"
          >
            <Play className="w-3.5 h-3.5" />
            Đẩy Lô Gói Tin Mới (Batch I/O)
          </button>
          <button
            onClick={handleResetAllArenas}
            className="flex items-center gap-2 px-3.5 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 rounded-lg transition-colors whitespace-nowrap shrink-0"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Bump::reset() (0ns Free)
          </button>
        </div>
      </div>

      {/* Control Strip & Comparative Telemetry */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Left 6 Cols: Engine & Protocol Selectors */}
        <div className="lg:col-span-6 bg-slate-900/70 border border-slate-800 rounded-xl p-5 space-y-5">
          <div className="space-y-2">
            <label className="text-xs font-mono text-slate-400 block">
              1. Chọn Kiến trúc I/O &amp; Bộ nhớ (So sánh trực diện):
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              <button
                onClick={() => setIoEngine('io_uring_sqpoll')}
                className={`p-3 rounded-lg border text-left transition-colors ${
                  ioEngine === 'io_uring_sqpoll'
                    ? 'bg-amber-500/15 border-amber-500 text-slate-100'
                    : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                <div className="text-xs font-semibold text-amber-400">
                  FerrousX (io_uring + SQPOLL)
                </div>
                <div className="mt-1 text-[11px] font-mono text-slate-300">
                  Shared Ring · Fixed Buffers · Bumpalo
                </div>
              </button>

              <button
                onClick={() => setIoEngine('legacy_epoll')}
                className={`p-3 rounded-lg border text-left transition-colors ${
                  ioEngine === 'legacy_epoll'
                    ? 'bg-amber-500/15 border-amber-500 text-slate-100'
                    : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                <div className="text-xs font-semibold text-slate-200">
                  Kiến trúc Cũ (epoll + Heap Pool)
                </div>
                <div className="mt-1 text-[11px] font-mono text-slate-400">
                  epoll_wait syscall · Shm Mutex · malloc
                </div>
              </button>
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-xs font-mono text-slate-400 block">
              2. Giao thức Truyền tải &amp; Tăng tốc Phần cứng:
            </label>
            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => setProtocolMode('h3_quic_gro')}
                className={`px-3 py-1.5 text-xs font-mono rounded-md border transition-colors whitespace-nowrap shrink-0 ${
                  protocolMode === 'h3_quic_gro'
                    ? 'bg-amber-500 text-slate-950 font-semibold border-amber-500'
                    : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
                }`}
              >
                HTTP/3 QUIC + UDP GRO (64KB Super-Packet)
              </button>
              <button
                onClick={() => setProtocolMode('h2_tls13')}
                className={`px-3 py-1.5 text-xs font-mono rounded-md border transition-colors whitespace-nowrap shrink-0 ${
                  protocolMode === 'h2_tls13'
                    ? 'bg-amber-500 text-slate-950 font-semibold border-amber-500'
                    : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
                }`}
              >
                HTTP/2 TLS 1.3 (rustls AES-NI)
              </button>
              <button
                onClick={() => setProtocolMode('h1_keepalive')}
                className={`px-3 py-1.5 text-xs font-mono rounded-md border transition-colors whitespace-nowrap shrink-0 ${
                  protocolMode === 'h1_keepalive'
                    ? 'bg-amber-500 text-slate-950 font-semibold border-amber-500'
                    : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
                }`}
              >
                HTTP/1.1 Keep-Alive (SIMD httparse)
              </button>
            </div>
          </div>
        </div>

        {/* Right 6 Cols: Real-time Measured Architectural Telemetry */}
        <div className="lg:col-span-6 bg-slate-900/70 border border-slate-800 rounded-xl p-5 grid grid-cols-2 sm:grid-cols-4 gap-4 items-center">
          <div className="p-3 bg-slate-950/80 border border-slate-800/80 rounded-lg">
            <div className="text-[11px] font-mono text-slate-400">Syscalls / Lô I/O</div>
            <div
              className={`mt-1 text-2xl font-bold font-mono tabular-nums ${
                syscallsPerBatch === 0 ? 'text-emerald-400' : 'text-rose-400'
              }`}
            >
              {syscallsPerBatch}
            </div>
            <div className="mt-1 text-[11px] text-slate-400">
              {syscallsPerBatch === 0 ? 'SQPOLL Kernel Thread' : 'epoll_wait + read/write'}
            </div>
          </div>

          <div className="p-3 bg-slate-950/80 border border-slate-800/80 rounded-lg">
            <div className="text-[11px] font-mono text-slate-400">Heap Malloc / Req</div>
            <div
              className={`mt-1 text-2xl font-bold font-mono tabular-nums ${
                heapMallocsPerReq === 0 ? 'text-emerald-400' : 'text-rose-400'
              }`}
            >
              {heapMallocsPerReq}
            </div>
            <div className="mt-1 text-[11px] text-slate-400">
              {heapMallocsPerReq === 0 ? '100% Bumpalo Arena' : 'Cấp phát trên Heap'}
            </div>
          </div>

          <div className="p-3 bg-slate-950/80 border border-slate-800/80 rounded-lg">
            <div className="text-[11px] font-mono text-slate-400">Tranh chấp Khóa</div>
            <div
              className={`mt-1 text-2xl font-bold font-mono tabular-nums ${
                crossCoreLocks === 0 ? 'text-emerald-400' : 'text-rose-400'
              }`}
            >
              {crossCoreLocks}
            </div>
            <div className="mt-1 text-[11px] text-slate-400">
              {crossCoreLocks === 0 ? 'Shared-Nothing Core' : 'Mutex / RwLock Wait'}
            </div>
          </div>

          <div className="p-3 bg-slate-950/80 border border-slate-800/80 rounded-lg">
            <div className="text-[11px] font-mono text-slate-400">Độ trễ P99 Ước tính</div>
            <div className="mt-1 text-2xl font-bold font-mono tabular-nums text-amber-400">
              {p99LatencyUs} µs
            </div>
            <div className="mt-1 text-[11px] text-slate-400">
              {(p99LatencyUs / 1000).toFixed(2)} ms toàn trình
            </div>
          </div>
        </div>
      </div>

      {/* 4 Pinned CPU Core Workers Visualizer */}
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-base font-bold text-slate-100">
            Trạng thái Thời gian thực của Cụm Worker Thread-Per-Core (Ghim cứng core_affinity)
          </h3>
          <span className="text-xs font-mono text-slate-400">
            Bộ lọc nhân: SO_ATTACH_REUSEPORT_CBPF (SKF_AD_CPU % 4) · QUIC DCID Prefix Routing
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-5">
          {cores.map((core) => {
            const arenaPct = Math.round((core.arenaUsedBytes / core.arenaCapacityBytes) * 100);
            return (
              <div
                key={core.coreId}
                className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 space-y-4"
              >
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div>
                    <span className="text-xs font-mono font-semibold text-amber-400">
                      ferrousx-wkr-0{core.coreId}
                    </span>
                    <h4 className="text-sm font-bold text-slate-100">
                      Pinned CPU Core #{core.coreId}
                    </h4>
                  </div>
                  <span className="text-xs font-mono text-emerald-400 tabular-nums">
                    ArcSwap v{core.configEpochRead}
                  </span>
                </div>

                {/* io_uring SQ & CQ Ring Status */}
                <div className="space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between text-slate-300">
                    <span>io_uring SQ / CQ Ring:</span>
                    <span className="tabular-nums text-amber-300">
                      SQ:{core.sqRingUsed} · CQ:{core.cqRingReady} / 4096
                    </span>
                  </div>
                  <div className="w-full h-2 bg-slate-950 rounded-full overflow-hidden border border-slate-800">
                    <div
                      className="h-full bg-amber-500 transition-transform duration-150 origin-left"
                      style={{ transform: `scaleX(${Math.max(0.05, core.sqRingUsed / 64)})` }}
                    />
                  </div>
                </div>

                {/* Bumpalo Arena Linear Memory Bar */}
                <div className="space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between text-slate-300">
                    <span>Bumpalo Arena (L1d):</span>
                    <span className="tabular-nums text-emerald-400">
                      {(core.arenaUsedBytes / 1024).toFixed(1)} / 64.0 KiB ({arenaPct}%)
                    </span>
                  </div>
                  <div className="w-full h-2 bg-slate-950 rounded-full overflow-hidden border border-slate-800">
                    <div
                      className="h-full bg-emerald-500 transition-transform duration-150 origin-left"
                      style={{ transform: `scaleX(${Math.max(0.02, arenaPct / 100)})` }}
                    />
                  </div>
                </div>

                {/* Core Local Telemetry */}
                <div className="pt-2 border-t border-slate-800/80 space-y-1.5 text-xs font-mono text-slate-400 tabular-nums">
                  <div className="flex justify-between">
                    <span>QUIC DCID Định tuyến:</span>
                    <span className="text-slate-200">{core.lastQuicDcid}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Luồng đang xử lý:</span>
                    <span className="text-slate-200">{core.inFlightRequests} streams</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Tổng Request hoàn tất:</span>
                    <span className="text-emerald-400 font-semibold">
                      {core.completedRequests.toLocaleString()}
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Zero-Downtime Reload (ArcSwap) & UDS FD Passing Lab */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 space-y-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <span className="text-xs font-mono text-amber-400">
              04. Dynamic Configuration Engine &amp; Zero-Downtime Reload
            </span>
            <h3 className="mt-1 text-lg font-bold text-slate-100">
              Kiểm chứng Hoán đổi Con trỏ Nguyên tử (ArcSwap) &amp; Nâng cấp Binary (SCM_RIGHTS)
            </h3>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={handleTriggerArcSwapReload}
              className="flex items-center gap-2 px-4 py-2 text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 text-slate-950 rounded-lg transition-colors whitespace-nowrap shrink-0"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Gửi SIGHUP (ArcSwap Hot-Reload)
            </button>
            <button
              onClick={handleTriggerUdsUpgrade}
              className="flex items-center gap-2 px-4 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 rounded-lg transition-colors whitespace-nowrap shrink-0"
            >
              <ArrowUpRight className="w-3.5 h-3.5 text-amber-400" />
              Gửi SIGUSR2 (Chuyển giao FD qua Unix Socket)
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* ArcSwap Pointer Visualization */}
          <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-400">Con trỏ nguyên tử hiện hành:</span>
              <span className="text-emerald-400 font-semibold">
                ArcSwap&lt;ServerConfig&gt; @ Epoch #{configEpoch}
              </span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Khi nhận tín hiệu <code className="text-slate-100">SIGHUP</code>, luồng Control-Plane phân tích cú pháp file cấu hình mới và gọi <code className="text-slate-100">active_config.store(Arc::new(new_cfg))</code>. Các kết nối mới lập tức đọc <strong>Epoch #{configEpoch}</strong>, trong khi các kết nối đang dở dang trên Worker #1 và #3 vẫn giữ <code className="text-slate-100">Guard&lt;Arc&lt;ServerConfig&gt;&gt;</code> của{' '}
              <strong>
                {previousEpochDraining ? `Epoch #${previousEpochDraining} (Đang rút cạn an toàn)` : `Epoch #${configEpoch}`}
              </strong>{' '}
              cho đến khi gửi xong byte cuối cùng. Nhấn <em>&ldquo;Đẩy Lô Gói Tin Mới&rdquo;</em> để đồng bộ tất cả các lõi lên Epoch #{configEpoch}.
            </p>
          </div>

          {/* Unix Domain Socket SCM_RIGHTS Status */}
          <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-400">Thế hệ Binary đang chạy:</span>
              <span className="text-amber-400 font-semibold">
                Generation #{binaryGeneration} (Zero-Loss FD Handoff)
              </span>
            </div>
            <p className="text-xs font-mono text-slate-300 leading-relaxed">
              {udsTransferLog}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
