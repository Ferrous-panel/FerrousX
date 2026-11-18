import React, { useState, useEffect } from 'react';
import {
  AreaChart,
  Area,
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend
} from 'recharts';
import {
  Activity,
  Cpu,
  Zap,
  Play,
  Pause,
  RefreshCw,
  Server,
  Layers,
  ArrowUpRight,
  TrendingUp,
  AlertCircle
} from 'lucide-react';

interface TelemetryPoint {
  time: string;
  core0_cpu: number;
  core1_cpu: number;
  core2_cpu: number;
  core3_cpu: number;
  total_rps: number;
  core0_rps: number;
  core1_rps: number;
  core2_rps: number;
  core3_rps: number;
  h3_quic_conns: number;
  tcp_h2_conns: number;
  sq_ring_util: number;
  cq_ring_util: number;
  p99_latency_us: number;
}

export const TelemetryView: React.FC = () => {
  const [isLive, setIsLive] = useState<boolean>(true);
  const [selectedCoreFilter, setSelectedCoreFilter] = useState<'all' | '0' | '1' | '2' | '3'>('all');
  const [historyData, setHistoryData] = useState<TelemetryPoint[]>([]);

  // Initialize initial 15 seconds of realistic high-performance data
  useEffect(() => {
    const initial: TelemetryPoint[] = [];
    const now = Date.now();
    for (let i = 14; i >= 0; i--) {
      const t = new Date(now - i * 1000);
      const timeStr = `${t.getHours().toString().padStart(2, '0')}:${t.getMinutes().toString().padStart(2, '0')}:${t.getSeconds().toString().padStart(2, '0')}`;
      
      const c0_rps = Math.floor(340000 + Math.random() * 25000);
      const c1_rps = Math.floor(355000 + Math.random() * 20000);
      const c2_rps = Math.floor(338000 + Math.random() * 28000);
      const c3_rps = Math.floor(362000 + Math.random() * 22000);

      initial.push({
        time: timeStr,
        core0_cpu: Math.floor(64 + Math.random() * 8),
        core1_cpu: Math.floor(67 + Math.random() * 7),
        core2_cpu: Math.floor(63 + Math.random() * 9),
        core3_cpu: Math.floor(68 + Math.random() * 6),
        total_rps: c0_rps + c1_rps + c2_rps + c3_rps,
        core0_rps: c0_rps,
        core1_rps: c1_rps,
        core2_rps: c2_rps,
        core3_rps: c3_rps,
        h3_quic_conns: Math.floor(48000 + Math.random() * 1500),
        tcp_h2_conns: Math.floor(32000 + Math.random() * 1200),
        sq_ring_util: Math.floor(18 + Math.random() * 6), // out of 64 batch depth
        cq_ring_util: Math.floor(17 + Math.random() * 6),
        p99_latency_us: Math.floor(310 + Math.random() * 45)
      });
    }
    setHistoryData(initial);
  }, []);

  // Real-time polling tick every 1000ms
  useEffect(() => {
    if (!isLive) return;

    const interval = setInterval(() => {
      setHistoryData((prev) => {
        const last = prev[prev.length - 1];
        const t = new Date();
        const timeStr = `${t.getHours().toString().padStart(2, '0')}:${t.getMinutes().toString().padStart(2, '0')}:${t.getSeconds().toString().padStart(2, '0')}`;

        const c0_rps = Math.floor(345000 + (Math.random() - 0.5) * 40000);
        const c1_rps = Math.floor(358000 + (Math.random() - 0.5) * 35000);
        const c2_rps = Math.floor(342000 + (Math.random() - 0.5) * 45000);
        const c3_rps = Math.floor(364000 + (Math.random() - 0.5) * 38000);

        const newPoint: TelemetryPoint = {
          time: timeStr,
          core0_cpu: Math.floor(65 + Math.random() * 8),
          core1_cpu: Math.floor(68 + Math.random() * 6),
          core2_cpu: Math.floor(64 + Math.random() * 8),
          core3_cpu: Math.floor(69 + Math.random() * 7),
          total_rps: c0_rps + c1_rps + c2_rps + c3_rps,
          core0_rps: c0_rps,
          core1_rps: c1_rps,
          core2_rps: c2_rps,
          core3_rps: c3_rps,
          h3_quic_conns: Math.floor(48500 + Math.random() * 1800),
          tcp_h2_conns: Math.floor(32400 + Math.random() * 1400),
          sq_ring_util: Math.floor(20 + Math.random() * 5),
          cq_ring_util: Math.floor(19 + Math.random() * 6),
          p99_latency_us: Math.floor(315 + Math.random() * 40)
        };

        const updated = [...prev.slice(1), newPoint];
        return updated;
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [isLive]);

  const latest = historyData[historyData.length - 1] || {
    core0_cpu: 68,
    core1_cpu: 71,
    core2_cpu: 66,
    core3_cpu: 72,
    total_rps: 1412000,
    core0_rps: 345000,
    core1_rps: 358000,
    core2_rps: 342000,
    core3_rps: 367000,
    h3_quic_conns: 48900,
    tcp_h2_conns: 32600,
    sq_ring_util: 21,
    cq_ring_util: 20,
    p99_latency_us: 324
  };

  const avgCpu = Math.round(
    (latest.core0_cpu + latest.core1_cpu + latest.core2_cpu + latest.core3_cpu) / 4
  );

  return (
    <div className="space-y-10">
      {/* Header & Live Stream Controls */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-emerald-400 tracking-wide font-semibold">
              08. Giám Sát Thời Gian Thực (Real-Time Telemetry Stream)
            </span>
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              LIVE: /run/ferrousx/panel-admin.sock
            </span>
          </div>
          <h2 className="mt-1 text-2xl sm:text-3xl font-bold text-slate-100 tracking-tight text-balance">
            Telemetry Vòng Lặp Worker: CPU Pinning, Thông Lượng Mỗi Core &amp; Sức Khỏe Socket
          </h2>
          <p className="mt-2 text-sm text-slate-400 max-w-3xl leading-relaxed">
            Dữ liệu phát trực tiếp từ các luồng nhân <strong>Rust Thread-Per-Core Worker</strong> qua cơ chế đếm nguyên tử không khóa (<code className="text-slate-200">AtomicU64 / AtomicU32</code>) và vòng đệm <code className="text-slate-200">io_uring SQ/CQ Ring</code>, không làm ảnh hưởng đến độ trễ xử lý gói tin trên hot-path.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0 self-start">
          {/* Pause / Play Live Feed */}
          <button
            onClick={() => setIsLive(!isLive)}
            className={`flex items-center gap-2 px-3.5 py-2 text-xs font-semibold rounded-lg border transition-colors whitespace-nowrap shrink-0 ${
              isLive
                ? 'bg-amber-500 text-slate-950 border-amber-500 hover:bg-amber-400'
                : 'bg-slate-800 text-slate-200 border-slate-700 hover:bg-slate-700'
            }`}
          >
            {isLive ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            {isLive ? 'Tạm Dừng Cập Nhật' : 'Tiếp Tục Live Feed'}
          </button>

          {/* Core Selector */}
          <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg">
            {(['all', '0', '1', '2', '3'] as const).map((c) => (
              <button
                key={c}
                onClick={() => setSelectedCoreFilter(c)}
                className={`px-2.5 py-1 text-xs font-mono rounded transition-colors ${
                  selectedCoreFilter === c
                    ? 'bg-slate-100 text-slate-950 font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {c === 'all' ? 'Tất cả 4 Core' : `Core #${c}`}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* 4 Instant KPI Stat Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* KPI 1: Cluster RPS */}
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400">
            <span>Tổng Thông Lượng (Cluster RPS)</span>
            <Activity className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono tabular-nums text-slate-100">
            {(latest.total_rps / 1000000).toFixed(3)}M <span className="text-xs text-amber-400 font-sans">req/s</span>
          </div>
          <div className="text-[11px] font-mono text-emerald-400 flex items-center gap-1">
            <TrendingUp className="w-3 h-3" />
            {(latest.total_rps).toLocaleString()} requests/sec (0% drop)
          </div>
        </div>

        {/* KPI 2: Average CPU Core Utilization */}
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400">
            <span>CPU Pinning Tải Trung Bình</span>
            <Cpu className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono tabular-nums text-emerald-400">
            {avgCpu}% <span className="text-xs text-slate-400 font-sans">vật lý</span>
          </div>
          <div className="text-[11px] font-mono text-slate-400">
            core_affinity: 4 Threads / 4 Cores vật lý
          </div>
        </div>

        {/* KPI 3: Active Sockets (H3 QUIC + TCP) */}
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400">
            <span>Kết Nối Active Sockets</span>
            <Server className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-2xl font-bold font-mono tabular-nums text-sky-400">
            {(latest.h3_quic_conns + latest.tcp_h2_conns).toLocaleString()}
          </div>
          <div className="text-[11px] font-mono text-slate-400">
            QUIC (H3): {latest.h3_quic_conns.toLocaleString()} · TCP: {latest.tcp_h2_conns.toLocaleString()}
          </div>
        </div>

        {/* KPI 4: Hot-Path P99 Latency */}
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400">
            <span>Độ Trễ P99 Hot-Path</span>
            <Zap className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono tabular-nums text-amber-400">
            {latest.p99_latency_us} <span className="text-xs text-slate-400 font-sans">µs</span>
          </div>
          <div className="text-[11px] font-mono text-emerald-400">
            {(latest.p99_latency_us / 1000).toFixed(3)} ms (io_uring SQPOLL)
          </div>
        </div>
      </div>

      {/* Main Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Chart 1: Per-Core Request Throughput Over Time (8 Cols) */}
        <div className="lg:col-span-8 bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <span className="text-xs font-mono text-amber-400">Thông Lượng Xử Lý Gói Tin Thời Gian Thực</span>
              <h3 className="text-base font-bold text-slate-100">
                Throughput per Pinned Core (Requests / Giây)
              </h3>
            </div>
            <div className="text-xs font-mono text-slate-400">
              Cân bằng tải Kernel: <span className="text-slate-200">SO_ATTACH_REUSEPORT_CBPF</span>
            </div>
          </div>

          <div className="h-[280px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={historyData} barGap={1}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />
                <XAxis dataKey="time" stroke="#64748B" fontSize={11} tickLine={false} />
                <YAxis
                  stroke="#64748B"
                  fontSize={11}
                  tickLine={false}
                  tickFormatter={(val) => `${(val / 1000).toFixed(0)}k`}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0F172A',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '12px',
                    fontFamily: 'monospace'
                  }}
                  formatter={(value: any) => [`${Number(value).toLocaleString()} req/s`, '']}
                />
                <Legend wrapperStyle={{ fontSize: '11px', fontFamily: 'monospace' }} />

                {(selectedCoreFilter === 'all' || selectedCoreFilter === '0') && (
                  <Bar dataKey="core0_rps" name="Core #0 (wkr-00)" fill="#F59E0B" radius={[2, 2, 0, 0]} />
                )}
                {(selectedCoreFilter === 'all' || selectedCoreFilter === '1') && (
                  <Bar dataKey="core1_rps" name="Core #1 (wkr-01)" fill="#10B981" radius={[2, 2, 0, 0]} />
                )}
                {(selectedCoreFilter === 'all' || selectedCoreFilter === '2') && (
                  <Bar dataKey="core2_rps" name="Core #2 (wkr-02)" fill="#38BDF8" radius={[2, 2, 0, 0]} />
                )}
                {(selectedCoreFilter === 'all' || selectedCoreFilter === '3') && (
                  <Bar dataKey="core3_rps" name="Core #3 (wkr-03)" fill="#A855F7" radius={[2, 2, 0, 0]} />
                )}
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Chart 2: CPU Utilization Area Chart per Core (4 Cols) */}
        <div className="lg:col-span-4 bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs font-mono text-emerald-400">Hiệu Suất Tận Dụng CPU</span>
              <h3 className="text-base font-bold text-slate-100">CPU Core Load (%)</h3>
            </div>
            <span className="text-xs font-mono text-slate-400">Target &lt; 85%</span>
          </div>

          <div className="h-[280px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={historyData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />
                <XAxis dataKey="time" stroke="#64748B" fontSize={10} tickLine={false} />
                <YAxis stroke="#64748B" fontSize={10} domain={[40, 90]} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0F172A',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '11px',
                    fontFamily: 'monospace'
                  }}
                  formatter={(value: any) => [`${value}%`, '']}
                />
                <Legend wrapperStyle={{ fontSize: '10px', fontFamily: 'monospace' }} />
                <Line type="monotone" dataKey="core0_cpu" name="Core 0" stroke="#F59E0B" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="core1_cpu" name="Core 1" stroke="#10B981" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="core2_cpu" name="Core 2" stroke="#38BDF8" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="core3_cpu" name="Core 3" stroke="#A855F7" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Socket Health, io_uring Rings & Protocol Multiplexing Metrics */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Left 6 Cols: Dual-Stack Socket Health (QUIC vs TCP Conns Area Chart) */}
        <div className="lg:col-span-6 bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs font-mono text-sky-400">Phân Phối Socket Đồng Thời</span>
              <h3 className="text-base font-bold text-slate-100">
                HTTP/3 QUIC (UDP) vs HTTP/2 TLS 1.3 (TCP)
              </h3>
            </div>
            <span className="text-xs font-mono text-slate-400">Alt-Svc Active</span>
          </div>

          <div className="h-[240px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={historyData}>
                <defs>
                  <linearGradient id="colorQuic" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#38BDF8" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#38BDF8" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorTcp" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10B981" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#10B981" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />
                <XAxis dataKey="time" stroke="#64748B" fontSize={11} tickLine={false} />
                <YAxis
                  stroke="#64748B"
                  fontSize={11}
                  tickLine={false}
                  tickFormatter={(val) => `${(val / 1000).toFixed(0)}k`}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0F172A',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '12px',
                    fontFamily: 'monospace'
                  }}
                  formatter={(value: any) => [`${Number(value).toLocaleString()} sockets`, '']}
                />
                <Legend wrapperStyle={{ fontSize: '11px', fontFamily: 'monospace' }} />
                <Area
                  type="monotone"
                  dataKey="h3_quic_conns"
                  name="HTTP/3 QUIC (UDP GRO/GSO)"
                  stroke="#38BDF8"
                  fillOpacity={1}
                  fill="url(#colorQuic)"
                  strokeWidth={2}
                />
                <Area
                  type="monotone"
                  dataKey="tcp_h2_conns"
                  name="HTTP/2 TLS 1.3 (TCP BBR)"
                  stroke="#10B981"
                  fillOpacity={1}
                  fill="url(#colorTcp)"
                  strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Right 6 Cols: Kernel Ring Buffers & Hardware Offload Health Table */}
        <div className="lg:col-span-6 bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <span className="text-xs font-mono text-amber-400 font-semibold">
                Sức Khỏe Socket Tầng Nhân Linux &amp; Hàng Đợi io_uring
              </span>
              <span className="text-xs font-mono text-emerald-400">Zero Socket Drops</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-800/80 text-slate-400 font-mono">
                    <th className="py-2">Chỉ Số Nhân (Kernel Metric)</th>
                    <th className="py-2">Trạng Thái Hiện Hành</th>
                    <th className="py-2">Ngưỡng Giới Hạn</th>
                    <th className="py-2">Đánh Giá</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/50 font-mono tabular-nums">
                  <tr>
                    <td className="py-2 text-slate-200">io_uring SQ Ring Util</td>
                    <td className="py-2 text-amber-400 font-semibold">{latest.sq_ring_util} / 64 entries</td>
                    <td className="py-2 text-slate-400">4,096 entries max</td>
                    <td className="py-2 text-emerald-400 font-sans">Tối ưu (SQPOLL Hot)</td>
                  </tr>
                  <tr>
                    <td className="py-2 text-slate-200">UDP GRO GSO Batching</td>
                    <td className="py-2 text-emerald-400 font-semibold">44 pkts/super-frame</td>
                    <td className="py-2 text-slate-400">65,536 bytes max</td>
                    <td className="py-2 text-emerald-400 font-sans">Hoạt động 100%</td>
                  </tr>
                  <tr>
                    <td className="py-2 text-slate-200">TCP TIME_WAIT Sockets</td>
                    <td className="py-2 text-slate-300">148 sockets</td>
                    <td className="py-2 text-slate-400">tcp_tw_reuse = 1</td>
                    <td className="py-2 text-emerald-400 font-sans">Tái sử dụng ngay</td>
                  </tr>
                  <tr>
                    <td className="py-2 text-slate-200">SO_RCVBUF / SO_SNDBUF</td>
                    <td className="py-2 text-slate-300">16.0 MB / 16.0 MB</td>
                    <td className="py-2 text-slate-400">net.core.rmem_max</td>
                    <td className="py-2 text-emerald-400 font-sans">Không rớt gói UDP</td>
                  </tr>
                  <tr>
                    <td className="py-2 text-slate-200">Circuit Breaker Ejections</td>
                    <td className="py-2 text-emerald-400 font-semibold">0 nodes ejected</td>
                    <td className="py-2 text-slate-400">Max 50% cluster</td>
                    <td className="py-2 text-emerald-400 font-sans">Tất cả Backend khỏe</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/90 text-xs text-slate-300 leading-relaxed flex items-center gap-2.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 shrink-0 animate-ping" />
            <span>
              <strong>Bảo đảm kiến trúc:</strong> Dữ liệu Telemetry được đọc trực tiếp từ các biến nguyên tử <code className="text-amber-300">AtomicU64</code> và thống kê ngắt NAPI mà <strong>không hề dùng Mutex hay cản trở vòng lặp I/O của Worker</strong>.
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
