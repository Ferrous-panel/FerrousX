import React, { useState } from 'react';
import {
  SYSCTL_TUNING_ITEMS,
  BENCHMARK_SCENARIOS,
  SysctlItem,
  BenchmarkScenario
} from '../data/architectureData';
import { Copy, Check, Download, Terminal, Sliders, BarChart3 } from 'lucide-react';

export const BenchmarkTuningView: React.FC = () => {
  const [hwProfile, setHwProfile] = useState<'16core' | '32core' | '64core'>('32core');
  const [sysctlCategory, setSysctlCategory] = useState<string>('ALL');
  const [activeBenchId, setActiveBenchId] = useState<string>(BENCHMARK_SCENARIOS[0].id);
  const [copiedSysctl, setCopiedSysctl] = useState<boolean>(false);
  const [copiedBenchCmd, setCopiedBenchCmd] = useState<boolean>(false);

  const categories = [
    'ALL',
    'UDP & QUIC H3 Buffer',
    'TCP BBR & Low-Latency',
    'io_uring & File Descriptors',
    'NIC Queue & Core Backlog'
  ];

  const filteredSysctl = SYSCTL_TUNING_ITEMS.filter(
    (item) => sysctlCategory === 'ALL' || item.category === sysctlCategory
  );

  const getProfileValue = (item: SysctlItem) => {
    if (hwProfile === '16core') return item.value16Core;
    if (hwProfile === '32core') return item.value32Core;
    return item.value64Core;
  };

  const generateSysctlConfText = () => {
    const header = [
      '# ==============================================================================',
      `# /etc/sysctl.d/99-ferrousx-tuning.conf (Profile: ${hwProfile.toUpperCase()})`,
      '# Tối ưu hóa nhân Linux cho FerrousX (io_uring, HTTP/3 QUIC UDP GRO/GSO, TCP BBR)',
      '# Áp dụng bằng lệnh: sudo sysctl --system',
      '# ==============================================================================',
      ''
    ];
    const body = SYSCTL_TUNING_ITEMS.map(
      (item) => `# ${item.rationale}\n${item.key} = ${getProfileValue(item)}\n`
    );
    return [...header, ...body].join('\n');
  };

  const handleCopySysctl = () => {
    navigator.clipboard.writeText(generateSysctlConfText());
    setCopiedSysctl(true);
    setTimeout(() => setCopiedSysctl(false), 2000);
  };

  const handleDownloadSysctl = () => {
    const blob = new Blob([generateSysctlConfText()], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `99-ferrousx-${hwProfile}.conf`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const activeScenario: BenchmarkScenario =
    BENCHMARK_SCENARIOS.find((b) => b.id === activeBenchId) || BENCHMARK_SCENARIOS[0];

  const maxRps = Math.max(...activeScenario.metrics.map((m) => m.rps));

  const handleCopyBenchCmd = () => {
    navigator.clipboard.writeText(activeScenario.command);
    setCopiedBenchCmd(true);
    setTimeout(() => setCopiedBenchCmd(false), 2000);
  };

  return (
    <div className="space-y-12">
      {/* Part 4A: Linux Kernel sysctl.conf Tuning Generator */}
      <div className="space-y-6">
        <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 pb-6 border-b border-slate-800">
          <div>
            <p className="text-xs font-mono text-amber-400 tracking-wide">
              04. Kernel Tuning &amp; Benchmark Blueprint
            </p>
            <h2 className="mt-1 text-2xl sm:text-3xl font-bold text-slate-100 tracking-tight text-balance">
              Tinh chỉnh Nhân Linux (sysctl) &amp; Quy trình Đo kiểm Hiệu năng Thực chiến
            </h2>
            <p className="mt-2 text-sm text-slate-400 max-w-3xl leading-relaxed">
              Để đạt thông lượng hàng triệu request/giây với HTTP/3 QUIC và <code className="text-slate-200">io_uring</code>, ngăn xếp mạng của Linux cần được mở rộng vùng đệm UDP, kích hoạt điều khiển tắc nghẽn <code className="text-slate-200">BBR + fq</code> và tăng giới hạn vùng nhớ ánh xạ (<code className="text-slate-200">vm.max_map_count</code>).
            </p>
          </div>

          {/* Hardware Profile Selector */}
          <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg self-start shrink-0">
            <button
              onClick={() => setHwProfile('16core')}
              className={`px-3 py-1.5 text-xs font-mono rounded-md transition-colors whitespace-nowrap shrink-0 ${
                hwProfile === '16core'
                  ? 'bg-amber-500 text-slate-950 font-semibold'
                  : 'text-slate-400 hover:text-slate-100'
              }`}
            >
              16 Core · 25GbE
            </button>
            <button
              onClick={() => setHwProfile('32core')}
              className={`px-3 py-1.5 text-xs font-mono rounded-md transition-colors whitespace-nowrap shrink-0 ${
                hwProfile === '32core'
                  ? 'bg-amber-500 text-slate-950 font-semibold'
                  : 'text-slate-400 hover:text-slate-100'
              }`}
            >
              32 Core · 100GbE
            </button>
            <button
              onClick={() => setHwProfile('64core')}
              className={`px-3 py-1.5 text-xs font-mono rounded-md transition-colors whitespace-nowrap shrink-0 ${
                hwProfile === '64core'
                  ? 'bg-amber-500 text-slate-950 font-semibold'
                  : 'text-slate-400 hover:text-slate-100'
              }`}
            >
              64 Core · 200GbE
            </button>
          </div>
        </div>

        {/* Category Filter + Export Actions */}
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-1.5">
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setSysctlCategory(cat)}
                className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap shrink-0 ${
                  sysctlCategory === cat
                    ? 'bg-slate-100 text-slate-950 border-slate-100 font-semibold'
                    : 'bg-slate-900/70 text-slate-300 border-slate-800 hover:border-slate-700'
                }`}
              >
                {cat === 'ALL' ? 'Tất cả Thông số (11)' : cat}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopySysctl}
              className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 rounded-lg transition-colors whitespace-nowrap shrink-0"
            >
              {copiedSysctl ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copiedSysctl ? 'Đã sao chép sysctl.conf' : 'Sao chép sysctl.conf'}
            </button>
            <button
              onClick={handleDownloadSysctl}
              className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold bg-amber-500 hover:bg-amber-400 text-slate-950 rounded-lg transition-colors whitespace-nowrap shrink-0"
            >
              <Download className="w-3.5 h-3.5" />
              Tải 99-ferrousx.conf
            </button>
          </div>
        </div>

        {/* High-Density Sysctl Table */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/70 text-xs font-mono text-slate-400">
                  <th className="py-3 px-4">Tham số Kernel (sysctl key)</th>
                  <th className="py-3 px-4">Nhóm Tối ưu</th>
                  <th className="py-3 px-4 text-right">Giá trị Khuyến nghị</th>
                  <th className="py-3 px-4">Đơn vị</th>
                  <th className="py-3 px-4">Cơ sở Kỹ thuật &amp; Tác động</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70 text-xs">
                {filteredSysctl.map((item) => (
                  <tr key={item.key} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-4 font-mono font-semibold text-amber-300 whitespace-nowrap">
                      {item.key}
                    </td>
                    <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                      {item.category}
                    </td>
                    <td className="py-3 px-4 font-mono font-semibold text-emerald-400 text-right tabular-nums whitespace-nowrap">
                      {getProfileValue(item)}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400 whitespace-nowrap">
                      {item.unit}
                    </td>
                    <td className="py-3 px-4 text-slate-300 leading-relaxed min-w-[280px]">
                      {item.rationale}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Part 4B: Benchmark Blueprint & Head-to-Head Comparison (FerrousX vs LiteSpeed vs Nginx) */}
      <div className="pt-6 border-t border-slate-800 space-y-6">
        <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
          <div>
            <span className="text-xs font-mono text-amber-400">
              Đối chiếu Thực nghiệm: wrk · h2load · qlog
            </span>
            <h3 className="mt-1 text-xl font-bold text-slate-100">
              So sánh Thông lượng (RPS) &amp; Độ trễ P95/P99: FerrousX vs LiteSpeed vs Nginx
            </h3>
          </div>

          {/* Scenario Selector Buttons */}
          <div className="flex flex-wrap items-center gap-1.5 p-1 bg-slate-900 border border-slate-800 rounded-lg">
            {BENCHMARK_SCENARIOS.map((scen) => (
              <button
                key={scen.id}
                onClick={() => setActiveBenchId(scen.id)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                  activeBenchId === scen.id
                    ? 'bg-amber-500 text-slate-950 font-semibold'
                    : 'text-slate-400 hover:text-slate-100'
                }`}
              >
                {scen.protocol}
              </button>
            ))}
          </div>
        </div>

        {/* Command Runner Box */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-mono text-slate-300">
              <Terminal className="w-4 h-4 text-amber-400" />
              <span className="font-semibold text-slate-100">{activeScenario.name}</span>
              <span aria-hidden="true" className="text-slate-600">·</span>
              <span className="text-slate-400">{activeScenario.concurrency}</span>
            </div>

            <button
              onClick={handleCopyBenchCmd}
              className="flex items-center gap-1.5 px-3 py-1 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              {copiedBenchCmd ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copiedBenchCmd ? 'Đã sao chép lệnh' : 'Sao chép lệnh đo'}
            </button>
          </div>

          <pre className="p-3.5 rounded-lg bg-slate-950 border border-slate-800/90 text-xs font-mono text-amber-300 overflow-x-auto">
            {activeScenario.command}
          </pre>
        </div>

        {/* Visual Bar Comparison + Quantitative Metrics Table */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
          {/* Left 5 Cols: Visual RPS & Latency Bars */}
          <div className="lg:col-span-5 bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-5 flex flex-col justify-between">
            <div className="space-y-4">
              <h4 className="text-xs font-mono text-slate-300">
                Biểu đồ Thông lượng (Requests / Giây — Cao hơn là tốt hơn)
              </h4>

              <div className="space-y-4">
                {activeScenario.metrics.map((m, idx) => {
                  const ratio = m.rps / maxRps;
                  const isFerrous = idx === 0;
                  return (
                    <div key={m.server} className="space-y-1.5">
                      <div className="flex items-center justify-between text-xs font-mono">
                        <span className={isFerrous ? 'text-amber-400 font-semibold' : 'text-slate-300'}>
                          {m.server}
                        </span>
                        <span className="tabular-nums font-semibold text-slate-100">
                          {m.rps.toLocaleString()} req/s
                        </span>
                      </div>
                      <div className="w-full h-3 bg-slate-950 rounded-full overflow-hidden border border-slate-800">
                        <div
                          className={`h-full transition-transform duration-200 origin-left ${
                            isFerrous ? 'bg-amber-500' : idx === 1 ? 'bg-sky-500' : 'bg-slate-500'
                          }`}
                          style={{ transform: `scaleX(${ratio})` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="pt-4 border-t border-slate-800 text-xs text-slate-400 leading-relaxed">
              Môi trường chuẩn: Dual-socket AMD EPYC / Linux Kernel 6.8 · Bật <code className="text-slate-200">IORING_SETUP_SQPOLL</code> · Tắt Mitigations khi đo giới hạn phần cứng thuần túy.
            </div>
          </div>

          {/* Right 7 Cols: Detailed Quantitative Comparison Table */}
          <div className="lg:col-span-7 bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-950/70 text-xs font-mono text-slate-400">
                    <th className="py-3.5 px-4">Máy chủ (Web Server)</th>
                    <th className="py-3.5 px-4 text-right">Thông lượng (RPS)</th>
                    <th className="py-3.5 px-4 text-right">P50 (ms)</th>
                    <th className="py-3.5 px-4 text-right">P95 (ms)</th>
                    <th className="py-3.5 px-4 text-right">P99 (ms)</th>
                    <th className="py-3.5 px-4 text-right">CPU (%)</th>
                    <th className="py-3.5 px-4 text-right">RAM (MB)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70 text-xs font-mono tabular-nums">
                  {activeScenario.metrics.map((m, idx) => {
                    const isFerrous = idx === 0;
                    return (
                      <tr
                        key={m.server}
                        className={isFerrous ? 'bg-amber-500/10' : 'hover:bg-slate-800/40'}
                      >
                        <td className="py-3.5 px-4 font-sans font-semibold text-slate-100">
                          {m.server}
                        </td>
                        <td className="py-3.5 px-4 text-right font-bold text-emerald-400">
                          {m.rps.toLocaleString()}
                        </td>
                        <td className="py-3.5 px-4 text-right text-slate-200">
                          {m.p50LatencyMs.toFixed(2)}
                        </td>
                        <td className="py-3.5 px-4 text-right text-slate-200">
                          {m.p95LatencyMs.toFixed(2)}
                        </td>
                        <td
                          className={`py-3.5 px-4 text-right font-semibold ${
                            isFerrous ? 'text-amber-400' : 'text-slate-300'
                          }`}
                        >
                          {m.p99LatencyMs.toFixed(2)}
                        </td>
                        <td className="py-3.5 px-4 text-right text-slate-300">
                          {m.cpuUsagePct}%
                        </td>
                        <td className="py-3.5 px-4 text-right text-slate-300">
                          {m.memoryMb} MB
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Lua & qlog Diagnostic Script Snippets */}
            <div className="p-4 border-t border-slate-800 bg-slate-950/50 space-y-2">
              <div className="text-xs font-mono font-semibold text-slate-300">
                Hướng dẫn Phân tích Vết QUIC (qlog) &amp; Kiểm tra Cache Miss bằng perf:
              </div>
              <pre className="text-[11px] font-mono text-slate-300 overflow-x-auto leading-relaxed">
{`# 1. Đo tỷ lệ L1d Cache Miss & Context Switch của tiến trình FerrousX trong 30 giây tải nặng:
sudo perf stat -e cycles,instructions,L1-dcache-load-misses,context-switches -p $(pgrep ferrousx) -- sleep 30

# 2. Kiểm tra số lượng gói UDP gộp qua GRO/GSO và xác nhận 0 packet drops ở tầng socket:
nstat -az | grep -E "UdpInDatagrams|UdpRcvbufErrors|TcpExtTCPFastOpenActive"`}
              </pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
