import React, { useState } from 'react';
import {
  ARCHITECTURE_LAYERS,
  ASCII_ARCHITECTURE_DIAGRAM,
  MERMAID_ARCHITECTURE_DIAGRAM,
  ArchitectureLayer
} from '../data/architectureData';
import { Copy, Check, ArrowRight, Cpu, Layers, ShieldCheck, Zap } from 'lucide-react';

export const ArchitectureView: React.FC = () => {
  const [selectedLayerId, setSelectedLayerId] = useState<string>(ARCHITECTURE_LAYERS[1].id);
  const [diagramMode, setDiagramMode] = useState<'interactive' | 'ascii' | 'mermaid'>('interactive');
  const [copiedDiagram, setCopiedDiagram] = useState(false);

  const selectedLayer: ArchitectureLayer =
    ARCHITECTURE_LAYERS.find((l) => l.id === selectedLayerId) || ARCHITECTURE_LAYERS[0];

  const totalLatencyNs = ARCHITECTURE_LAYERS.reduce((sum, l) => sum + l.latencyBudgetNs, 0);

  const handleCopyDiagram = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedDiagram(true);
    setTimeout(() => setCopiedDiagram(false), 2000);
  };

  return (
    <div className="space-y-10">
      {/* Section Header */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 pb-6 border-b border-slate-800">
        <div>
          <p className="text-xs font-mono text-amber-400 tracking-wide">
            01. Thiết kế Kiến trúc Hệ thống &amp; Kernel Bypass
          </p>
          <h2 className="mt-1 text-2xl sm:text-3xl font-bold text-slate-100 tracking-tight text-balance">
            Phân lớp Kiến trúc Shared-Nothing từ Card mạng (NIC) tới Upstream
          </h2>
          <p className="mt-2 text-sm text-slate-400 max-w-3xl leading-relaxed">
            FerrousX loại bỏ hoàn toàn mô hình đa luồng tranh chấp khóa (<code className="text-slate-200">epoll</code> + Mutex) truyền thống. Mỗi lõi CPU vận hành một ngăn xếp mạng khép kín từ ngắt phần cứng RSS, bộ lọc nhân <code className="text-slate-200">SO_ATTACH_REUSEPORT_CBPF</code>, vòng đệm <code className="text-slate-200">io_uring</code> cho tới bộ cấp phát vùng nhớ <code className="text-slate-200">Bumpalo Arena</code>.
          </p>
        </div>

        {/* Diagram Mode Segmented Switcher */}
        <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg self-start shrink-0">
          <button
            onClick={() => setDiagramMode('interactive')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
              diagramMode === 'interactive'
                ? 'bg-amber-500 text-slate-950 font-semibold'
                : 'text-slate-400 hover:text-slate-100'
            }`}
          >
            Sơ đồ Phân lớp Tương tác
          </button>
          <button
            onClick={() => setDiagramMode('ascii')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
              diagramMode === 'ascii'
                ? 'bg-amber-500 text-slate-950 font-semibold'
                : 'text-slate-400 hover:text-slate-100'
            }`}
          >
            Sơ đồ ASCII Chuẩn
          </button>
          <button
            onClick={() => setDiagramMode('mermaid')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
              diagramMode === 'mermaid'
                ? 'bg-amber-500 text-slate-950 font-semibold'
                : 'text-slate-400 hover:text-slate-100'
            }`}
          >
            Mermaid Blueprint
          </button>
        </div>
      </div>

      {/* Mode 1: Interactive Multi-Layer Architecture Stack + Inspector */}
      {diagramMode === 'interactive' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          {/* Left 7 Cols: 6-Layer Vertical Pipeline Stack */}
          <div className="lg:col-span-7 space-y-3">
            <div className="flex items-center justify-between text-xs text-slate-400 pb-1">
              <span>Nhấp vào từng tầng kiến trúc để xem cơ chế tối ưu hóa cấp thấp</span>
              <span className="font-mono tabular-nums text-slate-300">
                Tổng ngân sách độ trễ nội bộ: {(totalLatencyNs / 1000).toFixed(2)} µs ({totalLatencyNs} ns)
              </span>
            </div>

            {ARCHITECTURE_LAYERS.map((layer, idx) => {
              const isSelected = layer.id === selectedLayerId;
              return (
                <button
                  key={layer.id}
                  onClick={() => setSelectedLayerId(layer.id)}
                  className={`w-full text-left p-4 rounded-xl border transition-all ${
                    isSelected
                      ? 'bg-slate-900/95 border-amber-500/80 shadow-sm'
                      : 'bg-slate-900/40 border-slate-800/90 hover:border-slate-700 hover:bg-slate-900/70'
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-3">
                      <span
                        className={`text-xs font-mono font-semibold px-2 py-0.5 rounded ${
                          isSelected
                            ? 'bg-amber-500 text-slate-950'
                            : 'bg-slate-800 text-slate-300'
                        }`}
                      >
                        {layer.layerIndex}
                      </span>
                      <h3 className="text-base font-semibold text-slate-100">
                        {layer.title}
                      </h3>
                    </div>

                    <div className="flex items-center gap-2 text-xs font-mono tabular-nums text-slate-400">
                      <span>{layer.kernelOrUser}</span>
                      <span aria-hidden="true">·</span>
                      <span className="text-amber-400 font-medium">~{layer.latencyBudgetNs} ns</span>
                    </div>
                  </div>

                  <p className="mt-1.5 text-xs text-slate-400">{layer.subtitle}</p>

                  <div className="mt-3 pt-2.5 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-xs font-mono text-slate-400">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="text-slate-500">Syscalls/Primitives:</span>
                      {layer.syscallsOrPrimitives.map((prim, i) => (
                        <React.Fragment key={prim}>
                          <span className="text-slate-200">{prim}</span>
                          {i < layer.syscallsOrPrimitives.length - 1 && (
                            <span className="text-slate-600">·</span>
                          )}
                        </React.Fragment>
                      ))}
                    </div>
                    {idx < ARCHITECTURE_LAYERS.length - 1 && (
                      <span className="text-slate-500 flex items-center gap-1">
                        Zero-Copy <ArrowRight className="w-3 h-3 text-amber-400" />
                      </span>
                    )}
                  </div>
                </button>
              );
            })}
          </div>

          {/* Right 5 Cols: Deep-Dive Layer Inspector */}
          <div className="lg:col-span-5 bg-slate-900/80 border border-slate-800 rounded-xl p-6 space-y-6 sticky top-24">
            <div className="border-b border-slate-800 pb-4">
              <div className="flex items-center justify-between text-xs font-mono text-amber-400">
                <span>{selectedLayer.layerIndex} · Đặc tả Kỹ thuật</span>
                <span>{selectedLayer.kernelOrUser}</span>
              </div>
              <h3 className="mt-2 text-xl font-bold text-slate-100">
                {selectedLayer.title}
              </h3>
              <p className="mt-2 text-sm text-slate-300 leading-relaxed">
                {selectedLayer.description}
              </p>
            </div>

            {/* Crates & Primitives */}
            <div className="grid grid-cols-2 gap-4 pt-1">
              <div>
                <h4 className="text-xs font-mono text-slate-400">Rust Crates phụ trách</h4>
                <p className="mt-1.5 text-xs font-mono text-slate-100 leading-relaxed">
                  {selectedLayer.cratesUsed.join(' · ')}
                </p>
              </div>
              <div>
                <h4 className="text-xs font-mono text-slate-400">Độ trễ mục tiêu (Hot-Path)</h4>
                <p className="mt-1.5 text-sm font-mono font-semibold text-emerald-400 tabular-nums">
                  {selectedLayer.latencyBudgetNs} nanoseconds
                </p>
              </div>
            </div>

            {/* Optimization Mechanics */}
            <div className="space-y-3 pt-2 border-t border-slate-800">
              <h4 className="text-xs font-mono text-slate-300">
                Cơ chế tối ưu hóa vượt trội so với Nginx &amp; LiteSpeed
              </h4>
              <ul className="space-y-2.5">
                {selectedLayer.optimizationMechanics.map((mech, i) => (
                  <li key={i} className="text-xs text-slate-300 leading-relaxed flex items-start gap-2.5">
                    <span className="font-mono text-amber-400 font-semibold shrink-0">
                      0{i + 1}.
                    </span>
                    <span>{mech}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Architectural Proof Table */}
            <div className="pt-4 border-t border-slate-800">
              <h4 className="text-xs font-mono text-slate-400 mb-2.5">
                Đối chiếu Kiến trúc Thực thi I/O
              </h4>
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-2 pr-2 font-medium">Tiêu chí</th>
                      <th className="py-2 px-2 font-medium text-amber-400">FerrousX</th>
                      <th className="py-2 pl-2 font-medium">Nginx (epoll)</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono tabular-nums">
                    <tr>
                      <td className="py-2 pr-2 text-slate-300 font-sans">Cơ chế I/O</td>
                      <td className="py-2 px-2 text-emerald-400">io_uring SQ/CQ</td>
                      <td className="py-2 pl-2 text-slate-400">epoll_wait syscall</td>
                    </tr>
                    <tr>
                      <td className="py-2 pr-2 text-slate-300 font-sans">Chia sẻ trạng thái</td>
                      <td className="py-2 px-2 text-emerald-400">0 Locks (ArcSwap)</td>
                      <td className="py-2 pl-2 text-slate-400">Shared Shm Mutex</td>
                    </tr>
                    <tr>
                      <td className="py-2 pr-2 text-slate-300 font-sans">Cấp phát bộ nhớ</td>
                      <td className="py-2 px-2 text-emerald-400">Bumpalo + FixedBuf</td>
                      <td className="py-2 pl-2 text-slate-400">ngx_pool_t Heap</td>
                    </tr>
                    <tr>
                      <td className="py-2 pr-2 text-slate-300 font-sans">Định tuyến QUIC</td>
                      <td className="py-2 px-2 text-emerald-400">eBPF DCID + GRO</td>
                      <td className="py-2 pl-2 text-slate-400">4-Tuple UDP Hash</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Mode 2: Full ASCII Diagram */}
      {diagramMode === 'ascii' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3 border-b border-slate-800 bg-slate-950/60">
            <span className="text-xs font-mono text-slate-300">
              Sơ đồ Phân lớp Kiến trúc FerrousX (ASCII Blueprint)
            </span>
            <button
              onClick={() => handleCopyDiagram(ASCII_ARCHITECTURE_DIAGRAM)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              {copiedDiagram ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copiedDiagram ? 'Đã sao chép' : 'Sao chép ASCII'}
            </button>
          </div>
          <pre className="p-6 text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed">
            {ASCII_ARCHITECTURE_DIAGRAM}
          </pre>
        </div>
      )}

      {/* Mode 3: Mermaid Diagram */}
      {diagramMode === 'mermaid' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3 border-b border-slate-800 bg-slate-950/60">
            <span className="text-xs font-mono text-slate-300">
              Mermaid.js Architecture Definition (Tích hợp trực tiếp vào tài liệu RFC / GitHub README)
            </span>
            <button
              onClick={() => handleCopyDiagram(MERMAID_ARCHITECTURE_DIAGRAM)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              {copiedDiagram ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copiedDiagram ? 'Đã sao chép' : 'Sao chép Mermaid'}
            </button>
          </div>
          <pre className="p-6 text-xs font-mono text-amber-300/90 overflow-x-auto leading-relaxed">
            {MERMAID_ARCHITECTURE_DIAGRAM}
          </pre>
        </div>
      )}

      {/* Deep-Dive Analysis: SO_REUSEPORT + SO_ATTACH_REUSEPORT_CBPF / eBPF */}
      <div className="pt-6 border-t border-slate-800 space-y-6">
        <div>
          <p className="text-xs font-mono text-amber-400">
            Phân tích Chuyên sâu Tầng Nhân Linux
          </p>
          <h3 className="mt-1 text-xl font-bold text-slate-100">
            Cơ chế Tiếp nhận Kết nối Đa luồng với SO_REUSEPORT &amp; SO_ATTACH_REUSEPORT_CBPF / eBPF
          </h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-stretch">
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span>01. Bài toán Nút cổ chai Cổ điển</span>
                <Cpu className="w-4 h-4 text-amber-400" />
              </div>
              <h4 className="text-base font-semibold text-slate-100">
                Loại bỏ Spinlock Hàng đợi Accept &amp; Nhảy lõi L1/L2 Cache
              </h4>
              <p className="text-xs text-slate-300 leading-relaxed">
                Trong kiến trúc 1 socket chia sẻ cho <code className="text-slate-100">N</code> luồng <code className="text-slate-100">epoll</code>, mọi gói <code className="text-slate-100">SYN</code> đến đều phải tranh chấp khóa <code className="text-slate-100">icsk_accept_queue.rskq_lock</code>. Ngay cả khi bật <code className="text-slate-100">SO_REUSEPORT</code> mặc định, nhân Linux dùng hàm băm 4-tuple ngẫu nhiên có thể đẩy gói tin đang nằm ở L1 cache của <strong>CPU Core 0</strong> sang socket của <strong>Worker Core 7</strong>, gây ra <em>Cross-Core Cache Miss</em>.
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-slate-800/80 text-xs font-mono text-emerald-400">
              Giải pháp FerrousX: Định tuyến gắn chặt theo địa phương hóa CPU (CPU Locality).
            </div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span>02. cBPF Locality Filter</span>
                <Layers className="w-4 h-4 text-amber-400" />
              </div>
              <h4 className="text-base font-semibold text-slate-100">
                Định tuyến Tức thì qua SKF_AD_CPU (SO_ATTACH_REUSEPORT_CBPF)
              </h4>
              <p className="text-xs text-slate-300 leading-relaxed">
                Khi khởi tạo Worker #0, FerrousX đính kèm chương trình bytecode BPF 3 lệnh thông qua <code className="text-slate-100">setsockopt(..., SO_ATTACH_REUSEPORT_CBPF)</code>. Khi ngắt mềm <code className="text-slate-100">NET_RX_SOFTIRQ</code> chạy trên lõi <code className="text-slate-100">k</code>, bộ lọc đọc thanh ghi <code className="text-slate-100">SKF_AD_OFF + SKF_AD_CPU</code> và trả về đúng chỉ số socket thứ <code className="text-slate-100">k % num_workers</code>.
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-slate-800/80 text-xs font-mono text-amber-300">
              Bytecode: LD [SKF_AD_CPU] -&gt; MOD #N -&gt; RET A
            </div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span>03. QUIC Connection Migration</span>
                <ShieldCheck className="w-4 h-4 text-amber-400" />
              </div>
              <h4 className="text-base font-semibold text-slate-100">
                eBPF sk_reuseport Bảo toàn Kết nối QUIC (HTTP/3)
              </h4>
              <p className="text-xs text-slate-300 leading-relaxed">
                Với UDP/QUIC, nếu điện thoại chuyển từ Wi-Fi sang 5G, địa chỉ IP và cổng nguồn thay đổi làm hàm băm 4-tuple đẩy gói tin sang nhầm Worker không giữ trạng thái mã hóa QUIC. FerrousX dùng chương trình eBPF <code className="text-slate-100">BPF_PROG_TYPE_SK_REUSEPORT</code> đọc trực tiếp <strong>Worker ID được mã hóa trong byte đầu của QUIC Destination Connection ID (DCID)</strong> để điều hướng chính xác 100%.
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-slate-800/80 text-xs font-mono text-emerald-400">
              Độ chính xác định tuyến QUIC Connection Migration: 100%
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
