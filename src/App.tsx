/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { ArchitectureView } from './components/ArchitectureView';
import { EbpfPipelineView } from './components/EbpfPipelineView';
import { WorkspaceCodeView } from './components/WorkspaceCodeView';
import { PolyglotRuntimeView } from './components/PolyglotRuntimeView';
import { EnterpriseFeaturesView } from './components/EnterpriseFeaturesView';
import { FerrousPanelReadmeView } from './components/FerrousPanelReadmeView';
import { InteractiveSimView } from './components/InteractiveSimView';
import { BenchmarkTuningView } from './components/BenchmarkTuningView';
import { generateWorkspaceBundleScript } from './data/workspaceData';
import { Download, Layers, Code2, Cpu, Gauge, Network, Globe2, ShieldCheck, FileText } from 'lucide-react';

type ActiveSection =
  | 'all'
  | 'architecture'
  | 'ebpf'
  | 'workspace'
  | 'polyglot'
  | 'resilience'
  | 'panel_readme'
  | 'simulation'
  | 'benchmark';

export default function App() {
  const [activeSection, setActiveSection] = useState<ActiveSection>('all');

  const handleDownloadFullWorkspace = () => {
    const script = generateWorkspaceBundleScript();
    const blob = new Blob([script], { type: 'text/x-shellscript;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'setup_ferrousx_workspace.sh';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-[#0B0F17] text-slate-100 flex flex-col">
      {/* Strict 3-Zone Top Bar Contract */}
      <header className="sticky top-0 z-30 flex items-center justify-between gap-8 px-6 py-4 bg-[#0B0F17]/95 backdrop-blur border-b border-slate-800/90">
        {/* Zone 1: Single text element wordmark */}
        <button
          onClick={() => setActiveSection('all')}
          className="text-lg font-bold tracking-tight text-slate-100 whitespace-nowrap shrink-0 text-left focus:outline-none"
        >
          FerrousX
        </button>

        {/* Zone 2: 5 concise single-line navigation links */}
        <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-400">
          <button
            onClick={() => setActiveSection('all')}
            className={`hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 ${
              activeSection === 'all' ? 'text-amber-400 underline underline-offset-8' : ''
            }`}
          >
            Toàn trình
          </button>
          <button
            onClick={() => setActiveSection('ebpf')}
            className={`hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 ${
              activeSection === 'ebpf' ? 'text-amber-400 underline underline-offset-8' : ''
            }`}
          >
            eBPF Pipeline
          </button>
          <button
            onClick={() => setActiveSection('resilience')}
            className={`hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 ${
              activeSection === 'resilience' ? 'text-amber-400 underline underline-offset-8' : ''
            }`}
          >
            Độ ổn định
          </button>
          <button
            onClick={() => setActiveSection('polyglot')}
            className={`hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 ${
              activeSection === 'polyglot' ? 'text-amber-400 underline underline-offset-8' : ''
            }`}
          >
            Đa Ngôn ngữ
          </button>
          <button
            onClick={() => setActiveSection('panel_readme')}
            className={`hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 ${
              activeSection === 'panel_readme' ? 'text-amber-400 underline underline-offset-8' : ''
            }`}
          >
            Ferrous Panel &amp; README
          </button>
        </nav>

        {/* Zone 3: 1 primary action */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={handleDownloadFullWorkspace}
            className="flex items-center gap-2 px-4 py-2 text-xs font-semibold text-slate-950 bg-amber-500 rounded-lg hover:bg-amber-400 transition-colors whitespace-nowrap shrink-0"
          >
            <Download className="w-3.5 h-3.5" />
            Tải Cargo Workspace (.sh)
          </button>
        </div>
      </header>

      {/* Main Content Container */}
      <main className="flex-1 max-w-[1380px] w-full mx-auto px-4 sm:px-8 py-10 space-y-16">
        {/* Hero Architectural Summary Banner */}
        <section className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 sm:p-8 space-y-6">
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-slate-400">
            <span className="text-amber-400 font-semibold">Ferrous Panel Core Web Engine</span>
            <span aria-hidden="true">·</span>
            <span>100% Safe &amp; Low-Level Rust (Edition 2024)</span>
            <span aria-hidden="true">·</span>
            <span>XDP &amp; SO_REUSEPORT eBPF</span>
            <span aria-hidden="true">·</span>
            <span>Singleflight Cache &amp; Circuit Breaker</span>
            <span aria-hidden="true">·</span>
            <span>Auto-HTTPS ACME &amp; OCSP Stapling</span>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-end">
            <div className="lg:col-span-7 space-y-3">
              <h1 className="text-3xl sm:text-4xl lg:text-[42px] font-bold text-slate-100 tracking-tight leading-[1.15] text-balance">
                FerrousX — Lõi Web Server &amp; Reverse Proxy Hiệu năng cao Tối ưu cho Ferrous Panel
              </h1>
              <p className="text-base text-slate-300 leading-relaxed max-w-3xl">
                Hội tụ các công nghệ nhân Linux cấp thấp (<code className="text-amber-300">io_uring</code>, <code className="text-amber-300">Thread-Per-Core</code>, <code className="text-amber-300">XDP + SO_REUSEPORT eBPF</code>, <code className="text-amber-300">HTTP/3 QUIC</code>) cùng giao diện điều khiển thời gian thực (<code className="text-amber-300">/run/ferrousx/panel-admin.sock</code>) cho phép <strong>Ferrous Panel</strong> tạo Website, đổi nóng phiên bản PHP-FPM, gắn cổng Node.js/Docker và xóa Cache trong <strong>&lt; 50 micro-giây</strong> với 0 kết nối bị ngắt.
              </p>
            </div>

            {/* Interactive Module Jump Tabs for fast switching */}
            <div className="lg:col-span-5 flex flex-col gap-2">
              <span className="text-xs font-mono text-slate-400">
                Chuyển nhanh tới từng phần triển khai:
              </span>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                <button
                  onClick={() => setActiveSection('panel_readme')}
                  className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap shrink-0 ${
                    activeSection === 'panel_readme'
                      ? 'bg-amber-500 text-slate-950 border-amber-500 font-semibold'
                      : 'bg-slate-950/80 text-slate-200 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <FileText className="w-3.5 h-3.5 shrink-0" />
                  Panel &amp; README
                </button>
                <button
                  onClick={() => setActiveSection('ebpf')}
                  className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap shrink-0 ${
                    activeSection === 'ebpf'
                      ? 'bg-amber-500 text-slate-950 border-amber-500 font-semibold'
                      : 'bg-slate-950/80 text-slate-200 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <Network className="w-3.5 h-3.5 shrink-0" />
                  eBPF Pipeline
                </button>
                <button
                  onClick={() => setActiveSection('resilience')}
                  className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap shrink-0 ${
                    activeSection === 'resilience'
                      ? 'bg-amber-500 text-slate-950 border-amber-500 font-semibold'
                      : 'bg-slate-950/80 text-slate-200 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <ShieldCheck className="w-3.5 h-3.5 shrink-0" />
                  Tính năng Ổn định
                </button>
                <button
                  onClick={() => setActiveSection('polyglot')}
                  className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap shrink-0 ${
                    activeSection === 'polyglot'
                      ? 'bg-amber-500 text-slate-950 border-amber-500 font-semibold'
                      : 'bg-slate-950/80 text-slate-200 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <Globe2 className="w-3.5 h-3.5 shrink-0" />
                  PHP / Node / Go
                </button>
                <button
                  onClick={() => setActiveSection('workspace')}
                  className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap shrink-0 ${
                    activeSection === 'workspace'
                      ? 'bg-amber-500 text-slate-950 border-amber-500 font-semibold'
                      : 'bg-slate-950/80 text-slate-200 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <Code2 className="w-3.5 h-3.5 shrink-0" />
                  Mã nguồn Rust
                </button>
                <button
                  onClick={() => setActiveSection('benchmark')}
                  className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap shrink-0 ${
                    activeSection === 'benchmark'
                      ? 'bg-amber-500 text-slate-950 border-amber-500 font-semibold'
                      : 'bg-slate-950/80 text-slate-200 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <Gauge className="w-3.5 h-3.5 shrink-0" />
                  Benchmark
                </button>
              </div>
            </div>
          </div>

          {/* 5 Core Architectural Pillars Strip */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 pt-4 border-t border-slate-800/90">
            <div className="space-y-1">
              <div className="text-xs font-mono text-amber-400">Trụ cột 01 · Kernel Bypass</div>
              <div className="text-sm font-semibold text-slate-100">io_uring + Thread-Per-Core</div>
              <div className="text-xs text-slate-400">
                Ghim cứng <code className="text-slate-300">core_affinity</code>, <code className="text-slate-300">SQPOLL</code> 0-syscall, <code className="text-slate-300">SPLICE</code> zero-copy.
              </div>
            </div>
            <div className="space-y-1">
              <div className="text-xs font-mono text-amber-400">Trụ cột 02 · Chống Sập Cache</div>
              <div className="text-sm font-semibold text-slate-100">Singleflight + Stale-If-Error</div>
              <div className="text-xs text-slate-400">
                Hợp nhất 10.000 request trùng khóa thành 1 lượt gọi Backend; phục vụ bản lưu cũ khi lỗi.
              </div>
            </div>
            <div className="space-y-1">
              <div className="text-xs font-mono text-amber-400">Trụ cột 03 · Tự Phục Hồi</div>
              <div className="text-sm font-semibold text-slate-100">Circuit Breaker &amp; Hedging</div>
              <div className="text-xs text-slate-400">
                Tự động cách ly node lỗi 5xx (<code className="text-slate-300">Outlier Detection</code>) và khởi động ấm <code className="text-slate-300">Slow-Start</code>.
              </div>
            </div>
            <div className="space-y-1">
              <div className="text-xs font-mono text-amber-400">Trụ cột 04 · Ferrous Panel API</div>
              <div className="text-sm font-semibold text-slate-100">ArcSwap Upsert (&lt;50µs)</div>
              <div className="text-xs text-slate-400">
                Thêm VHost, đổi nóng PHP-FPM 8.1..8.4 và cấp phát ACME SSL qua Unix Socket 0-downtime.
              </div>
            </div>
            <div className="space-y-1">
              <div className="text-xs font-mono text-amber-400">Trụ cột 05 · Đa Ngôn ngữ</div>
              <div className="text-sm font-semibold text-slate-100">PHP · Node · Python · Go</div>
              <div className="text-xs text-slate-400">
                FastCGI nhị phân, H1 Keep-Alive, gRPC H2 Trailers và đường hầm WebSocket SPLICE.
              </div>
            </div>
          </div>
        </section>

        {/* Render Active Sections */}
        {(activeSection === 'all' || activeSection === 'panel_readme') && (
          <section id="section-panel-readme">
            <FerrousPanelReadmeView />
          </section>
        )}

        {(activeSection === 'all' || activeSection === 'architecture') && (
          <section id="section-architecture">
            <ArchitectureView />
          </section>
        )}

        {(activeSection === 'all' || activeSection === 'ebpf') && (
          <section id="section-ebpf-pipeline">
            <EbpfPipelineView />
          </section>
        )}

        {(activeSection === 'all' || activeSection === 'resilience') && (
          <section id="section-resilience">
            <EnterpriseFeaturesView />
          </section>
        )}

        {(activeSection === 'all' || activeSection === 'polyglot') && (
          <section id="section-polyglot">
            <PolyglotRuntimeView />
          </section>
        )}

        {(activeSection === 'all' || activeSection === 'workspace') && (
          <section id="section-workspace">
            <WorkspaceCodeView />
          </section>
        )}

        {(activeSection === 'all' || activeSection === 'simulation') && (
          <section id="section-simulation">
            <InteractiveSimView />
          </section>
        )}

        {(activeSection === 'all' || activeSection === 'benchmark') && (
          <section id="section-benchmark">
            <BenchmarkTuningView />
          </section>
        )}
      </main>

      {/* Quiet Footer */}
      <footer className="border-t border-slate-800/80 py-6 px-6 text-center text-xs text-slate-500">
        <div className="max-w-[1380px] mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <span>FerrousX Systems Architecture Blueprint · 100% Rust (io_uring · Quinn QUIC · ArcSwap)</span>
          <button
            onClick={handleDownloadFullWorkspace}
            className="text-slate-300 hover:text-amber-400 underline underline-offset-4 transition-colors"
          >
            Tải tập lệnh khởi tạo Cargo Workspace (setup_ferrousx_workspace.sh)
          </button>
        </div>
      </footer>
    </div>
  );
}
