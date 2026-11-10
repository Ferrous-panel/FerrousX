import React, { useState } from 'react';
import {
  Terminal,
  Server,
  Cpu,
  Layers,
  CheckCircle2,
  Copy,
  Check,
  RefreshCw,
  FolderTree,
  Shield,
  Zap,
  Play,
  RotateCcw,
  Sliders,
  Flame,
  FileCode2,
  HardDrive
} from 'lucide-react';

interface TerminalHistoryItem {
  command: string;
  output: string | React.ReactNode;
  timestamp: string;
}

export const HostingIntegrationView: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'terminal' | 'cpanel' | 'directadmin' | 'plesk_aapanel'>('terminal');
  const [terminalInput, setTerminalInput] = useState<string>('ferrousx-ctl status');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Interactive Terminal Simulator State
  const [terminalHistory, setTerminalHistory] = useState<TerminalHistoryItem[]>([
    {
      command: 'ferrousx-ctl status',
      timestamp: '05:30:12',
      output: (
        <div className="space-y-2 text-xs font-mono">
          <div className="flex items-center gap-2 text-emerald-400 font-semibold">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            FerrousX Daemon v1.0.0 (x86_64-unknown-linux-gnu, Edition 2024) — ACTIVE (RUNNING)
          </div>
          <div className="text-slate-400">
            PID: 1042 · Master Uptime: 14d 6h 32m · Socket: /run/ferrousx/panel-admin.sock
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 py-1 text-slate-300">
            <div className="p-2 bg-slate-900/80 rounded border border-slate-800">
              <span className="text-slate-500 block text-[10px]">CORES PINNED</span>
              <span className="text-amber-400 font-bold">16 Threads</span> (Affinity 0-15)
            </div>
            <div className="p-2 bg-slate-900/80 rounded border border-slate-800">
              <span className="text-slate-500 block text-[10px]">TOTAL THROUGHPUT</span>
              <span className="text-emerald-400 font-bold">1,482,900 req/s</span>
            </div>
            <div className="p-2 bg-slate-900/80 rounded border border-slate-800">
              <span className="text-slate-500 block text-[10px]">ACTIVE CONNS</span>
              <span className="text-cyan-400 font-bold">48,920 H3 / 32,600 TCP</span>
            </div>
            <div className="p-2 bg-slate-900/80 rounded border border-slate-800">
              <span className="text-slate-500 block text-[10px]">MEMORY RSS</span>
              <span className="text-purple-400 font-bold">84.2 MB</span> (Arena Zero-Leak)
            </div>
          </div>
          <div className="text-slate-400 text-[11px]">
            Tích hợp bảng điều khiển: <span className="text-amber-300">Ferrous Panel</span> · <span className="text-emerald-300">cPanel EA4 Bridge</span> · <span className="text-blue-300">DirectAdmin CustomBuild</span>
          </div>
        </div>
      )
    }
  ]);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const executeCommand = (cmd: string) => {
    const trimmed = cmd.trim();
    if (!trimmed) return;

    const t = new Date();
    const timeStr = `${t.getHours().toString().padStart(2, '0')}:${t.getMinutes().toString().padStart(2, '0')}:${t.getSeconds().toString().padStart(2, '0')}`;

    let outputNode: React.ReactNode = null;

    if (trimmed === 'clear') {
      setTerminalHistory([]);
      setTerminalInput('');
      return;
    } else if (trimmed === 'ferrousx-ctl status' || trimmed === 'status') {
      outputNode = (
        <div className="space-y-1.5 text-xs font-mono">
          <div className="text-emerald-400 font-semibold">
            ● ferrousx.service - FerrousX High-Performance Web Server &amp; Reverse Proxy
          </div>
          <div className="text-slate-300">
            Loaded: loaded (/etc/systemd/system/ferrousx.service; enabled; vendor preset: enabled)
          </div>
          <div className="text-slate-300">
            Active: <span className="text-emerald-400 font-bold">active (running)</span> since Mon 2026-11-10 00:00:01 UTC
          </div>
          <div className="text-slate-400">
            Main PID: 1042 (ferrousx-bin) · IO Engine: Linux io_uring (SQPOLL, 4096 depth)
          </div>
          <div className="text-slate-400">
            Tasks: 16 (limit: 4194304) · Memory: 84.2M · CPU: 12min 38.410s
          </div>
        </div>
      );
    } else if (trimmed === 'ferrousx-ctl top' || trimmed === 'top') {
      outputNode = (
        <div className="space-y-2 text-xs font-mono">
          <div className="text-amber-400 font-semibold border-b border-slate-800 pb-1">
            FERROUSX TOP — Per-Core Shared-Nothing Realtime Monitor (Refresh 1.0s)
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-slate-300">
            <div className="p-2 bg-slate-900 rounded border border-slate-800">
              <div className="flex justify-between text-slate-400">
                <span>Core #0 [CPU: 67%]</span>
                <span className="text-emerald-400 font-bold">364k req/s</span>
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full mt-1">
                <div className="bg-emerald-500 h-1.5 rounded-full" style={{ width: '67%' }} />
              </div>
              <div className="text-[10px] text-slate-500 mt-1">SQ: 19/64 · CQ: 18/64 · Arena: 14KB/64KB</div>
            </div>
            <div className="p-2 bg-slate-900 rounded border border-slate-800">
              <div className="flex justify-between text-slate-400">
                <span>Core #1 [CPU: 69%]</span>
                <span className="text-emerald-400 font-bold">372k req/s</span>
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full mt-1">
                <div className="bg-emerald-500 h-1.5 rounded-full" style={{ width: '69%' }} />
              </div>
              <div className="text-[10px] text-slate-500 mt-1">SQ: 21/64 · CQ: 20/64 · Arena: 16KB/64KB</div>
            </div>
            <div className="p-2 bg-slate-900 rounded border border-slate-800">
              <div className="flex justify-between text-slate-400">
                <span>Core #2 [CPU: 64%]</span>
                <span className="text-emerald-400 font-bold">358k req/s</span>
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full mt-1">
                <div className="bg-emerald-500 h-1.5 rounded-full" style={{ width: '64%' }} />
              </div>
              <div className="text-[10px] text-slate-500 mt-1">SQ: 18/64 · CQ: 17/64 · Arena: 12KB/64KB</div>
            </div>
            <div className="p-2 bg-slate-900 rounded border border-slate-800">
              <div className="flex justify-between text-slate-400">
                <span>Core #3 [CPU: 71%]</span>
                <span className="text-emerald-400 font-bold">388k req/s</span>
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full mt-1">
                <div className="bg-emerald-500 h-1.5 rounded-full" style={{ width: '71%' }} />
              </div>
              <div className="text-[10px] text-slate-500 mt-1">SQ: 22/64 · CQ: 21/64 · Arena: 18KB/64KB</div>
            </div>
          </div>
          <div className="text-slate-400 text-[11px]">
            Zero-Lock: 0 Cross-Core Bounce · P99 Latency: 312µs · UDP GRO Packets: 64KB aggregated
          </div>
        </div>
      );
    } else if (trimmed.includes('panel-sync') || trimmed.includes('sync')) {
      outputNode = (
        <div className="space-y-1.5 text-xs font-mono">
          <div className="text-cyan-400 font-semibold">[AUTODETECT] Đang quét môi trường Hosting Control Panel...</div>
          <div className="text-emerald-400">✓ Phát hiện cPanel / EasyApache 4 tại /etc/apache2/conf.d</div>
          <div className="text-emerald-400">✓ Phát hiện 142 virtual hosts &amp; 8 phiên bản ea-php-fpm (8.1 - 8.4)</div>
          <div className="text-emerald-400">✓ Phát hiện DirectAdmin CustomBuild tại /usr/local/directadmin/custombuild</div>
          <div className="text-emerald-400">✓ Đã đồng bộ hóa 142 tên miền và gán socket PHP-FPM cô lập theo user</div>
          <div className="text-amber-300 font-semibold">
            [SUCCESS] Hoán đổi RCU ArcSwap hoàn tất trong 42.6 µs (Zero Downtime, 0 dropped conns).
          </div>
        </div>
      );
    } else if (trimmed.includes('vhost list')) {
      outputNode = (
        <div className="space-y-1 text-xs font-mono text-slate-300">
          <div className="text-slate-400 font-semibold grid grid-cols-12 border-b border-slate-800 pb-1">
            <span className="col-span-4">DOMAIN</span>
            <span className="col-span-3">RUNTIME</span>
            <span className="col-span-3">UPSTREAM SOCKET / PORT</span>
            <span className="col-span-2">SSL (ACME)</span>
          </div>
          <div className="grid grid-cols-12 py-1 border-b border-slate-900">
            <span className="col-span-4 text-amber-300">shop.khachhang-vip.vn</span>
            <span className="col-span-3 text-emerald-400">PHP 8.4 (FastCGI)</span>
            <span className="col-span-3 text-slate-400">unix:/run/php/u1042-php84.sock</span>
            <span className="col-span-2 text-cyan-400">TLS 1.3 + H3</span>
          </div>
          <div className="grid grid-cols-12 py-1 border-b border-slate-900">
            <span className="col-span-4 text-amber-300">api.cpanel-client.com</span>
            <span className="col-span-3 text-blue-400">Node.js (Next.js)</span>
            <span className="col-span-3 text-slate-400">127.0.0.1:3000 (Keep-Alive)</span>
            <span className="col-span-2 text-cyan-400">TLS 1.3 + H3</span>
          </div>
          <div className="grid grid-cols-12 py-1 border-b border-slate-900">
            <span className="col-span-4 text-amber-300">portal.directadmin-host.net</span>
            <span className="col-span-3 text-emerald-400">PHP 8.3 (DirectAdmin)</span>
            <span className="col-span-3 text-slate-400">unix:/usr/local/php83/sockets/admin.sock</span>
            <span className="col-span-2 text-cyan-400">TLS 1.3 + H3</span>
          </div>
        </div>
      );
    } else if (trimmed.includes('reload')) {
      outputNode = (
        <div className="text-xs font-mono space-y-1">
          <div className="text-cyan-400">Gửi tín hiệu nạp lại cấu hình tới /run/ferrousx/panel-admin.sock...</div>
          <div className="text-emerald-400 font-semibold">
            ✓ ArcSwap Atomic Pointer Swap thành công! (Thời gian RCU: 36 µs · 0 kết nối bị rớt)
          </div>
        </div>
      );
    } else if (trimmed.includes('test')) {
      outputNode = (
        <div className="text-xs font-mono space-y-1">
          <div className="text-slate-300">ferrousx: kiểm tra cú pháp tệp cấu hình /etc/ferrousx/ferrousx.toml...</div>
          <div className="text-emerald-400">ferrousx: cú pháp cấu hình ferrousx.toml là HỢP LỆ (OK)</div>
          <div className="text-emerald-400">ferrousx: kiểm tra quyền truy cập socket PHP-FPM và SSL: THÀNH CÔNG</div>
        </div>
      );
    } else if (trimmed.includes('cache purge') || trimmed.includes('purge')) {
      outputNode = (
        <div className="text-xs font-mono space-y-1">
          <div className="text-cyan-400">Thực hiện xóa bộ nhớ đệm Edge Cache (LiteSpeed / FerrousX Tag)...</div>
          <div className="text-emerald-400 font-semibold">
            ✓ Đã xóa 1,842 đối tượng cache khớp tag `lscache` trên toàn bộ 16 cores trong 1.2ms.
          </div>
        </div>
      );
    } else {
      outputNode = (
        <div className="text-xs font-mono space-y-1">
          <div className="text-slate-300">Lệnh: <code className="text-amber-400">{trimmed}</code></div>
          <div className="text-slate-400">
            Danh sách lệnh có sẵn: <span className="text-cyan-400">status</span>, <span className="text-cyan-400">top</span>, <span className="text-cyan-400">panel-sync</span>, <span className="text-cyan-400">vhost list</span>, <span className="text-cyan-400">test</span>, <span className="text-cyan-400">reload</span>, <span className="text-cyan-400">cache purge</span>, <span className="text-cyan-400">clear</span>
          </div>
        </div>
      );
    }

    setTerminalHistory((prev) => [
      ...prev,
      {
        command: trimmed,
        timestamp: timeStr,
        output: outputNode
      }
    ]);
    setTerminalInput('');
  };

  return (
    <div className="space-y-12">
      {/* Section Header */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-cyan-400 tracking-wide font-semibold">
              09. Khả Năng Tương Thích Hosting &amp; Quản Trị Terminal Server
            </span>
            <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              cPanel · DirectAdmin · Plesk · aaPanel · ferrousx-ctl CLI
            </span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-bold text-slate-100 tracking-tight mt-1">
            Đa Môi Trường Hosting Control Panel &amp; Quản Trị Máy Chủ Qua Terminal
          </h2>
          <p className="text-sm text-slate-400 mt-2 max-w-4xl">
            FerrousX được thiết kế để không chỉ chạy độc lập hoặc với <strong>Ferrous Panel</strong>, mà còn hoạt động mượt mà như một <strong>Frontend Reverse Proxy Accelerator</strong> hoặc <strong>Drop-in Replacement</strong> trên <strong>cPanel (EasyApache 4)</strong>, <strong>DirectAdmin (CustomBuild 2.0)</strong>, <strong>Plesk</strong> và <strong>aaPanel</strong>; đi kèm công cụ dòng lệnh <code className="text-amber-400">ferrousx-ctl</code> và giao diện Terminal TUI trực quan.
          </p>
        </div>

        {/* Tab Controls */}
        <div className="flex items-center gap-2 bg-slate-900/90 p-1.5 rounded-xl border border-slate-800 shrink-0">
          <button
            onClick={() => setActiveTab('terminal')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
              activeTab === 'terminal'
                ? 'bg-amber-500 text-slate-950 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            Terminal CLI (ferrousx-ctl)
          </button>
          <button
            onClick={() => setActiveTab('cpanel')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
              activeTab === 'cpanel'
                ? 'bg-amber-500 text-slate-950 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Server className="w-3.5 h-3.5" />
            cPanel (EA4)
          </button>
          <button
            onClick={() => setActiveTab('directadmin')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
              activeTab === 'directadmin'
                ? 'bg-amber-500 text-slate-950 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <HardDrive className="w-3.5 h-3.5" />
            DirectAdmin
          </button>
          <button
            onClick={() => setActiveTab('plesk_aapanel')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
              activeTab === 'plesk_aapanel'
                ? 'bg-amber-500 text-slate-950 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            Plesk &amp; aaPanel
          </button>
        </div>
      </div>

      {/* Tab 1: Terminal Server Management (ferrousx-ctl) */}
      {activeTab === 'terminal' && (
        <div className="space-y-8">
          {/* Interactive Terminal Simulator Card */}
          <div className="bg-[#05080E] border border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
            {/* Window Topbar */}
            <div className="flex items-center justify-between px-4 py-3 bg-slate-900/90 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 rounded-full bg-rose-500/80 inline-block" />
                <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block" />
                <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block" />
                <span className="text-xs font-mono text-slate-400 ml-2">
                  root@ferrousx-edge-01:~ (ferrousx-ctl v1.0.0)
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[11px] font-mono text-slate-500">
                  IPC Socket: /run/ferrousx/panel-admin.sock
                </span>
                <button
                  onClick={() => executeCommand('clear')}
                  className="px-2 py-0.5 text-[10px] font-mono text-slate-400 hover:text-slate-200 bg-slate-800 rounded"
                >
                  Xóa màn hình
                </button>
              </div>
            </div>

            {/* Quick Command Action Bar */}
            <div className="flex flex-wrap items-center gap-1.5 px-4 py-2 bg-slate-950 border-b border-slate-800/80 text-[11px] font-mono">
              <span className="text-slate-500 mr-1">Chạy nhanh:</span>
              <button
                onClick={() => executeCommand('ferrousx-ctl status')}
                className="px-2 py-1 bg-slate-900 hover:bg-slate-800 text-emerald-400 rounded border border-slate-800 hover:border-slate-700 transition-colors"
              >
                status
              </button>
              <button
                onClick={() => executeCommand('ferrousx-ctl top')}
                className="px-2 py-1 bg-slate-900 hover:bg-slate-800 text-amber-400 rounded border border-slate-800 hover:border-slate-700 transition-colors"
              >
                top (TUI Monitor)
              </button>
              <button
                onClick={() => executeCommand('ferrousx-ctl panel-sync --detect')}
                className="px-2 py-1 bg-slate-900 hover:bg-slate-800 text-cyan-400 rounded border border-slate-800 hover:border-slate-700 transition-colors"
              >
                panel-sync (cPanel/DA)
              </button>
              <button
                onClick={() => executeCommand('ferrousx-ctl vhost list')}
                className="px-2 py-1 bg-slate-900 hover:bg-slate-800 text-purple-400 rounded border border-slate-800 hover:border-slate-700 transition-colors"
              >
                vhost list
              </button>
              <button
                onClick={() => executeCommand('ferrousx-ctl reload')}
                className="px-2 py-1 bg-slate-900 hover:bg-slate-800 text-rose-400 rounded border border-slate-800 hover:border-slate-700 transition-colors"
              >
                reload (RCU &lt;50µs)
              </button>
              <button
                onClick={() => executeCommand('ferrousx-ctl test')}
                className="px-2 py-1 bg-slate-900 hover:bg-slate-800 text-slate-300 rounded border border-slate-800 hover:border-slate-700 transition-colors"
              >
                test (syntax)
              </button>
              <button
                onClick={() => executeCommand('ferrousx-ctl cache purge --tag lscache')}
                className="px-2 py-1 bg-slate-900 hover:bg-slate-800 text-orange-400 rounded border border-slate-800 hover:border-slate-700 transition-colors"
              >
                cache purge
              </button>
            </div>

            {/* Terminal Body Screen */}
            <div className="p-4 sm:p-6 space-y-4 max-h-[480px] overflow-y-auto font-mono text-sm leading-relaxed">
              {terminalHistory.map((item, index) => (
                <div key={index} className="space-y-1.5">
                  <div className="flex items-center gap-2 text-slate-400 text-xs">
                    <span className="text-emerald-400 font-bold">root@ferrousx-edge:~#</span>
                    <span className="text-slate-100">{item.command}</span>
                    <span className="text-slate-600 ml-auto text-[10px]">{item.timestamp}</span>
                  </div>
                  <div className="pl-4 border-l-2 border-slate-800/80">{item.output}</div>
                </div>
              ))}

              {/* Active Prompt Input */}
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  executeCommand(terminalInput);
                }}
                className="flex items-center gap-2 pt-2"
              >
                <span className="text-emerald-400 font-bold text-xs shrink-0">root@ferrousx-edge:~#</span>
                <input
                  type="text"
                  value={terminalInput}
                  onChange={(e) => setTerminalInput(e.target.value)}
                  placeholder="Gõ lệnh (ví dụ: ferrousx-ctl status, top, vhost list, reload)..."
                  className="w-full bg-transparent text-slate-100 focus:outline-none text-xs font-mono placeholder:text-slate-600"
                />
                <button
                  type="submit"
                  className="px-3 py-1 bg-amber-500 text-slate-950 rounded text-xs font-semibold hover:bg-amber-400 shrink-0"
                >
                  Chạy
                </button>
              </form>
            </div>
          </div>

          {/* Complete Terminal CLI Command Reference Guide */}
          <div className="space-y-4">
            <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <Sliders className="w-5 h-5 text-amber-400" />
              Bảng Tra Cứu Lệnh Quản Trị Server (ferrousx-ctl Command Cheatsheet)
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-emerald-400 font-semibold">1. GIÁM SÁT &amp; TRẠNG THÁI</span>
                  <button
                    onClick={() => handleCopy('ferrousx-ctl top\nferrousx-ctl status\nferrousx-ctl workers', 'cli-mon')}
                    className="text-slate-500 hover:text-slate-300"
                  >
                    {copiedId === 'cli-mon' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
                <p className="text-xs text-slate-400">Giám sát tải lõi CPU, socket HTTP/3, io_uring SQ/CQ.</p>
                <pre className="p-2 bg-slate-950 rounded text-[11px] font-mono text-slate-300 overflow-x-auto">
{`# Mở giao diện TUI realtime giống htop
ferrousx-ctl top

# Kiểm tra trạng thái service và memory RSS
ferrousx-ctl status

# Xem chi tiết từng luồng worker per-core
ferrousx-ctl workers --verbose`}
                </pre>
              </div>

              <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-cyan-400 font-semibold">2. TỰ ĐỘNG ĐỒNG BỘ HOSTING</span>
                  <button
                    onClick={() => handleCopy('ferrousx-ctl panel-sync --detect\nferrousx-ctl panel-sync --cpanel\nferrousx-ctl panel-sync --directadmin', 'cli-sync')}
                    className="text-slate-500 hover:text-slate-300"
                  >
                    {copiedId === 'cli-sync' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
                <p className="text-xs text-slate-400">Tự động phát hiện vHosts từ cPanel EA4 và DirectAdmin.</p>
                <pre className="p-2 bg-slate-950 rounded text-[11px] font-mono text-slate-300 overflow-x-auto">
{`# Quét và đồng bộ tự động mọi panel
ferrousx-ctl panel-sync --detect

# Đồng bộ chỉ từ cPanel EasyApache 4
ferrousx-ctl panel-sync --cpanel

# Đồng bộ từ DirectAdmin CustomBuild
ferrousx-ctl panel-sync --directadmin`}
                </pre>
              </div>

              <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-purple-400 font-semibold">3. QUẢN LÝ VHOST &amp; ROUTE</span>
                  <button
                    onClick={() => handleCopy('ferrousx-ctl vhost add example.com --php 8.4 --root /var/www/html\nferrousx-ctl vhost del example.com\nferrousx-ctl vhost list', 'cli-vhost')}
                    className="text-slate-500 hover:text-slate-300"
                  >
                    {copiedId === 'cli-vhost' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
                <p className="text-xs text-slate-400">Thêm, sửa, xóa website trực tiếp qua socket IPC.</p>
                <pre className="p-2 bg-slate-950 rounded text-[11px] font-mono text-slate-300 overflow-x-auto">
{`# Thêm website gán PHP-FPM 8.4
ferrousx-ctl vhost add example.com \\
  --php 8.4 --root /var/www/html

# Xóa website khỏi bảng định tuyến RCU
ferrousx-ctl vhost del example.com

# Liệt kê tất cả tên miền đang hoạt động
ferrousx-ctl vhost list`}
                </pre>
              </div>

              <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-rose-400 font-semibold">4. NẠP LẠI KHÔNG DOWNTIME</span>
                  <button
                    onClick={() => handleCopy('ferrousx-ctl test\nferrousx-ctl reload\nferrousx-ctl upgrade', 'cli-reload')}
                    className="text-slate-500 hover:text-slate-300"
                  >
                    {copiedId === 'cli-reload' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
                <p className="text-xs text-slate-400">Kiểm tra cú pháp và hoán đổi ArcSwap trong &lt;50 micro-giây.</p>
                <pre className="p-2 bg-slate-950 rounded text-[11px] font-mono text-slate-300 overflow-x-auto">
{`# Kiểm tra tính hợp lệ của cấu hình
ferrousx-ctl test

# Nạp lại cấu hình tức thì qua RCU (<50µs)
ferrousx-ctl reload

# Nâng cấp file nhị phân mới qua SCM_RIGHTS
ferrousx-ctl upgrade --binary /tmp/ferrousx-bin`}
                </pre>
              </div>

              <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-amber-400 font-semibold">5. BỘ NHỚ ĐỆM &amp; PURGE TAG</span>
                  <button
                    onClick={() => handleCopy('ferrousx-ctl cache purge --domain example.com\nferrousx-ctl cache purge --tag lscache\nferrousx-ctl cache stats', 'cli-cache')}
                    className="text-slate-500 hover:text-slate-300"
                  >
                    {copiedId === 'cli-cache' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
                <p className="text-xs text-slate-400">Xóa cache LiteSpeed / WordPress theo domain và tag.</p>
                <pre className="p-2 bg-slate-950 rounded text-[11px] font-mono text-slate-300 overflow-x-auto">
{`# Xóa toàn bộ cache của một domain
ferrousx-ctl cache purge --domain example.com

# Xóa theo tag (hỗ trợ LiteSpeed Cache)
ferrousx-ctl cache purge --tag F_post_42

# Xem thống kê Hit/Miss tỷ lệ bộ nhớ đệm
ferrousx-ctl cache stats`}
                </pre>
              </div>

              <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-blue-400 font-semibold">6. CHỨNG CHỈ ACME &amp; SSL</span>
                  <button
                    onClick={() => handleCopy('ferrousx-ctl ssl issue example.com\nferrousx-ctl ssl renew --all\nferrousx-ctl ssl list', 'cli-ssl')}
                    className="text-slate-500 hover:text-slate-300"
                  >
                    {copiedId === 'cli-ssl' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
                <p className="text-xs text-slate-400">Cấp phát Auto-SSL TLS-ALPN-01 và OCSP Stapling.</p>
                <pre className="p-2 bg-slate-950 rounded text-[11px] font-mono text-slate-300 overflow-x-auto">
{`# Cấp phát chứng chỉ Let's Encrypt / ZeroSSL
ferrousx-ctl ssl issue example.com

# Tự động gia hạn toàn bộ chứng chỉ sắp hết hạn
ferrousx-ctl ssl renew --all

# Liệt kê trạng thái chứng chỉ và OCSP staple
ferrousx-ctl ssl list`}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: cPanel & EasyApache 4 Integration */}
      {activeTab === 'cpanel' && (
        <div className="space-y-8">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
            <div className="lg:col-span-7 space-y-4">
              <h3 className="text-xl font-bold text-slate-100">
                Mô Hình Hoạt Động Trên cPanel (EasyApache 4)
              </h3>
              <p className="text-sm text-slate-300 leading-relaxed">
                Trên máy chủ cPanel, FerrousX hoạt động theo 2 chế độ linh hoạt mà <strong>không làm hỏng giao diện quản lý WHM</strong>:
              </p>
              <div className="space-y-3">
                <div className="p-4 bg-slate-900/80 rounded-xl border border-slate-800">
                  <span className="text-xs font-mono text-amber-400 font-semibold block mb-1">
                    Chế độ 1: Frontend Reverse Proxy Accelerator (Khuyến nghị cho WHM)
                  </span>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    FerrousX lắng nghe trực tiếp trên cổng <strong>80 (TCP)</strong> và <strong>443 (TCP TLS 1.3 &amp; UDP HTTP/3 QUIC)</strong>.
                    Toàn bộ tệp tĩnh, bộ nhớ đệm, SSL termination và định tuyến trực tiếp vào <strong>Multi-PHP FPM sockets</strong> (`/opt/cpanel/ea-php*/root/usr/var/run/php-fpm/*.sock`) do FerrousX phụ trách; các tác vụ đặc thù hoặc `.htaccess` phức tạp được chuyển tiếp vào Apache nội bộ ở cổng <strong>8080/8443</strong>.
                  </p>
                </div>

                <div className="p-4 bg-slate-900/80 rounded-xl border border-slate-800">
                  <span className="text-xs font-mono text-emerald-400 font-semibold block mb-1">
                    Chế độ 2: Drop-in Replacement Toàn Diện
                  </span>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    Tắt hoàn toàn tiến trình `httpd` của Apache, FerrousX đọc cấu hình người dùng từ `/etc/apache2/conf.d/userdata/` và `/var/cpanel/userdata/&#123;user&#125;/`, tự động phân giải cấu hình rewrite WordPress / Laravel và giao tiếp trực tiếp với PHP-FPM với thông lượng tối đa.
                  </p>
                </div>
              </div>
            </div>

            <div className="lg:col-span-5 bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-slate-400">Tập lệnh cài đặt cPanel Bridge Hook:</span>
                <button
                  onClick={() => handleCopy(`#!/bin/bash\n# /usr/local/cpanel/hooks/ferrousx_sync.sh\nsudo ferrousx-ctl panel-sync --cpanel`, 'cp-hook')}
                  className="text-slate-400 hover:text-slate-200 text-xs flex items-center gap-1"
                >
                  {copiedId === 'cp-hook' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  Sao chép
                </button>
              </div>
              <pre className="p-3 bg-slate-950 rounded-lg text-xs font-mono text-amber-300 overflow-x-auto leading-relaxed">
{`# 1. Cài đặt FerrousX từ GitHub repository
git clone --depth 1 https://github.com/Ferrous-panel/FerrousX.git
cd FerrousX && sudo ./scripts/install.sh

# 2. Thay đổi cổng Apache sang 8080 trong Tweak Settings
whmapi1 set_tweaksetting \\
  key=apache_port value=0.0.0.0:8080

# 3. Kích hoạt FerrousX ở port 80 & 443 (HTTP/3)
ferrousx-ctl panel-sync --cpanel
systemctl restart ferrousx`}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: DirectAdmin CustomBuild 2.0 Integration */}
      {activeTab === 'directadmin' && (
        <div className="space-y-8">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
            <div className="lg:col-span-7 space-y-4">
              <h3 className="text-xl font-bold text-slate-100">
                Tích Hợp Sâu Vào DirectAdmin CustomBuild 2.0
              </h3>
              <p className="text-sm text-slate-300 leading-relaxed">
                DirectAdmin sở hữu kiến trúc mô-đun hóa cao thông qua **CustomBuild 2.0**. FerrousX được tích hợp như một tùy chọn Web Server chính thức:
              </p>
              <div className="space-y-3 text-xs text-slate-300">
                <div className="p-4 bg-slate-900/80 rounded-xl border border-slate-800 space-y-1">
                  <span className="font-mono text-amber-400 font-semibold block">
                    Đồng bộ tự động Domain Hook DirectAdmin
                  </span>
                  <p>
                    Mỗi khi người dùng tạo, sửa, đổi phiên bản PHP hoặc xóa tên miền trong DirectAdmin, các tập lệnh hook tại <code className="text-slate-200">/usr/local/directadmin/scripts/custom/domain_create_post.sh</code> tự động phát bản tin IPC tới FerrousX để cập nhật vHost trong &lt;50 micro-giây.
                  </p>
                </div>
                <div className="p-4 bg-slate-900/80 rounded-xl border border-slate-800 space-y-1">
                  <span className="font-mono text-emerald-400 font-semibold block">
                    Ánh xạ Socket PHP-FPM Đa Phiên Bản
                  </span>
                  <p>
                    Tương thích với socket của CustomBuild: <code className="text-slate-200">/usr/local/php81/sockets/&#123;user&#125;.sock</code>, <code className="text-slate-200">/usr/local/php82/sockets/&#123;user&#125;.sock</code>, <code className="text-slate-200">/usr/local/php83/sockets/&#123;user&#125;.sock</code>, và <code className="text-slate-200">/usr/local/php84/sockets/&#123;user&#125;.sock</code>.
                  </p>
                </div>
              </div>
            </div>

            <div className="lg:col-span-5 bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-slate-400">Cấu hình CustomBuild DirectAdmin:</span>
                <button
                  onClick={() => handleCopy(`cd /usr/local/directadmin/custombuild\n./build set webserver ferrousx\n./build ferrousx`, 'da-cfg')}
                  className="text-slate-400 hover:text-slate-200 text-xs flex items-center gap-1"
                >
                  {copiedId === 'da-cfg' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  Sao chép
                </button>
              </div>
              <pre className="p-3 bg-slate-950 rounded-lg text-xs font-mono text-amber-300 overflow-x-auto leading-relaxed">
{`# 1. Truy cập thư mục CustomBuild
cd /usr/local/directadmin/custombuild

# 2. Đặt webserver là ferrousx
./build update
./build set webserver ferrousx
./build set php1_mode fpm
./build set php2_mode fpm

# 3. Biên dịch và nạp cấu hình vHost DirectAdmin
./build ferrousx
./build rewrite_confs`}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* Tab 4: Plesk, aaPanel & CyberPanel */}
      {activeTab === 'plesk_aapanel' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-5 bg-slate-900/70 border border-slate-800 rounded-xl space-y-3">
              <div className="flex items-center gap-2 text-emerald-400 font-semibold text-sm">
                <Server className="w-4 h-4" />
                Plesk Obsidian (Nginx Replacement Mode)
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Trên Plesk, FerrousX thay thế hoàn toàn vai trò của reverse proxy Nginx mặc định. FerrousX đọc cấu hình vHost Plesk từ <code className="text-slate-200">/var/www/vhosts/system/*/conf/vhost.conf</code>, kế thừa chứng chỉ SSL tự động của Let&apos;s Encrypt Plesk Extension và kết nối tới PHP-FPM Plesk sockets.
              </p>
              <pre className="p-2.5 bg-slate-950 rounded text-[11px] font-mono text-slate-300 overflow-x-auto">
{`# Thay thế Nginx Plesk bằng FerrousX
plesk sbin nginx_control --stop
systemctl disable nginx
ferrousx-ctl panel-sync --plesk
systemctl enable --now ferrousx`}
              </pre>
            </div>

            <div className="p-5 bg-slate-900/70 border border-slate-800 rounded-xl space-y-3">
              <div className="flex items-center gap-2 text-cyan-400 font-semibold text-sm">
                <Layers className="w-4 h-4" />
                aaPanel &amp; CyberPanel (One-Click Acceleration)
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Tương thích hoàn hảo với tệp cấu hình website của aaPanel tại <code className="text-slate-200">/www/server/panel/vhost/</code> và socket PHP tại <code className="text-slate-200">/tmp/php-cgi-*.sock</code>. Kích hoạt bộ nhớ đệm LiteSpeed Cache Tag tự động mà không cần cài đặt OpenLiteSpeed.
              </p>
              <pre className="p-2.5 bg-slate-950 rounded text-[11px] font-mono text-slate-300 overflow-x-auto">
{`# Kích hoạt trên aaPanel
ferrousx-ctl panel-sync --aapanel
# Tự động reload khi người dùng thêm domain trong aaPanel
ferrousx-ctl watch /www/server/panel/vhost/`}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
