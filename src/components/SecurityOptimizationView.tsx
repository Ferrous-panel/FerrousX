import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Zap,
  Cpu,
  Server,
  Lock,
  CheckCircle2,
  AlertTriangle,
  Copy,
  Check,
  Terminal,
  Flame,
  Layers,
  ArrowRight,
  TrendingUp,
  FileCode2,
  HardDrive
} from 'lucide-react';

interface SecurityCheckItem {
  id: string;
  category: 'network' | 'protocol' | 'waf' | 'os_sandbox';
  title: string;
  mitigation: string;
  status: 'PROTECTED (Active)' | 'ENABLED';
  cveOrStandard?: string;
  detail: string;
}

const SECURITY_CHECKS: SecurityCheckItem[] = [
  {
    id: 'xdp-l4',
    category: 'network',
    title: 'XDP Native L4 Anti-DDoS Filter',
    mitigation: 'Lọc và drop gói tin độc hại trong ~28ns trước khi cấp phát sk_buff',
    status: 'PROTECTED (Active)',
    detail: 'Sử dụng eBPF LPM Trie map để chặn dải IP blacklist và rate-limit ICMP/UDP flood ngay tại tầng driver của card mạng.'
  },
  {
    id: 'syn-flood',
    category: 'network',
    title: 'TCP Syncookies & Anti-Spoofing (RP Filter)',
    mitigation: 'net.ipv4.tcp_syncookies = 1 & net.ipv4.conf.all.rp_filter = 1',
    status: 'PROTECTED (Active)',
    detail: 'Ngăn chặn tràn hàng đợi SYN backlog khi bị flood; Reverse Path Filtering loại bỏ triệt để các gói tin giả mạo IP nguồn.'
  },
  {
    id: 'bpf-jit-harden',
    category: 'network',
    title: 'eBPF JIT Compiler Hardening',
    mitigation: 'net.core.bpf_jit_harden = 2 (Chống Spectre / BPF exploitation)',
    status: 'PROTECTED (Active)',
    detail: 'Làm mù hằng số (constant blinding) đối với các lệnh JIT eBPF, ngăn chặn kẻ tấn công lợi dụng lỗ hổng vi kiến trúc CPU.'
  },
  {
    id: 'cve-rapid-reset',
    category: 'protocol',
    title: 'HTTP/2 Rapid Reset Defense',
    mitigation: 'Giới hạn số lượng khung RST_STREAM đồng thời trên 1 kết nối (Max 100/sec)',
    status: 'PROTECTED (Active)',
    cveOrStandard: 'CVE-2023-44487',
    detail: 'Tự động phát hiện và ngắt kết nối (GOAWAY) ngay khi client gửi bão luồng RST_STREAM liên tục để làm nghẽn CPU máy chủ.'
  },
  {
    id: 'cve-continuation',
    category: 'protocol',
    title: 'HTTP/2 CONTINUATION Flood Shield',
    mitigation: 'Chặn chuỗi CONTINUATION frames vô tận không có END_HEADERS',
    status: 'PROTECTED (Active)',
    cveOrStandard: 'CVE-2024-27983',
    detail: 'Thiết lập giới hạn kích thước header 64KB và đếm số lượng frame trung gian; ngắt ngay kết nối nếu vi phạm.'
  },
  {
    id: 'quic-anti-amp',
    category: 'protocol',
    title: 'HTTP/3 QUIC Anti-Amplification (3x Factor)',
    mitigation: 'Chặn khuếch đại UDP bằng cơ chế kiểm chứng địa chỉ nguồn (RFC 9000)',
    status: 'PROTECTED (Active)',
    detail: 'Máy chủ chỉ gửi tối đa 3 lần lượng byte nhận được trước khi hoàn tất bắt tay TLS 1.3, triệt tiêu nguy cơ bị lợi dụng làm bàn đạp DDoS.'
  },
  {
    id: 'slowloris',
    category: 'waf',
    title: 'Anti-Slowloris & Slow-POST Protection',
    mitigation: 'Min-transfer rate threshold 500 bytes/s & Header timeout 5 giây',
    status: 'PROTECTED (Active)',
    detail: 'Rút ngắn vòng lặp chờ header; tự động giải phóng socket nếu client gửi dữ liệu nhỏ giọt cố tình chiếm dụng file descriptor.'
  },
  {
    id: 'sqli-xss-waf',
    category: 'waf',
    title: 'Embedded Low-Latency Regex AST WAF',
    mitigation: 'Kiểm tra SQLi, XSS, Path Traversal (../, /etc/passwd) trong < 15µs',
    status: 'PROTECTED (Active)',
    detail: 'Bộ lọc nhúng viết bằng Rust không cấp phát bộ nhớ (Zero-Allocation AST scanner), ngăn chặn các payload khai thác web phổ biến.'
  },
  {
    id: 'security-headers',
    category: 'waf',
    title: 'Tự Động Bổ Sung Security Headers & Cloak Server',
    mitigation: 'HSTS 2 năm, nosniff, SAMEORIGIN, CSP & Ẩn hoàn toàn Server version',
    status: 'PROTECTED (Active)',
    detail: 'Tự động chèn Strict-Transport-Security, X-Content-Type-Options; loại bỏ header phiên bản hệ điều hành để tránh bị thu thập fingerprint.'
  },
  {
    id: 'systemd-sandbox',
    category: 'os_sandbox',
    title: 'Linux Systemd Service Sandboxing',
    mitigation: 'ProtectSystem=strict, ProtectHome=read-only, PrivateTmp=true',
    status: 'PROTECTED (Active)',
    detail: 'Khóa chặt hệ thống tệp chỉ đọc (Read-Only) ngoại trừ thư mục log và socket; ngăn chặn mã độc ghi vào /bin, /usr, /root.'
  },
  {
    id: 'seccomp-caps',
    category: 'os_sandbox',
    title: 'Quyền Hạn Tối Thiểu (Least Privilege) & Seccomp',
    mitigation: 'Chỉ giữ CAP_NET_BIND_SERVICE, CAP_BPF, CAP_NET_ADMIN',
    status: 'PROTECTED (Active)',
    detail: 'NoNewPrivileges=true ngăn chặn leo thang quyền; cấm toàn bộ syscall can thiệp nhân không liên quan qua Seccomp native.'
  }
];

export const SecurityOptimizationView: React.FC = () => {
  const [activeCategory, setActiveCategory] = useState<'all' | 'network' | 'protocol' | 'waf' | 'os_sandbox'>('all');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const filteredChecks = SECURITY_CHECKS.filter(
    (c) => activeCategory === 'all' || c.category === activeCategory
  );

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  return (
    <div className="space-y-12">
      {/* Header & Overall Security Score Card */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-emerald-400 tracking-wide font-semibold">
              11. Tăng Cường Bảo Mật &amp; Tối Ưu Hóa Nhân Máy Chủ (Hardening &amp; Deep Tuning)
            </span>
            <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              Grade A+ (98/100) · CVE-Proof · NUMA &amp; HugePages Ready
            </span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-bold text-slate-100 tracking-tight mt-1">
            Bảo Mật Cấp Doanh Nghiệp &amp; Khai Thác Triệt Để Phần Cứng Máy Chủ
          </h2>
          <p className="text-sm text-slate-400 mt-2 max-w-4xl">
            FerrousX tích hợp sẵn các lớp phòng thủ chống tấn công mạng từ tầng <strong>XDP L4 eBPF</strong>, kháng bão <strong>HTTP/2 Rapid Reset (CVE-2023-44487)</strong> và <strong>CONTINUATION Flood (CVE-2024-27983)</strong>; kết hợp tối ưu hóa phần cứng chuyên sâu (<strong>2MB HugePages</strong>, <strong>NUMA Node Affinity</strong>, <strong>CPU Performance Governor</strong> và <strong>128MB UDP QUIC Buffers</strong>).
          </p>
        </div>

        {/* 1-Click Run Hardening Script Button */}
        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={() => handleCopy('sudo ./scripts/security-hardening.sh', 'hardening-cmd')}
            className="flex items-center gap-2 px-4 py-2 text-xs font-semibold text-slate-950 bg-emerald-400 rounded-lg hover:bg-emerald-300 transition-colors whitespace-nowrap"
          >
            {copiedKey === 'hardening-cmd' ? <Check className="w-3.5 h-3.5" /> : <Terminal className="w-3.5 h-3.5" />}
            Sao chép lệnh kích hoạt: sudo ./scripts/security-hardening.sh
          </button>
        </div>
      </div>

      {/* Top 4 Performance & Hardware Tuning Highlights */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 bg-slate-900/60 rounded-xl border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-xs font-mono text-emerald-400">
            <span className="flex items-center gap-1.5 font-semibold">
              <Cpu className="w-4 h-4" /> 2MB HUGEPAGES
            </span>
            <span className="text-slate-400">madvise</span>
          </div>
          <div className="text-lg font-bold text-slate-100">Giảm 80% TLB Cache Misses</div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Ánh xạ vùng nhớ vòng đệm <code className="text-slate-300">io_uring</code> qua trang nhớ 2MB thay vì 4KB thông thường, giúp CPU nạp con trỏ mạng tức thì.
          </p>
        </div>

        <div className="p-5 bg-slate-900/60 rounded-xl border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-xs font-mono text-amber-400">
            <span className="flex items-center gap-1.5 font-semibold">
              <Zap className="w-4 h-4" /> CPU GOVERNOR
            </span>
            <span className="text-slate-400">performance</span>
          </div>
          <div className="text-lg font-bold text-slate-100">Khóa Turbo &amp; 0 C-State Lag</div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Khóa tần số CPU ở mức tối đa trên mọi lõi, triệt tiêu thời gian chuyển đổi trạng thái ngủ (C-state latency) khi có đợt sóng request ập đến.
          </p>
        </div>

        <div className="p-5 bg-slate-900/60 rounded-xl border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-xs font-mono text-cyan-400">
            <span className="flex items-center gap-1.5 font-semibold">
              <Layers className="w-4 h-4" /> NUMA NODE AFFINITY
            </span>
            <span className="text-slate-400">Local Socket</span>
          </div>
          <div className="text-lg font-bold text-slate-100">0 Cross-Bus RAM Latency</div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Worker chạy trên CPU Socket #0 chỉ cấp phát RAM trên thanh nhớ cục bộ của Socket #0, loại bỏ hoàn toàn độ trễ xe buýt liên socket QPI/UPI.
          </p>
        </div>

        <div className="p-5 bg-slate-900/60 rounded-xl border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-xs font-mono text-purple-400">
            <span className="flex items-center gap-1.5 font-semibold">
              <HardDrive className="w-4 h-4" /> 128MB UDP BUFFERS
            </span>
            <span className="text-slate-400">rmem_max</span>
          </div>
          <div className="text-lg font-bold text-slate-100">HTTP/3 QUIC Không Rơi Gói</div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Mở rộng hàng đợi nhận UDP lên 128MB kết hợp GRO/GSO gộp gói 64KB, ngăn chặn hiện tượng drop gói tin khi lưu lượng bùng nổ hàng triệu RPS.
          </p>
        </div>
      </div>

      {/* Category Filter Tabs */}
      <div className="space-y-6">
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => setActiveCategory('all')}
            className={`px-3.5 py-1.5 text-xs font-medium rounded-lg border transition-colors ${
              activeCategory === 'all'
                ? 'bg-amber-500 text-slate-950 border-amber-500 font-semibold'
                : 'bg-slate-900/80 text-slate-300 border-slate-800 hover:border-slate-700'
            }`}
          >
            Tất Cả Hạng Mục Bảo Mật (11 Checks)
          </button>
          <button
            onClick={() => setActiveCategory('network')}
            className={`px-3.5 py-1.5 text-xs font-medium rounded-lg border transition-colors ${
              activeCategory === 'network'
                ? 'bg-amber-500 text-slate-950 border-amber-500 font-semibold'
                : 'bg-slate-900/80 text-slate-300 border-slate-800 hover:border-slate-700'
            }`}
          >
            Network &amp; DDoS (XDP, SYN Flood, BPF)
          </button>
          <button
            onClick={() => setActiveCategory('protocol')}
            className={`px-3.5 py-1.5 text-xs font-medium rounded-lg border transition-colors ${
              activeCategory === 'protocol'
                ? 'bg-amber-500 text-slate-950 border-amber-500 font-semibold'
                : 'bg-slate-900/80 text-slate-300 border-slate-800 hover:border-slate-700'
            }`}
          >
            HTTP/2 &amp; HTTP/3 CVE Defense
          </button>
          <button
            onClick={() => setActiveCategory('waf')}
            className={`px-3.5 py-1.5 text-xs font-medium rounded-lg border transition-colors ${
              activeCategory === 'waf'
                ? 'bg-amber-500 text-slate-950 border-amber-500 font-semibold'
                : 'bg-slate-900/80 text-slate-300 border-slate-800 hover:border-slate-700'
            }`}
          >
            WAF, Slowloris &amp; Security Headers
          </button>
          <button
            onClick={() => setActiveCategory('os_sandbox')}
            className={`px-3.5 py-1.5 text-xs font-medium rounded-lg border transition-colors ${
              activeCategory === 'os_sandbox'
                ? 'bg-amber-500 text-slate-950 border-amber-500 font-semibold'
                : 'bg-slate-900/80 text-slate-300 border-slate-800 hover:border-slate-700'
            }`}
          >
            Linux OS Sandboxing &amp; Seccomp
          </button>
        </div>

        {/* Security Checks List Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredChecks.map((check) => (
            <div
              key={check.id}
              className="p-5 bg-slate-900/60 rounded-xl border border-slate-800 space-y-3"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-bold text-slate-100">{check.title}</span>
                    {check.cveOrStandard && (
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-rose-500/10 text-rose-400 border border-rose-500/30">
                        {check.cveOrStandard}
                      </span>
                    )}
                  </div>
                  <div className="text-xs font-mono text-emerald-400">
                    {check.mitigation}
                  </div>
                </div>
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 shrink-0">
                  <CheckCircle2 className="w-3 h-3" />
                  {check.status}
                </span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed border-t border-slate-800/80 pt-2">
                {check.detail}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Linux Systemd Sandboxing Deep Dive Card */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 sm:p-8 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <Lock className="w-5 h-5 text-emerald-400" />
              Cách Ly Tuyệt Đối Với Linux Systemd Sandboxing (Zero Exploit Surface)
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Kể cả khi mã nguồn website PHP/Node.js của người dùng bị dính lỗ hổng bảo mật, tiến trình FerrousX vẫn được cô lập hoàn toàn và không thể bị chiếm quyền root.
            </p>
          </div>
          <button
            onClick={() => handleCopy(`sudo ./scripts/security-hardening.sh`, 'copy-script-btn')}
            className="text-xs font-mono text-emerald-400 hover:text-emerald-300 flex items-center gap-1.5 px-3 py-1.5 bg-slate-950 rounded-lg border border-slate-800 shrink-0"
          >
            {copiedKey === 'copy-script-btn' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
            Sao chép script
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono text-slate-300 pt-2">
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
            <span className="text-amber-400 font-semibold block">ProtectSystem=strict</span>
            <span className="text-slate-400 text-[11px] block">
              Gắn cờ chỉ đọc (Read-Only) cho toàn bộ hệ thống file `/usr`, `/bin`, `/boot`, `/etc`.
            </span>
          </div>
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
            <span className="text-cyan-400 font-semibold block">MemoryDenyWriteExecute=true</span>
            <span className="text-slate-400 text-[11px] block">
              Chống tấn công chèn mã thực thi W^X (Write XOR Execute) trên vùng nhớ heap/stack.
            </span>
          </div>
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
            <span className="text-emerald-400 font-semibold block">PrivateTmp=true &amp; PrivateDevices</span>
            <span className="text-slate-400 text-[11px] block">
              Cách ly thư mục /tmp riêng biệt và chặn truy cập thiết bị phần cứng /dev.
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
