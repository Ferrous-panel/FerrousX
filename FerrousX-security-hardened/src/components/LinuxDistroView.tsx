import React, { useState } from 'react';
import {
  Terminal,
  Server,
  Cpu,
  Layers,
  CheckCircle2,
  Copy,
  Check,
  Shield,
  Zap,
  HardDrive,
  Download,
  AlertTriangle,
  Flame,
  ArrowRight
} from 'lucide-react';

interface LinuxDistro {
  id: string;
  name: string;
  family: 'debian' | 'rhel' | 'alpine' | 'arch';
  versions: string[];
  kernelDefault: string;
  packageManager: string;
  installCommand: string;
  notes: string;
  ioUringSupport: 'Native SQPOLL (Tối đa)' | 'Full io_uring' | 'Static musl binary';
  features: string[];
}

const LINUX_DISTROS: LinuxDistro[] = [
  {
    id: 'ubuntu',
    name: 'Ubuntu Linux',
    family: 'debian',
    versions: ['24.04 LTS (Noble)', '22.04 LTS (Jammy)', '20.04 LTS (Focal)'],
    kernelDefault: 'Linux 6.8+ (24.04) / 5.15 (22.04)',
    packageManager: 'GitHub Repo (scripts/install.sh / make)',
    installCommand: `# 1. Cài đặt trực tiếp 1 dòng lệnh từ GitHub:
curl -fsSL https://raw.githubusercontent.com/Ferrous-panel/FerrousX/main/scripts/install.sh | sudo bash

# HOẶC clone từ GitHub và biên dịch:
git clone --depth 1 https://github.com/Ferrous-panel/FerrousX.git
cd FerrousX && sudo ./scripts/install.sh`,
    notes: 'Bản 24.04 LTS hỗ trợ hoàn hảo XDP Native Driver và io_uring SQPOLL mà không cần cấu hình kernel phụ trợ.',
    ioUringSupport: 'Native SQPOLL (Tối đa)',
    features: ['Kernel 6.8+ Native', 'AppArmor profile tích hợp', 'Tương thích sẵn PHP-FPM Ondřej Surý', 'Hỗ trợ cả x86_64 và aarch64 (ARM64)']
  },
  {
    id: 'debian',
    name: 'Debian GNU/Linux',
    family: 'debian',
    versions: ['Debian 12 (Bookworm)', 'Debian 11 (Bullseye)'],
    kernelDefault: 'Linux 6.1 LTS (Debian 12) / 5.10 (Debian 11)',
    packageManager: 'GitHub Repo (scripts/install.sh / make)',
    installCommand: `# Clone mã nguồn từ GitHub repo:
git clone --depth 1 https://github.com/Ferrous-panel/FerrousX.git
cd FerrousX
sudo ./scripts/install.sh

# Kiểm tra trạng thái máy chủ
ferrousx-ctl status`,
    notes: 'Debian 12 Bookworm là môi trường lý tưởng cho máy chủ web ổn định cao với Kernel 6.1 LTS hỗ trợ io_uring hoàn chỉnh.',
    ioUringSupport: 'Native SQPOLL (Tối đa)',
    features: ['Độ ổn định tối đa (Debian Stable)', 'Zero-Dependency runtime', 'Hỗ trợ máy chủ tối giản (minimal netinst)', 'SELinux / AppArmor ready']
  },
  {
    id: 'rhel_almalinux',
    name: 'AlmaLinux / Rocky / RHEL',
    family: 'rhel',
    versions: ['AlmaLinux 9.x / 8.x', 'Rocky Linux 9.x / 8.x', 'RHEL 9 / 8', 'CloudLinux 8/9'],
    kernelDefault: 'Linux 5.14+ (RHEL 9) / 4.18 Enterprise (RHEL 8)',
    packageManager: 'GitHub Repo (scripts/install.sh / make)',
    installCommand: `# 1. Cài đặt git và clone repo từ GitHub:
sudo dnf install -y git curl
git clone --depth 1 https://github.com/Ferrous-panel/FerrousX.git
cd FerrousX

# 2. Chạy installer tự động thiết lập SELinux & Systemd
sudo ./scripts/install.sh`,
    notes: 'Hệ điều hành tiêu chuẩn cho cPanel, DirectAdmin và máy chủ doanh nghiệp. Đi kèm module SELinux ferrousx.te cấp phép socket reuseport.',
    ioUringSupport: 'Full io_uring',
    features: ['SELinux Enforcing tương thích', 'Tích hợp mượt cPanel EA4 & DirectAdmin', 'Hỗ trợ CloudLinux CageFS', 'Hỗ trợ kiến trúc x86_64, aarch64, s390x']
  },
  {
    id: 'alpine',
    name: 'Alpine Linux (Docker / MicroVM)',
    family: 'alpine',
    versions: ['v3.20', 'v3.19', 'Edge'],
    kernelDefault: 'Linux 6.6 LTS (musl libc)',
    packageManager: 'GitHub Repo (scripts/install.sh / musl build)',
    installCommand: `# Cài đặt công cụ và clone từ GitHub
apk add --no-cache git bash curl build-base
git clone --depth 1 https://github.com/Ferrous-panel/FerrousX.git
cd FerrousX
./scripts/install.sh`,
    notes: 'Kích thước container Docker chỉ 18.4 MB! Sử dụng tệp nhị phân statically linked với musl libc, khởi động trong 12 mili-giây.',
    ioUringSupport: 'Static musl binary',
    features: ['Dung lượng siêu nhẹ (< 19MB)', 'Khởi động trong ~12ms', 'Hỗ trợ OpenRC & Container runtime', 'Không phụ thuộc glibc']
  },
  {
    id: 'arch',
    name: 'Arch Linux / Manjaro',
    family: 'arch',
    versions: ['Rolling Release (Kernel 6.10+)'],
    kernelDefault: 'Bleeding-edge Linux 6.10+',
    packageManager: 'pacman (Arch AUR: ferrousx-bin)',
    installCommand: `# Cài đặt từ kho AUR hoặc binary repo
yay -S ferrousx-bin
sudo systemctl enable --now ferrousx`,
    notes: 'Luôn chạy trên nhân Linux mới nhất, cho phép khai thác toàn bộ tập lệnh mới nhất của io_uring và BPF.',
    ioUringSupport: 'Native SQPOLL (Tối đa)',
    features: ['Kernel mới nhất thế giới', 'Hỗ trợ AVX-512 & Zen 4/5 optimizations', 'AUR Package tự động cập nhật', 'Chạy mượt cho máy chủ phát triển']
  }
];

export const LinuxDistroView: React.FC = () => {
  const [selectedDistro, setSelectedDistro] = useState<string>('ubuntu');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [probeKernelSim, setProbeKernelSim] = useState<'kernel68' | 'kernel515' | 'container_locked'>('kernel68');

  const activeDistro = LINUX_DISTROS.find((d) => d.id === selectedDistro) || LINUX_DISTROS[0];

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  return (
    <div className="space-y-12">
      {/* Section Header */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-amber-400 tracking-wide font-semibold">
              10. Tương Thích Các Bản Phân Phối Linux (OS Distribution &amp; Kernel Matrix)
            </span>
            <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              Ubuntu · Debian · AlmaLinux · Rocky · Alpine · Arch
            </span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-bold text-slate-100 tracking-tight mt-1">
            Chạy Mượt Mà Trên Mọi Hệ Điều Hành Linux Nổi Tiếng
          </h2>
          <p className="text-sm text-slate-400 mt-2 max-w-4xl">
            FerrousX được kiểm thử và đóng gói tự động cho tất cả các bản phân phối Linux phổ biến nhất hiện nay. Máy chủ tích hợp sẵn <strong>cơ chế tự động dò tìm tính năng nhân (Kernel Feature Auto-Probe)</strong> để bật tối đa <code className="text-amber-400">io_uring SQPOLL</code> và <code className="text-cyan-400">XDP eBPF</code> trên các nhân mới (Ubuntu 24.04, Debian 12, AlmaLinux 9), đồng thời <strong>tự động fallback an toàn về epoll</strong> trên các môi trường bị hạn chế quyền.
          </p>
        </div>

        {/* 1-Line Quick Install Badge */}
        <div className="p-3 bg-slate-900/90 rounded-xl border border-slate-800 shrink-0">
          <div className="text-[11px] font-mono text-slate-400 flex items-center justify-between mb-1">
            <span>Cài đặt nhanh 1 dòng lệnh:</span>
            <button
              onClick={() => handleCopy('curl -fsSL https://raw.githubusercontent.com/Ferrous-panel/FerrousX/main/scripts/install.sh | sudo bash', 'quick-install')}
              className="text-amber-400 hover:text-amber-300 flex items-center gap-1 text-[10px]"
            >
              {copiedKey === 'quick-install' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              Sao chép
            </button>
          </div>
          <code className="text-xs font-mono text-emerald-400 select-all block">
            curl -fsSL https://raw.githubusercontent.com/Ferrous-panel/FerrousX/main/scripts/install.sh | sudo bash
          </code>
        </div>
      </div>

      {/* Linux Distro Selector Tabs */}
      <div className="space-y-6">
        <div className="flex flex-wrap gap-2">
          {LINUX_DISTROS.map((distro) => {
            const isSelected = distro.id === selectedDistro;
            return (
              <button
                key={distro.id}
                onClick={() => setSelectedDistro(distro.id)}
                className={`flex items-center gap-2.5 px-4 py-2.5 rounded-xl border text-sm font-medium transition-colors ${
                  isSelected
                    ? 'bg-amber-500 text-slate-950 border-amber-500 font-semibold shadow-lg shadow-amber-500/10'
                    : 'bg-slate-900/80 text-slate-300 border-slate-800 hover:border-slate-700 hover:text-slate-100'
                }`}
              >
                <Server className="w-4 h-4 shrink-0" />
                <span>{distro.name}</span>
                <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
                  isSelected ? 'bg-slate-950/20 text-slate-950' : 'bg-slate-800 text-slate-400'
                }`}>
                  {distro.family.toUpperCase()}
                </span>
              </button>
            );
          })}
        </div>

        {/* Selected Distro Detailed Card */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 sm:p-8 space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
            {/* Left: Distro Specifications */}
            <div className="lg:col-span-6 space-y-5">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xl font-bold text-slate-100">{activeDistro.name}</h3>
                  <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-slate-400 mt-1">
                    <span>Trình quản lý gói: <strong className="text-amber-400">{activeDistro.packageManager}</strong></span>
                    <span aria-hidden="true">·</span>
                    <span>Nhân mặc định: <strong className="text-cyan-400">{activeDistro.kernelDefault}</strong></span>
                  </div>
                </div>
                <span className="px-2.5 py-1 text-xs font-mono font-semibold rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                  {activeDistro.ioUringSupport}
                </span>
              </div>

              <p className="text-sm text-slate-300 leading-relaxed">
                {activeDistro.notes}
              </p>

              {/* Supported Versions & Features */}
              <div className="space-y-3">
                <span className="text-xs font-mono text-slate-400 block">Các phiên bản hỗ trợ chính thức:</span>
                <div className="flex flex-wrap gap-2">
                  {activeDistro.versions.map((ver, idx) => (
                    <span
                      key={idx}
                      className="px-2.5 py-1 text-xs font-mono rounded bg-slate-950 text-slate-300 border border-slate-800"
                    >
                      {ver}
                    </span>
                  ))}
                </div>
              </div>

              <div className="space-y-2 pt-2 border-t border-slate-800">
                <span className="text-xs font-mono text-slate-400 block">Đặc điểm tích hợp nổi bật:</span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-slate-300">
                  {activeDistro.features.map((feat, idx) => (
                    <div key={idx} className="flex items-center gap-2">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      <span>{feat}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Right: Installation Script & Commands */}
            <div className="lg:col-span-6 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-slate-400 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-amber-400" />
                  Lệnh cài đặt cho {activeDistro.name}:
                </span>
                <button
                  onClick={() => handleCopy(activeDistro.installCommand, `install-${activeDistro.id}`)}
                  className="text-slate-400 hover:text-slate-200 text-xs flex items-center gap-1"
                >
                  {copiedKey === `install-${activeDistro.id}` ? (
                    <span className="text-emerald-400 flex items-center gap-1">
                      <Check className="w-3.5 h-3.5" /> Đã chép
                    </span>
                  ) : (
                    <span className="flex items-center gap-1">
                      <Copy className="w-3.5 h-3.5" /> Sao chép
                    </span>
                  )}
                </button>
              </div>

              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 overflow-x-auto">
                <pre className="text-xs font-mono text-amber-300 leading-relaxed">
                  {activeDistro.installCommand}
                </pre>
              </div>

              <div className="text-[11px] font-mono text-slate-500">
                Tự động tạo tệp cấu hình tại <code className="text-slate-400">/etc/ferrousx/ferrousx.toml</code> và kích hoạt systemd service.
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Kernel Feature Probing & Adaptive Fallback Matrix */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 sm:p-8 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <Cpu className="w-5 h-5 text-cyan-400" />
              Cơ Chế Tự Động Thích Ứng Nhân (Kernel Auto-Probe &amp; Fallback)
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              FerrousX khởi tạo hàm <code className="text-amber-300">probe_kernel_capabilities()</code> để tự động phát hiện khả năng của kernel lúc khởi động, đảm bảo hoạt động 100% không bao giờ gặp lỗi panic kể cả trên các VPS / Docker cũ.
            </p>
          </div>

          {/* Interactive Kernel Probe Simulator Selector */}
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs font-mono shrink-0">
            <span className="text-slate-500 px-2">Mô phỏng Kernel:</span>
            <button
              onClick={() => setProbeKernelSim('kernel68')}
              className={`px-2.5 py-1 rounded transition-colors ${
                probeKernelSim === 'kernel68' ? 'bg-emerald-500 text-slate-950 font-bold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Kernel 6.8+ (Ubuntu 24.04)
            </button>
            <button
              onClick={() => setProbeKernelSim('kernel515')}
              className={`px-2.5 py-1 rounded transition-colors ${
                probeKernelSim === 'kernel515' ? 'bg-amber-500 text-slate-950 font-bold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Kernel 5.15 (Ubuntu 22 / Alma 8)
            </button>
            <button
              onClick={() => setProbeKernelSim('container_locked')}
              className={`px-2.5 py-1 rounded transition-colors ${
                probeKernelSim === 'container_locked' ? 'bg-rose-500 text-slate-950 font-bold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Container Khóa Quyền (No CAP_BPF)
            </button>
          </div>
        </div>

        {/* Dynamic Probe Results Display */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
          <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
            <span className="text-xs font-mono text-slate-400 block">1. I/O ENGINE ĐƯỢC CHỌN</span>
            {probeKernelSim === 'kernel68' && (
              <div className="text-emerald-400 font-mono font-semibold text-sm flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4" />
                io_uring SQPOLL (0-Syscall FastPath)
              </div>
            )}
            {probeKernelSim === 'kernel515' && (
              <div className="text-amber-400 font-mono font-semibold text-sm flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4" />
                Standard io_uring (Fixed Buffers)
              </div>
            )}
            {probeKernelSim === 'container_locked' && (
              <div className="text-rose-400 font-mono font-semibold text-sm flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4" />
                Epoll Event-Loop Fallback (An toàn)
              </div>
            )}
            <p className="text-xs text-slate-400">
              {probeKernelSim === 'kernel68' && 'Tận dụng luồng kernel polling độc lập, giảm 98% overhead context switch.'}
              {probeKernelSim === 'kernel515' && 'Hoạt động ổn định trên toàn bộ nhân Linux LTS từ 5.10 trở lên.'}
              {probeKernelSim === 'container_locked' && 'Tự động hạ cấp về mô hình epoll non-blocking đa luồng để đảm bảo chạy mượt trên VPS OpenVZ/WSL.'}
            </p>
          </div>

          <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
            <span className="text-xs font-mono text-slate-400 block">2. ĐỊNH TUYẾN GÓI TIN &amp; DDOS</span>
            {probeKernelSim === 'kernel68' && (
              <div className="text-cyan-400 font-mono font-semibold text-sm flex items-center gap-1.5">
                <Zap className="w-4 h-4" />
                XDP Driver Hook + eBPF Reuseport
              </div>
            )}
            {probeKernelSim === 'kernel515' && (
              <div className="text-amber-400 font-mono font-semibold text-sm flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4" />
                SO_ATTACH_REUSEPORT_CBPF (SKF_AD_CPU)
              </div>
            )}
            {probeKernelSim === 'container_locked' && (
              <div className="text-slate-300 font-mono font-semibold text-sm flex items-center gap-1.5">
                <Shield className="w-4 h-4" />
                Kernel 4-Tuple Hash SO_REUSEPORT
              </div>
            )}
            <p className="text-xs text-slate-400">
              {probeKernelSim === 'kernel68' && 'Lọc gói tin ở tốc độ dây 100Gbps, loại bỏ cache bounce giữa các cores.'}
              {probeKernelSim === 'kernel515' && 'Cân bằng tải TCP kết nối trực tiếp vào core xử lý ngắt phần cứng.'}
              {probeKernelSim === 'container_locked' && 'Sử dụng thuật toán băm IP/Port mặc định của Linux, không cần đặc quyền CAP_BPF.'}
            </p>
          </div>

          <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
            <span className="text-xs font-mono text-slate-400 block">3. QUIC HTTP/3 TĂNG TỐC UDP</span>
            {probeKernelSim === 'kernel68' && (
              <div className="text-emerald-400 font-mono font-semibold text-sm flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4" />
                UDP GRO &amp; GSO (64KB Super-Packets)
              </div>
            )}
            {probeKernelSim === 'kernel515' && (
              <div className="text-emerald-400 font-mono font-semibold text-sm flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4" />
                UDP GSO Segmentation Offload
              </div>
            )}
            {probeKernelSim === 'container_locked' && (
              <div className="text-amber-400 font-mono font-semibold text-sm flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4" />
                Standard UDP Recvmsg/Sendmsg
              </div>
            )}
            <p className="text-xs text-slate-400">
              {probeKernelSim === 'kernel68' && 'Gộp hàng chục gói tin UDP 1400 bytes thành 1 siêu gói tin 64KB cho Quinn.'}
              {probeKernelSim === 'kernel515' && 'Phân mảnh gói tin UDP tại NIC phần cứng, giảm tiêu thụ CPU máy chủ.'}
              {probeKernelSim === 'container_locked' && 'Xử lý từng gói tin chuẩn POSIX, tương thích 100% mọi card mạng ảo.'}
            </p>
          </div>
        </div>
      </div>

      {/* Production Systemd Service Unit File */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 sm:p-8 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <HardDrive className="w-5 h-5 text-amber-400" />
              Tệp Cấu Hình Khởi Động Chuẩn Systemd (/lib/systemd/system/ferrousx.service)
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Cấu hình đặc quyền an toàn tối thiểu (<code className="text-slate-300">CapabilityBoundingSet</code>) và dỡ bỏ giới hạn bộ nhớ locked memory cho <code className="text-amber-400">io_uring</code>.
            </p>
          </div>
          <button
            onClick={() => handleCopy(`[Unit]
Description=FerrousX High-Performance Web Server & Reverse Proxy
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/ferrousx-bin /etc/ferrousx/ferrousx.toml
ExecReload=/usr/local/bin/ferrousx-ctl reload
KillMode=mixed
TimeoutStopSec=30
Restart=always
RestartSec=1s

# Tuning Limits for io_uring and 1M+ Conns
LimitNOFILE=2097152
LimitMEMLOCK=infinity
LimitNPROC=512000

# Security Capabilities
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_BPF CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_BPF CAP_NET_ADMIN
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target`, 'systemd-unit')}
            className="text-slate-400 hover:text-slate-200 text-xs flex items-center gap-1.5 px-3 py-1.5 bg-slate-950 rounded-lg border border-slate-800 shrink-0"
          >
            {copiedKey === 'systemd-unit' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            Sao chép tệp .service
          </button>
        </div>

        <pre className="p-4 bg-slate-950 rounded-xl border border-slate-800 text-xs font-mono text-emerald-300 overflow-x-auto leading-relaxed">
{`[Unit]
Description=FerrousX High-Performance Web Server & Reverse Proxy
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/ferrousx-bin /etc/ferrousx/ferrousx.toml
ExecReload=/usr/local/bin/ferrousx-ctl reload
KillMode=mixed
TimeoutStopSec=30
Restart=always
RestartSec=1s

# Tối ưu hóa giới hạn File Descriptor và Bộ nhớ Khóa cho io_uring
LimitNOFILE=2097152
LimitMEMLOCK=infinity
LimitNPROC=512000

# Đặc quyền Linux Kernel tối thiểu (Principle of Least Privilege)
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_BPF CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_BPF CAP_NET_ADMIN
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target`}
        </pre>
      </div>
    </div>
  );
};
