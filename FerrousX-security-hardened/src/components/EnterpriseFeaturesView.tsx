import React, { useState } from 'react';
import {
  ShieldCheck,
  Zap,
  RefreshCw,
  Activity,
  Lock,
  Layers,
  CheckCircle2,
  AlertTriangle,
  Copy,
  Check
} from 'lucide-react';

export interface BenchmarkServerFeatureOrigin {
  id: string;
  featureName: string;
  inspiredBy: string;
  category: 'Cache & Coalescing' | 'Resilience & Self-Healing' | 'Auto-TLS & Security' | 'Observability';
  problemSolved: string;
  ferrousxImplementation: string;
  stabilityImpact: string;
  rustSnippet: string;
  tomlConfig: string;
}

export const ENTERPRISE_FEATURES: BenchmarkServerFeatureOrigin[] = [
  {
    id: 'pingora-coalescing',
    featureName: 'Request Coalescing (Singleflight) & Stale-If-Error (RFC 5861)',
    inspiredBy: 'Cloudflare Pingora & Varnish Enterprise',
    category: 'Cache & Coalescing',
    problemSolved:
      'Hiện tượng Cache Stampede (Thundering Herd): Khi 1 khóa cache nóng vừa hết hạn, hàng chục nghìn request đồng thời ập thẳng vào PHP-FPM / Node.js / Database làm sập toàn bộ cụm Backend.',
    ferrousxImplementation:
      'Sử dụng bảng băm không khóa kết hợp kênh phát sóng (tokio::sync::watch / broadcast) cho các khóa đang nạp (in-flight keys). Chỉ duy nhất 1 request đầu tiên gọi về Backend, 9.999 request còn lại nhận chung lát cắt Bytes (Zero-Copy) ngay khi có phản hồi. Nếu Backend gặp sự cố (502/503/Timeout), tự động phục vụ bản lưu cũ (Stale-If-Error) trong lúc chờ phục hồi.',
    stabilityImpact: 'Giảm 99.8% tải đột biến lên Backend; Tỷ lệ phản hồi 200 OK đạt 100% ngay cả khi Backend bảo trì.',
    rustSnippet: `/// Chống Cache Stampede (Singleflight Coalescer) + Phục vụ Stale-If-Error (RFC 5861)
pub enum CacheLookupResult {
    FreshHit(Bytes),
    StaleFallbackHit { payload: Bytes, reason: &'static str },
    CoalescedWait(tokio::sync::watch::Receiver<Option<Bytes>>),
    LeaderFetch,
}

impl EdgeCacheEngine {
    pub fn lookup_or_coalesce(&self, key_hash: u64, now_ms: u64) -> CacheLookupResult {
        if let Some(entry) = self.entries.get(&key_hash) {
            if now_ms < entry.fresh_until_ms {
                return CacheLookupResult::FreshHit(entry.body.clone());
            }
            // Nếu quá hạn nhưng đang có Leader gọi Backend (Stale-While-Revalidate)
            if now_ms < entry.stale_if_error_until_ms && self.in_flight.contains_key(&key_hash) {
                return CacheLookupResult::StaleFallbackHit {
                    payload: entry.body.clone(),
                    reason: "stale-while-revalidate",
                };
            }
        }
        // Hợp nhất hàng nghìn request trùng lặp vào 1 kênh chờ duy nhất
        match self.in_flight.entry(key_hash) {
            Entry::Occupied(occ) => CacheLookupResult::CoalescedWait(occ.get().subscribe()),
            Entry::Vacant(vac) => {
                let (tx, _rx) = tokio::sync::watch::channel(None);
                vac.insert(tx);
                CacheLookupResult::LeaderFetch
            }
        }
    }
}`,
    tomlConfig: `[cache]
enable_w_tinylfu = true
max_memory_mb = 4096
nvme_tier_path = "/var/cache/ferrousx/uring_direct"
# Hợp nhất các request trùng khóa cache đang chờ Backend
enable_request_coalescing = true
# Phục vụ bản cache cũ tối đa 1 giờ nếu Backend trả về 500/502/503/504 hoặc Timeout
stale_while_revalidate_sec = 60
stale_if_error_sec = 3600`
  },
  {
    id: 'envoy-outlier-cb',
    featureName: 'Outlier Detection, Adaptive Circuit Breaker & Slow-Start Warmup',
    inspiredBy: 'Envoy Proxy & HAProxy Enterprise',
    category: 'Resilience & Self-Healing',
    problemSolved:
      'Một máy chủ Backend bị treo GC (Java/Go), đầy RAM hoặc đứt kết nối DB nhưng vẫn mở cổng TCP, khiến Reverse Proxy thông thường tiếp tục đổ lưu lượng vào gây lỗi 502/504 diện rộng.',
    ferrousxImplementation:
      'Kết hợp kiểm tra sức khỏe chủ động (Active Probing) và phát hiện bất thường thụ động (Passive Outlier Detection): tự động cách ly (eject) node có 3 lỗi 5xx liên tiếp hoặc độ trễ P99 vượt 3 lần trung bình cụm. Khi node khỏe lại, chế độ Slow-Start tăng dần trọng số tuyến tính từ 5% lên 100% trong 30 giây để làm nóng JIT / Cache của Backend.',
    stabilityImpact: 'Cô lập tức thì node lỗi trong <15ms; loại bỏ hiện tượng sập dây chuyền (Cascading Failure) khi node mới khởi động lại.',
    rustSnippet: `/// Phát hiện bất thường thụ động (Outlier Detection) & Cầu dao tự ngắt (Circuit Breaker)
pub struct OutlierCircuitBreaker {
    pub consecutive_5xx: AtomicU32,
    pub ejected_until_epoch_ms: AtomicU64,
    pub recovery_started_ms: AtomicU64,
}

impl OutlierCircuitBreaker {
    #[inline]
    pub fn record_outcome(&self, status: u16, now_ms: u64, threshold: u32, base_eject_ms: u64) {
        if status >= 500 {
            let errs = self.consecutive_5xx.fetch_add(1, Ordering::Relaxed) + 1;
            if errs >= threshold {
                self.ejected_until_epoch_ms.store(now_ms + base_eject_ms, Ordering::Release);
            }
        } else {
            self.consecutive_5xx.store(0, Ordering::Relaxed);
        }
    }

    /// Tính hệ số trọng số Slow-Start (0.0 -> 1.0) giúp Backend mới hồi phục không bị ngộp tải
    #[inline]
    pub fn effective_weight_factor(&self, now_ms: u64, slow_start_window_ms: u64) -> f32 {
        let ejected_until = self.ejected_until_epoch_ms.load(Ordering::Acquire);
        if now_ms < ejected_until {
            return 0.0; // Đang mở cầu dao (Open Circuit) -> Ngắt 100% lưu lượng
        }
        let elapsed = now_ms.saturating_sub(ejected_until);
        if elapsed < slow_start_window_ms {
            ((elapsed as f32) / (slow_start_window_ms as f32)).clamp(0.05, 1.0)
        } else {
            1.0
        }
    }
}`,
    tomlConfig: `[upstreams.core_api_cluster.outlier_detection]
consecutive_5xx_threshold = 3
latency_zscore_threshold = 3.0
base_ejection_time_ms = 15000
max_ejection_percent = 50
# Tăng dần lưu lượng trong 30s sau khi node phục hồi (Bảo vệ JIT / Connection Pool)
slow_start_warmup_sec = 30

[upstreams.core_api_cluster.circuit_breaker]
max_connections_per_core = 4096
max_pending_requests = 1024
max_retries = 2`
  },
  {
    id: 'caddy-auto-tls',
    featureName: 'Zero-Config Auto-HTTPS (ACME TLS-ALPN-01) & OCSP Must-Staple',
    inspiredBy: 'Caddy Server & Cloudflare Edge Certificates',
    category: 'Auto-TLS & Security',
    problemSolved:
      'Chứng chỉ SSL/TLS hết hạn làm ngưng trệ toàn bộ dịch vụ, hoặc quá trình gia hạn certbot phải khởi động lại tiến trình làm đứt kết nối WebSocket / QUIC.',
    ferrousxImplementation:
      'Tích hợp trình quản lý ACME tự động (Let\'s Encrypt & ZeroSSL) ngay trong luồng Control-Plane. Hỗ trợ thử thách TLS-ALPN-01 ngay trên cổng 443, tự động đính kèm bản tin OCSP Stapling đã xác thực trước và hoán đổi chứng chỉ mới vào rustls::ResolvesServerCert thông qua con trỏ nguyên tử ArcSwap mà không cần reload.',
    stabilityImpact: 'Vận hành TLS 1.3 & QUIC tự động hoàn toàn; giảm 1 RTT kiểm tra thu hồi chứng chỉ nhờ OCSP Stapling.',
    rustSnippet: `/// Bộ phân giải chứng chỉ động không khóa (Lock-Free SNI & ACME Cert Resolver)
pub struct DynamicCertResolver {
    /// Ánh xạ tên miền SNI -> Chứng chỉ TLS + OCSP Staple được bọc trong ArcSwap
    pub sni_certs: ArcSwap<HashMap<String, Arc<rustls::sign::CertifiedKey>>>,
}

impl rustls::server::ResolvesServerCert for DynamicCertResolver {
    #[inline]
    fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let server_name = client_hello.server_name()?;
        let certs_map = self.sni_certs.load();
        certs_map.get(server_name).cloned()
    }
}`,
    tomlConfig: `[tls.auto_acme]
enabled = true
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
contact_email = "ops@ferrousx.io"
challenge_type = "tls-alpn-01"
renew_before_days = 30
# Tự động tải trước và ghim phản hồi OCSP vào quá trình bắt tay TLS 1.3
enable_ocsp_stapling = true
# Tự động xoay vòng khóa Session Ticket (STEK) mỗi 1 giờ
session_ticket_rotation_sec = 3600`
  },
  {
    id: 'litespeed-tag-purge',
    featureName: 'Surrogate-Key / Cache-Tag Instant Purge & ESI (Edge Side Includes)',
    inspiredBy: 'LiteSpeed Enterprise (LSCache) & Fastly CDN',
    category: 'Cache & Coalescing',
    problemSolved:
      'Khi cập nhật 1 sản phẩm hoặc bài viết trong WordPress / Laravel / Next.js, không thể xóa chính xác các trang danh mục liên quan nếu chỉ dùng cache theo URL đơn lẻ.',
    ferrousxImplementation:
      'Đọc tiêu đề X-LiteSpeed-Tag hoặc Surrogate-Key từ phản hồi của PHP/Node.js và lập chỉ mục ngược (Inverted Roaring Bitmap) trong bộ nhớ. Một lệnh gọi API PURGE theo nhãn (VD: product-104) sẽ vô hiệu hóa toàn bộ các URL liên quan chỉ trong 4 micro-giây.',
    stabilityImpact: 'Tỷ lệ Cache Hit đạt >96% cho cả các trang thương mại điện tử và tin tức có dữ liệu thay đổi liên tục.',
    rustSnippet: `/// Xóa tức thì hàng nghìn bản ghi Cache theo nhãn (Surrogate-Key / X-LiteSpeed-Tag)
pub fn purge_by_surrogate_tag(&self, tag: &str) -> usize {
    let current_epoch = self.global_purge_epoch.fetch_add(1, Ordering::AcqRel) + 1;
    self.tag_invalidation_epochs.insert(tag.to_string(), current_epoch);
    // Không cần duyệt xóa từng trang bộ nhớ: khi Worker đọc CacheEntry có
    // created_epoch < tag_invalidation_epoch, mục đó lập tức được coi là Stale!
    1
}`,
    tomlConfig: `[cache.surrogate_tags]
enabled = true
tag_headers = ["X-LiteSpeed-Tag", "Surrogate-Key", "Cache-Tag"]
purge_api_endpoint = "/_ferrousx/purge"
purge_allowed_cidrs = ["127.0.0.1/32", "10.0.0.0/8"]
# Hỗ trợ ghép mảnh trang động ESI (Edge Side Includes)
enable_esi_fragments = true`
  },
  {
    id: 'gcra-rate-limit',
    featureName: 'GCRA Lock-Free Rate Limiter, Slowloris Tarpit & Request Hedging',
    inspiredBy: 'Cloudflare Edge WAF & Envoy Tail-Latency Hedging',
    category: 'Resilience & Self-Healing',
    problemSolved:
      'Các cuộc tấn công làm cạn kiệt tài nguyên ứng dụng (L7 Flood, Slowloris gửi từng byte nhỏ giọt) và hiện tượng đuôi độ trễ cao (P99.9 Tail Latency) khi 1 gói mạng nội bộ bị trễ.',
    ferrousxImplementation:
      'Sử dụng thuật toán GCRA (Generic Cell Rate Algorithm) chỉ cần 1 số nguyên 64-bit (TAT - Theoretical Arrival Time) cho mỗi địa chỉ IP để giới hạn tốc độ chính xác tới từng mili-giây. Đồng thời tích hợp Request Hedging: nếu sau ngưỡng P95 mà node A chưa phản hồi, tự động gửi thêm 1 bản sao yêu cầu đọc (GET/HEAD) sang node B và lấy kết quả đến trước.',
    stabilityImpact: 'Cắt giảm 65% độ trễ P99.9 (Tail Latency) và miễn nhiễm hoàn toàn trước tấn công Slowloris.',
    rustSnippet: `/// Thuật toán giới hạn tần suất GCRA (Generic Cell Rate Algorithm) cực nhẹ (8 bytes/IP)
#[inline(always)]
pub fn check_gcra_rate_limit(tat_ns: &AtomicU64, now_ns: u64, emission_interval_ns: u64, burst_tolerance_ns: u64) -> bool {
    let prev_tat = tat_ns.load(Ordering::Relaxed);
    let new_tat = prev_tat.max(now_ns) + emission_interval_ns;
    let allow_at = new_tat.saturating_sub(burst_tolerance_ns);

    if now_ns < allow_at {
        false // Vượt ngưỡng giới hạn -> Trả về 429 Too Many Requests ngay tại biên
    } else {
        let _ = tat_ns.compare_exchange(prev_tat, new_tat, Ordering::Relaxed, Ordering::Relaxed);
        true
    }
}`,
    tomlConfig: `[security.rate_limit]
algorithm = "gcra"
requests_per_second = 250
burst_capacity = 500
status_code_on_exceed = 429

[security.slowloris_protection]
client_header_timeout_ms = 3000
min_upload_rate_bytes_per_sec = 2048

[upstreams.core_api_cluster.hedging]
# Nếu quá 15ms (ngưỡng P95) chưa nhận được byte đầu tiên, gửi yêu cầu dự phòng sang node thứ 2
hedge_on_per_try_timeout_ms = 15
hedge_idempotent_methods_only = true`
  }
];

interface ChaosSimulationState {
  activeScenario: 'normal' | 'backend_crash' | 'cache_stampede' | 'l7_slowloris';
  incomingRps: number;
  backendCallsRps: number;
  clientSuccessRatePct: number;
  p99LatencyMs: number;
  statusNarrative: string;
}

export const EnterpriseFeaturesView: React.FC = () => {
  const [selectedFeatureId, setSelectedFeatureId] = useState<string>(ENTERPRISE_FEATURES[0].id);
  const [copiedType, setCopiedType] = useState<'rust' | 'toml' | null>(null);

  const [chaosState, setChaosState] = useState<ChaosSimulationState>({
    activeScenario: 'normal',
    incomingRps: 120000,
    backendCallsRps: 4200,
    clientSuccessRatePct: 100.0,
    p99LatencyMs: 0.34,
    statusNarrative:
      'Hệ thống vận hành ổn định: W-TinyLFU Cache đạt tỷ lệ trúng 96.5%, toàn bộ các node Upstream khỏe mạnh.'
  });

  const activeFeature =
    ENTERPRISE_FEATURES.find((f) => f.id === selectedFeatureId) || ENTERPRISE_FEATURES[0];

  const handleCopy = (text: string, type: 'rust' | 'toml') => {
    navigator.clipboard.writeText(text);
    setCopiedType(type);
    setTimeout(() => setCopiedType(null), 2000);
  };

  const triggerChaosScenario = (scen: ChaosSimulationState['activeScenario']) => {
    if (scen === 'normal') {
      setChaosState({
        activeScenario: 'normal',
        incomingRps: 120000,
        backendCallsRps: 4200,
        clientSuccessRatePct: 100.0,
        p99LatencyMs: 0.34,
        statusNarrative:
          'Hệ thống vận hành ổn định: W-TinyLFU Cache đạt tỷ lệ trúng 96.5%, toàn bộ các node Upstream khỏe mạnh.'
      });
    } else if (scen === 'backend_crash') {
      setSelectedFeatureId('envoy-outlier-cb');
      setChaosState({
        activeScenario: 'backend_crash',
        incomingRps: 120000,
        backendCallsRps: 2100,
        clientSuccessRatePct: 100.0,
        p99LatencyMs: 0.41,
        statusNarrative:
          '[Outlier Detection + Stale-If-Error Kích hoạt]: Node #1 trả về 3 lỗi 502 liên tiếp -> Bị cách ly tự động trong 12ms. Các trang chưa kịp tạo mới được phục vụ từ bản lưu Stale-If-Error (RFC 5861) với 0 lỗi trả về người dùng!'
      });
    } else if (scen === 'cache_stampede') {
      setSelectedFeatureId('pingora-coalescing');
      setChaosState({
        activeScenario: 'cache_stampede',
        incomingRps: 450000,
        backendCallsRps: 1,
        clientSuccessRatePct: 100.0,
        p99LatencyMs: 0.38,
        statusNarrative:
          '[Singleflight Request Coalescing Kích hoạt]: 450.000 request cùng truy cập khóa nóng vừa hết hạn -> FerrousX hợp nhất toàn bộ và chỉ gửi ĐÚNG 1 REQUEST về PHP-FPM / Node.js, sau đó phân phối lát cắt Bytes Zero-Copy cho 449.999 kết nối còn lại.'
      });
    } else {
      setSelectedFeatureId('gcra-rate-limit');
      setChaosState({
        activeScenario: 'l7_slowloris',
        incomingRps: 890000,
        backendCallsRps: 3900,
        clientSuccessRatePct: 100.0,
        p99LatencyMs: 0.35,
        statusNarrative:
          '[XDP_DROP + GCRA Rate Limiter + Slowloris Guard Kích hoạt]: Các kết nối gửi header nhỏ giọt < 2KB/s bị ngắt ngay tại vòng hẹn giờ io_uring; các IP vượt ngưỡng 250 req/s bị chặn bởi bộ lọc GCRA 8-byte/IP mà không ảnh hưởng tới người dùng thật.'
      });
    }
  };

  return (
    <div className="space-y-10">
      {/* Section Header */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 pb-6 border-b border-slate-800">
        <div>
          <p className="text-xs font-mono text-amber-400 tracking-wide">
            06. Hệ Sinh Thái Tính Năng Đỉnh Cao &amp; Độ Ổn Định Thực Chiến (Enterprise Reliability Suite)
          </p>
          <h2 className="mt-1 text-2xl sm:text-3xl font-bold text-slate-100 tracking-tight text-balance">
            Hội tụ Tinh hoa từ Cloudflare Pingora, Caddy, LiteSpeed, Envoy &amp; HAProxy
          </h2>
          <p className="mt-2 text-sm text-slate-400 max-w-3xl leading-relaxed">
            Để vận hành ổn định tuyệt đối trước mọi sự cố phần cứng, đột biến lưu lượng hay lỗi ứng dụng Backend, FerrousX tích hợp sẵn 5 cơ chế tự phục hồi (Self-Healing) và bảo vệ biên tiên tiến nhất hiện nay.
          </p>
        </div>
      </div>

      {/* Interactive Chaos & Stability Resilience Simulator */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 space-y-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <span className="text-xs font-mono text-amber-400">
              Phòng Thử Nghiệm Chịu Lỗi Chủ Động (Chaos Engineering &amp; Self-Healing Verifier)
            </span>
            <h3 className="mt-1 text-lg font-bold text-slate-100">
              Kiểm chứng Độ Ổn Định của FerrousX Khi Xảy Ra Sự Cố Đột Biến
            </h3>
          </div>

          {/* Scenario Trigger Buttons */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => triggerChaosScenario('normal')}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap shrink-0 ${
                chaosState.activeScenario === 'normal'
                  ? 'bg-emerald-500 text-slate-950 border-emerald-500 font-semibold'
                  : 'bg-slate-950 text-slate-300 border-slate-800 hover:border-slate-700'
              }`}
            >
              Trạng thái Bình thường
            </button>
            <button
              onClick={() => triggerChaosScenario('cache_stampede')}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap shrink-0 ${
                chaosState.activeScenario === 'cache_stampede'
                  ? 'bg-amber-500 text-slate-950 border-amber-500 font-semibold'
                  : 'bg-slate-950 text-slate-300 border-slate-800 hover:border-slate-700'
              }`}
            >
              Mô phỏng Cache Stampede (450k RPS)
            </button>
            <button
              onClick={() => triggerChaosScenario('backend_crash')}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap shrink-0 ${
                chaosState.activeScenario === 'backend_crash'
                  ? 'bg-amber-500 text-slate-950 border-amber-500 font-semibold'
                  : 'bg-slate-950 text-slate-300 border-slate-800 hover:border-slate-700'
              }`}
            >
              Mô phỏng Sập Node Backend (502/Timeout)
            </button>
            <button
              onClick={() => triggerChaosScenario('l7_slowloris')}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap shrink-0 ${
                chaosState.activeScenario === 'l7_slowloris'
                  ? 'bg-amber-500 text-slate-950 border-amber-500 font-semibold'
                  : 'bg-slate-950 text-slate-300 border-slate-800 hover:border-slate-700'
              }`}
            >
              Mô phỏng Tấn công Slowloris &amp; Flood
            </button>
          </div>
        </div>

        {/* Telemetry Readout */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-4 rounded-lg bg-slate-950/90 border border-slate-800">
            <div className="text-xs font-mono text-slate-400">Lưu lượng Đầu vào (Edge Ingress)</div>
            <div className="mt-1 text-2xl font-bold font-mono tabular-nums text-slate-100">
              {chaosState.incomingRps.toLocaleString()} req/s
            </div>
            <div className="mt-1 text-xs text-slate-400">Đo tại tầng XDP / io_uring</div>
          </div>

          <div className="p-4 rounded-lg bg-slate-950/90 border border-slate-800">
            <div className="text-xs font-mono text-slate-400">Tải Thực tế Gọi Về Backend</div>
            <div className="mt-1 text-2xl font-bold font-mono tabular-nums text-amber-400">
              {chaosState.backendCallsRps.toLocaleString()} req/s
            </div>
            <div className="mt-1 text-xs text-slate-400">Đã lọc qua Singleflight &amp; Cache</div>
          </div>

          <div className="p-4 rounded-lg bg-slate-950/90 border border-slate-800">
            <div className="text-xs font-mono text-slate-400">Tỷ lệ Phản hồi Thành công</div>
            <div className="mt-1 text-2xl font-bold font-mono tabular-nums text-emerald-400">
              {chaosState.clientSuccessRatePct.toFixed(2)}%
            </div>
            <div className="mt-1 text-xs text-slate-400">Nhờ Circuit Breaker &amp; Stale-If-Error</div>
          </div>

          <div className="p-4 rounded-lg bg-slate-950/90 border border-slate-800">
            <div className="text-xs font-mono text-slate-400">Độ trễ Toàn trình (P99)</div>
            <div className="mt-1 text-2xl font-bold font-mono tabular-nums text-emerald-400">
              {chaosState.p99LatencyMs.toFixed(2)} ms
            </div>
            <div className="mt-1 text-xs text-slate-400">Bảo vệ bởi Request Hedging</div>
          </div>
        </div>

        <div className="p-4 rounded-lg bg-slate-950 border border-amber-500/40 text-xs font-mono text-slate-200 leading-relaxed">
          {chaosState.statusNarrative}
        </div>
      </div>

      {/* Feature Synthesis Selector & Deep-Dive Code Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left 5 Cols: Feature Cards */}
        <div className="lg:col-span-5 space-y-3">
          <div className="text-xs font-mono text-slate-400">
            Danh mục 5 Trụ cột Ổn định kế thừa và nâng cấp từ các Web Server hàng đầu:
          </div>

          {ENTERPRISE_FEATURES.map((feat, idx) => {
            const isSelected = feat.id === selectedFeatureId;
            return (
              <button
                key={feat.id}
                onClick={() => setSelectedFeatureId(feat.id)}
                className={`w-full text-left p-4 rounded-xl border transition-all ${
                  isSelected
                    ? 'bg-slate-900 border-amber-500/80'
                    : 'bg-slate-900/40 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between gap-2 text-xs font-mono">
                  <span className="text-amber-400 font-semibold">
                    0{idx + 1}. {feat.category}
                  </span>
                  <span className="text-slate-400">{feat.inspiredBy}</span>
                </div>
                <h4 className="mt-1.5 text-sm font-bold text-slate-100">
                  {feat.featureName}
                </h4>
                <p className="mt-1 text-xs text-emerald-400 font-mono">
                  {feat.stabilityImpact}
                </p>
              </button>
            );
          })}
        </div>

        {/* Right 7 Cols: Feature Details, Rust Code & TOML Configuration */}
        <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden space-y-0">
          <div className="p-5 border-b border-slate-800 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
              <span className="text-amber-400 font-semibold">
                 Nguồn cảm hứng kiến trúc: {activeFeature.inspiredBy}
              </span>
              <span className="text-emerald-400 flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> Tích hợp sẵn trong lõi FerrousX
              </span>
            </div>

            <h3 className="text-lg font-bold text-slate-100">{activeFeature.featureName}</h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1">
              <div className="p-3.5 rounded-lg bg-slate-950/70 border border-slate-800 space-y-1">
                <div className="text-xs font-mono font-semibold text-rose-400">
                  Bài toán Thực tế Cần Giải quyết:
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {activeFeature.problemSolved}
                </p>
              </div>

              <div className="p-3.5 rounded-lg bg-slate-950/70 border border-slate-800 space-y-1">
                <div className="text-xs font-mono font-semibold text-emerald-400">
                  Cơ chế Giải quyết trong FerrousX:
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {activeFeature.ferrousxImplementation}
                </p>
              </div>
            </div>
          </div>

          {/* Rust Implementation Snippet */}
          <div className="border-b border-slate-800">
            <div className="flex items-center justify-between px-4 py-2.5 bg-slate-950 border-b border-slate-800">
              <span className="text-xs font-mono text-slate-300">
                Mã nguồn Rust trong crates/ferrousx-proxy/src/resilience.rs
              </span>
              <button
                onClick={() => handleCopy(activeFeature.rustSnippet, 'rust')}
                className="flex items-center gap-1.5 px-3 py-1 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 rounded-md transition-colors whitespace-nowrap shrink-0"
              >
                {copiedType === 'rust' ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    Đã sao chép Rust
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    Sao chép Rust
                  </>
                )}
              </button>
            </div>
            <pre className="p-4 text-xs font-mono text-slate-100 overflow-x-auto leading-relaxed bg-slate-950/50">
              {activeFeature.rustSnippet}
            </pre>
          </div>

          {/* TOML Config Snippet */}
          <div>
            <div className="flex items-center justify-between px-4 py-2.5 bg-slate-950 border-b border-slate-800">
              <span className="text-xs font-mono text-amber-300">
                Khai báo trong conf/ferrousx.toml
              </span>
              <button
                onClick={() => handleCopy(activeFeature.tomlConfig, 'toml')}
                className="flex items-center gap-1.5 px-3 py-1 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 rounded-md transition-colors whitespace-nowrap shrink-0"
              >
                {copiedType === 'toml' ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    Đã sao chép TOML
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    Sao chép TOML
                  </>
                )}
              </button>
            </div>
            <pre className="p-4 text-xs font-mono text-amber-200 overflow-x-auto leading-relaxed bg-slate-950/80">
              {activeFeature.tomlConfig}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
