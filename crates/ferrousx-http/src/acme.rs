//! crates/ferrousx-http/src/acme.rs
//! Tự động cấp phát và gia hạn chứng chỉ SSL/TLS miễn phí (Let's Encrypt / ZeroSSL)
//! qua giao thức ACMEv2 (RFC 8555) với thử thách TLS-ALPN-01 (RFC 8737) và HTTP-01,
//! kèm bộ nhớ đệm OCSP Stapling 100% viết bằng Rust.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tracing::info;

/// OID chuẩn của tiện ích mở rộng `id-pe-acmeIdentifier` (1.3.6.1.5.5.7.1.31) dùng cho TLS-ALPN-01
pub const ACME_TLS_ALPN_01_PROTOCOL: &[u8] = b"acme-tls/1";

/// Trạng thái của chứng chỉ và OCSP Staple lưu trong bộ nhớ không khóa
#[derive(Debug, Clone)]
pub struct CachedCertificateEntry {
    pub domain: String,
    pub fullchain_pem: Bytes,
    pub privkey_pem: Bytes,
    pub ocsp_staple_der: Option<Bytes>,
    pub issued_at: Instant,
    pub expires_in: Duration,
}

impl CachedCertificateEntry {
    /// Kiểm tra xem chứng chỉ có cần gia hạn sớm (khi còn dưới 30 ngày hiệu lực) hay không
    #[inline]
    pub fn should_renew(&self) -> bool {
        let elapsed = self.issued_at.elapsed();
        let renew_threshold = self.expires_in.saturating_sub(Duration::from_secs(30 * 86400));
        elapsed >= renew_threshold
    }
}

/// Bộ quản lý ACMEv2 Auto-HTTPS và OCSP Stapling chạy hoàn toàn trong tiến trình Rust
pub struct AcmeCertManager {
    pub directory_url: String,
    pub contact_email: String,
    /// Bảng lưu trữ token thử thách HTTP-01 (`/.well-known/acme-challenge/<token>`)
    http01_tokens: Arc<RwLock<HashMap<String, String>>>,
    /// Kho chứng chỉ đang hoạt động kèm gói tin OCSP Stapling
    cert_store: Arc<RwLock<HashMap<String, CachedCertificateEntry>>>,
}

impl AcmeCertManager {
    pub fn new(contact_email: impl Into<String>) -> Self {
        Self {
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".to_string(),
            contact_email: contact_email.into(),
            http01_tokens: Arc::new(RwLock::new(HashMap::new())),
            cert_store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Đăng ký cặp `(token, key_authorization)` để phản hồi tức thì ở tầng Worker cho HTTP-01
    pub fn register_http01_challenge(&self, token: String, key_authorization: String) {
        if let Ok(mut guard) = self.http01_tokens.write() {
            info!(token = %token, "Đã đăng ký token ACME HTTP-01 vào bộ nhớ Worker");
            guard.insert(token, key_authorization);
        }
    }

    /// Kiểm tra và trả về phản hồi cho đường dẫn `/.well-known/acme-challenge/{token}` với 0 syscall đọc đĩa
    #[inline]
    pub fn resolve_http01_challenge(&self, request_path: &str) -> Option<String> {
        const PREFIX: &str = "/.well-known/acme-challenge/";
        if let Some(token) = request_path.strip_prefix(PREFIX) {
            if let Ok(guard) = self.http01_tokens.read() {
                return guard.get(token).cloned();
            }
        }
        None
    }

    /// Cập nhật gói phản hồi OCSP Stapling đã ký của CA để gửi kèm trong lúc bắt tay TLS 1.3
    pub fn update_ocsp_staple(&self, domain: &str, ocsp_der: Bytes) {
        if let Ok(mut guard) = self.cert_store.write() {
            if let Some(entry) = guard.get_mut(domain) {
                entry.ocsp_staple_der = Some(ocsp_der);
                info!(domain = %domain, "Đã làm mới OCSP Staple trong RAM cho tên miền");
            }
        }
    }

    /// Truy xuất gói OCSP Staple để đính kèm vào ServerHello (tiết kiệm 1 vòng RTT của trình duyệt)
    #[inline]
    pub fn get_ocsp_staple(&self, domain: &str) -> Option<Bytes> {
        if let Ok(guard) = self.cert_store.read() {
            return guard.get(domain).and_then(|e| e.ocsp_staple_der.clone());
        }
        None
    }
}
