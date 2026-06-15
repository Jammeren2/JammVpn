//! Общий rustls-клиент-конфиг с проверкой сертификата (aws-lc-rs + корни
//! Mozilla через `webpki-roots`). Используется для HTTPS-подписок, DoH и DoT.

use std::sync::{Arc, OnceLock};

/// Возвращает разделяемый [`rustls::ClientConfig`] (строится один раз).
pub(crate) fn verified_client_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("протоколы по умолчанию")
            .with_root_certificates(roots)
            .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}
