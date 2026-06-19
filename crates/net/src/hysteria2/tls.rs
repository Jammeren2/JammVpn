//! QUIC-клиент-конфиг для Hysteria2: rustls 0.23 на aws-lc-rs (тот же провайдер,
//! что REALITY/WG/TUIC) + ALPN `h3`. Поддерживает строгую проверку цепочки
//! (webpki-roots, для узлов с настоящими сертификатами) и `insecure`-режим.

use quinn::crypto::rustls::QuicClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{aws_lc_rs, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme};
use std::io;
use std::sync::Arc;

/// Верификатор, принимающий любой сертификат (для `insecure`-узлов). Подписи
/// проверяются, пропускается только цепочка доверия.
#[derive(Debug)]
struct InsecureVerifier {
    supported: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end: &CertificateDer<'_>,
        _inter: &[CertificateDer<'_>],
        _name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

fn io_other<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

/// Строит [`quinn::ClientConfig`] для Hysteria2 (ALPN `["h3"]`).
///
/// `insecure` — пропуск проверки цепочки сертификата (самоподписанные узлы).
/// Иначе — проверка по корням Mozilla (webpki-roots).
pub(crate) fn build_quic_client_config(insecure: bool) -> io::Result<quinn::ClientConfig> {
    let provider = Arc::new(aws_lc_rs::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(io_other)?;

    let mut tls = if insecure {
        let supported = provider.signature_verification_algorithms;
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier { supported }))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let qcc = QuicClientConfig::try_from(tls).map_err(io_other)?;
    Ok(quinn::ClientConfig::new(Arc::new(qcc)))
}
