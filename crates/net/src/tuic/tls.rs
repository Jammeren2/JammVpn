//! QUIC-клиент-конфиг для TUIC: rustls 0.23 на aws-lc-rs (тот же провайдер, что
//! REALITY/WG — без конфликта крипто-провайдеров) + опциональный insecure-режим
//! (самоподписанные/пиннингованные сертификаты) + ALPN.

use quinn::crypto::rustls::QuicClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{aws_lc_rs, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use std::io;
use std::sync::Arc;

/// Верификатор, принимающий ЛЮБОЙ сертификат сервера (для `insecure`-узлов).
/// Подписи всё равно проверяются (только цепочка доверия пропускается).
#[derive(Debug)]
struct InsecureVerifier {
    supported: WebPkiSupportedAlgorithms,
}

impl InsecureVerifier {
    fn new(provider: &CryptoProvider) -> Self {
        Self {
            supported: provider.signature_verification_algorithms,
        }
    }
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

/// Строит [`quinn::ClientConfig`] с явным aws-lc-rs-провайдером и заданным ALPN.
///
/// При `insecure` цепочка сертификатов не проверяется (узлы с самоподписанными
/// сертификатами). Строгий путь (webpki-roots) — позже.
pub(crate) fn build_quic_client_config(
    insecure: bool,
    alpn: Vec<Vec<u8>>,
) -> io::Result<quinn::ClientConfig> {
    let provider = Arc::new(aws_lc_rs::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(io_other)?;

    let mut tls = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier::new(&provider)))
            .with_no_client_auth()
    } else {
        // TODO: строгая проверка через webpki-roots; пока требуем insecure.
        return Err(io::Error::other(
            "tuic: строгая проверка сертификата не реализована — задайте insecure",
        ));
    };
    tls.alpn_protocols = alpn;

    let qcc = QuicClientConfig::try_from(tls).map_err(io_other)?;
    Ok(quinn::ClientConfig::new(Arc::new(qcc)))
}
