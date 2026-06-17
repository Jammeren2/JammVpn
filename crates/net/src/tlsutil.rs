//! Общий rustls-клиент-конфиг с проверкой сертификата (aws-lc-rs + корни
//! Mozilla через `webpki-roots`). Используется для HTTPS-подписок, DoH и DoT,
//! а также TLS-транспорта прокси (Shadowsocks/Trojan `security=tls`).

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{aws_lc_rs, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use std::io;
use std::sync::{Arc, OnceLock};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

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

/// Верификатор, принимающий ЛЮБОЙ сертификат сервера (для `insecure`-узлов).
/// Подписи проверяются, пропускается только цепочка доверия. Для proxy-TLS это
/// норма: реальную защиту даёт внутренний слой (SS-2022/Trojan-PSK).
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

/// Клиент-конфиг для TLS-транспорта прокси с заданным ALPN. `insecure` —
/// пропустить проверку цепочки сертификата (самоподписанные / IP-узлы).
fn proxy_tls_config(insecure: bool, alpn: &[String]) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(aws_lc_rs::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("протоколы по умолчанию");
    let mut tls = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier {
                supported: provider.signature_verification_algorithms,
            }))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    tls.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    Arc::new(tls)
}

/// TLS-рукопожатие поверх уже установленного TCP. `sni` — имя сервера (для
/// IP-адреса SNI-расширение не отправляется, как требует RFC). Возвращает
/// зашифрованный поток для дальнейшего проксирующего протокола.
pub(crate) async fn proxy_tls_connect(
    tcp: TcpStream,
    sni: &str,
    insecure: bool,
    alpn: &[String],
) -> io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let cfg = proxy_tls_config(insecure, alpn);
    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|_| io::Error::other(format!("tls: некорректный SNI '{sni}'")))?;
    TlsConnector::from(cfg).connect(server_name, tcp).await
}
