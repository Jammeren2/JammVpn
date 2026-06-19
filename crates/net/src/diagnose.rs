//! Пошаговая диагностика исходящего соединения — для кнопки «Тест соединения».
//!
//! Прогоняет через выбранный узел реальный путь как у браузера и сообщает, на
//! каком шаге рвётся: подключение к узлу (TCP + REALITY + VLESS Encryption +
//! VLESS-заголовок) → TLS-рукопожатие через туннель → HTTP-ответ. Так видно,
//! теряется ли пакет на рукопожатии узла, на TLS или дальше.

use crate::outbound::Outbound;
use crate::target::Target;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Один шаг диагностики.
pub struct DiagStep {
    pub name: String,
    pub ok: bool,
    pub detail: String,
    pub ms: u64,
}

impl DiagStep {
    fn ok(name: &str, detail: String, t: Instant) -> Self {
        Self {
            name: name.to_string(),
            ok: true,
            detail,
            ms: t.elapsed().as_millis() as u64,
        }
    }
    fn err(name: &str, detail: String, t: Instant) -> Self {
        Self {
            name: name.to_string(),
            ok: false,
            detail,
            ms: t.elapsed().as_millis() as u64,
        }
    }
}

const TEST_HOST: &str = "cp.cloudflare.com";
const TEST_PORT: u16 = 443;
const TEST_PATH: &str = "/generate_204";
const STEP_TIMEOUT: Duration = Duration::from_secs(10);

/// Прогоняет диагностику исходящего соединения по шагам.
pub async fn diagnose_outbound(ob: &Outbound) -> Vec<DiagStep> {
    let mut steps = Vec::new();
    let target = Target::Domain(TEST_HOST.to_string(), TEST_PORT);

    // Шаг 1: подключение к узлу (включает REALITY + VLESS Encryption + заголовок).
    let t = Instant::now();
    let stream = match tokio::time::timeout(STEP_TIMEOUT, ob.connect_tcp(&target)).await {
        Ok(Ok(s)) => {
            steps.push(DiagStep::ok(
                "Подключение к узлу",
                format!("TCP/REALITY/Encryption/VLESS до {TEST_HOST}:{TEST_PORT}"),
                t,
            ));
            s
        }
        Ok(Err(e)) => {
            steps.push(DiagStep::err("Подключение к узлу", e.to_string(), t));
            return steps;
        }
        Err(_) => {
            steps.push(DiagStep::err(
                "Подключение к узлу",
                "таймаут 10с (узел не отвечает / рукопожатие зависло)".into(),
                t,
            ));
            return steps;
        }
    };

    // Шаг 2: TLS-рукопожатие через туннель (здесь видна порча потока, если есть).
    let t = Instant::now();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("rustls версии протокола")
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let sni = match rustls::pki_types::ServerName::try_from(TEST_HOST) {
        Ok(s) => s,
        Err(e) => {
            steps.push(DiagStep::err("TLS-рукопожатие через туннель", e.to_string(), t));
            return steps;
        }
    };
    let mut tls = match tokio::time::timeout(STEP_TIMEOUT, connector.connect(sni, stream)).await {
        Ok(Ok(t2)) => {
            steps.push(DiagStep::ok(
                "TLS-рукопожатие через туннель",
                "сертификат и шифрование согласованы".into(),
                t,
            ));
            t2
        }
        Ok(Err(e)) => {
            steps.push(DiagStep::err(
                "TLS-рукопожатие через туннель",
                format!("{e} (вероятна порча потока в туннеле)"),
                t,
            ));
            return steps;
        }
        Err(_) => {
            steps.push(DiagStep::err(
                "TLS-рукопожатие через туннель",
                "таймаут 10с".into(),
                t,
            ));
            return steps;
        }
    };

    // Шаг 3: HTTP-ответ через туннель.
    let t = Instant::now();
    let req =
        format!("GET {TEST_PATH} HTTP/1.1\r\nHost: {TEST_HOST}\r\nConnection: close\r\n\r\n");
    let res = tokio::time::timeout(STEP_TIMEOUT, async {
        tls.write_all(req.as_bytes()).await?;
        tls.flush().await?;
        let mut buf = vec![0u8; 256];
        let n = tls.read(&mut buf).await?;
        Ok::<String, std::io::Error>(
            String::from_utf8_lossy(&buf[..n])
                .lines()
                .next()
                .unwrap_or("")
                .to_string(),
        )
    })
    .await;
    match res {
        Ok(Ok(line)) if line.starts_with("HTTP/") => {
            steps.push(DiagStep::ok("HTTP-ответ через туннель", line, t))
        }
        Ok(Ok(line)) => steps.push(DiagStep::err(
            "HTTP-ответ через туннель",
            format!("неожиданный ответ: {line:?}"),
            t,
        )),
        Ok(Err(e)) => steps.push(DiagStep::err("HTTP-ответ через туннель", e.to_string(), t)),
        Err(_) => steps.push(DiagStep::err(
            "HTTP-ответ через туннель",
            "таймаут 10с".into(),
            t,
        )),
    }
    steps
}
