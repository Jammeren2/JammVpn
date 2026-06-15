//! Параметры TUIC-узла и общий (лениво поднимаемый) дескриптор исходящего.
//!
//! Как и WireGuard: `Clone` разделяет одно QUIC-соединение (движок клонирует
//! `Outbound` на каждое соединение — все клоны делят ОДИН handshake/auth, а
//! каждая цель получает свой bidi-стрим, мультиплексируемый поверх соединения).

use super::tunnel::TuicTunnel;
use super::udp::TuicUdp;
use crate::target::Target;
use crate::BoxedStream;
use std::io;
use std::sync::Arc;
use tokio::sync::OnceCell;

/// Разобранные параметры TUIC-узла.
#[derive(Clone)]
pub struct TuicParams {
    /// Адрес сервера `host:port` (UDP/QUIC).
    pub server: String,
    /// UUID клиента (16 байт).
    pub uuid: [u8; 16],
    /// Пароль (контекст для вывода токена через TLS-экспортёр).
    pub password: String,
    /// Override SNI (иначе — host из `server`).
    pub sni: Option<String>,
    /// Пропускать проверку цепочки сертификата.
    pub insecure: bool,
    /// ALPN (по умолчанию `["h3"]`).
    pub alpn: Vec<Vec<u8>>,
}

impl std::fmt::Debug for TuicParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Пароль НЕ печатаем (секрет).
        f.debug_struct("TuicParams")
            .field("server", &self.server)
            .field("sni", &self.sni)
            .field("insecure", &self.insecure)
            .finish_non_exhaustive()
    }
}

/// TUIC-исходящий: общий лениво-поднимаемый QUIC-туннель.
#[derive(Clone)]
pub struct TuicConfig {
    inner: Arc<TuicInner>,
}

struct TuicInner {
    params: TuicParams,
    tunnel: OnceCell<Arc<TuicTunnel>>,
    udp: OnceCell<Arc<TuicUdp>>,
}

impl TuicConfig {
    /// Создаёт конфиг (соединение поднимается лениво при первом коннекте).
    pub fn new(params: TuicParams) -> Self {
        Self {
            inner: Arc::new(TuicInner {
                params,
                tunnel: OnceCell::new(),
                udp: OnceCell::new(),
            }),
        }
    }

    /// Общий туннель (лениво: QUIC-connect + Authenticate при первом вызове).
    pub(crate) async fn tunnel(&self) -> io::Result<Arc<TuicTunnel>> {
        let t = self
            .inner
            .tunnel
            .get_or_try_init(|| TuicTunnel::start(&self.inner.params))
            .await?;
        Ok(Arc::clone(t))
    }

    /// Открывает TCP-поток до `target` (новый bidi-стрим + команда Connect).
    pub(crate) async fn connect_tcp(&self, target: &Target) -> io::Result<BoxedStream> {
        self.tunnel().await?.connect(target).await
    }

    /// Общий UDP-менеджер узла (лениво: поднимает туннель и запускает
    /// демультиплексор датаграмм при первом UDP-потоке).
    pub(crate) async fn udp(&self) -> io::Result<Arc<TuicUdp>> {
        let m = self
            .inner
            .udp
            .get_or_try_init(|| async {
                let tunnel = self.tunnel().await?;
                io::Result::Ok(TuicUdp::start(tunnel.connection()))
            })
            .await?;
        Ok(Arc::clone(m))
    }

    /// Параметры узла (для диагностики/тестов).
    pub fn params(&self) -> &TuicParams {
        &self.inner.params
    }
}

impl std::fmt::Debug for TuicConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TuicConfig")
            .field("server", &self.inner.params.server)
            .finish_non_exhaustive()
    }
}
