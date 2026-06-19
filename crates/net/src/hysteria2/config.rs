//! Параметры Hysteria2-узла и общий (лениво поднимаемый) исходящий.
//!
//! Как TUIC/WireGuard: `Clone` разделяет одно QUIC-соединение — все клоны делят
//! один handshake/HTTP3-auth, каждая цель получает свой bidi-стрим.

use super::tunnel::Hysteria2Tunnel;
use super::udp::Hysteria2Udp;
use crate::target::Target;
use crate::BoxedStream;
use std::io;
use std::sync::Arc;
use tokio::sync::OnceCell;

/// Разобранные параметры Hysteria2-узла.
#[derive(Clone)]
pub struct Hysteria2Params {
    /// Адрес сервера `host:port` (UDP/QUIC).
    pub server: String,
    /// Строка аутентификации (заголовок `Hysteria-Auth`).
    pub auth: String,
    /// Override SNI (иначе — host из `server`).
    pub sni: Option<String>,
    /// Пропускать проверку цепочки сертификата.
    pub insecure: bool,
}

impl Hysteria2Params {
    /// Host для SNI и `:authority` (из `sni` или host части `server`).
    pub(crate) fn authority_host(&self) -> String {
        self.sni
            .clone()
            .unwrap_or_else(|| host_of(&self.server).to_string())
    }
}

impl std::fmt::Debug for Hysteria2Params {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // auth НЕ печатаем (секрет).
        f.debug_struct("Hysteria2Params")
            .field("server", &self.server)
            .field("sni", &self.sni)
            .field("insecure", &self.insecure)
            .finish_non_exhaustive()
    }
}

/// Hysteria2-исходящий: общий лениво-поднимаемый QUIC-туннель.
#[derive(Clone)]
pub struct Hysteria2Config {
    inner: Arc<Hysteria2Inner>,
}

struct Hysteria2Inner {
    params: Hysteria2Params,
    tunnel: OnceCell<Arc<Hysteria2Tunnel>>,
    udp: OnceCell<Arc<Hysteria2Udp>>,
}

impl Hysteria2Config {
    /// Создаёт конфиг (соединение поднимается лениво при первом коннекте).
    pub fn new(params: Hysteria2Params) -> Self {
        Self {
            inner: Arc::new(Hysteria2Inner {
                params,
                tunnel: OnceCell::new(),
                udp: OnceCell::new(),
            }),
        }
    }

    /// Общий туннель (лениво: QUIC-connect + HTTP3-auth при первом вызове).
    pub(crate) async fn tunnel(&self) -> io::Result<Arc<Hysteria2Tunnel>> {
        let t = self
            .inner
            .tunnel
            .get_or_try_init(|| Hysteria2Tunnel::start(&self.inner.params))
            .await?;
        Ok(Arc::clone(t))
    }

    /// Открывает TCP-поток до `target` (новый bidi-стрим + TCP-запрос `0x401`).
    pub(crate) async fn connect_tcp(&self, target: &Target) -> io::Result<BoxedStream> {
        self.tunnel().await?.connect(target).await
    }

    /// Общий UDP-менеджер узла (лениво: поднимает туннель и запускает
    /// демультиплексор датаграмм при первом UDP-потоке). Ошибка, если сервер
    /// не разрешил UDP.
    pub(crate) async fn udp(&self) -> io::Result<Arc<Hysteria2Udp>> {
        let m = self
            .inner
            .udp
            .get_or_try_init(|| async {
                let tunnel = self.tunnel().await?;
                if !tunnel.udp_allowed() {
                    return Err(io::Error::other(
                        "hysteria2: сервер запретил UDP (Hysteria-UDP != true)",
                    ));
                }
                io::Result::Ok(Hysteria2Udp::start(tunnel.connection()))
            })
            .await?;
        Ok(Arc::clone(m))
    }

    /// Параметры узла (для диагностики/тестов).
    pub fn params(&self) -> &Hysteria2Params {
        &self.inner.params
    }
}

impl std::fmt::Debug for Hysteria2Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2Config")
            .field("server", &self.inner.params.server)
            .finish_non_exhaustive()
    }
}

/// Извлекает host из `host:port` (для SNI). Поддерживает `[ipv6]:port`.
fn host_of(server: &str) -> &str {
    let host = if let Some(rest) = server.strip_prefix('[') {
        rest.split(']').next().unwrap_or(server)
    } else {
        server.rsplit_once(':').map(|(h, _)| h).unwrap_or(server)
    };
    if host.is_empty() {
        server
    } else {
        host
    }
}
