//! Общий TUIC-туннель: одно QUIC-соединение + аутентификация; каждая цель —
//! отдельный bidi-стрим с командой Connect.

use super::config::TuicParams;
use super::proto;
use super::stream::TuicStream;
use super::tls::build_quic_client_config;
use crate::target::Target;
use crate::BoxedStream;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// Таймаут на сетевые шаги (QUIC-handshake, Authenticate, открытие стрима) —
/// quinn имеет свой handshake-таймаут, но не защищает от сервера, который
/// принимает стрим и не отдаёт flow-control (завис бы `write_all`).
const STEP_TIMEOUT: Duration = Duration::from_secs(15);

/// Запущенный TUIC-туннель (общий для всех соединений узла).
pub struct TuicTunnel {
    // Endpoint держим живым: его сброс закрыл бы соединение.
    _endpoint: quinn::Endpoint,
    conn: quinn::Connection,
}

impl TuicTunnel {
    /// Поднимает соединение: QUIC-connect → вывод токена из TLS-экспортёра →
    /// Authenticate на uni-стриме. Все сетевые шаги под таймаутом.
    pub(crate) async fn start(params: &TuicParams) -> io::Result<Arc<TuicTunnel>> {
        let server_addr = resolve_endpoint(&params.server).await?;
        let bind: SocketAddr = if server_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let mut endpoint = quinn::Endpoint::client(bind)?;
        endpoint.set_default_client_config(build_quic_client_config(
            params.insecure,
            params.alpn.clone(),
        )?);

        let sni = params
            .sni
            .clone()
            .unwrap_or_else(|| host_of(&params.server).to_string());

        // QUIC-handshake (с таймаутом — защита от зависшего сервера).
        let conn = with_timeout("QUIC-handshake", async {
            endpoint
                .connect(server_addr, &sni)
                .map_err(io_other)?
                .await
                .map_err(io_other)
        })
        .await?;

        // Токен = TLS-экспортёр(label = UUID-16-байт, context = пароль), 32 байта.
        let mut token = [0u8; 32];
        conn.export_keying_material(&mut token, &params.uuid, params.password.as_bytes())
            .map_err(|_| io::Error::other("tuic: export_keying_material не удался"))?;

        // Authenticate на uni-стриме; стрим завершаем (finish).
        let auth_pkt = proto::encode_authenticate(&params.uuid, &token);
        with_timeout("Authenticate", async {
            let mut auth = conn.open_uni().await.map_err(io_other)?;
            auth.write_all(&auth_pkt).await.map_err(io_other)?;
            auth.finish().map_err(io_other)?;
            io::Result::Ok(())
        })
        .await?;

        Ok(Arc::new(TuicTunnel {
            _endpoint: endpoint,
            conn,
        }))
    }

    /// Клон общего QUIC-соединения (для UDP-менеджера). `quinn::Connection`
    /// дешёвый в клонировании (внутри Arc).
    pub(crate) fn connection(&self) -> quinn::Connection {
        self.conn.clone()
    }

    /// Открывает bidi-стрим, шлёт Connect(target); далее — сырой канал к цели.
    ///
    /// Цель-домен передаётся серверу КАК ЕСТЬ (сервер сам резолвит — нет утечки
    /// DNS на стороне клиента, в отличие от WireGuard v0). Под таймаутом, чтобы
    /// враждебный/зависший сервер не блокировал коннект.
    pub(crate) async fn connect(&self, target: &Target) -> io::Result<BoxedStream> {
        let connect_pkt = proto::encode_connect(target)?;
        let stream = with_timeout("Connect", async {
            let (mut send, recv) = self.conn.open_bi().await.map_err(io_other)?;
            send.write_all(&connect_pkt).await.map_err(io_other)?;
            // Прокидываем Connect немедленно (как VLESS/REALITY-заголовки): иначе
            // при раннем drop без прикладных данных команда осталась бы в буфере.
            send.flush().await.map_err(io_other)?;
            io::Result::Ok(TuicStream::new(send, recv))
        })
        .await?;
        Ok(Box::new(stream))
    }
}

/// Оборачивает сетевой шаг в [`STEP_TIMEOUT`]; на истечении — `TimedOut`.
async fn with_timeout<T>(
    what: &str,
    fut: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    match tokio::time::timeout(STEP_TIMEOUT, fut).await {
        Ok(r) => r,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("tuic: таймаут шага: {what}"),
        )),
    }
}

/// Резолвит `host:port` сервера в [`SocketAddr`].
async fn resolve_endpoint(server: &str) -> io::Result<SocketAddr> {
    tokio::net::lookup_host(server)
        .await?
        .next()
        .ok_or_else(|| io::Error::other(format!("tuic: не удалось разрешить {server}")))
}

/// Извлекает host из `host:port` (для SNI). Поддерживает `[ipv6]:port` и
/// `ipv6:port` (порт — после последнего двоеточия). На пустом результате —
/// откат к исходной строке.
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

fn io_other<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}
