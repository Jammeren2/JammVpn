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

/// Запущенный TUIC-туннель (общий для всех соединений узла).
pub struct TuicTunnel {
    // Endpoint держим живым: его сброс закрыл бы соединение.
    _endpoint: quinn::Endpoint,
    conn: quinn::Connection,
}

impl TuicTunnel {
    /// Поднимает соединение: QUIC-connect → вывод токена из TLS-экспортёра →
    /// Authenticate на uni-стриме.
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
        let conn = endpoint
            .connect(server_addr, &sni)
            .map_err(io_other)?
            .await
            .map_err(io_other)?;

        // Токен = TLS-экспортёр(label = UUID-16-байт, context = пароль), 32 байта.
        let mut token = [0u8; 32];
        conn.export_keying_material(&mut token, &params.uuid, params.password.as_bytes())
            .map_err(|_| io::Error::other("tuic: export_keying_material не удался"))?;

        // Authenticate на uni-стриме; стрим завершаем (finish).
        let mut auth = conn.open_uni().await.map_err(io_other)?;
        auth.write_all(&proto::encode_authenticate(&params.uuid, &token))
            .await
            .map_err(io_other)?;
        auth.finish().map_err(io_other)?;

        Ok(Arc::new(TuicTunnel {
            _endpoint: endpoint,
            conn,
        }))
    }

    /// Открывает bidi-стрим, шлёт Connect(target); далее — сырой канал к цели.
    ///
    /// Цель-домен передаётся серверу КАК ЕСТЬ (сервер сам резолвит — нет утечки
    /// DNS на стороне клиента, в отличие от WireGuard v0).
    pub(crate) async fn connect(&self, target: &Target) -> io::Result<BoxedStream> {
        let (mut send, recv) = self.conn.open_bi().await.map_err(io_other)?;
        send.write_all(&proto::encode_connect(target)?)
            .await
            .map_err(io_other)?;
        Ok(Box::new(TuicStream::new(send, recv)))
    }
}

/// Резолвит `host:port` сервера в [`SocketAddr`].
async fn resolve_endpoint(server: &str) -> io::Result<SocketAddr> {
    tokio::net::lookup_host(server)
        .await?
        .next()
        .ok_or_else(|| io::Error::other(format!("tuic: не удалось разрешить {server}")))
}

/// Извлекает host из `host:port` (для SNI). Срезает скобки IPv6.
fn host_of(server: &str) -> &str {
    if let Some(rest) = server.strip_prefix('[') {
        // [ipv6]:port
        return rest.split(']').next().unwrap_or(server);
    }
    server.rsplit_once(':').map(|(h, _)| h).unwrap_or(server)
}

fn io_other<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}
