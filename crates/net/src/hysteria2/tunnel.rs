//! Общий Hysteria2-туннель: одно QUIC-соединение + HTTP/3-аутентификация;
//! каждая цель — отдельный bidi-стрим с TCP-запросом `0x401`.

use super::config::Hysteria2Params;
use super::http3::{self, H3Guard};
use super::proto;
use super::stream::Hysteria2Stream;
use super::tls::build_quic_client_config;
use crate::target::Target;
use crate::BoxedStream;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// Таймаут на сетевые шаги (handshake, auth, открытие стрима).
const STEP_TIMEOUT: Duration = Duration::from_secs(15);

/// Запущенный Hysteria2-туннель (общий для всех соединений узла).
pub struct Hysteria2Tunnel {
    // Endpoint держим живым: его сброс закрыл бы соединение.
    _endpoint: quinn::Endpoint,
    // Удерживает h3-драйвер/SendRequest, пока жив туннель.
    _h3: H3Guard,
    conn: quinn::Connection,
}

impl Hysteria2Tunnel {
    /// Поднимает соединение: QUIC-connect → HTTP/3 `POST /auth`.
    pub(crate) async fn start(params: &Hysteria2Params) -> io::Result<Arc<Hysteria2Tunnel>> {
        let server_addr = resolve_endpoint(&params.server).await?;
        let bind: SocketAddr = if server_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let mut endpoint = quinn::Endpoint::client(bind)?;
        endpoint.set_default_client_config(build_quic_client_config(params.insecure)?);

        let sni = params.authority_host();

        let conn = with_timeout("QUIC-handshake", async {
            endpoint
                .connect(server_addr, &sni)
                .map_err(io_other)?
                .await
                .map_err(io_other)
        })
        .await?;

        // HTTP/3-аутентификация поверх клона соединения; conn остаётся для
        // сырых прокси-стримов (quinn::Connection дешёвый в клонировании).
        let (_auth, h3) = with_timeout("HTTP3-auth", http3::authenticate(conn.clone(), params)).await?;

        Ok(Arc::new(Hysteria2Tunnel {
            _endpoint: endpoint,
            _h3: h3,
            conn,
        }))
    }

    /// Открывает bidi-стрим, шлёт TCP-запрос, читает ответ сервера, затем —
    /// сырой канал к цели. Под таймаутом на установочную фазу.
    pub(crate) async fn connect(&self, target: &Target) -> io::Result<BoxedStream> {
        let request = proto::encode_tcp_request(target);
        let stream = with_timeout("Connect", async {
            let (mut send, mut recv) = self.conn.open_bi().await.map_err(io_other)?;
            send.write_all(&request).await.map_err(io_other)?;
            send.flush().await.map_err(io_other)?;
            // Сервер отвечает status/msg/padding ДО проксируемых данных.
            let resp = proto::read_tcp_response(&mut recv).await?;
            if !resp.ok {
                return Err(io::Error::other(format!(
                    "hysteria2: сервер отклонил соединение: {}",
                    resp.message
                )));
            }
            io::Result::Ok(Hysteria2Stream::new(send, recv))
        })
        .await?;
        Ok(Box::new(stream))
    }
}

/// Оборачивает сетевой шаг в [`STEP_TIMEOUT`].
async fn with_timeout<T>(
    what: &str,
    fut: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    match tokio::time::timeout(STEP_TIMEOUT, fut).await {
        Ok(r) => r,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("hysteria2: таймаут шага: {what}"),
        )),
    }
}

/// Резолвит `host:port` сервера в [`SocketAddr`].
async fn resolve_endpoint(server: &str) -> io::Result<SocketAddr> {
    tokio::net::lookup_host(server)
        .await?
        .next()
        .ok_or_else(|| io::Error::other(format!("hysteria2: не удалось разрешить {server}")))
}

fn io_other<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}
