//! Локальный SOCKS5-сервер (inbound) — цель перенаправления WFP-драйвера.
//!
//! Принимает соединения по SOCKS5 (без аутентификации, команда CONNECT) и
//! проксирует их через [`Outbound`]. Рукопожатие и relay вынесены в
//! `pub(crate)`-хелперы — их переиспользует движок маршрутизации ([`crate::engine`]).

use crate::outbound::Outbound;
use crate::target::Target;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Обслуживает входящие SOCKS5-соединения, проксируя их через один `outbound`.
pub async fn serve_socks(listener: TcpListener, outbound: Arc<Outbound>) -> io::Result<()> {
    loop {
        let (client, _) = listener.accept().await?;
        let ob = Arc::clone(&outbound);
        tokio::spawn(async move {
            let _ = handle_client(client, ob).await;
        });
    }
}

async fn handle_client(mut client: TcpStream, outbound: Arc<Outbound>) -> io::Result<()> {
    match socks_handshake(&mut client).await? {
        SocksRequest::Connect(target) => relay_through(client, &outbound, &target).await,
        // Одиночный исходящий не маршрутизирует UDP — отвечаем «не поддерживается».
        SocksRequest::UdpAssociate => {
            client.write_all(&reply(0x07)).await?;
            Ok(())
        }
    }
}

/// Запрос клиента после SOCKS5-рукопожатия.
pub(crate) enum SocksRequest {
    /// CONNECT к цели (TCP).
    Connect(Target),
    /// UDP ASSOCIATE (DST в запросе — подсказка источника, игнорируется).
    UdpAssociate,
}

/// SOCKS5-рукопожатие (no-auth). Поддерживает CONNECT и UDP ASSOCIATE.
pub(crate) async fn socks_handshake(client: &mut TcpStream) -> io::Result<SocksRequest> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(err("socks5: неверная версия"));
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods).await?;
    client.write_all(&[0x05, 0x00]).await?;

    let mut rhead = [0u8; 4];
    client.read_exact(&mut rhead).await?;
    let cmd = rhead[1];
    // Адрес запроса читаем всегда (для CONNECT — цель, для ASSOCIATE — подсказка).
    let addr = read_target(client, rhead[3]).await?;
    match cmd {
        0x01 => Ok(SocksRequest::Connect(addr)),
        0x03 => Ok(SocksRequest::UdpAssociate),
        _ => {
            client.write_all(&reply(0x07)).await?; // command not supported
            Err(err("socks5: команда не поддерживается"))
        }
    }
}

/// Подключается к цели через `outbound` и гоняет данные в обе стороны.
pub(crate) async fn relay_through(
    mut client: TcpStream,
    outbound: &Outbound,
    target: &Target,
) -> io::Result<()> {
    match outbound.connect_tcp(target).await {
        Ok(mut upstream) => {
            client.write_all(&reply(0x00)).await?;
            tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
            Ok(())
        }
        Err(e) => {
            client.write_all(&reply(0x05)).await?; // connection refused
            Err(e)
        }
    }
}

async fn read_target(client: &mut TcpStream, atyp: u8) -> io::Result<Target> {
    match atyp {
        0x01 => {
            let mut a = [0u8; 4];
            client.read_exact(&mut a).await?;
            let mut p = [0u8; 2];
            client.read_exact(&mut p).await?;
            Ok(Target::Socket(SocketAddr::from((a, u16::from_be_bytes(p)))))
        }
        0x04 => {
            let mut a = [0u8; 16];
            client.read_exact(&mut a).await?;
            let mut p = [0u8; 2];
            client.read_exact(&mut p).await?;
            Ok(Target::Socket(SocketAddr::from((a, u16::from_be_bytes(p)))))
        }
        0x03 => {
            let mut l = [0u8; 1];
            client.read_exact(&mut l).await?;
            let mut d = vec![0u8; l[0] as usize];
            client.read_exact(&mut d).await?;
            let host = String::from_utf8(d).map_err(|_| err("socks5: некорректный домен"))?;
            let mut p = [0u8; 2];
            client.read_exact(&mut p).await?;
            Ok(Target::Domain(host, u16::from_be_bytes(p)))
        }
        _ => Err(err("socks5: неизвестный ATYP")),
    }
}

/// Ответ SOCKS5 с указанным кодом и фиктивным адресом `0.0.0.0:0`.
pub(crate) fn reply(rep: u8) -> [u8; 10] {
    [0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

/// Ответ SOCKS5 с указанным кодом и адресом привязки (BND) — для UDP ASSOCIATE.
pub(crate) fn reply_addr(rep: u8, addr: SocketAddr) -> Vec<u8> {
    let mut out = vec![0x05, rep, 0x00];
    match addr {
        SocketAddr::V4(a) => {
            out.push(0x01);
            out.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            out.push(0x04);
            out.extend_from_slice(&a.ip().octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
    out
}

fn err(msg: &str) -> io::Error {
    io::Error::other(msg)
}
