//! Локальный SOCKS5-сервер (inbound) — цель перенаправления WFP-драйвера.
//!
//! Принимает соединения по SOCKS5 (без аутентификации, команда CONNECT),
//! определяет цель и проксирует её через переданный [`Outbound`], после чего
//! гоняет данные в обе стороны.

use crate::outbound::Outbound;
use crate::target::Target;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Обслуживает входящие SOCKS5-соединения на `listener`, проксируя их через
/// `outbound`. Бесконечный цикл; каждое соединение обрабатывается в своей задаче.
pub async fn serve_socks(listener: TcpListener, outbound: Arc<Outbound>) -> io::Result<()> {
    loop {
        let (client, _) = listener.accept().await?;
        let ob = Arc::clone(&outbound);
        tokio::spawn(async move {
            let _ = handle_client(client, &ob).await;
        });
    }
}

async fn handle_client(mut client: TcpStream, outbound: &Outbound) -> io::Result<()> {
    // Приветствие.
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(err("socks5: неверная версия"));
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods).await?;
    // Поддерживаем только no-auth.
    client.write_all(&[0x05, 0x00]).await?;

    // Запрос: VER CMD RSV ATYP ...
    let mut rhead = [0u8; 4];
    client.read_exact(&mut rhead).await?;
    if rhead[1] != 0x01 {
        client.write_all(&reply(0x07)).await?; // command not supported
        return Err(err("socks5: поддерживается только CONNECT"));
    }
    let target = read_target(&mut client, rhead[3]).await?;

    match outbound.connect_tcp(&target).await {
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
fn reply(rep: u8) -> [u8; 10] {
    [0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

fn err(msg: &str) -> io::Error {
    io::Error::other(msg)
}
