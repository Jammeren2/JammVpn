//! Интеграционные тесты сетевого ядра: end-to-end через локальные сокеты.

use crate::inbound::serve_socks;
use crate::outbound::{HttpConfig, Outbound, Socks5Config};
use crate::target::Target;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Поднимает echo-сервер, возвращает его адрес.
async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// Поднимает SOCKS5-inbound с заданным outbound, возвращает адрес прокси.
async fn spawn_socks_inbound(outbound: Outbound) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_socks(listener, Arc::new(outbound)));
    addr
}

/// Минимальный mock HTTP-прокси: отвечает 200 на CONNECT и эхо-проксирует тело.
async fn spawn_mock_http_connect() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut b = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            match sock.read(&mut b).await {
                Ok(0) | Err(_) => return,
                Ok(_) => buf.push(b[0]),
            }
        }
        sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .unwrap();
        let mut data = vec![0u8; 4096];
        loop {
            match sock.read(&mut data).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if sock.write_all(&data[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    addr
}

/// Сырой SOCKS5-клиент: CONNECT к IPv4-адресу, возвращает готовый поток.
async fn socks5_client(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    s.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00]);

    let IpAddr::V4(ip) = target.ip() else {
        panic!("ожидался IPv4");
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip.octets());
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).await.unwrap();

    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.unwrap();
    assert_eq!(head[1], 0x00, "SOCKS5 reply must be success");
    let mut tail = [0u8; 6]; // IPv4 BND.ADDR + port
    s.read_exact(&mut tail).await.unwrap();
    s
}

#[tokio::test]
async fn socks_inbound_direct_roundtrip() {
    let echo = spawn_echo().await;
    let proxy = spawn_socks_inbound(Outbound::Direct).await;
    let mut s = socks5_client(proxy, echo).await;
    s.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");
}

#[tokio::test]
async fn outbound_socks5_through_inbound() {
    let echo = spawn_echo().await;
    let proxy = spawn_socks_inbound(Outbound::Direct).await;
    let ob = Outbound::Socks5(Socks5Config {
        server: proxy.to_string(),
        username: None,
        password: None,
    });
    let mut s = ob.connect_tcp(&Target::Socket(echo)).await.unwrap();
    s.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

#[tokio::test]
async fn outbound_http_connect_roundtrip() {
    let proxy = spawn_mock_http_connect().await;
    let ob = Outbound::Http(HttpConfig {
        server: proxy.to_string(),
        username: None,
        password: None,
    });
    let mut s = ob
        .connect_tcp(&Target::Domain("example.com".to_string(), 443))
        .await
        .unwrap();
    s.write_all(b"hey").await.unwrap();
    let mut buf = [0u8; 3];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hey");
}

#[tokio::test]
async fn direct_connects_to_echo() {
    let echo = spawn_echo().await;
    let mut s = Outbound::Direct
        .connect_tcp(&Target::Socket(echo))
        .await
        .unwrap();
    s.write_all(b"x").await.unwrap();
    let mut buf = [0u8; 1];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"x");
}
