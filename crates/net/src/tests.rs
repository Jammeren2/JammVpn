//! Интеграционные тесты сетевого ядра: end-to-end через локальные сокеты.

use crate::engine::{serve_socks_routed, Engine};
use crate::inbound::serve_socks;
use crate::outbound::{
    HttpConfig, Outbound, ShadowsocksConfig, Socks5Config, Transport, VlessConfig,
};
use crate::shadowsocks::{evp_bytes_to_key, Method, ShadowsocksStream};
use crate::target::Target;
use crate::vless;
use jammvpn_core::routing::{RouteAction, Rule};
use jammvpn_core::split::IpCidr;
use std::collections::HashMap;
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

/// Mock VLESS-сервер: валидирует заголовок запроса, шлёт ответный заголовок и
/// эхо-проксирует тело.
async fn spawn_mock_vless(expected_uuid: [u8; 16]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut ver = [0u8; 1];
        sock.read_exact(&mut ver).await.unwrap();
        assert_eq!(ver[0], 0x00);
        let mut uuid = [0u8; 16];
        sock.read_exact(&mut uuid).await.unwrap();
        assert_eq!(uuid, expected_uuid);
        let mut addon_len = [0u8; 1];
        sock.read_exact(&mut addon_len).await.unwrap();
        if addon_len[0] > 0 {
            let mut a = vec![0u8; addon_len[0] as usize];
            sock.read_exact(&mut a).await.unwrap();
        }
        let mut cmd = [0u8; 1];
        sock.read_exact(&mut cmd).await.unwrap();
        let mut port = [0u8; 2];
        sock.read_exact(&mut port).await.unwrap();
        let mut atyp = [0u8; 1];
        sock.read_exact(&mut atyp).await.unwrap();
        match atyp[0] {
            0x01 => {
                let mut a = [0u8; 4];
                sock.read_exact(&mut a).await.unwrap();
            }
            0x03 => {
                let mut a = [0u8; 16];
                sock.read_exact(&mut a).await.unwrap();
            }
            0x02 => {
                let mut l = [0u8; 1];
                sock.read_exact(&mut l).await.unwrap();
                let mut d = vec![0u8; l[0] as usize];
                sock.read_exact(&mut d).await.unwrap();
            }
            _ => return,
        }
        // Ответный заголовок: версия + длина addon (0).
        sock.write_all(&[0x00, 0x00]).await.unwrap();
        // Эхо тела.
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
    addr
}

#[tokio::test]
async fn vless_over_tcp_roundtrip() {
    let uuid = vless::parse_uuid("11111111-2222-3333-4444-555555555555").unwrap();
    let server = spawn_mock_vless(uuid).await;
    let ob = Outbound::Vless(VlessConfig {
        server: server.to_string(),
        uuid,
        flow: None,
        transport: Transport::Tcp,
    });
    let mut s = ob
        .connect_tcp(&Target::Domain("example.com".to_string(), 443))
        .await
        .unwrap();
    s.write_all(b"vless!").await.unwrap();
    let mut buf = [0u8; 6];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"vless!");
}

/// Mock SS-сервер: оборачивает сокет в `ShadowsocksStream`, читает адрес и
/// эхо-проксирует тело.
async fn spawn_mock_ss(method: Method, password: String) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let key = evp_bytes_to_key(password.as_bytes(), method.key_len());
    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let mut ss = ShadowsocksStream::new(sock, method, key);
        let mut atyp = [0u8; 1];
        ss.read_exact(&mut atyp).await.unwrap();
        match atyp[0] {
            0x01 => {
                let mut a = [0u8; 4];
                ss.read_exact(&mut a).await.unwrap();
            }
            0x04 => {
                let mut a = [0u8; 16];
                ss.read_exact(&mut a).await.unwrap();
            }
            0x03 => {
                let mut l = [0u8; 1];
                ss.read_exact(&mut l).await.unwrap();
                let mut d = vec![0u8; l[0] as usize];
                ss.read_exact(&mut d).await.unwrap();
            }
            _ => return,
        }
        let mut port = [0u8; 2];
        ss.read_exact(&mut port).await.unwrap();
        let mut buf = vec![0u8; 4096];
        loop {
            match ss.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if ss.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    addr
}

#[tokio::test]
async fn shadowsocks_stream_duplex_roundtrip() {
    let method = Method::Aes256Gcm;
    let key = evp_bytes_to_key(b"secret", method.key_len());
    let (a, b) = tokio::io::duplex(128 * 1024);
    let mut ca = ShadowsocksStream::new(a, method, key.clone());
    let mut cb = ShadowsocksStream::new(b, method, key.clone());

    // Многочанковая нагрузка (> MAX_CHUNK).
    let payload = vec![0xABu8; 50_000];
    ca.write_all(&payload).await.unwrap();
    ca.flush().await.unwrap();
    let mut got = vec![0u8; 50_000];
    cb.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload);

    // Обратное направление.
    cb.write_all(b"pong").await.unwrap();
    cb.flush().await.unwrap();
    let mut r = [0u8; 4];
    ca.read_exact(&mut r).await.unwrap();
    assert_eq!(&r, b"pong");
}

#[tokio::test]
async fn outbound_shadowsocks_against_mock() {
    let method = Method::Chacha20IetfPoly1305;
    let server = spawn_mock_ss(method, "pw".to_string()).await;
    let ob = Outbound::Shadowsocks(ShadowsocksConfig {
        server: server.to_string(),
        method,
        password: "pw".to_string(),
    });
    let mut s = ob
        .connect_tcp(&Target::Domain("example.com".to_string(), 443))
        .await
        .unwrap();
    s.write_all(b"shadow").await.unwrap();
    let mut buf = [0u8; 6];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"shadow");
}

/// Поднимает SOCKS5-сервер с маршрутизацией, возвращает его адрес.
async fn spawn_routed(engine: Engine) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_socks_routed(listener, Arc::new(engine)));
    addr
}

#[tokio::test]
async fn routed_engine_direct_path() {
    let echo = spawn_echo().await;
    // Без правил, действие по умолчанию — Direct.
    let engine = Engine::new(HashMap::new(), None, vec![], RouteAction::Direct);
    let proxy = spawn_routed(engine).await;
    let mut s = socks5_client(proxy, echo).await;
    s.write_all(b"routed").await.unwrap();
    let mut buf = [0u8; 6];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"routed");
}

#[tokio::test]
async fn routed_engine_proxy_chain() {
    let echo = spawn_echo().await;
    // Вышестоящий прокси: SOCKS5-inbound, проксирующий напрямую.
    let upstream = spawn_socks_inbound(Outbound::Direct).await;

    let mut outbounds = HashMap::new();
    outbounds.insert(
        "p".to_string(),
        Outbound::Socks5(Socks5Config {
            server: upstream.to_string(),
            username: None,
            password: None,
        }),
    );
    // Правило: IP echo-сервера → через прокси "p".
    let rule = Rule {
        ip_cidrs: vec![IpCidr::parse(&format!("{}/32", echo.ip())).unwrap()],
        action: RouteAction::Proxy(Some("p".to_string())),
        ..Default::default()
    };
    let engine = Engine::new(outbounds, None, vec![rule], RouteAction::Direct);
    let proxy = spawn_routed(engine).await;

    let mut s = socks5_client(proxy, echo).await;
    s.write_all(b"viapxy").await.unwrap();
    let mut buf = [0u8; 6];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"viapxy");
}
