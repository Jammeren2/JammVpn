//! Интеграционный тест TUIC v5 без внешнего сервера: клиентом выступает наш
//! [`super::tuic_connect`], сервером — минимальный quinn TUIC-эхо-сервер
//! (самоподписанный сертификат, ALPN h3): читает Authenticate (валидирует токен
//! через тот же TLS-экспортёр), на несовпадении закрывает соединение; на
//! Connect-стримах эхо-ит байты.
//!
//! Проверяет сквозной путь: QUIC-handshake + insecure-проверка + Authenticate
//! (вывод токена) + Connect-фрейминг + двунаправленный обмен; переиспользование
//! соединения; отклонение неверного пароля.

use super::config::{TuicConfig, TuicParams};
use super::{proto, tuic_connect};
use crate::target::Target;
use quinn::{Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

fn server_endpoint() -> (Endpoint, u16) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert = CertificateDer::from(ck.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let endpoint = Endpoint::server(
        ServerConfig::with_crypto(Arc::new(qsc)),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let port = endpoint.local_addr().unwrap().port();
    (endpoint, port)
}

/// Эхо-сервер: валидирует Authenticate против `expected_pw` (закрывает соединение
/// при несовпадении), на Connect-стримах эхо-ит и публикует цель в `addr_tx`.
async fn run_server(endpoint: Endpoint, expected_pw: String, addr_tx: mpsc::Sender<String>) {
    while let Some(incoming) = endpoint.accept().await {
        let pw = expected_pw.clone();
        let addr_tx = addr_tx.clone();
        tokio::spawn(async move {
            let Ok(conn) = incoming.await else { return };

            // Читатель Authenticate: при неверном токене закрываем соединение.
            let conn_auth = conn.clone();
            tokio::spawn(async move {
                if let Ok(mut uni) = conn_auth.accept_uni().await {
                    if let Ok((uuid, token)) = proto::read_authenticate(&mut uni).await {
                        let mut expect = [0u8; 32];
                        let _ = conn_auth.export_keying_material(&mut expect, &uuid, pw.as_bytes());
                        if expect != token {
                            conn_auth.close(1u32.into(), b"auth failed");
                        }
                    }
                }
            });

            // Датаграммный эхо (UDP relay): декодируем Packet, шлём обратно тем же
            // assoc_id/адресом + payload (как будто цель ответила).
            let conn_dg = conn.clone();
            tokio::spawn(async move {
                while let Ok(dg) = conn_dg.read_datagram().await {
                    if let Ok((head, payload)) = proto::decode_packet(&dg) {
                        if let Some(addr) = head.addr {
                            let max = conn_dg.max_datagram_size().unwrap_or(1200);
                            if let Ok(dgs) = proto::encode_packets(
                                head.assoc_id,
                                head.pkt_id,
                                &addr,
                                payload,
                                max,
                            ) {
                                for d in dgs {
                                    let _ = conn_dg.send_datagram(bytes::Bytes::from(d));
                                }
                            }
                        }
                    }
                }
            });

            // Connect-стримы: эхо (достижимы только если соединение не закрыто).
            while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                let addr_tx = addr_tx.clone();
                tokio::spawn(async move {
                    let Ok(addr) = proto::read_connect(&mut recv).await else {
                        return;
                    };
                    let _ = addr_tx.send(addr).await;
                    let mut buf = vec![0u8; 8192];
                    while let Ok(Some(n)) = recv.read(&mut buf).await {
                        if n == 0 || send.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    let _ = send.finish();
                });
            }
        });
    }
}

fn client_config(port: u16, password: &str) -> TuicConfig {
    TuicConfig::new(TuicParams {
        server: format!("127.0.0.1:{port}"),
        uuid: [0x42; 16],
        password: password.to_string(),
        sni: Some("localhost".to_string()),
        insecure: true,
        alpn: vec![b"h3".to_vec()],
    })
}

#[tokio::test]
async fn loopback_echo() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (endpoint, port) = server_endpoint();
        let (addr_tx, mut addr_rx) = mpsc::channel(8);
        tokio::spawn(run_server(endpoint, "secret".to_string(), addr_tx));

        let cfg = client_config(port, "secret");
        let target = Target::Domain("example.com".to_string(), 443);
        let mut s = tuic_connect(&cfg, &target).await.expect("connect");

        let msg = b"hello tuic v5 tunnel";
        s.write_all(msg).await.expect("write");
        let mut buf = vec![0u8; msg.len()];
        s.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, msg, "эхо через TUIC совпадает");

        // сервер увидел правильную цель (домен ушёл серверу как есть).
        assert_eq!(addr_rx.recv().await.unwrap(), "example.com:443");
    })
    .await
    .expect("тест не должен зависнуть");
}

#[tokio::test]
async fn loopback_two_connections_reuse() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (endpoint, port) = server_endpoint();
        let (addr_tx, _addr_rx) = mpsc::channel(8);
        tokio::spawn(run_server(endpoint, "pw".to_string(), addr_tx));

        // Два соединения через ОДИН TuicConfig: общий QUIC-conn + один Authenticate,
        // два независимых bidi-стрима.
        let cfg = client_config(port, "pw");
        let t1 = Target::Domain("a.test".to_string(), 80);
        let t2 = Target::Domain("b.test".to_string(), 81);
        let mut s1 = tuic_connect(&cfg, &t1).await.expect("connect 1");
        let mut s2 = tuic_connect(&cfg, &t2).await.expect("connect 2");

        s1.write_all(b"first").await.unwrap();
        s2.write_all(b"second").await.unwrap();
        let mut b1 = [0u8; 5];
        let mut b2 = [0u8; 6];
        s1.read_exact(&mut b1).await.unwrap();
        s2.read_exact(&mut b2).await.unwrap();
        assert_eq!(&b1, b"first");
        assert_eq!(&b2, b"second");
    })
    .await
    .expect("тест не должен зависнуть");
}

#[tokio::test]
async fn loopback_udp_echo() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (endpoint, port) = server_endpoint();
        let (addr_tx, _addr_rx) = mpsc::channel(8);
        tokio::spawn(run_server(endpoint, "pw".to_string(), addr_tx));

        // UDP через TUIC: общий QUIC-conn + Authenticate (в udp()), затем Packet
        // в QUIC-датаграммах. Сервер эхо-ит.
        let cfg = client_config(port, "pw");
        let ob = crate::outbound::Outbound::Tuic(cfg);
        let target = Target::Domain("udp.test".to_string(), 5353);
        let session = ob.connect_udp(&target).await.expect("udp session");

        session.send(b"hello-tuic-udp").await.expect("send");
        let got = tokio::time::timeout(Duration::from_secs(5), session.recv())
            .await
            .expect("recv не уложился в таймаут")
            .expect("recv");
        assert_eq!(got, b"hello-tuic-udp", "эхо UDP через TUIC совпадает");

        // Второй пакет по той же сессии (assoc_id переиспользуется).
        session.send(b"second").await.unwrap();
        let got2 = tokio::time::timeout(Duration::from_secs(5), session.recv())
            .await
            .expect("recv2 таймаут")
            .expect("recv2");
        assert_eq!(got2, b"second");

        session.close().await;
    })
    .await
    .expect("тест не должен зависнуть");
}

#[tokio::test]
async fn loopback_wrong_password_rejected() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (endpoint, port) = server_endpoint();
        let (addr_tx, _addr_rx) = mpsc::channel(8);
        tokio::spawn(run_server(endpoint, "correct".to_string(), addr_tx));

        // Клиент с НЕВЕРНЫМ паролем: токен не сойдётся → сервер закроет соединение
        // → connect/обмен завершится ошибкой.
        let cfg = client_config(port, "wrong");
        let target = Target::Domain("example.com".to_string(), 443);

        let result = async {
            let mut s = tuic_connect(&cfg, &target).await?;
            s.write_all(b"data").await?;
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).await?;
            std::io::Result::Ok(())
        }
        .await;
        assert!(result.is_err(), "неверный пароль должен быть отклонён");
    })
    .await
    .expect("тест не должен зависнуть");
}
