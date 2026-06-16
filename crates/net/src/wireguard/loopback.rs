//! Интеграционный тест WG-туннеля без внешнего сервера: клиентом выступает наш
//! [`super::tunnel::WgTunnel`] (через [`super::wireguard_connect`]), сервером —
//! минимальный echo-харнесс (второе ядро `boringtun` + свой smoltcp-стек со
//! слушающим TCP-сокетом), соединённый с клиентом по localhost-UDP.
//!
//! Проверяет сквозной путь: Noise-handshake → TCP SYN/ACK через шифрование →
//! двунаправленный обмен данными, в т.ч. с AmneziaWG-обфускацией.

use super::config::{AwgObfuscation, WgConfig, WgParams};
use super::device::WgDevice;
use super::obfs::AwgObfs;
use super::wireguard_connect;
use crate::target::Target;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

fn pubkey(priv_bytes: [u8; 32]) -> [u8; 32] {
    *PublicKey::from(&StaticSecret::from(priv_bytes)).as_bytes()
}

/// Echo-сервер: WG-пир (responder) + smoltcp-стек, слушающий `listen_port` на
/// `iface_ip`; всё принятое отправляет обратно.
#[allow(clippy::too_many_arguments)]
async fn echo_server(
    udp: Arc<UdpSocket>,
    server_priv: [u8; 32],
    client_pub: [u8; 32],
    awg: Option<AwgObfuscation>,
    iface_ip: Ipv4Addr,
    prefix: u8,
    listen_port: u16,
    n_listeners: usize,
) {
    let mut tunn = Tunn::new(
        StaticSecret::from(server_priv),
        PublicKey::from(client_pub),
        None,
        None,
        0,
        None,
    );
    let obfs = AwgObfs::new(awg, pubkey(server_priv), client_pub);

    let mut device = WgDevice::new();
    let base = StdInstant::now();
    let mut iface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        SmolInstant::from_micros(0),
    );
    iface.update_ip_addrs(|a| {
        let _ = a.push(IpCidr::new(IpAddress::from(IpAddr::V4(iface_ip)), prefix));
    });
    let mut sockets = SocketSet::new(Vec::new());
    // Несколько слушающих сокетов на одном порту — backlog для параллельных
    // соединений (smoltcp раздаёт входящие SYN свободным listen-сокетам).
    let handles: Vec<_> = (0..n_listeners)
        .map(|_| {
            let mut sock = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; 65536]),
                tcp::SocketBuffer::new(vec![0u8; 65536]),
            );
            sock.listen(listen_port).unwrap();
            sockets.add(sock)
        })
        .collect();

    // UDP-echo на том же порту (отдельное пространство портов smoltcp): любую
    // принятую датаграмму отправляем обратно источнику.
    let udp_echo = {
        let rx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; 8],
            vec![0u8; 65536],
        );
        let tx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; 8],
            vec![0u8; 65536],
        );
        let mut s = udp::Socket::new(rx, tx);
        s.bind(listen_port).unwrap();
        sockets.add(s)
    };

    let mut scratch = vec![0u8; 65535];
    let mut udp_buf = vec![0u8; 65535];
    let mut peer = None;
    let mut ticker = tokio::time::interval(Duration::from_millis(50));

    loop {
        let now = SmolInstant::from_micros(base.elapsed().as_micros() as i64);
        iface.poll(now, &mut device, &mut sockets);

        // Эхо: что приняли — то и отправили обратно (на каждом сокете).
        for &handle in &handles {
            let s = sockets.get_mut::<tcp::Socket>(handle);
            if s.can_recv() && s.can_send() {
                let mut tmp = [0u8; 4096];
                if let Ok(n) = s.recv_slice(&mut tmp) {
                    if n > 0 {
                        let _ = s.send_slice(&tmp[..n]);
                    }
                }
            }
        }

        // UDP-echo: датаграмму отправляем обратно её источнику.
        {
            let s = sockets.get_mut::<udp::Socket>(udp_echo);
            let echo = s.recv().ok().map(|(d, m)| (d.to_vec(), m.endpoint));
            if let Some((data, ep)) = echo {
                let _ = s.send_slice(&data, ep);
            }
        }

        // Шифруем исходящие IP-пакеты в outbox.
        let mut outbox: Vec<Vec<u8>> = Vec::new();
        while let Some(pkt) = device.tx.pop_front() {
            if let TunnResult::WriteToNetwork(b) = tunn.encapsulate(&pkt, &mut scratch) {
                outbox.extend(obfs.wrap(b));
            }
        }
        let delay = iface
            .poll_delay(now, &sockets)
            .map(|d| Duration::from_micros(d.total_micros()));

        if let Some(addr) = peer {
            for dg in &outbox {
                let _ = udp.send_to(dg, addr).await;
            }
        }

        tokio::select! {
            r = udp.recv_from(&mut udp_buf) => {
                if let Ok((n, addr)) = r {
                    peer = Some(addr);
                    if let Some(clean) = obfs.unwrap(&udp_buf[..n]) {
                        let mut to_send: Vec<Vec<u8>> = Vec::new();
                        let mut first = true;
                        loop {
                            let input: &[u8] = if first { &clean } else { &[] };
                            first = false;
                            match tunn.decapsulate(None, input, &mut scratch) {
                                TunnResult::WriteToNetwork(b) => to_send.extend(obfs.wrap(b)),
                                TunnResult::WriteToTunnelV4(p, _)
                                | TunnResult::WriteToTunnelV6(p, _) => {
                                    device.rx.push_back(p.to_vec());
                                    break;
                                }
                                _ => break,
                            }
                        }
                        for dg in &to_send {
                            let _ = udp.send_to(dg, addr).await;
                        }
                    }
                }
            }
            _ = ticker.tick() => {
                if let TunnResult::WriteToNetwork(b) = tunn.update_timers(&mut scratch) {
                    if let Some(addr) = peer {
                        for dg in obfs.wrap(b) {
                            let _ = udp.send_to(&dg, addr).await;
                        }
                    }
                }
            }
            _ = async { match delay {
                Some(d) => tokio::time::sleep(d).await,
                None => std::future::pending::<()>().await,
            } } => {}
        }
    }
}

/// Поднимает echo-сервер и клиентский туннель, гоняет «hello» через туннель.
async fn run_echo(awg: Option<AwgObfuscation>) {
    let client_priv = [11u8; 32];
    let server_priv = [22u8; 32];
    let server_iface = Ipv4Addr::new(10, 0, 0, 1);
    let client_iface = Ipv4Addr::new(10, 0, 0, 2);
    let listen_port = 8080;

    let server_udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server_udp.local_addr().unwrap();

    tokio::spawn(echo_server(
        server_udp,
        server_priv,
        pubkey(client_priv),
        awg.clone(),
        server_iface,
        24,
        listen_port,
        1,
    ));

    let cfg = WgConfig::new(WgParams {
        endpoint: server_addr.to_string(),
        private_key: client_priv,
        peer_public_key: pubkey(server_priv),
        preshared_key: None,
        address: vec![(IpAddr::V4(client_iface), 24)],
        dns: vec![],
        persistent_keepalive: None,
        awg,
    });

    let target = Target::Socket(format!("{server_iface}:{listen_port}").parse().unwrap());
    let mut stream = wireguard_connect(&cfg, &target).await.expect("connect");

    let msg = b"hello wireguard tunnel";
    stream.write_all(msg).await.expect("write");

    let mut buf = vec![0u8; msg.len()];
    stream.read_exact(&mut buf).await.expect("read");
    assert_eq!(&buf, msg, "echo через туннель совпадает");
}

#[tokio::test]
async fn loopback_echo_plain_wireguard() {
    tokio::time::timeout(Duration::from_secs(20), run_echo(None))
        .await
        .expect("тест не должен зависнуть");
}

/// Два соединения через ОДИН [`WgConfig`]: второй коннект переиспользует туннель
/// (один handshake/netstack — общий `Arc<WgTunnel>` через `OnceCell`).
async fn run_two_conns() {
    let client_priv = [11u8; 32];
    let server_priv = [22u8; 32];
    let server_iface = Ipv4Addr::new(10, 0, 0, 1);
    let client_iface = Ipv4Addr::new(10, 0, 0, 2);
    let listen_port = 8080;

    let server_udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server_udp.local_addr().unwrap();
    tokio::spawn(echo_server(
        server_udp,
        server_priv,
        pubkey(client_priv),
        None,
        server_iface,
        24,
        listen_port,
        2,
    ));

    let cfg = WgConfig::new(WgParams {
        endpoint: server_addr.to_string(),
        private_key: client_priv,
        peer_public_key: pubkey(server_priv),
        preshared_key: None,
        address: vec![(IpAddr::V4(client_iface), 24)],
        dns: vec![],
        persistent_keepalive: None,
        awg: None,
    });
    let target = Target::Socket(format!("{server_iface}:{listen_port}").parse().unwrap());

    let mut s1 = wireguard_connect(&cfg, &target).await.expect("connect 1");
    let mut s2 = wireguard_connect(&cfg, &target).await.expect("connect 2");

    s1.write_all(b"first").await.unwrap();
    s2.write_all(b"second").await.unwrap();

    let mut b1 = [0u8; 5];
    let mut b2 = [0u8; 6];
    s1.read_exact(&mut b1).await.unwrap();
    s2.read_exact(&mut b2).await.unwrap();
    assert_eq!(&b1, b"first");
    assert_eq!(&b2, b"second");
}

#[tokio::test]
async fn loopback_two_connections_share_tunnel() {
    tokio::time::timeout(Duration::from_secs(20), run_two_conns())
        .await
        .expect("тест не должен зависнуть");
}

#[tokio::test]
async fn loopback_echo_amneziawg() {
    // Нестандартные H1..H4 + S-префиксы + junk: проверяем wrap/unwrap в живом цикле.
    let awg = AwgObfuscation {
        jc: 3,
        jmin: 20,
        jmax: 60,
        s1: 16,
        s2: 24,
        h1: 0x5111_1111,
        h2: 0x5222_2222,
        h3: 0x5333_3333,
        h4: 0x5444_4444,
    };
    tokio::time::timeout(Duration::from_secs(20), run_echo(Some(awg)))
        .await
        .expect("тест не должен зависнуть");
}

/// UDP через туннель: датаграмма доходит до UDP-echo сервера и возвращается.
async fn run_udp_echo() {
    let client_priv = [11u8; 32];
    let server_priv = [22u8; 32];
    let server_iface = Ipv4Addr::new(10, 0, 0, 1);
    let client_iface = Ipv4Addr::new(10, 0, 0, 2);
    let listen_port = 8080;

    let server_udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server_udp.local_addr().unwrap();
    tokio::spawn(echo_server(
        server_udp,
        server_priv,
        pubkey(client_priv),
        None,
        server_iface,
        24,
        listen_port,
        1,
    ));

    let cfg = WgConfig::new(WgParams {
        endpoint: server_addr.to_string(),
        private_key: client_priv,
        peer_public_key: pubkey(server_priv),
        preshared_key: None,
        address: vec![(IpAddr::V4(client_iface), 24)],
        dns: vec![],
        persistent_keepalive: None,
        awg: None,
    });
    let target = Target::Socket(format!("{server_iface}:{listen_port}").parse().unwrap());
    let sess = super::wireguard_connect_udp(&cfg, &target)
        .await
        .expect("udp session");

    // UDP best-effort: первые датаграммы до завершения handshake могут пропасть,
    // поэтому шлём с ретраями, ожидая эхо.
    for _ in 0..10u32 {
        sess.send(b"ping udp").await.expect("send");
        match tokio::time::timeout(Duration::from_millis(500), sess.recv()).await {
            Ok(Ok(resp)) => {
                assert_eq!(&resp, b"ping udp", "udp echo совпадает");
                return;
            }
            _ => continue,
        }
    }
    panic!("UDP-echo не вернулся за 10 попыток");
}

#[tokio::test]
async fn loopback_udp_echo() {
    tokio::time::timeout(Duration::from_secs(20), run_udp_echo())
        .await
        .expect("тест не должен зависнуть");
}
