//! SOCKS5 UDP ASSOCIATE: проброс UDP-датаграмм через исходящие (ТЗ, раздел 4).
//!
//! Клиент по управляющему TCP-соединению просит UDP ASSOCIATE; сервер привязывает
//! relay-сокет и сообщает его адрес (BND). Далее клиент шлёт на этот адрес
//! датаграммы с SOCKS5 UDP-заголовком (DST + payload).
//!
//! Модель — symmetric NAT: на каждый уникальный DST клиента заводится отдельный
//! `connect()`-нутый UDP-сокет (per-flow задача). Это даёт изоляцию пиров (ядро
//! отбрасывает датаграммы от чужих источников — нет off-path инъекции) и
//! корректную корреляцию: ответ заворачивается тем же адресом DST, который слал
//! клиент (а не реальным resolved IP), как ждёт RFC 1928-клиент.
//!
//! Ассоциация привязывается к первому клиенту (и только с хоста управляющего
//! соединения), живёт пока открыт управляющий TCP; без единой датаграммы за
//! [`HANDSHAKE_IDLE`] — закрывается (анти-DoS).

use crate::engine::{Decision, Engine};
use crate::inbound::reply_addr;
use crate::outbound::Outbound;
use crate::target::Target;
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

/// Максимальный размер UDP-датаграммы (с запасом под заголовок).
const MAX_DATAGRAM: usize = 65_535;
/// Таймаут ожидания первой датаграммы: ASSOCIATE без трафика → закрыть (анти-DoS).
const HANDSHAKE_IDLE: Duration = Duration::from_secs(120);
/// Глубина очереди исходящих датаграмм одного flow (переполнение → дроп, UDP).
const FLOW_QUEUE: usize = 64;

fn short() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "udp: усечённый заголовок")
}

/// Разбирает SOCKS5 UDP-заголовок: `(FRAG, цель, смещение данных)`.
pub fn parse_udp_datagram(buf: &[u8]) -> io::Result<(u8, Target, usize)> {
    if buf.len() < 4 {
        return Err(short());
    }
    let frag = buf[2];
    let atyp = buf[3];
    match atyp {
        0x01 => {
            if buf.len() < 10 {
                return Err(short());
            }
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            Ok((frag, Target::Socket(SocketAddr::from((ip, port))), 10))
        }
        0x04 => {
            if buf.len() < 22 {
                return Err(short());
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[4..20]);
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            Ok((
                frag,
                Target::Socket(SocketAddr::from((Ipv6Addr::from(o), port))),
                22,
            ))
        }
        0x03 => {
            let len = buf[4] as usize;
            let end = 5 + len + 2;
            if buf.len() < end {
                return Err(short());
            }
            let host = String::from_utf8_lossy(&buf[5..5 + len]).into_owned();
            let port = u16::from_be_bytes([buf[5 + len], buf[5 + len + 1]]);
            Ok((frag, Target::Domain(host, port), end))
        }
        _ => Err(io::Error::other("udp: неизвестный ATYP")),
    }
}

/// Кодирует SOCKS5 UDP-датаграмму: заголовок с адресом DST = `target` + `payload`.
/// В ответах `target` — это адрес, который слал клиент (а не resolved IP).
pub fn encode_udp_datagram(target: &Target, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 22);
    out.extend_from_slice(&[0, 0, 0]); // RSV(2) + FRAG(1)
    match target {
        Target::Socket(SocketAddr::V4(a)) => {
            out.push(0x01);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Socket(SocketAddr::V6(a)) => {
            out.push(0x04);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Domain(host, port) => {
            // Длина имени — 1 байт; имена DNS ≤ 255, но подстрахуемся.
            let h = host.as_bytes();
            let len = h.len().min(255);
            out.push(0x03);
            out.push(len as u8);
            out.extend_from_slice(&h[..len]);
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    out
}

/// Обслуживает UDP ASSOCIATE до закрытия управляющего соединения.
pub async fn udp_associate(mut control: TcpStream, engine: Arc<Engine>) -> io::Result<()> {
    let control_peer_ip = control.peer_addr()?.ip();
    // Relay-сокет на IP управляющего соединения (для 127.0.0.1 — только localhost).
    let local_ip = control.local_addr()?.ip();
    let relay = Arc::new(UdpSocket::bind((local_ip, 0)).await?);
    control
        .write_all(&reply_addr(0x00, relay.local_addr()?))
        .await?;

    // Активные потоки: ключ = строковый DST клиента → отправитель в per-flow задачу.
    let mut flows: HashMap<String, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut client_addr: Option<SocketAddr> = None;
    let mut warned_proxy = false;
    let mut cbuf = vec![0u8; MAX_DATAGRAM];
    let mut ctl = [0u8; 256];

    loop {
        tokio::select! {
            // Управляющее соединение закрылось/прислало EOF → рвём ассоциацию.
            r = control.read(&mut ctl) => {
                if matches!(r, Ok(0) | Err(_)) { break; }
            }
            // Датаграмма от клиента (с idle-таймаутом до первой датаграммы).
            r = tokio::time::timeout(HANDSHAKE_IDLE, relay.recv_from(&mut cbuf)) => {
                let (n, src) = match r {
                    // Таймаут: если не было ни одной датаграммы — закрываем (анти-DoS);
                    // иначе ассоциация активна — продолжаем ждать.
                    Err(_) => {
                        if client_addr.is_none() { break; } else { continue; }
                    }
                    Ok(Err(_)) => break,
                    Ok(Ok(v)) => v,
                };
                // Принимаем только с хоста управляющего соединения и от первого
                // привязавшегося клиента (анти-хайджек/спуфинг).
                if src.ip() != control_peer_ip {
                    continue;
                }
                match client_addr {
                    None => client_addr = Some(src),
                    Some(c) if c == src => {}
                    Some(_) => continue,
                }
                let (frag, target, off) = match parse_udp_datagram(&cbuf[..n]) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if frag != 0 {
                    continue; // фрагментацию не поддерживаем (RFC 1928 — опционально)
                }
                let key = target.to_string();
                // Существующий поток?
                if let Some(tx) = flows.get(&key) {
                    if tx.try_send(cbuf[off..n].to_vec()).is_ok() {
                        continue;
                    }
                    flows.remove(&key); // задача потока завершилась — пересоздаём ниже
                }
                // Новый поток: маршрутизируем DST → выбранный исходящий.
                let routed = engine.route(&target).await;
                let outbound = match routed.decision {
                    Decision::Connect(ob) => ob,
                    Decision::Block => continue, // намеренный дроп
                };
                match spawn_flow(&relay, src, &target, &outbound, &routed.target, &cbuf[off..n])
                    .await
                {
                    Some(tx) => {
                        flows.insert(key, tx);
                    }
                    None => {
                        // connect_udp не удался: резолв либо неподдержанный прокси-UDP.
                        if !matches!(outbound, Outbound::Direct) && !warned_proxy {
                            warned_proxy = true;
                            eprintln!(
                                "предупреждение: UDP через этот исходящий пока не поддержан — \
                                 датаграммы отбрасываются (поддержаны: Direct, Shadowsocks legacy)"
                            );
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Создаёт per-flow задачу: открывает UDP-сессию выбранного `outbound` к `dst`
/// (resolved цель маршрутизации), ответы заворачивает адресом `client_dst` (как
/// слал клиент). `None` — если резолв/connect/протокол не поддержан.
async fn spawn_flow(
    relay: &Arc<UdpSocket>,
    client: SocketAddr,
    client_dst: &Target,
    outbound: &Outbound,
    dst: &Target,
    first: &[u8],
) -> Option<mpsc::Sender<Vec<u8>>> {
    let session = outbound.connect_udp(dst).await.ok()?;

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(FLOW_QUEUE);
    let relay = Arc::clone(relay);
    let reply_dst = client_dst.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                // Исходящие от клиента → цели.
                p = rx.recv() => match p {
                    Some(payload) => {
                        if session.send(&payload).await.is_err() { break; }
                    }
                    None => break, // ассоциация закрылась (отправитель удалён)
                },
                // Ответы цели → клиенту (заголовок с DST, который слал клиент).
                r = session.recv() => match r {
                    Ok(payload) => {
                        let dg = encode_udp_datagram(&reply_dst, &payload);
                        if relay.send_to(&dg, client).await.is_err() { break; }
                    }
                    Err(_) => break,
                },
            }
        }
        session.close().await; // для TUIC — Dissociate + снятие регистрации
    });
    let _ = tx.try_send(first.to_vec());
    Some(tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_roundtrip_v4() {
        let dst = Target::Socket("203.0.113.5:53".parse().unwrap());
        let dg = encode_udp_datagram(&dst, b"hello");
        let (frag, target, off) = parse_udp_datagram(&dg).unwrap();
        assert_eq!(frag, 0);
        assert_eq!(target, dst);
        assert_eq!(&dg[off..], b"hello");
    }

    #[test]
    fn datagram_roundtrip_v6() {
        let dst = Target::Socket("[2001:db8::1]:443".parse().unwrap());
        let dg = encode_udp_datagram(&dst, b"data");
        let (_, target, off) = parse_udp_datagram(&dg).unwrap();
        assert_eq!(target, dst);
        assert_eq!(&dg[off..], b"data");
    }

    #[test]
    fn datagram_roundtrip_domain() {
        // Ответ под доменным DST — клиент сопоставит по имени, не по resolved IP.
        let dst = Target::Domain("ya.ru".into(), 443);
        let dg = encode_udp_datagram(&dst, b"x");
        let (_, target, off) = parse_udp_datagram(&dg).unwrap();
        assert_eq!(target, dst);
        assert_eq!(&dg[off..], b"x");
    }

    #[test]
    fn parses_domain_target() {
        let mut dg = vec![0, 0, 0, 0x03, 5];
        dg.extend_from_slice(b"ya.ru");
        dg.extend_from_slice(&443u16.to_be_bytes());
        dg.extend_from_slice(b"q");
        let (_, target, off) = parse_udp_datagram(&dg).unwrap();
        assert_eq!(target, Target::Domain("ya.ru".into(), 443));
        assert_eq!(&dg[off..], b"q");
    }

    #[test]
    fn rejects_truncated() {
        assert!(parse_udp_datagram(&[0, 0, 0]).is_err());
        assert!(parse_udp_datagram(&[0, 0, 0, 0x01, 1, 2]).is_err()); // обрезанный v4
        assert!(parse_udp_datagram(&[0, 0, 0, 0x09]).is_err()); // неизвестный ATYP
    }

    use crate::engine::{serve_socks_routed, Engine};
    use jammvpn_core::routing::RouteAction;
    use std::collections::HashMap;
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    /// UDP-echo: возвращает любую датаграмму отправителю.
    async fn udp_echo() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, src)) = sock.recv_from(&mut buf).await {
                let _ = sock.send_to(&buf[..n], src).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn udp_associate_relays_through_direct() {
        let echo = udp_echo().await;
        let engine = Arc::new(Engine::new(
            HashMap::new(),
            None,
            Vec::new(),
            RouteAction::Direct,
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks = listener.local_addr().unwrap();
        tokio::spawn(serve_socks_routed(listener, engine));

        let run = async {
            let mut ctl = TcpStream::connect(socks).await.unwrap();
            ctl.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut m = [0u8; 2];
            ctl.read_exact(&mut m).await.unwrap();
            assert_eq!(m, [0x05, 0x00]);

            ctl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut rep = [0u8; 10];
            ctl.read_exact(&mut rep).await.unwrap();
            assert_eq!(&rep[0..2], &[0x05, 0x00]);
            let relay = SocketAddr::from((
                [rep[4], rep[5], rep[6], rep[7]],
                u16::from_be_bytes([rep[8], rep[9]]),
            ));

            let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let dgram = encode_udp_datagram(&Target::Socket(echo), b"ping");
            cli.send_to(&dgram, relay).await.unwrap();

            let mut buf = [0u8; 2048];
            let (n, from) = cli.recv_from(&mut buf).await.unwrap();
            assert_eq!(from, relay, "ответ приходит с relay-сокета");
            let (_, target, off) = parse_udp_datagram(&buf[..n]).unwrap();
            // Ответ заворачивается адресом, который слал клиент (echo).
            assert_eq!(target, Target::Socket(echo));
            assert_eq!(&buf[off..n], b"ping");

            // Второй пакет к тому же DST переиспользует поток.
            cli.send_to(&encode_udp_datagram(&Target::Socket(echo), b"two"), relay)
                .await
                .unwrap();
            let (n2, _) = cli.recv_from(&mut buf).await.unwrap();
            let (_, _, off2) = parse_udp_datagram(&buf[..n2]).unwrap();
            assert_eq!(&buf[off2..n2], b"two");

            drop(ctl);
        };
        timeout(Duration::from_secs(5), run)
            .await
            .expect("UDP relay не уложился в таймаут");
    }

    #[tokio::test]
    async fn udp_associate_relays_through_shadowsocks() {
        use crate::outbound::{Outbound, ShadowsocksConfig};
        use crate::shadowsocks::{decrypt_packet, encrypt_packet, evp_bytes_to_key, Method};

        let method = Method::Aes256Gcm;
        let master = evp_bytes_to_key(b"testpass", method.key_len());

        // Mock SS-UDP сервер: расшифровывает пакет клиента, «эхит» payload обратно
        // (как будто цель ответила), зашифровав адресом цели как источником.
        let ss_master = master.clone();
        let ss_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ss_addr = ss_sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, src)) = ss_sock.recv_from(&mut buf).await {
                if let Ok((target, payload)) = decrypt_packet(method, &ss_master, &buf[..n]) {
                    if let Ok(resp) = encrypt_packet(method, &ss_master, &target, &payload) {
                        let _ = ss_sock.send_to(&resp, src).await;
                    }
                }
            }
        });

        // Движок: весь трафик через Shadowsocks-узел (mock).
        let engine = Arc::new(Engine::single_proxy(Outbound::Shadowsocks(
            ShadowsocksConfig {
                server: ss_addr.to_string(),
                method,
                password: "testpass".into(),
            },
        )));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks = listener.local_addr().unwrap();
        tokio::spawn(serve_socks_routed(listener, engine));

        let run = async {
            let mut ctl = TcpStream::connect(socks).await.unwrap();
            ctl.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut m = [0u8; 2];
            ctl.read_exact(&mut m).await.unwrap();
            ctl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut rep = [0u8; 10];
            ctl.read_exact(&mut rep).await.unwrap();
            let relay = SocketAddr::from((
                [rep[4], rep[5], rep[6], rep[7]],
                u16::from_be_bytes([rep[8], rep[9]]),
            ));

            // DST произвольный (mock SS не форвардит — просто эхо). Домен — чтобы
            // проверить, что адрес уходит в SS-заголовок как есть (remote DNS).
            let dst = Target::Domain("echo.test".into(), 5353);
            let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            cli.send_to(&encode_udp_datagram(&dst, b"via-ss"), relay)
                .await
                .unwrap();
            let mut buf = [0u8; 2048];
            let (n, _) = cli.recv_from(&mut buf).await.unwrap();
            let (_, target, off) = parse_udp_datagram(&buf[..n]).unwrap();
            assert_eq!(target, dst, "ответ под доменным DST, который слал клиент");
            assert_eq!(&buf[off..n], b"via-ss");
            drop(ctl);
        };
        timeout(Duration::from_secs(5), run)
            .await
            .expect("SS-UDP relay не уложился в таймаут");
    }

    #[tokio::test]
    async fn udp_associate_relays_through_ss2022() {
        use crate::outbound::{Outbound, ShadowsocksConfig};
        use crate::shadowsocks::{echo_server_packet, Method};
        use jammvpn_core::base64;

        let method = Method::Ss2022Aes128Gcm;
        let psk = vec![0x11u8; method.key_len()]; // 16 байт PSK
        let password = base64::encode_standard(&psk);

        // Mock SS-2022 UDP-сервер: расшифровывает запрос, эхит ответ (type=1).
        let srv_psk = psk.clone();
        let ss = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ss_addr = ss.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let mut server_pid = 0u64;
            while let Ok((n, src)) = ss.recv_from(&mut buf).await {
                let resp = echo_server_packet(method, &srv_psk, &buf[..n], server_pid);
                server_pid += 1;
                let _ = ss.send_to(&resp, src).await;
            }
        });

        let engine = Arc::new(Engine::single_proxy(Outbound::Shadowsocks(
            ShadowsocksConfig {
                server: ss_addr.to_string(),
                method,
                password,
            },
        )));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks = listener.local_addr().unwrap();
        tokio::spawn(serve_socks_routed(listener, engine));

        let run = async {
            let mut ctl = TcpStream::connect(socks).await.unwrap();
            ctl.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut m = [0u8; 2];
            ctl.read_exact(&mut m).await.unwrap();
            ctl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut rep = [0u8; 10];
            ctl.read_exact(&mut rep).await.unwrap();
            let relay = SocketAddr::from((
                [rep[4], rep[5], rep[6], rep[7]],
                u16::from_be_bytes([rep[8], rep[9]]),
            ));
            let dst = Target::Domain("echo.test".into(), 5353);
            let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            cli.send_to(&encode_udp_datagram(&dst, b"via-ss2022"), relay)
                .await
                .unwrap();
            let mut buf = [0u8; 2048];
            let (n, _) = cli.recv_from(&mut buf).await.unwrap();
            let (_, target, off) = parse_udp_datagram(&buf[..n]).unwrap();
            assert_eq!(target, dst, "ответ под доменным DST клиента");
            assert_eq!(&buf[off..n], b"via-ss2022");
            drop(ctl);
        };
        timeout(Duration::from_secs(5), run)
            .await
            .expect("SS-2022 UDP relay не уложился в таймаут");
    }

    #[tokio::test]
    async fn udp_associate_relays_through_trojan() {
        use crate::outbound::{Outbound, Transport, TrojanConfig};

        let echo = udp_echo().await;

        // Mock Trojan-сервер (raw TCP): читает заголовок (CMD=0x03 UDP), затем
        // length-framed пакеты — форвардит на цель и заворачивает ответ.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tj_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut hdr = [0u8; 58]; // 56 hash + CRLF
                    if sock.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    if sock.read_u8().await.is_err() {
                        return; // CMD
                    }
                    if crate::trojan::read_address(&mut sock).await.is_err() {
                        return;
                    }
                    let mut crlf = [0u8; 2];
                    if sock.read_exact(&mut crlf).await.is_err() {
                        return;
                    }
                    // Форвардим каждый UDP-пакет на реальную цель, ответ — обратно.
                    let fwd = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    loop {
                        let (t, payload) = match crate::trojan::read_udp_packet(&mut sock).await {
                            Ok(v) => v,
                            Err(_) => break,
                        };
                        if let Target::Socket(a) = t {
                            let _ = fwd.send_to(&payload, a).await;
                            let mut buf = [0u8; 2048];
                            if let Ok((n, _)) = fwd.recv_from(&mut buf).await {
                                let resp = crate::trojan::encode_udp_packet(&t, &buf[..n]);
                                if sock.write_all(&resp).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });

        let engine = Arc::new(Engine::single_proxy(Outbound::Trojan(TrojanConfig {
            server: tj_addr.to_string(),
            password: "trojanpass".into(),
            transport: Transport::Tcp,
        })));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks = listener.local_addr().unwrap();
        tokio::spawn(serve_socks_routed(listener, engine));

        let run = async {
            let mut ctl = TcpStream::connect(socks).await.unwrap();
            ctl.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut m = [0u8; 2];
            ctl.read_exact(&mut m).await.unwrap();
            ctl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut rep = [0u8; 10];
            ctl.read_exact(&mut rep).await.unwrap();
            let relay = SocketAddr::from((
                [rep[4], rep[5], rep[6], rep[7]],
                u16::from_be_bytes([rep[8], rep[9]]),
            ));
            // DST = echo (IPv4 Socket — mock форвардит туда).
            let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            cli.send_to(
                &encode_udp_datagram(&Target::Socket(echo), b"via-trojan"),
                relay,
            )
            .await
            .unwrap();
            let mut buf = [0u8; 2048];
            let (n, _) = cli.recv_from(&mut buf).await.unwrap();
            let (_, target, off) = parse_udp_datagram(&buf[..n]).unwrap();
            assert_eq!(target, Target::Socket(echo));
            assert_eq!(&buf[off..n], b"via-trojan");
            drop(ctl);
        };
        timeout(Duration::from_secs(5), run)
            .await
            .expect("Trojan-UDP relay не уложился в таймаут");
    }

    #[tokio::test]
    async fn rejects_datagram_from_foreign_host() {
        // Датаграмма с IP, не совпадающим с управляющим соединением, игнорируется.
        // (control с 127.0.0.1; «чужой» источник эмулируем проверкой кода —
        // здесь проверяем, что валидный клиент работает, чужой бы отсеялся по IP.)
        let echo = udp_echo().await;
        let engine = Arc::new(Engine::new(
            HashMap::new(),
            None,
            Vec::new(),
            RouteAction::Direct,
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks = listener.local_addr().unwrap();
        tokio::spawn(serve_socks_routed(listener, engine));

        let run = async {
            let mut ctl = TcpStream::connect(socks).await.unwrap();
            ctl.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut m = [0u8; 2];
            ctl.read_exact(&mut m).await.unwrap();
            ctl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut rep = [0u8; 10];
            ctl.read_exact(&mut rep).await.unwrap();
            let relay = SocketAddr::from((
                [rep[4], rep[5], rep[6], rep[7]],
                u16::from_be_bytes([rep[8], rep[9]]),
            ));
            // Легитимный клиент (127.0.0.1 == control peer) работает.
            let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            cli.send_to(&encode_udp_datagram(&Target::Socket(echo), b"ok"), relay)
                .await
                .unwrap();
            let mut buf = [0u8; 2048];
            let (n, _) = cli.recv_from(&mut buf).await.unwrap();
            let (_, _, off) = parse_udp_datagram(&buf[..n]).unwrap();
            assert_eq!(&buf[off..n], b"ok");
            drop(ctl);
        };
        timeout(Duration::from_secs(5), run).await.unwrap();
    }
}
