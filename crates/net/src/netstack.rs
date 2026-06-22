//! Userspace tun2socks-движок: принимает «сырые» IP-пакеты ([`Netstack::inject`]),
//! терминирует TCP/UDP-потоки к ПРОИЗВОЛЬНЫМ назначениям (smoltcp с `any_ip`) и
//! релеит каждый поток через [`Engine`] (тот же роутинг/исходящие, что у прокси).
//! Сгенерированные стеком исходящие IP-пакеты отдаются через [`NetstackOut`].
//!
//! Общий для WG-сервера ([`crate::wgserver`]) и перехвата приложений (split):
//! источник пакетов (WG-декапсуляция / захват NDIS) и приёмник (WG-инкапсуляция /
//! инъекция в ОС) — снаружи; здесь только терминация и релей.

use crate::engine::{Decision, Engine};
use crate::target::Target;
use crate::wireguard::device::WgDevice;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, IpProtocol, Ipv4Packet,
    Ipv6Packet, TcpPacket, UdpPacket,
};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant as StdInstant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::runtime::Handle;
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;

/// Размер буфера TCP-сокета.
const SOCKET_BUF: usize = 64 * 1024;
/// Слоты метаданных UDP-датаграмм.
const UDP_META: usize = 32;
/// Простой UDP-flow без активности дольше — закрываем.
const UDP_IDLE: Duration = Duration::from_secs(60);
/// Таймаут ожидания установления входящего TCP.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);

/// Метка цели для монитора соединений.
fn target_label(t: &Target) -> String {
    match t {
        Target::Socket(a) => a.to_string(),
        Target::Domain(h, p) => format!("{h}:{p}"),
    }
}

/// Конвертирует smoltcp-эндпоинт в `std::net::SocketAddr`.
fn ep_to_sockaddr(ep: IpEndpoint) -> SocketAddr {
    let ip = match ep.addr {
        IpAddress::Ipv4(a) => IpAddr::V4(a),
        IpAddress::Ipv6(a) => IpAddr::V6(a),
    };
    SocketAddr::new(ip, ep.port)
}

/// Разобранный из IP-пакета поток (5-кортеж + признак SYN для TCP).
struct Flow {
    src: IpEndpoint,
    dst: IpEndpoint,
    proto: IpProtocol,
    syn: bool,
}

/// Парсит IPv4/IPv6 + TCP/UDP заголовки IP-пакета.
fn parse_flow(pkt: &[u8]) -> Option<Flow> {
    if pkt.is_empty() {
        return None;
    }
    let (src_ip, dst_ip, proto, l4): (IpAddress, IpAddress, IpProtocol, &[u8]) = match pkt[0] >> 4 {
        4 => {
            let ip = Ipv4Packet::new_checked(pkt).ok()?;
            let hdr = ((pkt[0] & 0x0F) as usize) * 4;
            (
                IpAddress::Ipv4(ip.src_addr()),
                IpAddress::Ipv4(ip.dst_addr()),
                ip.next_header(),
                pkt.get(hdr..)?,
            )
        }
        6 => {
            let ip = Ipv6Packet::new_checked(pkt).ok()?;
            (
                IpAddress::Ipv6(ip.src_addr()),
                IpAddress::Ipv6(ip.dst_addr()),
                ip.next_header(),
                pkt.get(40..)?,
            )
        }
        _ => return None,
    };
    match proto {
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(l4).ok()?;
            Some(Flow {
                src: IpEndpoint::new(src_ip, tcp.src_port()),
                dst: IpEndpoint::new(dst_ip, tcp.dst_port()),
                proto,
                syn: tcp.syn() && !tcp.ack(),
            })
        }
        IpProtocol::Udp => {
            let udp = UdpPacket::new_checked(l4).ok()?;
            Some(Flow {
                src: IpEndpoint::new(src_ip, udp.src_port()),
                dst: IpEndpoint::new(dst_ip, udp.dst_port()),
                proto,
                syn: false,
            })
        }
        _ => None,
    }
}

/// Разделяемый сетевой стек. Под `std::sync::Mutex`; НЕ держать через `.await`.
struct Stack {
    iface: Interface,
    device: WgDevice,
    sockets: SocketSet<'static>,
    tcp_seen: HashSet<(SocketAddr, SocketAddr)>,
    udp_flows: HashMap<(SocketAddr, SocketAddr), SocketHandle>,
    abandoned: Vec<SocketHandle>,
}

/// Общее состояние (видно driver-task и relay-задачам).
struct Shared {
    stack: Mutex<Stack>,
    notify: Notify,
    wake_tx: mpsc::UnboundedSender<()>,
    out_tx: mpsc::UnboundedSender<Vec<u8>>,
    engine: Arc<Engine>,
    /// Хендлы relay-задач — для отмены при остановке стека.
    relays: Mutex<Vec<JoinHandle<()>>>,
    /// Хендл tokio-рантайма: спавн relay из любого (в т.ч. не-async) потока,
    /// т.к. `inject` может вызываться из потока захвата NDIS.
    handle: Handle,
}

impl Shared {
    fn kick(&self) {
        let _ = self.wake_tx.send(());
    }
}

/// Приёмник исходящих IP-пакетов, сгенерированных стеком.
pub struct NetstackOut {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl NetstackOut {
    /// Следующий исходящий IP-пакет (для отправки пиру / инъекции в ОС).
    /// `None` — стек остановлен (все отправители сброшены).
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }
}

/// Userspace tun2socks-движок.
pub struct Netstack {
    shared: Arc<Shared>,
    _driver: tokio::task::JoinHandle<()>,
}

impl Netstack {
    /// Создаёт стек: внутренний интерфейс `iface_ip/prefix`, релей через `engine`.
    /// Возвращает дескриптор и приёмник исходящих пакетов.
    pub fn new(engine: Arc<Engine>, iface_ip: Ipv4Addr, prefix: u8) -> (Netstack, NetstackOut) {
        let mut device = WgDevice::new();
        let config = Config::new(HardwareAddress::Ip);
        let base = StdInstant::now();
        let mut iface = Interface::new(config, &mut device, SmolInstant::from_micros(0));
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(iface_ip), prefix));
        });
        let _ = iface.routes_mut().add_default_ipv4_route(iface_ip);
        // КЛЮЧЕВОЕ: принимать пакеты к произвольным адресам (tun2socks).
        iface.set_any_ip(true);

        let (wake_tx, wake_rx) = mpsc::unbounded_channel();
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            stack: Mutex::new(Stack {
                iface,
                device,
                sockets: SocketSet::new(Vec::new()),
                tcp_seen: HashSet::new(),
                udp_flows: HashMap::new(),
                abandoned: Vec::new(),
            }),
            notify: Notify::new(),
            wake_tx,
            out_tx,
            engine,
            relays: Mutex::new(Vec::new()),
            handle: Handle::current(),
        });

        let driver = tokio::spawn(run_driver(shared.clone(), wake_rx, base));
        (
            Netstack {
                shared,
                _driver: driver,
            },
            NetstackOut { rx: out_rx },
        )
    }

    /// Подаёт входящий IP-пакет (от пира/приложения) в стек.
    pub fn inject(&self, ip_packet: &[u8]) {
        demux_and_enqueue(&self.shared, ip_packet);
    }
}

impl Drop for Netstack {
    fn drop(&mut self) {
        self._driver.abort();
        if let Ok(mut relays) = self.shared.relays.lock() {
            for h in relays.drain(..) {
                h.abort();
            }
        }
    }
}

/// Driver-task: единственное место, где вызывается `iface.poll`. Сливает
/// сгенерированные исходящие IP-пакеты в `out_tx`.
async fn run_driver(
    shared: Arc<Shared>,
    mut wake_rx: mpsc::UnboundedReceiver<()>,
    base: StdInstant,
) {
    loop {
        let (outbox, delay) = {
            let mut st = shared.stack.lock().unwrap();
            let now = SmolInstant::from_micros(base.elapsed().as_micros() as i64);
            let Stack {
                iface,
                device,
                sockets,
                abandoned,
                ..
            } = &mut *st;
            iface.poll(now, device, sockets);
            abandoned.retain(|&h| {
                if sockets.get::<tcp::Socket>(h).state() == tcp::State::Closed {
                    sockets.remove(h);
                    false
                } else {
                    true
                }
            });
            let mut outbox: Vec<Vec<u8>> = Vec::new();
            while let Some(ip_pkt) = device.tx.pop_front() {
                outbox.push(ip_pkt);
            }
            let delay = iface
                .poll_delay(now, sockets)
                .map(|d| Duration::from_micros(d.total_micros()));
            (outbox, delay)
        };
        for pkt in outbox {
            if shared.out_tx.send(pkt).is_err() {
                return; // приёмник сброшен — стек больше не нужен.
            }
        }
        shared.notify.notify_waiters();
        // Подчищаем завершённые relay-хендлы (анти-рост памяти).
        if let Ok(mut relays) = shared.relays.lock() {
            relays.retain(|h| !h.is_finished());
        }

        tokio::select! {
            _ = async { match delay {
                Some(d) => tokio::time::sleep(d).await,
                None => std::future::pending::<()>().await,
            } } => {}
            r = wake_rx.recv() => {
                if r.is_none() { return; }
            }
        }
    }
}

/// Создаёт сокет для нового потока (если нужно), спавнит relay и кладёт пакет в стек.
fn demux_and_enqueue(shared: &Arc<Shared>, ip_pkt: &[u8]) {
    let flow = parse_flow(ip_pkt);
    let mut st = shared.stack.lock().unwrap();

    if let Some(f) = flow {
        let key = (ep_to_sockaddr(f.src), ep_to_sockaddr(f.dst));
        match f.proto {
            IpProtocol::Tcp if f.syn && !st.tcp_seen.contains(&key) => {
                let mut sock = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0u8; SOCKET_BUF]),
                    tcp::SocketBuffer::new(vec![0u8; SOCKET_BUF]),
                );
                let listen = IpListenEndpoint {
                    addr: Some(f.dst.addr),
                    port: f.dst.port,
                };
                if sock.listen(listen).is_ok() {
                    let handle = st.sockets.add(sock);
                    st.tcp_seen.insert(key);
                    let dst = Target::Socket(ep_to_sockaddr(f.dst));
                    let jh = shared.handle.spawn(relay_tcp(shared.clone(), handle, key, dst));
                    shared.relays.lock().unwrap().push(jh);
                }
            }
            IpProtocol::Udp if !st.udp_flows.contains_key(&key) => {
                let rx = udp::PacketBuffer::new(
                    vec![udp::PacketMetadata::EMPTY; UDP_META],
                    vec![0u8; SOCKET_BUF],
                );
                let tx = udp::PacketBuffer::new(
                    vec![udp::PacketMetadata::EMPTY; UDP_META],
                    vec![0u8; SOCKET_BUF],
                );
                let mut sock = udp::Socket::new(rx, tx);
                let listen = IpListenEndpoint {
                    addr: Some(f.dst.addr),
                    port: f.dst.port,
                };
                if sock.bind(listen).is_ok() {
                    let handle = st.sockets.add(sock);
                    st.udp_flows.insert(key, handle);
                    let dst = Target::Socket(ep_to_sockaddr(f.dst));
                    let jh = shared
                        .handle
                        .spawn(relay_udp(shared.clone(), handle, key, dst, f.src));
                    shared.relays.lock().unwrap().push(jh);
                }
            }
            _ => {}
        }
    }

    st.device.rx.push_back(ip_pkt.to_vec());
    drop(st);
    shared.kick();
}

/// Ждёт перехода TCP-сокета в Established (или ошибку/таймаут).
async fn wait_established(shared: &Arc<Shared>, handle: SocketHandle) -> bool {
    let fut = async {
        loop {
            let notified = shared.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut st = shared.stack.lock().unwrap();
                let s = st.sockets.get_mut::<tcp::Socket>(handle);
                use tcp::State::*;
                match s.state() {
                    Established => return true,
                    Closed | TimeWait | Closing | LastAck | FinWait1 | FinWait2 => return false,
                    _ => {}
                }
            }
            notified.await;
        }
    };
    matches!(tokio::time::timeout(ACCEPT_TIMEOUT, fut).await, Ok(true))
}

/// Relay одного TCP-потока: стек ↔ исходящий (через Engine).
async fn relay_tcp(
    shared: Arc<Shared>,
    handle: SocketHandle,
    key: (SocketAddr, SocketAddr),
    dst: Target,
) {
    if wait_established(&shared, handle).await {
        let routed = shared.engine.route(&dst).await;
        if let Decision::Connect(ob) = routed.decision {
            if let Ok(up) = ob.connect_tcp(&routed.target).await {
                let down = NsTcpStream::new(shared.clone(), handle);
                // Регистрируем в мониторе соединений (видно в статистике).
                let via = if matches!(ob, crate::outbound::Outbound::Direct) {
                    "direct"
                } else {
                    "proxy"
                };
                let g = crate::conn::register(target_label(&dst), via, Some(key.0));
                let _ = crate::conn::copy_counted(down, up, &g).await;
            }
        }
    }
    {
        let mut st = shared.stack.lock().unwrap();
        st.tcp_seen.remove(&key);
        if st.sockets.get::<tcp::Socket>(handle).state() != tcp::State::Closed {
            st.sockets.get_mut::<tcp::Socket>(handle).close();
            st.abandoned.push(handle);
        } else {
            st.sockets.remove(handle);
        }
    }
    shared.kick();
}

/// Relay одного UDP-flow: стек ↔ исходящий (через Engine).
async fn relay_udp(
    shared: Arc<Shared>,
    handle: SocketHandle,
    key: (SocketAddr, SocketAddr),
    dst: Target,
    client: IpEndpoint,
) {
    let routed = shared.engine.route(&dst).await;
    if let Decision::Connect(ob) = routed.decision {
        if let Ok(sess) = ob.connect_udp(&routed.target).await {
            let via = if matches!(ob, crate::outbound::Outbound::Direct) {
                "direct"
            } else {
                "proxy"
            };
            // Регистрируем в мониторе соединений (видно в статистике, как у TCP).
            let g = crate::conn::register(target_label(&dst), via, Some(key.0));
            let sess = Arc::new(sess);
            // Направления — НЕЗАВИСИМЫЕ циклы, а НЕ ветки `select!`: select! отменял
            // бы `sess.recv()` на полпути `read_exact` при каждом исходящем пакете,
            // ломая length-фрейминг VLESS/Trojan UDP → ответы (download) рвутся
            // (Discord: «он меня слышит, а я его — нет»). Таймаут на каждой операции
            // = простой направления; отмена recv по таймауту безопасна (мы выходим).
            let egress = {
                let shared = shared.clone();
                let sess = sess.clone();
                let up = Arc::clone(&g.up);
                async move {
                    while let Ok(Some(data)) =
                        tokio::time::timeout(UDP_IDLE, udp_recv(&shared, handle)).await
                    {
                        up.fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
                        if sess.send(&data).await.is_err() {
                            break;
                        }
                    }
                }
            };
            let ingress = {
                let shared = shared.clone();
                let sess = sess.clone();
                let down = Arc::clone(&g.down);
                async move {
                    while let Ok(Ok(data)) =
                        tokio::time::timeout(UDP_IDLE, sess.recv()).await
                    {
                        down.fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
                        udp_send(&shared, handle, &data, client);
                    }
                }
            };
            tokio::join!(egress, ingress);
            sess.close().await;
            drop(g);
        }
    }
    {
        let mut st = shared.stack.lock().unwrap();
        st.udp_flows.remove(&key);
        st.sockets.remove(handle);
    }
    shared.kick();
}

/// Принимает датаграмму из стек-UDP-сокета. `None` — сокет закрыт.
async fn udp_recv(shared: &Arc<Shared>, handle: SocketHandle) -> Option<Vec<u8>> {
    std::future::poll_fn(|cx| {
        let mut st = shared.stack.lock().unwrap();
        let s = st.sockets.get_mut::<udp::Socket>(handle);
        if s.can_recv() {
            let mut buf = vec![0u8; 65_535];
            return match s.recv_slice(&mut buf) {
                Ok((n, _)) => {
                    buf.truncate(n);
                    Poll::Ready(Some(buf))
                }
                Err(_) => Poll::Ready(None),
            };
        }
        s.register_recv_waker(cx.waker());
        drop(st);
        shared.kick();
        Poll::Pending
    })
    .await
}

/// Отправляет ответ цели обратно источнику через стек-UDP-сокет.
fn udp_send(shared: &Arc<Shared>, handle: SocketHandle, data: &[u8], client: IpEndpoint) {
    let mut st = shared.stack.lock().unwrap();
    let s = st.sockets.get_mut::<udp::Socket>(handle);
    let _ = s.send_slice(data, client);
    drop(st);
    shared.kick();
}

/// `AsyncRead`/`AsyncWrite` поверх стек-TCP-сокета.
struct NsTcpStream {
    shared: Arc<Shared>,
    handle: SocketHandle,
}

impl NsTcpStream {
    fn new(shared: Arc<Shared>, handle: SocketHandle) -> Self {
        Self { shared, handle }
    }
}

impl AsyncRead for NsTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let mut st = me.shared.stack.lock().unwrap();
        let s = st.sockets.get_mut::<tcp::Socket>(me.handle);
        if s.can_recv() {
            let n = s
                .recv_slice(buf.initialize_unfilled())
                .map_err(|e| io::Error::other(format!("netstack: recv: {e:?}")))?;
            buf.advance(n);
            drop(st);
            me.shared.kick();
            return Poll::Ready(Ok(()));
        }
        if !s.may_recv() {
            return Poll::Ready(Ok(())); // EOF
        }
        s.register_recv_waker(cx.waker());
        drop(st);
        me.shared.kick();
        Poll::Pending
    }
}

impl AsyncWrite for NsTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let mut st = me.shared.stack.lock().unwrap();
        let s = st.sockets.get_mut::<tcp::Socket>(me.handle);
        if !s.may_send() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "netstack: сокет закрыт для записи",
            )));
        }
        if s.can_send() {
            let n = s
                .send_slice(data)
                .map_err(|e| io::Error::other(format!("netstack: send: {e:?}")))?;
            drop(st);
            me.shared.kick();
            return Poll::Ready(Ok(n));
        }
        s.register_send_waker(cx.waker());
        drop(st);
        me.shared.kick();
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shared.kick();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        {
            let mut st = me.shared.stack.lock().unwrap();
            st.sockets.get_mut::<tcp::Socket>(me.handle).close();
        }
        me.shared.kick();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;
    use std::time::Duration;

    /// Контрольная сумма IPv4-заголовка (поле суммы = 0 на входе).
    fn ipv4_checksum(hdr: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut i = 0;
        while i + 1 < hdr.len() {
            sum += u16::from_be_bytes([hdr[i], hdr[i + 1]]) as u32;
            i += 2;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Собирает IPv4+UDP пакет (UDP-сумма = 0, допустимо для IPv4).
    fn udp_packet(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
        let total = 20 + 8 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64; // ttl
        p[9] = 17; // udp
        p[12..16].copy_from_slice(&src.ip().octets());
        p[16..20].copy_from_slice(&dst.ip().octets());
        let cks = ipv4_checksum(&p[..20]);
        p[10..12].copy_from_slice(&cks.to_be_bytes());
        p[20..22].copy_from_slice(&src.port().to_be_bytes());
        p[22..24].copy_from_slice(&dst.port().to_be_bytes());
        p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p[28..].copy_from_slice(payload);
        p
    }

    /// Сквозной UDP через Direct: ответ должен прийти ОТ цели (а не от iface),
    /// и соединение должно попасть в монитор со счётчиком байт (фикс статистики).
    #[tokio::test]
    async fn udp_relay_direct_echo_src_and_stats() {
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = match echo.local_addr().unwrap() {
            SocketAddr::V4(a) => a,
            _ => unreachable!(),
        };
        tokio::spawn(async move {
            let mut b = vec![0u8; 2048];
            while let Ok((n, peer)) = echo.recv_from(&mut b).await {
                let _ = echo.send_to(&b[..n], peer).await;
            }
        });

        let engine = Arc::new(crate::engine::Engine::new(
            HashMap::new(),
            None,
            vec![],
            jammvpn_core::RouteAction::Direct,
        ));
        let (ns, mut out) = Netstack::new(engine, Ipv4Addr::new(10, 9, 0, 1), 24);
        let app = SocketAddrV4::new(Ipv4Addr::new(10, 9, 0, 5), 40000);

        ns.inject(&udp_packet(app, echo_addr, b"voice-ping"));

        let resp = tokio::time::timeout(Duration::from_secs(5), out.recv())
            .await
            .expect("нет ответного пакета (download UDP сломан)")
            .expect("стек остановлен");
        let flow = parse_flow(&resp).expect("ответ — не UDP/IP");
        assert_eq!(flow.proto, IpProtocol::Udp);
        // КЛЮЧЕВОЕ: src ответа = цель (echo), а не iface 10.9.0.1.
        assert_eq!(ep_to_sockaddr(flow.src), SocketAddr::V4(echo_addr));
        assert_eq!(ep_to_sockaddr(flow.dst), SocketAddr::V4(app));
        assert_eq!(&resp[28..], b"voice-ping");

        let snap = crate::conn::snapshot();
        assert!(
            snap.iter()
                .any(|c| c.via == "direct" && c.target == echo_addr.to_string() && c.up >= 10),
            "UDP-соединение должно быть в мониторе со счётчиком байт"
        );
        drop(ns);
    }
}
