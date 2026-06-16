//! Локальный WireGuard-сервер (inbound-шлюз).
//!
//! JammVPN поднимает WG-эндпоинт (boringtun как responder), к которому
//! подключается клиент (приложение/устройство по экспортированному `.conf`).
//! Весь трафик клиента терминируется userspace-стеком ([`smoltcp`] с `any_ip` —
//! приём пакетов к ПРОИЗВОЛЬНЫМ назначениям, паттерн tun2socks) и релеится
//! наружу через [`Engine`] (тот же роутинг/исходящие, что у основного прокси).
//!
//! Схема: `клиент → WG → этот сервер → Engine/выбранный узел → апстрим-туннель`.
//! Поддерживается один пир (один клиентский ключ). Обфускации нет — соединение
//! локальное (LAN/localhost), цензуру обходит уже апстрим-узел.

use crate::engine::{Decision, Engine};
use crate::target::Target;
use crate::wireguard::device::WgDevice;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
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
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinSet;

/// Размер буфера TCP-сокета через стек.
const SOCKET_BUF: usize = 64 * 1024;
/// Слоты метаданных UDP-датаграмм.
const UDP_META: usize = 32;
/// Период тика boringtun (handshake/keepalive/rekey).
const TIMER_TICK: Duration = Duration::from_millis(250);
/// Простой UDP-flow без активности дольше — закрываем.
const UDP_IDLE: Duration = Duration::from_secs(60);
/// Таймаут ожидания установления входящего TCP.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);
const SCRATCH: usize = 65535;

/// Генерирует X25519-приватный ключ (32 байта, clamped) из системного ГСЧ.
pub fn gen_private_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    getrandom::getrandom(&mut k).expect("getrandom");
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

/// Публичный ключ из приватного.
pub fn public_key(private: &[u8; 32]) -> [u8; 32] {
    *PublicKey::from(&StaticSecret::from(*private)).as_bytes()
}

/// Генерирует preshared-ключ (32 случайных байта).
pub fn gen_preshared_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    getrandom::getrandom(&mut k).expect("getrandom");
    k
}

/// Параметры локального WG-сервера.
pub struct WgServerParams {
    /// UDP-адрес прослушивания (обычно `0.0.0.0:port`).
    pub listen: SocketAddr,
    /// Статический приватный ключ сервера.
    pub server_private: [u8; 32],
    /// Публичный ключ единственного клиента-пира.
    pub client_public: [u8; 32],
    /// Preshared-ключ (опционально).
    pub preshared_key: Option<[u8; 32]>,
    /// IP сервера в туннеле (gateway, напр. 10.9.0.1).
    pub server_ip: Ipv4Addr,
    /// Длина префикса подсети туннеля.
    pub prefix: u8,
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

/// Парсит IPv4/IPv6 + TCP/UDP заголовки входящего пакета клиента.
fn parse_flow(pkt: &[u8]) -> Option<Flow> {
    if pkt.is_empty() {
        return None;
    }
    let (src_ip, dst_ip, proto, l4): (IpAddress, IpAddress, IpProtocol, &[u8]) = match pkt[0] >> 4 {
        4 => {
            let ip = Ipv4Packet::new_checked(pkt).ok()?;
            (
                IpAddress::Ipv4(ip.src_addr()),
                IpAddress::Ipv4(ip.dst_addr()),
                ip.next_header(),
                {
                    // payload() возвращает срез внутри pkt; пересоберём по смещению.
                    let hdr = ((pkt[0] & 0x0F) as usize) * 4;
                    pkt.get(hdr..)?
                },
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
    /// 5-кортежи TCP, для которых уже создан сокет (анти-дубликат на ретрансмиты).
    tcp_seen: HashSet<(SocketAddr, SocketAddr)>,
    /// UDP-flow → handle сокета.
    udp_flows: HashMap<(SocketAddr, SocketAddr), SocketHandle>,
    /// Сокеты на отложенное удаление (после грациозного закрытия).
    abandoned: Vec<SocketHandle>,
}

/// Общее состояние сервера (видно driver-task и relay-задачам).
struct Shared {
    stack: Mutex<Stack>,
    notify: Notify,
    wake_tx: mpsc::UnboundedSender<()>,
    engine: Arc<Engine>,
}

impl Shared {
    fn kick(&self) {
        let _ = self.wake_tx.send(());
    }
}

/// Запущенный локальный WG-сервер.
pub struct WgServer {
    driver: tokio::task::JoinHandle<()>,
    addr: SocketAddr,
}

impl WgServer {
    /// Поднимает сервер: bind UDP, netstack с `any_ip`, boringtun-responder,
    /// driver-task. Возвращается после успешного bind.
    pub async fn start(params: WgServerParams, engine: Arc<Engine>) -> io::Result<WgServer> {
        let udp = Arc::new(UdpSocket::bind(params.listen).await?);
        let addr = udp.local_addr()?;

        let tunn = Tunn::new(
            StaticSecret::from(params.server_private),
            PublicKey::from(params.client_public),
            params.preshared_key,
            None,
            0,
            None,
        );

        let mut device = WgDevice::new();
        let config = Config::new(HardwareAddress::Ip);
        let base = StdInstant::now();
        let mut iface = Interface::new(config, &mut device, SmolInstant::from_micros(0));
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(
                IpAddress::Ipv4(params.server_ip),
                params.prefix,
            ));
        });
        let _ = iface.routes_mut().add_default_ipv4_route(params.server_ip);
        // КЛЮЧЕВОЕ: принимать пакеты к произвольным адресам (tun2socks).
        iface.set_any_ip(true);

        let (wake_tx, wake_rx) = mpsc::unbounded_channel();
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
            engine,
        });

        let driver = tokio::spawn(run_driver(shared, udp, tunn, wake_rx, base));
        Ok(WgServer { driver, addr })
    }

    /// Фактический UDP-адрес прослушивания (важно при `port = 0`).
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Останавливает сервер (driver и все relay-задачи прекращаются).
    pub fn stop(self) {
        self.driver.abort();
    }
}

/// Тело driver-task: единственное место, где вызываются `iface.poll`,
/// `Tunn::{encapsulate,decapsulate,update_timers}` и UDP send/recv.
async fn run_driver(
    shared: Arc<Shared>,
    udp: Arc<UdpSocket>,
    mut tunn: Tunn,
    mut wake_rx: mpsc::UnboundedReceiver<()>,
    base: StdInstant,
) {
    let mut scratch = vec![0u8; SCRATCH];
    let mut udp_buf = vec![0u8; SCRATCH];
    let mut ticker = tokio::time::interval(TIMER_TICK);
    let mut peer: Option<SocketAddr> = None;
    // Relay-задачи живут в JoinSet: при завершении driver (abort) — все отменяются.
    let mut relays: JoinSet<()> = JoinSet::new();

    loop {
        // 1. Поллим стек, собираем исходящие IP-пакеты, шифруем.
        let outbox = {
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
                if let TunnResult::WriteToNetwork(b) = tunn.encapsulate(&ip_pkt, &mut scratch) {
                    outbox.push(b.to_vec());
                }
            }
            outbox
        };
        if let Some(addr) = peer {
            for dg in &outbox {
                let _ = udp.send_to(dg, addr).await;
            }
        }
        shared.notify.notify_waiters();
        while relays.try_join_next().is_some() {}

        let delay = {
            let mut st = shared.stack.lock().unwrap();
            let now = SmolInstant::from_micros(base.elapsed().as_micros() as i64);
            let Stack {
                iface, sockets, ..
            } = &mut *st;
            iface
                .poll_delay(now, sockets)
                .map(|d| Duration::from_micros(d.total_micros()))
        };

        tokio::select! {
            r = udp.recv_from(&mut udp_buf) => {
                if let Ok((n, addr)) = r {
                    peer = Some(addr);
                    handle_incoming(&shared, &udp, &mut tunn, &mut scratch, &udp_buf[..n], addr, &mut relays).await;
                }
            }
            _ = ticker.tick() => {
                if let TunnResult::WriteToNetwork(b) = tunn.update_timers(&mut scratch) {
                    if let Some(addr) = peer {
                        let _ = udp.send_to(b, addr).await;
                    }
                }
            }
            _ = async { match delay {
                Some(d) => tokio::time::sleep(d).await,
                None => std::future::pending::<()>().await,
            } } => {}
            _ = wake_rx.recv() => {}
        }
    }
}

/// Обрабатывает входящую UDP-датаграмму от клиента: расшифровывает, для
/// внутренних IP-пакетов демультиплексирует потоки (создаёт сокеты + relay),
/// кладёт пакет в стек.
async fn handle_incoming(
    shared: &Arc<Shared>,
    udp: &UdpSocket,
    tunn: &mut Tunn,
    scratch: &mut [u8],
    packet: &[u8],
    peer: SocketAddr,
    relays: &mut JoinSet<()>,
) {
    let mut first = true;
    loop {
        let input: &[u8] = if first { packet } else { &[] };
        first = false;
        // decapsulate берёт &mut scratch, но нам ещё нужен scratch для следующих
        // итераций — копируем результат сразу.
        let res = match tunn.decapsulate(None, input, scratch) {
            TunnResult::WriteToNetwork(b) => Some((true, b.to_vec())),
            TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
                Some((false, p.to_vec()))
            }
            _ => None,
        };
        match res {
            Some((true, b)) => {
                let _ = udp.send_to(&b, peer).await;
                // продолжаем дренировать очередь boringtun (input=&[]).
            }
            Some((false, ip_pkt)) => {
                demux_and_enqueue(shared, &ip_pkt, relays);
                break;
            }
            None => break,
        }
    }
}

/// Создаёт сокет для нового потока (если нужно) и кладёт IP-пакет в стек.
fn demux_and_enqueue(shared: &Arc<Shared>, ip_pkt: &[u8], relays: &mut JoinSet<()>) {
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
                    let shared2 = shared.clone();
                    relays.spawn(relay_tcp(shared2, handle, key, dst));
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
                    let shared2 = shared.clone();
                    relays.spawn(relay_udp(shared2, handle, key, dst, f.src));
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
    matches!(
        tokio::time::timeout(ACCEPT_TIMEOUT, fut).await,
        Ok(true)
    )
}

/// Relay одного TCP-потока: стек ↔ исходящий (через Engine).
async fn relay_tcp(
    shared: Arc<Shared>,
    handle: SocketHandle,
    key: (SocketAddr, SocketAddr),
    dst: Target,
) {
    let ok = wait_established(&shared, handle).await;
    if ok {
        let routed = shared.engine.route(&dst).await;
        if let Decision::Connect(ob) = routed.decision {
            if let Ok(mut up) = ob.connect_tcp(&routed.target).await {
                let mut down = ServerTcpStream::new(shared.clone(), handle);
                let _ = tokio::io::copy_bidirectional(&mut down, &mut up).await;
            }
        }
    }
    // Очистка: снять 5-кортеж и грациозно закрыть сокет.
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
            loop {
                tokio::select! {
                    out = udp_recv(&shared, handle) => match out {
                        Some(data) => { if sess.send(&data).await.is_err() { break; } }
                        None => break,
                    },
                    inb = sess.recv() => match inb {
                        Ok(data) => udp_send(&shared, handle, &data, client),
                        Err(_) => break,
                    },
                    _ = tokio::time::sleep(UDP_IDLE) => break,
                }
            }
            sess.close().await;
        }
    }
    {
        let mut st = shared.stack.lock().unwrap();
        st.udp_flows.remove(&key);
        st.sockets.remove(handle);
    }
    shared.kick();
}

/// Принимает датаграмму из стек-UDP-сокета (от клиента). `None` — сокет закрыт.
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

/// Отправляет ответ цели обратно клиенту через стек-UDP-сокет.
fn udp_send(shared: &Arc<Shared>, handle: SocketHandle, data: &[u8], client: IpEndpoint) {
    let mut st = shared.stack.lock().unwrap();
    let s = st.sockets.get_mut::<udp::Socket>(handle);
    let _ = s.send_slice(data, client);
    drop(st);
    shared.kick();
}

/// `AsyncRead`/`AsyncWrite` поверх стек-TCP-сокета сервера (зеркало клиентского
/// `WgTcpStream`, но над [`Shared`]).
struct ServerTcpStream {
    shared: Arc<Shared>,
    handle: SocketHandle,
}

impl ServerTcpStream {
    fn new(shared: Arc<Shared>, handle: SocketHandle) -> Self {
        Self { shared, handle }
    }
}

impl AsyncRead for ServerTcpStream {
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
                .map_err(|e| io::Error::other(format!("wgsrv: recv: {e:?}")))?;
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

impl AsyncWrite for ServerTcpStream {
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
                "wgsrv: сокет закрыт для записи",
            )));
        }
        if s.can_send() {
            let n = s
                .send_slice(data)
                .map_err(|e| io::Error::other(format!("wgsrv: send: {e:?}")))?;
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
    use crate::outbound::Outbound;
    use crate::wireguard::{wireguard_connect, WgConfig, WgParams};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Сквозной шлюз: наш WG-клиент (исходящий) подключается к нашему WG-серверу
    /// (responder с any_ip), тот релеит TCP через Direct к локальному echo.
    async fn run_gateway_tcp() {
        // 1. TCP-echo сервер.
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });

        // 2. Ключи: сервер и клиент.
        let server_priv = gen_private_key();
        let client_priv = gen_private_key();
        let server_pub = public_key(&server_priv);
        let client_pub = public_key(&client_priv);

        // 3. WG-сервер (Direct-движок).
        let engine = Arc::new(Engine::single_proxy(Outbound::Direct));
        let server = WgServer::start(
            WgServerParams {
                listen: "127.0.0.1:0".parse().unwrap(),
                server_private: server_priv,
                client_public: client_pub,
                preshared_key: None,
                server_ip: Ipv4Addr::new(10, 9, 0, 1),
                prefix: 24,
            },
            engine,
        )
        .await
        .unwrap();

        // 4. Наш WG-клиент к серверу; цель — echo по его реальному адресу.
        let cfg = WgConfig::new(WgParams {
            endpoint: server.local_addr().to_string(),
            private_key: client_priv,
            peer_public_key: server_pub,
            preshared_key: None,
            address: vec![(IpAddr::V4(Ipv4Addr::new(10, 9, 0, 2)), 24)],
            dns: vec![],
            persistent_keepalive: None,
            awg: None,
        });
        let target = Target::Socket(echo_addr);
        let mut stream = wireguard_connect(&cfg, &target).await.expect("connect");

        let msg = b"hello wg gateway";
        stream.write_all(msg).await.expect("write");
        let mut buf = vec![0u8; msg.len()];
        stream.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, msg, "echo через WG-шлюз совпадает");

        server.stop();
    }

    #[tokio::test]
    async fn gateway_relays_tcp_through_direct() {
        tokio::time::timeout(Duration::from_secs(20), run_gateway_tcp())
            .await
            .expect("тест не должен зависнуть");
    }

    /// Сквозной шлюз для UDP: WG-клиент → WG-сервер → Direct → UDP-echo.
    async fn run_gateway_udp() {
        let echo = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let echo_addr = echo.local_addr().unwrap();
        {
            let echo = echo.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                while let Ok((n, from)) = echo.recv_from(&mut buf).await {
                    let _ = echo.send_to(&buf[..n], from).await;
                }
            });
        }

        let server_priv = gen_private_key();
        let client_priv = gen_private_key();
        let server_pub = public_key(&server_priv);
        let client_pub = public_key(&client_priv);

        let engine = Arc::new(Engine::single_proxy(Outbound::Direct));
        let server = WgServer::start(
            WgServerParams {
                listen: "127.0.0.1:0".parse().unwrap(),
                server_private: server_priv,
                client_public: client_pub,
                preshared_key: None,
                server_ip: Ipv4Addr::new(10, 9, 0, 1),
                prefix: 24,
            },
            engine,
        )
        .await
        .unwrap();

        let cfg = WgConfig::new(WgParams {
            endpoint: server.local_addr().to_string(),
            private_key: client_priv,
            peer_public_key: server_pub,
            preshared_key: None,
            address: vec![(IpAddr::V4(Ipv4Addr::new(10, 9, 0, 2)), 24)],
            dns: vec![],
            persistent_keepalive: None,
            awg: None,
        });
        let sess = crate::wireguard::wireguard_connect_udp(&cfg, &Target::Socket(echo_addr))
            .await
            .expect("udp session");

        // UDP best-effort: ретраи до эха.
        for _ in 0..10u32 {
            sess.send(b"ping via gateway").await.expect("send");
            match tokio::time::timeout(Duration::from_millis(500), sess.recv()).await {
                Ok(Ok(resp)) => {
                    assert_eq!(&resp, b"ping via gateway", "udp echo через шлюз");
                    server.stop();
                    return;
                }
                _ => continue,
            }
        }
        panic!("UDP через шлюз не вернулся за 10 попыток");
    }

    #[tokio::test]
    async fn gateway_relays_udp_through_direct() {
        tokio::time::timeout(Duration::from_secs(20), run_gateway_udp())
            .await
            .expect("тест не должен зависнуть");
    }
}
