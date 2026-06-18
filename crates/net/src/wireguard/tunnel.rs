//! Общий WG-туннель: netstack (smoltcp) + Noise (boringtun) + driver-task.
//!
//! Один туннель на узел; разделяется всеми соединениями (см. [`super::config`]).

use super::config::WgParams;
use super::device::WgDevice;
use super::obfs::AwgObfs;
use super::stream::WgTcpStream;
use super::{driver, resolve_target};
use crate::target::Target;
use crate::BoxedStream;
use boringtun::noise::Tunn;
use boringtun::x25519::{PublicKey, StaticSecret};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as StdInstant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};

/// Буфер приёма/передачи smoltcp-сокета (на соединение).
const SOCKET_BUF: usize = 64 * 1024;
/// Кол-во слотов метаданных датаграмм в UDP-буфере (приём/передача).
const UDP_META: usize = 32;
/// Таймаут установления TCP-соединения через туннель.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Динамический диапазон локальных портов.
const PORT_BASE: u16 = 49152;
const PORT_SPAN: u32 = (u16::MAX - PORT_BASE) as u32;

/// Разделяемый сетевой стек. Под `std::sync::Mutex`; держать НЕ через `.await`.
pub(crate) struct Stack {
    pub iface: Interface,
    pub device: WgDevice,
    pub sockets: SocketSet<'static>,
    /// Сокеты «брошенных» потоков: закрыты (FIN инициирован), ждут, пока
    /// driver дошлёт буфер и удалит их по достижении `Closed`.
    pub abandoned: Vec<SocketHandle>,
}

/// Запущенный WG-туннель.
pub struct WgTunnel {
    stack: Arc<Mutex<Stack>>,
    wake_tx: mpsc::UnboundedSender<()>,
    notify: Arc<Notify>,
    next_port: AtomicU32,
    driver: tokio::task::JoinHandle<()>,
}

/// Без этого `Drop` сброс `WgTunnel` лишь *отсоединял* бы driver-task (дроп
/// `JoinHandle` в tokio не отменяет задачу) — и драйвер крутился бы вечно,
/// сжигая CPU на пустом `udp.recv` (особенно после latency-теста узлов).
impl Drop for WgTunnel {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl WgTunnel {
    pub(crate) fn stack(&self) -> &Arc<Mutex<Stack>> {
        &self.stack
    }

    /// Будит driver-task (после записи/закрытия сокета или нового соединения).
    pub(crate) fn kick(&self) {
        let _ = self.wake_tx.send(());
    }

    fn alloc_port(&self) -> u16 {
        let n = self.next_port.fetch_add(1, Ordering::Relaxed);
        PORT_BASE + (n % PORT_SPAN) as u16
    }

    /// Немедленно удаляет сокет (путь ошибки connect: соединение не
    /// установлено, грациозное закрытие не требуется).
    pub(crate) fn remove_socket(&self, handle: SocketHandle) {
        if let Ok(mut st) = self.stack.lock() {
            st.sockets.remove(handle);
        }
        self.kick();
    }

    /// Грациозно закрывает сокет брошенного потока: инициирует FIN и помечает
    /// сокет на отложенное удаление — driver дошлёт буферизованные данные и
    /// удалит сокет, когда тот достигнет `Closed` (без потери последних байт).
    pub(crate) fn abandon_socket(&self, handle: SocketHandle) {
        if let Ok(mut st) = self.stack.lock() {
            st.sockets.get_mut::<tcp::Socket>(handle).close();
            st.abandoned.push(handle);
        }
        self.kick();
    }

    /// Поднимает туннель: bind UDP, конструирует netstack и Noise-ядро,
    /// запускает driver-task. Возвращает общий дескриптор.
    pub(crate) async fn start(params: &WgParams) -> io::Result<Arc<WgTunnel>> {
        // 1. UDP к эндпойнту.
        let endpoint = resolve_endpoint(&params.endpoint).await?;
        let bind = if endpoint.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let udp = UdpSocket::bind(bind).await?;
        udp.connect(endpoint).await?;
        let udp = Arc::new(udp);

        // 2. Noise-ядро (индекс 0 — boringtun сам управляет индексами сессий).
        let tunn = Tunn::new(
            StaticSecret::from(params.private_key),
            PublicKey::from(params.peer_public_key),
            params.preshared_key,
            params.persistent_keepalive,
            0,
            None,
        );

        // 3. smoltcp-интерфейс (Medium::Ip).
        let base = StdInstant::now();
        let mut device = WgDevice::new();
        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, SmolInstant::from_micros(0));
        iface.update_ip_addrs(|addrs| {
            for (ip, prefix) in &params.address {
                let _ = addrs.push(IpCidr::new(IpAddress::from(*ip), *prefix));
            }
        });
        add_default_routes(&mut iface, &params.address);
        let sockets = SocketSet::new(Vec::new());

        let stack = Arc::new(Mutex::new(Stack {
            iface,
            device,
            sockets,
            abandoned: Vec::new(),
        }));
        let notify = Arc::new(Notify::new());
        let (wake_tx, wake_rx) = mpsc::unbounded_channel();
        let our_public = PublicKey::from(&StaticSecret::from(params.private_key)).to_bytes();
        let obfs = AwgObfs::new(params.awg.clone(), our_public, params.peer_public_key);

        let driver = tokio::spawn(driver::run(
            stack.clone(),
            udp,
            tunn,
            obfs,
            notify.clone(),
            wake_rx,
            base,
        ));

        Ok(Arc::new(WgTunnel {
            stack,
            wake_tx,
            notify,
            next_port: AtomicU32::new(0),
            driver,
        }))
    }

    /// Открывает TCP-поток до `target` через туннель.
    pub(crate) async fn connect(self: &Arc<Self>, target: &Target) -> io::Result<BoxedStream> {
        let (ip, port) = resolve_target(target).await?;

        let handle = {
            let mut st = self.stack.lock().unwrap();
            let rx = tcp::SocketBuffer::new(vec![0u8; SOCKET_BUF]);
            let tx = tcp::SocketBuffer::new(vec![0u8; SOCKET_BUF]);
            let mut socket = tcp::Socket::new(rx, tx);
            let local_port = self.alloc_port();
            let remote = IpEndpoint::new(IpAddress::from(ip), port);
            socket
                .connect(st.iface.context(), remote, local_port)
                .map_err(|e| io::Error::other(format!("wg: connect: {e:?}")))?;
            st.sockets.add(socket)
        };
        self.kick();

        // Ждём Established (или ошибку/таймаут).
        let wait = async {
            loop {
                let notified = self.notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                {
                    let mut st = self.stack.lock().unwrap();
                    let s = st.sockets.get_mut::<tcp::Socket>(handle);
                    use tcp::State::*;
                    match s.state() {
                        Established => return Ok(()),
                        Closed | TimeWait | Closing | LastAck | FinWait1 | FinWait2 => {
                            return Err(io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                "wg: соединение не установлено",
                            ));
                        }
                        _ => {}
                    }
                }
                notified.await;
            }
        };

        match tokio::time::timeout(CONNECT_TIMEOUT, wait).await {
            Ok(Ok(())) => Ok(Box::new(WgTcpStream::new(self.clone(), handle))),
            Ok(Err(e)) => {
                self.remove_socket(handle);
                Err(e)
            }
            Err(_) => {
                self.remove_socket(handle);
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "wg: таймаут установления соединения",
                ))
            }
        }
    }

    /// Открывает UDP-сокет до `target` через туннель: привязывает локальный порт
    /// и нацеливает на разрешённый адрес. UDP без установления — сокет готов сразу
    /// (первые датаграммы до завершения handshake могут быть потеряны, как и
    /// положено UDP).
    pub(crate) async fn connect_udp(
        self: &Arc<Self>,
        target: &Target,
    ) -> io::Result<super::udp_socket::WgUdpSocket> {
        let (ip, port) = resolve_target(target).await?;
        let remote = IpEndpoint::new(IpAddress::from(ip), port);

        let handle = {
            let mut st = self.stack.lock().unwrap();
            let rx = udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_META],
                vec![0u8; SOCKET_BUF],
            );
            let tx = udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_META],
                vec![0u8; SOCKET_BUF],
            );
            let mut socket = udp::Socket::new(rx, tx);
            let local_port = self.alloc_port();
            socket
                .bind(local_port)
                .map_err(|e| io::Error::other(format!("wg: udp bind: {e:?}")))?;
            st.sockets.add(socket)
        };
        self.kick();
        Ok(super::udp_socket::WgUdpSocket::new(
            self.clone(),
            handle,
            remote,
        ))
    }
}

/// Резолвит `host:port` эндпойнта в [`std::net::SocketAddr`].
async fn resolve_endpoint(endpoint: &str) -> io::Result<std::net::SocketAddr> {
    tokio::net::lookup_host(endpoint)
        .await?
        .next()
        .ok_or_else(|| io::Error::other(format!("wg: не удалось разрешить эндпойнт {endpoint}")))
}

/// Добавляет дефолтные маршруты (через первый IPv4/IPv6-адрес интерфейса). В
/// режиме `Medium::Ip` шлюз не разрешается на канальном уровне — нужен лишь для
/// выбора исходящего адреса и достижимости off-link назначений.
fn add_default_routes(iface: &mut Interface, addrs: &[(IpAddr, u8)]) {
    if let Some(IpAddr::V4(v4)) = addrs.iter().map(|(ip, _)| *ip).find(IpAddr::is_ipv4) {
        let _ = iface.routes_mut().add_default_ipv4_route(v4);
    }
    if let Some(IpAddr::V6(v6)) = addrs.iter().map(|(ip, _)| *ip).find(IpAddr::is_ipv6) {
        let _ = iface.routes_mut().add_default_ipv6_route(v6);
    }
}
