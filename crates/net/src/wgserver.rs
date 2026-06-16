//! Локальный WireGuard-сервер (inbound-шлюз).
//!
//! JammVPN поднимает WG-эндпоинт (boringtun как responder), к которому
//! подключается клиент (приложение/устройство по экспортированному `.conf`).
//! Декапсулированные IP-пакеты клиента отдаются в [`crate::netstack::Netstack`]
//! (userspace tun2socks), который терминирует TCP/UDP-потоки и релеит их наружу
//! через [`Engine`]. Исходящие IP-пакеты стека инкапсулируются обратно к клиенту.
//!
//! Схема: `клиент → WG → этот сервер → netstack → Engine/узел → апстрим`.
//! Один пир (один клиентский ключ), без обфускации — соединение локальное.

use crate::engine::Engine;
use crate::netstack::{Netstack, NetstackOut};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Период тика boringtun (handshake/keepalive/rekey).
const TIMER_TICK: Duration = Duration::from_millis(250);
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

/// Запущенный локальный WG-сервер.
pub struct WgServer {
    driver: tokio::task::JoinHandle<()>,
    addr: SocketAddr,
}

impl WgServer {
    /// Поднимает сервер: bind UDP, netstack, boringtun-responder, WG-loop.
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

        let (netstack, out) = Netstack::new(engine, params.server_ip, params.prefix);
        let driver = tokio::spawn(run_wg(udp, tunn, netstack, out));
        Ok(WgServer { driver, addr })
    }

    /// Фактический UDP-адрес прослушивания (важно при `port = 0`).
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Останавливает сервер (WG-loop и стек прекращаются).
    pub fn stop(self) {
        self.driver.abort();
    }
}

/// WG-loop: UDP ↔ boringtun ↔ netstack. Единственное место `encapsulate/
/// decapsulate/update_timers`. `netstack` держим живым здесь (Drop остановит стек).
async fn run_wg(udp: Arc<UdpSocket>, mut tunn: Tunn, netstack: Netstack, mut out: NetstackOut) {
    let mut scratch = vec![0u8; SCRATCH];
    let mut udp_buf = vec![0u8; SCRATCH];
    let mut ticker = tokio::time::interval(TIMER_TICK);
    let mut peer: Option<SocketAddr> = None;

    loop {
        tokio::select! {
            // Входящее от клиента: расшифровать; handshake-ответы шлём, внутренние
            // IP-пакеты — в стек.
            r = udp.recv_from(&mut udp_buf) => {
                if let Ok((n, addr)) = r {
                    peer = Some(addr);
                    let mut first = true;
                    loop {
                        let input: &[u8] = if first { &udp_buf[..n] } else { &[] };
                        first = false;
                        let res = match tunn.decapsulate(None, input, &mut scratch) {
                            TunnResult::WriteToNetwork(b) => Some((true, b.to_vec())),
                            TunnResult::WriteToTunnelV4(p, _)
                            | TunnResult::WriteToTunnelV6(p, _) => Some((false, p.to_vec())),
                            _ => None,
                        };
                        match res {
                            Some((true, b)) => { let _ = udp.send_to(&b, addr).await; }
                            Some((false, ip)) => { netstack.inject(&ip); break; }
                            None => break,
                        }
                    }
                }
            }
            // Исходящий IP-пакет из стека → инкапсулировать и отправить клиенту.
            Some(ip) = out.recv() => {
                if let TunnResult::WriteToNetwork(b) = tunn.encapsulate(&ip, &mut scratch) {
                    if let Some(addr) = peer {
                        let _ = udp.send_to(b, addr).await;
                    }
                }
            }
            // Таймеры boringtun (keepalive/rekey).
            _ = ticker.tick() => {
                if let TunnResult::WriteToNetwork(b) = tunn.update_timers(&mut scratch) {
                    if let Some(addr) = peer {
                        let _ = udp.send_to(b, addr).await;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::Outbound;
    use crate::target::Target;
    use crate::wireguard::{wireguard_connect, WgConfig, WgParams};
    use std::net::IpAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Сквозной шлюз: наш WG-клиент (исходящий) подключается к нашему WG-серверу,
    /// тот релеит TCP через Direct к локальному echo.
    async fn run_gateway_tcp() {
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
