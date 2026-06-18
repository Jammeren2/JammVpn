//! Per-app split-туннелирование через **WinDivert** (альтернатива WinpkFilter).
//!
//! Захват исходящих IP-пакетов на NETWORK-слое WinDivert. Для каждого пакета
//! определяется процесс-владелец (через таблицы соединений, как в WinpkFilter);
//! пакеты приложений из split-набора отдаются в userspace `netstack` через
//! `on_capture`, остальные — реинъектятся обратно (идут напрямую). Ответы из
//! netstack ([`ResponseInjector::inject`]) инъектятся приложению как входящие.
//!
//! Драйвер `WinDivert64.sys` (подписанный, официальный) вшит в exe и ставится в
//! рантайме. Требуются права администратора.
//!
//! ВНИМАНИЕ: реализация экспериментальная (требует проверки на железе).

pub mod driver;

use crate::winpkfilter::attribution::{Proto, ProcessResolver};
use jammvpn_core::split::{decide, Action, ConnApp, ConnRequest, SplitConfig};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use windivert::layer::NetworkLayer;
use windivert::packet::WinDivertPacket;
use windivert::prelude::WinDivertFlags;
use windivert::WinDivert;

/// Колбэк на туннелируемый IP-пакет приложения.
type OnCapture = Box<dyn FnMut(&[u8]) + Send>;
/// Логгер диагностики.
pub type Logger = std::sync::Arc<dyn Fn(String) + Send + Sync>;

pub use crate::winpkfilter::{is_elevated, relaunch_elevated};

/// Дескриптор WinDivert, помеченный Send/Sync. Драйвер допускает параллельные
/// recv (поток захвата) и send (инъекция ответов) на одном хендле.
struct DivertHandle(WinDivert<NetworkLayer>);
unsafe impl Send for DivertHandle {}
unsafe impl Sync for DivertHandle {}

/// Запущенный split-перехват на WinDivert.
pub struct SplitTunnel {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    handle: Arc<DivertHandle>,
    /// Адрес последнего исходящего пакета (интерфейс) — шаблон для инъекции ответов.
    last_addr: Arc<Mutex<Option<windivert::address::WinDivertAddress<NetworkLayer>>>>,
}

/// Хендл для инъекции ответных IP-пакетов из netstack обратно приложению.
#[derive(Clone)]
pub struct ResponseInjector {
    handle: Arc<DivertHandle>,
    last_addr: Arc<Mutex<Option<windivert::address::WinDivertAddress<NetworkLayer>>>>,
}

impl ResponseInjector {
    /// Инъектирует IP-пакет (ответ из netstack) приложению как ВХОДЯЩИЙ.
    pub fn inject(&self, ip_packet: Vec<u8>) {
        // Берём шаблон адреса последнего исходящего пакета (интерфейс), помечаем
        // как входящий + impostor и пересчитываем контрольные суммы.
        let addr = { self.last_addr.lock().unwrap().clone() };
        let Some(mut addr) = addr else {
            return; // ещё не видели исходящих — некуда инъектить
        };
        addr.set_outbound(false);
        addr.set_impostor(true);
        let mut pkt = unsafe { WinDivertPacket::<NetworkLayer>::new(ip_packet) };
        pkt.address = addr;
        let _ = pkt.recalculate_checksums(Default::default());
        let _ = self.handle.0.send(&pkt);
    }
}

impl SplitTunnel {
    /// Запускает перехват. `on_capture` вызывается с IP-пакетом каждого
    /// «туннелируемого» приложения. Ошибка — если драйвер недоступен.
    pub fn start(
        config: SplitConfig,
        on_capture: OnCapture,
        log: Logger,
    ) -> Result<SplitTunnel, String> {
        if !is_elevated() {
            return Err("split требует запуска JammVPN от администратора".into());
        }
        driver::ensure_installed(&|m| log(m))
            .map_err(|e| format!("драйвер WinDivert: {e}"))?;

        // Захватываем только исходящие TCP/UDP; входящие приложениям доставляет
        // система, а ответы туннеля мы инъектируем сами.
        let filter = "outbound and (tcp or udp)";
        let wd = WinDivert::<NetworkLayer>::network(filter, 0, WinDivertFlags::new())
            .map_err(|e| format!("WinDivertOpen: {e}. Установлен ли драйвер и есть ли права админа?"))?;
        let handle = Arc::new(DivertHandle(wd));
        let last_addr = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));

        let thread = {
            let stop = stop.clone();
            let handle = handle.clone();
            let last_addr = last_addr.clone();
            std::thread::Builder::new()
                .name("windivert-capture".into())
                .spawn(move || capture_loop(stop, config, on_capture, handle, last_addr, log))
                .map_err(|e| e.to_string())?
        };

        Ok(SplitTunnel {
            stop,
            thread: Some(thread),
            handle,
            last_addr,
        })
    }

    /// Инжектор ответов (для подключения к netstack-выходу).
    pub fn injector(&self) -> ResponseInjector {
        ResponseInjector {
            handle: self.handle.clone(),
            last_addr: self.last_addr.clone(),
        }
    }

    /// Останавливает перехват. Поток выходит сам в течение ~200 мс (таймаут recv);
    /// хендл закрывается, когда снимутся все ссылки (после join + drop инжектора).
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Главный цикл захвата (отдельный поток).
fn capture_loop(
    stop: Arc<AtomicBool>,
    config: SplitConfig,
    mut on_capture: OnCapture,
    handle: Arc<DivertHandle>,
    last_addr: Arc<Mutex<Option<windivert::address::WinDivertAddress<NetworkLayer>>>>,
    log: Logger,
) {
    log(format!("split(WinDivert): старт, приложения: {:?}", config.apps));
    let mut resolver = ProcessResolver::new();
    let mut buf = vec![0u8; 65535];
    let (mut n_tunnel, mut n_direct) = (0u64, 0u64);
    let mut last_report = std::time::Instant::now();

    while !stop.load(Ordering::Relaxed) {
        // Блокирующий recv с таймаутом, чтобы периодически проверять stop.
        let packet = match handle.0.recv_wait(&mut buf, 200) {
            Ok(Some(p)) => p,
            Ok(None) => continue, // таймаут
            Err(_) => {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                continue;
            }
        };

        if last_report.elapsed().as_secs() >= 5 {
            log(format!("split(WinDivert): туннель={n_tunnel} прямо={n_direct}"));
            last_report = std::time::Instant::now();
        }

        let verdict = classify(&packet.data, &config, &mut resolver);
        // Запоминаем интерфейс исходящего пакета для инъекции ответов.
        {
            *last_addr.lock().unwrap() = Some(packet.address.clone());
        }
        match verdict {
            Verdict::Tunnel => {
                n_tunnel += 1;
                on_capture(&packet.data);
                // оригинал НЕ реинъектим — пакет уходит в туннель.
            }
            Verdict::Direct => {
                n_direct += 1;
                let _ = handle.0.send(&packet); // напрямую
            }
            Verdict::Drop => {}
        }
    }
    log("split(WinDivert): остановлен".into());
}

enum Verdict {
    Tunnel,
    Direct,
    Drop,
}

/// Классифицирует исходящий IP-пакет: туннель / напрямую / дроп (kill-switch).
fn classify(ip: &[u8], config: &SplitConfig, resolver: &mut ProcessResolver) -> Verdict {
    let Some((proto, is_v6, local_port, dst_ip, dst_port)) = parse_ip(ip) else {
        return Verdict::Direct;
    };
    let app = resolver
        .resolve(proto, is_v6, local_port)
        .unwrap_or(ConnApp {
            exe_path: None,
            process_name: None,
        });
    let req = ConnRequest {
        app: &app,
        dst_ip,
        dst_port,
    };
    match decide(&req, config, true) {
        Action::Tunnel => Verdict::Tunnel,
        Action::Direct => Verdict::Direct,
        Action::Block => Verdict::Drop,
    }
}

/// Разбирает IPv4/IPv6 + TCP/UDP: `(proto, is_v6, local_port, dst_ip, dst_port)`.
fn parse_ip(ip: &[u8]) -> Option<(Proto, bool, u16, IpAddr, u16)> {
    if ip.is_empty() {
        return None;
    }
    let (is_v6, proto_num, dst_ip, l4): (bool, u8, IpAddr, &[u8]) = match ip[0] >> 4 {
        4 => {
            if ip.len() < 20 {
                return None;
            }
            let ihl = ((ip[0] & 0x0F) as usize) * 4;
            let dst = IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]));
            (false, ip[9], dst, ip.get(ihl..)?)
        }
        6 => {
            if ip.len() < 40 {
                return None;
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&ip[24..40]);
            (true, ip[6], IpAddr::V6(Ipv6Addr::from(o)), ip.get(40..)?)
        }
        _ => return None,
    };
    let proto = match proto_num {
        6 => Proto::Tcp,
        17 => Proto::Udp,
        _ => return None,
    };
    if l4.len() < 4 {
        return None;
    }
    let src_port = u16::from_be_bytes([l4[0], l4[1]]);
    let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
    Some((proto, is_v6, src_port, dst_ip, dst_port))
}
