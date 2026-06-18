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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

type AddrSlot = Arc<Mutex<Option<windivert::address::WinDivertAddress<NetworkLayer>>>>;

/// Счётчики для диагностики split(WinDivert).
#[derive(Default)]
struct Stats {
    captured: AtomicU64,
    tunnel: AtomicU64,
    direct: AtomicU64,
    dropped: AtomicU64,
    inject_ok: AtomicU64,
    inject_err: AtomicU64,
    send_err: AtomicU64,
    no_addr: AtomicU64,
}

/// Запущенный split-перехват на WinDivert.
pub struct SplitTunnel {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    handle: Arc<DivertHandle>,
    /// Адрес последнего исходящего пакета (интерфейс) — шаблон для инъекции ответов.
    last_addr: AddrSlot,
    stats: Arc<Stats>,
    log: Logger,
}

/// Хендл для инъекции ответных IP-пакетов из netstack обратно приложению.
#[derive(Clone)]
pub struct ResponseInjector {
    handle: Arc<DivertHandle>,
    last_addr: AddrSlot,
    stats: Arc<Stats>,
    log: Logger,
}

impl ResponseInjector {
    /// Инъектирует IP-пакет (ответ из netstack) приложению как ВХОДЯЩИЙ.
    pub fn inject(&self, ip_packet: Vec<u8>) {
        // Берём шаблон адреса последнего исходящего пакета (интерфейс), помечаем
        // как входящий + impostor и пересчитываем контрольные суммы.
        let addr = { self.last_addr.lock().unwrap().clone() };
        let Some(mut addr) = addr else {
            // Ещё не видели исходящих — некуда инъектить (нет интерфейса).
            let n = self.stats.no_addr.fetch_add(1, Ordering::Relaxed);
            if n < 3 {
                (self.log)("split(WinDivert): инъекция ответа отложена — ещё нет исходящего пакета (нет шаблона интерфейса)".into());
            }
            return;
        };
        addr.set_outbound(false);
        addr.set_impostor(true);
        let plen = ip_packet.len();
        let mut pkt = unsafe { WinDivertPacket::<NetworkLayer>::new(ip_packet) };
        pkt.address = addr;
        if let Err(e) = pkt.recalculate_checksums(Default::default()) {
            let n = self.stats.inject_err.fetch_add(1, Ordering::Relaxed);
            if n < 5 {
                (self.log)(format!("split(WinDivert): пересчёт контрольных сумм ответа ({plen} б): {e}"));
            }
            return;
        }
        match self.handle.0.send(&pkt) {
            Ok(_) => {
                let n = self.stats.inject_ok.fetch_add(1, Ordering::Relaxed);
                if n == 0 {
                    (self.log)(format!("split(WinDivert): ПЕРВЫЙ ответ инъектирован приложению ({plen} б) ✓"));
                }
            }
            Err(e) => {
                let n = self.stats.inject_err.fetch_add(1, Ordering::Relaxed);
                if n < 5 {
                    (self.log)(format!("split(WinDivert): ОШИБКА инъекции ответа ({plen} б): {e}"));
                }
            }
        }
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
        log(format!(
            "split(WinDivert): хендл открыт (фильтр «{filter}»), драйвер ОК"
        ));
        let handle = Arc::new(DivertHandle(wd));
        let last_addr = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(Stats::default());

        let thread = {
            let stop = stop.clone();
            let handle = handle.clone();
            let last_addr = last_addr.clone();
            let stats = stats.clone();
            let log = log.clone();
            std::thread::Builder::new()
                .name("windivert-capture".into())
                .spawn(move || capture_loop(stop, config, on_capture, handle, last_addr, stats, log))
                .map_err(|e| e.to_string())?
        };

        Ok(SplitTunnel {
            stop,
            thread: Some(thread),
            handle,
            last_addr,
            stats,
            log,
        })
    }

    /// Инжектор ответов (для подключения к netstack-выходу).
    pub fn injector(&self) -> ResponseInjector {
        ResponseInjector {
            handle: self.handle.clone(),
            last_addr: self.last_addr.clone(),
            stats: self.stats.clone(),
            log: self.log.clone(),
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
#[allow(clippy::too_many_arguments)]
fn capture_loop(
    stop: Arc<AtomicBool>,
    config: SplitConfig,
    mut on_capture: OnCapture,
    handle: Arc<DivertHandle>,
    last_addr: AddrSlot,
    stats: Arc<Stats>,
    log: Logger,
) {
    log(format!(
        "split(WinDivert): поток захвата запущен; режим={:?}, приложения={:?}, kill_switch={}",
        config.mode, config.apps, config.kill_switch
    ));
    let mut resolver = ProcessResolver::new();
    let mut buf = vec![0u8; 65535];
    let mut detailed = 0u32; // сколько пакетов залогировать детально
    let mut recv_err = 0u32;
    let mut last_report = std::time::Instant::now();
    // Кэш вердиктов по потокам: решение по ПЕРВОМУ пакету соединения применяется
    // ко всем последующим — иначе гонка атрибуции (SYN «прямо», данные «в туннель»)
    // расщепляет TLS-соединение между путями → «соединение не защищено».
    let mut flows: std::collections::HashMap<FlowKey, Verdict> = std::collections::HashMap::new();

    while !stop.load(Ordering::Relaxed) {
        // Блокирующий recv с таймаутом, чтобы периодически проверять stop.
        let packet = match handle.0.recv_wait(&mut buf, 200) {
            Ok(Some(p)) => p,
            Ok(None) => {
                periodic_report(&stats, &mut last_report, &log);
                continue;
            }
            Err(e) => {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                recv_err += 1;
                if recv_err <= 5 {
                    log(format!("split(WinDivert): ошибка recv: {e}"));
                }
                continue;
            }
        };

        stats.captured.fetch_add(1, Ordering::Relaxed);

        // Вердикт: из кэша потока (консистентность) либо решаем для нового потока.
        let (verdict, info) = match parse_ip(&packet.data) {
            None => (Verdict::Direct, "не-TCP/UDP/короткий → прямо".to_string()),
            Some((proto, is_v6, lport, dst_ip, dst_port)) => {
                let key: FlowKey = (lport, dst_ip, dst_port);
                // Завершение TCP-потока → убираем из кэша (на случай переиспользования порта).
                if tcp_fin_or_rst(&packet.data) {
                    flows.remove(&key);
                }
                match flows.get(&key) {
                    Some(&v) => (v, format!("{proto:?} :{lport}→{dst_ip}:{dst_port} (кэш)")),
                    None => {
                        let (v, app, known) =
                            decide_for(proto, is_v6, lport, dst_ip, dst_port, &config, &mut resolver);
                        // Кэшируем ТОЛЬКО уверенный вердикт (процесс определён),
                        // иначе ранний SYN залипнет «прямо» и соединение пойдёт мимо
                        // туннеля (утечка IP). Неопределённые — переспрашиваем.
                        if known {
                            if flows.len() >= 16384 {
                                flows.clear(); // backstop от роста памяти
                            }
                            flows.insert(key, v);
                        }
                        (v, format!("{proto:?} :{lport}→{dst_ip}:{dst_port} app={app} known={known}"))
                    }
                }
            }
        };
        if detailed < 15 {
            detailed += 1;
            log(format!("split(WinDivert): пакет#{detailed} {info} → {verdict:?}"));
        }

        match verdict {
            Verdict::Tunnel => {
                stats.tunnel.fetch_add(1, Ordering::Relaxed);
                // Запоминаем интерфейс именно ТУННЕЛЬНОГО потока (реальный NIC) —
                // ответы инъектируем как входящие на этот интерфейс. (Адрес
                // localhost-потоков сюда не попадёт.)
                *last_addr.lock().unwrap() = Some(packet.address.clone());
                // WinDivert ловит исходящие пакеты ДО offload-вычисления контрольных
                // сумм — у них невалидные/нулевые суммы. netstack (smoltcp) валидирует
                // RX-суммы и отбросил бы их → пересчитываем перед подачей.
                let mut owned = packet.into_owned();
                if let Err(e) = owned.recalculate_checksums(Default::default()) {
                    let n = stats.send_err.fetch_add(1, Ordering::Relaxed);
                    if n < 5 {
                        log(format!("split(WinDivert): пересчёт сумм туннельного пакета: {e}"));
                    }
                }
                on_capture(&owned.data);
                // оригинал НЕ реинъектим — уходит в туннель (netstack).
            }
            Verdict::Direct => {
                stats.direct.fetch_add(1, Ordering::Relaxed);
                if let Err(e) = handle.0.send(&packet) {
                    let n = stats.send_err.fetch_add(1, Ordering::Relaxed);
                    if n < 5 {
                        log(format!("split(WinDivert): ошибка реинъекции (прямой трафик): {e}"));
                    }
                }
            }
            Verdict::Drop => {
                stats.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        periodic_report(&stats, &mut last_report, &log);
    }
    log(format!(
        "split(WinDivert): остановлен. {}",
        stats_line(&stats)
    ));
}

/// Периодический отчёт о счётчиках (раз в ~3 с).
fn periodic_report(stats: &Stats, last: &mut std::time::Instant, log: &Logger) {
    if last.elapsed().as_secs() >= 3 {
        log(format!("split(WinDivert): {}", stats_line(stats)));
        *last = std::time::Instant::now();
    }
}

fn stats_line(s: &Stats) -> String {
    use Ordering::Relaxed;
    format!(
        "захвачено={} туннель={} прямо={} дроп={} инъекций={} (ошибок_инъекции={}) ошибок_send={} нет_адреса={}",
        s.captured.load(Relaxed),
        s.tunnel.load(Relaxed),
        s.direct.load(Relaxed),
        s.dropped.load(Relaxed),
        s.inject_ok.load(Relaxed),
        s.inject_err.load(Relaxed),
        s.send_err.load(Relaxed),
        s.no_addr.load(Relaxed),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Tunnel,
    Direct,
    Drop,
}

/// Ключ потока для консистентного вердикта: (локальный порт, dst, dst-порт).
type FlowKey = (u16, IpAddr, u16);

/// Решение для потока: атрибуция к процессу + правила.
/// Возвращает `(вердикт, имя_app, определён_ли_процесс)`. Последний флаг важен:
/// вердикт кэшируется ТОЛЬКО когда процесс уверенно определён — иначе ранний SYN
/// (порт ещё не в таблице соединений) залип бы как «прямо» на всё соединение.
fn decide_for(
    proto: Proto,
    is_v6: bool,
    local_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    config: &SplitConfig,
    resolver: &mut ProcessResolver,
) -> (Verdict, String, bool) {
    let resolved = resolver.resolve(proto, is_v6, local_port);
    let known = resolved.is_some();
    let app = resolved.unwrap_or(ConnApp {
        exe_path: None,
        process_name: None,
    });
    let app_name = app
        .process_name
        .clone()
        .or_else(|| app.exe_path.clone())
        .unwrap_or_else(|| "<неизвестно>".into());
    let req = ConnRequest {
        app: &app,
        dst_ip,
        dst_port,
    };
    let verdict = match decide(&req, config, true) {
        Action::Tunnel => Verdict::Tunnel,
        Action::Direct => Verdict::Direct,
        Action::Block => Verdict::Drop,
    };
    (verdict, app_name, known)
}

/// Бит FIN или RST в TCP-флагах (для эвикции завершённых потоков из кэша).
fn tcp_fin_or_rst(ip: &[u8]) -> bool {
    let Some((Proto::Tcp, _, _, _, _)) = parse_ip(ip) else {
        return false;
    };
    // Смещение TCP-флагов = IP-заголовок + 13.
    let ihl = match ip[0] >> 4 {
        4 => ((ip[0] & 0x0F) as usize) * 4,
        6 => 40,
        _ => return false,
    };
    ip.get(ihl + 13).is_some_and(|f| f & 0x05 != 0) // FIN(0x01)|RST(0x04)
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
