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
use std::collections::HashMap;
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

/// Адрес WinDivert (интерфейс) исходящего пакета per ЛОКАЛЬНЫЙ IP: ответ
/// инъектируем как входящий на ТОТ интерфейс, с которого ушёл поток этого IP.
/// `last` — фолбэк. Раньше был один общий адрес на все потоки — на машинах с
/// несколькими адаптерами ответы уходили не на тот интерфейс (Discord/UDP не
/// получал IP-discovery → соединение не вставало с первого раза).
#[derive(Default)]
struct AddrTable {
    by_ip: HashMap<IpAddr, windivert::address::WinDivertAddress<NetworkLayer>>,
    last: Option<windivert::address::WinDivertAddress<NetworkLayer>>,
}
type AddrMap = Arc<Mutex<AddrTable>>;

/// Общий переоткрываемый хендл: поток захвата может переоткрыть его после сбоя
/// драйвера, и инжектор сразу увидит новый (оба берут текущий под Mutex).
type SharedHandle = Arc<Mutex<Arc<DivertHandle>>>;

/// WinDivert-фильтр: только исходящие TCP/UDP (входящие доставляет система,
/// ответы туннеля инъектируем сами).
const FILTER: &str = "outbound and (tcp or udp)";

/// Открывает WinDivert-хендл (network-слой, заданный фильтр).
fn open_handle(log: &Logger) -> Result<DivertHandle, String> {
    let wd = WinDivert::<NetworkLayer>::network(FILTER, 0, WinDivertFlags::new())
        .map_err(|e| format!("WinDivertOpen: {e}. Установлен ли драйвер и есть ли права админа?"))?;
    log(format!(
        "split(WinDivert): хендл открыт (фильтр «{FILTER}»), драйвер ОК"
    ));
    Ok(DivertHandle(wd))
}

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
    /// Сколько раз хендл переоткрывался после сбоя драйвера (восстановления).
    reopens: AtomicU64,
}

/// Запущенный split-перехват на WinDivert.
pub struct SplitTunnel {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    handle: SharedHandle,
    /// Адреса интерфейсов per локальный IP (шаблоны для инъекции ответов).
    addrs: AddrMap,
    stats: Arc<Stats>,
    /// `false`, пока поток захвата восстанавливает хендл после сбоя драйвера.
    healthy: Arc<AtomicBool>,
    log: Logger,
}

/// Хендл для инъекции ответных IP-пакетов из netstack обратно приложению.
#[derive(Clone)]
pub struct ResponseInjector {
    handle: SharedHandle,
    addrs: AddrMap,
    stats: Arc<Stats>,
    log: Logger,
}

impl ResponseInjector {
    /// Инъектирует IP-пакет (ответ из netstack) приложению как ВХОДЯЩИЙ.
    pub fn inject(&self, ip_packet: Vec<u8>) {
        // Ответ адресован локальному IP приложения (= dst пакета). Берём шаблон
        // адреса интерфейса именно этого IP (фолбэк — последний), помечаем как
        // входящий + impostor и пересчитываем контрольные суммы.
        let addr = {
            let t = self.addrs.lock().unwrap();
            ip_src_dst(&ip_packet)
                .and_then(|(_, dst)| t.by_ip.get(&dst).cloned())
                .or_else(|| t.last.clone())
        };
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
        let h = { self.handle.lock().unwrap().clone() };
        match h.0.send(&pkt) {
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
        let handle: SharedHandle = Arc::new(Mutex::new(Arc::new(open_handle(&log)?)));
        let addrs: AddrMap = Arc::new(Mutex::new(AddrTable::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(Stats::default());
        let healthy = Arc::new(AtomicBool::new(true));

        let thread = {
            let stop = stop.clone();
            let handle = handle.clone();
            let addrs = addrs.clone();
            let stats = stats.clone();
            let healthy = healthy.clone();
            let log = log.clone();
            std::thread::Builder::new()
                .name("windivert-capture".into())
                .spawn(move || {
                    capture_loop(stop, config, on_capture, handle, addrs, stats, healthy, log)
                })
                .map_err(|e| e.to_string())?
        };

        Ok(SplitTunnel {
            stop,
            thread: Some(thread),
            handle,
            addrs,
            stats,
            healthy,
            log,
        })
    }

    /// `true`, если поток захвата работает штатно; `false` — пока он
    /// восстанавливает хендл после сбоя драйвера (для уведомления в UI).
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// Инжектор ответов (для подключения к netstack-выходу).
    pub fn injector(&self) -> ResponseInjector {
        ResponseInjector {
            handle: self.handle.clone(),
            addrs: self.addrs.clone(),
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
    handle: SharedHandle,
    addrs: AddrMap,
    stats: Arc<Stats>,
    healthy: Arc<AtomicBool>,
    log: Logger,
) {
    use std::time::Duration;
    /// Серия подряд ошибок recv, после которой считаем драйвер упавшим и
    /// переоткрываем хендл.
    const REOPEN_AFTER: u32 = 10;

    log(format!(
        "split(WinDivert): поток захвата запущен; режим={:?}, приложения={:?}, kill_switch={}",
        config.mode, config.apps, config.kill_switch
    ));
    let mut resolver = ProcessResolver::new();
    let mut buf = vec![0u8; 65535];
    let mut detailed = 0u32; // сколько пакетов залогировать детально
    let mut consec_err = 0u32; // подряд ошибок recv (сброс при успехе)
    let mut last_report = std::time::Instant::now();
    // Локальная копия хендла для горячего цикла; меняется только при переоткрытии.
    let mut h = { handle.lock().unwrap().clone() };

    while !stop.load(Ordering::Relaxed) {
        // Блокирующий recv с таймаутом, чтобы периодически проверять stop.
        let packet = match h.0.recv_wait(&mut buf, 200) {
            Ok(Some(p)) => {
                consec_err = 0;
                p
            }
            Ok(None) => {
                consec_err = 0;
                periodic_report(&stats, &mut last_report, &log);
                continue;
            }
            Err(e) => {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                consec_err += 1;
                if consec_err <= 5 {
                    log(format!("split(WinDivert): ошибка recv: {e}"));
                }
                // Серия ошибок = вероятный сбой драйвера → переоткрываем хендл,
                // пока не получится (с паузой). Иначе цикл крутился бы вхолостую.
                if consec_err >= REOPEN_AFTER {
                    healthy.store(false, Ordering::Relaxed);
                    log("split(WinDivert): драйвер не отвечает — переоткрываю хендл…".into());
                    while !stop.load(Ordering::Relaxed) {
                        match open_handle(&log) {
                            Ok(nh) => {
                                let nh = Arc::new(nh);
                                *handle.lock().unwrap() = nh.clone();
                                h = nh;
                                stats.reopens.fetch_add(1, Ordering::Relaxed);
                                healthy.store(true, Ordering::Relaxed);
                                consec_err = 0;
                                log("split(WinDivert): хендл переоткрыт, захват возобновлён ✓".into());
                                break;
                            }
                            Err(e) => {
                                log(format!(
                                    "split(WinDivert): переоткрытие не удалось: {e}; повтор через 2 с"
                                ));
                                std::thread::sleep(Duration::from_secs(2));
                            }
                        }
                    }
                    continue;
                }
                std::thread::sleep(Duration::from_millis(50)); // не спиним на ошибке
                continue;
            }
        };

        stats.captured.fetch_add(1, Ordering::Relaxed);

        let (verdict, info) = classify(&packet.data, &config, &mut resolver);
        if detailed < 15 {
            detailed += 1;
            log(format!("split(WinDivert): пакет#{detailed} {info} → {verdict:?}"));
        }

        match verdict {
            Verdict::Tunnel => {
                stats.tunnel.fetch_add(1, Ordering::Relaxed);
                // Запоминаем интерфейс ТУННЕЛЬНОГО потока per локальный IP (src) —
                // ответы инъектируем как входящие именно на этот интерфейс. На
                // машинах с несколькими адаптерами один общий адрес был неверным.
                if let Some((src, _)) = ip_src_dst(&packet.data) {
                    let a = packet.address.clone();
                    let mut t = addrs.lock().unwrap();
                    if t.by_ip.len() >= 64 {
                        t.by_ip.clear(); // защита от роста (адаптеров единицы)
                    }
                    t.by_ip.insert(src, a.clone());
                    t.last = Some(a);
                }
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
                if let Err(e) = h.0.send(&packet) {
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
        "захвачено={} туннель={} прямо={} дроп={} инъекций={} (ошибок_инъекции={}) ошибок_send={} нет_адреса={} переоткрытий={}",
        s.captured.load(Relaxed),
        s.tunnel.load(Relaxed),
        s.direct.load(Relaxed),
        s.dropped.load(Relaxed),
        s.inject_ok.load(Relaxed),
        s.inject_err.load(Relaxed),
        s.send_err.load(Relaxed),
        s.no_addr.load(Relaxed),
        s.reopens.load(Relaxed),
    )
}

#[derive(Debug)]
enum Verdict {
    Tunnel,
    Direct,
    Drop,
}

/// Классифицирует исходящий IP-пакет → (вердикт, строка для лога).
fn classify(
    ip: &[u8],
    config: &SplitConfig,
    resolver: &mut ProcessResolver,
) -> (Verdict, String) {
    let Some((proto, is_v6, local_port, dst_ip, dst_port)) = parse_ip(ip) else {
        return (Verdict::Direct, "не-TCP/UDP/короткий → прямо".into());
    };
    let app = resolver
        .resolve(proto, is_v6, local_port)
        .unwrap_or(ConnApp {
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
    let info = format!(
        "{proto:?} :{local_port}→{dst_ip}:{dst_port} app={app_name}",
    );
    (verdict, info)
}

/// Адреса источника и назначения IP-пакета (IPv4/IPv6) без разбора L4.
/// Для исходящего src = локальный IP приложения; для ответа dst = он же.
fn ip_src_dst(ip: &[u8]) -> Option<(IpAddr, IpAddr)> {
    match ip.first()? >> 4 {
        4 => {
            if ip.len() < 20 {
                return None;
            }
            Some((
                IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15])),
                IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19])),
            ))
        }
        6 => {
            if ip.len() < 40 {
                return None;
            }
            let mut s = [0u8; 16];
            s.copy_from_slice(&ip[8..24]);
            let mut d = [0u8; 16];
            d.copy_from_slice(&ip[24..40]);
            Some((IpAddr::V6(Ipv6Addr::from(s)), IpAddr::V6(Ipv6Addr::from(d))))
        }
        _ => None,
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
