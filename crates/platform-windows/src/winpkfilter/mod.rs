//! Per-app split-туннелирование через Windows Packet Filter (WinpkFilter/ndisapi).
//!
//! Захват пакетов на уровне NDIS (как WireSock): адаптеры переводятся в
//! tunnel-режим (весь трафик идёт в userspace, оригинал дропается). Для каждого
//! исходящего пакета определяется процесс-владелец; пакеты приложений из
//! split-набора отдаются наружу через `on_capture` (в userspace `netstack`),
//! остальные — реинъектятся в исходный путь без изменений. Ответы из netstack
//! ([`ResponseInjector::inject`]) реинъектятся приложению (в MSTCP).
//!
//! Требует установленного драйвера `ndisrd` и запуска процесса от администратора.

pub mod attribution;

use attribution::{Proto, ProcessResolver};
use jammvpn_core::split::{decide, Action, ConnApp, ConnRequest, SplitConfig};
use ndisapi::{DirectionFlags, EthRequest, FilterFlags, IntermediateBuffer, Ndisapi};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::thread::JoinHandle;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    CreateEventW, ResetEvent, SetEvent, WaitForMultipleObjects,
};

const MAX_FRAME: usize = 1514;
const ETH_HDR: usize = 14;
const RESPONSE_QUEUE: usize = 8192;

/// Колбэк на туннелируемый IP-пакет приложения.
type OnCapture = Box<dyn FnMut(&[u8]) + Send>;
/// Логгер диагностики (пишет в файл лога приложения).
pub type Logger = std::sync::Arc<dyn Fn(String) + Send + Sync>;

/// `true`, если процесс запущен с правами администратора (нужно для драйвера).
pub fn is_elevated() -> bool {
    use std::mem::size_of;
    use windows::Win32::Foundation::HANDLE as WHANDLE;
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = WHANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

/// HANDLE, помеченный Send/Sync (Win32 event-хендлы потокобезопасны для Set/Reset).
#[derive(Clone, Copy)]
struct SendHandle(HANDLE);
unsafe impl Send for SendHandle {}
unsafe impl Sync for SendHandle {}

/// Запущенный split-перехват.
pub struct SplitTunnel {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    response_tx: SyncSender<Vec<u8>>,
    response_event: SendHandle,
    packet_event: SendHandle,
}

/// Хендл для инъекции ответных IP-пакетов из netstack обратно приложению.
#[derive(Clone)]
pub struct ResponseInjector {
    tx: SyncSender<Vec<u8>>,
    event: SendHandle,
}

impl ResponseInjector {
    /// Кладёт IP-пакет в очередь и будит поток захвата для реинъекции в MSTCP.
    pub fn inject(&self, ip_packet: Vec<u8>) {
        if self.tx.try_send(ip_packet).is_ok() {
            unsafe {
                let _ = SetEvent(self.event.0);
            }
        }
    }
}

impl SplitTunnel {
    /// Запускает перехват. `on_capture` вызывается с IP-пакетом (без Ethernet)
    /// каждого «туннелируемого» приложения. Ошибка — если драйвер недоступен.
    pub fn start(
        config: SplitConfig,
        on_capture: OnCapture,
        log: Logger,
    ) -> Result<SplitTunnel, String> {
        if !is_elevated() {
            return Err("split требует запуска JammVPN от администратора".into());
        }
        // Проверяем доступность драйвера заранее (понятная ошибка для UI).
        Ndisapi::new("NDISRD")
            .map_err(|e| format!("драйвер WinpkFilter (ndisrd) недоступен: {e}. Установите его и запустите от администратора"))?;

        let packet_event = SendHandle(
            unsafe { CreateEventW(None, true, false, None) }.map_err(|e| e.to_string())?,
        );
        let response_event = SendHandle(
            unsafe { CreateEventW(None, true, false, None) }.map_err(|e| e.to_string())?,
        );
        let (response_tx, response_rx) = sync_channel::<Vec<u8>>(RESPONSE_QUEUE);
        let stop = Arc::new(AtomicBool::new(false));

        let thread = {
            let stop = stop.clone();
            std::thread::Builder::new()
                .name("winpkfilter-capture".into())
                .spawn(move || {
                    capture_loop(
                        stop,
                        config,
                        on_capture,
                        response_rx,
                        packet_event,
                        response_event,
                        log,
                    );
                })
                .map_err(|e| e.to_string())?
        };

        Ok(SplitTunnel {
            stop,
            thread: Some(thread),
            response_tx,
            response_event,
            packet_event,
        })
    }

    /// Инжектор ответов (для подключения к netstack-выходу).
    pub fn injector(&self) -> ResponseInjector {
        ResponseInjector {
            tx: self.response_tx.clone(),
            event: self.response_event,
        }
    }

    /// Останавливает перехват (снимает tunnel-режим, ждёт поток).
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        unsafe {
            let _ = SetEvent(self.packet_event.0);
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        unsafe {
            let _ = CloseHandle(self.packet_event.0);
            let _ = CloseHandle(self.response_event.0);
        }
    }
}

/// Решение по одному пакету.
enum Verdict {
    /// Туннелировать: IP-пакет + Ethernet-шаблон ответа (swapped MAC).
    Tunnel(Vec<u8>, [u8; ETH_HDR]),
    /// Реинъектить на адаптер (исходящее напрямую).
    ToAdapter,
    /// Реинъектить в MSTCP (входящее / системное).
    ToMstcp,
    /// Дропнуть (kill-switch Block).
    Drop,
}

/// Главный цикл захвата (отдельный поток).
#[allow(clippy::too_many_arguments)]
fn capture_loop(
    stop: Arc<AtomicBool>,
    config: SplitConfig,
    mut on_capture: OnCapture,
    response_rx: Receiver<Vec<u8>>,
    packet_event: SendHandle,
    response_event: SendHandle,
    log: Logger,
) {
    let driver = match Ndisapi::new("NDISRD") {
        Ok(d) => d,
        Err(e) => {
            log(format!("split: драйвер недоступен: {e}"));
            return;
        }
    };
    let adapters = driver.get_tcpip_bound_adapters_info().unwrap_or_default();
    if adapters.is_empty() {
        log("split: нет TCP/IP-адаптеров".into());
        return;
    }
    log(format!(
        "split: драйвер открыт, адаптеров {}; приложения: {:?}",
        adapters.len(),
        config.apps
    ));

    // Один общий event на все адаптеры + tunnel-режим (весь трафик в userspace).
    for ad in &adapters {
        let _ = driver.set_packet_event(ad.get_handle(), packet_event.0);
        let _ = driver
            .set_adapter_mode(ad.get_handle(), FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL);
    }

    let mut resolver = ProcessResolver::new();
    let mut read_ib = IntermediateBuffer::new();
    let mut inject_ib = IntermediateBuffer::new();
    // Адаптер + Ethernet-шаблон последнего туннелированного пакета (для инъекции
    // ответов). Допущение v1: одна активная сеть.
    let mut active: Option<(HANDLE, [u8; ETH_HDR])> = None;

    // Счётчики для периодической диагностики.
    let (mut n_out, mut n_tunnel, mut n_direct, mut n_inject) = (0u64, 0u64, 0u64, 0u64);
    let mut last_report = std::time::Instant::now();

    let events = [packet_event.0, response_event.0];

    while !stop.load(Ordering::Relaxed) {
        unsafe {
            WaitForMultipleObjects(&events, false, 200);
            let _ = ResetEvent(packet_event.0);
            let _ = ResetEvent(response_event.0);
        }
        if stop.load(Ordering::Relaxed) {
            break;
        }

        // 1) Инъекция ответов из netstack в MSTCP.
        if let Some((handle, eth)) = active {
            while let Ok(ip) = response_rx.try_recv() {
                if ip.len() + ETH_HDR > MAX_FRAME {
                    continue;
                }
                inject_ib.device_flags = DirectionFlags::PACKET_FLAG_ON_RECEIVE;
                inject_ib.set_length((ip.len() + ETH_HDR) as u32);
                let data = inject_ib.get_data_mut();
                data[..ETH_HDR].copy_from_slice(&eth);
                data[ETH_HDR..].copy_from_slice(&ip);
                let mut req = EthRequest::new(handle);
                req.set_packet(&mut inject_ib);
                let _ = driver.send_packet_to_mstcp(&req);
                n_inject += 1;
            }
        }

        // Периодический отчёт (раз в ~5 с) — для диагностики.
        if last_report.elapsed().as_secs() >= 5 {
            log(format!(
                "split: исходящих={n_out} туннель={n_tunnel} прямо={n_direct} ответов-в-mstcp={n_inject}"
            ));
            last_report = std::time::Instant::now();
        }

        // 2) Чтение и обработка пакетов со всех адаптеров.
        for ad in &adapters {
            let handle = ad.get_handle();
            loop {
                let mut req = EthRequest::new(handle);
                req.set_packet(&mut read_ib);
                if driver.read_packet(&mut req).is_err() {
                    break; // очередь адаптера пуста
                }
                let verdict = {
                    let ib = req.packet.buffer.as_deref().unwrap();
                    classify(ib.get_data(), ib.get_device_flags(), &config, &mut resolver)
                };
                match verdict {
                    Verdict::Tunnel(ip, eth) => {
                        n_out += 1;
                        n_tunnel += 1;
                        active = Some((handle, eth));
                        on_capture(&ip);
                        // оригинал не реинъектим (дропнут tunnel-режимом).
                    }
                    Verdict::ToAdapter => {
                        n_out += 1;
                        n_direct += 1;
                        let _ = driver.send_packet_to_adapter(&req);
                    }
                    Verdict::ToMstcp => {
                        let _ = driver.send_packet_to_mstcp(&req);
                    }
                    Verdict::Drop => {}
                }
            }
        }
    }

    // Снимаем tunnel-режим.
    for ad in &adapters {
        let _ = driver.set_adapter_mode(ad.get_handle(), FilterFlags::default());
    }
}

/// Классифицирует Ethernet-кадр: куда направить / туннелировать.
fn classify(
    frame: &[u8],
    dir: DirectionFlags,
    config: &SplitConfig,
    resolver: &mut ProcessResolver,
) -> Verdict {
    let outgoing = dir == DirectionFlags::PACKET_FLAG_ON_SEND;
    // Не-IP / короткие кадры — просто пропускаем по направлению.
    if frame.len() < ETH_HDR {
        return passthrough(outgoing);
    }
    let ip = &frame[ETH_HDR..];
    let parsed = parse_ip(ip);
    let Some((proto, is_v6, local_port, dst_ip, dst_port)) = parsed else {
        return passthrough(outgoing);
    };
    // Входящее (ответы прямым приложениям/системе) — наверх в TCP/IP.
    if !outgoing {
        return Verdict::ToMstcp;
    }
    // Исходящее: атрибуция к процессу и решение по split-правилам.
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
        Action::Tunnel => Verdict::Tunnel(ip.to_vec(), swapped_eth(frame)),
        Action::Direct => Verdict::ToAdapter,
        Action::Block => Verdict::Drop,
    }
}

fn passthrough(outgoing: bool) -> Verdict {
    if outgoing {
        Verdict::ToAdapter
    } else {
        Verdict::ToMstcp
    }
}

/// Ethernet-шаблон для ответа: меняем местами src/dst MAC (как будто пакет
/// пришёл от шлюза к локальному адаптеру).
fn swapped_eth(frame: &[u8]) -> [u8; ETH_HDR] {
    let mut e = [0u8; ETH_HDR];
    e[0..6].copy_from_slice(&frame[6..12]); // dst = бывший src (локальный MAC)
    e[6..12].copy_from_slice(&frame[0..6]); // src = бывший dst (MAC шлюза)
    e[12..14].copy_from_slice(&frame[12..14]); // ethertype
    e
}

/// Разбирает IPv4/IPv6 + TCP/UDP: `(proto, is_v6, local_port, dst_ip, dst_port)`.
/// `local_port` — порт источника (для исходящих = локальный порт приложения).
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
