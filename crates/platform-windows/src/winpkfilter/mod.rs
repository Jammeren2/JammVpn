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
pub mod driver;

use attribution::{Proto, ProcessResolver};
use jammvpn_core::split::{decide, Action, ConnRequest, SplitConfig};
use ndisapi::{DirectionFlags, EthRequest, FilterFlags, IntermediateBuffer, Ndisapi};
use std::collections::HashMap;
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

/// Перезапускает приложение с запросом прав администратора (UAC) и просит
/// вызывающего завершить текущий процесс. Ошибка — если UAC отклонён.
pub fn relaunch_elevated() -> Result<(), String> {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe_w = HSTRING::from(exe.as_os_str());
    let verb = HSTRING::from("runas");
    let h = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(exe_w.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    // ShellExecuteW возвращает значение > 32 при успехе.
    if h.0 as isize <= 32 {
        return Err("перезапуск от администратора отменён".into());
    }
    Ok(())
}

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
        // Если драйвер не установлен — ставим вшитый в exe пакет (нужны админ-права).
        driver::ensure_installed(&|m| log(m))
            .map_err(|e| format!("драйвер WinpkFilter (ndisrd): {e}"))?;
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

    /// Останавливает перехват. Реальная остановка — в `Drop` (вызывается и при
    /// явном stop, и при любом уничтожении контроллера), чтобы поток захвата НЕ
    /// мог утечь зомби-инстансом при смене драйвера/перезапуске.
    pub fn stop(self) {
        // drop(self) → Drop снимет tunnel-режим, дождётся поток, закроет события.
    }
}

impl Drop for SplitTunnel {
    fn drop(&mut self) {
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
    /// Туннелировать: IP-пакет + Ethernet-шаблон ответа (swapped MAC) +
    /// локальный IP потока (ключ, на какой адаптер инъектировать ответы).
    Tunnel(Vec<u8>, [u8; ETH_HDR], IpAddr),
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
    // Адаптер + Ethernet-шаблон ответа per ЛОКАЛЬНЫЙ IP. У каждого адаптера свой
    // IP и своя пара MAC (локальный↔шлюз), поэтому ответ из netstack инъектируем
    // на тот адаптер, с которого ушёл исходящий пакет этого же локального IP.
    // `last` — фолбэк, если поток ещё не в карте. (Раньше был один `active` на
    // все адаптеры — на машинах с несколькими адаптерами ответы уходили не туда.)
    let mut flow_eth: HashMap<IpAddr, (HANDLE, [u8; ETH_HDR])> = HashMap::new();
    let mut last: Option<(HANDLE, [u8; ETH_HDR])> = None;

    // Счётчики + первые N пакетов детально (для диагностики, как у WinDivert).
    let (mut n_out, mut n_tunnel, mut n_direct, mut n_inject, mut n_lost) =
        (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut detailed = 0u32;
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

        // 1) Инъекция ответов из netstack в MSTCP — на адаптер исходного потока.
        while let Ok(ip) = response_rx.try_recv() {
            if ip.len() + ETH_HDR > MAX_FRAME {
                n_lost += 1;
                continue;
            }
            // Ответ адресован локальному IP приложения = dst пакета. Берём
            // адаптер/MAC именно этого локального IP; фолбэк — последний.
            let target = parse_ip(&ip)
                .and_then(|(_, _, _, dst_ip, _, _)| flow_eth.get(&dst_ip).copied())
                .or(last);
            let Some((handle, eth)) = target else {
                n_lost += 1;
                continue;
            };
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

        // Периодический отчёт (раз в ~5 с) — для диагностики.
        if last_report.elapsed().as_secs() >= 5 {
            log(format!(
                "split: исходящих={n_out} туннель={n_tunnel} прямо={n_direct} ответов-в-mstcp={n_inject} потеряно-ответов={n_lost} потоков={}",
                flow_eth.len()
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
                let (verdict, info) = {
                    let ib = req.packet.buffer.as_deref().unwrap();
                    classify(ib.get_data(), ib.get_device_flags(), &config, &mut resolver)
                };
                if detailed < 15 && !info.is_empty() {
                    detailed += 1;
                    log(format!("split: пакет#{detailed} {info}"));
                }
                match verdict {
                    Verdict::Tunnel(mut ip, eth, local_ip) => {
                        n_out += 1;
                        n_tunnel += 1;
                        // Карта адаптеров мала (по числу локальных IP); страховка
                        // от роста при странных конфигурациях.
                        if flow_eth.len() >= 64 {
                            flow_eth.clear();
                        }
                        flow_eth.insert(local_ip, (handle, eth));
                        last = Some((handle, eth));
                        // На NDIS-краю контрольные суммы ещё не посчитаны
                        // (checksum offload) — netstack/smoltcp валидирует rx и
                        // иначе отбросил бы пакет. WinDivert (L3) делает то же.
                        recalc_checksums(&mut ip);
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
/// Возвращает вердикт и строку диагностики (пустую для входящих/не-IP — их не
/// логируем, чтобы не зашумлять).
fn classify(
    frame: &[u8],
    dir: DirectionFlags,
    config: &SplitConfig,
    resolver: &mut ProcessResolver,
) -> (Verdict, String) {
    let outgoing = dir == DirectionFlags::PACKET_FLAG_ON_SEND;
    // Не-IP / короткие кадры — просто пропускаем по направлению.
    if frame.len() < ETH_HDR {
        return (passthrough(outgoing), String::new());
    }
    let ip = &frame[ETH_HDR..];
    let Some((proto, is_v6, local_port, dst_ip, dst_port, src_ip)) = parse_ip(ip) else {
        return (passthrough(outgoing), String::new());
    };
    // Входящее (ответы прямым приложениям/системе) — наверх в TCP/IP.
    if !outgoing {
        return (Verdict::ToMstcp, String::new());
    }
    // Исходящее: атрибуция к процессу и решение по split-правилам.
    let app = resolver.resolve(proto, is_v6, local_port).unwrap_or_default();
    let name = app
        .process_name
        .clone()
        .or_else(|| app.exe_path.clone())
        .unwrap_or_else(|| "<неизвестно>".into());
    let req = ConnRequest {
        app: &app,
        dst_ip,
        dst_port,
    };
    let (verdict, label) = match decide(&req, config, true) {
        Action::Tunnel => (
            Verdict::Tunnel(ip.to_vec(), swapped_eth(frame), src_ip),
            "Tunnel",
        ),
        Action::Direct => (Verdict::ToAdapter, "Direct"),
        Action::Block => (Verdict::Drop, "Drop"),
    };
    (
        verdict,
        format!("{proto:?} :{local_port}→{dst_ip}:{dst_port} app={name} → {label}"),
    )
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

/// Разбирает IPv4/IPv6 + TCP/UDP:
/// `(proto, is_v6, src_port, dst_ip, dst_port, src_ip)`.
/// `src_port`/`src_ip` — источник (для исходящих = локальные порт/IP приложения).
fn parse_ip(ip: &[u8]) -> Option<(Proto, bool, u16, IpAddr, u16, IpAddr)> {
    if ip.is_empty() {
        return None;
    }
    let (is_v6, proto_num, src_ip, dst_ip, l4): (bool, u8, IpAddr, IpAddr, &[u8]) =
        match ip[0] >> 4 {
            4 => {
                if ip.len() < 20 {
                    return None;
                }
                let ihl = ((ip[0] & 0x0F) as usize) * 4;
                let src = IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
                let dst = IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]));
                (false, ip[9], src, dst, ip.get(ihl..)?)
            }
            6 => {
                if ip.len() < 40 {
                    return None;
                }
                let mut s = [0u8; 16];
                s.copy_from_slice(&ip[8..24]);
                let mut d = [0u8; 16];
                d.copy_from_slice(&ip[24..40]);
                (
                    true,
                    ip[6],
                    IpAddr::V6(Ipv6Addr::from(s)),
                    IpAddr::V6(Ipv6Addr::from(d)),
                    ip.get(40..)?,
                )
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
    Some((proto, is_v6, src_port, dst_ip, dst_port, src_ip))
}

/// Сумма 16-битных слов (для контрольной суммы интернета), с начальным `init`.
fn sum16(data: &[u8], init: u32) -> u32 {
    let mut sum = init;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8; // нечётный хвост — старший байт
    }
    sum
}

/// Свёртка переносов + дополнение до единицы → итоговая контрольная сумма.
fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Записывает контрольную сумму TCP/UDP по уже накопленной сумме псевдозаголовка.
/// `l4` — транспортный сегмент целиком; смещение поля: TCP=16, UDP=6.
fn set_l4_checksum(proto: u8, l4: &mut [u8], pseudo: u32) {
    let off = match proto {
        6 => 16,  // TCP
        17 => 6,  // UDP
        _ => return,
    };
    if l4.len() < off + 2 {
        return;
    }
    l4[off] = 0;
    l4[off + 1] = 0;
    let mut cs = fold(sum16(l4, pseudo));
    if proto == 17 && cs == 0 {
        cs = 0xFFFF; // UDP: нулевая сумма кодируется как 0xFFFF
    }
    l4[off..off + 2].copy_from_slice(&cs.to_be_bytes());
}

/// Пересчитывает контрольные суммы захваченного IP-пакета (IPv4-заголовок +
/// TCP/UDP). На NDIS-краю они не посчитаны (checksum offload). Обрезанные
/// LSO-суперсегменты (`total_length` > буфера) пропускаем — их не восстановить.
fn recalc_checksums(ip: &mut [u8]) {
    match ip.first().map(|b| b >> 4) {
        Some(4) => {
            if ip.len() < 20 {
                return;
            }
            let ihl = ((ip[0] & 0x0F) as usize) * 4;
            let total_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
            if ihl < 20 || ihl > ip.len() || total_len < ihl || total_len > ip.len() {
                return; // битый/обрезанный заголовок
            }
            let proto = ip[9];
            let mut src = [0u8; 4];
            src.copy_from_slice(&ip[12..16]);
            let mut dst = [0u8; 4];
            dst.copy_from_slice(&ip[16..20]);
            // Контрольная сумма IPv4-заголовка.
            ip[10] = 0;
            ip[11] = 0;
            let hc = fold(sum16(&ip[..ihl], 0));
            ip[10..12].copy_from_slice(&hc.to_be_bytes());
            // Транспортная сумма: псевдозаголовок + сегмент.
            let l4 = &mut ip[ihl..total_len];
            let l4_len = l4.len() as u32;
            let mut pseudo = 0u32;
            pseudo = sum16(&src, pseudo);
            pseudo = sum16(&dst, pseudo);
            pseudo += proto as u32 + l4_len;
            set_l4_checksum(proto, l4, pseudo);
        }
        Some(6) => {
            if ip.len() < 40 {
                return;
            }
            let next = ip[6]; // без extension-заголовков (упрощение v1)
            let payload = u16::from_be_bytes([ip[4], ip[5]]) as usize;
            if payload == 0 || 40 + payload > ip.len() {
                return;
            }
            let mut src = [0u8; 16];
            src.copy_from_slice(&ip[8..24]);
            let mut dst = [0u8; 16];
            dst.copy_from_slice(&ip[24..40]);
            let l4 = &mut ip[40..40 + payload];
            let l4_len = l4.len() as u32;
            let mut pseudo = 0u32;
            pseudo = sum16(&src, pseudo);
            pseudo = sum16(&dst, pseudo);
            pseudo += next as u32 + l4_len;
            set_l4_checksum(next, l4, pseudo);
        }
        _ => {}
    }
}

#[cfg(test)]
mod checksum_tests {
    use super::{recalc_checksums, sum16};

    /// IPv4-заголовок валиден, если сумма всех 16-битных слов свёрнута в 0xFFFF.
    fn ipv4_hdr_ok(ip: &[u8]) -> bool {
        let ihl = ((ip[0] & 0x0F) as usize) * 4;
        let mut s = sum16(&ip[..ihl], 0);
        while s >> 16 != 0 {
            s = (s & 0xFFFF) + (s >> 16);
        }
        s as u16 == 0xFFFF
    }

    /// TCP/UDP валиден, если псевдозаголовок+сегмент свёрнуты в 0xFFFF.
    fn l4_ok(ip: &[u8]) -> bool {
        let ihl = ((ip[0] & 0x0F) as usize) * 4;
        let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
        let proto = ip[9];
        let l4 = &ip[ihl..total];
        let mut pseudo = 0u32;
        pseudo = sum16(&ip[12..16], pseudo);
        pseudo = sum16(&ip[16..20], pseudo);
        pseudo += proto as u32 + l4.len() as u32;
        let mut s = sum16(l4, pseudo);
        while s >> 16 != 0 {
            s = (s & 0xFFFF) + (s >> 16);
        }
        s as u16 == 0xFFFF
    }

    #[test]
    fn recalc_makes_ipv4_tcp_valid() {
        // IPv4 (ihl=5) + TCP (20 байт) + 4 байта payload, суммы обнулены/мусор.
        let mut ip = vec![
            0x45, 0x00, 0x00, 0x2c, // ver/ihl, tos, total_len=44
            0x12, 0x34, 0x40, 0x00, // id, flags/frag
            0x40, 0x06, 0xff, 0xff, // ttl, proto=6(TCP), checksum=мусор
            192, 168, 1, 50, // src
            93, 184, 216, 34, // dst
            // TCP
            0xc0, 0x00, 0x01, 0xbb, // sport, dport=443
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x18, 0xff, 0xff, // off/flags, window
            0xab, 0xcd, 0x00, 0x00, // checksum=мусор, urg
            0xde, 0xad, 0xbe, 0xef, // payload
        ];
        recalc_checksums(&mut ip);
        assert!(ipv4_hdr_ok(&ip), "IPv4-заголовок невалиден после пересчёта");
        assert!(l4_ok(&ip), "TCP-сумма невалидна после пересчёта");
    }

    #[test]
    fn truncated_lso_packet_left_untouched() {
        // total_len=64000, но буфер мал → обрезанный LSO, не трогаем.
        let mut ip = vec![0x45, 0x00, 0xfa, 0x00, 0, 0, 0, 0, 0x40, 0x06, 0, 0];
        ip.extend_from_slice(&[192, 168, 1, 50, 93, 184, 216, 34]);
        ip.extend_from_slice(&[0u8; 20]);
        let before = ip.clone();
        recalc_checksums(&mut ip);
        assert_eq!(ip, before, "обрезанный LSO-пакет не должен меняться");
    }
}
