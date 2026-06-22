//! Атрибуция сетевого потока к процессу: по локальному порту (из захваченного
//! пакета) находим владеющий PID через таблицы TCP/UDP (`GetExtendedTcpTable` /
//! `GetExtendedUdpTable`), затем PID → путь к `.exe` (`QueryFullProcessImageNameW`).
//!
//! Таблицы кэшируются и обновляются не чаще раза в `REFRESH`, т.к. построение
//! таблицы — относительно дорогой системный вызов, а захват идёт на каждый пакет.

use jammvpn_core::split::ConnApp;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDP6TABLE_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Транспорт потока.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Proto {
    Tcp,
    Udp,
}

/// Как часто перестраивать таблицы порт→PID (фоновое).
const REFRESH: Duration = Duration::from_millis(1000);
/// Минимальный интервал между принудительными обновлениями при промахе.
const FORCE_COOLDOWN: Duration = Duration::from_millis(20);

/// Резолвер «локальный порт → процесс» с кэшем таблиц и путей.
pub struct ProcessResolver {
    /// (proto, is_v6, local_port) → PID.
    ports: HashMap<(bool, bool, u16), u32>,
    /// PID → путь к exe (кэш, чтобы не открывать процесс на каждый пакет).
    pid_exe: HashMap<u32, Option<String>>,
    /// Ключи, уже пробованные форс-обновлением против ТЕКУЩЕЙ таблицы (сброс при
    /// пересборке) — чтобы новый ключ всегда форсил пересборку в обход кулдауна.
    forced_keys: HashSet<(bool, bool, u16)>,
    last: Option<Instant>,
    last_forced: Option<Instant>,
}

impl Default for ProcessResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessResolver {
    pub fn new() -> Self {
        Self {
            ports: HashMap::new(),
            pid_exe: HashMap::new(),
            forced_keys: HashSet::new(),
            last: None,
            last_forced: None,
        }
    }

    /// Возвращает приложение-владельца потока с локальным портом `local_port`.
    /// При промахе (новое соединение, которого ещё нет в устаревшей таблице)
    /// принудительно обновляет таблицу и повторяет — иначе SYN утекал бы «прямо».
    pub fn resolve(&mut self, proto: Proto, is_v6: bool, local_port: u16) -> Option<ConnApp> {
        self.maybe_refresh();
        let key = (proto == Proto::Tcp, is_v6, local_port);
        let mut pid = self.ports.get(&key).copied();
        if pid.is_none() && self.force_refresh_for(key) {
            pid = self.ports.get(&key).copied();
        }
        let pid = pid?;
        let exe = self.exe_for(pid);
        let process_name = exe.as_ref().and_then(|p| {
            std::path::Path::new(p)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
        });
        Some(ConnApp {
            exe_path: exe,
            process_name,
        })
    }

    /// Перестраивает таблицы порт→PID.
    fn load_tables(&mut self) {
        self.ports.clear();
        self.forced_keys.clear(); // новая таблица → все ключи снова «не пробованы»
        unsafe {
            self.load_tcp(false);
            self.load_tcp(true);
            self.load_udp(false);
            self.load_udp(true);
        }
        self.last = Some(Instant::now());
    }

    fn maybe_refresh(&mut self) {
        let stale = match self.last {
            Some(t) => t.elapsed() >= REFRESH,
            None => true,
        };
        if stale {
            self.pid_exe.clear();
            self.load_tables();
        }
    }

    /// Принудительная пересборка таблиц при промахе. НОВЫЙ ключ (ещё не пробованный
    /// против текущей таблицы) форсит пересборку в обход кулдауна — иначе пачка
    /// новых сокетов (VRChat и т.п.) утекала бы «прямо». Повторный промах того же
    /// ключа (его просто нет в таблице) подавляется кулдауном, чтобы не молотить
    /// системные таблицы.
    fn force_refresh_for(&mut self, key: (bool, bool, u16)) -> bool {
        let already = self.forced_keys.contains(&key);
        let recent = self
            .last_forced
            .map(|t| t.elapsed() < FORCE_COOLDOWN)
            .unwrap_or(false);
        if already && recent {
            return false;
        }
        self.last_forced = Some(Instant::now());
        self.load_tables(); // очищает forced_keys
        self.forced_keys.insert(key);
        true
    }

    /// Кэшируемый путь к exe по PID.
    fn exe_for(&mut self, pid: u32) -> Option<String> {
        if let Some(cached) = self.pid_exe.get(&pid) {
            return cached.clone();
        }
        let exe = unsafe { query_exe_path(pid) };
        self.pid_exe.insert(pid, exe.clone());
        exe
    }

    unsafe fn load_tcp(&mut self, is_v6: bool) {
        let af = if is_v6 { AF_INET6.0 } else { AF_INET.0 } as u32;
        let mut size: u32 = 0;
        // Первый вызов — узнаём размер.
        let _ = GetExtendedTcpTable(None, &mut size, false, af, TCP_TABLE_OWNER_PID_ALL, 0);
        if size == 0 {
            return;
        }
        // Таблица могла вырасти между size-probe и fill → ERROR_INSUFFICIENT_BUFFER
        // (fill НЕ заполняет буфер). Повторяем с увеличенным размером; парсим только
        // при NO_ERROR, иначе читали бы нулевой буфер (0 строк → пропадают все порты).
        let mut buf = vec![0u8; size as usize];
        let mut rc;
        let mut tries = 0;
        loop {
            rc = GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                af,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if rc != ERROR_INSUFFICIENT_BUFFER.0 || tries >= 3 {
                break;
            }
            tries += 1;
            buf = vec![0u8; size as usize];
        }
        if rc != 0 {
            return;
        }
        if is_v6 {
            let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(
                table.table.as_ptr(),
                table.dwNumEntries as usize,
            );
            for r in rows {
                let port = swap_port(r.dwLocalPort);
                self.ports.insert((true, true, port), r.dwOwningPid);
                // Dual-stack сокет на `::` (IPV6_V6ONLY=false) шлёт и IPv4 — в v4-
                // таблице его нет, добавляем v4-алиас (не затирая реальный v4-ряд).
                if r.ucLocalAddr == [0u8; 16] {
                    self.ports.entry((true, false, port)).or_insert(r.dwOwningPid);
                }
            }
        } else {
            let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(
                table.table.as_ptr(),
                table.dwNumEntries as usize,
            );
            for r in rows {
                self.ports.insert(
                    (true, false, swap_port(r.dwLocalPort)),
                    r.dwOwningPid,
                );
            }
        }
    }

    unsafe fn load_udp(&mut self, is_v6: bool) {
        let af = if is_v6 { AF_INET6.0 } else { AF_INET.0 } as u32;
        let mut size: u32 = 0;
        let _ = GetExtendedUdpTable(None, &mut size, false, af, UDP_TABLE_OWNER_PID, 0);
        if size == 0 {
            return;
        }
        let mut buf = vec![0u8; size as usize];
        let mut rc;
        let mut tries = 0;
        loop {
            rc = GetExtendedUdpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                af,
                UDP_TABLE_OWNER_PID,
                0,
            );
            if rc != ERROR_INSUFFICIENT_BUFFER.0 || tries >= 3 {
                break;
            }
            tries += 1;
            buf = vec![0u8; size as usize];
        }
        if rc != 0 {
            return;
        }
        if is_v6 {
            let table = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(
                table.table.as_ptr(),
                table.dwNumEntries as usize,
            );
            for r in rows {
                let port = swap_port(r.dwLocalPort);
                self.ports.insert((false, true, port), r.dwOwningPid);
                // Dual-stack UDP-сокет на `::` шлёт и IPv4 — добавляем v4-алиас.
                if r.ucLocalAddr == [0u8; 16] {
                    self.ports.entry((false, false, port)).or_insert(r.dwOwningPid);
                }
            }
        } else {
            let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(
                table.table.as_ptr(),
                table.dwNumEntries as usize,
            );
            for r in rows {
                self.ports.insert(
                    (false, false, swap_port(r.dwLocalPort)),
                    r.dwOwningPid,
                );
            }
        }
    }
}

/// Порт из таблицы хранится в сетевом порядке в младших 16 битах u32 →
/// перестановка байт даёт хостовый порядок.
fn swap_port(dw: u32) -> u16 {
    ((dw & 0xFFFF) as u16).swap_bytes()
}

/// Полный путь к исполняемому файлу процесса по PID (`None` — нет доступа/процесса).
unsafe fn query_exe_path(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    let handle: HANDLE = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
    let mut buf = vec![0u16; 1024];
    let mut size = buf.len() as u32;
    let res = QueryFullProcessImageNameW(
        handle,
        PROCESS_NAME_WIN32,
        windows::core::PWSTR(buf.as_mut_ptr()),
        &mut size,
    );
    let _ = CloseHandle(handle);
    res.ok()?;
    Some(String::from_utf16_lossy(&buf[..size as usize]))
}
