//! Контракт user-mode ↔ kernel-driver для подсистемы split.
//!
//! Решение «перенаправлять соединение или нет» драйвер принимает в ядре в
//! момент `connect` (слой `ALE_CONNECT_REDIRECT`), поэтому ему нужен компактный
//! снимок правил. Здесь определены: путь к устройству, коды IOCTL и
//! версионированный бинарный формат [`DriverConfig`]. И UI, и драйвер опираются
//! на этот модуль как на единый источник истины.

use jammvpn_core::split::{AppMatcher, IpCidr, SplitConfig, SplitMode, ALWAYS_BYPASS_CIDRS};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Путь к устройству со стороны user-mode (`CreateFile`).
pub const USER_MODE_DEVICE_PATH: &str = r"\\.\JammVpnSplit";
/// Имя устройства со стороны ядра.
pub const KERNEL_DEVICE_NAME: &str = r"\Device\JammVpnSplit";
/// Символьная ссылка со стороны ядра.
pub const KERNEL_SYMLINK: &str = r"\DosDevices\JammVpnSplit";

const FILE_DEVICE_NETWORK: u32 = 0x12;
const METHOD_BUFFERED: u32 = 0;
const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;

/// Аналог макроса `CTL_CODE` из WDK.
pub const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

/// Загрузить/обновить набор правил (вход: [`encode_config`]).
pub const IOCTL_JAMM_SET_CONFIG: u32 =
    ctl_code(FILE_DEVICE_NETWORK, 0x800, METHOD_BUFFERED, FILE_WRITE_DATA);
/// Снять все правила (`SPL-40`).
pub const IOCTL_JAMM_CLEAR: u32 =
    ctl_code(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA);
/// Запросить статистику (`SPL-54`).
pub const IOCTL_JAMM_GET_STATS: u32 =
    ctl_code(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_READ_DATA);

const MAGIC: [u8; 4] = *b"JVP1";
const VERSION: u16 = 2;

/// Ошибка кодирования/декодирования контракта.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcError {
    /// Неверная сигнатура буфера.
    BadMagic,
    /// Неподдерживаемая версия формата.
    BadVersion(u16),
    /// Буфер усечён / повреждён.
    Truncated,
    /// Строка не является валидным UTF-8.
    BadString,
    /// Некорректный CIDR.
    InvalidCidr(String),
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpcError::BadMagic => write!(f, "неверная сигнатура буфера"),
            IpcError::BadVersion(v) => write!(f, "неподдерживаемая версия формата: {v}"),
            IpcError::Truncated => write!(f, "буфер усечён или повреждён"),
            IpcError::BadString => write!(f, "строка не в UTF-8"),
            IpcError::InvalidCidr(s) => write!(f, "некорректный CIDR: {s}"),
        }
    }
}

impl std::error::Error for IpcError {}

/// Запись о приложении для драйвера.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppEntry {
    /// `true` — сопоставлять по имени процесса, `false` — по полному пути.
    pub by_name: bool,
    /// Путь к `.exe` или имя процесса.
    pub value: String,
}

/// Снимок правил split для передачи в драйвер.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverConfig {
    /// Режим split.
    pub mode: SplitMode,
    /// Активен ли kill-switch.
    pub kill_switch: bool,
    /// Локальный порт прокси, куда драйвер перенаправляет выбранные сокеты.
    pub redirect_port: u16,
    /// PID процесса-прокси, принимающего перенаправленные соединения
    /// (`localRedirectTargetPID` для connect-redirect на localhost).
    pub redirect_pid: u32,
    /// Список приложений.
    pub apps: Vec<AppEntry>,
    /// Диапазоны «всегда напрямую» — LAN/системные (`SPL-23`).
    pub bypass_cidrs: Vec<IpCidr>,
    /// Пользовательские «всегда напрямую» (`SPL-25`).
    pub force_direct: Vec<IpCidr>,
    /// Пользовательские «всегда в тоннель» (`SPL-25`).
    pub force_tunnel: Vec<IpCidr>,
    /// Адреса VPN-сервера для hairpin-исключения (`SPL-27`).
    pub endpoints: Vec<IpAddr>,
}

impl DriverConfig {
    /// Строит конфиг драйвера из [`SplitConfig`], порта и PID локального прокси.
    pub fn from_split_config(
        cfg: &SplitConfig,
        redirect_port: u16,
        redirect_pid: u32,
    ) -> Result<Self, IpcError> {
        let apps = cfg
            .apps
            .iter()
            .map(|m| match m {
                AppMatcher::ExePath(p) => AppEntry {
                    by_name: false,
                    value: p.clone(),
                },
                AppMatcher::ProcessName(n) => AppEntry {
                    by_name: true,
                    value: n.clone(),
                },
            })
            .collect();
        Ok(DriverConfig {
            mode: cfg.mode,
            kill_switch: cfg.kill_switch,
            redirect_port,
            redirect_pid,
            apps,
            bypass_cidrs: parse_cidrs(ALWAYS_BYPASS_CIDRS.iter().copied())?,
            force_direct: parse_cidrs(cfg.force_direct_cidrs.iter().map(String::as_str))?,
            force_tunnel: parse_cidrs(cfg.force_tunnel_cidrs.iter().map(String::as_str))?,
            endpoints: cfg
                .server_endpoints
                .iter()
                .filter_map(|e| endpoint_ip(e))
                .collect(),
        })
    }
}

fn parse_cidrs<'a>(it: impl Iterator<Item = &'a str>) -> Result<Vec<IpCidr>, IpcError> {
    it.map(|s| IpCidr::parse(s).map_err(|_| IpcError::InvalidCidr(s.to_string())))
        .collect()
}

fn endpoint_ip(e: &str) -> Option<IpAddr> {
    if let Ok(ip) = e.parse::<IpAddr>() {
        return Some(ip);
    }
    e.rsplit_once(':')
        .and_then(|(h, _)| h.parse::<IpAddr>().ok())
}

/// Длина redirect-context в байтах: family(1) + addr(16) + port(2, big-endian).
pub const REDIRECT_CONTEXT_LEN: usize = 19;

/// Сериализует оригинальный адрес назначения в redirect-context.
///
/// При перенаправлении соединения драйвер сохраняет original-dst в этом формате
/// (WFP redirect-context), а локальный транспарент-прокси читает его через
/// `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT)`, чтобы знать, куда
/// соединение шло на самом деле. Единый источник истины для драйвера и прокси.
pub fn encode_redirect_context(dst: SocketAddr) -> [u8; REDIRECT_CONTEXT_LEN] {
    let mut b = [0u8; REDIRECT_CONTEXT_LEN];
    match dst.ip() {
        IpAddr::V4(a) => {
            b[0] = 4;
            b[1..5].copy_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            b[0] = 6;
            b[1..17].copy_from_slice(&a.octets());
        }
    }
    b[17..19].copy_from_slice(&dst.port().to_be_bytes());
    b
}

/// Разбирает redirect-context обратно в адрес назначения.
pub fn decode_redirect_context(buf: &[u8]) -> Result<SocketAddr, IpcError> {
    if buf.len() < REDIRECT_CONTEXT_LEN {
        return Err(IpcError::Truncated);
    }
    let ip = match buf[0] {
        4 => IpAddr::V4(Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4])),
        6 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&buf[1..17]);
            IpAddr::V6(Ipv6Addr::from(a))
        }
        _ => return Err(IpcError::Truncated),
    };
    let port = u16::from_be_bytes([buf[17], buf[18]]);
    Ok(SocketAddr::new(ip, port))
}

/// Сериализует конфиг в байты для `IOCTL_JAMM_SET_CONFIG`.
pub fn encode_config(cfg: &DriverConfig) -> Vec<u8> {
    let mut w = Vec::new();
    w.extend_from_slice(&MAGIC);
    push_u16(&mut w, VERSION);
    w.push(match cfg.mode {
        SplitMode::Inclusive => 0,
        SplitMode::Exclusive => 1,
    });
    w.push(u8::from(cfg.kill_switch));
    push_u16(&mut w, cfg.redirect_port);
    push_u32(&mut w, cfg.redirect_pid);
    push_u16(&mut w, cfg.apps.len() as u16);
    for a in &cfg.apps {
        w.push(u8::from(a.by_name));
        push_str(&mut w, &a.value);
    }
    push_cidrs(&mut w, &cfg.bypass_cidrs);
    push_cidrs(&mut w, &cfg.force_direct);
    push_cidrs(&mut w, &cfg.force_tunnel);
    push_u16(&mut w, cfg.endpoints.len() as u16);
    for ip in &cfg.endpoints {
        push_ip(&mut w, *ip);
    }
    w
}

/// Разбирает байты, полученные драйвером, обратно в [`DriverConfig`].
pub fn decode_config(buf: &[u8]) -> Result<DriverConfig, IpcError> {
    let mut r = Reader::new(buf);
    if r.take(4)? != MAGIC.as_slice() {
        return Err(IpcError::BadMagic);
    }
    let ver = r.u16()?;
    if ver != VERSION {
        return Err(IpcError::BadVersion(ver));
    }
    let mode = match r.u8()? {
        0 => SplitMode::Inclusive,
        1 => SplitMode::Exclusive,
        _ => return Err(IpcError::Truncated),
    };
    let kill_switch = r.u8()? != 0;
    let redirect_port = r.u16()?;
    let redirect_pid = r.u32()?;
    let n_apps = r.u16()? as usize;
    let mut apps = Vec::with_capacity(n_apps);
    for _ in 0..n_apps {
        let by_name = r.u8()? != 0;
        let value = r.string()?;
        apps.push(AppEntry { by_name, value });
    }
    let bypass_cidrs = r.cidrs()?;
    let force_direct = r.cidrs()?;
    let force_tunnel = r.cidrs()?;
    let n_ep = r.u16()? as usize;
    let mut endpoints = Vec::with_capacity(n_ep);
    for _ in 0..n_ep {
        endpoints.push(r.ip()?);
    }
    Ok(DriverConfig {
        mode,
        kill_switch,
        redirect_port,
        redirect_pid,
        apps,
        bypass_cidrs,
        force_direct,
        force_tunnel,
        endpoints,
    })
}

fn push_u16(w: &mut Vec<u8>, v: u16) {
    w.extend_from_slice(&v.to_le_bytes());
}

fn push_u32(w: &mut Vec<u8>, v: u32) {
    w.extend_from_slice(&v.to_le_bytes());
}

fn push_str(w: &mut Vec<u8>, s: &str) {
    push_u16(w, s.len() as u16);
    w.extend_from_slice(s.as_bytes());
}

fn push_ip(w: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(a) => {
            w.push(4);
            w.extend_from_slice(&a.octets());
            w.extend_from_slice(&[0u8; 12]);
        }
        IpAddr::V6(a) => {
            w.push(6);
            w.extend_from_slice(&a.octets());
        }
    }
}

fn push_cidrs(w: &mut Vec<u8>, list: &[IpCidr]) {
    push_u16(w, list.len() as u16);
    for c in list {
        push_ip(w, c.base());
        w.push(c.prefix());
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], IpcError> {
        let end = self.pos.checked_add(n).ok_or(IpcError::Truncated)?;
        if end > self.buf.len() {
            return Err(IpcError::Truncated);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, IpcError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, IpcError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, IpcError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn string(&mut self) -> Result<String, IpcError> {
        let n = self.u16()? as usize;
        let b = self.take(n)?;
        String::from_utf8(b.to_vec()).map_err(|_| IpcError::BadString)
    }

    fn ip(&mut self) -> Result<IpAddr, IpcError> {
        let fam = self.u8()?;
        let b = self.take(16)?;
        match fam {
            4 => Ok(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))),
            6 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(b);
                Ok(IpAddr::V6(Ipv6Addr::from(a)))
            }
            _ => Err(IpcError::Truncated),
        }
    }

    fn cidr(&mut self) -> Result<IpCidr, IpcError> {
        let ip = self.ip()?;
        let prefix = self.u8()?;
        IpCidr::new(ip, prefix).map_err(|_| IpcError::InvalidCidr(format!("{ip}/{prefix}")))
    }

    fn cidrs(&mut self) -> Result<Vec<IpCidr>, IpcError> {
        let n = self.u16()? as usize;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(self.cidr()?);
        }
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DriverConfig {
        DriverConfig {
            mode: SplitMode::Exclusive,
            kill_switch: true,
            redirect_port: 39001,
            redirect_pid: 4242,
            apps: vec![
                AppEntry {
                    by_name: false,
                    value: r"C:\Apps\chrome.exe".into(),
                },
                AppEntry {
                    by_name: true,
                    value: "game.exe".into(),
                },
            ],
            bypass_cidrs: vec![IpCidr::parse("192.168.0.0/16").unwrap()],
            force_direct: vec![IpCidr::parse("1.1.1.1/32").unwrap()],
            force_tunnel: vec![IpCidr::parse("203.0.113.0/24").unwrap()],
            endpoints: vec![
                "203.0.113.9".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
            ],
        }
    }

    #[test]
    fn roundtrip() {
        let cfg = sample();
        let bytes = encode_config(&cfg);
        let back = decode_config(&bytes).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn from_split_config_maps_fields() {
        let split = SplitConfig {
            mode: SplitMode::Inclusive,
            apps: vec![
                AppMatcher::ExePath(r"C:\a.exe".into()),
                AppMatcher::ProcessName("b.exe".into()),
            ],
            kill_switch: true,
            force_tunnel_cidrs: vec!["10.20.0.0/16".into()],
            server_endpoints: vec!["198.51.100.7:443".into()],
            ..Default::default()
        };
        let dc = DriverConfig::from_split_config(&split, 39001, 12345).unwrap();
        assert_eq!(dc.mode, SplitMode::Inclusive);
        assert!(dc.kill_switch);
        assert_eq!(dc.redirect_port, 39001);
        assert_eq!(dc.redirect_pid, 12345);
        assert_eq!(dc.apps.len(), 2);
        assert!(!dc.apps[0].by_name);
        assert!(dc.apps[1].by_name);
        assert!(!dc.bypass_cidrs.is_empty());
        assert_eq!(dc.force_tunnel.len(), 1);
        assert_eq!(
            dc.endpoints,
            vec!["198.51.100.7".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn rejects_bad_magic() {
        assert_eq!(decode_config(b"XXXX...."), Err(IpcError::BadMagic));
    }

    #[test]
    fn rejects_truncated() {
        let bytes = encode_config(&sample());
        assert_eq!(
            decode_config(&bytes[..bytes.len() - 3]),
            Err(IpcError::Truncated)
        );
    }

    #[test]
    fn ioctl_codes_are_distinct() {
        assert_ne!(IOCTL_JAMM_SET_CONFIG, IOCTL_JAMM_CLEAR);
        assert_ne!(IOCTL_JAMM_SET_CONFIG, IOCTL_JAMM_GET_STATS);
    }

    #[test]
    fn redirect_context_roundtrip() {
        for s in ["1.2.3.4:443", "[2001:db8::1]:8080", "0.0.0.0:0"] {
            let a: SocketAddr = s.parse().unwrap();
            let b = encode_redirect_context(a);
            assert_eq!(b.len(), REDIRECT_CONTEXT_LEN);
            assert_eq!(decode_redirect_context(&b).unwrap(), a);
        }
        // усечённый буфер — ошибка.
        assert_eq!(decode_redirect_context(&[4u8, 1, 2]), Err(IpcError::Truncated));
    }
}
