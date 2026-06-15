//! Параметры WG/AWG-узла и общий (лениво поднимаемый) дескриптор исходящего.

use super::tunnel::WgTunnel;
use crate::target::Target;
use crate::BoxedStream;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::OnceCell;

/// Параметры AmneziaWG-обфускации (см. [`super::obfs`]). `None`-значения по
/// умолчанию = выключено (на уровне 0 трансформация — тождественная).
#[derive(Debug, Clone, Default)]
pub struct AwgObfuscation {
    /// Кол-во junk-пакетов перед handshake-инициацией.
    pub jc: u32,
    /// Мин. размер junk-пакета.
    pub jmin: u32,
    /// Макс. размер junk-пакета.
    pub jmax: u32,
    /// Префикс случайных байт перед handshake-инициацией (init).
    pub s1: u32,
    /// Префикс случайных байт перед handshake-ответом (response).
    pub s2: u32,
    /// Магический заголовок, замещающий тип=1 (init).
    pub h1: u32,
    /// Магический заголовок, замещающий тип=2 (response).
    pub h2: u32,
    /// Магический заголовок, замещающий тип=3 (cookie).
    pub h3: u32,
    /// Магический заголовок, замещающий тип=4 (transport/data).
    pub h4: u32,
}

impl AwgObfuscation {
    /// `true`, если параметры эквивалентны чистому WireGuard (нет junk/префиксов,
    /// заголовки канонические 1..4) — тогда обфускация тождественна.
    pub fn is_identity(&self) -> bool {
        self.jc == 0
            && self.s1 == 0
            && self.s2 == 0
            && self.h1 == 1
            && self.h2 == 2
            && self.h3 == 3
            && self.h4 == 4
    }
}

/// Разобранные параметры WG-узла (готовы к поднятию туннеля).
#[derive(Clone)]
pub struct WgParams {
    /// UDP-эндпойнт `host:port`.
    pub endpoint: String,
    /// Статический приватный ключ клиента.
    pub private_key: [u8; 32],
    /// Публичный ключ пира (сервера).
    pub peer_public_key: [u8; 32],
    /// Опциональный preshared-ключ.
    pub preshared_key: Option<[u8; 32]>,
    /// IP-адреса интерфейса (адрес + длина префикса).
    pub address: Vec<(IpAddr, u8)>,
    /// DNS-серверы (резолв в туннеле).
    pub dns: Vec<IpAddr>,
    /// Persistent keepalive, сек.
    pub persistent_keepalive: Option<u16>,
    /// AmneziaWG-обфускация (`None` = чистый WireGuard).
    pub awg: Option<AwgObfuscation>,
}

impl std::fmt::Debug for WgParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Ключи НЕ печатаем (секреты).
        f.debug_struct("WgParams")
            .field("endpoint", &self.endpoint)
            .field("address", &self.address)
            .field("dns", &self.dns)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field("amnezia", &self.awg.is_some())
            .finish_non_exhaustive()
    }
}

/// Декодирует base64-ключ WG в 32 байта (стандартный/url-safe, паддинг опц.).
pub fn decode_key(s: &str) -> Option<[u8; 32]> {
    let v = jammvpn_core::base64::decode_loose(s).ok()?;
    (v.len() == 32).then(|| {
        let mut k = [0u8; 32];
        k.copy_from_slice(&v);
        k
    })
}

/// Разбирает CSV CIDR-адресов ("10.0.0.2/32, fd00::2/128") в `(IpAddr, префикс)`.
/// Одиночный адрес без `/` трактуется как /32 (IPv4) или /128 (IPv6).
pub fn parse_addresses(csv: &str) -> Vec<(IpAddr, u8)> {
    csv.split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }
            match part.split_once('/') {
                Some((ip, p)) => Some((ip.trim().parse().ok()?, p.trim().parse().ok()?)),
                None => {
                    let ip: IpAddr = part.parse().ok()?;
                    let full = if ip.is_ipv4() { 32 } else { 128 };
                    Some((ip, full))
                }
            }
        })
        .collect()
}

/// Разбирает CSV IP-адресов (для DNS).
pub fn parse_ip_list(csv: &str) -> Vec<IpAddr> {
    csv.split(',')
        .filter_map(|p| p.trim().parse().ok())
        .collect()
}

/// WG-исходящий: общий лениво-поднимаемый туннель.
///
/// `Clone` разделяет туннель (важно: движок клонирует [`crate::Outbound`] на
/// каждое соединение — все клоны обязаны делить ОДИН handshake/netstack, иначе
/// каждый коннект порождал бы новый handshake).
#[derive(Clone)]
pub struct WgConfig {
    inner: Arc<WgInner>,
}

struct WgInner {
    params: WgParams,
    tunnel: OnceCell<Arc<WgTunnel>>,
}

impl WgConfig {
    /// Создаёт конфиг (туннель не поднимается до первого соединения).
    pub fn new(params: WgParams) -> Self {
        Self {
            inner: Arc::new(WgInner {
                params,
                tunnel: OnceCell::new(),
            }),
        }
    }

    /// Возвращает общий туннель, лениво поднимая его при первом вызове.
    pub(crate) async fn tunnel(&self) -> io::Result<Arc<WgTunnel>> {
        let t = self
            .inner
            .tunnel
            .get_or_try_init(|| WgTunnel::start(&self.inner.params))
            .await?;
        Ok(Arc::clone(t))
    }

    /// Открывает TCP-поток до `target` через общий туннель.
    pub(crate) async fn connect_tcp(&self, target: &Target) -> io::Result<BoxedStream> {
        self.tunnel().await?.connect(target).await
    }

    /// Параметры узла (для диагностики/тестов).
    pub fn params(&self) -> &WgParams {
        &self.inner.params
    }
}

impl std::fmt::Debug for WgConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgConfig")
            .field("endpoint", &self.inner.params.endpoint)
            .field("amnezia", &self.inner.params.awg.is_some())
            .finish_non_exhaustive()
    }
}
