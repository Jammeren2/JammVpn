//! Исходящие соединения: Direct / SOCKS5 / HTTP CONNECT / VLESS (ТЗ, раздел 4).
//!
//! Диалер устанавливает соединение до цели и возвращает [`BoxedStream`],
//! готовый к обмену. Шифрованные транспорты (TLS/REALITY) и протоколы
//! (Shadowsocks, WireGuard/AWG, …) добавляются отдельно.

use crate::reality_transport::{reality_connect, RealityTransport};
use crate::shadowsocks::{evp_bytes_to_key, Method, ShadowsocksStream, Ss2022Stream};
use crate::target::Target;
use crate::tuic::TuicConfig;
use crate::vision::VisionStream;
use crate::wireguard::WgConfig;
use crate::{trojan, vless, BoxedStream};
use jammvpn_core::base64;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

/// Настройки SOCKS5-прокси.
#[derive(Debug, Clone)]
pub struct Socks5Config {
    /// Адрес прокси `host:port`.
    pub server: String,
    /// Имя пользователя.
    pub username: Option<String>,
    /// Пароль.
    pub password: Option<String>,
}

/// Настройки HTTP(S)-прокси (метод CONNECT).
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Адрес прокси `host:port`.
    pub server: String,
    /// Имя пользователя (Basic).
    pub username: Option<String>,
    /// Пароль.
    pub password: Option<String>,
}

/// Транспорт для протоколов поверх потока (VLESS и т.п.).
#[derive(Debug, Clone, Default)]
pub enum Transport {
    /// Открытый TCP.
    #[default]
    Tcp,
    /// REALITY — TLS 1.3-обфускация поверх TCP (порт из cfal/shoes).
    Reality(RealityTransport),
    // TODO: обычный TLS (rustls + SNI/ALPN).
}

/// Настройки VLESS-исходящего.
#[derive(Debug, Clone)]
pub struct VlessConfig {
    /// Адрес сервера `host:port`.
    pub server: String,
    /// UUID (16 байт).
    pub uuid: [u8; 16],
    /// Flow (XTLS-Vision и т.п.) — пока не реализован, поле для совместимости.
    pub flow: Option<String>,
    /// Транспорт.
    pub transport: Transport,
}

/// Настройки Shadowsocks-исходящего.
#[derive(Debug, Clone)]
pub struct ShadowsocksConfig {
    /// Адрес сервера `host:port`.
    pub server: String,
    /// AEAD-метод.
    pub method: Method,
    /// Пароль (из него выводится мастер-ключ).
    pub password: String,
}

/// Настройки Trojan-исходящего.
#[derive(Debug, Clone)]
pub struct TrojanConfig {
    /// Адрес сервера `host:port`.
    pub server: String,
    /// Пароль.
    pub password: String,
    /// Транспорт.
    pub transport: Transport,
}

/// Способ исходящего соединения.
#[derive(Debug, Clone, Default)]
pub enum Outbound {
    /// Прямое соединение, без прокси.
    #[default]
    Direct,
    /// Через SOCKS5-прокси.
    Socks5(Socks5Config),
    /// Через HTTP-прокси (CONNECT).
    Http(HttpConfig),
    /// Через VLESS.
    Vless(VlessConfig),
    /// Через Shadowsocks (AEAD).
    Shadowsocks(ShadowsocksConfig),
    /// Через Trojan.
    Trojan(TrojanConfig),
    /// Через WireGuard / AmneziaWG (userspace netstack).
    Wireguard(WgConfig),
    /// Через TUIC v5 (QUIC).
    Tuic(TuicConfig),
}

impl Outbound {
    /// Устанавливает соединение до `target` согласно способу.
    pub async fn connect_tcp(&self, target: &Target) -> io::Result<BoxedStream> {
        match self {
            Outbound::Direct => direct_connect(target).await,
            Outbound::Socks5(cfg) => socks5_connect(cfg, target).await,
            Outbound::Http(cfg) => http_connect(cfg, target).await,
            Outbound::Vless(cfg) => vless_connect(cfg, target).await,
            Outbound::Shadowsocks(cfg) => shadowsocks_connect(cfg, target).await,
            Outbound::Trojan(cfg) => trojan_connect(cfg, target).await,
            Outbound::Wireguard(cfg) => crate::wireguard::wireguard_connect(cfg, target).await,
            Outbound::Tuic(cfg) => crate::tuic::tuic_connect(cfg, target).await,
        }
    }
}

fn proto_err(msg: &str) -> io::Error {
    io::Error::other(msg)
}

async fn direct_connect(target: &Target) -> io::Result<BoxedStream> {
    let stream = match target {
        Target::Socket(addr) => TcpStream::connect(addr).await?,
        Target::Domain(host, port) => TcpStream::connect((host.as_str(), *port)).await?,
    };
    Ok(Box::new(stream))
}

async fn socks5_connect(cfg: &Socks5Config, target: &Target) -> io::Result<BoxedStream> {
    let mut s = TcpStream::connect(&cfg.server).await?;

    // Приветствие: версия 5, предлагаем no-auth (и username/password при наличии).
    if cfg.username.is_some() {
        s.write_all(&[0x05, 0x01, 0x02]).await?;
    } else {
        s.write_all(&[0x05, 0x01, 0x00]).await?;
    }
    let mut method = [0u8; 2];
    s.read_exact(&mut method).await?;
    if method[0] != 0x05 {
        return Err(proto_err("socks5: неверная версия"));
    }
    match method[1] {
        0x00 => {}
        0x02 => {
            let user = cfg.username.clone().unwrap_or_default();
            let pass = cfg.password.clone().unwrap_or_default();
            let mut req = vec![0x01, user.len() as u8];
            req.extend_from_slice(user.as_bytes());
            req.push(pass.len() as u8);
            req.extend_from_slice(pass.as_bytes());
            s.write_all(&req).await?;
            let mut ar = [0u8; 2];
            s.read_exact(&mut ar).await?;
            if ar[1] != 0x00 {
                return Err(proto_err("socks5: аутентификация отклонена"));
            }
        }
        _ => return Err(proto_err("socks5: нет приемлемого метода аутентификации")),
    }

    // Запрос CONNECT.
    let mut req = vec![0x05, 0x01, 0x00];
    match target {
        Target::Domain(host, port) => {
            req.push(0x03);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
            req.extend_from_slice(&port.to_be_bytes());
        }
        Target::Socket(SocketAddr::V4(a)) => {
            req.push(0x01);
            req.extend_from_slice(&a.ip().octets());
            req.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Socket(SocketAddr::V6(a)) => {
            req.push(0x04);
            req.extend_from_slice(&a.ip().octets());
            req.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    s.write_all(&req).await?;

    // Ответ: VER REP RSV ATYP BND.ADDR BND.PORT.
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        return Err(proto_err("socks5: сервер отклонил CONNECT"));
    }
    let bnd_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize
        }
        _ => return Err(proto_err("socks5: неизвестный ATYP в ответе")),
    };
    let mut tail = vec![0u8; bnd_len + 2];
    s.read_exact(&mut tail).await?;
    Ok(Box::new(s))
}

async fn http_connect(cfg: &HttpConfig, target: &Target) -> io::Result<BoxedStream> {
    let mut s = TcpStream::connect(&cfg.server).await?;
    let hostport = match target {
        Target::Domain(h, p) => format!("{h}:{p}"),
        Target::Socket(a) => a.to_string(),
    };
    let mut req = format!("CONNECT {hostport} HTTP/1.1\r\nHost: {hostport}\r\n");
    if let Some(user) = &cfg.username {
        let pass = cfg.password.clone().unwrap_or_default();
        let token = base64::encode_standard(format!("{user}:{pass}").as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;

    let status = read_http_status(&mut s).await?;
    if !(200..300).contains(&status) {
        return Err(proto_err("http connect: ответ не 2xx"));
    }
    Ok(Box::new(s))
}

/// Читает заголовок HTTP-ответа до `\r\n\r\n` и возвращает код статуса.
async fn read_http_status(s: &mut TcpStream) -> io::Result<u16> {
    let mut buf = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        let n = s.read(&mut byte).await?;
        if n == 0 {
            return Err(proto_err(
                "http connect: соединение закрыто до конца заголовка",
            ));
        }
        buf.push(byte[0]);
        if buf.len() > 8192 {
            return Err(proto_err("http connect: слишком длинный заголовок"));
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let first = head.lines().next().unwrap_or_default();
    first
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| proto_err("http connect: не разобран статус"))
}

async fn vless_connect(cfg: &VlessConfig, target: &Target) -> io::Result<BoxedStream> {
    // XTLS-Vision: только поверх REALITY. По образцу cfal/shoes — VLESS-заголовок
    // (с flow-addon) отправляется ОБЫЧНОЙ TLS-записью, после чего TLS-поток
    // разбирается на (TCP, сессия), а Vision-padding применяется к прикладным
    // данным. VisionStream сам отбрасывает VLESS-ответ.
    if cfg.flow.as_deref() == Some(vless::FLOW_VISION) {
        let Transport::Reality(rt) = &cfg.transport else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "flow=xtls-rprx-vision поддерживается только с transport=reality",
            ));
        };
        let tcp = TcpStream::connect(&cfg.server).await?;
        let mut tls = reality_connect(tcp, rt).await?;
        let header = vless::encode_request(&cfg.uuid, cfg.flow.as_deref(), target);
        tls.write_all(&header).await?;
        tls.flush().await?;
        let (io, conn) = tls.into_inner();
        return Ok(Box::new(VisionStream::new_client(io, conn, cfg.uuid)));
    }

    let mut stream: BoxedStream = match &cfg.transport {
        Transport::Tcp => Box::new(TcpStream::connect(&cfg.server).await?),
        Transport::Reality(rt) => {
            let tcp = TcpStream::connect(&cfg.server).await?;
            Box::new(reality_connect(tcp, rt).await?)
        }
    };

    let header = vless::encode_request(&cfg.uuid, cfg.flow.as_deref(), target);
    stream.write_all(&header).await?;
    stream.flush().await?; // важно для буферизующих транспортов (REALITY)

    // VLESS-ответный заголовок отбрасывается ЛЕНИВО при первом чтении: упреждающий
    // read между записью заголовка и payload ломает порядок поверх REALITY.
    Ok(Box::new(VlessRespStrip::new(stream)))
}

/// Обёртка, отбрасывающая VLESS-ответный заголовок (версия + addon) при первом
/// чтении; записи проходят насквозь.
struct VlessRespStrip {
    inner: BoxedStream,
    hdr_buf: Vec<u8>,
    addon_len: Option<usize>,
    done: bool,
}

impl VlessRespStrip {
    fn new(inner: BoxedStream) -> Self {
        Self {
            inner,
            hdr_buf: Vec::new(),
            addon_len: None,
            done: false,
        }
    }
}

impl AsyncRead for VlessRespStrip {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        while !me.done {
            let need = match me.addon_len {
                None => 2,
                Some(a) => 2 + a,
            };
            if me.hdr_buf.len() >= need {
                if me.addon_len.is_none() {
                    me.addon_len = Some(me.hdr_buf[1] as usize);
                    continue;
                }
                me.done = true;
                break;
            }
            let mut tmp = [0u8; 64];
            let want = (need - me.hdr_buf.len()).min(tmp.len());
            let mut rb = ReadBuf::new(&mut tmp[..want]);
            match Pin::new(&mut me.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "vless: усечён ответный заголовок",
                        )));
                    }
                    me.hdr_buf.extend_from_slice(filled);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut me.inner).poll_read(cx, out)
    }
}

impl AsyncWrite for VlessRespStrip {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Адрес назначения в формате Shadowsocks: `ATYP + addr + port(2, BE)`.
/// ATYP: `1`=IPv4, `3`=домен, `4`=IPv6.
fn encode_ss_address(target: &Target) -> Vec<u8> {
    let mut b = Vec::new();
    match target {
        Target::Domain(host, port) => {
            b.push(0x03);
            b.push(host.len() as u8);
            b.extend_from_slice(host.as_bytes());
            b.extend_from_slice(&port.to_be_bytes());
        }
        Target::Socket(SocketAddr::V4(a)) => {
            b.push(0x01);
            b.extend_from_slice(&a.ip().octets());
            b.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Socket(SocketAddr::V6(a)) => {
            b.push(0x04);
            b.extend_from_slice(&a.ip().octets());
            b.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    b
}

async fn shadowsocks_connect(cfg: &ShadowsocksConfig, target: &Target) -> io::Result<BoxedStream> {
    let tcp = TcpStream::connect(&cfg.server).await?;
    if cfg.method.is_2022() {
        // SS-2022: пароль — base64-кодированный PSK длиной key_len; адрес цели —
        // в структурном заголовке (формируется в new), флашим его сразу.
        let psk = base64::decode_loose(&cfg.password)
            .map_err(|_| proto_err("ss2022: пароль не base64"))?;
        if psk.len() != cfg.method.key_len() {
            return Err(proto_err("ss2022: длина PSK не совпадает с методом"));
        }
        let mut stream = Ss2022Stream::new(tcp, cfg.method, psk, encode_ss_address(target))?;
        stream.flush().await?;
        Ok(Box::new(stream))
    } else {
        let master = evp_bytes_to_key(cfg.password.as_bytes(), cfg.method.key_len());
        let mut stream = ShadowsocksStream::new(tcp, cfg.method, master);
        stream.write_all(&encode_ss_address(target)).await?;
        Ok(Box::new(stream))
    }
}

async fn trojan_connect(cfg: &TrojanConfig, target: &Target) -> io::Result<BoxedStream> {
    let mut stream: BoxedStream = match &cfg.transport {
        Transport::Tcp => Box::new(TcpStream::connect(&cfg.server).await?),
        Transport::Reality(rt) => {
            let tcp = TcpStream::connect(&cfg.server).await?;
            Box::new(reality_connect(tcp, rt).await?)
        }
    };
    stream
        .write_all(&trojan::encode_request(&cfg.password, target))
        .await?;
    Ok(stream)
}
