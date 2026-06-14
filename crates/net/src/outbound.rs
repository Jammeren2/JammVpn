//! Исходящие соединения: Direct / SOCKS5 / HTTP CONNECT (ТЗ, раздел 4, `PRO-*`).
//!
//! Диалер устанавливает TCP-соединение до цели через выбранный протокол и
//! возвращает готовый к обмену [`TcpStream`]. Шифрованные протоколы
//! (Shadowsocks, WireGuard/AWG, VLESS/REALITY и т.п.) добавляются отдельно.

use crate::target::Target;
use jammvpn_core::base64;
use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Настройки SOCKS5-прокси.
#[derive(Debug, Clone)]
pub struct Socks5Config {
    /// Адрес прокси `host:port`.
    pub server: String,
    /// Имя пользователя (для username/password-аутентификации).
    pub username: Option<String>,
    /// Пароль.
    pub password: Option<String>,
}

/// Настройки HTTP(S)-прокси (метод CONNECT).
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Адрес прокси `host:port`.
    pub server: String,
    /// Имя пользователя (Basic-аутентификация).
    pub username: Option<String>,
    /// Пароль.
    pub password: Option<String>,
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
}

impl Outbound {
    /// Устанавливает TCP-соединение до `target` согласно способу.
    pub async fn connect_tcp(&self, target: &Target) -> io::Result<TcpStream> {
        match self {
            Outbound::Direct => direct_connect(target).await,
            Outbound::Socks5(cfg) => socks5_connect(cfg, target).await,
            Outbound::Http(cfg) => http_connect(cfg, target).await,
        }
    }
}

fn proto_err(msg: &str) -> io::Error {
    io::Error::other(msg)
}

async fn direct_connect(target: &Target) -> io::Result<TcpStream> {
    match target {
        Target::Socket(addr) => TcpStream::connect(addr).await,
        Target::Domain(host, port) => TcpStream::connect((host.as_str(), *port)).await,
    }
}

async fn socks5_connect(cfg: &Socks5Config, target: &Target) -> io::Result<TcpStream> {
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
    Ok(s)
}

async fn http_connect(cfg: &HttpConfig, target: &Target) -> io::Result<TcpStream> {
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
    Ok(s)
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
    // Формат: "HTTP/1.1 200 Connection established".
    first
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| proto_err("http connect: не разобран статус"))
}
