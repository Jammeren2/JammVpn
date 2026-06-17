//! Загрузка и автообновление подписок (SRV, раздел импорта).
//!
//! Тянет тело подписки по HTTP/HTTPS (https — с проверкой сертификата по корням
//! Mozilla через `webpki-roots`), парсит его [`jammvpn_core::parse_subscription`]
//! и вливает серверы в конфиг (по тегу подписки).

use crate::tlsutil::verified_client_config;
use jammvpn_core::{parse_subscription, AppConfig, ServerProfile, Subscription};
use rustls::pki_types::ServerName;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Таймаут загрузки подписки по умолчанию.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);

/// Загружает тело по HTTP(S) GET. `https` — с проверкой сертификата сервера.
pub async fn fetch_text(url: &str, timeout: Duration) -> io::Result<String> {
    match tokio::time::timeout(timeout, fetch_inner(url)).await {
        Ok(r) => r,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "подписка: таймаут")),
    }
}

/// Обновляет одну подписку: загружает, парсит, помечает серверы тегом подписки.
pub async fn update_subscription(
    sub: &Subscription,
    timeout: Duration,
) -> io::Result<Vec<ServerProfile>> {
    let body = fetch_text(&sub.url, timeout).await?;
    let tag = sub_tag(sub);
    let mut profiles: Vec<ServerProfile> = parse_subscription(&body)
        .into_iter()
        .filter_map(Result::ok)
        .collect();
    // Тегируем узлы источником-подпиской (для группировки в UI и обновления).
    for p in &mut profiles {
        if !p.tags.iter().any(|t| t == &tag) {
            p.tags.push(tag.clone());
        }
    }
    Ok(profiles)
}

/// Тег подписки для группировки/обновления: явный `sub.tag` или хост из URL.
pub fn sub_tag(sub: &Subscription) -> String {
    if let Some(t) = &sub.tag {
        if !t.trim().is_empty() {
            return t.clone();
        }
    }
    let rest = sub.url.split("://").nth(1).unwrap_or(&sub.url);
    rest.split('/').next().unwrap_or(&sub.url).to_string()
}

/// Вливает обновлённые серверы подписки в конфиг: удаляет прежние серверы этой
/// подписки (по её теге) и добавляет новые.
pub fn merge_subscription(
    cfg: &mut AppConfig,
    sub: &Subscription,
    new_servers: Vec<ServerProfile>,
) {
    let tag = sub_tag(sub);
    let incoming: std::collections::HashSet<&str> =
        new_servers.iter().map(|s| s.name.as_str()).collect();
    // Удаляем прежние узлы этой подписки: по тегу ИЛИ по совпадению имени
    // (дедуп — на случай легаси-узлов без тега).
    cfg.servers
        .retain(|s| !s.tags.iter().any(|t| t == &tag) && !incoming.contains(s.name.as_str()));
    cfg.servers.extend(new_servers);
}

// --- HTTP(S) ---

enum Scheme {
    Http,
    Https,
}

async fn fetch_inner(url: &str) -> io::Result<String> {
    let (scheme, host, port, path) = parse_url(url)?;
    let tcp = TcpStream::connect((host.as_str(), port)).await?;
    match scheme {
        Scheme::Http => http_exchange(tcp, &host, &path).await,
        Scheme::Https => {
            let connector = TlsConnector::from(verified_client_config());
            let name = ServerName::try_from(host.clone())
                .map_err(|_| io::Error::other("подписка: некорректный SNI"))?;
            let tls = connector.connect(name, tcp).await?;
            http_exchange(tls, &host, &path).await
        }
    }
}

/// Скачивает бинарный ресурс, следуя редиректам (для geo-баз с GitHub-релизов).
pub async fn fetch_bytes(url: &str, timeout: Duration) -> io::Result<Vec<u8>> {
    let mut current = url.to_string();
    for _ in 0..6 {
        let resp = tokio::time::timeout(timeout, fetch_raw(&current))
            .await
            .map_err(|_| io::Error::other("таймаут загрузки"))??;
        match resp.status {
            200 => return Ok(resp.body),
            301 | 302 | 303 | 307 | 308 => {
                let loc = resp
                    .location
                    .ok_or_else(|| io::Error::other("редирект без Location"))?;
                current = if loc.starts_with("http") {
                    loc
                } else {
                    // относительный Location — приклеиваем к схеме+хосту.
                    let (sch, host, _port, _) = parse_url(&current)?;
                    let pfx = match sch {
                        Scheme::Https => "https://",
                        Scheme::Http => "http://",
                    };
                    format!("{pfx}{host}{loc}")
                };
            }
            s => return Err(io::Error::other(format!("HTTP статус {s}"))),
        }
    }
    Err(io::Error::other("слишком много редиректов"))
}

/// Сырой ответ: статус, Location (для редиректа), тело (бинарь).
struct RawResp {
    status: u16,
    location: Option<String>,
    body: Vec<u8>,
}

async fn fetch_raw(url: &str) -> io::Result<RawResp> {
    let (scheme, host, port, path) = parse_url(url)?;
    let tcp = TcpStream::connect((host.as_str(), port)).await?;
    match scheme {
        Scheme::Http => exchange_raw(tcp, &host, &path).await,
        Scheme::Https => {
            let connector = TlsConnector::from(verified_client_config());
            let name = ServerName::try_from(host.clone())
                .map_err(|_| io::Error::other("некорректный SNI"))?;
            let tls = connector.connect(name, tcp).await?;
            exchange_raw(tls, &host, &path).await
        }
    }
}

async fn exchange_raw<S>(mut stream: S, host: &str, path: &str) -> io::Result<RawResp>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: jammvpn\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::other("нет заголовков HTTP"))?;
    let head = String::from_utf8_lossy(&raw[..sep]);
    let body = &raw[sep + 4..];
    let mut lines = head.lines();
    let status = lines
        .next()
        .unwrap_or("")
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    let mut location = None;
    let mut chunked = false;
    for l in lines {
        let ll = l.to_ascii_lowercase();
        if let Some(v) = ll.strip_prefix("location:") {
            // берём из оригинальной строки (без lowercase) значение.
            location = Some(l[l.find(':').unwrap() + 1..].trim().to_string());
            let _ = v;
        }
        if ll.starts_with("transfer-encoding:") && ll.contains("chunked") {
            chunked = true;
        }
    }
    let body = if chunked { dechunk(body)? } else { body.to_vec() };
    Ok(RawResp {
        status,
        location,
        body,
    })
}

/// Один HTTP/1.1 обмен (GET с `Connection: close`), возвращает тело.
async fn http_exchange<S>(mut stream: S, host: &str, path: &str) -> io::Result<String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: jammvpn\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    parse_http_response(&raw)
}

/// Разбирает сырой HTTP-ответ: проверяет статус 2xx, выделяет тело
/// (де-чанкинг при `Transfer-Encoding: chunked`).
fn parse_http_response(raw: &[u8]) -> io::Result<String> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::other("подписка: нет заголовков HTTP"))?;
    let head = String::from_utf8_lossy(&raw[..sep]);
    let body = &raw[sep + 4..];

    let mut lines = head.lines();
    let status = lines.next().unwrap_or("");
    let ok = status
        .split_whitespace()
        .nth(1)
        .is_some_and(|c| c.starts_with('2'));
    if !ok {
        return Err(io::Error::other(format!(
            "подписка: статус не 2xx: {status}"
        )));
    }

    let chunked = lines.any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });

    let body = if chunked {
        dechunk(body)?
    } else {
        body.to_vec()
    };
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Де-чанкинг тела `Transfer-Encoding: chunked`.
fn dechunk(mut data: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let nl = data
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| io::Error::other("подписка: битый chunk"))?;
        let size_line = std::str::from_utf8(&data[..nl]).unwrap_or("");
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| io::Error::other("подписка: битый размер chunk"))?;
        data = &data[nl + 2..];
        if size == 0 {
            break;
        }
        if data.len() < size {
            return Err(io::Error::other("подписка: chunk обрезан"));
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size..];
        // пропустить завершающий CRLF чанка.
        if data.starts_with(b"\r\n") {
            data = &data[2..];
        }
    }
    Ok(out)
}

/// Разбирает `http(s)://host[:port][/path]`.
fn parse_url(url: &str) -> io::Result<(Scheme, String, u16, String)> {
    let (scheme, rest, default_port) = if let Some(r) = url.strip_prefix("https://") {
        (Scheme::Https, r, 443u16)
    } else if let Some(r) = url.strip_prefix("http://") {
        (Scheme::Http, r, 80u16)
    } else {
        return Err(io::Error::other("подписка: только http:// и https://"));
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(io::Error::other("подписка: пустой host"));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse()
                .map_err(|_| io::Error::other("подписка: некорректный порт"))?,
        ),
        None => (authority.to_string(), default_port),
    };
    Ok((scheme, host, port, path.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// Mock-HTTP-сервер: отдаёт `body` со статусом 200 и закрывает соединение.
    async fn mock_body(body: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        port
    }

    #[test]
    fn parse_url_schemes() {
        let (_, h, p, path) = parse_url("https://sub.example.com/list").unwrap();
        assert_eq!(
            (h.as_str(), p, path.as_str()),
            ("sub.example.com", 443, "/list")
        );
        let (_, h, p, _) = parse_url("http://1.2.3.4:8080/x").unwrap();
        assert_eq!((h.as_str(), p), ("1.2.3.4", 8080));
        assert!(parse_url("ftp://x/").is_err());
    }

    #[test]
    fn dechunk_basic() {
        // "Wiki" + "pedia" чанками.
        let chunked = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(dechunk(chunked).unwrap(), b"Wikipedia");
    }

    #[test]
    fn parse_response_rejects_non_2xx() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        assert!(parse_http_response(raw).is_err());
    }

    #[tokio::test]
    async fn fetch_http_body() {
        let port = mock_body("hello-subscription-body").await;
        let url = format!("http://127.0.0.1:{port}/sub");
        let body = fetch_text(&url, DEFAULT_TIMEOUT).await.unwrap();
        assert_eq!(body, "hello-subscription-body");
    }

    #[tokio::test]
    async fn update_subscription_parses_and_tags() {
        // base64 двух vless-ссылок (как реальная подписка).
        let links = "vless://11111111-2222-3333-4444-555555555555@a.com:443#A\n\
                     trojan://pw@b.com:443#B";
        let b64 = jammvpn_core::base64::encode_standard(links.as_bytes());
        let body: &'static str = Box::leak(b64.into_boxed_str());
        let port = mock_body(body).await;

        let sub = Subscription {
            url: format!("http://127.0.0.1:{port}/sub"),
            tag: Some("grp".to_string()),
            update_interval_hours: 12,
        };
        let profiles = update_subscription(&sub, DEFAULT_TIMEOUT).await.unwrap();
        assert_eq!(profiles.len(), 2);
        assert!(profiles.iter().all(|p| p.tags.iter().any(|t| t == "grp")));

        // merge: старые серверы тега заменяются.
        let mut cfg = AppConfig::default();
        cfg.servers.push(ServerProfile {
            name: "old".into(),
            protocol: jammvpn_core::ProtocolKind::Vless,
            address: "old.com".into(),
            port: 1,
            params: Default::default(),
            tags: vec!["grp".to_string()],
        });
        merge_subscription(&mut cfg, &sub, profiles);
        assert_eq!(
            cfg.servers.len(),
            2,
            "старый сервер тега удалён, добавлены 2 новых"
        );
        assert!(cfg.servers.iter().all(|s| s.name != "old"));
    }
}
