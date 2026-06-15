//! DNS-резолвер (ТЗ, раздел 5): UDP / DoT (DNS-over-TLS) / DoH (DNS-over-HTTPS).
//!
//! Шифрованные транспорты (DoT/DoH) защищают от подмены/слежки за DNS. Свой
//! кодек ([`message`]) — без тяжёлых DNS-крейтов.

mod message;

pub use message::{TYPE_A, TYPE_AAAA};

use crate::tlsutil::verified_client_config;
use rustls::pki_types::ServerName;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;

/// Таймаут одного DNS-запроса по умолчанию.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Сервер DNS и его транспорт.
#[derive(Debug, Clone)]
pub enum DnsServer {
    /// Открытый UDP (`host:port`, обычно :53).
    Udp(SocketAddr),
    /// DNS-over-TLS (RFC 7858): `host:port` (обычно :853) + SNI.
    Dot { server: SocketAddr, sni: String },
    /// DNS-over-HTTPS (RFC 8484): URL вида `https://host/dns-query`.
    Doh(String),
}

/// Резолвер: транспорт + таймаут. `resolve` запрашивает A и AAAA конкурентно.
#[derive(Debug, Clone)]
pub struct DnsResolver {
    server: DnsServer,
    timeout: Duration,
}

impl DnsResolver {
    pub fn new(server: DnsServer) -> Self {
        Self {
            server,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Резолвит имя в IP-адреса (A + AAAA). Ошибка — если оба запроса неуспешны
    /// или записей нет.
    pub async fn resolve(&self, name: &str) -> io::Result<Vec<IpAddr>> {
        let (a, aaaa) = tokio::join!(self.query(name, TYPE_A), self.query(name, TYPE_AAAA));
        let mut ips = Vec::new();
        if let Ok(v) = a {
            ips.extend(v);
        }
        if let Ok(v) = aaaa {
            ips.extend(v);
        }
        if ips.is_empty() {
            return Err(io::Error::other(format!("dns: нет записей для {name}")));
        }
        Ok(ips)
    }

    async fn query(&self, name: &str, qtype: u16) -> io::Result<Vec<IpAddr>> {
        match &self.server {
            DnsServer::Udp(s) => udp_query(*s, name, qtype, self.timeout).await,
            DnsServer::Dot { server, sni } => {
                dot_query(*server, sni, name, qtype, self.timeout).await
            }
            DnsServer::Doh(url) => doh_query(url, name, qtype, self.timeout).await,
        }
    }
}

fn query_id() -> u16 {
    let mut b = [0u8; 2];
    let _ = getrandom::getrandom(&mut b);
    u16::from_be_bytes(b)
}

async fn with_timeout<T>(
    timeout: Duration,
    fut: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    match tokio::time::timeout(timeout, fut).await {
        Ok(r) => r,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "dns: таймаут")),
    }
}

/// DNS over UDP (RFC 1035).
pub async fn udp_query(
    server: SocketAddr,
    name: &str,
    qtype: u16,
    timeout: Duration,
) -> io::Result<Vec<IpAddr>> {
    let id = query_id();
    let query = message::encode_query(id, name, qtype)?;
    with_timeout(timeout, async move {
        let bind: SocketAddr = if server.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let sock = UdpSocket::bind(bind).await?;
        sock.connect(server).await?;
        sock.send(&query).await?;
        let mut buf = [0u8; 1500];
        let n = sock.recv(&mut buf).await?;
        message::decode_response(&buf[..n], Some(id))
    })
    .await
}

/// DNS over TLS (RFC 7858): 2-байтная длина + DNS-сообщение поверх TLS.
pub async fn dot_query(
    server: SocketAddr,
    sni: &str,
    name: &str,
    qtype: u16,
    timeout: Duration,
) -> io::Result<Vec<IpAddr>> {
    let id = query_id();
    let query = message::encode_query(id, name, qtype)?;
    let sni = sni.to_string();
    with_timeout(timeout, async move {
        let tcp = TcpStream::connect(server).await?;
        let connector = TlsConnector::from(verified_client_config());
        let server_name =
            ServerName::try_from(sni).map_err(|_| io::Error::other("dns: некорректный SNI"))?;
        let mut tls = connector.connect(server_name, tcp).await?;

        let mut framed = Vec::with_capacity(query.len() + 2);
        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
        framed.extend_from_slice(&query);
        tls.write_all(&framed).await?;
        tls.flush().await?;

        let mut lenb = [0u8; 2];
        tls.read_exact(&mut lenb).await?;
        let rlen = u16::from_be_bytes(lenb) as usize;
        let mut resp = vec![0u8; rlen];
        tls.read_exact(&mut resp).await?;
        message::decode_response(&resp, Some(id))
    })
    .await
}

/// DNS over HTTPS (RFC 8484): `POST` с телом `application/dns-message`.
pub async fn doh_query(
    url: &str,
    name: &str,
    qtype: u16,
    timeout: Duration,
) -> io::Result<Vec<IpAddr>> {
    let id = query_id();
    let query = message::encode_query(id, name, qtype)?;
    let (host, port, path) = parse_https_url(url)?;
    with_timeout(timeout, async move {
        let tcp = TcpStream::connect((host.as_str(), port)).await?;
        let connector = TlsConnector::from(verified_client_config());
        let server_name = ServerName::try_from(host.clone())
            .map_err(|_| io::Error::other("dns: некорректный SNI"))?;
        let mut tls = connector.connect(server_name, tcp).await?;

        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/dns-message\r\n\
             Content-Type: application/dns-message\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n",
            query.len()
        );
        tls.write_all(req.as_bytes()).await?;
        tls.write_all(&query).await?;
        tls.flush().await?;

        let mut raw = Vec::new();
        tls.read_to_end(&mut raw).await?;
        let body = http_body(&raw)?;
        message::decode_response(body, Some(id))
    })
    .await
}

/// Выделяет тело HTTP-ответа (после `\r\n\r\n`), проверив статус 2xx.
fn http_body(raw: &[u8]) -> io::Result<&[u8]> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::other("doh: нет заголовков"))?;
    let status = String::from_utf8_lossy(&raw[..raw.iter().position(|&b| b == b'\r').unwrap_or(0)]);
    let ok = status
        .split_whitespace()
        .nth(1)
        .is_some_and(|c| c.starts_with('2'));
    if !ok {
        return Err(io::Error::other(format!("doh: статус не 2xx: {status}")));
    }
    Ok(&raw[sep + 4..])
}

fn parse_https_url(url: &str) -> io::Result<(String, u16, String)> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| io::Error::other("doh: только https://"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/dns-query"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse().map_err(|_| io::Error::other("doh: порт"))?,
        ),
        None => (authority.to_string(), 443u16),
    };
    Ok((host, port, path.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Mock-UDP-DNS: отвечает фиксированной A-записью на любой запрос (эхо ID).
    async fn mock_udp_dns(answer_ip: Ipv4Addr) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            // Циклически отвечаем (resolve шлёт A и AAAA — два запроса).
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                let id = [buf[0], buf[1]];
                let mut resp = Vec::new();
                resp.extend_from_slice(&id);
                resp.extend_from_slice(&0x8180u16.to_be_bytes());
                resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
                resp.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
                resp.extend_from_slice(&[0, 0, 0, 0]);
                // копируем вопрос (с 12 до конца запроса).
                resp.extend_from_slice(&buf[12..n]);
                // answer: указатель 0xC00C, A, IN, TTL, RDLEN=4, IP.
                resp.extend_from_slice(&[0xC0, 0x0C]);
                resp.extend_from_slice(&TYPE_A.to_be_bytes());
                resp.extend_from_slice(&1u16.to_be_bytes());
                resp.extend_from_slice(&60u32.to_be_bytes());
                resp.extend_from_slice(&4u16.to_be_bytes());
                resp.extend_from_slice(&answer_ip.octets());
                let _ = sock.send_to(&resp, peer).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn udp_resolve_ok() {
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        let server = mock_udp_dns(ip).await;
        let resolver = DnsResolver::new(DnsServer::Udp(server));
        // только A (AAAA-запрос уйдёт тому же mock-серверу, который ответит A —
        // decode вернёт IP; берём через udp_query напрямую для чистоты).
        let ips = udp_query(server, "example.com", TYPE_A, DEFAULT_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(ips, vec![IpAddr::V4(ip)]);
        // resolver.resolve тоже находит адрес.
        let r = resolver.resolve("example.com").await.unwrap();
        assert!(r.contains(&IpAddr::V4(ip)));
    }

    #[tokio::test]
    async fn udp_timeout_on_silent_server() {
        // Сервер, который не отвечает.
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let res = udp_query(addr, "x.com", TYPE_A, Duration::from_millis(200)).await;
        assert!(res.is_err());
    }

    #[test]
    fn parse_doh_url() {
        assert_eq!(
            parse_https_url("https://dns.google/dns-query").unwrap(),
            ("dns.google".into(), 443, "/dns-query".into())
        );
        assert_eq!(
            parse_https_url("https://1.1.1.1:443/dns-query").unwrap(),
            ("1.1.1.1".into(), 443, "/dns-query".into())
        );
        assert!(parse_https_url("http://x/").is_err());
    }
}
