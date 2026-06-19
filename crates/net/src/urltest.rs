//! Тестирование исходящих (SRV): задержка через измерение connect/HTTP-запроса.
//!
//! `tcp_ping` — время установления соединения; `url_test` — соединение + HTTP
//! GET к тест-URL (обычно отдающему `204 No Content`); достижимость = любой
//! валидный HTTP-ответ;
//! `test_outbounds` — конкурентный тест группы именованных исходящих. Позволяет
//! UI/движку ранжировать узлы и выбирать быстрейший.

use crate::outbound::Outbound;
use crate::target::Target;
use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Тест-URL по умолчанию (отдаёт `204 No Content`; широко используется).
pub const DEFAULT_TEST_URL: &str = "http://cp.cloudflare.com/generate_204";

/// Таймаут одного теста по умолчанию.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Измеряет время установления TCP-соединения до `target` через `outbound`.
pub async fn tcp_ping(
    outbound: &Outbound,
    target: &Target,
    timeout: Duration,
) -> io::Result<Duration> {
    let start = Instant::now();
    match tokio::time::timeout(timeout, outbound.connect_tcp(target)).await {
        Ok(Ok(_stream)) => Ok(start.elapsed()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "ping: таймаут")),
    }
}

/// Тест задержки: соединение через `outbound` + HTTP GET к `url`. Достижимость =
/// получен любой валидный HTTP-ответ (не обязательно 2xx — тест-эндпойнт может
/// отдать 403/5xx через рабочий туннель). Возвращает RTT до статусной строки.
///
/// Поддерживается `http://` (тест-эндпойнты `generate_204` доступны по http).
pub async fn url_test(outbound: &Outbound, url: &str, timeout: Duration) -> io::Result<Duration> {
    let (host, port, path) = parse_http_url(url)?;
    let target = Target::Domain(host.clone(), port);
    let start = Instant::now();

    let work = async {
        let mut stream = outbound.connect_tcp(&target).await?;
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: jammvpn\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await?;

        let mut buf = [0u8; 128];
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "url-test: пустой ответ",
            ));
        }
        let status_line = std::str::from_utf8(&buf[..n])
            .unwrap_or("")
            .lines()
            .next()
            .unwrap_or("");
        // Любой валидный HTTP-ответ ("HTTP/1.x <3 цифры> ...") = узел достижим:
        // меряем RTT до первого байта. Не требуем строго 2xx — рабочий туннель
        // может получить 403/3xx/5xx от тест-эндпойнта (напр. Cloudflare режет
        // egress-IP сервера), но сам узел при этом жив и быстр. Недостижимость
        // ловится раньше (ошибка connect_tcp / пустой ответ / таймаут).
        let reachable = status_line.starts_with("HTTP/")
            && status_line
                .split_whitespace()
                .nth(1)
                .is_some_and(|c| c.len() == 3 && c.bytes().all(|b| b.is_ascii_digit()));
        if !reachable {
            return Err(io::Error::other(format!(
                "url-test: не похоже на HTTP-ответ: {status_line}"
            )));
        }
        io::Result::Ok(())
    };

    match tokio::time::timeout(timeout, work).await {
        Ok(Ok(())) => Ok(start.elapsed()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "url-test: таймаут")),
    }
}

/// Конкурентно тестирует группу именованных исходящих. Результаты — в порядке
/// завершения (не входном); вызывающий обычно сортирует по задержке.
pub async fn test_outbounds(
    outbounds: &HashMap<String, Outbound>,
    url: &str,
    timeout: Duration,
) -> Vec<(String, io::Result<Duration>)> {
    let mut set = tokio::task::JoinSet::new();
    for (name, ob) in outbounds {
        let name = name.clone();
        let ob = ob.clone(); // дешёво: Arc-backed транспорты разделяют соединение
        let url = url.to_string();
        set.spawn(async move { (name, url_test(&ob, &url, timeout).await) });
    }
    let mut results = Vec::with_capacity(outbounds.len());
    while let Some(joined) = set.join_next().await {
        if let Ok(pair) = joined {
            results.push(pair);
        }
    }
    results
}

/// Разбирает `http://host[:port][/path]` в `(host, port, path)`.
fn parse_http_url(url: &str) -> io::Result<(String, u16, String)> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| io::Error::other("url-test: поддерживается только http://"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(io::Error::other("url-test: пустой host"));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse()
                .map_err(|_| io::Error::other("url-test: некорректный порт"))?,
        ),
        None => (authority.to_string(), 80u16),
    };
    Ok((host, port, path.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// Локальный mock-HTTP: отвечает заданной статусной строкой на любой запрос.
    async fn mock_http(status: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    let resp =
                        format!("{status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        port
    }

    #[test]
    fn parse_url_variants() {
        assert_eq!(
            parse_http_url("http://cp.cloudflare.com/generate_204").unwrap(),
            ("cp.cloudflare.com".into(), 80, "/generate_204".into())
        );
        assert_eq!(
            parse_http_url("http://1.2.3.4:8080/x").unwrap(),
            ("1.2.3.4".into(), 8080, "/x".into())
        );
        assert_eq!(
            parse_http_url("http://host").unwrap(),
            ("host".into(), 80, "/".into())
        );
        assert!(parse_http_url("https://x/").is_err());
    }

    #[tokio::test]
    async fn url_test_ok_on_204() {
        let port = mock_http("HTTP/1.1 204 No Content").await;
        let url = format!("http://127.0.0.1:{port}/generate_204");
        let rtt = url_test(&Outbound::Direct, &url, DEFAULT_TIMEOUT)
            .await
            .expect("url_test");
        assert!(rtt < DEFAULT_TIMEOUT);
    }

    #[tokio::test]
    async fn url_test_ok_on_403_and_5xx() {
        // Любой валидный HTTP-ответ = узел достижим (туннель долетел до сервера).
        for status in ["HTTP/1.1 403 Forbidden", "HTTP/1.1 500 Internal Server Error"] {
            let port = mock_http(status).await;
            let url = format!("http://127.0.0.1:{port}/x");
            assert!(
                url_test(&Outbound::Direct, &url, DEFAULT_TIMEOUT)
                    .await
                    .is_ok(),
                "ожидалась достижимость для {status}"
            );
        }
    }

    #[tokio::test]
    async fn url_test_errors_on_non_http() {
        // Не-HTTP мусор в ответе = не считаем узел достижимым.
        let port = mock_http("GARBAGE not-http response").await;
        let url = format!("http://127.0.0.1:{port}/x");
        assert!(url_test(&Outbound::Direct, &url, DEFAULT_TIMEOUT)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn tcp_ping_ok() {
        let port = mock_http("HTTP/1.1 204 No Content").await;
        let target = Target::Socket(format!("127.0.0.1:{port}").parse().unwrap());
        assert!(tcp_ping(&Outbound::Direct, &target, DEFAULT_TIMEOUT)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn ping_times_out_on_unroutable() {
        // 10.255.255.1 — не маршрутизируемый в тесте → таймаут.
        let target = Target::Socket("10.255.255.1:9".parse().unwrap());
        let res = tcp_ping(&Outbound::Direct, &target, Duration::from_millis(300)).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_outbounds_ranks_group() {
        let port = mock_http("HTTP/1.1 204 No Content").await;
        let url = format!("http://127.0.0.1:{port}/generate_204");
        let mut group = HashMap::new();
        group.insert("a".to_string(), Outbound::Direct);
        group.insert("b".to_string(), Outbound::Direct);
        let results = test_outbounds(&group, &url, DEFAULT_TIMEOUT).await;
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|(_, r)| r.is_ok()));
    }
}
