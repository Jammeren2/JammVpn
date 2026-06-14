//! Маленький разборщик URI вида `scheme://[userinfo@]host[:port][?query][#fragment]`.
//!
//! Не пытается покрыть весь RFC 3986 — только то, что нужно для share-ссылок
//! VPN-протоколов. IPv6-хосты в квадратных скобках поддерживаются.

use crate::error::ParseError;
use crate::util::percent_decode;

/// Разобранные части URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uri {
    /// Схема в нижнем регистре (`vless`, `ss`, ...).
    pub scheme: String,
    /// Часть до `@` (как есть, без percent-декодирования).
    pub userinfo: Option<String>,
    /// Хост (для IPv6 — без скобок).
    pub host: String,
    /// Порт, если присутствует.
    pub port: Option<u16>,
    /// Пары query (ключи/значения percent-декодированы).
    pub query: Vec<(String, String)>,
    /// Фрагмент (percent-декодирован).
    pub fragment: Option<String>,
}

impl Uri {
    /// Разбирает строку URI.
    pub fn parse(input: &str) -> Result<Uri, ParseError> {
        let idx = input
            .find("://")
            .ok_or_else(|| ParseError::MalformedUrl(input.to_string()))?;
        let scheme = input[..idx].to_ascii_lowercase();
        let rest = &input[idx + 3..];

        let (before_frag, fragment) = match rest.find('#') {
            Some(i) => (&rest[..i], Some(percent_decode(&rest[i + 1..]))),
            None => (rest, None),
        };
        let (authority, query_str) = match before_frag.find('?') {
            Some(i) => (&before_frag[..i], Some(&before_frag[i + 1..])),
            None => (before_frag, None),
        };
        let (userinfo, hostport) = match authority.rfind('@') {
            Some(i) => (Some(authority[..i].to_string()), &authority[i + 1..]),
            None => (None, authority),
        };
        if hostport.is_empty() {
            return Err(ParseError::MissingHost);
        }
        let (host, port) = split_host_port(hostport)?;
        let query = query_str.map(parse_query).unwrap_or_default();

        Ok(Uri {
            scheme,
            userinfo,
            host,
            port,
            query,
            fragment,
        })
    }
}

/// Разбивает `host:port` (с поддержкой `[ipv6]:port`).
pub fn split_host_port(s: &str) -> Result<(String, Option<u16>), ParseError> {
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| ParseError::MalformedUrl(s.to_string()))?;
        let host = rest[..end].to_string();
        let port = match rest[end + 1..].strip_prefix(':') {
            Some(p) => Some(
                p.parse::<u16>()
                    .map_err(|_| ParseError::InvalidPort(p.to_string()))?,
            ),
            None => None,
        };
        Ok((host, port))
    } else if let Some(i) = s.rfind(':') {
        let host = s[..i].to_string();
        if host.is_empty() {
            return Err(ParseError::MissingHost);
        }
        let port_str = &s[i + 1..];
        let port = port_str
            .parse::<u16>()
            .map_err(|_| ParseError::InvalidPort(port_str.to_string()))?;
        Ok((host, Some(port)))
    } else {
        Ok((s.to_string(), None))
    }
}

fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.find('=') {
            Some(i) => (percent_decode(&pair[..i]), percent_decode(&pair[i + 1..])),
            None => (percent_decode(pair), String::new()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_uri() {
        let u = Uri::parse("vless://uuid@example.com:443?type=tcp&sni=ya.ru#Name").unwrap();
        assert_eq!(u.scheme, "vless");
        assert_eq!(u.userinfo.as_deref(), Some("uuid"));
        assert_eq!(u.host, "example.com");
        assert_eq!(u.port, Some(443));
        assert_eq!(u.fragment.as_deref(), Some("Name"));
        assert!(u.query.contains(&("type".to_string(), "tcp".to_string())));
    }

    #[test]
    fn parses_ipv6() {
        let (h, p) = split_host_port("[2001:db8::1]:8443").unwrap();
        assert_eq!(h, "2001:db8::1");
        assert_eq!(p, Some(8443));
    }

    #[test]
    fn rejects_bad_port() {
        assert!(matches!(
            split_host_port("host:notaport"),
            Err(ParseError::InvalidPort(_))
        ));
    }
}
