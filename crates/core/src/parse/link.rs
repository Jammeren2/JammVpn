//! Парсеры share-ссылок отдельных протоколов (ТЗ, раздел 6, `IMP-*`).

use crate::base64;
use crate::error::ParseError;
use crate::model::{ProtocolKind, ServerProfile};
use crate::parse::uri::{split_host_port, Uri};
use crate::util::percent_decode;
use std::collections::BTreeMap;

/// Разбирает одну share-ссылку в [`ServerProfile`].
///
/// Поддержано: `vless://`, `trojan://`, `ss://`, `socks5://`/`socks://`,
/// `http://`/`https://` (как прокси), `hysteria2://`/`hy2://`, `tuic://`.
pub fn parse_link(input: &str) -> Result<ServerProfile, ParseError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(ParseError::EmptyInput);
    }
    let idx = s
        .find("://")
        .ok_or_else(|| ParseError::MalformedUrl(s.to_string()))?;
    match s[..idx].to_ascii_lowercase().as_str() {
        "vless" => parse_vless(s),
        "trojan" => parse_trojan(s),
        "ss" => parse_shadowsocks(s),
        "socks" | "socks5" => proxy_profile(s, ProtocolKind::Socks5),
        "http" | "https" => proxy_profile(s, ProtocolKind::Http),
        "hysteria2" | "hy2" => parse_hysteria2(s),
        "tuic" => parse_tuic(s),
        other => Err(ParseError::UnknownScheme(other.to_string())),
    }
}

fn parse_vless(s: &str) -> Result<ServerProfile, ParseError> {
    let uri = Uri::parse(s)?;
    let uuid = uri.userinfo.ok_or(ParseError::MissingField("uuid"))?;
    let port = uri.port.ok_or(ParseError::MissingPort)?;
    let mut params = query_to_params(&uri.query);
    params.insert("uuid".to_string(), percent_decode(&uuid));
    Ok(make_profile(
        ProtocolKind::Vless,
        uri.host,
        port,
        params,
        uri.fragment,
    ))
}

fn parse_trojan(s: &str) -> Result<ServerProfile, ParseError> {
    let uri = Uri::parse(s)?;
    let password = uri.userinfo.ok_or(ParseError::MissingField("password"))?;
    let port = uri.port.ok_or(ParseError::MissingPort)?;
    let mut params = query_to_params(&uri.query);
    params.insert("password".to_string(), percent_decode(&password));
    Ok(make_profile(
        ProtocolKind::Trojan,
        uri.host,
        port,
        params,
        uri.fragment,
    ))
}

fn parse_hysteria2(s: &str) -> Result<ServerProfile, ParseError> {
    let uri = Uri::parse(s)?;
    let port = uri.port.ok_or(ParseError::MissingPort)?;
    let mut params = query_to_params(&uri.query);
    if let Some(auth) = uri.userinfo.as_deref().filter(|a| !a.is_empty()) {
        params.insert("auth".to_string(), percent_decode(auth));
    }
    Ok(make_profile(
        ProtocolKind::Hysteria2,
        uri.host,
        port,
        params,
        uri.fragment,
    ))
}

fn parse_tuic(s: &str) -> Result<ServerProfile, ParseError> {
    let uri = Uri::parse(s)?;
    let userinfo = uri.userinfo.ok_or(ParseError::MissingField("uuid"))?;
    let port = uri.port.ok_or(ParseError::MissingPort)?;
    let mut params = query_to_params(&uri.query);
    match userinfo.split_once(':') {
        Some((uuid, password)) => {
            params.insert("uuid".to_string(), percent_decode(uuid));
            params.insert("password".to_string(), percent_decode(password));
        }
        None => {
            params.insert("uuid".to_string(), percent_decode(&userinfo));
        }
    }
    Ok(make_profile(
        ProtocolKind::Tuic,
        uri.host,
        port,
        params,
        uri.fragment,
    ))
}

fn proxy_profile(s: &str, kind: ProtocolKind) -> Result<ServerProfile, ParseError> {
    let uri = Uri::parse(s)?;
    let port = uri.port.ok_or(ParseError::MissingPort)?;
    let mut params = query_to_params(&uri.query);
    if let Some(ui) = uri.userinfo.as_deref().filter(|u| !u.is_empty()) {
        match ui.split_once(':') {
            Some((user, pass)) => {
                params.insert("username".to_string(), percent_decode(user));
                params.insert("password".to_string(), percent_decode(pass));
            }
            None => {
                params.insert("username".to_string(), percent_decode(ui));
            }
        }
    }
    Ok(make_profile(kind, uri.host, port, params, uri.fragment))
}

/// Shadowsocks: SIP002 (`ss://base64(method:password)@host:port#name`)
/// и легаси (`ss://base64(method:password@host:port)#name`).
fn parse_shadowsocks(s: &str) -> Result<ServerProfile, ParseError> {
    let idx = s
        .find("://")
        .ok_or_else(|| ParseError::MalformedUrl(s.to_string()))?;
    let rest = &s[idx + 3..];
    let (before_frag, fragment) = match rest.find('#') {
        Some(i) => (&rest[..i], Some(percent_decode(&rest[i + 1..]))),
        None => (rest, None),
    };
    // Тело до query; query сохраняем (TLS-транспорт: security/sni/alpn/...).
    let (body, query) = match before_frag.find('?') {
        Some(i) => (&before_frag[..i], &before_frag[i + 1..]),
        None => (before_frag, ""),
    };

    let (method, password, host, port) = if let Some(at) = body.rfind('@') {
        let creds = decode_userinfo(&body[..at])?;
        ss_from_parts(&creds, &body[at + 1..])?
    } else {
        let decoded = base64::decode_to_string(body)?;
        let at = decoded
            .rfind('@')
            .ok_or_else(|| ParseError::MalformedUrl(decoded.clone()))?;
        ss_from_parts(&decoded[..at], &decoded[at + 1..])?
    };

    let mut params = BTreeMap::new();
    params.insert("method".to_string(), method);
    params.insert("password".to_string(), password);
    // Параметры транспорта (Xray streamSettings): security=tls, sni, alpn, fp,
    // allowInsecure/insecure. `plugin` пока игнорируем.
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, percent_decode(v)),
            None => (pair, String::new()),
        };
        match k {
            "security" | "sni" | "alpn" | "fp" | "insecure" | "allowInsecure" | "allow_insecure" => {
                params.insert(k.replace("allowInsecure", "allow_insecure"), v);
            }
            _ => {}
        }
    }
    Ok(make_profile(
        ProtocolKind::Shadowsocks,
        host,
        port,
        params,
        fragment,
    ))
}

/// Декодирует `userinfo` Shadowsocks: пробует Base64, иначе percent-decode.
fn decode_userinfo(u: &str) -> Result<String, ParseError> {
    if let Ok(decoded) = base64::decode_to_string(u) {
        if decoded.contains(':') {
            return Ok(decoded);
        }
    }
    let pd = percent_decode(u);
    if pd.contains(':') {
        return Ok(pd);
    }
    Err(ParseError::MissingField("method:password"))
}

fn ss_from_parts(creds: &str, hostport: &str) -> Result<(String, String, String, u16), ParseError> {
    let (method, password) = creds
        .split_once(':')
        .ok_or(ParseError::MissingField("method:password"))?;
    // Отбрасываем путь после host:port (`host:port/?outline=1`, `host:port/path`):
    // host:port не содержит `/` (IPv6 — в скобках `[..]`), поэтому первый сегмент
    // до `/` — это и есть адрес. Без этого Outline-ссылки падали на InvalidPort.
    let hostport = hostport.split('/').next().unwrap_or(hostport);
    let (host, port_opt) = split_host_port(hostport)?;
    let port = port_opt.ok_or(ParseError::MissingPort)?;
    Ok((method.to_string(), password.to_string(), host, port))
}

fn query_to_params(query: &[(String, String)]) -> BTreeMap<String, String> {
    query.iter().cloned().collect()
}

fn make_profile(
    protocol: ProtocolKind,
    host: String,
    port: u16,
    params: BTreeMap<String, String>,
    fragment: Option<String>,
) -> ServerProfile {
    let name = match fragment {
        Some(f) if !f.is_empty() => f,
        _ => format!("{host}:{port}"),
    };
    ServerProfile {
        name,
        protocol,
        address: host,
        port,
        params,
        tags: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vless_basic() {
        let p = parse_link(
            "vless://11111111-2222-3333-4444-555555555555@example.com:443\
?encryption=none&security=reality&pbk=KEY&sni=ya.ru&type=tcp&flow=xtls-rprx-vision#My%20Node",
        )
        .unwrap();
        assert_eq!(p.protocol, ProtocolKind::Vless);
        assert_eq!(p.address, "example.com");
        assert_eq!(p.port, 443);
        assert_eq!(
            p.param("uuid"),
            Some("11111111-2222-3333-4444-555555555555")
        );
        assert_eq!(p.param("security"), Some("reality"));
        assert_eq!(p.param("flow"), Some("xtls-rprx-vision"));
        assert_eq!(p.name, "My Node");
    }

    #[test]
    fn parse_ss_sip002() {
        let p = parse_link("ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#ss-node").unwrap();
        assert_eq!(p.protocol, ProtocolKind::Shadowsocks);
        assert_eq!(p.address, "1.2.3.4");
        assert_eq!(p.port, 8388);
        assert_eq!(p.param("method"), Some("aes-256-gcm"));
        assert_eq!(p.param("password"), Some("pass"));
        assert_eq!(p.name, "ss-node");
    }

    #[test]
    fn parse_ss_keeps_tls_transport_params() {
        // SS с TLS-транспортом (Xray streamSettings): параметры должны сохраниться.
        let p = parse_link(
            "ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388?security=tls&sni=ex.com&alpn=h2%2Chttp%2F1.1&fp=chrome#n",
        )
        .unwrap();
        assert_eq!(p.protocol, ProtocolKind::Shadowsocks);
        assert_eq!(p.port, 8388);
        assert_eq!(p.param("security"), Some("tls"));
        assert_eq!(p.param("sni"), Some("ex.com"));
        assert_eq!(p.param("alpn"), Some("h2,http/1.1"));
    }

    #[test]
    fn parse_ss_sip002_with_outline_path() {
        // Outline-форма: путь `/?outline=1` после host:port не должен ломать порт.
        let p = parse_link(
            "ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388/?outline=1#ss-node",
        )
        .unwrap();
        assert_eq!(p.address, "1.2.3.4");
        assert_eq!(p.port, 8388);
        assert_eq!(p.param("method"), Some("aes-256-gcm"));
        assert_eq!(p.name, "ss-node");
    }

    #[test]
    fn parse_ss_legacy_whole_base64() {
        // base64("aes-128-gcm:pw@9.9.9.9:443")
        let encoded = base64::encode_standard("aes-128-gcm:pw@9.9.9.9:443".as_bytes());
        let p = parse_link(&format!("ss://{encoded}#legacy")).unwrap();
        assert_eq!(p.param("method"), Some("aes-128-gcm"));
        assert_eq!(p.param("password"), Some("pw"));
        assert_eq!(p.address, "9.9.9.9");
        assert_eq!(p.port, 443);
    }

    #[test]
    fn parse_trojan_basic() {
        let p = parse_link("trojan://secret@host.example:443?sni=host.example#t1").unwrap();
        assert_eq!(p.protocol, ProtocolKind::Trojan);
        assert_eq!(p.param("password"), Some("secret"));
        assert_eq!(p.param("sni"), Some("host.example"));
        assert_eq!(p.port, 443);
    }

    #[test]
    fn parse_hysteria2_basic() {
        let p = parse_link("hysteria2://auth123@h.example:8443?sni=h.example&obfs=salamander#hy")
            .unwrap();
        assert_eq!(p.protocol, ProtocolKind::Hysteria2);
        assert_eq!(p.param("auth"), Some("auth123"));
        assert_eq!(p.param("obfs"), Some("salamander"));
        assert_eq!(p.name, "hy");
    }

    #[test]
    fn parse_tuic_basic() {
        let p = parse_link("tuic://uuid-xyz:passw@t.example:443?alpn=h3#tu").unwrap();
        assert_eq!(p.protocol, ProtocolKind::Tuic);
        assert_eq!(p.param("uuid"), Some("uuid-xyz"));
        assert_eq!(p.param("password"), Some("passw"));
    }

    #[test]
    fn parse_socks_with_auth() {
        let p = parse_link("socks5://user:pwd@127.0.0.1:1080#local").unwrap();
        assert_eq!(p.protocol, ProtocolKind::Socks5);
        assert_eq!(p.param("username"), Some("user"));
        assert_eq!(p.param("password"), Some("pwd"));
        assert_eq!(p.port, 1080);
    }

    #[test]
    fn name_falls_back_to_hostport() {
        let p = parse_link("trojan://pw@host.example:443").unwrap();
        assert_eq!(p.name, "host.example:443");
    }

    #[test]
    fn unknown_scheme_errors() {
        assert!(matches!(
            parse_link("ftp://x:1"),
            Err(ParseError::UnknownScheme(_))
        ));
    }

    #[test]
    fn empty_errors() {
        assert!(matches!(parse_link("   "), Err(ParseError::EmptyInput)));
    }
}
