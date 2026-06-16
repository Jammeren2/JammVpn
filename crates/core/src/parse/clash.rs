//! Разбор Clash / Clash.Meta YAML-конфигов (ТЗ, раздел 6, `IMP-*`).
//!
//! Берёт секцию `proxies:` (список карт) и раскладывает каждый прокси в
//! нормализованный [`ServerProfile`] с теми же ключами `params`, что и парсеры
//! ссылок / sing-box (чтобы импортированные узлы подключались движком).
//!
//! Это НЕ полноценный YAML-парсер: поддержаны плоские скаляры записей `proxies`
//! в блочной (`- name: …` + отступ) и flow-форме (`- {name: …, type: …}`),
//! строковые списки `[a, b]` (для `alpn`). Вложенные карты (`reality-opts`,
//! `ws-opts`) НЕ разбираются — для vless-REALITY используйте ссылку `vless://`
//! или sing-box JSON. Неподдерживаемые типы (`vmess`, …) дают ошибку записи.

use crate::error::ParseError;
use crate::model::{ProtocolKind, ServerProfile};
use std::collections::BTreeMap;

/// Разбирает Clash YAML в список результатов (по одному на запись `proxies`).
pub fn parse_clash(input: &str) -> Vec<Result<ServerProfile, ParseError>> {
    let lines: Vec<&str> = input.lines().collect();

    // Находим верхнеуровневую секцию `proxies:`.
    let mut start = None;
    let mut base_indent = 0;
    for (i, l) in lines.iter().enumerate() {
        if let Some(after) = l.trim_start().strip_prefix("proxies:") {
            if after.trim().is_empty() {
                start = Some(i);
                base_indent = indent(l);
                break;
            }
        }
    }
    let Some(start) = start else {
        return vec![Err(ParseError::Json("нет секции proxies".to_string()))];
    };

    // Собираем записи как плоские карты key→value.
    let mut items: Vec<Vec<(String, String)>> = Vec::new();
    let mut cur: Option<Vec<(String, String)>> = None;
    for raw in &lines[start + 1..] {
        let line = raw.trim_end();
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let ind = indent(line);
        let body = line.trim_start();
        // Строка с меньшим/равным отступом и не элемент списка → конец секции.
        if ind <= base_indent && !body.starts_with('-') {
            break;
        }
        if let Some(rest) = body.strip_prefix('-') {
            if let Some(it) = cur.take() {
                items.push(it);
            }
            let mut it = Vec::new();
            let rest = rest.trim();
            if let Some(inner) = rest.strip_prefix('{').and_then(|r| r.strip_suffix('}')) {
                parse_flow_map(inner, &mut it);
            } else if !rest.is_empty() {
                push_kv(rest, &mut it);
            }
            cur = Some(it);
        } else if let Some(it) = cur.as_mut() {
            push_kv(body, it);
        }
    }
    if let Some(it) = cur.take() {
        items.push(it);
    }

    if items.is_empty() {
        return vec![Err(ParseError::Json("секция proxies пуста".to_string()))];
    }
    items.iter().map(|kv| item_to_profile(kv)).collect()
}

/// Число ведущих пробелов.
fn indent(s: &str) -> usize {
    s.len() - s.trim_start_matches(' ').len()
}

/// Снимает парные кавычки и пробелы со скалярного значения.
fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Разбирает `key: value` и кладёт в карту. Списки `[a, b]` → `a,b`.
/// Вложенные карты (`{...}`) пропускаются.
fn push_kv(s: &str, out: &mut Vec<(String, String)>) {
    let Some((k, v)) = s.split_once(':') else {
        return;
    };
    let key = k.trim().to_string();
    if key.is_empty() {
        return;
    }
    let v = v.trim();
    let value = if let Some(inner) = v.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
        inner
            .split(',')
            .map(unquote)
            .filter(|x| !x.is_empty())
            .collect::<Vec<_>>()
            .join(",")
    } else if v.starts_with('{') {
        return; // вложенная карта не поддерживается
    } else {
        unquote(v)
    };
    out.push((key, value));
}

/// Разбирает flow-карту `k: v, k: v` (внутренность фигурных скобок). Запятые
/// внутри `[...]`/`{...}` не считаются разделителями (например `alpn: [h2, h3]`).
fn parse_flow_map(inner: &str, out: &mut Vec<(String, String)>) {
    let mut depth = 0i32;
    let mut start = 0usize;
    let mut split_at = Vec::new();
    for (i, ch) in inner.char_indices() {
        match ch {
            '[' | '{' => depth += 1,
            ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                split_at.push((start, i));
                start = i + 1;
            }
            _ => {}
        }
    }
    split_at.push((start, inner.len()));
    for (a, b) in split_at {
        push_kv(&inner[a..b], out);
    }
}

/// Запись `proxies` → [`ServerProfile`] с нормализованными ключами `params`.
fn item_to_profile(kv: &[(String, String)]) -> Result<ServerProfile, ParseError> {
    let get = |key: &str| kv.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());

    let kind = get("type").ok_or(ParseError::MissingField("type"))?;
    let protocol = map_type(kind)?;

    let address = get("server")
        .filter(|s| !s.is_empty())
        .ok_or(ParseError::MissingHost)?
        .to_string();
    let port = get("port")
        .and_then(|p| p.parse::<u16>().ok())
        .filter(|p| *p != 0)
        .ok_or(ParseError::MissingPort)?;

    let mut params = BTreeMap::new();
    let mut req = |src: &str, key: &'static str| -> Result<(), ParseError> {
        let val = get(src).filter(|s| !s.is_empty()).ok_or(ParseError::MissingField(key))?;
        params.insert(key.to_string(), val.to_string());
        Ok(())
    };
    // Необязательное поле: src (clash) → key (наш).
    macro_rules! opt {
        ($src:expr, $key:expr) => {
            if let Some(v) = get($src).filter(|s| !s.is_empty()) {
                params.insert($key.to_string(), v.to_string());
            }
        };
    }

    match protocol {
        ProtocolKind::Shadowsocks => {
            req("cipher", "method")?;
            req("password", "password")?;
        }
        ProtocolKind::Trojan => {
            req("password", "password")?;
            opt!("sni", "sni");
            opt!("alpn", "alpn");
        }
        ProtocolKind::Vless => {
            req("uuid", "uuid")?;
            opt!("flow", "flow");
            // Clash: SNI у vless — `servername`; у части конфигов — `sni`.
            opt!("servername", "sni");
            opt!("sni", "sni");
            opt!("network", "type"); // ws/grpc/tcp
            opt!("client-fingerprint", "fp");
            opt!("alpn", "alpn");
        }
        ProtocolKind::Tuic => {
            req("uuid", "uuid")?;
            req("password", "password")?;
            opt!("sni", "sni");
            opt!("alpn", "alpn");
        }
        ProtocolKind::Hysteria2 => {
            // Clash hysteria2: `password` — это auth (как userinfo в hy2://).
            req("password", "auth")?;
            opt!("sni", "sni");
            opt!("obfs", "obfs");
            opt!("obfs-password", "obfs-password");
        }
        ProtocolKind::Socks5 | ProtocolKind::Http => {
            opt!("username", "username");
            opt!("password", "password");
        }
        _ => {}
    }

    let name = get("name")
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("{address}:{port}"));

    Ok(ServerProfile {
        name,
        protocol,
        address,
        port,
        params,
        tags: Vec::new(),
    })
}

/// Clash `type` → [`ProtocolKind`]. Неподдерживаемые типы (vmess, …) отвергаются.
fn map_type(kind: &str) -> Result<ProtocolKind, ParseError> {
    match kind {
        "ss" | "shadowsocks" => Ok(ProtocolKind::Shadowsocks),
        "trojan" => Ok(ProtocolKind::Trojan),
        "vless" => Ok(ProtocolKind::Vless),
        "tuic" => Ok(ProtocolKind::Tuic),
        "hysteria2" | "hy2" => Ok(ProtocolKind::Hysteria2),
        "socks5" | "socks" => Ok(ProtocolKind::Socks5),
        "http" => Ok(ProtocolKind::Http),
        other => Err(ParseError::UnknownScheme(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
proxies:
  - name: \"🇳🇱 ss\"
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: \"pw1\"
    udp: true
  - { name: tj, type: trojan, server: t.example, port: 443, password: pw2, sni: t.example, alpn: [h2, http/1.1] }
  - name: hy
    type: hysteria2
    server: h.example
    port: 8443
    password: authpw
    sni: h.example
    obfs: salamander
  - name: bad
    type: vmess
    server: v.example
    port: 443
    uuid: x
rules:
  - MATCH,DIRECT
";

    #[test]
    fn parses_block_and_flow() {
        let res = parse_clash(SAMPLE);
        assert_eq!(res.len(), 4);

        let ss = res[0].as_ref().unwrap();
        assert_eq!(ss.protocol, ProtocolKind::Shadowsocks);
        assert_eq!(ss.name, "🇳🇱 ss");
        assert_eq!(ss.address, "ss.example.com");
        assert_eq!(ss.port, 8388);
        assert_eq!(ss.param("method"), Some("aes-256-gcm"));
        assert_eq!(ss.param("password"), Some("pw1"));

        let tj = res[1].as_ref().unwrap();
        assert_eq!(tj.protocol, ProtocolKind::Trojan);
        assert_eq!(tj.name, "tj");
        assert_eq!(tj.port, 443);
        assert_eq!(tj.param("password"), Some("pw2"));
        assert_eq!(tj.param("sni"), Some("t.example"));
        assert_eq!(tj.param("alpn"), Some("h2,http/1.1"));

        let hy = res[2].as_ref().unwrap();
        assert_eq!(hy.protocol, ProtocolKind::Hysteria2);
        assert_eq!(hy.param("auth"), Some("authpw"));
        assert_eq!(hy.param("obfs"), Some("salamander"));

        // vmess не поддержан → ошибка записи.
        assert!(matches!(res[3], Err(ParseError::UnknownScheme(ref s)) if s == "vmess"));
    }

    #[test]
    fn no_proxies_section() {
        let res = parse_clash("rules:\n  - MATCH,DIRECT\n");
        assert_eq!(res.len(), 1);
        assert!(matches!(res[0], Err(ParseError::Json(_))));
    }

    #[test]
    fn missing_required_field() {
        // ss без cipher → ошибка поля.
        let res = parse_clash("proxies:\n  - {name: a, type: ss, server: s, port: 8388, password: p}\n");
        assert!(matches!(res[0], Err(ParseError::MissingField("method"))));
    }
}
