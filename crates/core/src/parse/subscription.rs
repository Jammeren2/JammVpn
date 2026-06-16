//! Разбор подписок (ТЗ, раздел 6, `IMP-*`).
//!
//! Подписка — это либо Base64 от списка ссылок, либо «сырой» список ссылок,
//! по одной на строку. Строки-комментарии (`#`, `//`) и пустые игнорируются.

use crate::base64;
use crate::error::ParseError;
use crate::model::ServerProfile;
use crate::parse::clash::parse_clash;
use crate::parse::link::parse_link;
use crate::parse::singbox::parse_singbox_config;
use crate::parse::xray::parse_xray_config;

/// Разбирает тело подписки в список результатов.
///
/// Поддерживает: JSON (Xray/v2rayN — в т.ч. массив конфигов, sing-box), Clash
/// YAML и списки ссылок (возможно в Base64). Возвращает `Vec<Result<...>>`,
/// чтобы показать частичный успех и ошибки отдельных элементов.
pub fn parse_subscription(body: &str) -> Vec<Result<ServerProfile, ParseError>> {
    let t = body.trim_start();
    // JSON-подписка: пробуем sing-box (поле `type`), затем Xray (`protocol`).
    if t.starts_with('{') || t.starts_with('[') {
        let sb = parse_singbox_config(body);
        if sb.iter().any(Result::is_ok) {
            return sb;
        }
        let xr = parse_xray_config(body);
        if xr.iter().any(Result::is_ok) {
            return xr;
        }
        // Ничего не разобрали — вернём ошибки Xray для диагностики.
        return xr;
    }
    // Clash / Clash.Meta YAML.
    if t.contains("proxies:") {
        return parse_clash(body);
    }
    // Список ссылок (возможно в Base64).
    decode_body(body)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"))
        .map(parse_link)
        .collect()
}

/// Если тело не похоже на ссылки — пробуем Base64-декодировать целиком.
fn decode_body(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.contains("://") {
        return trimmed.to_string();
    }
    match base64::decode_to_string(trimmed) {
        Ok(decoded) if decoded.contains("://") => decoded,
        _ => trimmed.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(res: Vec<Result<ServerProfile, ParseError>>) -> Vec<String> {
        res.into_iter()
            .filter_map(Result::ok)
            .map(|p| p.name)
            .collect()
    }

    #[test]
    fn plain_multiline() {
        let body = "vless://uuid@a.com:443#a\n# comment\n//c\ntrojan://pw@b.com:443#b\n";
        assert_eq!(names(parse_subscription(body)), vec!["a", "b"]);
    }

    #[test]
    fn base64_body() {
        let inner = "vless://uuid@a.com:443#a\ntrojan://pw@b.com:443#b";
        let body = base64::encode_standard(inner.as_bytes());
        assert_eq!(names(parse_subscription(&body)), vec!["a", "b"]);
    }

    #[test]
    fn collects_errors_too() {
        let body = "vless://uuid@a.com:443#a\nnonsense\n";
        let res = parse_subscription(body);
        assert_eq!(res.len(), 2);
        assert!(res[0].is_ok());
        assert!(res[1].is_err());
    }

    #[test]
    fn json_array_of_xray_configs() {
        // Формат Happ/v2rayN: массив полных конфигов с remarks + outbounds.
        let body = r#"[
          {"remarks":"DE","outbounds":[
            {"protocol":"freedom","tag":"direct"},
            {"protocol":"shadowsocks","tag":"n1","settings":{"servers":[{"address":"s.com","port":8388,"method":"aes-256-gcm","password":"pw"}]}}
          ]},
          {"remarks":"NL","outbounds":[
            {"protocol":"trojan","tag":"n2","settings":{"servers":[{"address":"t.com","port":443,"password":"sec"}]}}
          ]}
        ]"#;
        let n = names(parse_subscription(body));
        assert_eq!(n, vec!["DE · n1", "NL · n2"]);
    }
}
