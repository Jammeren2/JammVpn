//! Разбор JSON-конфигов sing-box (ТЗ, раздел 6, `IMP-*`).
//!
//! Берёт массив исходящих по ключу `"outbounds"`, либо верхний уровень-массив,
//! либо одиночный outbound-объект (с полем `"type"`). Для каждого outbound
//! возвращается отдельный [`Result`], чтобы вызывающий код мог показать
//! частичный успех и ошибки конкретных записей. Протоколо-специфичные поля
//! раскладываются в плоскую нормализованную карту [`ServerProfile::params`].

use crate::error::ParseError;
use crate::json::JsonValue;
use crate::model::{ProtocolKind, ServerProfile};
use std::collections::BTreeMap;

/// Разбирает JSON-конфиг sing-box в список результатов (по одному на outbound).
pub fn parse_singbox_config(input: &str) -> Vec<Result<ServerProfile, ParseError>> {
    let root = match JsonValue::parse(input) {
        Ok(v) => v,
        Err(e) => return vec![Err(e)],
    };

    let outbounds = match &root {
        JsonValue::Object(_) => match root.get("outbounds").and_then(JsonValue::as_array) {
            Some(arr) => arr,
            // Одиночный outbound-объект распознаём по наличию "type".
            None if root.get("type").is_some() => std::slice::from_ref(&root),
            None => return vec![Err(ParseError::Json("нет ключа outbounds".to_string()))],
        },
        JsonValue::Array(arr) => arr,
        _ => {
            return vec![Err(ParseError::Json(
                "ожидался объект или массив".to_string(),
            ))]
        }
    };

    outbounds.iter().map(parse_outbound).collect()
}

/// Разбирает один outbound-объект.
fn parse_outbound(ob: &JsonValue) -> Result<ServerProfile, ParseError> {
    let kind = ob
        .get("type")
        .and_then(JsonValue::as_str)
        .ok_or(ParseError::MissingField("type"))?;

    let protocol = map_type(kind)?;

    let address = ob
        .get("server")
        .and_then(JsonValue::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(ParseError::MissingHost)?
        .to_string();
    let port = ob
        .get("server_port")
        .and_then(JsonValue::as_u16_port)
        .ok_or(ParseError::MissingPort)?;

    let mut params = BTreeMap::new();

    match protocol {
        ProtocolKind::Vless => {
            insert_field(&mut params, ob, "uuid", "uuid")?;
            insert_opt(&mut params, ob, "flow", "flow");
        }
        ProtocolKind::Tuic => {
            insert_field(&mut params, ob, "uuid", "uuid")?;
            insert_field(&mut params, ob, "password", "password")?;
        }
        ProtocolKind::Shadowsocks => {
            insert_field(&mut params, ob, "method", "method")?;
            insert_field(&mut params, ob, "password", "password")?;
        }
        ProtocolKind::Trojan | ProtocolKind::Hysteria2 => {
            insert_field(&mut params, ob, "password", "password")?;
        }
        _ => {}
    }

    parse_tls(&mut params, ob);
    parse_transport(&mut params, ob);

    let name = ob
        .get("tag")
        .and_then(JsonValue::as_str)
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

/// Маппинг `type` -> [`ProtocolKind`]. Служебные исходящие отвергаются.
fn map_type(kind: &str) -> Result<ProtocolKind, ParseError> {
    match kind {
        "vless" => Ok(ProtocolKind::Vless),
        "shadowsocks" => Ok(ProtocolKind::Shadowsocks),
        "trojan" => Ok(ProtocolKind::Trojan),
        "wireguard" => Ok(ProtocolKind::Wireguard),
        "socks" => Ok(ProtocolKind::Socks5),
        "http" => Ok(ProtocolKind::Http),
        "hysteria2" => Ok(ProtocolKind::Hysteria2),
        "tuic" => Ok(ProtocolKind::Tuic),
        other => Err(ParseError::UnknownScheme(other.to_string())),
    }
}

/// Раскладывает объект `tls` в нормализованные параметры.
fn parse_tls(params: &mut BTreeMap<String, String>, ob: &JsonValue) {
    let Some(tls) = ob.get("tls") else {
        return;
    };

    if let Some(sni) = tls.get("server_name").and_then(JsonValue::as_str) {
        params.insert("sni".to_string(), sni.to_string());
    }
    if let Some(reality) = tls.get("reality") {
        if let Some(pbk) = reality.get("public_key").and_then(JsonValue::as_str) {
            params.insert("pbk".to_string(), pbk.to_string());
        }
        if let Some(sid) = reality.get("short_id").and_then(JsonValue::as_str) {
            params.insert("sid".to_string(), sid.to_string());
        }
    }
    if let Some(fp) = tls
        .get("utls")
        .and_then(|u| u.get("fingerprint"))
        .and_then(JsonValue::as_str)
    {
        params.insert("fp".to_string(), fp.to_string());
    }
    if let Some(alpn) = tls.get("alpn").and_then(JsonValue::as_array) {
        let joined = alpn
            .iter()
            .filter_map(JsonValue::as_str)
            .collect::<Vec<_>>()
            .join(",");
        if !joined.is_empty() {
            params.insert("alpn".to_string(), joined);
        }
    }
}

/// Раскладывает объект `transport` в нормализованные параметры.
fn parse_transport(params: &mut BTreeMap<String, String>, ob: &JsonValue) {
    let Some(transport) = ob.get("transport") else {
        return;
    };

    if let Some(ty) = transport.get("type").and_then(JsonValue::as_str) {
        params.insert("type".to_string(), ty.to_string());
    }
    if let Some(path) = transport.get("path").and_then(JsonValue::as_str) {
        params.insert("path".to_string(), path.to_string());
    }
    if let Some(host) = transport
        .get("headers")
        .and_then(|h| h.get("Host"))
        .and_then(JsonValue::as_str)
    {
        params.insert("host".to_string(), host.to_string());
    }
}

/// Извлекает обязательное строковое поле или возвращает [`ParseError::MissingField`].
fn insert_field(
    params: &mut BTreeMap<String, String>,
    ob: &JsonValue,
    src: &str,
    key: &'static str,
) -> Result<(), ParseError> {
    let value = ob
        .get(src)
        .and_then(JsonValue::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(ParseError::MissingField(key))?;
    params.insert(key.to_string(), value.to_string());
    Ok(())
}

/// Извлекает необязательное строковое поле (молча пропускает отсутствие).
fn insert_opt(params: &mut BTreeMap<String, String>, ob: &JsonValue, src: &str, key: &str) {
    if let Some(value) = ob
        .get(src)
        .and_then(JsonValue::as_str)
        .filter(|s| !s.is_empty())
    {
        params.insert(key.to_string(), value.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{"outbounds":[
        {"type":"vless","tag":"proxy","server":"ex.com","server_port":443,
         "uuid":"uuid-1","flow":"xtls-rprx-vision",
         "tls":{"enabled":true,"server_name":"ya.ru",
                "reality":{"enabled":true,"public_key":"PBK","short_id":"SID"},
                "utls":{"enabled":true,"fingerprint":"chrome"},
                "alpn":["h2","http/1.1"]},
         "transport":{"type":"ws","path":"/ray","headers":{"Host":"cdn.ya.ru"}}},
        {"type":"shadowsocks","server":"s.com","server_port":8388,
         "method":"aes-256-gcm","password":"pw"},
        {"type":"hysteria2","tag":"hy","server":"h.com","server_port":8443,"password":"pw"},
        {"type":"direct","tag":"d"}
    ]}"#;

    #[test]
    fn parses_vless_with_tls_and_transport() {
        let res = parse_singbox_config(SAMPLE);
        let vless = res[0].as_ref().unwrap();
        assert_eq!(vless.protocol, ProtocolKind::Vless);
        assert_eq!(vless.name, "proxy");
        assert_eq!(vless.address, "ex.com");
        assert_eq!(vless.port, 443);
        assert_eq!(vless.param("uuid"), Some("uuid-1"));
        assert_eq!(vless.param("flow"), Some("xtls-rprx-vision"));
        assert_eq!(vless.param("sni"), Some("ya.ru"));
        assert_eq!(vless.param("pbk"), Some("PBK"));
        assert_eq!(vless.param("sid"), Some("SID"));
        assert_eq!(vless.param("fp"), Some("chrome"));
        assert_eq!(vless.param("alpn"), Some("h2,http/1.1"));
        assert_eq!(vless.param("type"), Some("ws"));
        assert_eq!(vless.param("path"), Some("/ray"));
        assert_eq!(vless.param("host"), Some("cdn.ya.ru"));
    }

    #[test]
    fn parses_shadowsocks_and_hysteria2() {
        let res = parse_singbox_config(SAMPLE);
        let ss = res[1].as_ref().unwrap();
        assert_eq!(ss.protocol, ProtocolKind::Shadowsocks);
        // tag отсутствует -> имя = host:port.
        assert_eq!(ss.name, "s.com:8388");
        assert_eq!(ss.param("method"), Some("aes-256-gcm"));
        assert_eq!(ss.param("password"), Some("pw"));

        let hy = res[2].as_ref().unwrap();
        assert_eq!(hy.protocol, ProtocolKind::Hysteria2);
        assert_eq!(hy.name, "hy");
        assert_eq!(hy.param("password"), Some("pw"));
    }

    #[test]
    fn rejects_service_outbound() {
        let res = parse_singbox_config(SAMPLE);
        assert!(matches!(
            res[3],
            Err(ParseError::UnknownScheme(ref s)) if s == "direct"
        ));
    }

    #[test]
    fn missing_fields_and_broken_json() {
        // Нет server_port.
        let no_port = r#"{"type":"trojan","server":"t.com","password":"pw"}"#;
        let res = parse_singbox_config(no_port);
        assert_eq!(res.len(), 1);
        assert!(matches!(res[0], Err(ParseError::MissingPort)));

        // Нет uuid у vless.
        let no_uuid = r#"[{"type":"vless","server":"v.com","server_port":443}]"#;
        let res = parse_singbox_config(no_uuid);
        assert!(matches!(res[0], Err(ParseError::MissingField("uuid"))));

        // Битый JSON -> единственная ошибка.
        let res = parse_singbox_config("{not json");
        assert_eq!(res.len(), 1);
        assert!(matches!(res[0], Err(ParseError::Json(_))));
    }
}
