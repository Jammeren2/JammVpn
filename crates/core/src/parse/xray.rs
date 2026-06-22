//! Импорт JSON-конфигов Xray / v2rayN (ТЗ, раздел 6, `IMP-*`).
//!
//! Берёт массив `outbounds` (либо верхний уровень как массив, либо одиночный
//! outbound-объект) и превращает каждый поддержанный outbound в
//! [`ServerProfile`]. Неподдержанные протоколы (`vmess`, `freedom`, `dns`,
//! `blackhole`, ...) возвращаются как [`ParseError::UnknownScheme`], чтобы
//! вызывающая сторона могла их пропустить, не теряя позиции в списке.

use crate::error::ParseError;
use crate::json::JsonValue;
use crate::model::{ProtocolKind, ServerProfile};
use std::collections::BTreeMap;

/// Разбирает JSON-конфиг Xray/v2rayN и возвращает по одному результату на
/// каждый outbound.
///
/// Если верхний уровень — объект с ключом `outbounds`, используется этот
/// массив. Если верхний уровень сам массив — он трактуется как список
/// outbound-ов. Если это одиночный объект с полем `protocol` — он
/// оборачивается в массив из одного элемента. При ошибке разбора самого JSON
/// возвращается один элемент `Err`.
pub fn parse_xray_config(input: &str) -> Vec<Result<ServerProfile, ParseError>> {
    let root = match JsonValue::parse(input) {
        Ok(v) => v,
        Err(e) => return vec![Err(e)],
    };

    // Подписка Happ/v2rayN: массив ПОЛНЫХ конфигов (каждый со своими `outbounds`
    // и `remarks`). Извлекаем proxy-узлы из каждого, имя = `remarks · tag`.
    if let Some(arr) = root.as_array() {
        if arr.iter().any(|c| c.get("outbounds").is_some()) {
            return arr.iter().flat_map(parse_config_entry).collect();
        }
    }

    let outbounds: &[JsonValue] =
        if let Some(arr) = root.get("outbounds").and_then(JsonValue::as_array) {
            arr
        } else if let Some(arr) = root.as_array() {
            arr
        } else if root.get("protocol").is_some() {
            std::slice::from_ref(&root)
        } else {
            return vec![Err(ParseError::MissingField("outbounds"))];
        };

    outbounds.iter().map(parse_outbound).collect()
}

/// Разбирает один полный конфиг из массива-подписки: берёт все поддержанные
/// proxy-outbounds, неподдержанные (freedom/blackhole/dns/...) молча отбрасывает,
/// имя префиксует `remarks` конфига.
fn parse_config_entry(config: &JsonValue) -> Vec<Result<ServerProfile, ParseError>> {
    let remarks = config
        .get("remarks")
        .and_then(JsonValue::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    // Балансировщики Xray: каждый группирует outbound'ы, чьи теги начинаются с
    // одного из префиксов `selector`. Запоминаем (тег → префиксы), чтобы пометить
    // узлы балансировщиком (для «объединения» нод по группам в UI).
    let balancers: Vec<(String, Vec<String>)> = config
        .get("routing")
        .and_then(|r| r.get("balancers"))
        .and_then(JsonValue::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|b| {
                    let tag = b.get("tag").and_then(JsonValue::as_str)?.to_string();
                    let sel = b
                        .get("selector")
                        .and_then(JsonValue::as_array)
                        .map(|s| {
                            s.iter()
                                .filter_map(|x| x.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default();
                    Some((tag, sel))
                })
                .collect()
        })
        .unwrap_or_default();
    let balancer_of = |ob_tag: &str| -> Option<String> {
        balancers
            .iter()
            .find(|(_, sel)| sel.iter().any(|p| ob_tag.starts_with(p.as_str())))
            .map(|(tag, _)| tag.clone())
    };
    let Some(obs) = config.get("outbounds").and_then(JsonValue::as_array) else {
        return Vec::new();
    };
    obs.iter()
        .map(|ob| {
            let ob_tag = ob.get("tag").and_then(JsonValue::as_str).unwrap_or("");
            let bal = balancer_of(ob_tag);
            parse_outbound(ob).map(|mut p| {
                if let Some(rem) = &remarks {
                    p.name = format!("{rem} · {}", p.name);
                }
                if let Some(b) = bal {
                    p.params.insert("balancer".into(), b);
                }
                p
            })
        })
        // Не-proxy outbound (freedom/dns/blackhole) и объекты без protocol — мимо.
        .filter(|r| {
            !matches!(
                r,
                Err(ParseError::UnknownScheme(_)) | Err(ParseError::MissingField("protocol"))
            )
        })
        .collect()
}

/// Разбирает один outbound-объект.
fn parse_outbound(ob: &JsonValue) -> Result<ServerProfile, ParseError> {
    let protocol = ob
        .get("protocol")
        .and_then(JsonValue::as_str)
        .ok_or(ParseError::MissingField("protocol"))?;

    let kind = match protocol {
        "vless" => ProtocolKind::Vless,
        "shadowsocks" => ProtocolKind::Shadowsocks,
        "trojan" => ProtocolKind::Trojan,
        "socks" => ProtocolKind::Socks5,
        "http" => ProtocolKind::Http,
        other => return Err(ParseError::UnknownScheme(other.to_string())),
    };

    let settings = ob.get("settings");
    let mut params = BTreeMap::new();

    let (address, port) = if kind == ProtocolKind::Vless {
        let node = settings
            .and_then(|s| s.get("vnext"))
            .and_then(JsonValue::as_array)
            .and_then(<[JsonValue]>::first)
            .ok_or(ParseError::MissingField("vnext"))?;
        extract_vless(node, &mut params)?
    } else {
        let server = settings
            .and_then(|s| s.get("servers"))
            .and_then(JsonValue::as_array)
            .and_then(<[JsonValue]>::first)
            .ok_or(ParseError::MissingField("servers"))?;
        extract_server(kind, server, &mut params)?
    };

    if let Some(stream) = ob.get("streamSettings") {
        extract_stream(stream, &mut params);
    }

    let name = ob
        .get("tag")
        .and_then(JsonValue::as_str)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("{address}:{port}"));

    Ok(ServerProfile {
        name,
        protocol: kind,
        address,
        port,
        params,
        tags: Vec::new(),
    })
}

/// Адрес/порт и пользовательские поля для VLESS (`settings.vnext[0]`).
fn extract_vless(
    node: &JsonValue,
    params: &mut BTreeMap<String, String>,
) -> Result<(String, u16), ParseError> {
    let (address, port) = address_port(node)?;

    let user = node
        .get("users")
        .and_then(JsonValue::as_array)
        .and_then(<[JsonValue]>::first)
        .ok_or(ParseError::MissingField("users"))?;

    let uuid = user
        .get("id")
        .and_then(JsonValue::as_str)
        .ok_or(ParseError::MissingField("id"))?;
    params.insert("uuid".to_string(), uuid.to_string());

    insert_str(params, "flow", user.get("flow"));
    insert_str(params, "encryption", user.get("encryption"));

    Ok((address, port))
}

/// Адрес/порт и пользовательские поля для `settings.servers[0]`.
fn extract_server(
    kind: ProtocolKind,
    server: &JsonValue,
    params: &mut BTreeMap<String, String>,
) -> Result<(String, u16), ParseError> {
    let (address, port) = address_port(server)?;

    match kind {
        ProtocolKind::Shadowsocks => {
            let method = server
                .get("method")
                .and_then(JsonValue::as_str)
                .ok_or(ParseError::MissingField("method"))?;
            let password = server
                .get("password")
                .and_then(JsonValue::as_str)
                .ok_or(ParseError::MissingField("password"))?;
            params.insert("method".to_string(), method.to_string());
            params.insert("password".to_string(), password.to_string());
        }
        ProtocolKind::Trojan => {
            let password = server
                .get("password")
                .and_then(JsonValue::as_str)
                .ok_or(ParseError::MissingField("password"))?;
            params.insert("password".to_string(), password.to_string());
        }
        _ => {}
    }

    Ok((address, port))
}

/// Общая выборка `address` + `port` (порт через `as_u16_port`).
fn address_port(node: &JsonValue) -> Result<(String, u16), ParseError> {
    let address = node
        .get("address")
        .and_then(JsonValue::as_str)
        .ok_or(ParseError::MissingField("address"))?;
    let port = node
        .get("port")
        .and_then(JsonValue::as_u16_port)
        .ok_or(ParseError::MissingPort)?;
    Ok((address.to_string(), port))
}

/// Разбор `streamSettings` (транспорт + TLS/REALITY/WS/gRPC).
fn extract_stream(stream: &JsonValue, params: &mut BTreeMap<String, String>) {
    insert_str(params, "type", stream.get("network"));
    insert_str(params, "security", stream.get("security"));

    if let Some(tls) = stream.get("tlsSettings") {
        insert_str(params, "sni", tls.get("serverName"));
    }

    if let Some(reality) = stream.get("realitySettings") {
        insert_str(params, "sni", reality.get("serverName"));
        insert_str(params, "pbk", reality.get("publicKey"));
        insert_str(params, "sid", reality.get("shortId"));
        insert_str(params, "fp", reality.get("fingerprint"));
    }

    if let Some(ws) = stream.get("wsSettings") {
        insert_str(params, "path", ws.get("path"));
        if let Some(host) = ws.get("headers").and_then(|h| h.get("Host")) {
            insert_str(params, "host", Some(host));
        }
    }

    if let Some(grpc) = stream.get("grpcSettings") {
        insert_str(params, "servicename", grpc.get("serviceName"));
    }
}

/// Вставляет строковое значение, только если оно присутствует и непустое.
fn insert_str(params: &mut BTreeMap<String, String>, key: &str, value: Option<&JsonValue>) {
    if let Some(s) = value.and_then(JsonValue::as_str).filter(|s| !s.is_empty()) {
        params.insert(key.to_string(), s.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{"outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"ex.com","port":443,"users":[{"id":"uuid-1","flow":"xtls-rprx-vision","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"ya.ru","publicKey":"PBK","shortId":"SID","fingerprint":"chrome"}}},{"protocol":"shadowsocks","settings":{"servers":[{"address":"s.com","port":8388,"method":"aes-256-gcm","password":"pw"}]}}]}"#;

    #[test]
    fn parses_vless_reality_outbound() {
        let results = parse_xray_config(SAMPLE);
        assert_eq!(results.len(), 2);

        let vless = results[0].as_ref().unwrap();
        assert_eq!(vless.protocol, ProtocolKind::Vless);
        assert_eq!(vless.name, "proxy");
        assert_eq!(vless.address, "ex.com");
        assert_eq!(vless.port, 443);
        assert_eq!(vless.param("uuid"), Some("uuid-1"));
        assert_eq!(vless.param("flow"), Some("xtls-rprx-vision"));
        assert_eq!(vless.param("encryption"), Some("none"));
        assert_eq!(vless.param("type"), Some("tcp"));
        assert_eq!(vless.param("security"), Some("reality"));
        assert_eq!(vless.param("sni"), Some("ya.ru"));
        assert_eq!(vless.param("pbk"), Some("PBK"));
        assert_eq!(vless.param("sid"), Some("SID"));
        assert_eq!(vless.param("fp"), Some("chrome"));
    }

    #[test]
    fn parses_shadowsocks_outbound() {
        let results = parse_xray_config(SAMPLE);
        let ss = results[1].as_ref().unwrap();
        assert_eq!(ss.protocol, ProtocolKind::Shadowsocks);
        // tag отсутствует -> имя из address:port.
        assert_eq!(ss.name, "s.com:8388");
        assert_eq!(ss.param("method"), Some("aes-256-gcm"));
        assert_eq!(ss.param("password"), Some("pw"));
    }

    #[test]
    fn unsupported_protocol_is_err_but_kept() {
        let input = r#"{"outbounds":[{"protocol":"freedom","tag":"direct"},{"protocol":"trojan","tag":"t","settings":{"servers":[{"address":"t.com","port":443,"password":"sec"}]},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"t.com"},"wsSettings":{"path":"/ws","headers":{"Host":"cdn.t.com"}}}}]}"#;
        let results = parse_xray_config(input);
        assert_eq!(results.len(), 2);
        assert!(matches!(
            results[0],
            Err(ParseError::UnknownScheme(ref s)) if s == "freedom"
        ));

        let trojan = results[1].as_ref().unwrap();
        assert_eq!(trojan.protocol, ProtocolKind::Trojan);
        assert_eq!(trojan.param("password"), Some("sec"));
        assert_eq!(trojan.param("type"), Some("ws"));
        assert_eq!(trojan.param("security"), Some("tls"));
        assert_eq!(trojan.param("sni"), Some("t.com"));
        assert_eq!(trojan.param("path"), Some("/ws"));
        assert_eq!(trojan.param("host"), Some("cdn.t.com"));
    }

    #[test]
    fn balancers_tag_member_nodes() {
        // Подписка-массив с балансировщиком: selector — префиксы тегов outbound'ов.
        let input = r#"[{"remarks":"sub","routing":{"balancers":[{"tag":"eu","selector":["EUROPE_MAIN"]}]},"outbounds":[
            {"protocol":"vless","tag":"EUROPE_MAIN","settings":{"vnext":[{"address":"a.com","port":443,"users":[{"id":"u","encryption":"none"}]}]}},
            {"protocol":"vless","tag":"EUROPE_MAIN-2","settings":{"vnext":[{"address":"b.com","port":443,"users":[{"id":"u","encryption":"none"}]}]}},
            {"protocol":"vless","tag":"OTHER","settings":{"vnext":[{"address":"c.com","port":443,"users":[{"id":"u","encryption":"none"}]}]}}
        ]}]"#;
        let ok: Vec<_> = parse_xray_config(input)
            .into_iter()
            .filter_map(Result::ok)
            .collect();
        assert_eq!(ok.len(), 3);
        assert_eq!(ok[0].param("balancer"), Some("eu"));
        assert_eq!(ok[1].param("balancer"), Some("eu"));
        assert_eq!(ok[2].param("balancer"), None);
    }

    #[test]
    fn malformed_json_yields_single_err() {
        let results = parse_xray_config("{not json");
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], Err(ParseError::Json(_))));
    }

    #[test]
    fn single_outbound_object_is_wrapped() {
        let input =
            r#"{"protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1080}]}}"#;
        let results = parse_xray_config(input);
        assert_eq!(results.len(), 1);
        let socks = results[0].as_ref().unwrap();
        assert_eq!(socks.protocol, ProtocolKind::Socks5);
        assert_eq!(socks.address, "127.0.0.1");
        assert_eq!(socks.port, 1080);
    }
}
