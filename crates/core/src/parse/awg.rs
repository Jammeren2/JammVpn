//! Разбор INI-подобного конфига WireGuard / AmneziaWG (`*.conf`).
//!
//! Поддерживаются секции `[Interface]` и `[Peer]`, строки вида `Key = Value`,
//! комментарии начинаются с `#` или `;`. Имена секций и ключей
//! регистронезависимы; в `params` ключи нормализуются к нижнему регистру
//! (`private_key`, `public_key`, `endpoint`, `allowed_ips`, обфускационные
//! `jc`/`jmin`/`jmax`/`s1`/`s2`/`h1`..`h4` и т.п.).
//!
//! Протокол определяется как [`ProtocolKind::AmneziaWg`], если присутствует хотя
//! бы один обфускационный ключ, иначе [`ProtocolKind::Wireguard`]. Адрес и порт
//! извлекаются из `Endpoint` (поддерживается форма `[ipv6]:port`).

use crate::error::ParseError;
use crate::model::{ProtocolKind, ServerProfile};
use crate::parse::uri::split_host_port;
use std::collections::BTreeMap;

/// Обфускационные ключи AmneziaWG (в нижнем регистре).
const AMNEZIA_KEYS: [&str; 9] = ["jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"];

/// Приводит сырое имя ключа конфига к нормализованному виду для `params`.
fn normalize_key(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    match lower.as_str() {
        "privatekey" => "private_key".to_string(),
        "publickey" => "public_key".to_string(),
        "presharedkey" => "preshared_key".to_string(),
        "allowedips" => "allowed_ips".to_string(),
        "persistentkeepalive" => "persistent_keepalive".to_string(),
        _ => lower,
    }
}

/// Разбирает INI-подобный конфиг WireGuard/AmneziaWG в [`ServerProfile`].
pub fn parse_awg_conf(input: &str) -> Result<ServerProfile, ParseError> {
    if input.trim().is_empty() {
        return Err(ParseError::EmptyInput);
    }

    let mut params: BTreeMap<String, String> = BTreeMap::new();
    let mut in_section = false;

    for line in input.lines() {
        let line = strip_comment(line).trim();
        if line.is_empty() {
            continue;
        }

        if let Some(section) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            // Допускаются только [Interface] и [Peer]; прочие секции игнорируем.
            match section.trim().to_ascii_lowercase().as_str() {
                "interface" | "peer" => in_section = true,
                _ => in_section = false,
            }
            continue;
        }

        if !in_section {
            continue;
        }

        let (key, value) = line
            .split_once('=')
            .ok_or(ParseError::MissingField("key = value"))?;
        let key = normalize_key(key.trim());
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        params.insert(key, value.to_string());
    }

    let endpoint = params
        .get("endpoint")
        .ok_or(ParseError::MissingHost)?
        .clone();
    let (address, port_opt) = split_host_port(&endpoint)?;
    let port = port_opt.ok_or(ParseError::MissingPort)?;

    let protocol = if AMNEZIA_KEYS.iter().any(|k| params.contains_key(*k)) {
        ProtocolKind::AmneziaWg
    } else {
        ProtocolKind::Wireguard
    };

    Ok(ServerProfile {
        name: format!("{address}:{port}"),
        protocol,
        address,
        port,
        params,
        tags: Vec::new(),
    })
}

/// Отбрасывает хвост строки после первого символа комментария (`#` или `;`).
fn strip_comment(line: &str) -> &str {
    match line.find(['#', ';']) {
        Some(i) => &line[..i],
        None => line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AWG_CONF: &str = "\
# тестовый конфиг
[Interface]
PrivateKey = aPrivKeyBase64=
Address = 10.0.0.2/32
DNS = 1.1.1.1
Jc = 4
Jmin = 40
Jmax = 70
S1 = 50
S2 = 100
H1 = 1
H2 = 2
H3 = 3
H4 = 4
[Peer]
PublicKey = aPubKeyBase64=
PresharedKey = aPskBase64=
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
";

    #[test]
    fn parses_amnezia_conf() {
        let p = parse_awg_conf(AWG_CONF).unwrap();
        assert_eq!(p.protocol, ProtocolKind::AmneziaWg);
        assert_eq!(p.address, "1.2.3.4");
        assert_eq!(p.port, 51820);
        assert_eq!(p.name, "1.2.3.4:51820");
        assert_eq!(p.param("private_key"), Some("aPrivKeyBase64="));
        assert_eq!(p.param("public_key"), Some("aPubKeyBase64="));
        assert_eq!(p.param("preshared_key"), Some("aPskBase64="));
        assert_eq!(p.param("allowed_ips"), Some("0.0.0.0/0, ::/0"));
        assert_eq!(p.param("persistent_keepalive"), Some("25"));
        assert_eq!(p.param("jc"), Some("4"));
        assert_eq!(p.param("h4"), Some("4"));
        assert_eq!(p.param("address"), Some("10.0.0.2/32"));
    }

    #[test]
    fn plain_wireguard_without_obfuscation() {
        let conf = "\
[Interface]
PrivateKey = privkey==
Address = 10.0.0.3/32
[Peer]
PublicKey = pubkey==
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
";
        let p = parse_awg_conf(conf).unwrap();
        assert_eq!(p.protocol, ProtocolKind::Wireguard);
        assert_eq!(p.address, "vpn.example.com");
        assert_eq!(p.port, 51820);
        assert_eq!(p.param("h1"), None);
    }

    #[test]
    fn ipv6_endpoint_and_case_insensitive_keys() {
        let conf = "\
[INTERFACE]
privatekey = pk==
s1 = 10
[peer]
PUBLICKEY = pub==
endpoint = [2001:db8::1]:443
";
        let p = parse_awg_conf(conf).unwrap();
        assert_eq!(p.protocol, ProtocolKind::AmneziaWg);
        assert_eq!(p.address, "2001:db8::1");
        assert_eq!(p.port, 443);
        assert_eq!(p.param("private_key"), Some("pk=="));
        assert_eq!(p.param("public_key"), Some("pub=="));
    }

    #[test]
    fn missing_endpoint_errors() {
        let conf = "\
[Interface]
PrivateKey = pk==
[Peer]
PublicKey = pub==
";
        assert!(matches!(parse_awg_conf(conf), Err(ParseError::MissingHost)));
        assert!(matches!(parse_awg_conf("   "), Err(ParseError::EmptyInput)));
    }
}
