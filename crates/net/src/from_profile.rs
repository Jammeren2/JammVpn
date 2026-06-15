//! Мост «импортированный профиль → исходящий» (`ServerProfile` → [`Outbound`]).
//!
//! Связывает слой импорта ([`jammvpn_core::parse`]) с сетевым ядром: позволяет
//! из распарсенной ссылки/подписки получить готовый к подключению [`Outbound`].

use crate::outbound::{
    HttpConfig, Outbound, ShadowsocksConfig, Socks5Config, Transport, TrojanConfig, VlessConfig,
};
use crate::reality_transport::RealityTransport;
use crate::shadowsocks::Method;
use crate::vless;
use crate::wireguard::{
    decode_key, parse_addresses, parse_ip_list, AwgObfuscation, WgConfig, WgParams,
};
use jammvpn_core::{ProtocolKind, ServerProfile};
use std::fmt;

/// Ошибка преобразования профиля в исходящий.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    /// Отсутствует обязательное поле.
    MissingField(&'static str),
    /// UUID не разобран.
    BadUuid,
    /// Неизвестный AEAD-метод Shadowsocks.
    UnsupportedMethod(String),
    /// Некорректный ключ (например, не base64 или не 32 байта) — WireGuard.
    BadKey(&'static str),
    /// Протокол ещё не поддержан сетевым ядром.
    Unsupported(ProtocolKind),
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProfileError::MissingField(s) => write!(f, "отсутствует поле: {s}"),
            ProfileError::BadUuid => write!(f, "некорректный uuid"),
            ProfileError::UnsupportedMethod(s) => write!(f, "неизвестный метод shadowsocks: {s}"),
            ProfileError::BadKey(k) => write!(f, "некорректный ключ: {k}"),
            ProfileError::Unsupported(p) => write!(f, "протокол пока не поддержан: {p}"),
        }
    }
}

impl std::error::Error for ProfileError {}

/// Преобразует [`ServerProfile`] в [`Outbound`].
pub fn outbound_from_profile(p: &ServerProfile) -> Result<Outbound, ProfileError> {
    let server = format!("{}:{}", p.address, p.port);
    match p.protocol {
        ProtocolKind::Shadowsocks => {
            let method_name = p
                .param("method")
                .ok_or(ProfileError::MissingField("method"))?;
            let method = Method::from_name(method_name)
                .ok_or_else(|| ProfileError::UnsupportedMethod(method_name.to_string()))?;
            let password = p
                .param("password")
                .ok_or(ProfileError::MissingField("password"))?
                .to_string();
            Ok(Outbound::Shadowsocks(ShadowsocksConfig {
                server,
                method,
                password,
            }))
        }
        ProtocolKind::Vless => {
            let uuid_str = p.param("uuid").ok_or(ProfileError::MissingField("uuid"))?;
            let uuid = vless::parse_uuid(uuid_str).ok_or(ProfileError::BadUuid)?;
            let transport = if p.param("security") == Some("reality") {
                Transport::Reality(RealityTransport {
                    public_key: p.param("pbk").unwrap_or_default().to_string(),
                    short_id: p.param("sid").unwrap_or_default().to_string(),
                    server_name: p
                        .param("sni")
                        .or_else(|| p.param("host"))
                        .unwrap_or_default()
                        .to_string(),
                })
            } else {
                Transport::Tcp
            };
            Ok(Outbound::Vless(VlessConfig {
                server,
                uuid,
                flow: p.param("flow").map(str::to_string),
                transport,
            }))
        }
        ProtocolKind::Trojan => {
            let password = p
                .param("password")
                .ok_or(ProfileError::MissingField("password"))?
                .to_string();
            Ok(Outbound::Trojan(TrojanConfig {
                server,
                password,
                transport: Transport::Tcp,
            }))
        }
        ProtocolKind::Socks5 => Ok(Outbound::Socks5(Socks5Config {
            server,
            username: p.param("username").map(str::to_string),
            password: p.param("password").map(str::to_string),
        })),
        ProtocolKind::Http => Ok(Outbound::Http(HttpConfig {
            server,
            username: p.param("username").map(str::to_string),
            password: p.param("password").map(str::to_string),
        })),
        ProtocolKind::Wireguard | ProtocolKind::AmneziaWg => {
            let private_key = decode_key(
                p.param("private_key")
                    .ok_or(ProfileError::MissingField("private_key"))?,
            )
            .ok_or(ProfileError::BadKey("private_key"))?;
            let peer_public_key = decode_key(
                p.param("public_key")
                    .ok_or(ProfileError::MissingField("public_key"))?,
            )
            .ok_or(ProfileError::BadKey("public_key"))?;
            let preshared_key = match p.param("preshared_key") {
                Some(s) => Some(decode_key(s).ok_or(ProfileError::BadKey("preshared_key"))?),
                None => None,
            };
            let address = parse_addresses(
                p.param("address")
                    .ok_or(ProfileError::MissingField("address"))?,
            );
            if address.is_empty() {
                return Err(ProfileError::MissingField("address"));
            }
            let dns = p.param("dns").map(parse_ip_list).unwrap_or_default();
            let persistent_keepalive = p.param("persistent_keepalive").and_then(|s| s.parse().ok());
            // AWG-обфускация — только для AmneziaWg (парсер уже различил протокол
            // по наличию обфускационных ключей). Отсутствующие/нечисловые → 0.
            let awg = (p.protocol == ProtocolKind::AmneziaWg).then(|| {
                let g = |k: &str| p.param(k).and_then(|v| v.parse().ok()).unwrap_or(0u32);
                AwgObfuscation {
                    jc: g("jc"),
                    jmin: g("jmin"),
                    jmax: g("jmax"),
                    s1: g("s1"),
                    s2: g("s2"),
                    h1: g("h1"),
                    h2: g("h2"),
                    h3: g("h3"),
                    h4: g("h4"),
                }
            });
            Ok(Outbound::Wireguard(WgConfig::new(WgParams {
                endpoint: server,
                private_key,
                peer_public_key,
                preshared_key,
                address,
                dns,
                persistent_keepalive,
                awg,
            })))
        }
        other => Err(ProfileError::Unsupported(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jammvpn_core::parse_link;

    #[test]
    fn maps_shadowsocks() {
        let p = parse_link("ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#x").unwrap();
        match outbound_from_profile(&p).unwrap() {
            Outbound::Shadowsocks(c) => {
                assert_eq!(c.server, "1.2.3.4:8388");
                assert_eq!(c.method, Method::Aes256Gcm);
                assert_eq!(c.password, "pass");
            }
            other => panic!("ожидался Shadowsocks, получено {other:?}"),
        }
    }

    #[test]
    fn maps_vless_and_trojan() {
        let v = parse_link(
            "vless://11111111-2222-3333-4444-555555555555@h:443?flow=xtls-rprx-vision#x",
        )
        .unwrap();
        assert!(matches!(
            outbound_from_profile(&v).unwrap(),
            Outbound::Vless(_)
        ));

        let t = parse_link("trojan://pw@h:443#x").unwrap();
        assert!(matches!(
            outbound_from_profile(&t).unwrap(),
            Outbound::Trojan(_)
        ));
    }

    #[test]
    fn maps_socks_with_auth() {
        let p = parse_link("socks5://user:pwd@127.0.0.1:1080#x").unwrap();
        match outbound_from_profile(&p).unwrap() {
            Outbound::Socks5(c) => {
                assert_eq!(c.username.as_deref(), Some("user"));
                assert_eq!(c.password.as_deref(), Some("pwd"));
            }
            other => panic!("ожидался Socks5, получено {other:?}"),
        }
    }

    #[test]
    fn unsupported_protocol_errors() {
        use jammvpn_core::model::ServerProfile;
        use std::collections::BTreeMap;
        let p = ServerProfile {
            name: "h".to_string(),
            protocol: ProtocolKind::Hysteria2,
            address: "h".to_string(),
            port: 443,
            params: BTreeMap::new(),
            tags: Vec::new(),
        };
        assert!(matches!(
            outbound_from_profile(&p),
            Err(ProfileError::Unsupported(ProtocolKind::Hysteria2))
        ));
    }

    fn wg_profile(protocol: ProtocolKind, extra: &[(&str, &str)]) -> jammvpn_core::ServerProfile {
        use jammvpn_core::base64::encode_standard;
        use std::collections::BTreeMap;
        let mut params = BTreeMap::new();
        params.insert("private_key".to_string(), encode_standard(&[1u8; 32]));
        params.insert("public_key".to_string(), encode_standard(&[2u8; 32]));
        params.insert("address".to_string(), "10.0.0.2/32".to_string());
        for (k, v) in extra {
            params.insert(k.to_string(), v.to_string());
        }
        jammvpn_core::ServerProfile {
            name: "wg".to_string(),
            protocol,
            address: "1.2.3.4".to_string(),
            port: 51820,
            params,
            tags: Vec::new(),
        }
    }

    #[test]
    fn maps_wireguard() {
        let p = wg_profile(ProtocolKind::Wireguard, &[]);
        match outbound_from_profile(&p).unwrap() {
            Outbound::Wireguard(c) => {
                assert_eq!(c.params().endpoint, "1.2.3.4:51820");
                assert_eq!(c.params().address, vec![("10.0.0.2".parse().unwrap(), 32)]);
                assert!(c.params().awg.is_none());
            }
            other => panic!("ожидался Wireguard, получено {other:?}"),
        }
    }

    #[test]
    fn maps_amneziawg() {
        let p = wg_profile(
            ProtocolKind::AmneziaWg,
            &[("jc", "4"), ("h1", "1"), ("h4", "4")],
        );
        match outbound_from_profile(&p).unwrap() {
            Outbound::Wireguard(c) => {
                let awg = c.params().awg.as_ref().expect("awg");
                assert_eq!(awg.jc, 4);
                assert_eq!(awg.h4, 4);
            }
            other => panic!("ожидался Wireguard(AWG), получено {other:?}"),
        }
    }

    #[test]
    fn wireguard_missing_key_errors() {
        use std::collections::BTreeMap;
        let p = jammvpn_core::ServerProfile {
            name: "w".to_string(),
            protocol: ProtocolKind::Wireguard,
            address: "h".to_string(),
            port: 51820,
            params: BTreeMap::new(),
            tags: Vec::new(),
        };
        assert!(matches!(
            outbound_from_profile(&p),
            Err(ProfileError::MissingField("private_key"))
        ));
    }

    #[test]
    fn wireguard_bad_key_errors() {
        let p = wg_profile(ProtocolKind::Wireguard, &[("private_key", "not-base64!!")]);
        assert!(matches!(
            outbound_from_profile(&p),
            Err(ProfileError::BadKey("private_key"))
        ));
    }
}
