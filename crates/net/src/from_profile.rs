//! Мост «импортированный профиль → исходящий» (`ServerProfile` → [`Outbound`]).
//!
//! Связывает слой импорта ([`jammvpn_core::parse`]) с сетевым ядром: позволяет
//! из распарсенной ссылки/подписки получить готовый к подключению [`Outbound`].

use crate::outbound::{
    HttpConfig, Outbound, ShadowsocksConfig, Socks5Config, Transport, TrojanConfig, VlessConfig,
};
use crate::shadowsocks::Method;
use crate::vless;
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
    /// Протокол ещё не поддержан сетевым ядром.
    Unsupported(ProtocolKind),
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProfileError::MissingField(s) => write!(f, "отсутствует поле: {s}"),
            ProfileError::BadUuid => write!(f, "некорректный uuid"),
            ProfileError::UnsupportedMethod(s) => write!(f, "неизвестный метод shadowsocks: {s}"),
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
            Ok(Outbound::Vless(VlessConfig {
                server,
                uuid,
                flow: p.param("flow").map(str::to_string),
                transport: Transport::Tcp,
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
            name: "w".to_string(),
            protocol: ProtocolKind::Wireguard,
            address: "h".to_string(),
            port: 51820,
            params: BTreeMap::new(),
            tags: Vec::new(),
        };
        assert!(matches!(
            outbound_from_profile(&p),
            Err(ProfileError::Unsupported(ProtocolKind::Wireguard))
        ));
    }
}
