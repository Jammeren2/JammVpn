//! Перечень поддерживаемых протоколов (ТЗ, раздел 4).

use std::fmt;

/// Тип исходящего протокола (outbound).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolKind {
    /// VLESS (в т.ч. REALITY / XTLS-Vision).
    Vless,
    /// Shadowsocks (AEAD / SS-2022).
    Shadowsocks,
    /// Trojan.
    Trojan,
    /// WireGuard.
    Wireguard,
    /// AmneziaWG (обфусцированный WireGuard).
    AmneziaWg,
    /// SOCKS5.
    Socks5,
    /// HTTP(S) CONNECT.
    Http,
    /// Hysteria2.
    Hysteria2,
    /// TUIC v5.
    Tuic,
}

impl ProtocolKind {
    /// Краткий машинный идентификатор протокола.
    pub fn as_str(self) -> &'static str {
        match self {
            ProtocolKind::Vless => "vless",
            ProtocolKind::Shadowsocks => "shadowsocks",
            ProtocolKind::Trojan => "trojan",
            ProtocolKind::Wireguard => "wireguard",
            ProtocolKind::AmneziaWg => "amneziawg",
            ProtocolKind::Socks5 => "socks5",
            ProtocolKind::Http => "http",
            ProtocolKind::Hysteria2 => "hysteria2",
            ProtocolKind::Tuic => "tuic",
        }
    }
}

impl fmt::Display for ProtocolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
