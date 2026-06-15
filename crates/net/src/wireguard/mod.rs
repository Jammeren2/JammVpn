//! WireGuard / AmneziaWG исходящий (ТЗ, раздел 4, `PRO-*`).
//!
//! Userspace-реализация без TUN-устройства: Noise-ядро WireGuard
//! ([`boringtun`]) + сетевой стек ([`smoltcp`]) для выдачи per-TCP-потоков, и
//! собственная AmneziaWG-обфускация поверх UDP ([`obfs`]).
//!
//! Один общий туннель (`WgTunnel`) на узел поднимается лениво при первом
//! соединении и разделяется всеми коннектами (см. [`config::WgConfig`]).

mod config;
mod device;
mod driver;
mod obfs;
mod stream;
mod tunnel;

pub use config::{decode_key, parse_addresses, parse_ip_list, AwgObfuscation, WgConfig, WgParams};

use crate::target::Target;
use crate::BoxedStream;
use std::io;
use std::net::IpAddr;

/// Точка входа: TCP-соединение до `target` через WG-туннель (лениво поднимаемый).
pub async fn wireguard_connect(cfg: &WgConfig, target: &Target) -> io::Result<BoxedStream> {
    cfg.connect_tcp(target).await
}

/// Резолвит цель в `(IpAddr, port)`.
///
/// v0: домены разрешаются СИСТЕМНЫМ резолвером (вне туннеля) — известное
/// ограничение (утечка DNS); in-tunnel DNS (smoltcp `socket-dns` против
/// `params.dns`) — следующий шаг. IP-цели проходят без резолва.
pub(crate) async fn resolve_target(target: &Target) -> io::Result<(IpAddr, u16)> {
    match target {
        Target::Socket(addr) => Ok((addr.ip(), addr.port())),
        Target::Domain(host, port) => {
            let addr = tokio::net::lookup_host((host.as_str(), *port))
                .await?
                .next()
                .ok_or_else(|| io::Error::other(format!("wg: DNS: пусто для {host}")))?;
            Ok((addr.ip(), addr.port()))
        }
    }
}
