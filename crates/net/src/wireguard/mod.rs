//! WireGuard / AmneziaWG исходящий (ТЗ, раздел 4, `PRO-*`).
//!
//! Userspace-реализация без TUN-устройства: Noise-ядро WireGuard
//! ([`boringtun`]) + сетевой стек ([`smoltcp`]) для выдачи per-TCP-потоков, и
//! собственная AmneziaWG-обфускация поверх UDP ([`obfs`]).
//!
//! Один общий туннель (`WgTunnel`) на узел поднимается лениво при первом
//! соединении и разделяется всеми коннектами (см. [`config::WgConfig`]).

mod config;
// Задействуются драйвером в WG-C; временно глушим dead_code до подключения.
#[allow(dead_code)]
mod device;
#[allow(dead_code)]
mod obfs;
mod tunnel;

pub use config::{decode_key, parse_addresses, parse_ip_list, AwgObfuscation, WgConfig, WgParams};

use crate::target::Target;
use crate::BoxedStream;
use std::io;

/// Точка входа: TCP-соединение до `target` через WG-туннель (лениво поднимаемый).
pub async fn wireguard_connect(cfg: &WgConfig, target: &Target) -> io::Result<BoxedStream> {
    cfg.connect_tcp(target).await
}
