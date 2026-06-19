//! # jammvpn-net
//!
//! Асинхронное сетевое ядро JammVPN на `tokio`. Кроссплатформенно (пригодно и
//! для будущего Android). Содержит абстракцию исходящих соединений
//! ([`Outbound`]) и локальный прокси-сервер ([`inbound`]) — будущую цель
//! перенаправления WFP-драйвера.
//!
//! Соответствие ТЗ: раздел 4 (протоколы/ядро, `PRO-*`).

// Вендоренные из cfal/shoes (MIT) модули: код не «улучшаем», поэтому глушим
// dead_code (часть API ещё не подключена) и clippy (стиль апстрима). См. ATTRIBUTION.md.
#[allow(dead_code, clippy::all)]
mod buf_reader;
pub mod conn;
pub mod dns;
pub mod engine;
pub mod fakeip;
pub mod from_profile;
pub mod inbound;
pub mod hysteria2;
pub mod outbound;
#[allow(dead_code, clippy::all)]
pub mod reality;
pub mod reality_transport;
pub mod shadowsocks;
#[allow(dead_code, clippy::all)]
mod slide_buffer;
pub mod subscription;
#[allow(dead_code, clippy::all)]
mod sync_adapter;
pub mod target;
mod tlsutil;
pub mod trojan;
pub mod tuic;
pub mod udp;
pub mod urltest;
mod util;
#[allow(dead_code, clippy::all)]
mod vision;
pub mod netstack;
pub mod vless;
pub mod wgserver;
pub mod wireguard;

pub use conn::{drop_connection as connection_drop, snapshot as connection_snapshot, ConnInfo};
pub use arc_swap::ArcSwap;
pub use engine::{
    serve_socks_routed, serve_socks_swappable, serve_transparent_redirect, set_route_notifier,
    Decision, Engine, RouteNotice, Routed,
};
pub use fakeip::FakeIp;
pub use from_profile::{outbound_from_profile, ProfileError};
pub use hysteria2::{Hysteria2Config, Hysteria2Params};
pub use outbound::{
    HttpConfig, Outbound, ShadowsocksConfig, Socks5Config, Transport, TrojanConfig, UdpSession,
    VlessConfig,
};
pub use reality_transport::RealityTransport;
pub use shadowsocks::Method as ShadowsocksMethod;
pub use target::Target;
pub use tuic::{TuicConfig, TuicParams};
pub use udp::{encode_udp_datagram, parse_udp_datagram, udp_associate};
pub use wgserver::{
    gen_preshared_key, gen_private_key, public_key as wg_public_key, WgServer, WgServerParams,
};
pub use wireguard::{AwgObfuscation, WgConfig, WgParams};

use tokio::io::{AsyncRead, AsyncWrite};

/// Поток данных: асинхронные чтение и запись. Позволяет возвращать из разных
/// транспортов (TCP, TLS, …) единый тип.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// Боксированный поток.
pub type BoxedStream = Box<dyn AsyncStream>;

#[cfg(test)]
mod tests;
