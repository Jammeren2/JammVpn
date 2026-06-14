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
pub mod engine;
pub mod from_profile;
pub mod inbound;
pub mod outbound;
#[allow(dead_code, clippy::all)]
pub mod reality;
pub mod reality_transport;
pub mod shadowsocks;
#[allow(dead_code, clippy::all)]
mod slide_buffer;
#[allow(dead_code, clippy::all)]
mod sync_adapter;
pub mod target;
pub mod trojan;
mod util;
#[allow(dead_code, clippy::all)]
mod vision;
pub mod vless;

pub use engine::{serve_socks_routed, Decision, Engine};
pub use from_profile::{outbound_from_profile, ProfileError};
pub use outbound::{
    HttpConfig, Outbound, ShadowsocksConfig, Socks5Config, Transport, TrojanConfig, VlessConfig,
};
pub use reality_transport::RealityTransport;
pub use shadowsocks::Method as ShadowsocksMethod;
pub use target::Target;

use tokio::io::{AsyncRead, AsyncWrite};

/// Поток данных: асинхронные чтение и запись. Позволяет возвращать из разных
/// транспортов (TCP, TLS, …) единый тип.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// Боксированный поток.
pub type BoxedStream = Box<dyn AsyncStream>;

#[cfg(test)]
mod tests;
