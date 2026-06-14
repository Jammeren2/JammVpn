//! # jammvpn-net
//!
//! Асинхронное сетевое ядро JammVPN на `tokio`. Кроссплатформенно (пригодно и
//! для будущего Android). Содержит абстракцию исходящих соединений
//! ([`Outbound`]) и локальный прокси-сервер ([`inbound`]) — будущую цель
//! перенаправления WFP-драйвера.
//!
//! Соответствие ТЗ: раздел 4 (протоколы/ядро, `PRO-*`).

pub mod engine;
pub mod inbound;
pub mod outbound;
pub mod shadowsocks;
pub mod target;
pub mod vless;

pub use engine::{serve_socks_routed, Decision, Engine};
pub use outbound::{HttpConfig, Outbound, ShadowsocksConfig, Socks5Config, Transport, VlessConfig};
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
