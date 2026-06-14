//! # jammvpn-net
//!
//! Асинхронное сетевое ядро JammVPN на `tokio`. Кроссплатформенно (пригодно и
//! для будущего Android). Содержит абстракцию исходящих соединений
//! ([`Outbound`]) и локальный прокси-сервер ([`inbound`]) — будущую цель
//! перенаправления WFP-драйвера.
//!
//! Соответствие ТЗ: раздел 4 (протоколы/ядро, `PRO-*`).

pub mod inbound;
pub mod outbound;
pub mod target;

pub use outbound::{HttpConfig, Outbound, Socks5Config};
pub use target::Target;

#[cfg(test)]
mod tests;
