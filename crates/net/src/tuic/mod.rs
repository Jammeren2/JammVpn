//! TUIC v5 исходящий (ТЗ, раздел 4, `PRO-*`).
//!
//! QUIC-прокси с бинарным фреймингом (без HTTP/3): Authenticate (UUID + токен из
//! TLS-экспортёра) на uni-стриме, затем Connect на bidi-стримах. Одно общее
//! QUIC-соединение мультиплексирует все проксируемые TCP-потоки (цель-домен
//! резолвит сервер — нет DNS-утечки на клиенте).
//!
//! Транспорт — `quinn` + `rustls`/aws-lc-rs (см. [`tls`]). Протокол сверен с
//! крейтом `tuic` 5.0.0 (см. [`proto`]).

mod config;
mod proto;
mod stream;
mod tls;
mod tunnel;

#[cfg(test)]
mod loopback;

pub use config::{TuicConfig, TuicParams};

use crate::target::Target;
use crate::BoxedStream;
use std::io;

/// Точка входа: TCP-соединение до `target` через TUIC-туннель (лениво поднимаемый).
pub async fn tuic_connect(cfg: &TuicConfig, target: &Target) -> io::Result<BoxedStream> {
    cfg.connect_tcp(target).await
}
