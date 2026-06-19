//! Hysteria2 исходящий (ТЗ, раздел 4, `PRO-*`).
//!
//! QUIC-прокси: аутентификация по HTTP/3 (`POST /auth`, заголовок
//! `Hysteria-Auth`, успех = статус `233`), затем проксирование TCP по сырым
//! bidi-стримам с бинарным фреймом запроса `0x401`. Одно общее QUIC-соединение
//! мультиплексирует все потоки; цель-домен резолвит сервер (нет утечки DNS).
//!
//! Транспорт — `quinn` + `rustls`/aws-lc-rs (см. [`tls`]); HTTP/3 — крейт `h3`.
//! UDP и obfs (Salamander) — отдельным шагом (MVP — TCP без обфускации).

mod config;
mod http3;
mod proto;
mod stream;
mod tls;
mod tunnel;

pub use config::{Hysteria2Config, Hysteria2Params};

use crate::target::Target;
use crate::BoxedStream;
use std::io;

/// Точка входа: TCP-соединение до `target` через Hysteria2-туннель (лениво).
pub async fn hysteria2_connect(
    cfg: &Hysteria2Config,
    target: &Target,
) -> io::Result<BoxedStream> {
    cfg.connect_tcp(target).await
}
