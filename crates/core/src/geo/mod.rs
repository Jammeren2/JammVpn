//! Базы правил geosite/geoip (ТЗ, раздел 5 — split-tunneling по категориям).
//!
//! Читает форматы v2ray/xray `.dat` (protobuf) без тяжёлых зависимостей: свой
//! минимальный protobuf-ридер ([`protobuf`]). [`GeoSiteDb`] сопоставляет домены по
//! категориям (`geosite:google`), [`GeoIpDb`] — IP по странам (`geoip:ru`).
//! Движок ([`crate`]-потребитель) использует их в правилах маршрутизации.

mod geoip;
mod geosite;
mod protobuf;

pub use geoip::GeoIpDb;
pub use geosite::{DomainSet, GeoSiteDb};

use std::fmt;

/// Ошибка разбора/загрузки geo-базы.
#[derive(Debug)]
pub enum GeoError {
    /// Данные оборваны (varint/length за границей буфера).
    Truncated,
    /// Некорректная структура protobuf.
    Malformed(&'static str),
    /// Ошибка ввода-вывода при загрузке файла.
    Io(String),
}

impl fmt::Display for GeoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GeoError::Truncated => write!(f, "geo: данные оборваны"),
            GeoError::Malformed(s) => write!(f, "geo: некорректный формат: {s}"),
            GeoError::Io(s) => write!(f, "geo: ошибка ввода-вывода: {s}"),
        }
    }
}

impl std::error::Error for GeoError {}
