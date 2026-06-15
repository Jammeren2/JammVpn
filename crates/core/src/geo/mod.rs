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

#[cfg(test)]
mod live_tests {
    use super::*;

    /// Парсит реальные `.dat` из путей в env (`JAMMVPN_GEOSITE`/`JAMMVPN_GEOIP`)
    /// и проверяет осмысленные счётчики + известные сопоставления.
    #[test]
    #[ignore = "данные: реальные geosite.dat/geoip.dat из env"]
    fn live_parse_real_dat() {
        if let Ok(p) = std::env::var("JAMMVPN_GEOSITE") {
            let db = GeoSiteDb::load(std::path::Path::new(&p)).unwrap();
            println!("geosite: {} категорий", db.len());
            assert!(db.len() > 100, "категорий неправдоподобно мало");
            assert!(
                db.matches("google", "www.google.com"),
                "google.com ∉ geosite:google"
            );
            assert!(!db.matches("google", "example.org"));
        }
        if let Ok(p) = std::env::var("JAMMVPN_GEOIP") {
            let db = GeoIpDb::load(std::path::Path::new(&p)).unwrap();
            println!("geoip: {} стран", db.len());
            assert!(db.len() > 100, "стран неправдоподобно мало");
            assert!(
                db.matches("us", "8.8.8.8".parse().unwrap()),
                "8.8.8.8 ∉ geoip:us"
            );
        }
    }
}
