//! Разбор `geoip.dat` (v2ray/xray) и сопоставление IP по странам.
//!
//! Схема protobuf:
//! ```text
//! GeoIPList { repeated GeoIP entry = 1; }
//! GeoIP     { string country_code = 1; repeated CIDR cidr = 2; }
//! CIDR      { bytes ip = 1; uint32 prefix = 2; }   // ip — 4 или 16 байт
//! ```

use super::protobuf::{Reader, WIRE_LEN, WIRE_VARINT};
use super::GeoError;
use crate::split::IpCidr;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// База geoip: код страны (нижний регистр) → список подсетей.
#[derive(Debug, Default, Clone)]
pub struct GeoIpDb {
    countries: HashMap<String, Vec<IpCidr>>,
}

impl GeoIpDb {
    /// Разбирает содержимое `geoip.dat`.
    pub fn parse(bytes: &[u8]) -> Result<Self, GeoError> {
        let mut db = GeoIpDb::default();
        let mut r = Reader::new(bytes);
        while !r.eof() {
            let (field, wire) = r.read_tag()?;
            if field == 1 && wire == WIRE_LEN {
                let (code, cidrs) = parse_geoip(r.read_bytes()?)?;
                if !code.is_empty() {
                    db.countries.insert(code, cidrs);
                }
            } else {
                r.skip(wire)?;
            }
        }
        Ok(db)
    }

    /// Загружает базу из файла.
    pub fn load(path: &std::path::Path) -> Result<Self, GeoError> {
        let bytes = std::fs::read(path).map_err(|e| GeoError::Io(e.to_string()))?;
        Self::parse(&bytes)
    }

    /// Входит ли адрес в диапазоны страны (отсутствующая страна → `false`).
    pub fn matches(&self, country: &str, ip: IpAddr) -> bool {
        self.countries
            .get(&country.to_ascii_lowercase())
            .is_some_and(|cidrs| cidrs.iter().any(|c| c.contains(ip)))
    }

    /// Подсети страны.
    pub fn country(&self, code: &str) -> Option<&[IpCidr]> {
        self.countries
            .get(&code.to_ascii_lowercase())
            .map(Vec::as_slice)
    }

    /// Число стран.
    pub fn len(&self) -> usize {
        self.countries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.countries.is_empty()
    }
}

/// Разбирает одно сообщение `GeoIP` → (код страны, подсети).
fn parse_geoip(bytes: &[u8]) -> Result<(String, Vec<IpCidr>), GeoError> {
    let mut code = String::new();
    let mut cidrs = Vec::new();
    let mut r = Reader::new(bytes);
    while !r.eof() {
        let (field, wire) = r.read_tag()?;
        match (field, wire) {
            (1, WIRE_LEN) => code = r.read_string()?.to_ascii_lowercase(),
            (2, WIRE_LEN) => {
                if let Some(cidr) = parse_cidr(r.read_bytes()?)? {
                    cidrs.push(cidr);
                }
            }
            _ => r.skip(wire)?,
        }
    }
    Ok((code, cidrs))
}

/// Разбирает одно сообщение `CIDR` → подсеть (None — если адрес некорректной длины).
fn parse_cidr(bytes: &[u8]) -> Result<Option<IpCidr>, GeoError> {
    let mut ip_bytes: Option<Vec<u8>> = None;
    let mut prefix: u64 = 0;
    let mut r = Reader::new(bytes);
    while !r.eof() {
        let (field, wire) = r.read_tag()?;
        match (field, wire) {
            (1, WIRE_LEN) => ip_bytes = Some(r.read_bytes()?.to_vec()),
            (2, WIRE_VARINT) => prefix = r.read_varint()?,
            _ => r.skip(wire)?,
        }
    }
    let ip = match ip_bytes.as_deref() {
        Some(b) if b.len() == 4 => IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])),
        Some(b) if b.len() == 16 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(b);
            IpAddr::V6(Ipv6Addr::from(o))
        }
        // некорректная или отсутствующая длина — пропускаем запись, не ломая базу
        _ => return Ok(None),
    };
    Ok(IpCidr::new(ip, prefix as u8).ok())
}

#[cfg(test)]
mod tests {
    use super::super::protobuf::tests_support::{cidr_msg, geoip_entry, list};
    use super::*;

    #[test]
    fn parse_and_match_countries() {
        // RU: 1.1.1.0/24 и 2.2.0.0/16. US: 8.8.8.0/24. + IPv6 ::/0 в RU.
        let ru = geoip_entry(
            "RU",
            &[
                cidr_msg(&[1, 1, 1, 0], 24),
                cidr_msg(&[2, 2, 0, 0], 16),
                cidr_msg(
                    &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    32,
                ),
            ],
        );
        let us = geoip_entry("us", &[cidr_msg(&[8, 8, 8, 0], 24)]);
        let dat = list(1, &[ru, us]);

        let db = GeoIpDb::parse(&dat).unwrap();
        assert_eq!(db.len(), 2);

        assert!(db.matches("ru", "1.1.1.55".parse().unwrap()));
        assert!(db.matches("RU", "2.2.250.1".parse().unwrap())); // регистр кода
        assert!(!db.matches("ru", "8.8.8.8".parse().unwrap()));
        assert!(db.matches("us", "8.8.8.8".parse().unwrap()));
        // IPv6
        assert!(db.matches("ru", "2001:db8::1".parse().unwrap()));
        // несуществующая страна
        assert!(!db.matches("cn", "1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn skips_bad_cidr_length() {
        // 5-байтный «IP» — некорректен, запись пропускается, база остаётся валидной.
        let bad = geoip_entry("xx", &[cidr_msg(&[1, 2, 3, 4, 5], 24)]);
        let db = GeoIpDb::parse(&list(1, &[bad])).unwrap();
        assert_eq!(db.country("xx").unwrap().len(), 0);
    }

    #[test]
    fn empty_and_malformed() {
        assert!(GeoIpDb::parse(&[]).unwrap().is_empty());
        assert!(GeoIpDb::parse(&[0x0A, 0x7F]).is_err()); // обещанные 127 байт отсутствуют
    }
}
