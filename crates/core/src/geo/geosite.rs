//! Разбор `geosite.dat` (v2ray/xray) и сопоставление доменов по категориям.
//!
//! Схема protobuf:
//! ```text
//! GeoSiteList { repeated GeoSite entry = 1; }
//! GeoSite    { string country_code = 1; repeated Domain domain = 2; }
//! Domain     { Type type = 1; string value = 2; repeated Attribute attribute = 3; }
//! Type: Plain=0 (подстрока), Regex=1 (пропускаем), Domain=2 (суффикс), Full=3 (точно)
//! ```
//! Regex-записи не поддерживаются (нет regex-движка) — пропускаются и считаются.

use super::protobuf::{Reader, WIRE_LEN, WIRE_VARINT};
use super::GeoError;
use std::collections::{HashMap, HashSet};

const TYPE_PLAIN: u64 = 0;
const TYPE_REGEX: u64 = 1;
const TYPE_DOMAIN: u64 = 2;
const TYPE_FULL: u64 = 3;

/// Эффективный набор доменных правил одной категории.
///
/// `full` — точные имена (O(1)); `suffix` — домены и поддомены (проверка по
/// суффиксам имени, O(меток)); `keyword` — подстроки (линейно по немногим).
#[derive(Debug, Default, Clone)]
pub struct DomainSet {
    full: HashSet<String>,
    suffix: HashSet<String>,
    keyword: Vec<String>,
    /// Сколько regex-записей пропущено при разборе.
    skipped_regex: usize,
}

impl DomainSet {
    /// Совпадает ли хост с категорией (регистр и завершающая точка игнорируются).
    pub fn matches(&self, host: &str) -> bool {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        if self.full.contains(&h) {
            return true;
        }
        if !self.suffix.is_empty() {
            // Само имя и каждый родительский суффикс: a.b.example.com →
            // a.b.example.com, b.example.com, example.com, com.
            if self.suffix.contains(&h) {
                return true;
            }
            let mut rest = h.as_str();
            while let Some(pos) = rest.find('.') {
                rest = &rest[pos + 1..];
                if self.suffix.contains(rest) {
                    return true;
                }
            }
        }
        self.keyword.iter().any(|k| h.contains(k))
    }

    /// Число записей (для диагностики).
    pub fn len(&self) -> usize {
        self.full.len() + self.suffix.len() + self.keyword.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Сколько regex-правил было пропущено.
    pub fn skipped_regex(&self) -> usize {
        self.skipped_regex
    }

    fn add(&mut self, dtype: u64, value: String) {
        let v = value.trim_end_matches('.').to_ascii_lowercase();
        if v.is_empty() {
            return;
        }
        match dtype {
            TYPE_FULL => {
                self.full.insert(v);
            }
            TYPE_DOMAIN => {
                self.suffix.insert(v);
            }
            TYPE_PLAIN => self.keyword.push(v),
            TYPE_REGEX => self.skipped_regex += 1,
            _ => {} // неизвестный тип — игнор
        }
    }
}

/// База geosite: категория (нижний регистр) → набор доменов.
#[derive(Debug, Default, Clone)]
pub struct GeoSiteDb {
    categories: HashMap<String, DomainSet>,
}

impl GeoSiteDb {
    /// Разбирает содержимое `geosite.dat`.
    pub fn parse(bytes: &[u8]) -> Result<Self, GeoError> {
        let mut db = GeoSiteDb::default();
        let mut r = Reader::new(bytes);
        while !r.eof() {
            let (field, wire) = r.read_tag()?;
            if field == 1 && wire == WIRE_LEN {
                let (code, set) = parse_geosite(r.read_bytes()?)?;
                if !code.is_empty() {
                    db.categories.insert(code, set);
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

    /// Совпадает ли хост с категорией (отсутствующая категория → `false`).
    pub fn matches(&self, category: &str, host: &str) -> bool {
        self.categories
            .get(&category.to_ascii_lowercase())
            .is_some_and(|s| s.matches(host))
    }

    /// Набор доменов категории.
    pub fn category(&self, name: &str) -> Option<&DomainSet> {
        self.categories.get(&name.to_ascii_lowercase())
    }

    /// Число категорий.
    pub fn len(&self) -> usize {
        self.categories.len()
    }

    pub fn is_empty(&self) -> bool {
        self.categories.is_empty()
    }
}

/// Разбирает одно сообщение `GeoSite` → (код категории, набор доменов).
fn parse_geosite(bytes: &[u8]) -> Result<(String, DomainSet), GeoError> {
    let mut code = String::new();
    let mut set = DomainSet::default();
    let mut r = Reader::new(bytes);
    while !r.eof() {
        let (field, wire) = r.read_tag()?;
        match (field, wire) {
            (1, WIRE_LEN) => code = r.read_string()?.to_ascii_lowercase(),
            (2, WIRE_LEN) => {
                let (dtype, value) = parse_domain(r.read_bytes()?)?;
                set.add(dtype, value);
            }
            _ => r.skip(wire)?,
        }
    }
    Ok((code, set))
}

/// Разбирает одно сообщение `Domain` → (тип, значение).
fn parse_domain(bytes: &[u8]) -> Result<(u64, String), GeoError> {
    let mut dtype = TYPE_PLAIN;
    let mut value = String::new();
    let mut r = Reader::new(bytes);
    while !r.eof() {
        let (field, wire) = r.read_tag()?;
        match (field, wire) {
            (1, WIRE_VARINT) => dtype = r.read_varint()?,
            (2, WIRE_LEN) => value = r.read_string()?,
            _ => r.skip(wire)?,
        }
    }
    Ok((dtype, value))
}

#[cfg(test)]
mod tests {
    use super::super::protobuf::tests_support::{domain_msg, geosite_entry, list};
    use super::*;

    #[test]
    fn parse_and_match_categories() {
        // category "google": Domain google.com (суффикс), Full mail.google.com,
        //   Plain "gstatic"; Regex (пропуск). category "ads": Full bad.example.
        let google = geosite_entry(
            "google",
            &[
                domain_msg(TYPE_DOMAIN, "google.com"),
                domain_msg(TYPE_FULL, "mail.google.com"),
                domain_msg(TYPE_PLAIN, "gstatic"),
                domain_msg(TYPE_REGEX, ".*\\.doubleclick\\.net"),
            ],
        );
        let ads = geosite_entry("ADS", &[domain_msg(TYPE_FULL, "bad.example")]);
        let dat = list(1, &[google, ads]);

        let db = GeoSiteDb::parse(&dat).unwrap();
        assert_eq!(db.len(), 2);

        // суффикс
        assert!(db.matches("google", "www.google.com"));
        assert!(db.matches("google", "google.com"));
        assert!(!db.matches("google", "notgoogle.com"));
        // точное
        assert!(db.matches("google", "mail.google.com"));
        // ключевое слово (подстрока)
        assert!(db.matches("google", "cdn.gstatic.io"));
        // регистронезависимость категории
        assert!(db.matches("ads", "bad.example"));
        assert!(db.matches("ADS", "bad.example"));
        // regex пропущен и посчитан
        assert_eq!(db.category("google").unwrap().skipped_regex(), 1);
        // несуществующая категория
        assert!(!db.matches("nonexistent", "x.com"));
    }

    #[test]
    fn empty_and_malformed() {
        assert!(GeoSiteDb::parse(&[]).unwrap().is_empty());
        // обрезанный length-delimited → ошибка
        assert!(GeoSiteDb::parse(&[0x0A, 0x05, 0x01]).is_err());
    }
}
