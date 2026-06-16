//! Прикладной конфиг (ТЗ, раздел 7): профили, подписки, правила, split, настройки.
//!
//! Сериализуется в JSON; секреты в `params`/`split` шифруются на уровне хранилища
//! (DPAPI на Windows) — это слой выше. Здесь — модель и (де)сериализация.

use crate::model::ServerProfile;
use crate::routing::Rule;
use crate::split::SplitConfig;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

/// Подписка (URL + расписание обновления).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Subscription {
    /// URL подписки.
    pub url: String,
    /// Тег/группа, в которую попадают серверы подписки.
    #[serde(default)]
    pub tag: Option<String>,
    /// Период автообновления, часов.
    #[serde(default = "default_interval")]
    pub update_interval_hours: u32,
}

fn default_interval() -> u32 {
    12
}

/// Общие настройки.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Тег исходящего по умолчанию (для правил `Proxy(None)` и default-прокси).
    pub default_proxy: Option<String>,
    /// Если `true`, трафик без совпавшего правила идёт в прокси, иначе — напрямую.
    pub default_to_proxy: bool,
    /// Локальный адрес основного прокси (SOCKS5/HTTP), напр. `127.0.0.1:1080`.
    pub listen: Option<String>,
    /// Узел для туннель-прокси «всё в туннель».
    pub tunnel_node: Option<String>,
    /// Локальный адрес туннель-прокси, напр. `127.0.0.1:1081`.
    pub tunnel_listen: Option<String>,
}

/// Описание DNS-сервера для движка (строки; `net` парсит в транспорт).
///
/// Резолв нужен движку, чтобы IP-CIDR правила (в т.ч. geoip) срабатывали и для
/// доменных целей: домен резолвится в адрес перед проверкой диапазонов.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DnsServerConfig {
    /// Открытый UDP, `host:port` (обычно :53).
    Udp { server: String },
    /// DNS-over-TLS (RFC 7858): `host:port` (:853) + SNI.
    Dot { server: String, sni: String },
    /// DNS-over-HTTPS (RFC 8484): URL `https://host/dns-query`.
    Doh { url: String },
}

/// Настройки FakeIP: подмена доменов синтетическими IP.
///
/// Позволяет маршрутизировать по домену там, где приложение само резолвит и
/// подключается по IP (TUN-режим): DNS-сервер выдаёт поддельный IP из `range`,
/// движок восстанавливает домен по нему и подключается по домену (без утечки DNS).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FakeIpConfig {
    /// Включён ли режим.
    pub enabled: bool,
    /// Диапазон поддельных адресов (IPv4 CIDR).
    pub range: String,
}

impl Default for FakeIpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            range: "198.18.0.0/15".to_string(),
        }
    }
}

/// Конфигурация DNS движка: серверы для резолва + FakeIP.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    /// Серверы (по порядку; используется первый). Пусто → резолв в движке выключен
    /// (поведение как раньше: только доменные правила и литеральные IP).
    pub servers: Vec<DnsServerConfig>,
    /// FakeIP.
    pub fakeip: FakeIpConfig,
}

/// Пути к базам правил geosite/geoip (форматы v2ray/xray `.dat`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GeoConfig {
    /// Путь к `geosite.dat` (доменные категории для правил `geosite:*`).
    pub geosite_path: Option<String>,
    /// Путь к `geoip.dat` (страновые IP-диапазоны для правил `geoip:*`).
    pub geoip_path: Option<String>,
}

/// Корневой конфиг приложения.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    /// Серверы (имя профиля используется как тег исходящего).
    pub servers: Vec<ServerProfile>,
    /// Подписки.
    pub subscriptions: Vec<Subscription>,
    /// Правила маршрутизации (first-match).
    pub rules: Vec<Rule>,
    /// Конфигурация раздельного туннелирования.
    pub split: SplitConfig,
    /// Общие настройки.
    pub settings: Settings,
    /// Конфигурация DNS (резолв для маршрутизации + FakeIP).
    pub dns: DnsConfig,
    /// Пути к базам geosite/geoip.
    pub geo: GeoConfig,
}

/// Ошибка загрузки/сохранения конфига.
#[derive(Debug)]
pub enum ConfigError {
    /// Ошибка ввода-вывода.
    Io(String),
    /// Ошибка разбора JSON.
    Json(String),
    /// Ошибка шифрования/расшифровки секретов.
    Secret(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(s) => write!(f, "ошибка ввода-вывода: {s}"),
            ConfigError::Json(s) => write!(f, "ошибка JSON: {s}"),
            ConfigError::Secret(s) => write!(f, "ошибка секретов: {s}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl AppConfig {
    /// Разбирает конфиг из JSON (отсутствующие поля берут значения по умолчанию).
    pub fn from_json(s: &str) -> Result<Self, ConfigError> {
        serde_json::from_str(s).map_err(|e| ConfigError::Json(e.to_string()))
    }

    /// Сериализует конфиг в человекочитаемый JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Загружает конфиг из файла.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let s = std::fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;
        Self::from_json(&s)
    }

    /// Сохраняет конфиг в файл.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        std::fs::write(path, self.to_json()).map_err(|e| ConfigError::Io(e.to_string()))
    }

    /// Сохраняет конфиг, предварительно зашифровав секреты через `store`
    /// (на диске секретные значения параметров получают префикс `enc:`).
    /// Конфиг в памяти не изменяется.
    pub fn save_protected(
        &self,
        path: &Path,
        store: &dyn crate::secret::SecretStore,
    ) -> Result<(), ConfigError> {
        let mut clone = self.clone();
        crate::secret::protect_config(&mut clone, store)
            .map_err(|e| ConfigError::Secret(e.to_string()))?;
        clone.save(path)
    }

    /// Загружает конфиг и расшифровывает секреты через `store`.
    pub fn load_protected(
        path: &Path,
        store: &dyn crate::secret::SecretStore,
    ) -> Result<Self, ConfigError> {
        let mut cfg = Self::load(path)?;
        crate::secret::unprotect_config(&mut cfg, store)
            .map_err(|e| ConfigError::Secret(e.to_string()))?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_link;
    use crate::routing::{DomainRule, RouteAction};

    #[test]
    fn roundtrip_json() {
        let mut cfg = AppConfig::default();
        cfg.servers
            .push(parse_link("vless://11111111-2222-3333-4444-555555555555@h:443#node").unwrap());
        cfg.subscriptions.push(Subscription {
            url: "https://example/sub".to_string(),
            tag: Some("main".to_string()),
            update_interval_hours: 6,
        });
        cfg.rules.push(Rule {
            domains: vec![DomainRule::Suffix("example.com".to_string())],
            action: RouteAction::Proxy(Some("node".to_string())),
            ..Default::default()
        });
        cfg.settings.default_to_proxy = true;

        let json = cfg.to_json();
        let back = AppConfig::from_json(&json).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn parses_minimal_with_defaults() {
        let cfg = AppConfig::from_json("{}").unwrap();
        assert!(cfg.servers.is_empty());
        assert!(!cfg.settings.default_to_proxy);
    }

    #[test]
    fn subscription_default_interval() {
        let cfg = AppConfig::from_json(r#"{"subscriptions":[{"url":"https://x/sub"}]}"#).unwrap();
        assert_eq!(cfg.subscriptions[0].update_interval_hours, 12);
    }

    #[test]
    fn rejects_bad_json() {
        assert!(AppConfig::from_json("{not json").is_err());
    }
}
