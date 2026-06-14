//! Унифицированная модель серверного профиля.
//!
//! На этапе v0.1 протоколо-специфичные параметры хранятся в строковой карте
//! `params` (uuid, password, method, sni, flow, security, type, path, host,
//! pbk, sid, fp, obfs, alpn, ...). Строго типизированные структуры под каждый
//! протокол появятся при реализации сетевого слоя.

use crate::model::ProtocolKind;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Один импортированный/настроенный сервер.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerProfile {
    /// Отображаемое имя (из `#fragment` ссылки либо `host:port`).
    pub name: String,
    /// Протокол.
    pub protocol: ProtocolKind,
    /// Хост (домен или IP).
    pub address: String,
    /// Порт.
    pub port: u16,
    /// Протоколо-специфичные параметры (нормализованные ключи).
    pub params: BTreeMap<String, String>,
    /// Пользовательские теги (группировка).
    pub tags: Vec<String>,
}

impl ServerProfile {
    /// Удобный доступ к параметру.
    pub fn param(&self, key: &str) -> Option<&str> {
        self.params.get(key).map(String::as_str)
    }
}
