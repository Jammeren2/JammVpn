//! # jammvpn-core
//!
//! Переносимое ядро JammVPN. Содержит платформо-независимую логику:
//! модель серверного профиля, парсеры импорта конфигов (share-ссылки,
//! base64-подписки) и базовые типы. Не содержит платформенного кода
//! (WFP/wintun/DPAPI живут в `jammvpn-platform-windows`).
//!
//! Соответствие ТЗ: раздел 4 (модель/протоколы), раздел 6 (импорт, `IMP-*`).

pub mod base64;
pub mod error;
pub mod json;
pub mod model;
pub mod parse;
pub mod routing;
pub mod split;
pub mod util;

pub use error::ParseError;
pub use json::JsonValue;
pub use model::{ProtocolKind, ServerProfile};
pub use parse::{
    parse_awg_conf, parse_link, parse_singbox_config, parse_subscription, parse_xray_config,
};
pub use routing::{evaluate, RouteAction, RouteRequest, Rule};
pub use split::{decide, Action, SplitConfig, SplitMode};
