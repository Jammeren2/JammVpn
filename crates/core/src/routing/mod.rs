//! Движок маршрутизации (ТЗ, раздел 5, `RTE-*`).
//!
//! Правила сопоставляют соединение по домену / IP / процессу / порту и выдают
//! действие (прямо / в прокси / блок). Порядок правил значим: применяется
//! первое сработавшее (first-match), иначе — действие по умолчанию.
//!
//! Загрузка баз geosite/geoip и готовые пресеты на их основе появятся позже;
//! здесь — ядро логики и несколько пресетов из явных списков.

pub mod domain;
mod engine;
mod preset;
mod rule;

pub use domain::DomainRule;
pub use engine::evaluate;
pub use preset::{all_direct, all_proxy, direct_domains};
pub use rule::{RouteAction, RouteRequest, Rule};
