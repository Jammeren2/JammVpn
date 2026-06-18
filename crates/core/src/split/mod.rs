//! Раздельное туннелирование: модель и платформо-независимый движок решений
//! (ТЗ, раздел 3, `SPL-*`).
//!
//! Здесь живёт *логика выбора маршрута* для каждого соединения. Платформенный
//! слой (WFP на Windows) лишь **исполняет** эти решения, поэтому код переносим
//! (в т.ч. под будущий Android).

mod cidr;
mod config;
mod engine;

pub use cidr::IpCidr;
pub use config::{
    AppMatcher, ConnApp, SplitConfig, SplitDriver, SplitMode, ALWAYS_BYPASS_CIDRS,
};
pub use engine::{decide, Action, ConnRequest};
