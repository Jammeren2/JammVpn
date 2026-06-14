//! Парсеры импорта конфигов (ТЗ, раздел 6, `IMP-*`).

mod link;
mod subscription;
pub mod uri;

pub use link::parse_link;
pub use subscription::parse_subscription;
