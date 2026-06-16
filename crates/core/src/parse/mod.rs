//! Парсеры импорта конфигов (ТЗ, раздел 6, `IMP-*`).

mod awg;
pub mod clash;
mod link;
pub mod singbox;
mod subscription;
pub mod uri;
pub mod xray;

pub use awg::parse_awg_conf;
pub use clash::parse_clash;
pub use link::parse_link;
pub use singbox::parse_singbox_config;
pub use subscription::parse_subscription;
pub use xray::parse_xray_config;
