//! # jammvpn-platform-windows
//!
//! Платформенный слой Windows: раздельное туннелирование (WFP user-mode
//! connect-redirect), TUN-адаптер (wintun), хранение секретов (DPAPI).
//!
//! Текущая фаза (0): определены интерфейсы и заглушки, чтобы приложение
//! собиралось и тестировалось целиком. Реальная WFP-реализация (под
//! `cfg(windows)`) появится в следующей фазе — см. ТЗ, раздел 3 (`SPL-*`).

/// Автозапуск при входе в систему (реестр `Run`; только Windows).
#[cfg(windows)]
pub mod autostart;
/// DPAPI-хранилище секретов (реальная реализация; только Windows).
#[cfg(windows)]
pub mod dpapi;
pub mod split;
pub mod wfp;

#[cfg(windows)]
pub use dpapi::DpapiStore;
