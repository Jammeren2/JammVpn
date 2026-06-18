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
/// Системный прокси Windows (WinINET; только Windows).
#[cfg(windows)]
pub mod sysproxy;
/// DPAPI-хранилище секретов (реальная реализация; только Windows).
#[cfg(windows)]
pub mod dpapi;
pub mod split;
pub mod wfp;
/// Split-туннелирование через Windows Packet Filter (ndisapi; только Windows).
#[cfg(windows)]
pub mod winpkfilter;

#[cfg(windows)]
pub mod windivert;

#[cfg(windows)]
pub use dpapi::DpapiStore;
#[cfg(windows)]
pub use wfp::WfpDriverController;
