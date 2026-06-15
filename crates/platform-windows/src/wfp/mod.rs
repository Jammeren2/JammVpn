//! WFP-слой Windows (ТЗ, раздел 3, `SPL-*`).
//!
//! - [`ipc`] — бинарный контракт user↔kernel: коды IOCTL, путь к устройству и
//!   формат сериализации набора правил, который UI передаёт драйверу.
//! - [`controller`] — user-mode контроллер драйвера (открытие устройства,
//!   `DeviceIoControl`); сам kernel-callout — в `wfp-driver/` (собирается WDK).

pub mod ipc;

#[cfg(windows)]
pub mod controller;
#[cfg(windows)]
pub mod redirect;
#[cfg(windows)]
pub use controller::WfpDriverController;
