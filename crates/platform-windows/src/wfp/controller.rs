//! User-mode контроллер WFP-драйвера split (`SPL-35..40`).
//!
//! Открывает управляющее устройство драйвера (`\\.\JammVpnSplit`) и передаёт ему
//! снимок правил через `DeviceIoControl(IOCTL_JAMM_SET_CONFIG)` (бинарный формат —
//! [`super::ipc`]); снятие — `IOCTL_JAMM_CLEAR`. Требует загруженного драйвера и
//! прав администратора. Сам kernel-callout живёт в `wfp-driver/` (собирается WDK).
//!
//! Устройство открывается на каждый вызов: дескриптор нужен лишь для IOCTL,
//! конфиг хранится в драйвере до `CLEAR`/выгрузки — держать хендл не требуется.

use crate::split::{SplitConfig, SplitController, SplitError};
use crate::wfp::ipc::{
    encode_config, DriverConfig, IOCTL_JAMM_CLEAR, IOCTL_JAMM_SET_CONFIG, USER_MODE_DEVICE_PATH,
};
use std::ptr;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
    HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};
use windows_sys::Win32::System::IO::DeviceIoControl;

/// Права доступа `GENERIC_READ | GENERIC_WRITE` (объявлены локально, чтобы не
/// зависеть от перемещений констант между версиями `windows-sys`).
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

/// Контроллер реального WFP-драйвера: транслирует [`SplitConfig`] в IOCTL.
#[derive(Debug)]
pub struct WfpDriverController {
    /// Порт локального прокси, куда драйвер перенаправляет выбранные сокеты.
    redirect_port: u16,
    /// Применён ли сейчас набор правил.
    active: bool,
}

impl WfpDriverController {
    /// Создаёт контроллер для прокси-редиректа на `redirect_port`
    /// (драйвер при этом ещё не трогается).
    pub fn new(redirect_port: u16) -> Self {
        Self {
            redirect_port,
            active: false,
        }
    }

    /// Порт локального прокси, на который драйвер перенаправляет соединения.
    pub fn redirect_port(&self) -> u16 {
        self.redirect_port
    }

    /// Открывает управляющее устройство драйвера. Понятные ошибки:
    /// драйвер не загружен / нет прав администратора.
    fn open_device() -> Result<HANDLE, SplitError> {
        let path = wide(USER_MODE_DEVICE_PATH);
        // SAFETY: path — валидная NUL-терминированная UTF-16 строка; прочие
        // аргументы соответствуют контракту CreateFileW.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            // SAFETY: чтение кода последней ошибки потока.
            let code = unsafe { GetLastError() };
            return Err(match code {
                ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => {
                    SplitError::Backend("драйвер split не загружен".into())
                }
                ERROR_ACCESS_DENIED => SplitError::AccessDenied,
                other => SplitError::Backend(format!("CreateFile(JammVpnSplit): код {other}")),
            });
        }
        Ok(handle)
    }

    /// Отправляет IOCTL с входным буфером (без выходного) на устройство.
    fn ioctl(handle: HANDLE, code: u32, input: &[u8]) -> Result<(), SplitError> {
        let mut returned: u32 = 0;
        // SAFETY: handle валиден; input живёт на время вызова; выходного буфера нет.
        let ok = unsafe {
            DeviceIoControl(
                handle,
                code,
                input.as_ptr() as *const core::ffi::c_void,
                input.len() as u32,
                ptr::null_mut(),
                0,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            // SAFETY: чтение кода последней ошибки потока.
            let c = unsafe { GetLastError() };
            return Err(SplitError::Backend(format!("DeviceIoControl: код {c}")));
        }
        Ok(())
    }
}

impl SplitController for WfpDriverController {
    fn apply(&mut self, config: &SplitConfig) -> Result<(), SplitError> {
        // PID процесса, принимающего перенаправленные соединения — это сам
        // процесс с прокси (где работает WfpDriverController).
        let dc = DriverConfig::from_split_config(config, self.redirect_port, std::process::id())
            .map_err(|e| SplitError::Backend(e.to_string()))?;
        let bytes = encode_config(&dc);
        let handle = Self::open_device()?;
        let res = Self::ioctl(handle, IOCTL_JAMM_SET_CONFIG, &bytes);
        // SAFETY: закрываем валидный дескриптор устройства.
        unsafe { CloseHandle(handle) };
        res?;
        self.active = true;
        Ok(())
    }

    fn clear(&mut self) -> Result<(), SplitError> {
        let handle = Self::open_device()?;
        let res = Self::ioctl(handle, IOCTL_JAMM_CLEAR, &[]);
        // SAFETY: закрываем валидный дескриптор устройства.
        unsafe { CloseHandle(handle) };
        res?;
        self.active = false;
        Ok(())
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

/// UTF-16 строка с завершающим нулём (для широких WinAPI).
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_controller_is_inactive() {
        let c = WfpDriverController::new(39001);
        assert_eq!(c.redirect_port(), 39001);
        assert!(!c.is_active());
    }

    #[test]
    fn apply_handles_missing_driver_gracefully() {
        // В тестовой среде драйвер не загружен → open устройства падает, apply
        // возвращает ошибку (не панику). Если же драйвер вдруг загружен —
        // apply проходит и набор активен; тогда снимаем его, чтобы не оставить следов.
        let mut c = WfpDriverController::new(39001);
        match c.apply(&SplitConfig::default()) {
            Err(SplitError::Backend(_)) | Err(SplitError::AccessDenied) => {
                assert!(!c.is_active());
            }
            Ok(()) => {
                assert!(c.is_active());
                let _ = c.clear();
            }
            Err(other) => panic!("неожиданная ошибка: {other}"),
        }
    }
}
