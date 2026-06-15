//! Автозапуск при входе в Windows через реестр `HKCU\…\Run`.
//!
//! Значение `JammVPN` в ключе `Run` текущего пользователя содержит команду
//! запуска (путь к exe в кавычках + `--minimized`). Включение перезаписывает
//! команду актуальной (чинит устаревший путь), выключение удаляет значение.
//! Scope — текущий пользователь, прав администратора не требуется.

use std::ptr;
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW,
    RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE,
    REG_OPTION_NON_VOLATILE, REG_SZ,
};

/// Подключ автозапуска текущего пользователя.
const RUN_SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
/// Имя значения автозапуска приложения.
const VALUE_NAME: &str = "JammVPN";

/// UTF-16 строка с завершающим нулём (для широких WinAPI).
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Записывает значение `name` = `command` (REG_SZ) в ключ `Run`.
fn enable_named(name: &str, command: &str) -> Result<(), String> {
    let subkey = wide(RUN_SUBKEY);
    let mut hkey: HKEY = ptr::null_mut();
    // SAFETY: открываем/создаём ключ Run с правом записи значений; указатели валидны.
    let rc = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            ptr::null(),
            &mut hkey,
            ptr::null_mut(),
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(format!("RegCreateKeyExW(Run): код {rc}"));
    }
    let name_w = wide(name);
    let data = wide(command);
    let bytes = data.len() * 2; // размер в байтах, включая завершающий нуль.
    // SAFETY: hkey валиден; data живёт до RegCloseKey; cbData — размер в байтах.
    let rc = unsafe {
        RegSetValueExW(
            hkey,
            name_w.as_ptr(),
            0,
            REG_SZ,
            data.as_ptr() as *const u8,
            bytes as u32,
        )
    };
    // SAFETY: закрываем валидный дескриптор ключа.
    unsafe { RegCloseKey(hkey) };
    if rc != ERROR_SUCCESS {
        return Err(format!("RegSetValueExW({name}): код {rc}"));
    }
    Ok(())
}

/// Удаляет значение `name` из ключа `Run` (отсутствие — это успех).
fn disable_named(name: &str) -> Result<(), String> {
    let subkey = wide(RUN_SUBKEY);
    let mut hkey: HKEY = ptr::null_mut();
    // SAFETY: открываем ключ Run на запись; указатели валидны.
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut hkey,
        )
    };
    if rc != ERROR_SUCCESS {
        // Ключа Run нет → автозапуска и так нет.
        return Ok(());
    }
    let name_w = wide(name);
    // SAFETY: hkey валиден; удаляем именованное значение.
    let rc = unsafe { RegDeleteValueW(hkey, name_w.as_ptr()) };
    // SAFETY: закрываем дескриптор ключа.
    unsafe { RegCloseKey(hkey) };
    if rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        Err(format!("RegDeleteValueW({name}): код {rc}"))
    }
}

/// Присутствует ли значение `name` в ключе `Run`.
fn is_enabled_named(name: &str) -> Result<bool, String> {
    let subkey = wide(RUN_SUBKEY);
    let mut hkey: HKEY = ptr::null_mut();
    // SAFETY: открываем ключ Run на чтение; указатели валидны.
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut hkey,
        )
    };
    if rc != ERROR_SUCCESS {
        return Ok(false);
    }
    let name_w = wide(name);
    // SAFETY: проверяем наличие значения (данные не читаем: lpData/lpcbData = null).
    let rc = unsafe {
        RegQueryValueExW(
            hkey,
            name_w.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    // SAFETY: закрываем дескриптор ключа.
    unsafe { RegCloseKey(hkey) };
    Ok(rc == ERROR_SUCCESS)
}

/// Включает автозапуск: пишет `"<exe_path>" --minimized` в значение `JammVPN`.
pub fn enable(exe_path: &str) -> Result<(), String> {
    enable_named(VALUE_NAME, &format!("\"{exe_path}\" --minimized"))
}

/// Выключает автозапуск: удаляет значение `JammVPN`.
pub fn disable() -> Result<(), String> {
    disable_named(VALUE_NAME)
}

/// Включён ли автозапуск (присутствует ли значение `JammVPN`).
pub fn is_enabled() -> Result<bool, String> {
    is_enabled_named(VALUE_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autostart_roundtrip() {
        // Уникальное имя значения, чтобы не задеть реальный автозапуск пользователя.
        let name = format!("JammVPN-test-{}", std::process::id());

        // Изначально значения нет.
        assert!(!is_enabled_named(&name).unwrap());

        enable_named(&name, "\"C:\\x.exe\" --minimized").unwrap();
        assert!(is_enabled_named(&name).unwrap());

        disable_named(&name).unwrap();
        assert!(!is_enabled_named(&name).unwrap());

        // Повторное удаление отсутствующего значения — тоже Ok.
        disable_named(&name).unwrap();
    }
}
