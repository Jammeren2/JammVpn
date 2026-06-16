//! Системный прокси Windows (WinINET) через реестр `Internet Settings`.
//!
//! Прописывает `ProxyEnable`/`ProxyServer`/`ProxyOverride` в
//! `HKCU\…\Internet Settings` и уведомляет WinINET (`InternetSetOptionW`), чтобы
//! приложения, использующие системный прокси (браузеры и т. п.), пошли через наш
//! локальный прокси. Сервер задаётся без префикса протокола — значит и для HTTP,
//! и для HTTPS (CONNECT); наш локальный inbound понимает оба (см. `net::engine`).

use std::ptr;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::Networking::WinInet::{
    InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER,
    KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD, REG_SZ,
};

const SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

/// Список «в обход» по умолчанию: loopback, LAN и локальные имена.
pub const DEFAULT_BYPASS: &str = "localhost;127.*;10.*;172.16.*;192.168.*;<local>";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Открывает ключ Internet Settings с заданным доступом.
fn open_key(access: u32) -> Result<HKEY, String> {
    let subkey = wide(SUBKEY);
    let mut hkey: HKEY = ptr::null_mut();
    // SAFETY: указатели валидны; ключ существует в любой установке Windows.
    let rc = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, access, &mut hkey) };
    if rc != ERROR_SUCCESS {
        return Err(format!("RegOpenKeyExW(Internet Settings): код {rc}"));
    }
    Ok(hkey)
}

fn set_dword(hkey: HKEY, name: &str, value: u32) -> Result<(), String> {
    let name_w = wide(name);
    let bytes = value.to_ne_bytes();
    // SAFETY: hkey валиден; буфер 4 байта живёт на время вызова.
    let rc = unsafe {
        RegSetValueExW(hkey, name_w.as_ptr(), 0, REG_DWORD, bytes.as_ptr(), 4)
    };
    if rc != ERROR_SUCCESS {
        return Err(format!("RegSetValueExW({name}): код {rc}"));
    }
    Ok(())
}

fn set_sz(hkey: HKEY, name: &str, value: &str) -> Result<(), String> {
    let name_w = wide(name);
    let data = wide(value);
    let bytes = data.len() * 2;
    // SAFETY: hkey валиден; data живёт на время вызова; размер в байтах с нулём.
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
    if rc != ERROR_SUCCESS {
        return Err(format!("RegSetValueExW({name}): код {rc}"));
    }
    Ok(())
}

/// Уведомляет WinINET о смене настроек прокси (без перезапуска приложений).
fn notify() {
    // SAFETY: вызов без буфера; null-хендл = глобальные настройки.
    unsafe {
        InternetSetOptionW(ptr::null_mut(), INTERNET_OPTION_SETTINGS_CHANGED, ptr::null(), 0);
        InternetSetOptionW(ptr::null_mut(), INTERNET_OPTION_REFRESH, ptr::null(), 0);
    }
}

/// Включает системный прокси: `proxy` вида `127.0.0.1:1080`, `bypass` — список
/// исключений (можно [`DEFAULT_BYPASS`]).
pub fn set(proxy: &str, bypass: &str) -> Result<(), String> {
    let hkey = open_key(KEY_SET_VALUE)?;
    let res: Result<(), String> = (|| {
        set_dword(hkey, "ProxyEnable", 1)?;
        set_sz(hkey, "ProxyServer", proxy)?;
        set_sz(hkey, "ProxyOverride", bypass)?;
        Ok(())
    })();
    // SAFETY: закрываем валидный дескриптор.
    unsafe { RegCloseKey(hkey) };
    res?;
    notify();
    Ok(())
}

/// Выключает системный прокси (`ProxyEnable = 0`).
pub fn clear() -> Result<(), String> {
    let hkey = open_key(KEY_SET_VALUE)?;
    let res = set_dword(hkey, "ProxyEnable", 0);
    // SAFETY: закрываем валидный дескриптор.
    unsafe { RegCloseKey(hkey) };
    res?;
    notify();
    Ok(())
}

/// Текущее состояние: включён ли прокси и значение `ProxyServer`.
pub fn status() -> Result<(bool, Option<String>), String> {
    let hkey = open_key(KEY_QUERY_VALUE)?;
    let enabled = query_dword(hkey, "ProxyEnable").unwrap_or(0) != 0;
    let server = query_sz(hkey, "ProxyServer").filter(|s| !s.is_empty());
    // SAFETY: закрываем валидный дескриптор.
    unsafe { RegCloseKey(hkey) };
    Ok((enabled, server))
}

fn query_dword(hkey: HKEY, name: &str) -> Option<u32> {
    let name_w = wide(name);
    let mut buf = [0u8; 4];
    let mut len: u32 = 4;
    let mut ty: u32 = 0;
    // SAFETY: hkey валиден; буфер 4 байта; len ин-аут.
    let rc = unsafe {
        RegQueryValueExW(
            hkey,
            name_w.as_ptr(),
            ptr::null(),
            &mut ty,
            buf.as_mut_ptr(),
            &mut len,
        )
    };
    if rc == ERROR_SUCCESS && ty == REG_DWORD {
        Some(u32::from_ne_bytes(buf))
    } else {
        None
    }
}

fn query_sz(hkey: HKEY, name: &str) -> Option<String> {
    let name_w = wide(name);
    let mut len: u32 = 0;
    // SAFETY: первый вызов узнаёт размер (lpData = null).
    let rc = unsafe {
        RegQueryValueExW(
            hkey,
            name_w.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut len,
        )
    };
    if rc != ERROR_SUCCESS || len == 0 {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    let mut ty: u32 = 0;
    // SAFETY: буфер нужного размера; len ин-аут.
    let rc = unsafe {
        RegQueryValueExW(
            hkey,
            name_w.as_ptr(),
            ptr::null(),
            &mut ty,
            buf.as_mut_ptr(),
            &mut len,
        )
    };
    if rc != ERROR_SUCCESS || ty != REG_SZ {
        return None;
    }
    // UTF-16LE → String (без завершающего нуля).
    let wide: Vec<u16> = buf[..len as usize]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0)
        .collect();
    Some(String::from_utf16_lossy(&wide))
}
