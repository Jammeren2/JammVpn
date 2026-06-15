//! DPAPI-реализация [`SecretStore`] (Windows).
//!
//! Шифрование привязано к учётной записи текущего пользователя
//! (`CryptProtectData` без `LOCAL_MACHINE`). Зашифрованные блобы непортируемы на
//! другую машину/пользователя — это намеренно: защита секретов at-rest.

use jammvpn_core::secret::{SecretError, SecretStore};
use std::ptr;
use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
};

/// Не показывать UI (вернуть ошибку вместо запроса) — для headless-режима.
const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

/// Шифратор секретов на Windows DPAPI (scope = текущий пользователь).
#[derive(Debug, Clone, Copy, Default)]
pub struct DpapiStore;

impl SecretStore for DpapiStore {
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
        crypt(plaintext, true)
    }

    fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecretError> {
        crypt(ciphertext, false)
    }
}

/// Общая обёртка над `CryptProtectData`/`CryptUnprotectData`.
fn crypt(data: &[u8], protect: bool) -> Result<Vec<u8>, SecretError> {
    // Копируем вход в собственный буфер: поле `pbData` имеет тип `*mut u8`, а
    // приведение `*const`→`*mut` к заимствованным `data` нарушало бы инварианты
    // алиасинга Rust (DPAPI вход не изменяет, но компилятор это не гарантирует).
    let mut owned = data.to_vec();
    let input = CRYPT_INTEGER_BLOB {
        cbData: owned.len() as u32,
        pbData: owned.as_mut_ptr(),
    };
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    // SAFETY: указатели/длины валидны; out заполняется DPAPI (память освобождаем
    // ниже через LocalFree).
    let ok = unsafe {
        if protect {
            CryptProtectData(
                &input,
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        } else {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        }
    };

    if ok == 0 {
        // SAFETY: чтение кода последней ошибки потока.
        let code = unsafe { GetLastError() };
        let op = if protect {
            "CryptProtectData"
        } else {
            "CryptUnprotectData"
        };
        return Err(SecretError(format!("DPAPI {op}: код ошибки {code}")));
    }

    // SAFETY: при успехе out.pbData указывает на out.cbData валидных байт.
    let result = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec() };
    // SAFETY: освобождаем буфер, выделенный DPAPI (LocalAlloc).
    unsafe {
        LocalFree(out.pbData as _);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jammvpn_core::AppConfig;

    #[test]
    fn dpapi_roundtrip() {
        let store = DpapiStore;
        let secret = b"my-vpn-password-\x00\xff-binary";
        let enc = store.protect(secret).expect("protect");
        assert_ne!(enc.as_slice(), secret.as_slice(), "шифртекст != плейнтекст");
        let dec = store.unprotect(&enc).expect("unprotect");
        assert_eq!(dec.as_slice(), secret.as_slice());
    }

    #[test]
    fn dpapi_unprotect_garbage_errors() {
        let store = DpapiStore;
        // Случайные байты — не валидный DPAPI-блоб.
        assert!(store.unprotect(&[1, 2, 3, 4, 5, 6, 7, 8]).is_err());
    }

    #[test]
    fn config_save_load_protected_via_dpapi() {
        use jammvpn_core::model::{ProtocolKind, ServerProfile};
        use std::collections::BTreeMap;

        let mut params = BTreeMap::new();
        params.insert("password".to_string(), "topsecret".to_string());
        let mut cfg = AppConfig::default();
        cfg.servers.push(ServerProfile {
            name: "s".into(),
            protocol: ProtocolKind::Shadowsocks,
            address: "h".into(),
            port: 8388,
            params,
            tags: vec![],
        });

        let dir = std::env::temp_dir();
        let path = dir.join(format!("jammvpn-dpapi-test-{}.json", std::process::id()));

        cfg.save_protected(&path, &DpapiStore)
            .expect("save_protected");

        // На диске пароль зашифрован (нет плейнтекста, есть enc:).
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(!on_disk.contains("topsecret"), "плейнтекст не на диске");
        assert!(on_disk.contains("enc:"), "секрет помечен enc:");

        let loaded = AppConfig::load_protected(&path, &DpapiStore).expect("load_protected");
        assert_eq!(
            loaded.servers[0].params.get("password").unwrap(),
            "topsecret"
        );

        let _ = std::fs::remove_file(&path);
    }
}
