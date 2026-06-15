//! Шифрование секретов «на месте» (OS-backed) и защита секретных полей конфига
//! (ТЗ, раздел 7 + безопасность). Пароли/ключи/UUID не хранятся в плейнтексте.
//!
//! Кроссплатформенно: трейт [`SecretStore`] здесь, реализация — в платформенном
//! слое (DPAPI на Windows; Keychain/Keystore — позже). На диске секретные
//! значения параметров получают префикс `enc:<base64(blob)>`.

use crate::base64;
use crate::config::AppConfig;
use std::fmt;

/// Префикс зашифрованного значения: `enc:<base64(blob)>`.
const ENC_PREFIX: &str = "enc:";

/// Ключи параметров профиля, считающиеся секретными.
pub const SECRET_PARAM_KEYS: &[&str] = &[
    "password",
    "uuid",
    "private_key",
    "preshared_key",
    "auth",
    "obfs-password",
];

/// Ошибка операции с секрет-хранилищем.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretError(pub String);

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ошибка секрет-хранилища: {}", self.0)
    }
}

impl std::error::Error for SecretError {}

/// OS-backed шифратор секретов (DPAPI на Windows, Keychain/Keystore — позже).
///
/// `protect`/`unprotect` оперируют сырыми байтами; привязка к пользователю/машине
/// — на усмотрение реализации (DPAPI: к учётной записи пользователя).
pub trait SecretStore {
    /// Шифрует байты.
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecretError>;
    /// Расшифровывает байты, ранее зашифрованные [`Self::protect`].
    fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecretError>;
}

/// Заглушка без шифрования — для тестов и платформ без OS-хранилища.
/// **Не использовать для реальных секретов.**
pub struct NoopStore;

impl SecretStore for NoopStore {
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
        Ok(plaintext.to_vec())
    }
    fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecretError> {
        Ok(ciphertext.to_vec())
    }
}

/// `true`, если значение уже зашифровано (имеет префикс `enc:`).
pub fn is_protected(value: &str) -> bool {
    value.starts_with(ENC_PREFIX)
}

/// Шифрует все секретные значения параметров серверов на месте
/// (`plaintext` → `enc:<base64>`). Уже зашифрованные пропускаются (идемпотентно).
pub fn protect_config(cfg: &mut AppConfig, store: &dyn SecretStore) -> Result<(), SecretError> {
    for server in &mut cfg.servers {
        for key in SECRET_PARAM_KEYS {
            if let Some(val) = server.params.get_mut(*key) {
                if !is_protected(val) {
                    let blob = store.protect(val.as_bytes())?;
                    *val = format!("{ENC_PREFIX}{}", base64::encode_standard(&blob));
                }
            }
        }
    }
    Ok(())
}

/// Расшифровывает все секретные значения (`enc:<base64>` → `plaintext`) на месте.
/// Незашифрованные значения пропускаются.
pub fn unprotect_config(cfg: &mut AppConfig, store: &dyn SecretStore) -> Result<(), SecretError> {
    for server in &mut cfg.servers {
        for key in SECRET_PARAM_KEYS {
            if let Some(val) = server.params.get_mut(*key) {
                if let Some(b64) = val.strip_prefix(ENC_PREFIX) {
                    let blob = base64::decode_loose(b64)
                        .map_err(|e| SecretError(format!("base64: {e}")))?;
                    let plain = store.unprotect(&blob)?;
                    *val =
                        String::from_utf8(plain).map_err(|e| SecretError(format!("utf8: {e}")))?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ProtocolKind, ServerProfile};
    use std::collections::BTreeMap;

    /// Стор, имитирующий DPAPI: оборачивает байты (чтобы шифртекст ≠ плейнтекст).
    struct FakeStore;
    impl SecretStore for FakeStore {
        fn protect(&self, p: &[u8]) -> Result<Vec<u8>, SecretError> {
            let mut v = b"DPAPI:".to_vec();
            v.extend_from_slice(p);
            Ok(v)
        }
        fn unprotect(&self, c: &[u8]) -> Result<Vec<u8>, SecretError> {
            c.strip_prefix(b"DPAPI:".as_slice())
                .map(|s| s.to_vec())
                .ok_or_else(|| SecretError("плохой блоб".into()))
        }
    }

    fn cfg_with_secret(pw: &str) -> AppConfig {
        let mut params = BTreeMap::new();
        params.insert("password".to_string(), pw.to_string());
        params.insert("method".to_string(), "aes-256-gcm".to_string());
        let mut cfg = AppConfig::default();
        cfg.servers.push(ServerProfile {
            name: "s".into(),
            protocol: ProtocolKind::Shadowsocks,
            address: "h".into(),
            port: 8388,
            params,
            tags: vec![],
        });
        cfg
    }

    #[test]
    fn protect_then_unprotect_roundtrips() {
        let store = FakeStore;
        let mut cfg = cfg_with_secret("hunter2");

        protect_config(&mut cfg, &store).unwrap();
        let pw = cfg.servers[0].params.get("password").unwrap();
        assert!(is_protected(pw), "пароль зашифрован");
        assert!(!pw.contains("hunter2"), "плейнтекст не виден");
        // несекретные поля не тронуты.
        assert_eq!(cfg.servers[0].params.get("method").unwrap(), "aes-256-gcm");

        unprotect_config(&mut cfg, &store).unwrap();
        assert_eq!(cfg.servers[0].params.get("password").unwrap(), "hunter2");
    }

    #[test]
    fn protect_is_idempotent() {
        let store = FakeStore;
        let mut cfg = cfg_with_secret("pw");
        protect_config(&mut cfg, &store).unwrap();
        let once = cfg.servers[0].params.get("password").unwrap().clone();
        protect_config(&mut cfg, &store).unwrap();
        assert_eq!(
            cfg.servers[0].params.get("password").unwrap(),
            &once,
            "двойное шифрование не происходит"
        );
    }

    #[test]
    fn noop_store_is_transparent() {
        let mut cfg = cfg_with_secret("pw");
        protect_config(&mut cfg, &NoopStore).unwrap();
        // NoopStore не шифрует, но префикс enc: + base64 всё равно навешивается.
        unprotect_config(&mut cfg, &NoopStore).unwrap();
        assert_eq!(cfg.servers[0].params.get("password").unwrap(), "pw");
    }
}
