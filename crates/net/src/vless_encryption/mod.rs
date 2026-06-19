//! VLESS Encryption (`encryption=`/`decryption=`) — пост-квантовый слой Xray
//! (ML-KEM-768 + X25519). Спецификация: XTLS/Xray-core PR #5067, пакет
//! `proxy/vless/encryption`. Здесь — разбор клиентского дескриптора
//! `mlkem768x25519plus.<mode>.<rtt>.<key>[.padding...]`.
//!
//! ПОРТ В РАБОТЕ: парсинг дескриптора + AEAD-слой; handshake/stream —
//! отлаживаются против локального эталонного Xray (см. planning/xray/).

mod aead;
mod handshake;
mod stream;

pub use stream::VlessEncStream;

use tokio::io::{AsyncRead, AsyncWrite};

/// Выполняет клиентский handshake VLESS Encryption поверх `transport` и
/// возвращает прозрачный шифрующий поток (на нём дальше идёт обычный VLESS).
pub async fn wrap_client<S>(
    mut transport: S,
    enc: &VlessEncryption,
) -> std::io::Result<VlessEncStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let st = handshake::client_handshake(&mut transport, enc).await?;
    Ok(VlessEncStream::new(transport, st))
}

/// Способ упаковки клиентского hello.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncMode {
    /// Сырой формат пакета.
    Native,
    /// Сырой формат + обфускация публичной части (XOR).
    Xorpub,
    /// Полностью случайные байты (как VMess/SS).
    Random,
}

/// Тип NFS-аутентификации (статический ключ сервера).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NfsKey {
    /// X25519 публичный ключ (32 байта) — не пост-квантовый NFS-слой.
    X25519([u8; 32]),
    /// ML-KEM-768 encapsulation key (1184 байта) — пост-квантовый NFS-слой.
    MlKem768(Box<[u8; 1184]>),
}

/// Разобранный клиентский дескриптор VLESS Encryption.
#[derive(Debug, Clone)]
pub struct VlessEncryption {
    pub mode: EncMode,
    /// `true` — клиент готов к 0-RTT (переиспользование тикета); иначе 1-RTT.
    pub zero_rtt: bool,
    /// Статический публичный ключ сервера (NFS-слой).
    pub nfs_key: NfsKey,
    /// Сырые поля паддинга (если заданы) — для совместимости; пока не применяются.
    pub padding: Vec<String>,
}

/// Разбирает клиентский дескриптор `mlkem768x25519plus.<mode>.<rtt>.<key>[...]`.
/// Возвращает `Ok(None)`, если encryption выключен (`none`/пусто).
pub fn parse_encryption(desc: &str) -> Result<Option<VlessEncryption>, String> {
    let desc = desc.trim();
    if desc.is_empty() || desc == "none" {
        return Ok(None);
    }
    let parts: Vec<&str> = desc.split('.').collect();
    if parts.len() < 4 || parts[0] != "mlkem768x25519plus" {
        return Err(format!("неподдерживаемый VLESS encryption: «{desc}»"));
    }
    let mode = match parts[1] {
        "native" => EncMode::Native,
        "xorpub" => EncMode::Xorpub,
        "random" => EncMode::Random,
        m => return Err(format!("неизвестный режим VLESS encryption: «{m}»")),
    };
    let zero_rtt = match parts[2] {
        "0rtt" => true,
        "1rtt" => false,
        r => return Err(format!("ожидался 0rtt/1rtt, получено «{r}»")),
    };
    let key_bytes = base64url_decode(parts[3])
        .ok_or_else(|| "не удалось декодировать ключ VLESS encryption".to_string())?;
    let nfs_key = match key_bytes.len() {
        32 => {
            let mut k = [0u8; 32];
            k.copy_from_slice(&key_bytes);
            NfsKey::X25519(k)
        }
        1184 => {
            let mut k = Box::new([0u8; 1184]);
            k.copy_from_slice(&key_bytes);
            NfsKey::MlKem768(k)
        }
        n => return Err(format!("неожиданная длина ключа VLESS encryption: {n} (ожидалось 32 или 1184)")),
    };
    Ok(Some(VlessEncryption {
        mode,
        zero_rtt,
        nfs_key,
        padding: parts[4..].iter().map(|s| s.to_string()).collect(),
    }))
}

/// Декод base64url (с паддингом и без). Xray использует RawURLEncoding.
fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let s = s.trim_end_matches('=');
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_x25519_native_0rtt() {
        // Реальный клиентский ключ пользователя (X25519, 32 байта).
        let d = "mlkem768x25519plus.native.0rtt.Qs2nH0O7LoolWDPF9ryXuikLR0lZreHc_nLKCSTnihQ";
        let e = parse_encryption(d).unwrap().unwrap();
        assert_eq!(e.mode, EncMode::Native);
        assert!(e.zero_rtt);
        assert!(matches!(e.nfs_key, NfsKey::X25519(_)));
        assert!(e.padding.is_empty());
    }

    #[test]
    fn none_and_empty() {
        assert!(parse_encryption("none").unwrap().is_none());
        assert!(parse_encryption("").unwrap().is_none());
    }

    #[test]
    fn rejects_unknown() {
        assert!(parse_encryption("vmess.native.0rtt.AAAA").is_err());
        assert!(parse_encryption("mlkem768x25519plus.weird.0rtt.AAAA").is_err());
    }
}
