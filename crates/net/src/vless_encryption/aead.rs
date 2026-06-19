//! AEAD-обёртка VLESS Encryption (порт `common.go` NewAEAD/Seal/Open/Nonce).
//!
//! Ключ = `blake3::derive_key(ctx, key)` (32 байта) → AES-256-GCM (если есть
//! аппаратный AES) или ChaCha20-Poly1305. Nonce — 12-байтный big-endian
//! счётчик: `Seal`/`Open` без явного nonce инкрементируют ПЕРЕД использованием
//! (первый nonce = …0001). `MaxNonce` (все 0xFF) используется явно для
//! серверного pfsPublicKey.

use aes_gcm::aead::{Aead as _, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use std::io;

/// Все 0xFF — особый nonce для серверного pfsPublicKey (см. client.go).
pub const MAX_NONCE: [u8; 12] = [0xFF; 12];

enum Cipher {
    Aes(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

/// AEAD с внутренним nonce-счётчиком (как `*AEAD` в Go).
pub struct Aead {
    cipher: Cipher,
    nonce: [u8; 12],
}

impl Aead {
    /// `NewAEAD(ctx, key, useAES)`: ключ выводится BLAKE3-derive_key. `ctx` —
    /// произвольные байты (Go берёт `string(ctx)`; повторяем побайтно).
    pub fn new(ctx: &[u8], key: &[u8], use_aes: bool) -> Self {
        // blake3 crate требует &str для контекста; derive_key хеширует его байты,
        // поэтому безопасно переинтерпретируем произвольные байты как &str
        // (ровно то, что делает Go `string(ctx)`).
        let ctx_str = unsafe { std::str::from_utf8_unchecked(ctx) };
        let k = blake3::derive_key(ctx_str, key); // [u8; 32]
        let cipher = if use_aes {
            Cipher::Aes(Box::new(Aes256Gcm::new(k.as_ref().into())))
        } else {
            Cipher::ChaCha(Box::new(ChaCha20Poly1305::new(k.as_ref().into())))
        };
        Aead {
            cipher,
            nonce: [0u8; 12],
        }
    }

    /// Достигнут ли потолок nonce (нужна смена ключа).
    pub fn at_max(&self) -> bool {
        self.nonce == MAX_NONCE
    }

    fn increase(&mut self) -> [u8; 12] {
        for i in 0..12 {
            self.nonce[11 - i] = self.nonce[11 - i].wrapping_add(1);
            if self.nonce[11 - i] != 0 {
                break;
            }
        }
        self.nonce
    }

    fn enc(&self, nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let p = Payload { msg: plaintext, aad };
        match &self.cipher {
            Cipher::Aes(c) => c.encrypt(nonce.into(), p),
            Cipher::ChaCha(c) => c.encrypt(nonce.into(), p),
        }
        .expect("AEAD seal не должен падать")
    }

    fn dec(&self, nonce: &[u8; 12], ct: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
        let p = Payload { msg: ct, aad };
        match &self.cipher {
            Cipher::Aes(c) => c.decrypt(nonce.into(), p),
            Cipher::ChaCha(c) => c.decrypt(nonce.into(), p),
        }
        .map_err(|_| io::Error::other("VLESS encryption: ошибка расшифровки (AEAD)"))
    }

    /// `Seal` с авто-инкрементом nonce.
    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let n = self.increase();
        self.enc(&n, plaintext, aad)
    }

    /// `Seal` с явным nonce (без инкремента счётчика).
    pub fn seal_with(&self, nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        self.enc(nonce, plaintext, aad)
    }

    /// `Open` с авто-инкрементом nonce.
    pub fn open(&mut self, ct: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
        let n = self.increase();
        self.dec(&n, ct, aad)
    }

    /// `Open` с явным nonce (без инкремента счётчика).
    pub fn open_with(&self, nonce: &[u8; 12], ct: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
        self.dec(nonce, ct, aad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_nonce_order() {
        let mut a = Aead::new(b"ctx-bytes", &[7u8; 32], true);
        let mut b = Aead::new(b"ctx-bytes", &[7u8; 32], true);
        // Параллельные счётчики: seal на одном, open на другом — nonce совпадают.
        let c1 = a.seal(b"hello", b"aad1");
        let p1 = b.open(&c1, b"aad1").unwrap();
        assert_eq!(p1, b"hello");
        let c2 = a.seal(b"world", b"");
        let p2 = b.open(&c2, b"").unwrap();
        assert_eq!(p2, b"world");
        // Неверный AAD → ошибка.
        let c3 = a.seal(b"x", b"good");
        assert!(b.open(&c3, b"bad").is_err());
    }

    #[test]
    fn nonce_is_big_endian_counter() {
        let mut a = Aead::new(b"c", &[1u8; 32], false);
        a.increase();
        assert_eq!(a.nonce, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        a.nonce = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF];
        a.increase();
        assert_eq!(a.nonce, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
    }
}
