//! Криптография Shadowsocks AEAD: деривация ключей и операции seal/open.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use generic_array::GenericArray;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use sha1::Sha1;
use std::io;

/// AEAD-метод Shadowsocks (legacy AEAD + SS-2022/SIP022 на BLAKE3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `aes-128-gcm`
    Aes128Gcm,
    /// `aes-256-gcm`
    Aes256Gcm,
    /// `chacha20-ietf-poly1305`
    Chacha20IetfPoly1305,
    /// `2022-blake3-aes-128-gcm`
    Ss2022Aes128Gcm,
    /// `2022-blake3-aes-256-gcm`
    Ss2022Aes256Gcm,
    /// `2022-blake3-chacha20-poly1305`
    Ss2022Chacha20Poly1305,
}

/// Базовый AEAD-шифр (общий для legacy и 2022).
#[derive(Clone, Copy)]
enum Cipher {
    Aes128,
    Aes256,
    Chacha,
}

impl Method {
    /// Распознаёт метод по имени из конфига.
    pub fn from_name(s: &str) -> Option<Method> {
        match s.to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Some(Method::Aes128Gcm),
            "aes-256-gcm" => Some(Method::Aes256Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Some(Method::Chacha20IetfPoly1305),
            "2022-blake3-aes-128-gcm" => Some(Method::Ss2022Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Some(Method::Ss2022Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => Some(Method::Ss2022Chacha20Poly1305),
            _ => None,
        }
    }

    /// Длина ключа в байтах.
    pub fn key_len(self) -> usize {
        match self {
            Method::Aes128Gcm | Method::Ss2022Aes128Gcm => 16,
            Method::Aes256Gcm
            | Method::Chacha20IetfPoly1305
            | Method::Ss2022Aes256Gcm
            | Method::Ss2022Chacha20Poly1305 => 32,
        }
    }

    /// Длина соли (равна длине ключа).
    pub fn salt_len(self) -> usize {
        self.key_len()
    }

    /// `true` для методов SS-2022 (BLAKE3-деривация + структурный заголовок).
    pub fn is_2022(self) -> bool {
        matches!(
            self,
            Method::Ss2022Aes128Gcm | Method::Ss2022Aes256Gcm | Method::Ss2022Chacha20Poly1305
        )
    }

    /// `true` для `2022-blake3-chacha20-poly1305` (UDP: XChaCha, без separate header).
    pub fn is_chacha2022(self) -> bool {
        matches!(self, Method::Ss2022Chacha20Poly1305)
    }

    fn cipher(self) -> Cipher {
        match self {
            Method::Aes128Gcm | Method::Ss2022Aes128Gcm => Cipher::Aes128,
            Method::Aes256Gcm | Method::Ss2022Aes256Gcm => Cipher::Aes256,
            Method::Chacha20IetfPoly1305 | Method::Ss2022Chacha20Poly1305 => Cipher::Chacha,
        }
    }
}

/// EVP_BytesToKey (MD5) — мастер-ключ из пароля (как в Shadowsocks).
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len + 16);
    let mut prev: Vec<u8> = Vec::new();
    while key.len() < key_len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(password);
        let digest = h.finalize();
        key.extend_from_slice(digest.as_slice());
        prev = digest.to_vec();
    }
    key.truncate(key_len);
    key
}

/// Сессионный подключ (legacy AEAD): HKDF-SHA1(master, salt, "ss-subkey").
pub fn session_subkey(method: Method, master: &[u8], salt: &[u8]) -> Vec<u8> {
    let hk = Hkdf::<Sha1>::new(Some(salt), master);
    let mut okm = vec![0u8; method.key_len()];
    hk.expand(b"ss-subkey", &mut okm)
        .expect("hkdf expand: фиксированная длина");
    okm
}

/// Сессионный подключ SS-2022 (SIP022):
/// `BLAKE3_derive_key("shadowsocks 2022 session subkey", PSK || salt)[..key_len]`.
pub fn session_subkey_2022(method: Method, psk: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut material = Vec::with_capacity(psk.len() + salt.len());
    material.extend_from_slice(psk);
    material.extend_from_slice(salt);
    let derived = blake3::derive_key("shadowsocks 2022 session subkey", &material);
    derived[..method.key_len()].to_vec()
}

enum AeadKey {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    Chacha(Box<ChaCha20Poly1305>),
}

impl AeadKey {
    fn new(method: Method, subkey: &[u8]) -> io::Result<Self> {
        let res = match method.cipher() {
            Cipher::Aes128 => {
                Aes128Gcm::new_from_slice(subkey).map(|c| AeadKey::Aes128(Box::new(c)))
            }
            Cipher::Aes256 => {
                Aes256Gcm::new_from_slice(subkey).map(|c| AeadKey::Aes256(Box::new(c)))
            }
            Cipher::Chacha => {
                ChaCha20Poly1305::new_from_slice(subkey).map(|c| AeadKey::Chacha(Box::new(c)))
            }
        };
        res.map_err(|_| io::Error::other("ss: неверная длина подключа"))
    }

    fn seal(&self, nonce: &[u8; 12], pt: &[u8]) -> io::Result<Vec<u8>> {
        let result = match self {
            AeadKey::Aes128(c) => c.encrypt(GenericArray::from_slice(nonce), pt),
            AeadKey::Aes256(c) => c.encrypt(GenericArray::from_slice(nonce), pt),
            AeadKey::Chacha(c) => c.encrypt(GenericArray::from_slice(nonce), pt),
        };
        result.map_err(|_| io::Error::other("ss: ошибка шифрования"))
    }

    fn open(&self, nonce: &[u8; 12], ct: &[u8]) -> io::Result<Vec<u8>> {
        let result = match self {
            AeadKey::Aes128(c) => c.decrypt(GenericArray::from_slice(nonce), ct),
            AeadKey::Aes256(c) => c.decrypt(GenericArray::from_slice(nonce), ct),
            AeadKey::Chacha(c) => c.decrypt(GenericArray::from_slice(nonce), ct),
        };
        result.map_err(|_| io::Error::other("ss: ошибка расшифровки (аутентификация)"))
    }
}

/// Однонаправленное AEAD-состояние (свой счётчик nonce).
pub struct Crypto {
    key: AeadKey,
    nonce: [u8; 12],
}

impl Crypto {
    /// Создаёт состояние из метода и подключа.
    pub fn new(method: Method, subkey: &[u8]) -> io::Result<Self> {
        Ok(Self {
            key: AeadKey::new(method, subkey)?,
            nonce: [0u8; 12],
        })
    }

    /// Шифрует и продвигает nonce.
    pub fn seal(&mut self, pt: &[u8]) -> io::Result<Vec<u8>> {
        let ct = self.key.seal(&self.nonce, pt)?;
        incr_nonce(&mut self.nonce);
        Ok(ct)
    }

    /// Расшифровывает и продвигает nonce.
    pub fn open(&mut self, ct: &[u8]) -> io::Result<Vec<u8>> {
        let pt = self.key.open(&self.nonce, ct)?;
        incr_nonce(&mut self.nonce);
        Ok(pt)
    }
}

/// AEAD seal с явным 12-байтным nonce (SS-2022 UDP, AES-GCM body).
pub fn seal_nonce(
    method: Method,
    subkey: &[u8],
    nonce: &[u8; 12],
    pt: &[u8],
) -> io::Result<Vec<u8>> {
    AeadKey::new(method, subkey)?.seal(nonce, pt)
}

/// AEAD open с явным 12-байтным nonce (SS-2022 UDP, AES-GCM body).
pub fn open_nonce(
    method: Method,
    subkey: &[u8],
    nonce: &[u8; 12],
    ct: &[u8],
) -> io::Result<Vec<u8>> {
    AeadKey::new(method, subkey)?.open(nonce, ct)
}

/// AES-ECB шифрование одного 16-байтного блока ключом PSK (separate header
/// SS-2022 UDP). Длина PSK выбирает AES-128/256.
pub fn aes_ecb_encrypt_block(psk: &[u8], block: &mut [u8; 16]) -> io::Result<()> {
    use aes::cipher::{BlockEncrypt, KeyInit};
    let b = generic_array::GenericArray::from_mut_slice(block);
    match psk.len() {
        16 => aes::Aes128::new_from_slice(psk)
            .map_err(|_| io::Error::other("ss2022: ключ AES-128"))?
            .encrypt_block(b),
        32 => aes::Aes256::new_from_slice(psk)
            .map_err(|_| io::Error::other("ss2022: ключ AES-256"))?
            .encrypt_block(b),
        _ => return Err(io::Error::other("ss2022: длина PSK не 16/32")),
    }
    Ok(())
}

/// AES-ECB расшифровка одного 16-байтного блока ключом PSK.
pub fn aes_ecb_decrypt_block(psk: &[u8], block: &mut [u8; 16]) -> io::Result<()> {
    use aes::cipher::{BlockDecrypt, KeyInit};
    let b = generic_array::GenericArray::from_mut_slice(block);
    match psk.len() {
        16 => aes::Aes128::new_from_slice(psk)
            .map_err(|_| io::Error::other("ss2022: ключ AES-128"))?
            .decrypt_block(b),
        32 => aes::Aes256::new_from_slice(psk)
            .map_err(|_| io::Error::other("ss2022: ключ AES-256"))?
            .decrypt_block(b),
        _ => return Err(io::Error::other("ss2022: длина PSK не 16/32")),
    }
    Ok(())
}

/// Инкремент nonce как little-endian счётчика.
fn incr_nonce(nonce: &mut [u8; 12]) {
    for b in nonce.iter_mut() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evp_key_deterministic_and_sized() {
        let k = evp_bytes_to_key(b"password", 32);
        assert_eq!(k.len(), 32);
        assert_eq!(k, evp_bytes_to_key(b"password", 32));
        assert_eq!(evp_bytes_to_key(b"password", 16).len(), 16);
    }

    #[test]
    fn seal_open_roundtrip_sequence() {
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::Chacha20IetfPoly1305,
        ] {
            let subkey = vec![7u8; method.key_len()];
            let mut enc = Crypto::new(method, &subkey).unwrap();
            let mut dec = Crypto::new(method, &subkey).unwrap();
            for msg in [&b"hello"[..], b"second message", b""] {
                let ct = enc.seal(msg).unwrap();
                let pt = dec.open(&ct).unwrap();
                assert_eq!(pt, msg);
            }
        }
    }

    #[test]
    fn open_rejects_tampered() {
        let subkey = vec![1u8; 32];
        let mut enc = Crypto::new(Method::Aes256Gcm, &subkey).unwrap();
        let mut dec = Crypto::new(Method::Aes256Gcm, &subkey).unwrap();
        let mut ct = enc.seal(b"secret").unwrap();
        ct[0] ^= 0xFF;
        assert!(dec.open(&ct).is_err());
    }

    #[test]
    fn from_name_and_is_2022() {
        assert_eq!(Method::from_name("aes-256-gcm"), Some(Method::Aes256Gcm));
        assert_eq!(
            Method::from_name("2022-blake3-aes-256-gcm"),
            Some(Method::Ss2022Aes256Gcm)
        );
        assert_eq!(
            Method::from_name("2022-blake3-chacha20-poly1305"),
            Some(Method::Ss2022Chacha20Poly1305)
        );
        assert!(Method::Ss2022Aes128Gcm.is_2022());
        assert!(!Method::Aes256Gcm.is_2022());
        assert_eq!(Method::Ss2022Aes128Gcm.key_len(), 16);
        assert_eq!(Method::Ss2022Chacha20Poly1305.key_len(), 32);
    }

    #[test]
    fn nonce_increment() {
        let mut n = [0xFFu8; 12];
        n[0] = 0xFF;
        n[1] = 0x00;
        incr_nonce(&mut n);
        assert_eq!(n[0], 0x00);
        assert_eq!(n[1], 0x01);
    }
}
