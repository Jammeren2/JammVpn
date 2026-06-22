//! `NewCTR` + `XorConn` (порт `xor.go`) — для режимов `xorpub`/`random`.
//!
//! `NewCTR(key, iv)` = AES-256-CTR (128-битный BE-счётчик), где ключ выводится
//! `blake3::derive_key("VLESS", key)` (как в Go, чтобы не использовать ключ
//! напрямую). В режиме `xorpub` этим потоком обфусцируется публичная часть
//! relays (X25519 pub / ML-KEM ciphertext). В режиме `random` дополнительно
//! [`XorState`] ксорит 5-байтные заголовки TLS-подобных записей потока данных,
//! делая весь трафик неотличимым от случайного (тело уже случайно из-за AEAD).

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};

/// AES-256 в режиме CTR с 128-битным big-endian счётчиком (как `cipher.NewCTR`).
pub type Ctr = ctr::Ctr128BE<Aes256>;

/// `NewCTR(key, iv)`: ключ = `blake3::derive_key("VLESS", key)` → AES-256-CTR.
pub fn new_ctr(key: &[u8], iv: &[u8; 16]) -> Ctr {
    let k = blake3::derive_key("VLESS", key); // [u8; 32]
    Ctr::new((&k).into(), iv.into())
}

/// Обфускация публичной части relays (xorpub/random): XOR потоком
/// `NewCTR(nfsPKeyBytes, iv)` (порт строки 99 `client.go`).
pub fn xor_relays(nfs_pkey_bytes: &[u8], iv: &[u8; 16], relays: &mut [u8]) {
    new_ctr(nfs_pkey_bytes, iv).apply_keystream(relays);
}

/// Длина тела TLS-подобной записи из 5-байтного заголовка (как `DecodeHeader`,
/// игнорируя ошибку: при неверной «магии» 23 3 3 → 0).
fn decode_header_len(h: &[u8; 5]) -> usize {
    if h[0] != 23 || h[1] != 3 || h[2] != 3 {
        return 0;
    }
    ((h[3] as usize) << 8) | h[4] as usize
}

/// Состояние XOR-обёртки потока (порт `XorConn`). Ксорит только 5-байтные
/// заголовки записей; тело (AEAD-шифртекст) пропускается без изменений.
pub struct XorState {
    write_ctr: Ctr,
    read_ctr: Ctr,
    out_skip: usize,
    out_header: Vec<u8>,
    in_skip: usize,
    in_header: Vec<u8>,
}

impl XorState {
    /// Клиентский 1-RTT: write-CTR от `iv`, read-CTR от `ticket16`
    /// (`encryptedTicket[:16]`), `in_skip` = длина серверного паддинга (его байты
    /// сервер шлёт «как есть», их пропускаем перед ксором заголовков).
    pub fn client_1rtt(
        united_key: &[u8],
        iv: &[u8; 16],
        ticket16: &[u8; 16],
        peer_padding_len: usize,
    ) -> Self {
        Self {
            write_ctr: new_ctr(united_key, iv),
            read_ctr: new_ctr(united_key, ticket16),
            out_skip: 0,
            out_header: Vec::with_capacity(5),
            in_skip: peer_padding_len,
            in_header: Vec::with_capacity(5),
        }
    }

    /// Ксорит заголовки исходящих записей на месте (порт `XorConn.Write`).
    pub fn transform_write(&mut self, b: &mut [u8]) {
        let mut off = 0;
        loop {
            let rem = b.len() - off;
            if rem <= self.out_skip {
                self.out_skip -= rem;
                break;
            }
            off += self.out_skip;
            self.out_skip = 0;
            let need = 5 - self.out_header.len();
            let avail = b.len() - off;
            if avail < need {
                self.out_header.extend_from_slice(&b[off..]); // plaintext заголовок
                self.write_ctr.apply_keystream(&mut b[off..]);
                break;
            }
            // Длину тела декодируем из ПЛЕЙНТЕКСТА заголовка (до ксора).
            let mut hdr = [0u8; 5];
            let hl = self.out_header.len();
            hdr[..hl].copy_from_slice(&self.out_header);
            hdr[hl..].copy_from_slice(&b[off..off + need]);
            self.out_skip = decode_header_len(&hdr);
            self.out_header.clear();
            self.write_ctr.apply_keystream(&mut b[off..off + need]);
            off += need;
        }
    }

    /// Восстанавливает (ксорит обратно) заголовки входящих записей на месте
    /// (порт `XorConn.Read`).
    pub fn transform_read(&mut self, b: &mut [u8]) {
        let mut off = 0;
        loop {
            let rem = b.len() - off;
            if rem <= self.in_skip {
                self.in_skip -= rem;
                break;
            }
            off += self.in_skip;
            self.in_skip = 0;
            let need = 5 - self.in_header.len();
            let avail = b.len() - off;
            if avail < need {
                self.read_ctr.apply_keystream(&mut b[off..]); // расшифровали заголовок
                self.in_header.extend_from_slice(&b[off..]);
                break;
            }
            // Read: сперва расшифровываем заголовок, потом декодируем длину тела.
            self.read_ctr.apply_keystream(&mut b[off..off + need]);
            let mut hdr = [0u8; 5];
            let hl = self.in_header.len();
            hdr[..hl].copy_from_slice(&self.in_header);
            hdr[hl..].copy_from_slice(&b[off..off + need]);
            self.in_skip = decode_header_len(&hdr);
            self.in_header.clear();
            off += need;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Запись и зеркальное чтение по тем же CTR-параметрам восстанавливают
    /// исходные заголовки (имитируем «себя же» на другом конце).
    #[test]
    fn header_xor_roundtrip() {
        let uk = [9u8; 64];
        let iv = [3u8; 16];
        // Пишущая сторона: write от iv. Читающая «другая сторона»: read от iv.
        let mut w = XorState::client_1rtt(&uk, &iv, &[0u8; 16], 0);
        let mut r = XorState {
            read_ctr: new_ctr(&uk, &iv),
            write_ctr: new_ctr(&uk, &iv),
            out_skip: 0,
            out_header: Vec::new(),
            in_skip: 0,
            in_header: Vec::new(),
        };
        // Две записи: заголовок [23,3,3,hi,lo] + тело длиной l-16... тело l байт.
        let mut stream = Vec::new();
        for l in [20usize, 100] {
            stream.extend_from_slice(&[23, 3, 3, (l >> 8) as u8, l as u8]);
            stream.extend(std::iter::repeat(0xAB).take(l));
        }
        let original = stream.clone();
        w.transform_write(&mut stream);
        assert_ne!(stream[..5], original[..5], "заголовок должен быть заксорен");
        assert_eq!(stream[5..20 + 5], original[5..20 + 5], "тело не меняется");
        r.transform_read(&mut stream);
        assert_eq!(stream, original, "после read заголовки восстановлены");
    }
}
