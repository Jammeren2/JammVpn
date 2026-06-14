//! Минимальный Base64 без внешних зависимостей.
//!
//! Декодер принимает оба алфавита (стандартный и URL-safe), игнорирует
//! паддинг (`=`) и пробельные символы — что удобно для разнородных
//! share-ссылок и подписок. Кодер — стандартный алфавит с паддингом.

use crate::error::ParseError;

const INVALID: u8 = 0xFF;
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn decode_table() -> [u8; 256] {
    let mut t = [INVALID; 256];
    for (i, &c) in ALPHABET.iter().enumerate() {
        t[c as usize] = i as u8;
    }
    // URL-safe псевдонимы.
    t[b'-' as usize] = 62;
    t[b'_' as usize] = 63;
    t
}

/// Декодирует Base64 «терпимо»: оба алфавита, без требования паддинга,
/// игнорируя пробелы и переводы строк.
pub fn decode_loose(input: &str) -> Result<Vec<u8>, ParseError> {
    let table = decode_table();
    let mut out = Vec::with_capacity(input.len() / 4 * 3 + 3);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in input.as_bytes() {
        match b {
            b'=' | b'\r' | b'\n' | b' ' | b'\t' => continue,
            _ => {}
        }
        let v = table[b as usize];
        if v == INVALID {
            return Err(ParseError::Base64(format!("недопустимый байт: 0x{b:02x}")));
        }
        buf = (buf << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

/// Декодирует Base64 в строку UTF-8.
pub fn decode_to_string(input: &str) -> Result<String, ParseError> {
    let bytes = decode_loose(input)?;
    String::from_utf8(bytes).map_err(|_| ParseError::Utf8)
}

/// Кодирует байты в стандартный Base64 с паддингом.
pub fn encode_standard(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len() * 4 / 3 + 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for s in [
            "",
            "f",
            "fo",
            "foo",
            "foob",
            "fooba",
            "foobar",
            "aes-256-gcm:pass",
        ] {
            let enc = encode_standard(s.as_bytes());
            let dec = decode_loose(&enc).unwrap();
            assert_eq!(dec, s.as_bytes(), "roundtrip failed for {s:?}");
        }
    }

    #[test]
    fn urlsafe_and_padless() {
        assert_eq!(decode_to_string("c3M=").unwrap(), "ss");
        assert_eq!(decode_to_string("c3M").unwrap(), "ss");
    }

    #[test]
    fn known_vector() {
        assert_eq!(
            decode_to_string("YWVzLTI1Ni1nY206cGFzcw==").unwrap(),
            "aes-256-gcm:pass"
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(decode_loose("!!!"), Err(ParseError::Base64(_))));
    }
}
