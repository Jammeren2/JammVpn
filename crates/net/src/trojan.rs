//! Фрейминг протокола Trojan (ТЗ, раздел 4, `PRO-*`).
//!
//! Trojan не шифрует сам — защита обеспечивается транспортом (обычно TLS).
//! Заголовок запроса:
//! `hex(SHA224(password))(56) | CRLF | CMD(1) | ATYP(1) | addr | port(2,BE) | CRLF`,
//! после чего сразу идёт полезная нагрузка. Ответного заголовка нет.
//! ATYP как в SOCKS5: `1`=IPv4, `3`=домен, `4`=IPv6.

use crate::target::Target;
use sha2::{Digest, Sha224};
use std::net::SocketAddr;

/// Кодирует заголовок запроса Trojan.
pub fn encode_request(password: &str, target: &Target) -> Vec<u8> {
    let mut b = Vec::with_capacity(64);
    b.extend_from_slice(password_hash_hex(password).as_bytes());
    b.extend_from_slice(b"\r\n");
    b.push(0x01); // CONNECT
    match target {
        Target::Domain(host, port) => {
            b.push(0x03);
            b.push(host.len() as u8);
            b.extend_from_slice(host.as_bytes());
            b.extend_from_slice(&port.to_be_bytes());
        }
        Target::Socket(SocketAddr::V4(a)) => {
            b.push(0x01);
            b.extend_from_slice(&a.ip().octets());
            b.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Socket(SocketAddr::V6(a)) => {
            b.push(0x04);
            b.extend_from_slice(&a.ip().octets());
            b.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    b.extend_from_slice(b"\r\n");
    b
}

/// Hex(SHA224(password)) — 56 ASCII-символов.
fn password_hash_hex(password: &str) -> String {
    let digest = Sha224::digest(password.as_bytes());
    let mut s = String::with_capacity(56);
    for byte in digest {
        s.push(hex_digit(byte >> 4));
        s.push(hex_digit(byte & 0x0F));
    }
    s
}

fn hex_digit(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + (n - 10)) as char,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_known_vector() {
        // SHA224("") = d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f
        assert_eq!(
            password_hash_hex(""),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
        assert_eq!(password_hash_hex("anything").len(), 56);
    }

    #[test]
    fn header_layout_domain() {
        let full = encode_request("pw", &Target::Domain("a.com".to_string(), 443));
        // 56 (hash) + 2 (CRLF) + 1 (CMD) + 1 (ATYP) + 1 (len) + 5 (host) + 2 (port) + 2 (CRLF)
        assert_eq!(full.len(), 70);
        assert_eq!(&full[56..58], b"\r\n");
        assert_eq!(full[58], 0x01); // CONNECT
        assert_eq!(full[59], 0x03); // domain
        assert_eq!(full[60], 5); // len("a.com")
        assert_eq!(&full[61..66], b"a.com");
        assert_eq!(&full[66..68], &443u16.to_be_bytes());
        assert_eq!(&full[68..70], b"\r\n");
    }
}
