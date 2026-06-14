//! Фрейминг протокола VLESS (ТЗ, раздел 4, `PRO-*`).
//!
//! VLESS сам по себе не шифрует — защита обеспечивается транспортом
//! (TLS/REALITY). Здесь — кодирование заголовка запроса и разбор UUID.
//!
//! Формат запроса:
//! `версия(1) | uuid(16) | len_addon(1) | addon(M) | команда(1) | порт(2, BE) |
//!  тип_адреса(1) | адрес(N)`. Типы адреса VLESS: `1`=IPv4, `2`=домен, `3`=IPv6.
//!
//! Ответ сервера начинается с `версия(1) | len_addon(1) | addon(M)`, после чего
//! идёт полезная нагрузка.
//!
//! Ограничения текущей версии: команда только TCP; flow (XTLS-Vision) не
//! реализован (addon пустой) — заголовок совместим с VLESS без flow.

use crate::target::Target;
use std::net::SocketAddr;

/// Версия протокола.
pub const VERSION: u8 = 0x00;
/// Команда «TCP».
pub const CMD_TCP: u8 = 0x01;

/// Кодирует заголовок запроса VLESS.
pub fn encode_request(uuid: &[u8; 16], _flow: Option<&str>, target: &Target) -> Vec<u8> {
    let mut b = Vec::with_capacity(24);
    b.push(VERSION);
    b.extend_from_slice(uuid);
    b.push(0x00); // длина addon = 0 (flow не реализован)
    b.push(CMD_TCP);
    b.extend_from_slice(&target.port().to_be_bytes());
    match target {
        Target::Domain(host, _) => {
            b.push(0x02);
            b.push(host.len() as u8);
            b.extend_from_slice(host.as_bytes());
        }
        Target::Socket(SocketAddr::V4(a)) => {
            b.push(0x01);
            b.extend_from_slice(&a.ip().octets());
        }
        Target::Socket(SocketAddr::V6(a)) => {
            b.push(0x03);
            b.extend_from_slice(&a.ip().octets());
        }
    }
    b
}

/// Разбирает UUID из строки (с дефисами или без) в 16 байт.
pub fn parse_uuid(s: &str) -> Option<[u8; 16]> {
    let hex: Vec<u8> = s.bytes().filter(|c| *c != b'-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, pair) in hex.chunks_exact(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_request_domain() {
        let uuid = [1u8; 16];
        let b = encode_request(&uuid, None, &Target::Domain("a.com".to_string(), 443));
        assert_eq!(b[0], VERSION);
        assert_eq!(&b[1..17], &uuid);
        assert_eq!(b[17], 0); // addon len
        assert_eq!(b[18], CMD_TCP);
        assert_eq!(&b[19..21], &443u16.to_be_bytes());
        assert_eq!(b[21], 0x02); // domain
        assert_eq!(b[22], 5); // len("a.com")
        assert_eq!(&b[23..28], b"a.com");
    }

    #[test]
    fn encode_request_ipv4() {
        let uuid = [0u8; 16];
        let target = Target::Socket("1.2.3.4:80".parse().unwrap());
        let b = encode_request(&uuid, None, &target);
        assert_eq!(b[18], CMD_TCP);
        assert_eq!(&b[19..21], &80u16.to_be_bytes());
        assert_eq!(b[21], 0x01); // ipv4
        assert_eq!(&b[22..26], &[1, 2, 3, 4]);
    }

    #[test]
    fn uuid_parse() {
        assert!(parse_uuid("too-short").is_none());
        let u = parse_uuid("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        assert_eq!(u[0], 0x00);
        assert_eq!(u[1], 0x11);
        assert_eq!(u[15], 0xff);
        // без дефисов — тот же результат.
        assert_eq!(parse_uuid("00112233445566778899aabbccddeeff"), Some(u));
    }
}
