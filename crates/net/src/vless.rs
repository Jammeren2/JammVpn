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
//! Команда — только TCP. Flow (XTLS-Vision) кодируется в addon как protobuf
//! `Addons { Flow = 1 }`; без flow addon пуст (совместимо с VLESS без flow).
//! Сам data-path Vision реализован в [`crate::vision`].

use crate::target::Target;
use std::net::SocketAddr;

/// Версия протокола.
pub const VERSION: u8 = 0x00;
/// Команда «TCP».
pub const CMD_TCP: u8 = 0x01;
/// Команда «UDP».
pub const CMD_UDP: u8 = 0x02;
/// Значение flow для XTLS-Vision.
pub const FLOW_VISION: &str = "xtls-rprx-vision";

/// Дописывает тип адреса + адрес: `1`=IPv4, `2`=домен, `3`=IPv6.
fn push_address(b: &mut Vec<u8>, target: &Target) {
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
}

/// Кодирует заголовок запроса VLESS.
///
/// Если задан `flow`, addon кодируется как protobuf-сообщение `Addons { Flow = 1 }`
/// (тег `0x0A`, длина-varint, строка). Иначе addon пуст (длина 0) — заголовок
/// совместим с VLESS без flow.
pub fn encode_request(uuid: &[u8; 16], flow: Option<&str>, target: &Target) -> Vec<u8> {
    let mut b = Vec::with_capacity(24);
    b.push(VERSION);
    b.extend_from_slice(uuid);
    match flow {
        Some(f) if !f.is_empty() => {
            let fb = f.as_bytes();
            let mut addon = Vec::with_capacity(2 + fb.len());
            addon.push(0x0A); // field=1 (Flow), wire type=2 (length-delimited)
                              // длина строки как protobuf varint (для коротких flow — один байт)
            let mut len = fb.len();
            loop {
                let mut byte = (len & 0x7F) as u8;
                len >>= 7;
                if len != 0 {
                    byte |= 0x80;
                }
                addon.push(byte);
                if len == 0 {
                    break;
                }
            }
            addon.extend_from_slice(fb);
            debug_assert!(addon.len() <= u8::MAX as usize);
            b.push(addon.len() as u8);
            b.extend_from_slice(&addon);
        }
        _ => b.push(0x00), // длина addon = 0
    }
    b.push(CMD_TCP);
    b.extend_from_slice(&target.port().to_be_bytes());
    push_address(&mut b, target);
    b
}

/// Кодирует заголовок UDP-запроса VLESS. Flow ВСЕГДА пустой: XTLS-Vision не
/// поддерживает UDP, и сервер принимает UDP-команду только с пустым flow (даже у
/// vision-аккаунта). Данные после заголовка — датаграммы `[len(2 BE)][payload]`.
pub fn encode_request_udp(uuid: &[u8; 16], target: &Target) -> Vec<u8> {
    let mut b = Vec::with_capacity(24);
    b.push(VERSION);
    b.extend_from_slice(uuid);
    b.push(0x00); // addon len = 0 (без flow)
    b.push(CMD_UDP);
    b.extend_from_slice(&target.port().to_be_bytes());
    push_address(&mut b, target);
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
    fn encode_request_vision_flow_addon() {
        let uuid = [7u8; 16];
        let b = encode_request(
            &uuid,
            Some(FLOW_VISION),
            &Target::Domain("a.com".to_string(), 443),
        );
        // addon = protobuf Addons{Flow=1}: 0x0A, len(16), "xtls-rprx-vision" = 18 байт
        let addon_len = 2 + FLOW_VISION.len();
        assert_eq!(b[17], addon_len as u8);
        assert_eq!(b[18], 0x0A); // field 1, wire type 2
        assert_eq!(b[19], FLOW_VISION.len() as u8); // 16
        assert_eq!(&b[20..20 + FLOW_VISION.len()], FLOW_VISION.as_bytes());
        // далее — команда/порт/адрес
        let cmd_off = 18 + addon_len;
        assert_eq!(b[cmd_off], CMD_TCP);
        assert_eq!(&b[cmd_off + 1..cmd_off + 3], &443u16.to_be_bytes());
        assert_eq!(b[cmd_off + 3], 0x02); // domain
    }

    #[test]
    fn encode_request_udp_ipv4() {
        let uuid = [2u8; 16];
        let target = Target::Socket("8.8.8.8:53".parse().unwrap());
        let b = encode_request_udp(&uuid, &target);
        assert_eq!(b[0], VERSION);
        assert_eq!(&b[1..17], &uuid);
        assert_eq!(b[17], 0); // addon len = 0 (без flow)
        assert_eq!(b[18], CMD_UDP);
        assert_eq!(&b[19..21], &53u16.to_be_bytes());
        assert_eq!(b[21], 0x01); // ipv4
        assert_eq!(&b[22..26], &[8, 8, 8, 8]);
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
