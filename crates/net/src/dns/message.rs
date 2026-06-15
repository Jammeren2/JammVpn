//! Кодек DNS-сообщений (RFC 1035): запрос A/AAAA и разбор ответа.
//!
//! Минимально достаточный для резолва: кодирование запроса (recursion desired) и
//! извлечение A/AAAA-адресов из ответа (с поддержкой компрессии имён при разборе).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Тип записи A (IPv4).
pub const TYPE_A: u16 = 1;
/// Тип записи AAAA (IPv6).
pub const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Кодирует DNS-запрос (одна вопрос-запись, recursion desired).
pub fn encode_query(id: u16, name: &str, qtype: u16) -> io::Result<Vec<u8>> {
    let mut b = Vec::with_capacity(name.len() + 18);
    b.extend_from_slice(&id.to_be_bytes());
    b.extend_from_slice(&0x0100u16.to_be_bytes()); // флаги: RD
    b.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    b.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR COUNT

    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        if label.len() > 63 {
            return Err(bad("dns: метка длиннее 63"));
        }
        b.push(label.len() as u8);
        b.extend_from_slice(label.as_bytes());
    }
    b.push(0); // корень
    b.extend_from_slice(&qtype.to_be_bytes());
    b.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(b)
}

/// Разбирает DNS-ответ, возвращает все A/AAAA-адреса. Проверяет ID (если задан)
/// и RCODE (0 = ok).
pub fn decode_response(buf: &[u8], expect_id: Option<u16>) -> io::Result<Vec<IpAddr>> {
    if buf.len() < 12 {
        return Err(bad("dns: ответ короче заголовка"));
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if let Some(eid) = expect_id {
        if id != eid {
            return Err(bad("dns: ID ответа не совпал"));
        }
    }
    let rcode = u16::from_be_bytes([buf[2], buf[3]]) & 0x000F;
    if rcode != 0 {
        return Err(io::Error::other(format!("dns: RCODE {rcode}")));
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(buf, pos)?;
        pos = pos.checked_add(4).ok_or_else(|| bad("dns: переполнение"))?; // QTYPE+QCLASS
    }

    let mut ips = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(buf, pos)?;
        if pos + 10 > buf.len() {
            return Err(bad("dns: усечённая RR"));
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            return Err(bad("dns: усечённая RDATA"));
        }
        match rtype {
            TYPE_A if rdlen == 4 => {
                ips.push(IpAddr::V4(Ipv4Addr::new(
                    buf[pos],
                    buf[pos + 1],
                    buf[pos + 2],
                    buf[pos + 3],
                )));
            }
            TYPE_AAAA if rdlen == 16 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&buf[pos..pos + 16]);
                ips.push(IpAddr::V6(Ipv6Addr::from(o)));
            }
            _ => {} // CNAME и прочее — пропускаем (A/AAAA обычно тоже в ответе)
        }
        pos += rdlen;
    }
    Ok(ips)
}

/// Пропускает DNS-имя (метки + указатель компрессии), возвращает позицию после
/// имени. Для пропуска переходить по указателю не нужно.
fn skip_name(buf: &[u8], mut pos: usize) -> io::Result<usize> {
    let mut steps = 0;
    loop {
        if pos >= buf.len() {
            return Err(bad("dns: имя за границей"));
        }
        let len = buf[pos];
        if len == 0 {
            return Ok(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            // 2-байтный указатель — имя заканчивается здесь.
            if pos + 2 > buf.len() {
                return Err(bad("dns: усечённый указатель"));
            }
            return Ok(pos + 2);
        }
        if len & 0xC0 != 0 {
            return Err(bad("dns: неверный байт длины метки"));
        }
        pos += 1 + len as usize;
        steps += 1;
        if steps > 128 {
            return Err(bad("dns: слишком длинное имя"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_query_layout() {
        let q = encode_query(0x1234, "example.com", TYPE_A).unwrap();
        assert_eq!(&q[0..2], &[0x12, 0x34]); // ID
        assert_eq!(&q[2..4], &[0x01, 0x00]); // RD
        assert_eq!(&q[4..6], &[0x00, 0x01]); // QDCOUNT=1
                                             // QNAME: 7 "example" 3 "com" 0
        assert_eq!(q[12], 7);
        assert_eq!(&q[13..20], b"example");
        assert_eq!(q[20], 3);
        assert_eq!(&q[21..24], b"com");
        assert_eq!(q[24], 0);
        assert_eq!(&q[25..27], &TYPE_A.to_be_bytes());
        assert_eq!(&q[27..29], &CLASS_IN.to_be_bytes());
    }

    /// Собирает минимальный ответ: 1 вопрос + N answer-записей (имя — указатель
    /// 0xC00C на вопрос).
    fn build_response(id: u16, qname: &str, answers: &[(u16, &[u8])]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&id.to_be_bytes());
        b.extend_from_slice(&0x8180u16.to_be_bytes()); // QR + RD + RA
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 0]);
        for label in qname.split('.') {
            b.push(label.len() as u8);
            b.extend_from_slice(label.as_bytes());
        }
        b.push(0);
        b.extend_from_slice(&TYPE_A.to_be_bytes());
        b.extend_from_slice(&CLASS_IN.to_be_bytes());
        for (rtype, rdata) in answers {
            b.extend_from_slice(&[0xC0, 0x0C]); // указатель на вопрос
            b.extend_from_slice(&rtype.to_be_bytes());
            b.extend_from_slice(&CLASS_IN.to_be_bytes());
            b.extend_from_slice(&300u32.to_be_bytes()); // TTL
            b.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            b.extend_from_slice(rdata);
        }
        b
    }

    #[test]
    fn decode_a_and_aaaa() {
        let v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let resp = build_response(
            0xABCD,
            "example.com",
            &[
                (TYPE_A, &[93, 184, 216, 34]),
                (TYPE_AAAA, &v6),
                (5, &[1, 2, 3]), // CNAME — игнорируется
            ],
        );
        let ips = decode_response(&resp, Some(0xABCD)).unwrap();
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"93.184.216.34".parse().unwrap()));
        assert!(ips.contains(&"2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn decode_rejects_bad_id_and_rcode() {
        let resp = build_response(0x1111, "x.com", &[(TYPE_A, &[1, 1, 1, 1])]);
        assert!(decode_response(&resp, Some(0x2222)).is_err()); // чужой ID

        // RCODE=3 (NXDOMAIN)
        let mut nx = build_response(0x1111, "x.com", &[]);
        nx[3] = 0x83;
        assert!(decode_response(&nx, Some(0x1111)).is_err());
    }
}
