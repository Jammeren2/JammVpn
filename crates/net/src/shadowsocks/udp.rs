//! Shadowsocks UDP relay (legacy AEAD, SIP003-style per-packet).
//!
//! Каждый UDP-пакет самодостаточен: `salt(random) || AEAD_seal(subkey, nonce=0,
//! ATYP+addr+port || payload)`, где `subkey = HKDF-SHA1(master, salt, "ss-subkey")`.
//! Чанкинга/длины нет — один seal на датаграмму. Ответ сервера имеет тот же вид
//! (адрес = источник). SS-2022 UDP (session/packet id) пока не поддержан.

use super::crypto::{session_subkey, Crypto};
use super::Method;
use crate::target::Target;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn random_salt(len: usize) -> io::Result<Vec<u8>> {
    let mut salt = vec![0u8; len];
    // Ошибку ГСЧ пробрасываем: предсказуемая соль → предсказуемый подключ.
    getrandom::getrandom(&mut salt).map_err(|_| io::Error::other("ss-udp: ошибка ГСЧ"))?;
    Ok(salt)
}

/// Адрес назначения SS: `ATYP + addr + port(BE)`.
pub(super) fn encode_address(target: &Target) -> Vec<u8> {
    let mut b = Vec::new();
    match target {
        Target::Domain(host, port) => {
            b.push(0x03);
            let h = host.as_bytes();
            let len = h.len().min(255);
            b.push(len as u8);
            b.extend_from_slice(&h[..len]);
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
    b
}

/// Разбирает `ATYP+addr+port` в начале `buf` → (адрес, остаток-payload).
pub(super) fn parse_address(buf: &[u8]) -> io::Result<(Target, &[u8])> {
    if buf.is_empty() {
        return Err(bad("ss-udp: пустой заголовок"));
    }
    match buf[0] {
        0x01 => {
            if buf.len() < 7 {
                return Err(bad("ss-udp: усечённый IPv4-адрес"));
            }
            let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((Target::Socket(SocketAddr::from((ip, port))), &buf[7..]))
        }
        0x04 => {
            if buf.len() < 19 {
                return Err(bad("ss-udp: усечённый IPv6-адрес"));
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[1..17]);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((
                Target::Socket(SocketAddr::from((Ipv6Addr::from(o), port))),
                &buf[19..],
            ))
        }
        0x03 => {
            if buf.len() < 2 {
                return Err(bad("ss-udp: домен без байта длины"));
            }
            let len = buf[1] as usize;
            let end = 2 + len + 2;
            if buf.len() < end {
                return Err(bad("ss-udp: усечённый домен"));
            }
            let host = String::from_utf8_lossy(&buf[2..2 + len]).into_owned();
            let port = u16::from_be_bytes([buf[2 + len], buf[2 + len + 1]]);
            Ok((Target::Domain(host, port), &buf[end..]))
        }
        _ => Err(bad("ss-udp: неизвестный ATYP")),
    }
}

/// Шифрует один SS-UDP пакет к `target`.
pub fn encrypt_packet(
    method: Method,
    master: &[u8],
    target: &Target,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let salt = random_salt(method.salt_len())?;
    let subkey = session_subkey(method, master, &salt);
    let mut pt = encode_address(target);
    pt.extend_from_slice(payload);
    let ct = Crypto::new(method, &subkey)?.seal(&pt)?;
    let mut out = salt;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Расшифровывает SS-UDP пакет → (адрес-источник, payload).
pub fn decrypt_packet(
    method: Method,
    master: &[u8],
    packet: &[u8],
) -> io::Result<(Target, Vec<u8>)> {
    let slen = method.salt_len();
    if packet.len() < slen {
        return Err(bad("ss-udp: пакет короче соли"));
    }
    let subkey = session_subkey(method, master, &packet[..slen]);
    let pt = Crypto::new(method, &subkey)?.open(&packet[slen..])?;
    let (target, payload) = parse_address(&pt)?;
    Ok((target, payload.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::super::evp_bytes_to_key;
    use super::*;

    #[test]
    fn packet_roundtrip_all_methods() {
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::Chacha20IetfPoly1305,
        ] {
            let master = evp_bytes_to_key(b"pass", method.key_len());
            for target in [
                Target::Socket("1.2.3.4:53".parse().unwrap()),
                Target::Socket("[2001:db8::1]:443".parse().unwrap()),
                Target::Domain("example.com".into(), 443),
            ] {
                let pkt = encrypt_packet(method, &master, &target, b"payload-data").unwrap();
                let (got, payload) = decrypt_packet(method, &master, &pkt).unwrap();
                assert_eq!(got, target);
                assert_eq!(payload, b"payload-data");
            }
        }
    }

    #[test]
    fn fresh_salt_each_packet() {
        let method = Method::Aes256Gcm;
        let master = evp_bytes_to_key(b"pass", method.key_len());
        let t = Target::Socket("1.1.1.1:53".parse().unwrap());
        let a = encrypt_packet(method, &master, &t, b"x").unwrap();
        let b = encrypt_packet(method, &master, &t, b"x").unwrap();
        assert_ne!(a, b, "соль (и шифртекст) различаются между пакетами");
    }

    #[test]
    fn rejects_tampered_and_short() {
        let method = Method::Aes128Gcm;
        let master = evp_bytes_to_key(b"pass", method.key_len());
        let t = Target::Socket("1.1.1.1:53".parse().unwrap());
        let mut pkt = encrypt_packet(method, &master, &t, b"x").unwrap();
        let last = pkt.len() - 1;
        pkt[last] ^= 0xFF;
        assert!(decrypt_packet(method, &master, &pkt).is_err());
        assert!(decrypt_packet(method, &master, &[0u8; 4]).is_err());
    }
}
