//! Фрейминг протокола Trojan (ТЗ, раздел 4, `PRO-*`).
//!
//! Trojan не шифрует сам — защита обеспечивается транспортом (обычно TLS).
//! Заголовок запроса:
//! `hex(SHA224(password))(56) | CRLF | CMD(1) | ATYP(1) | addr | port(2,BE) | CRLF`,
//! после чего сразу идёт полезная нагрузка. Ответного заголовка нет.
//! ATYP как в SOCKS5: `1`=IPv4, `3`=домен, `4`=IPv6.
//!
//! UDP (CMD=`0x03`): после заголовка идут пакеты вида
//! `ATYP | addr | port(2) | length(2,BE) | CRLF | payload` (в обе стороны).

use crate::target::Target;
use sha2::{Digest, Sha224};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt};

const CMD_CONNECT: u8 = 0x01;
const CMD_UDP: u8 = 0x03;

/// Кодирует адрес в формате Trojan/SOCKS5: `ATYP | addr | port(2,BE)`.
fn encode_address(b: &mut Vec<u8>, target: &Target) {
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
}

fn encode_request_cmd(password: &str, target: &Target, cmd: u8) -> Vec<u8> {
    let mut b = Vec::with_capacity(72);
    b.extend_from_slice(password_hash_hex(password).as_bytes());
    b.extend_from_slice(b"\r\n");
    b.push(cmd);
    encode_address(&mut b, target);
    b.extend_from_slice(b"\r\n");
    b
}

/// Кодирует заголовок запроса Trojan (TCP, CONNECT).
pub fn encode_request(password: &str, target: &Target) -> Vec<u8> {
    encode_request_cmd(password, target, CMD_CONNECT)
}

/// Кодирует заголовок запроса Trojan для UDP ASSOCIATE.
pub fn encode_request_udp(password: &str, target: &Target) -> Vec<u8> {
    encode_request_cmd(password, target, CMD_UDP)
}

/// Кодирует один Trojan UDP-пакет: `ATYP+addr+port | length(2,BE) | CRLF | payload`.
pub fn encode_udp_packet(target: &Target, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(payload.len() + 24);
    encode_address(&mut b, target);
    b.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    b.extend_from_slice(b"\r\n");
    b.extend_from_slice(payload);
    b
}

/// Читает Trojan-адрес из потока: `ATYP | addr | port(2,BE)`.
pub async fn read_address<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Target> {
    let atyp = r.read_u8().await?;
    match atyp {
        0x01 => {
            let mut o = [0u8; 4];
            r.read_exact(&mut o).await?;
            let port = r.read_u16().await?;
            Ok(Target::Socket(SocketAddr::from((Ipv4Addr::from(o), port))))
        }
        0x04 => {
            let mut o = [0u8; 16];
            r.read_exact(&mut o).await?;
            let port = r.read_u16().await?;
            Ok(Target::Socket(SocketAddr::from((Ipv6Addr::from(o), port))))
        }
        0x03 => {
            let len = r.read_u8().await? as usize;
            let mut host = vec![0u8; len];
            r.read_exact(&mut host).await?;
            let port = r.read_u16().await?;
            Ok(Target::Domain(
                String::from_utf8_lossy(&host).into_owned(),
                port,
            ))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trojan: неизвестный ATYP",
        )),
    }
}

/// Читает один Trojan UDP-пакет из потока → (адрес, payload).
pub async fn read_udp_packet<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<(Target, Vec<u8>)> {
    let target = read_address(r).await?;
    let len = r.read_u16().await? as usize;
    let mut crlf = [0u8; 2];
    r.read_exact(&mut crlf).await?;
    if crlf != *b"\r\n" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trojan udp: нет CRLF после длины",
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok((target, payload))
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

    #[tokio::test]
    async fn udp_packet_roundtrip() {
        for target in [
            Target::Socket("1.2.3.4:53".parse().unwrap()),
            Target::Socket("[2001:db8::1]:443".parse().unwrap()),
            Target::Domain("ya.ru".into(), 5353),
        ] {
            let pkt = encode_udp_packet(&target, b"udp-payload");
            let mut cur = std::io::Cursor::new(pkt);
            let (got, payload) = read_udp_packet(&mut cur).await.unwrap();
            assert_eq!(got, target);
            assert_eq!(payload, b"udp-payload");
        }
    }

    #[test]
    fn udp_request_uses_cmd_3() {
        let h = encode_request_udp("pw", &Target::Domain("a.com".into(), 443));
        assert_eq!(h[58], 0x03, "UDP ASSOCIATE использует CMD=0x03");
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
