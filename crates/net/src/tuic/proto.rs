//! Кодек команд TUIC v5 (бинарный фрейминг, проверено против крейта `tuic` 5.0.0).
//!
//! Заголовок любой команды: `VER(0x05) | TYPE`. Authenticate (uni-стрим):
//! `+ UUID(16) + TOKEN(32)`. Connect (bidi-стрим): `+ ADDRESS`, далее сырой
//! поток к цели. Адрес: `ATYP(1) | ADDR | PORT(2, big-endian)`.

use crate::target::Target;
use std::io;
use std::net::SocketAddr;

pub const VERSION: u8 = 0x05;
pub const CMD_AUTHENTICATE: u8 = 0x00;
pub const CMD_CONNECT: u8 = 0x01;

pub const ATYP_DOMAIN: u8 = 0x00;
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_IPV6: u8 = 0x02;

/// Authenticate: `0x05 0x00 | UUID(16) | TOKEN(32)` — 50 байт.
pub fn encode_authenticate(uuid: &[u8; 16], token: &[u8; 32]) -> Vec<u8> {
    let mut b = Vec::with_capacity(50);
    b.push(VERSION);
    b.push(CMD_AUTHENTICATE);
    b.extend_from_slice(uuid);
    b.extend_from_slice(token);
    b
}

/// Connect: `0x05 0x01 | ADDRESS`. После него bidi-стрим — сырой канал к цели.
pub fn encode_connect(target: &Target) -> io::Result<Vec<u8>> {
    let mut b = Vec::with_capacity(22);
    b.push(VERSION);
    b.push(CMD_CONNECT);
    encode_address(&mut b, target)?;
    Ok(b)
}

/// Адрес TUIC: `ATYP(1) | ADDR | PORT(2, BE)`.
fn encode_address(b: &mut Vec<u8>, target: &Target) -> io::Result<()> {
    match target {
        Target::Domain(host, port) => {
            if host.len() > u8::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "tuic: домен длиннее 255 байт",
                ));
            }
            b.push(ATYP_DOMAIN);
            b.push(host.len() as u8);
            b.extend_from_slice(host.as_bytes());
            b.extend_from_slice(&port.to_be_bytes());
        }
        Target::Socket(SocketAddr::V4(a)) => {
            b.push(ATYP_IPV4);
            b.extend_from_slice(&a.ip().octets());
            b.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Socket(SocketAddr::V6(a)) => {
            b.push(ATYP_IPV6);
            b.extend_from_slice(&a.ip().octets());
            b.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    Ok(())
}

// --- Разбор (для тест-сервера) ---

/// Читает Authenticate из потока: `VER TYPE UUID(16) TOKEN(32)`.
#[cfg(test)]
pub async fn read_authenticate<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
) -> io::Result<([u8; 16], [u8; 32])> {
    use tokio::io::AsyncReadExt;
    if r.read_u8().await? != VERSION || r.read_u8().await? != CMD_AUTHENTICATE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tuic: не Authenticate",
        ));
    }
    let mut uuid = [0u8; 16];
    r.read_exact(&mut uuid).await?;
    let mut token = [0u8; 32];
    r.read_exact(&mut token).await?;
    Ok((uuid, token))
}

/// Читает Connect из потока и возвращает цель как `"host:port"`.
#[cfg(test)]
pub async fn read_connect<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> io::Result<String> {
    use tokio::io::AsyncReadExt;
    if r.read_u8().await? != VERSION || r.read_u8().await? != CMD_CONNECT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tuic: не Connect",
        ));
    }
    read_address(r).await
}

#[cfg(test)]
async fn read_address<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> io::Result<String> {
    use tokio::io::AsyncReadExt;
    let atyp = r.read_u8().await?;
    match atyp {
        ATYP_DOMAIN => {
            let len = r.read_u8().await? as usize;
            let mut buf = vec![0u8; len];
            r.read_exact(&mut buf).await?;
            let host = String::from_utf8_lossy(&buf).into_owned();
            let port = r.read_u16().await?;
            Ok(format!("{host}:{port}"))
        }
        ATYP_IPV4 => {
            let mut o = [0u8; 4];
            r.read_exact(&mut o).await?;
            let port = r.read_u16().await?;
            Ok(format!("{}:{}", std::net::Ipv4Addr::from(o), port))
        }
        ATYP_IPV6 => {
            let mut o = [0u8; 16];
            r.read_exact(&mut o).await?;
            let port = r.read_u16().await?;
            Ok(format!("[{}]:{}", std::net::Ipv6Addr::from(o), port))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("tuic: неизвестный ATYP {other:#x}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticate_layout() {
        let uuid = [7u8; 16];
        let token = [9u8; 32];
        let b = encode_authenticate(&uuid, &token);
        assert_eq!(b.len(), 50);
        assert_eq!(&b[..2], &[VERSION, CMD_AUTHENTICATE]);
        assert_eq!(&b[2..18], &uuid);
        assert_eq!(&b[18..50], &token);
    }

    #[test]
    fn connect_domain_layout() {
        let b = encode_connect(&Target::Domain("example.com".into(), 443)).unwrap();
        // 05 01 00 0B "example.com" 01 BB
        assert_eq!(&b[..4], &[VERSION, CMD_CONNECT, ATYP_DOMAIN, 11]);
        assert_eq!(&b[4..15], b"example.com");
        assert_eq!(&b[15..17], &443u16.to_be_bytes());
    }

    #[test]
    fn connect_ipv4_layout() {
        let b = encode_connect(&Target::Socket("1.2.3.4:80".parse().unwrap())).unwrap();
        assert_eq!(&b[..3], &[VERSION, CMD_CONNECT, ATYP_IPV4]);
        assert_eq!(&b[3..7], &[1, 2, 3, 4]);
        assert_eq!(&b[7..9], &80u16.to_be_bytes());
    }

    #[tokio::test]
    async fn connect_roundtrip_via_readers() {
        let enc = encode_connect(&Target::Domain("host.test".into(), 8443)).unwrap();
        let mut cur = std::io::Cursor::new(enc);
        let got = read_connect(&mut cur).await.unwrap();
        assert_eq!(got, "host.test:8443");
    }
}
