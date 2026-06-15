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
pub const CMD_PACKET: u8 = 0x02;
pub const CMD_DISSOCIATE: u8 = 0x03;

pub const ATYP_DOMAIN: u8 = 0x00;
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_IPV6: u8 = 0x02;
/// Адрес отсутствует (в Packet-фрагментах с `frag_id != 0`).
pub const ATYP_NONE: u8 = 0xff;

/// Заголовок команды Packet (UDP relay) — без payload.
#[derive(Debug, Clone)]
pub struct PacketHead {
    pub assoc_id: u16,
    pub pkt_id: u16,
    pub frag_total: u8,
    pub frag_id: u8,
    /// Адрес цели/источника — только во `frag_id == 0`. Читается тест-сервером и
    /// будущим uni-stream режимом; в датаграммном relay демультиплексинг идёт по
    /// `assoc_id`, поэтому в проде поле не читается.
    #[allow(dead_code)]
    pub addr: Option<Target>,
}

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

/// Dissociate: `0x05 0x03 | ASSOC_ID(2)` — закрыть UDP-ассоциацию.
pub fn encode_dissociate(assoc_id: u16) -> Vec<u8> {
    let mut b = Vec::with_capacity(4);
    b.push(VERSION);
    b.push(CMD_DISSOCIATE);
    b.extend_from_slice(&assoc_id.to_be_bytes());
    b
}

/// Длина закодированного TUIC-адреса в байтах.
fn address_len(target: &Target) -> io::Result<usize> {
    Ok(match target {
        Target::Domain(host, _) => {
            if host.len() > u8::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "tuic: домен длиннее 255 байт",
                ));
            }
            1 + 1 + host.len() + 2
        }
        Target::Socket(SocketAddr::V4(_)) => 1 + 4 + 2,
        Target::Socket(SocketAddr::V6(_)) => 1 + 16 + 2,
    })
}

/// Кодирует один Packet-датаграмм: `VER TYPE ASSOC PKT FRAG_TOTAL FRAG_ID SIZE ADDR payload`.
fn encode_packet_one(
    assoc_id: u16,
    pkt_id: u16,
    frag_total: u8,
    frag_id: u8,
    addr: Option<&Target>,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let mut b = Vec::with_capacity(payload.len() + 24);
    b.push(VERSION);
    b.push(CMD_PACKET);
    b.extend_from_slice(&assoc_id.to_be_bytes());
    b.extend_from_slice(&pkt_id.to_be_bytes());
    b.push(frag_total);
    b.push(frag_id);
    b.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    match addr {
        Some(t) => encode_address(&mut b, t)?,
        None => b.push(ATYP_NONE),
    }
    b.extend_from_slice(payload);
    Ok(b)
}

/// Кодирует UDP-пакет к `target` в один или несколько Packet-датаграмм (с
/// фрагментацией под `max_datagram`). Адрес — только в первом фрагменте.
pub fn encode_packets(
    assoc_id: u16,
    pkt_id: u16,
    target: &Target,
    payload: &[u8],
    max_datagram: usize,
) -> io::Result<Vec<Vec<u8>>> {
    // Заголовок: VER+TYPE+ASSOC+PKT+FRAG_TOTAL+FRAG_ID+SIZE = 10, затем адрес.
    let header = 10 + address_len(target)?;
    let cap = max_datagram
        .checked_sub(header)
        .filter(|c| *c > 0)
        .ok_or_else(|| io::Error::other("tuic: датаграмма мала для заголовка"))?;
    if payload.is_empty() {
        return Ok(vec![encode_packet_one(
            assoc_id,
            pkt_id,
            1,
            0,
            Some(target),
            &[],
        )?]);
    }
    let frag_total = payload.len().div_ceil(cap);
    if frag_total > u8::MAX as usize {
        return Err(io::Error::other("tuic: слишком много фрагментов"));
    }
    let mut out = Vec::with_capacity(frag_total);
    for (i, chunk) in payload.chunks(cap).enumerate() {
        let addr = if i == 0 { Some(target) } else { None };
        out.push(encode_packet_one(
            assoc_id,
            pkt_id,
            frag_total as u8,
            i as u8,
            addr,
            chunk,
        )?);
    }
    Ok(out)
}

/// Разбирает Packet-датаграмм → (заголовок, payload-фрагмент).
pub fn decode_packet(buf: &[u8]) -> io::Result<(PacketHead, &[u8])> {
    if buf.len() < 10 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tuic: короткий Packet",
        ));
    }
    if buf[0] != VERSION || buf[1] != CMD_PACKET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tuic: не Packet",
        ));
    }
    let assoc_id = u16::from_be_bytes([buf[2], buf[3]]);
    let pkt_id = u16::from_be_bytes([buf[4], buf[5]]);
    let frag_total = buf[6];
    let frag_id = buf[7];
    // Согласованность фрагментации: корректный отправитель шлёт frag_total ≥ 1 и
    // frag_id < frag_total. Иначе заголовок битый — отвергаем (а не интерпретируем).
    if frag_total == 0 || frag_id >= frag_total {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tuic: некорректные frag_total/frag_id",
        ));
    }
    let size = u16::from_be_bytes([buf[8], buf[9]]) as usize;
    let mut pos = 10;
    let addr = parse_address_sync(buf, &mut pos)?;
    let end = pos
        .checked_add(size)
        .filter(|e| *e <= buf.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "tuic: payload за границей"))?;
    Ok((
        PacketHead {
            assoc_id,
            pkt_id,
            frag_total,
            frag_id,
            addr,
        },
        &buf[pos..end],
    ))
}

/// Синхронно разбирает TUIC-адрес из `buf` начиная с `*pos` (двигает `pos`).
/// `ATYP_NONE` → `Ok(None)`.
fn parse_address_sync(buf: &[u8], pos: &mut usize) -> io::Result<Option<Target>> {
    let need = |p: usize, n: usize| -> io::Result<()> {
        if p + n > buf.len() {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tuic: адрес за границей",
            ))
        } else {
            Ok(())
        }
    };
    need(*pos, 1)?;
    let atyp = buf[*pos];
    *pos += 1;
    match atyp {
        ATYP_NONE => Ok(None),
        ATYP_IPV4 => {
            need(*pos, 6)?;
            let o = [buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]];
            let port = u16::from_be_bytes([buf[*pos + 4], buf[*pos + 5]]);
            *pos += 6;
            Ok(Some(Target::Socket(SocketAddr::from((
                std::net::Ipv4Addr::from(o),
                port,
            )))))
        }
        ATYP_IPV6 => {
            need(*pos, 18)?;
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[*pos..*pos + 16]);
            let port = u16::from_be_bytes([buf[*pos + 16], buf[*pos + 17]]);
            *pos += 18;
            Ok(Some(Target::Socket(SocketAddr::from((
                std::net::Ipv6Addr::from(o),
                port,
            )))))
        }
        ATYP_DOMAIN => {
            need(*pos, 1)?;
            let len = buf[*pos] as usize;
            *pos += 1;
            need(*pos, len + 2)?;
            let host = String::from_utf8_lossy(&buf[*pos..*pos + len]).into_owned();
            let port = u16::from_be_bytes([buf[*pos + len], buf[*pos + len + 1]]);
            *pos += len + 2;
            Ok(Some(Target::Domain(host, port)))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("tuic: неизвестный ATYP {other:#x}"),
        )),
    }
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

    #[test]
    fn packet_single_roundtrip() {
        let target = Target::Domain("ya.ru".into(), 53);
        let dgs = encode_packets(7, 11, &target, b"hello-udp", 1200).unwrap();
        assert_eq!(dgs.len(), 1, "влезает в одну датаграмму");
        let (head, payload) = decode_packet(&dgs[0]).unwrap();
        assert_eq!(head.assoc_id, 7);
        assert_eq!(head.pkt_id, 11);
        assert_eq!(head.frag_total, 1);
        assert_eq!(head.frag_id, 0);
        assert_eq!(head.addr, Some(target));
        assert_eq!(payload, b"hello-udp");
    }

    #[test]
    fn packet_fragmentation() {
        let target = Target::Socket("1.2.3.4:443".parse().unwrap());
        let payload: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        // Маленький max → несколько фрагментов; адрес только в первом.
        let dgs = encode_packets(1, 2, &target, &payload, 120).unwrap();
        assert!(dgs.len() > 1, "должно фрагментироваться");
        let mut reassembled = Vec::new();
        for (i, dg) in dgs.iter().enumerate() {
            let (head, frag) = decode_packet(dg).unwrap();
            assert_eq!(head.frag_total as usize, dgs.len());
            assert_eq!(head.frag_id as usize, i);
            if i == 0 {
                assert_eq!(head.addr, Some(target.clone()));
            } else {
                assert_eq!(head.addr, None, "у не-первых фрагментов адреса нет");
            }
            reassembled.extend_from_slice(frag);
        }
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn dissociate_layout() {
        let b = encode_dissociate(0xBEEF);
        assert_eq!(b, vec![VERSION, CMD_DISSOCIATE, 0xBE, 0xEF]);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode_packet(&[0u8; 3]).is_err());
        assert!(decode_packet(&[VERSION, CMD_CONNECT, 0, 0, 0, 0, 1, 0, 0, 0]).is_err());
    }

    #[test]
    fn decode_rejects_bad_fragmentation() {
        // frag_total=0 и frag_id>=frag_total — битый заголовок, должен отвергаться
        // (а не трактоваться как одиночный пакет). Формат: VER TYPE assoc(2) pkt(2)
        // frag_total frag_id size(2) ATYP_NONE.
        let with = |frag_total: u8, frag_id: u8| {
            let mut b = vec![VERSION, CMD_PACKET, 0, 1, 0, 1, frag_total, frag_id, 0, 0];
            b.push(ATYP_NONE);
            b
        };
        assert!(decode_packet(&with(0, 0)).is_err(), "frag_total=0");
        assert!(decode_packet(&with(2, 2)).is_err(), "frag_id==frag_total");
        assert!(decode_packet(&with(2, 5)).is_err(), "frag_id>frag_total");
        // валидный одиночный
        assert!(decode_packet(&with(1, 0)).is_ok());
    }
}
