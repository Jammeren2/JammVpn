//! Бинарный фрейминг Hysteria2 (сверено со спецификацией v2): QUIC-varint +
//! TCP-запрос (`0x401`) и ответ сервера. UDP/obfs — отдельно (MVP — TCP).

use crate::target::Target;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

/// ID кадра TCP-запроса (QUIC-varint `0x401`).
pub(crate) const TCP_REQUEST_ID: u64 = 0x401;

/// Кодирует значение как QUIC-varint (RFC 9000 §16) в конец `out`.
pub(crate) fn put_varint(out: &mut Vec<u8>, v: u64) {
    if v < (1 << 6) {
        out.push(v as u8);
    } else if v < (1 << 14) {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < (1 << 30) {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xC000_0000_0000_0000).to_be_bytes());
    }
}

/// Читает QUIC-varint из асинхронного потока.
pub(crate) async fn read_varint<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<u64> {
    let first = r.read_u8().await?;
    let prefix = first >> 6;
    let mut val = (first & 0x3F) as u64;
    let extra = match prefix {
        0 => 0,
        1 => 1,
        2 => 3,
        _ => 7,
    };
    for _ in 0..extra {
        val = (val << 8) | r.read_u8().await? as u64;
    }
    Ok(val)
}

/// Строит TCP-запрос Hysteria2: `varint(0x401) | addr | padding`.
/// Адрес — строка `host:port` (домен резолвит сервер — нет утечки DNS).
pub(crate) fn encode_tcp_request(target: &Target) -> Vec<u8> {
    // `Target` уже форматируется как `host:port` (IPv6 — в скобках).
    let addr = target.to_string();
    let mut out = Vec::with_capacity(addr.len() + 16);
    put_varint(&mut out, TCP_REQUEST_ID);
    put_varint(&mut out, addr.len() as u64);
    out.extend_from_slice(addr.as_bytes());
    // Паддинг: спецификация рекомендует случайный, но допускает пустой —
    // детерминированно шлём нулевой (без зависимости от ГПСЧ).
    put_varint(&mut out, 0);
    out
}

/// Ответ сервера на TCP-запрос.
pub(crate) struct TcpResponse {
    pub ok: bool,
    pub message: String,
}

/// Читает ответ сервера: `status(u8) | msg(varint+bytes) | padding(varint+bytes)`.
pub(crate) async fn read_tcp_response<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<TcpResponse> {
    let status = r.read_u8().await?;
    let msg_len = read_varint(r).await?;
    let msg = read_bounded_string(r, msg_len).await?;
    let pad_len = read_varint(r).await?;
    skip(r, pad_len).await?;
    Ok(TcpResponse {
        ok: status == 0,
        message: msg,
    })
}

/// Декодирует QUIC-varint из буфера: `(значение, сколько байт занял)`.
pub(crate) fn read_varint_buf(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let extra = match first >> 6 {
        0 => 0,
        1 => 1,
        2 => 3,
        _ => 7,
    };
    if buf.len() < 1 + extra {
        return None;
    }
    let mut val = (first & 0x3F) as u64;
    for &b in &buf[1..1 + extra] {
        val = (val << 8) | b as u64;
    }
    Some((val, 1 + extra))
}

/// Заголовок UDP-датаграммы Hysteria2.
pub(crate) struct UdpHead {
    pub session: u32,
    pub pkt_id: u16,
    pub frag_id: u8,
    pub frag_total: u8,
}

/// Кодирует UDP-пакет к `target` в одну или несколько QUIC-датаграмм:
/// `session(u32) | pkt_id(u16) | frag_id(u8) | frag_total(u8) | addr | payload`.
/// При превышении `max_datagram` payload режется на фрагменты (адрес — в каждом).
pub(crate) fn encode_udp_packets(
    session: u32,
    pkt_id: u16,
    target: &Target,
    payload: &[u8],
    max_datagram: usize,
) -> io::Result<Vec<Vec<u8>>> {
    let addr = target.to_string();
    let addr_bytes = addr.as_bytes();
    let mut addr_len_v = Vec::new();
    put_varint(&mut addr_len_v, addr_bytes.len() as u64);
    let header = 4 + 2 + 1 + 1 + addr_len_v.len() + addr_bytes.len();
    if max_datagram <= header {
        return Err(io::Error::other(
            "hysteria2: датаграмма мала для адреса",
        ));
    }
    let cap = max_datagram - header; // payload на фрагмент
    let total = payload.len().div_ceil(cap).max(1);
    if total > u8::MAX as usize {
        return Err(io::Error::other(
            "hysteria2: UDP-пакет требует >255 фрагментов",
        ));
    }
    let mut out = Vec::with_capacity(total);
    for i in 0..total {
        let start = i * cap;
        let end = (start + cap).min(payload.len());
        let mut dg = Vec::with_capacity(header + (end - start));
        dg.extend_from_slice(&session.to_be_bytes());
        dg.extend_from_slice(&pkt_id.to_be_bytes());
        dg.push(i as u8);
        dg.push(total as u8);
        dg.extend_from_slice(&addr_len_v);
        dg.extend_from_slice(addr_bytes);
        dg.extend_from_slice(&payload[start..end]);
        out.push(dg);
    }
    Ok(out)
}

/// Разбирает входящую UDP-датаграмму: `(заголовок, payload-фрагмент)`.
/// Адрес-источник пропускается (для connected-сессии он не нужен).
pub(crate) fn decode_udp_packet(dg: &[u8]) -> io::Result<(UdpHead, &[u8])> {
    if dg.len() < 8 {
        return Err(io::Error::other("hysteria2: короткая UDP-датаграмма"));
    }
    let session = u32::from_be_bytes([dg[0], dg[1], dg[2], dg[3]]);
    let pkt_id = u16::from_be_bytes([dg[4], dg[5]]);
    let frag_id = dg[6];
    let frag_total = dg[7];
    if frag_total == 0 || frag_id >= frag_total {
        return Err(io::Error::other("hysteria2: некорректная фрагментация"));
    }
    let (addr_len, consumed) =
        read_varint_buf(&dg[8..]).ok_or_else(|| io::Error::other("hysteria2: битый addr-len"))?;
    let off = 8 + consumed + addr_len as usize;
    if off > dg.len() {
        return Err(io::Error::other("hysteria2: addr выходит за датаграмму"));
    }
    Ok((
        UdpHead {
            session,
            pkt_id,
            frag_id,
            frag_total,
        },
        &dg[off..],
    ))
}

/// Читает `len` байт как UTF-8-строку (с разумным лимитом против абьюза).
async fn read_bounded_string<R: AsyncRead + Unpin>(r: &mut R, len: u64) -> io::Result<String> {
    const MAX: u64 = 4096;
    if len > MAX {
        return Err(io::Error::other("hysteria2: слишком длинное сообщение"));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Пропускает `n` байт потока (паддинг).
async fn skip<R: AsyncRead + Unpin>(r: &mut R, n: u64) -> io::Result<()> {
    const MAX: u64 = 1 << 20;
    if n > MAX {
        return Err(io::Error::other("hysteria2: слишком большой паддинг"));
    }
    let mut left = n;
    let mut buf = [0u8; 1024];
    while left > 0 {
        let take = left.min(buf.len() as u64) as usize;
        r.read_exact(&mut buf[..take]).await?;
        left -= take as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    fn dec_varint(mut b: &[u8]) -> u64 {
        // Синхронный декодер для тестов (зеркало read_varint).
        let first = b[0];
        b = &b[1..];
        let prefix = first >> 6;
        let mut val = (first & 0x3F) as u64;
        let extra = [0, 1, 3, 7][prefix as usize];
        for &x in &b[..extra] {
            val = (val << 8) | x as u64;
        }
        val
    }

    #[test]
    fn varint_roundtrip() {
        for v in [0u64, 63, 64, 1025, 16383, 16384, 1 << 29, 1 << 30, (1 << 62) - 1] {
            let mut out = Vec::new();
            put_varint(&mut out, v);
            assert_eq!(dec_varint(&out), v, "varint {v}");
        }
    }

    #[test]
    fn tcp_request_id_is_0x401() {
        let mut out = Vec::new();
        put_varint(&mut out, TCP_REQUEST_ID);
        assert_eq!(out, vec![0x44, 0x01]); // 2-байтовый varint 0x401
    }

    #[test]
    fn encode_tcp_request_domain() {
        let t = Target::Domain("example.com".into(), 443);
        let pkt = encode_tcp_request(&t);
        // 0x44 0x01 | len=15 | "example.com:443" | pad=0
        assert_eq!(&pkt[..2], &[0x44, 0x01]);
        assert_eq!(pkt[2], 15);
        assert_eq!(&pkt[3..18], b"example.com:443");
        assert_eq!(pkt[18], 0);
    }

    #[test]
    fn encode_tcp_request_ipv4() {
        let t = Target::Socket(SocketAddr::new(Ipv4Addr::new(1, 2, 3, 4).into(), 80));
        let pkt = encode_tcp_request(&t);
        assert_eq!(pkt[2] as usize, "1.2.3.4:80".len());
        assert_eq!(&pkt[3..3 + "1.2.3.4:80".len()], b"1.2.3.4:80");
    }

    #[tokio::test]
    async fn read_response_ok() {
        // status=0 | msg="OK"(2) | pad=3 bytes
        let data = [0x00, 0x02, b'O', b'K', 0x03, 9, 9, 9];
        let mut cur = &data[..];
        let resp = read_tcp_response(&mut cur).await.unwrap();
        assert!(resp.ok);
        assert_eq!(resp.message, "OK");
    }

    #[test]
    fn udp_single_roundtrip() {
        let t = Target::Domain("dns.example".into(), 53);
        let dgs = encode_udp_packets(7, 42, &t, b"hello-udp", 1500).unwrap();
        assert_eq!(dgs.len(), 1);
        let (h, payload) = decode_udp_packet(&dgs[0]).unwrap();
        assert_eq!(h.session, 7);
        assert_eq!(h.pkt_id, 42);
        assert_eq!(h.frag_total, 1);
        assert_eq!(payload, b"hello-udp");
    }

    #[test]
    fn udp_fragmentation_roundtrip() {
        let t = Target::Domain("h".into(), 1);
        let payload: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        // Малый max → несколько фрагментов.
        let dgs = encode_udp_packets(9, 1, &t, &payload, 200).unwrap();
        assert!(dgs.len() > 1, "ожидалась фрагментация");
        // Склеиваем payload-фрагменты в порядке frag_id.
        let mut parts: Vec<(u8, Vec<u8>)> = dgs
            .iter()
            .map(|dg| {
                let (h, p) = decode_udp_packet(dg).unwrap();
                assert_eq!(h.session, 9);
                assert_eq!(h.frag_total as usize, dgs.len());
                (h.frag_id, p.to_vec())
            })
            .collect();
        parts.sort_by_key(|(id, _)| *id);
        let joined: Vec<u8> = parts.into_iter().flat_map(|(_, p)| p).collect();
        assert_eq!(joined, payload);
    }

    #[tokio::test]
    async fn read_response_err() {
        let data = [0x01, 0x05, b'd', b'e', b'n', b'y', b'!', 0x00];
        let mut cur = &data[..];
        let resp = read_tcp_response(&mut cur).await.unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.message, "deny!");
    }
}
