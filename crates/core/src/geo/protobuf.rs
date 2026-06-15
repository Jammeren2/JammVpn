//! Минимальный читатель protobuf wire-format (для geosite/geoip `.dat`).
//!
//! Базы v2ray/xray (`geosite.dat`, `geoip.dat`) — это protobuf-сообщения с простой
//! фиксированной схемой. Полноценный protobuf-крейт не нужен: достаточно varint и
//! length-delimited полей (плюс пропуск неизвестных). См. [`super`].

use super::GeoError;

/// Курсор по байтам protobuf-сообщения.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

/// Тип кодирования поля (wire type).
pub const WIRE_VARINT: u8 = 0;
pub const WIRE_I64: u8 = 1;
pub const WIRE_LEN: u8 = 2;
pub const WIRE_I32: u8 = 5;

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Достигнут ли конец сообщения.
    pub fn eof(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Читает varint (LEB128, до 10 байт).
    pub fn read_varint(&mut self) -> Result<u64, GeoError> {
        let mut result: u64 = 0;
        let mut shift = 0;
        loop {
            if self.pos >= self.buf.len() {
                return Err(GeoError::Truncated);
            }
            let byte = self.buf[self.pos];
            self.pos += 1;
            if shift >= 64 {
                return Err(GeoError::Malformed("varint длиннее 10 байт"));
            }
            result |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
        }
    }

    /// Читает тег поля: `(номер_поля, wire_type)`.
    pub fn read_tag(&mut self) -> Result<(u32, u8), GeoError> {
        let key = self.read_varint()?;
        let field = (key >> 3) as u32;
        let wire = (key & 0x07) as u8;
        if field == 0 {
            return Err(GeoError::Malformed("нулевой номер поля"));
        }
        Ok((field, wire))
    }

    /// Читает length-delimited поле (string/bytes/вложенное сообщение).
    pub fn read_bytes(&mut self) -> Result<&'a [u8], GeoError> {
        let len = self.read_varint()? as usize;
        let end = self.pos.checked_add(len).ok_or(GeoError::Truncated)?;
        if end > self.buf.len() {
            return Err(GeoError::Truncated);
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Читает length-delimited поле как UTF-8 строку (невалидный UTF-8 — lossy).
    pub fn read_string(&mut self) -> Result<String, GeoError> {
        Ok(String::from_utf8_lossy(self.read_bytes()?).into_owned())
    }

    /// Пропускает значение поля заданного wire type.
    pub fn skip(&mut self, wire: u8) -> Result<(), GeoError> {
        match wire {
            WIRE_VARINT => {
                self.read_varint()?;
            }
            WIRE_I64 => self.advance(8)?,
            WIRE_LEN => {
                self.read_bytes()?;
            }
            WIRE_I32 => self.advance(4)?,
            _ => return Err(GeoError::Malformed("неизвестный wire type")),
        }
        Ok(())
    }

    fn advance(&mut self, n: usize) -> Result<(), GeoError> {
        let end = self.pos.checked_add(n).ok_or(GeoError::Truncated)?;
        if end > self.buf.len() {
            return Err(GeoError::Truncated);
        }
        self.pos = end;
        Ok(())
    }
}

/// Сборщики protobuf-сообщений для тестов geo-разбора (используются в нескольких
/// модулях, поэтому вынесены сюда).
#[cfg(test)]
pub mod tests_support {
    use super::{WIRE_LEN, WIRE_VARINT};

    /// Кодирует varint.
    pub fn put_varint(out: &mut Vec<u8>, mut v: u64) {
        loop {
            let mut b = (v & 0x7F) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                break;
            }
        }
    }

    pub fn tag(field: u32, wire: u8) -> u64 {
        (u64::from(field) << 3) | u64::from(wire)
    }

    fn field_varint(out: &mut Vec<u8>, field: u32, v: u64) {
        put_varint(out, tag(field, WIRE_VARINT));
        put_varint(out, v);
    }

    fn field_bytes(out: &mut Vec<u8>, field: u32, data: &[u8]) {
        put_varint(out, tag(field, WIRE_LEN));
        put_varint(out, data.len() as u64);
        out.extend_from_slice(data);
    }

    /// `Domain { type, value }`.
    pub fn domain_msg(dtype: u64, value: &str) -> Vec<u8> {
        let mut m = Vec::new();
        field_varint(&mut m, 1, dtype);
        field_bytes(&mut m, 2, value.as_bytes());
        m
    }

    /// `GeoSite { country_code, domain* }`.
    pub fn geosite_entry(code: &str, domains: &[Vec<u8>]) -> Vec<u8> {
        let mut m = Vec::new();
        field_bytes(&mut m, 1, code.as_bytes());
        for d in domains {
            field_bytes(&mut m, 2, d);
        }
        m
    }

    /// `CIDR { ip, prefix }`.
    pub fn cidr_msg(ip: &[u8], prefix: u64) -> Vec<u8> {
        let mut m = Vec::new();
        field_bytes(&mut m, 1, ip);
        field_varint(&mut m, 2, prefix);
        m
    }

    /// `GeoIP { country_code, cidr* }`.
    pub fn geoip_entry(code: &str, cidrs: &[Vec<u8>]) -> Vec<u8> {
        let mut m = Vec::new();
        field_bytes(&mut m, 1, code.as_bytes());
        for c in cidrs {
            field_bytes(&mut m, 2, c);
        }
        m
    }

    /// `*List { entry* }` (entry — поле `field`, обычно 1).
    pub fn list(field: u32, entries: &[Vec<u8>]) -> Vec<u8> {
        let mut m = Vec::new();
        for e in entries {
            field_bytes(&mut m, field, e);
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::{put_varint, tag};
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for v in [0u64, 1, 127, 128, 300, 16384, u32::MAX as u64, u64::MAX] {
            let mut b = Vec::new();
            put_varint(&mut b, v);
            let mut r = Reader::new(&b);
            assert_eq!(r.read_varint().unwrap(), v);
            assert!(r.eof());
        }
    }

    #[test]
    fn reads_tag_and_bytes() {
        let mut b = Vec::new();
        put_varint(&mut b, tag(2, WIRE_LEN));
        put_varint(&mut b, 5);
        b.extend_from_slice(b"hello");
        let mut r = Reader::new(&b);
        let (field, wire) = r.read_tag().unwrap();
        assert_eq!((field, wire), (2, WIRE_LEN));
        assert_eq!(r.read_bytes().unwrap(), b"hello");
    }

    #[test]
    fn skip_unknown_fields() {
        let mut b = Vec::new();
        // поле 1 varint = 42 (пропустить), затем поле 2 len = "ok"
        put_varint(&mut b, tag(1, WIRE_VARINT));
        put_varint(&mut b, 42);
        put_varint(&mut b, tag(2, WIRE_LEN));
        put_varint(&mut b, 2);
        b.extend_from_slice(b"ok");
        let mut r = Reader::new(&b);
        let (_, w) = r.read_tag().unwrap();
        r.skip(w).unwrap();
        let (f, _) = r.read_tag().unwrap();
        assert_eq!(f, 2);
        assert_eq!(r.read_string().unwrap(), "ok");
    }

    #[test]
    fn truncated_is_error() {
        let b = [0x82u8]; // незавершённый varint
        let mut r = Reader::new(&b);
        assert!(r.read_varint().is_err());

        let mut b2 = Vec::new();
        put_varint(&mut b2, tag(1, WIRE_LEN));
        put_varint(&mut b2, 10); // обещано 10 байт, а их нет
        let mut r2 = Reader::new(&b2);
        r2.read_tag().unwrap();
        assert!(r2.read_bytes().is_err());
    }
}
