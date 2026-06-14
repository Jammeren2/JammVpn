//! Минимальный JSON-парсер без внешних зависимостей.
//!
//! Достаточен для импорта конфигов Xray и sing-box (ТЗ, раздел 6). Сохраняет
//! порядок ключей объекта. Числа хранятся как `f64`; для портов есть
//! [`JsonValue::as_u16_port`], принимающий и число, и строку.

use crate::error::ParseError;

/// Узел JSON.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    /// `null`
    Null,
    /// `true` / `false`
    Bool(bool),
    /// число (хранится как `f64`)
    Number(f64),
    /// строка
    String(String),
    /// массив
    Array(Vec<JsonValue>),
    /// объект (порядок ключей сохраняется)
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    /// Разбирает строку JSON целиком (без хвостового мусора).
    pub fn parse(input: &str) -> Result<JsonValue, ParseError> {
        let mut p = Parser::new(input);
        let v = p.value()?;
        p.ws();
        if p.i != p.chars.len() {
            return Err(json_err());
        }
        Ok(v)
    }

    /// Значение по ключу (для объекта).
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(o) => o.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Строковое значение.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Логическое значение.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JsonValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Число как `f64`.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            JsonValue::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// Неотрицательное целое.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            JsonValue::Number(n) if *n >= 0.0 && n.fract() == 0.0 => Some(*n as u64),
            _ => None,
        }
    }

    /// Порт: принимает число либо строку с числом.
    pub fn as_u16_port(&self) -> Option<u16> {
        if let Some(n) = self.as_u64() {
            return u16::try_from(n).ok();
        }
        self.as_str().and_then(|s| s.parse::<u16>().ok())
    }

    /// Массив.
    pub fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            JsonValue::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Объект (пары ключ/значение).
    pub fn as_object(&self) -> Option<&[(String, JsonValue)]> {
        match self {
            JsonValue::Object(o) => Some(o),
            _ => None,
        }
    }
}

fn json_err() -> ParseError {
    ParseError::Json("некорректный JSON".to_string())
}

struct Parser {
    chars: Vec<char>,
    i: usize,
}

impl Parser {
    fn new(s: &str) -> Self {
        Self {
            chars: s.chars().collect(),
            i: 0,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.i).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.chars.get(self.i).copied();
        if c.is_some() {
            self.i += 1;
        }
        c
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.i += 1;
        }
    }

    fn value(&mut self) -> Result<JsonValue, ParseError> {
        self.ws();
        match self.peek().ok_or_else(json_err)? {
            '{' => self.object(),
            '[' => self.array(),
            '"' => Ok(JsonValue::String(self.string()?)),
            't' => self.literal("true", JsonValue::Bool(true)),
            'f' => self.literal("false", JsonValue::Bool(false)),
            'n' => self.literal("null", JsonValue::Null),
            c if c == '-' || c.is_ascii_digit() => self.number(),
            _ => Err(json_err()),
        }
    }

    fn literal(&mut self, word: &str, val: JsonValue) -> Result<JsonValue, ParseError> {
        for expected in word.chars() {
            if self.bump() != Some(expected) {
                return Err(json_err());
            }
        }
        Ok(val)
    }

    fn number(&mut self) -> Result<JsonValue, ParseError> {
        let start = self.i;
        if self.peek() == Some('-') {
            self.i += 1;
        }
        while matches!(self.peek(), Some(c) if c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '+' | '-'))
        {
            self.i += 1;
        }
        let s: String = self.chars[start..self.i].iter().copied().collect();
        s.parse::<f64>()
            .map(JsonValue::Number)
            .map_err(|_| json_err())
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.i += 1; // открывающая кавычка
        let mut out = String::new();
        loop {
            match self.bump().ok_or_else(json_err)? {
                '"' => return Ok(out),
                '\\' => match self.bump().ok_or_else(json_err)? {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    '/' => out.push('/'),
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'r' => out.push('\r'),
                    'b' => out.push('\u{8}'),
                    'f' => out.push('\u{C}'),
                    'u' => out.push(self.unicode_escape()?),
                    _ => return Err(json_err()),
                },
                ch => out.push(ch),
            }
        }
    }

    fn unicode_escape(&mut self) -> Result<char, ParseError> {
        let cp = self.hex4()?;
        if (0xD800..=0xDBFF).contains(&cp) {
            if self.bump() != Some('\\') || self.bump() != Some('u') {
                return Err(json_err());
            }
            let lo = self.hex4()?;
            if !(0xDC00..=0xDFFF).contains(&lo) {
                return Err(json_err());
            }
            let c = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            char::from_u32(c).ok_or_else(json_err)
        } else {
            Ok(char::from_u32(cp).unwrap_or('\u{FFFD}'))
        }
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let mut v = 0u32;
        for _ in 0..4 {
            let d = self
                .bump()
                .ok_or_else(json_err)?
                .to_digit(16)
                .ok_or_else(json_err)?;
            v = v * 16 + d;
        }
        Ok(v)
    }

    fn array(&mut self) -> Result<JsonValue, ParseError> {
        self.i += 1; // '['
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(']') {
            self.i += 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            items.push(self.value()?);
            self.ws();
            match self.bump().ok_or_else(json_err)? {
                ',' => continue,
                ']' => return Ok(JsonValue::Array(items)),
                _ => return Err(json_err()),
            }
        }
    }

    fn object(&mut self) -> Result<JsonValue, ParseError> {
        self.i += 1; // '{'
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some('}') {
            self.i += 1;
            return Ok(JsonValue::Object(items));
        }
        loop {
            self.ws();
            if self.peek() != Some('"') {
                return Err(json_err());
            }
            let key = self.string()?;
            self.ws();
            if self.bump() != Some(':') {
                return Err(json_err());
            }
            let val = self.value()?;
            items.push((key, val));
            self.ws();
            match self.bump().ok_or_else(json_err)? {
                ',' => continue,
                '}' => return Ok(JsonValue::Object(items)),
                _ => return Err(json_err()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scalars() {
        assert_eq!(JsonValue::parse("true").unwrap(), JsonValue::Bool(true));
        assert_eq!(JsonValue::parse("null").unwrap(), JsonValue::Null);
        assert_eq!(
            JsonValue::parse("  -12.5e1 ").unwrap(),
            JsonValue::Number(-125.0)
        );
        assert_eq!(JsonValue::parse("\"ab\"").unwrap().as_str(), Some("ab"));
    }

    #[test]
    fn parses_nested() {
        let v = JsonValue::parse(r#"{"a":[1,2,{"b":"c"}],"port":"443"}"#).unwrap();
        assert_eq!(v.get("a").unwrap().as_array().unwrap().len(), 3);
        assert_eq!(
            v.get("a").unwrap().as_array().unwrap()[2]
                .get("b")
                .unwrap()
                .as_str(),
            Some("c")
        );
        assert_eq!(v.get("port").unwrap().as_u16_port(), Some(443));
    }

    #[test]
    fn handles_escapes() {
        let v = JsonValue::parse(r#""line\n\tAé""#).unwrap();
        assert_eq!(v.as_str(), Some("line\n\tAé"));
    }

    #[test]
    fn surrogate_pair() {
        // U+1F600 = 😀
        let v = JsonValue::parse(r#""😀""#).unwrap();
        assert_eq!(v.as_str(), Some("😀"));
    }

    #[test]
    fn rejects_trailing_and_garbage() {
        assert!(JsonValue::parse("{} x").is_err());
        assert!(JsonValue::parse("[1,]").is_err());
        assert!(JsonValue::parse("nul").is_err());
    }

    #[test]
    fn port_as_number() {
        let v = JsonValue::parse(r#"{"p":8443}"#).unwrap();
        assert_eq!(v.get("p").unwrap().as_u16_port(), Some(8443));
    }
}
