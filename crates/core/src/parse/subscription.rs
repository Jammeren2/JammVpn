//! Разбор подписок (ТЗ, раздел 6, `IMP-*`).
//!
//! Подписка — это либо Base64 от списка ссылок, либо «сырой» список ссылок,
//! по одной на строку. Строки-комментарии (`#`, `//`) и пустые игнорируются.

use crate::base64;
use crate::error::ParseError;
use crate::model::ServerProfile;
use crate::parse::link::parse_link;

/// Разбирает тело подписки в список результатов (по одному на строку-ссылку).
///
/// Возвращает `Vec<Result<...>>`, чтобы вызывающий код мог показать частичный
/// успех (валидные серверы) и отдельно — ошибки конкретных строк.
pub fn parse_subscription(body: &str) -> Vec<Result<ServerProfile, ParseError>> {
    decode_body(body)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"))
        .map(parse_link)
        .collect()
}

/// Если тело не похоже на ссылки — пробуем Base64-декодировать целиком.
fn decode_body(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.contains("://") {
        return trimmed.to_string();
    }
    match base64::decode_to_string(trimmed) {
        Ok(decoded) if decoded.contains("://") => decoded,
        _ => trimmed.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(res: Vec<Result<ServerProfile, ParseError>>) -> Vec<String> {
        res.into_iter()
            .filter_map(Result::ok)
            .map(|p| p.name)
            .collect()
    }

    #[test]
    fn plain_multiline() {
        let body = "vless://uuid@a.com:443#a\n# comment\n//c\ntrojan://pw@b.com:443#b\n";
        assert_eq!(names(parse_subscription(body)), vec!["a", "b"]);
    }

    #[test]
    fn base64_body() {
        let inner = "vless://uuid@a.com:443#a\ntrojan://pw@b.com:443#b";
        let body = base64::encode_standard(inner.as_bytes());
        assert_eq!(names(parse_subscription(&body)), vec!["a", "b"]);
    }

    #[test]
    fn collects_errors_too() {
        let body = "vless://uuid@a.com:443#a\nnonsense\n";
        let res = parse_subscription(body);
        assert_eq!(res.len(), 2);
        assert!(res[0].is_ok());
        assert!(res[1].is_err());
    }
}
