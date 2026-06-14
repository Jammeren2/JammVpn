//! Типы ошибок разбора конфигов.

use std::fmt;

/// Ошибка разбора share-ссылки / подписки / конфига.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Пустая строка на входе.
    EmptyInput,
    /// Строка не похожа на `scheme://...`.
    MalformedUrl(String),
    /// Схема не поддерживается.
    UnknownScheme(String),
    /// Отсутствует хост.
    MissingHost,
    /// Отсутствует порт.
    MissingPort,
    /// Порт не парсится в `u16`.
    InvalidPort(String),
    /// Отсутствует обязательное поле (uuid/password/...).
    MissingField(&'static str),
    /// Ошибка декодирования Base64.
    Base64(String),
    /// Декодированные байты не являются валидным UTF-8.
    Utf8,
    /// Некорректный CIDR/IP в списке маршрутизации.
    InvalidCidr(String),
    /// Ошибка разбора JSON.
    Json(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::EmptyInput => write!(f, "пустой ввод"),
            ParseError::MalformedUrl(s) => write!(f, "некорректный URL: {s}"),
            ParseError::UnknownScheme(s) => write!(f, "неизвестная схема: {s}"),
            ParseError::MissingHost => write!(f, "отсутствует хост"),
            ParseError::MissingPort => write!(f, "отсутствует порт"),
            ParseError::InvalidPort(s) => write!(f, "некорректный порт: {s}"),
            ParseError::MissingField(s) => write!(f, "отсутствует поле: {s}"),
            ParseError::Base64(s) => write!(f, "ошибка base64: {s}"),
            ParseError::Utf8 => write!(f, "некорректный UTF-8"),
            ParseError::InvalidCidr(s) => write!(f, "некорректный CIDR/IP: {s}"),
            ParseError::Json(s) => write!(f, "ошибка JSON: {s}"),
        }
    }
}

impl std::error::Error for ParseError {}
