//! Shadowsocks AEAD (ТЗ, раздел 4, `PRO-*`).
//!
//! Поддержаны AEAD-шифры `aes-128-gcm`, `aes-256-gcm`,
//! `chacha20-ietf-poly1305`. SS-2022 (blake3) — отдельно, позже.
//!
//! - [`crypto`] — деривация ключей (EVP_BytesToKey, HKDF-SHA1) и AEAD-операции.
//! - [`stream`] — асинхронная обёртка [`ShadowsocksStream`], прозрачно
//!   шифрующая/расшифровывающая поток (соль + чанки `[len][payload]`).

mod crypto;
mod stream;

pub use crypto::{evp_bytes_to_key, Method};
pub use stream::ShadowsocksStream;
