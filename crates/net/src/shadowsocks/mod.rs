//! Shadowsocks AEAD (ТЗ, раздел 4, `PRO-*`).
//!
//! Legacy AEAD `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305` +
//! **SS-2022/SIP022** (`2022-blake3-*`): BLAKE3-подключ, структурный заголовок с
//! timestamp и привязкой ответа к соли запроса.
//!
//! - [`crypto`] — деривация ключей (EVP_BytesToKey/HKDF-SHA1 + BLAKE3) и AEAD.
//! - [`stream`] — legacy-поток ([`ShadowsocksStream`]).
//! - [`ss2022`] — SS-2022-поток ([`Ss2022Stream`]).

mod crypto;
mod ss2022;
mod stream;

pub use crypto::{evp_bytes_to_key, Method};
pub use ss2022::Ss2022Stream;
pub use stream::ShadowsocksStream;
