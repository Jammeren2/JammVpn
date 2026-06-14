//! XTLS-Vision: примитивы (TLS-дефреймеры, padding/unpadding).
//!
//! Порт self-contained примитивов из cfal/shoes (`src/vless/`) — MIT © 2021-2023
//! Alex Lau. Интеграция (обёртка над `RealityStream`) и flow-addon — отдельно.
//! Полный текст лицензии — `ATTRIBUTION.md`.

mod tls_deframer;
mod tls_fuzzy_deframer;
mod tls_handshake_util;
mod vision_filter;
mod vision_pad;
mod vision_stream;
mod vision_tls_util;
mod vision_unpad;

pub use vision_stream::VisionStream;
