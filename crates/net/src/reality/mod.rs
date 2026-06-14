//! REALITY: TLS-обфускация (X25519, HKDF-SHA256, AES-256-GCM, HMAC-SHA512).
//!
//! Порт клиентской части из cfal/shoes (`src/reality/`) — MIT © 2021-2023
//! Alex Lau. Серверная часть не переносится. Полный текст лицензии —
//! `ATTRIBUTION.md`.

mod common;
mod reality_aead;
mod reality_auth;
mod reality_certificate;
mod reality_cipher_suite;
mod reality_client_connection;
mod reality_client_verify;
mod reality_io_state;
mod reality_reader_writer;
mod reality_records;
mod reality_tls13_keys;
mod reality_tls13_messages;
mod reality_util;

pub use reality_cipher_suite::{CipherSuite, DEFAULT_CIPHER_SUITES};
pub use reality_client_connection::{
    feed_reality_client_connection, RealityClientConfig, RealityClientConnection,
};
pub use reality_reader_writer::{RealityReader, RealityWriter};
pub use reality_util::{decode_private_key, decode_public_key, decode_short_id, generate_keypair};
