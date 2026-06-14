// Извлечено из cfal/shoes `src/shadow_tls/shadow_tls_server_handler.rs` —
// MIT License, (c) 2021-2023 Alex Lau. Только generic-парсер ServerHello,
// используемый Vision-фильтром (исходно `crate::shadow_tls::parse_server_hello`).
// Полный текст лицензии — `ATTRIBUTION.md`.

use crate::buf_reader::BufReader;

const TLS_HEADER_LEN: usize = 5;
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
const TLS_EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const RETRY_REQUEST_RANDOM_BYTES: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

pub struct ParsedServerHello {
    pub server_random: Vec<u8>,
    pub cipher_suite: u16,
    pub session_id_len: u8,
    pub is_tls13: bool,
}

/// Parses a ServerHello frame and extracts relevant fields.
/// This is a generic parser that can be used by multiple protocols (ShadowTLS, Vision).
/// It performs strict validation on structure but is lenient on TLS version requirements.
pub fn parse_server_hello(server_hello_frame: &[u8]) -> std::io::Result<ParsedServerHello> {
    // Minimum size when session_id_len=0 and no extensions:
    // 5 (record header) + 4 (handshake header) + 2 (version) + 32 (random)
    // + 1 (session_id_len byte) + 2 (cipher) + 1 (compression) = 47
    if server_hello_frame.len() < 47 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ServerHello frame too short",
        ));
    }

    let content_type = server_hello_frame[0];
    if content_type != CONTENT_TYPE_HANDSHAKE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected handshake content type",
        ));
    }

    let record_version_major = server_hello_frame[1];
    let record_version_minor = server_hello_frame[2];
    if record_version_major != 3 || record_version_minor != 3 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unexpected record TLS version {record_version_major}.{record_version_minor}"),
        ));
    }

    let mut reader = BufReader::new(&server_hello_frame[TLS_HEADER_LEN..]);

    let handshake_type = reader.read_u8()?;
    if handshake_type != HANDSHAKE_TYPE_SERVER_HELLO {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected ServerHello handshake type",
        ));
    }

    let message_len = reader.read_u24_be()? as usize;
    if reader.remaining() < message_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ServerHello message length exceeds frame",
        ));
    }

    // Legacy version (should be 0x0303 for TLS 1.2/1.3)
    let version_major = reader.read_u8()?;
    let version_minor = reader.read_u8()?;
    if version_major != 3 || version_minor != 3 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("expected TLS version 3.3, got {version_major}.{version_minor}"),
        ));
    }

    let server_random = reader.read_slice(32)?.to_vec();
    if server_random == RETRY_REQUEST_RANDOM_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "server sent a HelloRetryRequest",
        ));
    }

    // Session ID (variable length, 0-32 bytes)
    let session_id_len = reader.read_u8()?;
    if session_id_len > 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid session_id_len {session_id_len}, max is 32"),
        ));
    }
    reader.skip(session_id_len as usize)?;

    let cipher_suite = reader.read_u16_be()?;
    reader.skip(1)?; // compression method
    let mut is_tls13 = false;
    if !reader.is_consumed() {
        let extensions_len = reader.read_u16_be()? as usize;
        if reader.remaining() < extensions_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "extensions length exceeds remaining data",
            ));
        }

        let extensions_data = reader.read_slice(extensions_len)?;
        let mut ext_reader = BufReader::new(extensions_data);

        while !ext_reader.is_consumed() {
            let ext_type = ext_reader.read_u16_be()?;
            let ext_len = ext_reader.read_u16_be()?;

            if ext_type == TLS_EXT_SUPPORTED_VERSIONS {
                // In ServerHello, supported_versions is exactly 2 bytes (single selected version).
                if ext_len != 2 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("supported_versions extension should be 2 bytes, got {ext_len}"),
                    ));
                }
                let version_bytes = ext_reader.read_slice(2)?;
                is_tls13 = version_bytes[0] == 0x03 && version_bytes[1] == 0x04;
            // TLS 1.3
            } else {
                ext_reader.skip(ext_len as usize)?;
            }
        }
    }

    Ok(ParsedServerHello {
        server_random,
        cipher_suite,
        session_id_len,
        is_tls13,
    })
}
