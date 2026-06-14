// Ported from cfal/shoes (https://github.com/cfal/shoes) — MIT License, (c) 2021-2023 Alex Lau.
// Adapted for JammVPN. Full license text in ATTRIBUTION.md.
/// Represents the I/O state after processing packets
#[derive(Debug, Clone, Copy)]
pub struct RealityIoState {
    /// Number of plaintext bytes available to read
    plaintext_bytes_to_read: usize,
}

impl RealityIoState {
    /// Create a new RealityIoState
    pub fn new(plaintext_bytes_to_read: usize) -> Self {
        Self {
            plaintext_bytes_to_read,
        }
    }

    /// How many plaintext bytes could be obtained via Read without further I/O
    pub fn plaintext_bytes_to_read(&self) -> usize {
        self.plaintext_bytes_to_read
    }
}
