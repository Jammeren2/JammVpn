//! Клиентский handshake VLESS Encryption (порт `client.go`). Поддержаны режимы
//! native/xorpub/random (XorMode 0/1/2) и NFS X25519 / ML-KEM-768; всегда 1-RTT.
//!
//! clientHello = `iv(16)` + `relays`(эфемерный X25519 pub 32) +
//! `pfsKeyExchange`(sealed len + sealed [ML-KEM-768 encap 1184 ++ X25519 pub 32]) +
//! `padding`(sealed len + sealed контент). Затем читаем serverHello, выводим
//! `pfsKey`, `unitedKey` и AEAD'ы для последующего потока данных.

use super::aead::{Aead, MAX_NONCE};
use super::{NfsKey, VlessEncryption};
use aws_lc_rs::{agreement, kem};
use rand::RngCore;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Результат handshake: готовые AEAD'ы и длина серверного паддинга (его контент
/// дочитывается при первом чтении потока).
pub struct EncState {
    pub write_aead: Aead,
    pub peer_aead: Aead,
    pub united_key: Vec<u8>,
    pub use_aes: bool,
    pub peer_padding_len: usize,
    /// XOR-обёртка потока данных (только режим `random`, XorMode=2).
    pub xor: Option<super::xor::XorState>,
}

/// ML-KEM-768 Encapsulate против статического encap-ключа сервера (1184 Б):
/// возвращает `(ciphertext 1088, общий секрет 32)` — порт ветки ML-KEM в relays.
fn mlkem_encapsulate(ek_bytes: &[u8]) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let ek = kem::EncapsulationKey::new(&kem::ML_KEM_768, ek_bytes)
        .map_err(|_| io::Error::other("vless-enc: ML-KEM encap key"))?;
    let (ct, ss) = ek
        .encapsulate()
        .map_err(|_| io::Error::other("vless-enc: ML-KEM encapsulate"))?;
    Ok((ct.as_ref().to_vec(), ss.as_ref().to_vec()))
}

fn encode_length(l: usize) -> [u8; 2] {
    [(l >> 8) as u8, l as u8]
}
fn decode_length(b: &[u8]) -> usize {
    ((b[0] as usize) << 8) | b[1] as usize
}

fn x25519_keypair() -> io::Result<(agreement::PrivateKey, Vec<u8>)> {
    let mut sk = [0u8; 32];
    rand::rng().fill_bytes(&mut sk);
    let priv_key = agreement::PrivateKey::from_private_key(&agreement::X25519, &sk)
        .map_err(|_| io::Error::other("vless-enc: X25519 ключ"))?;
    let pub_key = priv_key
        .compute_public_key()
        .map_err(|_| io::Error::other("vless-enc: X25519 pub"))?;
    Ok((priv_key, pub_key.as_ref().to_vec()))
}

fn x25519_ecdh(my: &agreement::PrivateKey, peer: &[u8]) -> io::Result<Vec<u8>> {
    let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, peer);
    agreement::agree(my, peer, aws_lc_rs::error::Unspecified, |s| Ok(s.to_vec()))
        .map_err(|_| io::Error::other("vless-enc: X25519 ECDH"))
}

/// Выполняет клиентский handshake поверх `stream` (1-RTT). Режим и тип NFS-ключа
/// берутся из дескриптора `enc`; для `random` возвращает [`EncState::xor`].
pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    enc: &VlessEncryption,
) -> io::Result<EncState> {
    // Режим → XorMode (conf_vless.go): native=0, xorpub=1, random=2.
    let xor_mode: u32 = match enc.mode {
        super::EncMode::Native => 0,
        super::EncMode::Xorpub => 1,
        super::EncMode::Random => 2,
    };
    // Сервер авто-детектит шифр; на x86-64 (AES-NI) обе стороны используют AES-256-GCM.
    let use_aes = true;

    // --- clientHello ---
    let mut iv = [0u8; 16];
    rand::rng().fill_bytes(&mut iv);

    // relays (один NFS-ключ): X25519 → эфемерный pub + ECDH; ML-KEM-768 →
    // Encapsulate(статический encap-ключ) → ciphertext(1088) + общий секрет.
    let (mut relays, nfs_key): (Vec<u8>, Vec<u8>) = match &enc.nfs_key {
        NfsKey::X25519(server_static) => {
            let (eph_priv, eph_pub) = x25519_keypair()?;
            let shared = x25519_ecdh(&eph_priv, server_static)?;
            (eph_pub, shared)
        }
        NfsKey::MlKem768(ek_bytes) => mlkem_encapsulate(ek_bytes.as_ref())?,
    };
    // xorpub/random: обфусцируем публичную часть relays потоком NewCTR(pkey, iv).
    if xor_mode > 0 {
        let pkey: &[u8] = match &enc.nfs_key {
            NfsKey::X25519(k) => k,
            NfsKey::MlKem768(k) => k.as_ref(),
        };
        super::xor::xor_relays(pkey, &iv, &mut relays);
    }
    let mut nfs = Aead::new(&iv, &nfs_key, use_aes);

    // PFS: эфемерные ML-KEM-768 (decap) + X25519.
    let mlkem_decap = kem::DecapsulationKey::generate(&kem::ML_KEM_768)
        .map_err(|_| io::Error::other("vless-enc: ML-KEM keygen"))?;
    let mlkem_encap_bytes = mlkem_decap
        .encapsulation_key()
        .and_then(|ek| ek.key_bytes().map(|b| b.as_ref().to_vec()))
        .map_err(|_| io::Error::other("vless-enc: ML-KEM encap bytes"))?;
    let (pfs_x_priv, pfs_x_pub) = x25519_keypair()?;
    let mut pfs_public_key = Vec::with_capacity(1184 + 32);
    pfs_public_key.extend_from_slice(&mlkem_encap_bytes); // 1184
    pfs_public_key.extend_from_slice(&pfs_x_pub); // 32

    // pfsKeyExchangeLength = 18 + 1184 + 32 + 16 = 1250; длина-значение = 1232.
    let mut hello = Vec::with_capacity(16 + 32 + 1250 + 64);
    hello.extend_from_slice(&iv);
    hello.extend_from_slice(&relays); // X25519 pub (32) или ML-KEM ciphertext (1088)
    hello.extend_from_slice(&nfs.seal(&encode_length(pfs_public_key.len() + 16), &[])); // nonce1
    hello.extend_from_slice(&nfs.seal(&pfs_public_key, &[])); // nonce2
    // padding: минимальный (len-блок + пустой контент-блок); сервер его дочитает.
    hello.extend_from_slice(&nfs.seal(&encode_length(16), &[])); // nonce3 (контент = 0+16 tag)
    hello.extend_from_slice(&nfs.seal(&[], &[])); // nonce4
    stream.write_all(&hello).await?;
    stream.flush().await?;

    // --- serverHello ---
    // encryptedPfsPublicKey: 1088 (ML-KEM ciphertext) + 32 (X25519 pub) + 16 tag.
    let mut enc_pfs = vec![0u8; 1088 + 32 + 16];
    stream.read_exact(&mut enc_pfs).await?;
    let server_pfs = nfs.open_with(&MAX_NONCE, &enc_pfs, &[])?; // 1120 байт
    if server_pfs.len() != 1120 {
        return Err(io::Error::other("vless-enc: неверная длина serverPfs"));
    }
    let mlkem_ct = kem::Ciphertext::from(&server_pfs[..1088]);
    let mlkem_shared = mlkem_decap
        .decapsulate(mlkem_ct)
        .map_err(|_| io::Error::other("vless-enc: ML-KEM decapsulate"))?;
    let x_shared = x25519_ecdh(&pfs_x_priv, &server_pfs[1088..1120])?;
    let mut pfs_key = Vec::with_capacity(64);
    pfs_key.extend_from_slice(mlkem_shared.as_ref()); // 32
    pfs_key.extend_from_slice(&x_shared); // 32

    let mut united_key = pfs_key;
    united_key.extend_from_slice(&nfs_key);
    let write_aead = Aead::new(&pfs_public_key, &united_key, use_aes);
    let mut peer_aead = Aead::new(&server_pfs, &united_key, use_aes);

    // encryptedTicket (32) — peer nonce1; для random режима нужен дешифрованный
    // ticket[:16] (read-CTR XorConn), иначе важно лишь продвинуть счётчик.
    let mut enc_ticket = vec![0u8; 32];
    stream.read_exact(&mut enc_ticket).await?;
    let ticket_plain = peer_aead.open(&enc_ticket, &[])?; // 16 байт

    // encryptedLength (18) — peer nonce2 → длина серверного паддинга.
    let mut enc_len = vec![0u8; 18];
    stream.read_exact(&mut enc_len).await?;
    let dl = peer_aead.open(&enc_len, &[])?;
    let peer_padding_len = decode_length(&dl);

    // Разовый лог — подтверждает, что слой VLESS Encryption реально работает
    // (помогает отличить «старый билд без поддержки» от рабочего соединения).
    use std::sync::atomic::{AtomicBool, Ordering};
    static LOGGED: AtomicBool = AtomicBool::new(false);
    if !LOGGED.swap(true, Ordering::Relaxed) {
        log::info!(
            "VLESS Encryption: handshake OK (aes={use_aes}, peer_padding={peer_padding_len} б)"
        );
    }

    // random (XorMode=2): поток данных оборачивается XorConn — write-CTR от iv,
    // read-CTR от дешифрованного ticket[:16], пропуск серверного паддинга.
    let xor = if xor_mode == 2 {
        let mut t16 = [0u8; 16];
        t16.copy_from_slice(&ticket_plain[..16]);
        Some(super::xor::XorState::client_1rtt(
            &united_key,
            &iv,
            &t16,
            peer_padding_len,
        ))
    } else {
        None
    };

    Ok(EncState {
        write_aead,
        peer_aead,
        united_key,
        use_aes,
        peer_padding_len,
        xor,
    })
}
