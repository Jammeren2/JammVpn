//! Клиентский handshake VLESS Encryption (порт `client.go`, путь native + X25519
//! NFS + 1-RTT — основной для пользовательских ключей `mlkem768x25519plus.native.0rtt`).
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
    agreement::agree(my, &peer, aws_lc_rs::error::Unspecified, |s| Ok(s.to_vec()))
        .map_err(|_| io::Error::other("vless-enc: X25519 ECDH"))
}

/// Выполняет клиентский handshake поверх `stream`. Поддержан режим
/// `native` + NFS X25519 + 1-RTT (первое подключение).
pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    enc: &VlessEncryption,
) -> io::Result<EncState> {
    if !matches!(enc.mode, super::EncMode::Native) {
        return Err(io::Error::other(
            "vless-enc: пока поддержан только режим native",
        ));
    }
    let server_static = match &enc.nfs_key {
        NfsKey::X25519(k) => k,
        NfsKey::MlKem768(_) => {
            return Err(io::Error::other(
                "vless-enc: NFS ML-KEM-768 пока не поддержан (нужен X25519-auth ключ)",
            ))
        }
    };
    // Сервер авто-детектит шифр; на x86-64 (AES-NI) обе стороны используют AES-256-GCM.
    let use_aes = true;

    // --- clientHello ---
    let mut iv = [0u8; 16];
    rand::rng().fill_bytes(&mut iv);

    // relays (native, один ключ): эфемерный X25519 pub; nfsKey = ECDH.
    let (eph_priv, eph_pub) = x25519_keypair()?;
    let nfs_key = x25519_ecdh(&eph_priv, server_static)?;
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
    hello.extend_from_slice(&eph_pub); // relays
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

    // encryptedTicket (32) — peer nonce1; нам важно только продвинуть счётчик.
    let mut enc_ticket = vec![0u8; 32];
    stream.read_exact(&mut enc_ticket).await?;
    peer_aead.open(&enc_ticket, &[])?;

    // encryptedLength (18) — peer nonce2 → длина серверного паддинга.
    let mut enc_len = vec![0u8; 18];
    stream.read_exact(&mut enc_len).await?;
    let dl = peer_aead.open(&enc_len, &[])?;
    let peer_padding_len = decode_length(&dl);

    Ok(EncState {
        write_aead,
        peer_aead,
        united_key,
        use_aes,
        peer_padding_len,
    })
}
