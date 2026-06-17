//! Shadowsocks 2022 UDP (SIP022): защищённый UDP-relay с session/packet id и
//! anti-replay-окном (легаси SS UDP их не имеет).
//!
//! Два режима (по методу):
//! - **AES** (`2022-blake3-aes-128/256-gcm`): «separate header» 16 байт
//!   (`session_id(8) || packet_id(8)`), шифрованный AES-ECB ключом PSK; тело —
//!   AES-GCM с подключом `derive_key("…session subkey", PSK||session_id)` и nonce
//!   `header_pt[4..16]`.
//! - **ChaCha** (`2022-blake3-chacha20-poly1305`): XChaCha20-Poly1305 ключом PSK,
//!   24-байтный случайный nonce; `session_id||packet_id` — в начале plaintext.
//!
//! Тело (одинаково для обоих режимов): запрос
//! `type(0) | timestamp(8) | padding_len(2) | padding | address | payload`;
//! ответ `type(1) | timestamp(8) | client_session_id(8) | padding_len(2) | … `.

use super::crypto::{
    aes_ecb_decrypt_block, aes_ecb_encrypt_block, open_nonce, psk_hash_16, seal_nonce,
    session_subkey_2022, Method,
};
use super::udp::{encode_address, parse_address};
use crate::target::Target;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const TYPE_CLIENT: u8 = 0;
const TYPE_SERVER: u8 = 1;
/// Окно валидности timestamp (±сек): иначе пакет считается replay.
const TIMESTAMP_WINDOW: u64 = 30;
/// Ширина sliding-window анти-replay по packet_id.
const REPLAY_WINDOW: u64 = 64;

fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Случайные байты; ошибка ГСЧ пробрасывается (НЕ возвращаем нули — иначе
/// session_id/nonce были бы предсказуемы → катастрофический nonce-reuse).
fn random_bytes<const N: usize>() -> io::Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|_| io::Error::other("ss2022: ошибка ГСЧ"))?;
    Ok(b)
}

/// Состояние анти-replay (WireGuard-стиль sliding window по `packet_id` в рамках
/// серверной сессии). Сброс при смене `server_session_id` (рестарт сервера).
#[derive(Default)]
struct Replay {
    sid: Option<[u8; 8]>,
    highest: u64,
    window: u64,
}

impl Replay {
    /// Принять `packet_id` для серверной сессии `sid`: `false` — дубликат/вне окна.
    fn accept(&mut self, sid: [u8; 8], pid: u64) -> bool {
        if self.sid != Some(sid) {
            // Новая серверная сессия — окно сбрасывается на неё.
            *self = Replay {
                sid: Some(sid),
                highest: pid,
                window: 1,
            };
            return true;
        }
        if pid > self.highest {
            let shift = pid - self.highest;
            self.window = if shift >= REPLAY_WINDOW {
                0
            } else {
                self.window << shift
            };
            self.window |= 1;
            self.highest = pid;
            true
        } else {
            let diff = self.highest - pid;
            if diff >= REPLAY_WINDOW {
                return false; // слишком старый
            }
            let bit = 1u64 << diff;
            if self.window & bit != 0 {
                return false; // дубликат
            }
            self.window |= bit;
            true
        }
    }
}

fn xchacha_seal(psk: &[u8], nonce: &[u8; 24], pt: &[u8]) -> io::Result<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    let cipher = XChaCha20Poly1305::new_from_slice(psk).map_err(|_| bad("ss2022: ключ chacha"))?;
    cipher
        .encrypt(XNonce::from_slice(nonce), pt)
        .map_err(|_| bad("ss2022: ошибка шифрования"))
}

fn xchacha_open(psk: &[u8], nonce: &[u8; 24], ct: &[u8]) -> io::Result<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    let cipher = XChaCha20Poly1305::new_from_slice(psk).map_err(|_| bad("ss2022: ключ chacha"))?;
    cipher
        .decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|_| bad("ss2022: ошибка расшифровки (аутентификация)"))
}

/// Клиентская SS-2022 UDP-сессия: фиксированный `session_id` + счётчик `packet_id`
/// (исходящий) + anti-replay по серверным `packet_id` (входящий).
pub struct Ss2022UdpSession {
    method: Method,
    psk: Vec<u8>,
    /// identity-PSK (iPSK) для multi-user (SIP022 EIH); пусто для single-user.
    identity_psks: Vec<Vec<u8>>,
    session_id: [u8; 8],
    next_packet_id: AtomicU64,
    replay: Mutex<Replay>,
}

impl Ss2022UdpSession {
    /// Создаёт single-user сессию (генерирует `session_id`). Ошибка — при сбое ГСЧ.
    pub fn new(method: Method, psk: Vec<u8>) -> io::Result<Self> {
        Self::with_identity(method, psk, Vec::new())
    }

    /// Создаёт сессию с цепочкой identity-PSK (multi-user, SIP022 EIH).
    /// `psk` — сессионная uPSK, `identity_psks` — iPSK (внешний→внутренний).
    pub fn with_identity(
        method: Method,
        psk: Vec<u8>,
        identity_psks: Vec<Vec<u8>>,
    ) -> io::Result<Self> {
        Ok(Self {
            method,
            psk,
            identity_psks,
            session_id: random_bytes::<8>()?,
            next_packet_id: AtomicU64::new(0),
            replay: Mutex::new(Replay::default()),
        })
    }

    /// Тело запроса: `type(0) | ts(8) | padding_len(2)=0 | address | payload`.
    fn request_body(&self, target: &Target, payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::with_capacity(payload.len() + 32);
        body.push(TYPE_CLIENT);
        body.extend_from_slice(&now_ts().to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes()); // padding_len = 0
        body.extend_from_slice(&encode_address(target));
        body.extend_from_slice(payload);
        body
    }

    /// Шифрует исходящий UDP-пакет к `target`.
    pub fn encrypt(&self, target: &Target, payload: &[u8]) -> io::Result<Vec<u8>> {
        let packet_id = self.next_packet_id.fetch_add(1, Ordering::Relaxed);
        let body = self.request_body(target, payload);
        if self.method.is_chacha2022() {
            // plaintext: session_id(8) | packet_id(8) | body
            let mut pt = Vec::with_capacity(16 + body.len());
            pt.extend_from_slice(&self.session_id);
            pt.extend_from_slice(&packet_id.to_be_bytes());
            pt.extend_from_slice(&body);
            let nonce = random_bytes::<24>()?;
            let ct = xchacha_seal(&self.psk, &nonce, &pt)?;
            let mut out = Vec::with_capacity(24 + ct.len());
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&ct);
            Ok(out)
        } else {
            // separate header (16): session_id(8) | packet_id(8).
            let mut header = [0u8; 16];
            header[..8].copy_from_slice(&self.session_id);
            header[8..].copy_from_slice(&packet_id.to_be_bytes());
            let nonce: [u8; 12] = header[4..16].try_into().unwrap(); // из ПЛЕЙНТЕКСТА
            // AEAD-тело шифруется сессионной (uPSK) подключом.
            let subkey = session_subkey_2022(self.method, &self.psk, &self.session_id);
            let sealed = seal_nonce(self.method, &subkey, &nonce, &body)?;

            // multi-user (SIP022 EIH): для каждой iPSK — AES-ECB(iPSK,
            // BLAKE3(next_psk)[..16] XOR плейнтекст-заголовок). Заголовки идут
            // между separate header и AEAD-телом.
            let mut id_headers = Vec::with_capacity(self.identity_psks.len() * 16);
            for (i, ipsk) in self.identity_psks.iter().enumerate() {
                let next = self
                    .identity_psks
                    .get(i + 1)
                    .map(Vec::as_slice)
                    .unwrap_or(&self.psk);
                let mut block = psk_hash_16(next);
                for j in 0..16 {
                    block[j] ^= header[j];
                }
                aes_ecb_encrypt_block(ipsk, &mut block)?;
                id_headers.extend_from_slice(&block);
            }
            // separate header шифруется внешней iPSK (для single-user — самой PSK).
            let header_key = self.identity_psks.first().map(Vec::as_slice).unwrap_or(&self.psk);
            let mut hk = [0u8; 16];
            hk.copy_from_slice(&header);
            aes_ecb_encrypt_block(header_key, &mut hk)?;

            let mut out = Vec::with_capacity(16 + id_headers.len() + sealed.len());
            out.extend_from_slice(&hk);
            out.extend_from_slice(&id_headers);
            out.extend_from_slice(&sealed);
            Ok(out)
        }
    }

    /// Расшифровывает ответ сервера → payload. Валидирует type/timestamp/
    /// client_session_id, затем (после успешной валидации, как требует SIP022)
    /// проверяет anti-replay по серверному `packet_id`.
    pub fn decrypt(&self, packet: &[u8]) -> io::Result<Vec<u8>> {
        let (server_sid, server_pid, body) = if self.method.is_chacha2022() {
            if packet.len() < 24 {
                return Err(bad("ss2022-udp: пакет короче nonce"));
            }
            let nonce: [u8; 24] = packet[..24].try_into().unwrap();
            let pt = xchacha_open(&self.psk, &nonce, &packet[24..])?;
            if pt.len() < 16 {
                return Err(bad("ss2022-udp: усечённый заголовок"));
            }
            // pt = server_session_id(8) | server_packet_id(8) | body
            let sid: [u8; 8] = pt[..8].try_into().unwrap();
            let pid = u64::from_be_bytes(pt[8..16].try_into().unwrap());
            (sid, pid, pt[16..].to_vec())
        } else {
            if packet.len() < 32 {
                return Err(bad("ss2022-udp: пакет короче минимума"));
            }
            let mut header: [u8; 16] = packet[..16].try_into().unwrap();
            aes_ecb_decrypt_block(&self.psk, &mut header)?;
            let sid: [u8; 8] = header[..8].try_into().unwrap();
            let pid = u64::from_be_bytes(header[8..16].try_into().unwrap());
            let nonce: [u8; 12] = header[4..16].try_into().unwrap();
            let subkey = session_subkey_2022(self.method, &self.psk, &sid);
            let body = open_nonce(self.method, &subkey, &nonce, &packet[16..])?;
            (sid, pid, body)
        };
        let payload = self.parse_response_body(&body)?;
        // Окно обновляем ТОЛЬКО после успешной валидации (требование SIP022).
        if !self.replay.lock().unwrap().accept(server_sid, server_pid) {
            return Err(bad("ss2022-udp: replay/дубликат пакета"));
        }
        Ok(payload)
    }

    /// Ответ: `type(1) | ts(8) | client_session_id(8) | padding_len(2) | padding |
    /// address | payload`.
    fn parse_response_body(&self, body: &[u8]) -> io::Result<Vec<u8>> {
        if body.len() < 19 {
            return Err(bad("ss2022-udp: усечённый ответ"));
        }
        if body[0] != TYPE_SERVER {
            return Err(bad("ss2022-udp: пакет не серверный"));
        }
        let ts = u64::from_be_bytes(body[1..9].try_into().unwrap());
        if now_ts().abs_diff(ts) > TIMESTAMP_WINDOW {
            return Err(bad("ss2022-udp: timestamp вне окна (replay?)"));
        }
        let client_sid: [u8; 8] = body[9..17].try_into().unwrap();
        if client_sid != self.session_id {
            return Err(bad("ss2022-udp: чужой client_session_id"));
        }
        let padding_len = u16::from_be_bytes(body[17..19].try_into().unwrap()) as usize;
        let pos = 19 + padding_len;
        if pos > body.len() {
            return Err(bad("ss2022-udp: padding за границей"));
        }
        let (_addr, payload) = parse_address(&body[pos..])?;
        Ok(payload.to_vec())
    }
}

/// Серверная сторона SS-2022 UDP для тестов: расшифровывает запрос клиента и
/// формирует ответ (type=1, client_session_id, тот же payload) под своим
/// session_id и `server_pid`. Используется юнит-тестами и e2e relay-тестом.
#[cfg(test)]
pub(crate) fn echo_server_packet(
    method: Method,
    psk: &[u8],
    client_packet: &[u8],
    server_pid: u64,
) -> Vec<u8> {
    tests::server_echo(method, psk, client_packet, server_pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shadowsocks::evp_bytes_to_key;

    /// Сервер-эхо: расшифровывает запрос клиента и формирует ответ (type=1,
    /// client_session_id, тот же payload) под фиксированным server session_id и
    /// заданным `server_pid` (растёт от пакета к пакету — иначе anti-replay).
    pub(super) fn server_echo(
        method: Method,
        psk: &[u8],
        client_packet: &[u8],
        server_pid: u64,
    ) -> Vec<u8> {
        // Разбор запроса клиента (с client session_id).
        let (client_sid, body) = if method.is_chacha2022() {
            let nonce: [u8; 24] = client_packet[..24].try_into().unwrap();
            let pt = xchacha_open(psk, &nonce, &client_packet[24..]).unwrap();
            let sid: [u8; 8] = pt[..8].try_into().unwrap();
            (sid, pt[16..].to_vec())
        } else {
            let mut header: [u8; 16] = client_packet[..16].try_into().unwrap();
            aes_ecb_decrypt_block(psk, &mut header).unwrap();
            let sid: [u8; 8] = header[..8].try_into().unwrap();
            let nonce: [u8; 12] = header[4..16].try_into().unwrap();
            let subkey = session_subkey_2022(method, psk, &sid);
            let body = open_nonce(method, &subkey, &nonce, &client_packet[16..]).unwrap();
            (sid, body)
        };
        // Запрос: type(0) ts(8) pad_len(2) address payload → достаём address+payload.
        assert_eq!(body[0], TYPE_CLIENT);
        let pad = u16::from_be_bytes(body[9..11].try_into().unwrap()) as usize;
        let (target, payload) = parse_address(&body[11 + pad..]).unwrap();

        // Ответ: type(1) ts(8) client_sid(8) pad_len(2)=0 address payload.
        let mut resp_body = Vec::new();
        resp_body.push(TYPE_SERVER);
        resp_body.extend_from_slice(&now_ts().to_be_bytes());
        resp_body.extend_from_slice(&client_sid);
        resp_body.extend_from_slice(&0u16.to_be_bytes());
        resp_body.extend_from_slice(&encode_address(&target));
        resp_body.extend_from_slice(payload);

        let server_sid: [u8; 8] = [9, 9, 9, 9, 9, 9, 9, 9];
        if method.is_chacha2022() {
            let mut pt = Vec::new();
            pt.extend_from_slice(&server_sid);
            pt.extend_from_slice(&server_pid.to_be_bytes());
            pt.extend_from_slice(&resp_body);
            let nonce = random_bytes::<24>().unwrap();
            let ct = xchacha_seal(psk, &nonce, &pt).unwrap();
            let mut out = nonce.to_vec();
            out.extend_from_slice(&ct);
            out
        } else {
            let mut header = [0u8; 16];
            header[..8].copy_from_slice(&server_sid);
            header[8..].copy_from_slice(&server_pid.to_be_bytes());
            let nonce: [u8; 12] = header[4..16].try_into().unwrap();
            let subkey = session_subkey_2022(method, psk, &server_sid);
            let sealed = seal_nonce(method, &subkey, &nonce, &resp_body).unwrap();
            aes_ecb_encrypt_block(psk, &mut header).unwrap();
            let mut out = header.to_vec();
            out.extend_from_slice(&sealed);
            out
        }
    }

    #[test]
    fn roundtrip_all_2022_methods() {
        for method in [
            Method::Ss2022Aes128Gcm,
            Method::Ss2022Aes256Gcm,
            Method::Ss2022Chacha20Poly1305,
        ] {
            let psk = evp_bytes_to_key(b"pass", method.key_len()); // любой PSK нужной длины
            let session = Ss2022UdpSession::new(method, psk.clone()).unwrap();
            let targets = [
                Target::Socket("1.2.3.4:53".parse().unwrap()),
                Target::Domain("example.com".into(), 443),
            ];
            for (i, target) in targets.iter().enumerate() {
                let pkt = session.encrypt(target, b"ss2022-udp-payload").unwrap();
                let resp = server_echo(method, &psk, &pkt, i as u64);
                let got = session.decrypt(&resp).unwrap();
                assert_eq!(got, b"ss2022-udp-payload", "{method:?}");
            }
        }
    }

    #[test]
    fn packet_id_increments() {
        let method = Method::Ss2022Aes256Gcm;
        let psk = evp_bytes_to_key(b"x", method.key_len());
        let s = Ss2022UdpSession::new(method, psk.clone()).unwrap();
        let p0 = s
            .encrypt(&Target::Socket("1.1.1.1:1".parse().unwrap()), b"a")
            .unwrap();
        let p1 = s
            .encrypt(&Target::Socket("1.1.1.1:1".parse().unwrap()), b"a")
            .unwrap();
        // separate header (зашифрован) различается из-за packet_id.
        assert_ne!(p0[..16], p1[..16]);
    }

    #[test]
    fn rejects_wrong_client_session() {
        let method = Method::Ss2022Aes128Gcm;
        let psk = evp_bytes_to_key(b"x", method.key_len());
        let s1 = Ss2022UdpSession::new(method, psk.clone()).unwrap();
        let s2 = Ss2022UdpSession::new(method, psk.clone()).unwrap();
        let pkt = s1
            .encrypt(&Target::Socket("1.1.1.1:1".parse().unwrap()), b"a")
            .unwrap();
        let resp = server_echo(method, &psk, &pkt, 0);
        // s2 имеет другой session_id → ответ для s1 не примет.
        assert!(s2.decrypt(&resp).is_err());
    }

    #[test]
    fn rejects_replayed_response() {
        let method = Method::Ss2022Aes256Gcm;
        let psk = evp_bytes_to_key(b"x", method.key_len());
        let s = Ss2022UdpSession::new(method, psk.clone()).unwrap();
        let pkt = s
            .encrypt(&Target::Socket("1.1.1.1:1".parse().unwrap()), b"a")
            .unwrap();
        let resp = server_echo(method, &psk, &pkt, 5);
        assert!(s.decrypt(&resp).is_ok(), "первый — принят");
        assert!(
            s.decrypt(&resp).is_err(),
            "повтор (тот же server_pid) — отвергнут"
        );
    }
}
