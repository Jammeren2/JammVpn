//! AmneziaWG-обфускация поверх UDP.
//!
//! Оборачивает/разворачивает стандартные WG-пакеты (которые отдаёт/принимает
//! boringtun) на UDP-слое: junk-пакеты (Jc/Jmin/Jmax), случайные префиксы
//! (S1/S2) и подмена 4-байтного типа сообщения на магический заголовок (H1..H4).
//!
//! Преобразование симметрично и self-consistent: `unwrap` восстанавливает
//! канонический тип в буфере ДО передачи в boringtun, поэтому MAC1 (вычисленный
//! boringtun над каноническим типом) сходится. При дефолтных параметрах
//! (H=1..4, S/Jc=0) wrap/unwrap — тождественны (байт-в-байт чистый WireGuard).
//!
//! Ограничение v0: корректность нестандартных H1/H2 (handshake) зависит от того,
//! нормализует ли сервер тип к каноническому ДО проверки MAC1 (как amneziawg-go);
//! требует интероп-проверки против живого сервера. См. план (awg_transform).

use super::config::AwgObfuscation;
use blake2::digest::{consts::U16, KeyInit, Mac};
use blake2::{Blake2s256, Blake2sMac, Digest};
use rand::Rng;

const LABEL_MAC1: &[u8] = b"mac1----";

/// Ключ MAC1 = Blake2s-256(`mac1----` || статический публичный ключ получателя).
fn mac1_key(receiver_pub: &[u8; 32]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    Digest::update(&mut h, LABEL_MAC1);
    Digest::update(&mut h, receiver_pub);
    let mut k = [0u8; 32];
    k.copy_from_slice(&Digest::finalize(h));
    k
}

/// Пересчитывает MAC1 в handshake-пакете (INIT 148 / RESP 92) под ключ
/// получателя: keyed-Blake2s (16 байт) над `msg[..len-32]`. Нужно после подмены
/// типа на H-заголовок — иначе MAC1 (его считал boringtun над каноническим
/// типом) не сойдётся на стороне-получателе.
fn fix_mac1(msg: &mut [u8], receiver_pub: &[u8; 32]) {
    let len = msg.len();
    if len != LEN_INIT && len != LEN_RESP {
        return;
    }
    let off = len - 32; // [..off] | mac1(16) | mac2(16)
    let key = mac1_key(receiver_pub);
    let mut mac = <Blake2sMac<U16> as KeyInit>::new_from_slice(&key).expect("blake2s key len");
    Mac::update(&mut mac, &msg[..off]);
    let tag = Mac::finalize(mac).into_bytes();
    msg[off..off + 16].copy_from_slice(&tag);
}

// Канонические типы WG-сообщений.
const T_INIT: u32 = 1;
const T_RESP: u32 = 2;
const T_COOKIE: u32 = 3;
const T_DATA: u32 = 4;

// Фиксированные размеры handshake-сообщений WG (тип+поля+mac1+mac2).
const LEN_INIT: usize = 148;
const LEN_RESP: usize = 92;
const LEN_COOKIE: usize = 64;
// Заголовок transport-пакета: 4 (type) + 4 (receiver) + 8 (counter).
const DATA_HEADER: usize = 16;
// Минимальный transport-пакет: заголовок + пустой AEAD-тег (keepalive).
const DATA_MIN: usize = DATA_HEADER + 16;

/// Обфускатор AmneziaWG. `identity` (params=None) ⇒ чистый WireGuard.
pub struct AwgObfs {
    params: Option<AwgObfuscation>,
    /// Наш статический публичный ключ (получатель входящих от сервера).
    our_public: [u8; 32],
    /// Публичный ключ пира/сервера (получатель наших исходящих).
    peer_public: [u8; 32],
}

impl AwgObfs {
    /// Строит обфускатор; дефолтные AWG-параметры сворачиваются в identity.
    /// `our_public`/`peer_public` нужны для пересчёта MAC1 под H-заголовок.
    pub fn new(params: Option<AwgObfuscation>, our_public: [u8; 32], peer_public: [u8; 32]) -> Self {
        let params = params.filter(|a| !a.is_identity());
        Self {
            params,
            our_public,
            peer_public,
        }
    }

    fn h_for(a: &AwgObfuscation, t: u32) -> u32 {
        match t {
            T_INIT => a.h1,
            T_RESP => a.h2,
            T_COOKIE => a.h3,
            T_DATA => a.h4,
            _ => t,
        }
    }

    fn s_for(a: &AwgObfuscation, t: u32) -> usize {
        match t {
            T_INIT => a.s1 as usize,
            T_RESP => a.s2 as usize,
            // S3/S4 в конфиге AmneziaWG (этой версии) нет.
            _ => 0,
        }
    }

    /// Оборачивает исходящий WG-пакет в одну или несколько UDP-датаграмм
    /// (для init с Jc>0 — сначала junk-пакеты, затем сам пакет с S-префиксом).
    pub fn wrap(&self, packet: &[u8]) -> Vec<Vec<u8>> {
        let Some(a) = &self.params else {
            return vec![packet.to_vec()];
        };
        if packet.len() < 4 {
            return vec![packet.to_vec()];
        }
        let t = u32::from_le_bytes([packet[0], packet[1], packet[2], packet[3]]);
        let mut out = Vec::new();

        // Junk-пакеты только перед handshake-инициацией.
        if t == T_INIT && a.jc > 0 {
            let mut rng = rand::rng();
            let lo = a.jmin as usize;
            let hi = (a.jmax as usize).max(lo);
            for _ in 0..a.jc {
                let n = if hi > lo {
                    rng.random_range(lo..=hi)
                } else {
                    lo
                };
                let mut junk = vec![0u8; n];
                rng.fill(&mut junk[..]);
                out.push(junk);
            }
        }

        // S-префикс (случайные байты) + перезапись типа на H[T].
        let s = Self::s_for(a, t);
        let h = Self::h_for(a, t);
        let mut dg = vec![0u8; s + packet.len()];
        if s > 0 {
            rand::rng().fill(&mut dg[..s]);
        }
        dg[s..].copy_from_slice(packet);
        dg[s..s + 4].copy_from_slice(&h.to_le_bytes());
        // Исходящий handshake к серверу: MAC1 пересчитываем под H-заголовок,
        // получатель — пир (его публичный ключ).
        if t == T_INIT || t == T_RESP {
            fix_mac1(&mut dg[s..], &self.peer_public);
        }
        out.push(dg);
        out
    }

    /// Разворачивает входящую UDP-датаграмму обратно в канонический WG-пакет.
    /// `None` — junk/нераспознанное (молча отбрасывается, как в AmneziaWG).
    pub fn unwrap(&self, dg: &[u8]) -> Option<Vec<u8>> {
        let Some(a) = &self.params else {
            return Some(dg.to_vec());
        };
        let l = dg.len();
        for (t, fixed, is_transport) in [
            (T_INIT, LEN_INIT, false),
            (T_RESP, LEN_RESP, false),
            (T_COOKIE, LEN_COOKIE, false),
            (T_DATA, DATA_MIN, true),
        ] {
            let pad = Self::s_for(a, t);
            if pad + 4 > l {
                continue;
            }
            let size_ok = if is_transport {
                l >= pad + fixed
            } else {
                l == pad + fixed
            };
            if !size_ok {
                continue;
            }
            let on_wire = u32::from_le_bytes([dg[pad], dg[pad + 1], dg[pad + 2], dg[pad + 3]]);
            if on_wire != Self::h_for(a, t) {
                continue;
            }
            // Совпало: снять S-префикс и восстановить канонический тип.
            let mut pkt = dg[pad..].to_vec();
            pkt[0..4].copy_from_slice(&t.to_le_bytes());
            // Входящий handshake от сервера: MAC1 пересчитываем под канонический
            // тип, получатель — мы (наш публичный ключ), чтобы прошла проверка
            // boringtun.
            if t == T_INIT || t == T_RESP {
                fix_mac1(&mut pkt, &self.our_public);
            }
            return Some(pkt);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn awg() -> AwgObfuscation {
        AwgObfuscation {
            jc: 3,
            jmin: 10,
            jmax: 20,
            s1: 8,
            s2: 12,
            h1: 0x1111_1111,
            h2: 0x2222_2222,
            h3: 0x3333_3333,
            h4: 0x4444_4444,
        }
    }

    fn fake(ty: u32, len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        v[0..4].copy_from_slice(&ty.to_le_bytes());
        for (i, b) in v.iter_mut().enumerate().skip(4) {
            *b = (i % 251) as u8; // детерминированная «нагрузка»
        }
        v
    }

    #[test]
    fn identity_when_default() {
        let o = AwgObfs::new(None, [0u8; 32], [0u8; 32]);
        let pkt = fake(T_DATA, 64);
        // Тождественность: wrap не меняет пакет, unwrap возвращает его же.
        assert_eq!(o.wrap(&pkt), vec![pkt.clone()]);
        assert_eq!(o.unwrap(&pkt), Some(pkt));
    }

    #[test]
    fn default_awg_params_collapse_to_identity() {
        let id = AwgObfuscation {
            jc: 0,
            jmin: 0,
            jmax: 0,
            s1: 0,
            s2: 0,
            h1: 1,
            h2: 2,
            h3: 3,
            h4: 4,
        };
        let o = AwgObfs::new(Some(id), [0u8; 32], [0u8; 32]);
        // Дефолтные AWG-параметры ⇒ тождественное преобразование.
        let pkt = fake(T_INIT, LEN_INIT);
        assert_eq!(o.wrap(&pkt), vec![pkt.clone()]);
        assert_eq!(o.unwrap(&pkt), Some(pkt));
    }

    #[test]
    fn wrap_unwrap_roundtrip_all_types() {
        let o = AwgObfs::new(Some(awg()), [7u8; 32], [9u8; 32]);
        for (ty, len) in [
            (T_INIT, LEN_INIT),
            (T_RESP, LEN_RESP),
            (T_COOKIE, LEN_COOKIE),
            (T_DATA, 80),
        ] {
            let pkt = fake(ty, len);
            let dgs = o.wrap(&pkt);
            // последняя датаграмма — это сам (обёрнутый) пакет.
            let wrapped = dgs.last().unwrap();
            // тип на проводе — магический H[ty] по смещению S[ty].
            let s = AwgObfs::s_for(&awg(), ty);
            let on_wire =
                u32::from_le_bytes([wrapped[s], wrapped[s + 1], wrapped[s + 2], wrapped[s + 3]]);
            assert_eq!(on_wire, AwgObfs::h_for(&awg(), ty), "H-заголовок на проводе");
            let back = o.unwrap(wrapped).expect("unwrap");
            // Тип восстановлен.
            assert_eq!(&back[0..4], &ty.to_le_bytes(), "type restored {ty}");
            // Тело совпадает; для INIT/RESP хвост mac1/mac2 пересчитан, поэтому
            // сравниваем без последних 32 байт.
            let body = if ty == T_INIT || ty == T_RESP { len - 32 } else { len };
            assert_eq!(&back[..body], &pkt[..body], "body type={ty}");
        }
    }

    #[test]
    fn init_emits_jc_junk_packets() {
        let o = AwgObfs::new(Some(awg()), [7u8; 32], [9u8; 32]);
        let dgs = o.wrap(&fake(T_INIT, LEN_INIT));
        // Jc junk + 1 реальный.
        assert_eq!(dgs.len(), 3 + 1);
        for junk in &dgs[..3] {
            assert!((10..=20).contains(&junk.len()), "junk size в [jmin,jmax]");
            assert!(o.unwrap(junk).is_none(), "junk не распознаётся");
        }
    }

    #[test]
    fn random_junk_is_dropped() {
        let o = AwgObfs::new(Some(awg()), [7u8; 32], [9u8; 32]);
        // Случайный мусор, не совпадающий ни с одним (size, header).
        assert!(o.unwrap(&[0xAB; 37]).is_none());
    }
}
