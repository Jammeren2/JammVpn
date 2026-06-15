//! TUIC v5 UDP relay: проброс датаграмм поверх общего QUIC-соединения.
//!
//! Все UDP-потоки узла мультиплексируются по ОДНОМУ QUIC-соединению через
//! QUIC-датаграммы (команда Packet). Каждый поток получает уникальный `assoc_id`;
//! фоновая задача-демультиплексор читает входящие датаграммы, реассемблирует
//! фрагменты и раздаёт payload потоку по `assoc_id`. Цель-домен уходит серверу
//! как есть (remote DNS). Режим uni-stream (для серверов без датаграмм) не
//! реализован.

use super::proto::{self, PacketHead};
use crate::target::Target;
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};

/// Глубина очереди ответов одного потока.
const FLOW_QUEUE: usize = 64;
/// Предел числа незавершённых реассемблируемых пакетов (анти-DoS).
const MAX_REASM: usize = 256;
/// Время жизни незавершённой сборки: потерянные фрагменты (норма для UDP) не копятся.
const REASM_TTL: Duration = Duration::from_secs(10);

/// Менеджер TUIC UDP: общий на QUIC-соединение, демультиплексирует по `assoc_id`.
/// `pub` лишь чтобы фигурировать в публичном [`crate::Outbound`]-API; методы —
/// крейт-приватные.
pub struct TuicUdp {
    conn: quinn::Connection,
    next_assoc: AtomicU16,
    next_pkt: AtomicU16,
    flows: Mutex<HashMap<u16, mpsc::Sender<Vec<u8>>>>,
}

impl TuicUdp {
    /// Запускает менеджер поверх соединения и фоновую задачу-демультиплексор.
    pub(crate) fn start(conn: quinn::Connection) -> Arc<Self> {
        let me = Arc::new(Self {
            conn,
            next_assoc: AtomicU16::new(1),
            next_pkt: AtomicU16::new(1),
            flows: Mutex::new(HashMap::new()),
        });
        let demux = Arc::clone(&me);
        tokio::spawn(async move { demux.recv_loop().await });
        me
    }

    /// Регистрирует новый поток: выдаёт СВОБОДНЫЙ `assoc_id` (≠0, не занятый) и
    /// приёмник ответов. `None`, если все 65535 id заняты (никогда не
    /// перезаписываем живой id — иначе ответы ушли бы чужому потоку).
    pub(crate) async fn register(&self) -> Option<(u16, mpsc::Receiver<Vec<u8>>)> {
        let (tx, rx) = mpsc::channel(FLOW_QUEUE);
        let mut flows = self.flows.lock().await;
        for _ in 0..=u16::MAX {
            let id = self.next_assoc.fetch_add(1, Ordering::Relaxed);
            if id != 0 && !flows.contains_key(&id) {
                flows.insert(id, tx);
                return Some((id, rx));
            }
        }
        None
    }

    /// Отправляет UDP-пакет к `target` от имени потока `assoc_id`.
    pub(crate) async fn send(
        &self,
        assoc_id: u16,
        target: &Target,
        payload: &[u8],
    ) -> io::Result<()> {
        let max = self
            .conn
            .max_datagram_size()
            .ok_or_else(|| io::Error::other("tuic: сервер не поддерживает QUIC-датаграммы"))?;
        let pkt_id = self.next_pkt.fetch_add(1, Ordering::Relaxed);
        for dg in proto::encode_packets(assoc_id, pkt_id, target, payload, max)? {
            self.conn
                .send_datagram(bytes::Bytes::from(dg))
                .map_err(|e| io::Error::other(e.to_string()))?;
        }
        Ok(())
    }

    /// Закрывает поток: снимает регистрацию и шлёт серверу Dissociate.
    pub(crate) async fn dissociate(&self, assoc_id: u16) {
        self.flows.lock().await.remove(&assoc_id);
        let _ = self
            .conn
            .send_datagram(bytes::Bytes::from(proto::encode_dissociate(assoc_id)));
    }

    /// Фоновый цикл: читает датаграммы, реассемблирует, раздаёт потокам.
    async fn recv_loop(self: Arc<Self>) {
        let mut reasm: HashMap<(u16, u16), Reasm> = HashMap::new();
        loop {
            let dg = match self.conn.read_datagram().await {
                Ok(d) => d,
                Err(_) => break, // соединение закрылось
            };
            let (head, frag) = match proto::decode_packet(&dg) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let full = if head.frag_total <= 1 {
                Some(frag.to_vec())
            } else {
                reassemble(&mut reasm, &head, frag)
            };
            if let Some(payload) = full {
                let tx = self.flows.lock().await.get(&head.assoc_id).cloned();
                if let Some(tx) = tx {
                    if tx.send(payload).await.is_err() {
                        self.flows.lock().await.remove(&head.assoc_id);
                    }
                }
            }
        }
        // Связь закрылась: дропаем все Sender'ы → recv() потоков получит None и
        // штатно завершится (иначе висели бы вечно на живом Sender).
        self.flows.lock().await.clear();
    }
}

/// Буфер реассемблинга одного фрагментированного пакета.
struct Reasm {
    frags: Vec<Option<Vec<u8>>>,
    have: usize,
    created: Instant,
}

/// Собирает фрагменты; при полноте возвращает склеенный payload.
///
/// `frag_total`/`frag_id` уже провалидированы в [`proto::decode_packet`]
/// (`frag_total ≥ 1`, `frag_id < frag_total`).
fn reassemble(
    map: &mut HashMap<(u16, u16), Reasm>,
    head: &PacketHead,
    frag: &[u8],
) -> Option<Vec<u8>> {
    let key = (head.assoc_id, head.pkt_id);
    // Выбрасываем протухшие частичные сборки (потеря фрагментов в UDP — норма),
    // чтобы они не копились и не триггерили массовый сброс.
    map.retain(|_, e| e.created.elapsed() < REASM_TTL);
    // Если всё ещё переполнено (флуд свежими) — эвиктим ОДНУ старейшую запись,
    // а не всю карту (иначе сброс губил бы честные потоки).
    if map.len() >= MAX_REASM && !map.contains_key(&key) {
        if let Some(oldest) = map.iter().min_by_key(|(_, e)| e.created).map(|(k, _)| *k) {
            map.remove(&oldest);
        }
    }
    let entry = map.entry(key).or_insert_with(|| Reasm {
        frags: vec![None; head.frag_total as usize],
        have: 0,
        created: Instant::now(),
    });
    if entry.frags.len() != head.frag_total as usize {
        return None; // несогласованный frag_total для того же pkt_id
    }
    let idx = head.frag_id as usize;
    if entry.frags[idx].is_none() {
        entry.frags[idx] = Some(frag.to_vec());
        entry.have += 1;
    }
    if entry.have == head.frag_total as usize {
        let r = map.remove(&key).unwrap();
        let mut out = Vec::new();
        for f in r.frags {
            out.extend_from_slice(&f.unwrap());
        }
        Some(out)
    } else {
        None
    }
}
