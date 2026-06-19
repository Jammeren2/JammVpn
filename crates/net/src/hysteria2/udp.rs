//! Hysteria2 UDP relay: проброс датаграмм поверх общего QUIC-соединения.
//!
//! Все UDP-потоки узла мультиплексируются по ОДНОМУ QUIC-соединению через
//! QUIC-датаграммы. Каждый поток получает уникальный 32-битный `session`;
//! фоновая задача-демультиплексор читает входящие датаграммы, реассемблирует
//! фрагменты и раздаёт payload потоку по `session`. Цель-домен уходит серверу
//! как есть (remote DNS). Сессии рвутся по idle-таймауту на сервере (нет
//! явной команды dissociate, в отличие от TUIC).

use super::proto::{self, UdpHead};
use crate::target::Target;
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};

/// Глубина очереди ответов одного потока.
const FLOW_QUEUE: usize = 64;
/// Предел числа незавершённых реассемблируемых пакетов (анти-DoS).
const MAX_REASM: usize = 256;
/// Время жизни незавершённой сборки (потеря фрагментов в UDP — норма).
const REASM_TTL: Duration = Duration::from_secs(10);

/// Менеджер Hysteria2 UDP: общий на QUIC-соединение, демультиплексирует по
/// `session`. `pub` лишь чтобы фигурировать в публичном [`crate::Outbound`]-API.
pub struct Hysteria2Udp {
    conn: quinn::Connection,
    next_session: AtomicU32,
    next_pkt: AtomicU16,
    flows: Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>,
}

impl Hysteria2Udp {
    /// Запускает менеджер поверх соединения и фоновую задачу-демультиплексор.
    pub(crate) fn start(conn: quinn::Connection) -> Arc<Self> {
        let me = Arc::new(Self {
            conn,
            next_session: AtomicU32::new(1),
            next_pkt: AtomicU16::new(1),
            flows: Mutex::new(HashMap::new()),
        });
        let demux = Arc::clone(&me);
        tokio::spawn(async move { demux.recv_loop().await });
        me
    }

    /// Регистрирует новый поток: выдаёт свободный `session` (≠0) и приёмник
    /// ответов. `None`, если не удалось подобрать свободный id.
    pub(crate) async fn register(&self) -> Option<(u32, mpsc::Receiver<Vec<u8>>)> {
        let (tx, rx) = mpsc::channel(FLOW_QUEUE);
        let mut flows = self.flows.lock().await;
        for _ in 0..1024 {
            let id = self.next_session.fetch_add(1, Ordering::Relaxed);
            if id != 0 && !flows.contains_key(&id) {
                flows.insert(id, tx);
                return Some((id, rx));
            }
        }
        None
    }

    /// Отправляет UDP-пакет к `target` от имени потока `session`.
    pub(crate) async fn send(
        &self,
        session: u32,
        target: &Target,
        payload: &[u8],
    ) -> io::Result<()> {
        let max = self.conn.max_datagram_size().ok_or_else(|| {
            io::Error::other("hysteria2: сервер не поддерживает QUIC-датаграммы (UDP недоступен)")
        })?;
        let pkt_id = self.next_pkt.fetch_add(1, Ordering::Relaxed);
        for dg in proto::encode_udp_packets(session, pkt_id, target, payload, max)? {
            self.conn
                .send_datagram(bytes::Bytes::from(dg))
                .map_err(|e| io::Error::other(e.to_string()))?;
        }
        Ok(())
    }

    /// Снимает регистрацию потока (сервер закроет сессию по idle-таймауту).
    pub(crate) async fn close(&self, session: u32) {
        self.flows.lock().await.remove(&session);
    }

    /// Фоновый цикл: читает датаграммы, реассемблирует, раздаёт потокам.
    async fn recv_loop(self: Arc<Self>) {
        let mut reasm: HashMap<(u32, u16), Reasm> = HashMap::new();
        loop {
            let dg = match self.conn.read_datagram().await {
                Ok(d) => d,
                Err(_) => break, // соединение закрылось
            };
            let (head, frag) = match proto::decode_udp_packet(&dg) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let full = if head.frag_total <= 1 {
                Some(frag.to_vec())
            } else {
                reassemble(&mut reasm, &head, frag)
            };
            if let Some(payload) = full {
                let tx = self.flows.lock().await.get(&head.session).cloned();
                if let Some(tx) = tx {
                    if tx.send(payload).await.is_err() {
                        self.flows.lock().await.remove(&head.session);
                    }
                }
            }
        }
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
fn reassemble(
    map: &mut HashMap<(u32, u16), Reasm>,
    head: &UdpHead,
    frag: &[u8],
) -> Option<Vec<u8>> {
    let key = (head.session, head.pkt_id);
    map.retain(|_, e| e.created.elapsed() < REASM_TTL);
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
