//! Реестр активных соединений (для монитора в UI).
//!
//! Процессо-глобальный (один локальный прокси на процесс). Каждое
//! проксируемое соединение регистрируется на время жизни ([`ConnGuard`]:
//! удаляется из реестра при `Drop`), а счётчики байт обновляются обёрткой
//! [`ReadCounting`] в ходе relay. [`snapshot`] отдаёт срез для команды UI.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

struct Entry {
    target: String,
    via: &'static str,
    /// Локальный источник (адрес инициатора) — для атрибуции к процессу в UI.
    src: Option<SocketAddr>,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
    /// Сигнал принудительного закрытия соединения из UI.
    kill: Arc<Notify>,
}

fn registry() -> &'static Mutex<HashMap<u64, Entry>> {
    static R: OnceLock<Mutex<HashMap<u64, Entry>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Срез активного соединения (для UI).
#[derive(Debug, Clone)]
pub struct ConnInfo {
    /// Идентификатор (для принудительного закрытия из UI).
    pub id: u64,
    /// Цель (`host:port` / `ip:port`).
    pub target: String,
    /// Маршрут: `proxy` | `direct`.
    pub via: &'static str,
    /// Локальный источник соединения (для атрибуции к процессу на стороне UI).
    pub src: Option<SocketAddr>,
    /// Передано (байт, egress).
    pub up: u64,
    /// Принято (байт, ingress).
    pub down: u64,
}

/// Учётная запись соединения: удаляется из реестра при `Drop`.
pub struct ConnGuard {
    id: u64,
    /// Счётчик отданных байт (читается из клиента).
    pub up: Arc<AtomicU64>,
    /// Счётчик принятых байт (читается из исходящего).
    pub down: Arc<AtomicU64>,
    /// Сигнал принудительного закрытия (см. [`copy_counted`]).
    kill: Arc<Notify>,
}

/// Регистрирует соединение; держите guard на время relay. `src` — локальный
/// адрес инициатора (для атрибуции к процессу в UI), `None` если неизвестен.
pub fn register(target: String, via: &'static str, src: Option<SocketAddr>) -> ConnGuard {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let up = Arc::new(AtomicU64::new(0));
    let down = Arc::new(AtomicU64::new(0));
    let kill = Arc::new(Notify::new());
    registry().lock().unwrap().insert(
        id,
        Entry {
            target,
            via,
            src,
            up: Arc::clone(&up),
            down: Arc::clone(&down),
            kill: Arc::clone(&kill),
        },
    );
    ConnGuard {
        id,
        up,
        down,
        kill,
    }
}

/// Принудительно закрывает соединение по `id` (UI «дропнуть»). `false` — нет
/// такого активного соединения.
pub fn drop_connection(id: u64) -> bool {
    match registry().lock().unwrap().get(&id) {
        Some(e) => {
            e.kill.notify_waiters();
            true
        }
        None => false,
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        registry().lock().unwrap().remove(&self.id);
    }
}

/// Срез всех активных соединений.
pub fn snapshot() -> Vec<ConnInfo> {
    registry()
        .lock()
        .unwrap()
        .iter()
        .map(|(id, e)| ConnInfo {
            id: *id,
            target: e.target.clone(),
            via: e.via,
            src: e.src,
            up: e.up.load(Ordering::Relaxed),
            down: e.down.load(Ordering::Relaxed),
        })
        .collect()
}

/// Обёртка над потоком, считающая прочитанные байты в счётчик (запись — насквозь).
pub struct ReadCounting<S> {
    inner: S,
    counter: Arc<AtomicU64>,
}

impl<S> ReadCounting<S> {
    pub fn new(inner: S, counter: Arc<AtomicU64>) -> Self {
        Self { inner, counter }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ReadCounting<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            let n = buf.filled().len() - before;
            if n > 0 {
                self.counter.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ReadCounting<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Двунаправленный relay с учётом байт в счётчики guard: `up` = прочитано из
/// клиента (egress), `down` = прочитано из исходящего (ingress).
pub async fn copy_counted<A, B>(client: A, upstream: B, guard: &ConnGuard) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut c = ReadCounting::new(client, Arc::clone(&guard.up));
    let mut u = ReadCounting::new(upstream, Arc::clone(&guard.down));
    // Гонка с сигналом принудительного закрытия из UI: при `kill` бросаем relay
    // (потоки закрываются при Drop).
    tokio::select! {
        r = tokio::io::copy_bidirectional(&mut c, &mut u) => { r?; }
        _ = guard.kill.notified() => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_snapshot_drop() {
        let snap0 = snapshot().len();
        {
            let g = register("example.com:443".into(), "proxy", None);
            g.up.fetch_add(100, Ordering::Relaxed);
            g.down.fetch_add(250, Ordering::Relaxed);
            let snap = snapshot();
            let mine = snap.iter().find(|c| c.target == "example.com:443").unwrap();
            assert_eq!(mine.via, "proxy");
            assert_eq!(mine.up, 100);
            assert_eq!(mine.down, 250);
        }
        // guard уронен → запись удалена.
        assert_eq!(snapshot().len(), snap0);
    }
}
