//! Sync-адаптеры: мост между async-сокетом (`tokio`) и синхронными
//! `read_tls()`/`write_tls()` нашего TLS/REALITY-конечного автомата.
//!
//! Порт из cfal/shoes `src/sync_adapter.rs` (MIT © 2021-2023 Alex Lau), который,
//! в свою очередь, адаптирован из tokio-rustls. Когда async-сокет вернул бы
//! `Poll::Pending`, адаптер отдаёт `WouldBlock`. См. `ATTRIBUTION.md`.

use std::io::{self, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Мост async-чтения → синхронный `Read` (для `read_tls()`).
pub struct SyncReadAdapter<'a, 'b, T> {
    pub io: &'a mut T,
    pub cx: &'a mut Context<'b>,
}

impl<T: AsyncRead + Unpin> std::io::Read for SyncReadAdapter<'_, '_, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut self.io).poll_read(self.cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Ok(read_buf.filled().len()),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

/// Мост async-записи → синхронный `Write` (для `write_tls()`).
pub struct SyncWriteAdapter<'a, 'b, T> {
    pub io: &'a mut T,
    pub cx: &'a mut Context<'b>,
}

impl<T: AsyncWrite + Unpin> Write for SyncWriteAdapter<'_, '_, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut self.io).poll_write(self.cx, buf) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match Pin::new(&mut self.io).poll_flush(self.cx) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}
