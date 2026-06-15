//! Поток поверх bidi QUIC-стрима TUIC: связывает `quinn::SendStream` и
//! `quinn::RecvStream` (которые уже реализуют tokio `AsyncWrite`/`AsyncRead`) в
//! единый `AsyncRead`+`AsyncWrite` для [`crate::BoxedStream`].

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// TCP-поток внутри TUIC-туннеля (один QUIC bidi-стрим).
pub struct TuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl TuicStream {
    pub(crate) fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for TuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Полная квалификация: у quinn::RecvStream есть inherent poll_read,
        // перекрывающий tokio-трейт через Deref.
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for TuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // tokio AsyncWrite у quinn::SendStream завершает стрим (finish + FIN).
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}
