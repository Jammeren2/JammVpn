//! Async-обёртка REALITY-транспорта поверх синхронного (rustls-подобного)
//! коннектора из портированного модуля [`crate::reality`].
//!
//! Хендшейк выполняется заранее в [`reality_connect`]; затем [`RealityStream`]
//! прозрачно шифрует/расшифровывает прикладные данные поверх нижележащего
//! асинхронного потока (TCP), реализуя `AsyncRead`/`AsyncWrite`.

use crate::reality::{
    decode_public_key, decode_short_id, feed_reality_client_connection, RealityClientConfig,
    RealityClientConnection,
};
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Параметры REALITY-транспорта (из share-ссылки).
#[derive(Debug, Clone)]
pub struct RealityTransport {
    /// Публичный ключ сервера `pbk` (base64url X25519).
    pub public_key: String,
    /// Короткий идентификатор `sid` (hex).
    pub short_id: String,
    /// Имя сервера `sni`/serverName.
    pub server_name: String,
}

/// Выполняет REALITY/TLS 1.3 хендшейк поверх `inner` и возвращает **сырой**
/// нижележащий поток вместе с установленным коннектором.
///
/// Используется там, где нужен раздельный доступ к TCP и TLS-сессии — в первую
/// очередь для XTLS-Vision (его «direct splice» пишет в сырой TCP мимо TLS).
/// Для обычного app-data поверх REALITY используйте [`reality_connect`].
///
/// Инвариант на выходе: хендшейк полностью завершён и **все** исходящие
/// TLS-записи (включая клиентский Finished) уже отправлены в `inner` — цикл
/// сбрасывает `wants_write` перед проверкой `is_handshaking`.
pub async fn reality_handshake<S>(
    mut inner: S,
    t: &RealityTransport,
) -> io::Result<(S, RealityClientConnection)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let cfg = RealityClientConfig {
        public_key: decode_public_key(&t.public_key)?,
        short_id: decode_short_id(&t.short_id)?,
        server_name: t.server_name.clone(),
        cipher_suites: vec![],
    };
    let mut conn = RealityClientConnection::new(cfg)?;

    let mut net = [0u8; 16384];
    loop {
        while conn.wants_write() {
            let mut out = Vec::new();
            conn.write_tls(&mut out)?;
            if out.is_empty() {
                break;
            }
            inner.write_all(&out).await?;
        }
        if !conn.is_handshaking() {
            break;
        }
        let n = inner.read(&mut net).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "REALITY: соединение закрыто во время хендшейка",
            ));
        }
        feed_reality_client_connection(&mut conn, &net[..n])?;
        conn.process_new_packets()?;
    }

    Ok((inner, conn))
}

/// Выполняет REALITY/TLS 1.3 хендшейк поверх `inner`, возвращает поток app-data.
pub async fn reality_connect<S>(inner: S, t: &RealityTransport) -> io::Result<RealityStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (inner, conn) = reality_handshake(inner, t).await?;
    Ok(RealityStream {
        inner,
        conn,
        wbuf: Vec::new(),
        wpos: 0,
    })
}

/// Поток REALITY: прикладные данные поверх установленного TLS 1.3.
pub struct RealityStream<S> {
    inner: S,
    conn: RealityClientConnection,
    wbuf: Vec<u8>,
    wpos: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin> RealityStream<S> {
    /// Разбирает поток на сырой транспорт и установленный TLS-коннектор —
    /// для XTLS-Vision, которому нужен раздельный доступ к TCP и сессии.
    ///
    /// Вызывать только после [`AsyncWriteExt::flush`]: иначе несброшенные
    /// исходящие TLS-записи в `wbuf` будут потеряны.
    pub fn into_inner(self) -> (S, RealityClientConnection) {
        debug_assert!(
            self.wpos >= self.wbuf.len(),
            "RealityStream::into_inner с несброшенным wbuf"
        );
        (self.inner, self.conn)
    }

    fn flush_wbuf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.wpos < self.wbuf.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.wbuf[self.wpos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)))
                }
                Poll::Ready(Ok(k)) => self.wpos += k,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.wbuf.clear();
        self.wpos = 0;
        Poll::Ready(Ok(()))
    }

    /// Сериализует ожидающие исходящие TLS-записи в `wbuf`.
    fn drain_tls(&mut self) -> io::Result<()> {
        while self.conn.wants_write() {
            match self.conn.write_tls(&mut self.wbuf) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for RealityStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            let want = out.remaining();
            if want == 0 {
                return Poll::Ready(Ok(()));
            }
            // 1. Попробовать достать расшифрованные данные из коннектора.
            let mut tmp = vec![0u8; want];
            match me.conn.reader().read(&mut tmp) {
                Ok(n) if n > 0 => {
                    out.put_slice(&tmp[..n]);
                    return Poll::Ready(Ok(()));
                }
                // Ok(0) = расшифрованных данных пока нет (НЕ EOF) → дочитать TLS.
                // Реальный EOF — закрытие нижележащего сокета (см. ниже).
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
            // 2. Дочитать TLS из нижележащего потока.
            let mut net = [0u8; 16384];
            let mut rb = ReadBuf::new(&mut net);
            match Pin::new(&mut me.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Ok(())); // EOF сокета
                    }
                    if let Err(e) = feed_reality_client_connection(&mut me.conn, filled) {
                        return Poll::Ready(Err(e));
                    }
                    if let Err(e) = me.conn.process_new_packets() {
                        return Poll::Ready(Err(e));
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RealityStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        match ready!(me.flush_wbuf(cx)) {
            Ok(()) => {}
            Err(e) => return Poll::Ready(Err(e)),
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = match me.conn.writer().write(buf) {
            Ok(n) => n,
            Err(e) => return Poll::Ready(Err(e)),
        };
        if let Err(e) = me.drain_tls() {
            return Poll::Ready(Err(e));
        }
        if let Poll::Ready(Err(e)) = me.flush_wbuf(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match ready!(me.flush_wbuf(cx)) {
            Ok(()) => {}
            Err(e) => return Poll::Ready(Err(e)),
        }
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        me.conn.send_close_notify();
        if let Err(e) = me.drain_tls() {
            return Poll::Ready(Err(e));
        }
        match ready!(me.flush_wbuf(cx)) {
            Ok(()) => {}
            Err(e) => return Poll::Ready(Err(e)),
        }
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}
