//! Асинхронная обёртка Shadowsocks AEAD над произвольным потоком.
//!
//! Формат потока: `соль(salt_len)` затем чанки
//! `[enc(len, 2)+tag(16)] [enc(payload, len)+tag(16)]`, nonce — счётчик с нуля.

use super::crypto::{session_subkey, Crypto, Method};
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_CHUNK: usize = 0x3FFF;
const TAG: usize = 16;

#[derive(Clone, Copy)]
enum ReadStage {
    Salt,
    Len,
    Data(usize),
}

/// Поток с прозрачным AEAD-шифрованием Shadowsocks.
pub struct ShadowsocksStream<S> {
    inner: S,
    method: Method,
    master: Vec<u8>,
    // запись
    send: Option<Crypto>,
    wbuf: Vec<u8>,
    wpos: usize,
    // чтение
    recv: Option<Crypto>,
    stage: ReadStage,
    rtmp: Vec<u8>,
    plain: Vec<u8>,
    ppos: usize,
}

impl<S> ShadowsocksStream<S> {
    /// Оборачивает поток `inner` с методом и мастер-ключом.
    pub fn new(inner: S, method: Method, master: Vec<u8>) -> Self {
        Self {
            inner,
            method,
            master,
            send: None,
            wbuf: Vec::new(),
            wpos: 0,
            recv: None,
            stage: ReadStage::Salt,
            rtmp: Vec::new(),
            plain: Vec::new(),
            ppos: 0,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> ShadowsocksStream<S> {
    /// Дочитывает `rtmp` до `need` байт. `Ok(false)` — чистый EOF на границе.
    fn fill(&mut self, cx: &mut Context<'_>, need: usize) -> Poll<io::Result<bool>> {
        while self.rtmp.len() < need {
            let mut tmp = [0u8; 4096];
            let want = (need - self.rtmp.len()).min(tmp.len());
            let mut rb = ReadBuf::new(&mut tmp[..want]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Ok(false));
                    }
                    self.rtmp.extend_from_slice(filled);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(true))
    }

    /// Сбрасывает накопленный `wbuf` в нижележащий поток.
    fn flush_wbuf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.wpos < self.wbuf.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.wbuf[self.wpos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)))
                }
                Poll::Ready(Ok(n)) => self.wpos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.wbuf.clear();
        self.wpos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ShadowsocksStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        // Отдаём накопленный расшифрованный буфер.
        if me.ppos < me.plain.len() {
            let n = out.remaining().min(me.plain.len() - me.ppos);
            out.put_slice(&me.plain[me.ppos..me.ppos + n]);
            me.ppos += n;
            if me.ppos == me.plain.len() {
                me.plain.clear();
                me.ppos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        loop {
            match me.stage {
                ReadStage::Salt => {
                    let salt_len = me.method.salt_len();
                    match ready!(me.fill(cx, salt_len)) {
                        Ok(false) => return Poll::Ready(Ok(())), // EOF до данных
                        Ok(true) => {}
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                    let salt = std::mem::take(&mut me.rtmp);
                    let subkey = session_subkey(me.method, &me.master, &salt);
                    me.recv = Some(match Crypto::new(me.method, &subkey) {
                        Ok(c) => c,
                        Err(e) => return Poll::Ready(Err(e)),
                    });
                    me.stage = ReadStage::Len;
                }
                ReadStage::Len => {
                    match ready!(me.fill(cx, 2 + TAG)) {
                        Ok(false) => return Poll::Ready(Ok(())), // чистый EOF на границе
                        Ok(true) => {}
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                    let frame = std::mem::take(&mut me.rtmp);
                    let recv = me.recv.as_mut().expect("recv инициализирован после соли");
                    let pt = match recv.open(&frame) {
                        Ok(p) => p,
                        Err(e) => return Poll::Ready(Err(e)),
                    };
                    let len = ((pt[0] as usize) << 8) | pt[1] as usize;
                    if len == 0 || len > MAX_CHUNK {
                        return Poll::Ready(Err(io::Error::other("ss: неверная длина чанка")));
                    }
                    me.stage = ReadStage::Data(len);
                }
                ReadStage::Data(len) => {
                    match ready!(me.fill(cx, len + TAG)) {
                        Ok(false) => {
                            return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)))
                        }
                        Ok(true) => {}
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                    let frame = std::mem::take(&mut me.rtmp);
                    let recv = me.recv.as_mut().expect("recv инициализирован после соли");
                    me.plain = match recv.open(&frame) {
                        Ok(p) => p,
                        Err(e) => return Poll::Ready(Err(e)),
                    };
                    me.ppos = 0;
                    me.stage = ReadStage::Len;

                    let n = out.remaining().min(me.plain.len());
                    out.put_slice(&me.plain[..n]);
                    me.ppos = n;
                    if me.ppos == me.plain.len() {
                        me.plain.clear();
                        me.ppos = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ShadowsocksStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();

        // Сначала добиваем недописанное.
        match ready!(me.flush_wbuf(cx)) {
            Ok(()) => {}
            Err(e) => return Poll::Ready(Err(e)),
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Первая запись — генерируем соль и подключ.
        if me.send.is_none() {
            let mut salt = vec![0u8; me.method.salt_len()];
            if let Err(e) = getrandom::getrandom(&mut salt) {
                return Poll::Ready(Err(io::Error::other(format!("getrandom: {e}"))));
            }
            let subkey = session_subkey(me.method, &me.master, &salt);
            me.send = Some(match Crypto::new(me.method, &subkey) {
                Ok(c) => c,
                Err(e) => return Poll::Ready(Err(e)),
            });
            me.wbuf.extend_from_slice(&salt);
        }

        let take = buf.len().min(MAX_CHUNK);
        let len_be = [(take >> 8) as u8, take as u8];
        let send = me.send.as_mut().expect("send инициализирован выше");
        match send.seal(&len_be) {
            Ok(ct) => me.wbuf.extend_from_slice(&ct),
            Err(e) => return Poll::Ready(Err(e)),
        }
        match send.seal(&buf[..take]) {
            Ok(ct) => me.wbuf.extend_from_slice(&ct),
            Err(e) => return Poll::Ready(Err(e)),
        }

        // Пробуем сбросить (Pending не страшен — данные буферизованы).
        if let Poll::Ready(Err(e)) = me.flush_wbuf(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(take))
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
        match ready!(me.flush_wbuf(cx)) {
            Ok(()) => {}
            Err(e) => return Poll::Ready(Err(e)),
        }
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}
