//! Поток данных VLESS Encryption (порт `CommonConn` из `common.go`).
//!
//! После handshake поверх транспорта идут TLS-подобные записи:
//! `[23,3,3, len_hi, len_lo]` + `AEAD.seal(data, aad = 5-байтный заголовок)`,
//! где `len = len(data)+16`. Nonce — счётчик с авто-инкрементом; при достижении
//! `MaxNonce` ключ AEAD пересоздаётся из `заголовок ++ шифртекст` записи.
//! Перед первой записью данных клиент дочитывает серверный паддинг (peer nonce3).

use super::aead::Aead;
use super::handshake::EncState;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Максимум полезной нагрузки в одной записи (как в `common.go`).
const MAX_DATA: usize = 8192;
const TAG: usize = 16;

#[derive(Clone, Copy)]
enum ReadStage {
    /// Дочитать серверный паддинг (один раз, peer nonce3).
    Padding,
    /// 5-байтный заголовок записи.
    Header,
    /// `l` байт зашифрованной записи (l = data+16, 17..=16640).
    Data(usize),
}

/// Прозрачный поток VLESS Encryption поверх транспорта `S`.
pub struct VlessEncStream<S> {
    inner: S,
    write_aead: Aead,
    peer_aead: Aead,
    united_key: Vec<u8>,
    use_aes: bool,
    // чтение
    stage: ReadStage,
    peer_padding_len: usize,
    hdr: [u8; 5],
    rtmp: Vec<u8>,
    plain: Vec<u8>,
    ppos: usize,
    // запись
    wbuf: Vec<u8>,
    wpos: usize,
    // режим random: XOR-обёртка заголовков записей (None для native/xorpub)
    xor: Option<super::xor::XorState>,
}

impl<S> VlessEncStream<S> {
    /// Оборачивает транспорт результатом handshake.
    pub fn new(inner: S, st: EncState) -> Self {
        let stage = if st.peer_padding_len > 0 {
            ReadStage::Padding
        } else {
            ReadStage::Header
        };
        Self {
            inner,
            write_aead: st.write_aead,
            peer_aead: st.peer_aead,
            united_key: st.united_key,
            use_aes: st.use_aes,
            stage,
            peer_padding_len: st.peer_padding_len,
            hdr: [0u8; 5],
            rtmp: Vec::new(),
            plain: Vec::new(),
            ppos: 0,
            wbuf: Vec::new(),
            wpos: 0,
            xor: st.xor,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> VlessEncStream<S> {
    /// Дочитывает `rtmp` до `need` байт. `Ok(false)` — чистый EOF на границе.
    fn fill(&mut self, cx: &mut Context<'_>, need: usize) -> Poll<io::Result<bool>> {
        while self.rtmp.len() < need {
            let mut tmp = [0u8; 4096];
            let want = (need - self.rtmp.len()).min(tmp.len());
            let mut rb = ReadBuf::new(&mut tmp[..want]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        if self.rtmp.is_empty() {
                            return Poll::Ready(Ok(false));
                        }
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                    }
                    // random: восстанавливаем заголовки записей до фрейминга.
                    if let Some(xor) = self.xor.as_mut() {
                        xor.transform_read(&mut tmp[..n]);
                    }
                    self.rtmp.extend_from_slice(&tmp[..n]);
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

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VlessEncStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        // Остаток ранее расшифрованной записи.
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
                ReadStage::Padding => {
                    match ready!(me.fill(cx, me.peer_padding_len)) {
                        Ok(false) => return Poll::Ready(Ok(())), // EOF до данных
                        Ok(true) => {}
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                    let pad = std::mem::take(&mut me.rtmp);
                    // peer nonce3; содержимое отбрасываем.
                    if let Err(e) = me.peer_aead.open(&pad, &[]) {
                        return Poll::Ready(Err(e));
                    }
                    me.stage = ReadStage::Header;
                }
                ReadStage::Header => {
                    match ready!(me.fill(cx, 5)) {
                        Ok(false) => return Poll::Ready(Ok(())), // чистый EOF
                        Ok(true) => {}
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                    let h = std::mem::take(&mut me.rtmp);
                    me.hdr.copy_from_slice(&h);
                    let l = ((me.hdr[3] as usize) << 8) | me.hdr[4] as usize;
                    if me.hdr[0] != 23 || me.hdr[1] != 3 || me.hdr[2] != 3 || !(17..=16640).contains(&l)
                    {
                        return Poll::Ready(Err(io::Error::other(
                            "vless-enc: неверный заголовок записи",
                        )));
                    }
                    me.stage = ReadStage::Data(l);
                }
                ReadStage::Data(l) => {
                    match ready!(me.fill(cx, l)) {
                        Ok(false) => {
                            return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)))
                        }
                        Ok(true) => {}
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                    let frame = std::mem::take(&mut me.rtmp);
                    // Пересоздание ключа при достижении MaxNonce (ctx = заголовок ++ шифртекст).
                    let rekey = me.peer_aead.at_max();
                    let pt = match me.peer_aead.open(&frame, &me.hdr) {
                        Ok(p) => p,
                        Err(e) => return Poll::Ready(Err(e)),
                    };
                    if rekey {
                        let mut ctx = Vec::with_capacity(5 + frame.len());
                        ctx.extend_from_slice(&me.hdr);
                        ctx.extend_from_slice(&frame);
                        me.peer_aead = Aead::new(&ctx, &me.united_key, me.use_aes);
                    }
                    me.plain = pt;
                    me.ppos = 0;
                    me.stage = ReadStage::Header;

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

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VlessEncStream<S> {
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

        let take = buf.len().min(MAX_DATA);
        let rec_len = take + TAG;
        let hdr = [23u8, 3, 3, (rec_len >> 8) as u8, rec_len as u8];
        let rekey = me.write_aead.at_max();
        let sealed = me.write_aead.seal(&buf[..take], &hdr);
        // record = заголовок(5) ++ шифртекст(take+16).
        let mut record = Vec::with_capacity(5 + sealed.len());
        record.extend_from_slice(&hdr);
        record.extend_from_slice(&sealed);
        if rekey {
            me.write_aead = Aead::new(&record, &me.united_key, me.use_aes);
        }
        // random: ксорим заголовок записи (rekey-ctx выше — по плейнтексту, как в Go).
        if let Some(xor) = me.xor.as_mut() {
            xor.transform_write(&mut record);
        }
        me.wbuf.extend_from_slice(&record);

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
