//! XTLS-Vision поверх ПЛОСКОГО потока (без внешнего TLS).
//!
//! Используется, когда под Vision лежит слой VLESS Encryption (`CommonConn`):
//! транспорт уже отдаёт расшифрованный байтовый поток, поэтому внешнего
//! TLS-дефрейминга/сессии нет — паддинг применяется прямо к плоским данным.
//!
//! Так как сквозной splice через слой Encryption невозможен, клиент всегда
//! шлёт команду `END` (а не `DIRECT`): после неё обе стороны переходят на
//! прозрачную ретрансляцию через `CommonConn`. Решение об `END` опирается лишь
//! на состояние фильтра по ИСХОДЯЩЕМУ направлению (ClientHello + счётчик
//! записей), поэтому путь чтения — простой unpad без фильтрации.

use super::tls_fuzzy_deframer::{DeframeResult, FuzzyTlsDeframer};
use super::vision_filter::VisionFilter;
use super::vision_pad::{pad_with_command, pad_with_uuid_and_command};
use super::vision_unpad::{UnpadCommand, UnpadResult, VisionUnpadder};
use bytes::{Buf, BytesMut};
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const COMMAND_CONTINUE: u8 = 0x00;
const COMMAND_END: u8 = 0x01;
/// Максимум контента в одном Vision-блоке (содержимое 2-байтное → нельзя >u16;
/// держим как у Xray-буфера, чтобы не раздувать кадр).
const MAX_CONTENT: usize = 8192;

#[derive(Debug, PartialEq, Clone, Copy)]
enum Mode {
    /// Применяем/снимаем Vision-паддинг.
    Padding,
    /// Прозрачная ретрансляция (после END/DIRECT).
    Passthrough,
}

/// Vision-обёртка над плоским потоком (слой Encryption).
pub struct VisionPlainStream<IO> {
    inner: IO,
    user_uuid: [u8; 16],
    // чтение
    read_mode: Mode,
    read_unpadder: VisionUnpadder,
    pending_read: BytesMut,
    vless_response_pending: bool,
    partial_vless_response: BytesMut,
    is_read_eof: bool,
    // запись
    write_mode: Mode,
    write_deframer: FuzzyTlsDeframer,
    filter: VisionFilter,
    write_first_packet: bool,
    wbuf: Vec<u8>,
    wpos: usize,
}

impl<IO> VisionPlainStream<IO> {
    /// Клиентская обёртка: VLESS-ответный заголовок снимается при первом чтении,
    /// первый исходящий Vision-пакет содержит UUID.
    pub fn new_client(inner: IO, user_uuid: [u8; 16]) -> Self {
        Self {
            inner,
            user_uuid,
            read_mode: Mode::Padding,
            read_unpadder: VisionUnpadder::new(user_uuid),
            pending_read: BytesMut::new(),
            vless_response_pending: true,
            partial_vless_response: BytesMut::new(),
            is_read_eof: false,
            write_mode: Mode::Padding,
            write_deframer: FuzzyTlsDeframer::new(),
            filter: VisionFilter::new(),
            write_first_packet: true,
            wbuf: Vec::new(),
            wpos: 0,
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> VisionPlainStream<IO> {
    /// Паддинг очередного блока с учётом первого пакета (UUID-префикс).
    fn pad(&mut self, data: &[u8], command: u8, is_tls: bool) -> bytes::Bytes {
        if self.write_first_packet {
            self.write_first_packet = false;
            pad_with_uuid_and_command(data, &self.user_uuid, command, is_tls)
        } else {
            pad_with_command(data, command, is_tls)
        }
    }

    /// Кладёт `data` в `wbuf` Vision-блоками ≤`MAX_CONTENT`: все, кроме
    /// последнего — CONTINUE, последний — `final_command` (так длинный кусок
    /// не переполняет 2-байтное поле длины и повторяет шейп Xray).
    fn push_padded(&mut self, data: &[u8], final_command: u8) {
        let is_tls = self.filter.is_tls();
        if data.is_empty() {
            let p = self.pad(data, final_command, is_tls);
            self.wbuf.extend_from_slice(&p);
            return;
        }
        let mut off = 0;
        while off < data.len() {
            let end = (off + MAX_CONTENT).min(data.len());
            let cmd = if end == data.len() {
                final_command
            } else {
                COMMAND_CONTINUE
            };
            let p = self.pad(&data[off..end], cmd, is_tls);
            self.wbuf.extend_from_slice(&p);
            off = end;
        }
    }

    /// Сбрасывает `wbuf` в нижележащий поток.
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

    /// Снимает Vision-паддинг с куска плоских данных, наполняя `pending_read`.
    /// При команде END/DIRECT переключает чтение в прозрачный режим.
    fn handle_unpad(&mut self, data: &[u8]) -> io::Result<()> {
        let UnpadResult { content, command } = self.read_unpadder.unpad(data)?;
        if !content.is_empty() {
            self.pending_read.extend_from_slice(&content);
        }
        if matches!(command, Some(UnpadCommand::End) | Some(UnpadCommand::Direct)) {
            // Хвост сырых данных уже добавлен распаковщиком в content.
            self.read_mode = Mode::Passthrough;
        }
        Ok(())
    }

    fn serve_pending(&mut self, buf: &mut ReadBuf<'_>) {
        let n = buf.remaining().min(self.pending_read.len());
        buf.put_slice(&self.pending_read[..n]);
        self.pending_read.advance(n);
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for VisionPlainStream<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        if !me.pending_read.is_empty() {
            me.serve_pending(buf);
            return Poll::Ready(Ok(()));
        }
        if me.read_mode == Mode::Passthrough {
            return Pin::new(&mut me.inner).poll_read(cx, buf);
        }
        if me.is_read_eof {
            return Poll::Ready(Ok(()));
        }

        loop {
            let mut tmp = [0u8; 8192];
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut me.inner).poll_read(cx, &mut rb))?;
            let chunk = rb.filled().to_vec();
            if chunk.is_empty() {
                me.is_read_eof = true;
                return Poll::Ready(Ok(()));
            }

            // Снять VLESS-ответный заголовок (версия + addon_len + addon) единожды.
            let to_unpad: Vec<u8> = if me.vless_response_pending {
                me.partial_vless_response.extend_from_slice(&chunk);
                if me.partial_vless_response.len() < 2 {
                    continue;
                }
                if me.partial_vless_response[0] != 0 {
                    return Poll::Ready(Err(io::Error::other(
                        "vision/enc: неверная версия VLESS-ответа",
                    )));
                }
                let total = 2 + me.partial_vless_response[1] as usize;
                if me.partial_vless_response.len() < total {
                    continue;
                }
                let tail = me.partial_vless_response.split_off(total);
                me.partial_vless_response = BytesMut::new();
                me.vless_response_pending = false;
                tail.to_vec()
            } else {
                chunk
            };

            if !to_unpad.is_empty() {
                me.handle_unpad(&to_unpad)?;
            }

            if !me.pending_read.is_empty() {
                me.serve_pending(buf);
                return Poll::Ready(Ok(()));
            }
            if me.read_mode == Mode::Passthrough {
                // Контента не осталось — дальше читаем напрямую.
                return Pin::new(&mut me.inner).poll_read(cx, buf);
            }
            // Иначе нужно больше данных — повторяем чтение.
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VisionPlainStream<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();

        // Всегда сначала добиваем накопленный вывод.
        ready!(me.flush_wbuf(cx))?;

        if me.write_mode == Mode::Passthrough {
            return Pin::new(&mut me.inner).poll_write(cx, buf);
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        me.write_deframer.feed(buf);
        loop {
            match me.write_deframer.next_record()? {
                DeframeResult::TlsRecord(record) => {
                    me.filter.filter_record(&record);
                    let is_app_data = me.filter.is_tls()
                        && record.len() >= 3
                        && record[0] == 0x17
                        && record[1] == 0x03;
                    let non_tls_ended = !is_app_data
                        && !me.filter.is_filtering()
                        && !me.filter.is_tls12_or_above();

                    if is_app_data || non_tls_ended {
                        me.push_padded(&record, COMMAND_END);
                        let tail = me.write_deframer.remaining_data().to_vec();
                        me.wbuf.extend_from_slice(&tail);
                        me.write_deframer.clear();
                        me.write_mode = Mode::Passthrough;
                        break;
                    }
                    me.push_padded(&record, COMMAND_CONTINUE);
                }
                DeframeResult::UnknownPrefix(prefix) => {
                    me.filter.decrement_filter_count();
                    if me.filter.is_filtering() {
                        me.push_padded(&prefix, COMMAND_CONTINUE);
                    } else {
                        me.push_padded(&prefix, COMMAND_END);
                        let tail = me.write_deframer.remaining_data().to_vec();
                        me.wbuf.extend_from_slice(&tail);
                        me.write_deframer.clear();
                        me.write_mode = Mode::Passthrough;
                        break;
                    }
                }
                DeframeResult::NeedData => break,
            }
        }

        // Лучшая попытка слить (Pending не страшен — данные буферизованы).
        if let Poll::Ready(Err(e)) = me.flush_wbuf(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(me.flush_wbuf(cx))?;
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(me.flush_wbuf(cx))?;
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}
