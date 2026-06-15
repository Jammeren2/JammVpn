//! Поток поверх smoltcp tcp-сокета в WG-туннеле: `AsyncRead`/`AsyncWrite`.
//!
//! Чтение/запись блокируют общий стек лишь на время копирования из/в кольцевые
//! буферы сокета и регистрируют waker'ы smoltcp; после успешной операции будят
//! driver-task (kick) — чтобы он отправил данные/ACK и обновил окно.

use super::tunnel::WgTunnel;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// TCP-поток внутри WG-туннеля.
pub struct WgTcpStream {
    tunnel: Arc<WgTunnel>,
    handle: SocketHandle,
}

impl WgTcpStream {
    pub(crate) fn new(tunnel: Arc<WgTunnel>, handle: SocketHandle) -> Self {
        Self { tunnel, handle }
    }
}

impl AsyncRead for WgTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let mut st = me.tunnel.stack().lock().unwrap();
        let socket = st.sockets.get_mut::<tcp::Socket>(me.handle);

        if socket.can_recv() {
            let n = socket
                .recv_slice(buf.initialize_unfilled())
                .map_err(|e| io::Error::other(format!("wg: recv: {e:?}")))?;
            buf.advance(n);
            drop(st);
            me.tunnel.kick(); // отправить ACK / обновить окно
            return Poll::Ready(Ok(()));
        }
        if !socket.may_recv() {
            // Удалённая сторона закрыла приём / соединение мертво → EOF.
            return Poll::Ready(Ok(()));
        }
        socket.register_recv_waker(cx.waker());
        Poll::Pending
    }
}

impl AsyncWrite for WgTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let mut st = me.tunnel.stack().lock().unwrap();
        let socket = st.sockets.get_mut::<tcp::Socket>(me.handle);

        if !socket.may_send() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "wg: сокет закрыт для записи",
            )));
        }
        if socket.can_send() {
            let n = socket
                .send_slice(data)
                .map_err(|e| io::Error::other(format!("wg: send: {e:?}")))?;
            drop(st);
            me.tunnel.kick(); // протолкнуть данные в туннель
            return Poll::Ready(Ok(n));
        }
        socket.register_send_waker(cx.waker());
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // smoltcp отправляет данные сам; flush сводится к пробуждению драйвера.
        self.tunnel.kick();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        {
            let mut st = me.tunnel.stack().lock().unwrap();
            st.sockets.get_mut::<tcp::Socket>(me.handle).close();
        }
        me.tunnel.kick();
        Poll::Ready(Ok(()))
    }
}

impl Drop for WgTcpStream {
    fn drop(&mut self) {
        // Удаляем сокет из стека (v0: без ожидания graceful close).
        self.tunnel.remove_socket(self.handle);
    }
}
