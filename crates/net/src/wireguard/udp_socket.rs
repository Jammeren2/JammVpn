//! UDP-сокет поверх smoltcp udp-сокета в WG-туннеле.
//!
//! Аналог [`super::stream::WgTcpStream`] для датаграмм: `send`/`recv` блокируют
//! общий стек лишь на время копирования из/в буферы сокета, регистрируют
//! waker'ы smoltcp и будят driver-task (`kick`). Все датаграммы нацелены на
//! фиксированный `remote` (выбранный при ASSOCIATE адрес назначения).

use super::tunnel::WgTunnel;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::udp;
use smoltcp::wire::IpEndpoint;
use std::future::poll_fn;
use std::io;
use std::sync::Arc;
use std::task::Poll;

/// UDP-сокет внутри WG-туннеля (одна цель).
pub struct WgUdpSocket {
    tunnel: Arc<WgTunnel>,
    handle: SocketHandle,
    remote: IpEndpoint,
}

impl WgUdpSocket {
    pub(crate) fn new(tunnel: Arc<WgTunnel>, handle: SocketHandle, remote: IpEndpoint) -> Self {
        Self {
            tunnel,
            handle,
            remote,
        }
    }

    /// Отправляет датаграмму цели через туннель.
    pub async fn send(&self, payload: &[u8]) -> io::Result<()> {
        poll_fn(|cx| {
            let mut st = self.tunnel.stack().lock().unwrap();
            let socket = st.sockets.get_mut::<udp::Socket>(self.handle);
            match socket.send_slice(payload, self.remote) {
                Ok(()) => {
                    drop(st);
                    self.tunnel.kick(); // протолкнуть датаграмму в туннель
                    Poll::Ready(Ok(()))
                }
                Err(udp::SendError::BufferFull) => {
                    socket.register_send_waker(cx.waker());
                    drop(st);
                    self.tunnel.kick();
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(io::Error::other(format!("wg: udp send: {e:?}")))),
            }
        })
        .await
    }

    /// Принимает следующую датаграмму от цели (payload без заголовков).
    pub async fn recv(&self) -> io::Result<Vec<u8>> {
        poll_fn(|cx| {
            let mut st = self.tunnel.stack().lock().unwrap();
            let socket = st.sockets.get_mut::<udp::Socket>(self.handle);
            if socket.can_recv() {
                let mut buf = vec![0u8; 65_535];
                return match socket.recv_slice(&mut buf) {
                    Ok((n, _meta)) => {
                        buf.truncate(n);
                        Poll::Ready(Ok(buf))
                    }
                    Err(e) => Poll::Ready(Err(io::Error::other(format!("wg: udp recv: {e:?}")))),
                };
            }
            socket.register_recv_waker(cx.waker());
            drop(st);
            self.tunnel.kick(); // подтолкнуть driver к немедленному poll
            Poll::Pending
        })
        .await
    }
}

impl Drop for WgUdpSocket {
    fn drop(&mut self) {
        // UDP без рукопожатия закрытия — удаляем сокет сразу.
        self.tunnel.remove_socket(self.handle);
    }
}
