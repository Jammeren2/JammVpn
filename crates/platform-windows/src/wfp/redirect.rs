//! Восстановление original-dst для перенаправленного драйвером соединения.
//!
//! Драйвер при connect-redirect сохраняет оригинальный адрес назначения в
//! redirect-context (формат [`super::ipc::encode_redirect_context`]). Локальный
//! транспарент-прокси на принятом сокете запрашивает его через
//! `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT)` — здесь это обёрнуто в
//! [`query_original_dst`].

use super::ipc::{decode_redirect_context, REDIRECT_CONTEXT_LEN};
use std::net::SocketAddr;
use std::ptr;
use windows_sys::Win32::Networking::WinSock::{WSAGetLastError, WSAIoctl, SOCKET};

/// `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT` = `_WSAIOR(IOC_VENDOR, 38)`
/// (`IOC_OUT|IOC_VENDOR|38` = `0x4000_0000 | 0x1800_0000 | 0x26`).
const SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT: u32 = 0x5800_0026;

/// По сырому дескриптору сокета (`SOCKET`) возвращает оригинальный адрес
/// назначения из redirect-context драйвера. Ошибка — если сокет не был
/// перенаправлен (контекста нет) либо WSAIoctl/декодирование не удалось.
pub fn query_original_dst(socket: usize) -> Result<SocketAddr, String> {
    let mut buf = [0u8; REDIRECT_CONTEXT_LEN];
    let mut returned: u32 = 0;
    // SAFETY: socket — валидный дескриптор; out-буфер живёт на время вызова;
    // входного буфера нет; overlapped/completion отсутствуют (синхронный вызов).
    let rc = unsafe {
        WSAIoctl(
            socket as SOCKET,
            SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
            ptr::null(),
            0,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            buf.len() as u32,
            &mut returned,
            ptr::null_mut(),
            None,
        )
    };
    if rc != 0 {
        // SAFETY: чтение кода последней ошибки Winsock.
        let err = unsafe { WSAGetLastError() };
        return Err(format!("WSAIoctl(redirect context): код {err}"));
    }
    decode_redirect_context(&buf[..returned as usize]).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::os::windows::io::AsRawSocket;

    #[test]
    fn errors_for_non_redirected_socket() {
        // Обычное (не перенаправленное драйвером) соединение не имеет
        // redirect-context → WSAIoctl возвращает ошибку, а не панику.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let _accepted = l.accept().unwrap();
        let res = query_original_dst(client.as_raw_socket() as usize);
        assert!(res.is_err());
    }
}
