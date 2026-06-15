//! WG-туннель: общий netstack (smoltcp) + Noise-ядро (boringtun) + driver-task.
//!
//! Скелет: реальная реализация — WG-C (driver) и WG-D (поток).

use super::config::WgParams;
use crate::target::Target;
use crate::BoxedStream;
use std::io;
use std::sync::Arc;

/// Запущенный WG-туннель — общий для всех соединений узла.
pub struct WgTunnel {
    // Поля (Stack=Interface+WgDevice+SocketSet, UdpSocket, driver-handle, wake) — WG-C.
}

impl WgTunnel {
    /// Поднимает туннель: bind UDP, конструирует netstack и Noise-ядро, запускает
    /// единственный driver-task. Возвращает общий дескриптор.
    pub(crate) async fn start(_params: &WgParams) -> io::Result<Arc<WgTunnel>> {
        Err(io::Error::other(
            "WireGuard: поднятие туннеля ещё не реализовано (WG-C)",
        ))
    }

    /// Открывает TCP-поток до `target` через туннель (smoltcp-сокет → поток).
    pub(crate) async fn connect(&self, _target: &Target) -> io::Result<BoxedStream> {
        Err(io::Error::other(
            "WireGuard connect: ещё не реализовано (WG-D)",
        ))
    }
}
