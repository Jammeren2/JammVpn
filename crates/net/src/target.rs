//! Адрес назначения соединения.

use std::fmt;
use std::net::SocketAddr;

/// Цель исходящего соединения: доменное имя или конкретный адрес.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Доменное имя и порт (резолв выполняется на стороне исполнителя).
    Domain(String, u16),
    /// Готовый сокет-адрес.
    Socket(SocketAddr),
}

impl Target {
    /// Порт назначения.
    pub fn port(&self) -> u16 {
        match self {
            Target::Domain(_, p) => *p,
            Target::Socket(s) => s.port(),
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Domain(host, port) => write!(f, "{host}:{port}"),
            Target::Socket(addr) => write!(f, "{addr}"),
        }
    }
}
