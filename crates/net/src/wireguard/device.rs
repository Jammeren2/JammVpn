//! smoltcp-устройство поверх WG-туннеля (без реального NIC).
//!
//! `rx` — очередь расшифрованных входящих IP-пакетов (драйвер кладёт сюда то,
//! что вернул `Tunn::decapsulate`); `tx` — очередь исходящих IP-пакетов, которые
//! сгенерировал smoltcp (драйвер заберёт их, зашифрует через `Tunn::encapsulate`
//! и отправит по UDP). Medium::Ip — работаем на уровне IP-пакетов, без Ethernet.

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use std::collections::VecDeque;

/// MTU WG-туннеля (1500 − 20 IP − 8 UDP − 32 WG-overhead ≈ 1440; берём 1420 как
/// типовое значение WireGuard).
pub const WG_MTU: usize = 1420;

/// Виртуальное устройство: мост между smoltcp и WG-driver'ом.
pub struct WgDevice {
    /// Входящие (расшифрованные) IP-пакеты → smoltcp.
    pub rx: VecDeque<Vec<u8>>,
    /// Исходящие IP-пакеты от smoltcp → драйверу на шифрование.
    pub tx: VecDeque<Vec<u8>>,
}

impl WgDevice {
    pub fn new() -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
        }
    }
}

impl Device for WgDevice {
    type RxToken<'a> = WgRxToken;
    type TxToken<'a> = WgTxToken<'a>;

    fn receive(&mut self, _ts: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((WgRxToken(pkt), WgTxToken(&mut self.tx)))
    }

    fn transmit(&mut self, _ts: Instant) -> Option<Self::TxToken<'_>> {
        Some(WgTxToken(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = WG_MTU;
        caps
    }
}

/// Токен приёма: владеет одним расшифрованным IP-пакетом.
pub struct WgRxToken(Vec<u8>);

impl RxToken for WgRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

/// Токен передачи: складывает сконструированный smoltcp пакет в `tx`.
pub struct WgTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl TxToken for WgTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_ip_mtu() {
        let dev = WgDevice::new();
        let caps = dev.capabilities();
        assert_eq!(caps.medium, Medium::Ip);
        assert_eq!(caps.max_transmission_unit, WG_MTU);
    }

    #[test]
    fn rx_token_delivers_packet() {
        let mut dev = WgDevice::new();
        dev.rx.push_back(vec![1, 2, 3, 4]);
        let (rx, _tx) = dev.receive(Instant::from_millis(0)).expect("rx token");
        let got = rx.consume(|buf| buf.to_vec());
        assert_eq!(got, vec![1, 2, 3, 4]);
        // очередь опустошена.
        assert!(dev.receive(Instant::from_millis(0)).is_none());
    }

    #[test]
    fn tx_token_enqueues_packet() {
        let mut dev = WgDevice::new();
        let tx = dev.transmit(Instant::from_millis(0)).expect("tx token");
        tx.consume(5, |buf| buf.copy_from_slice(&[9, 8, 7, 6, 5]));
        assert_eq!(dev.tx.pop_front(), Some(vec![9, 8, 7, 6, 5]));
    }
}
