//! Единственный task, сводящий boringtun (Noise) + smoltcp (poll) + UDP-сокет +
//! асинхронные потоки. Только здесь вызываются `iface.poll`, `Tunn::encapsulate
//! /decapsulate/update_timers`. Инвариант: НИКОГДА не держим `Mutex<Stack>` через
//! `.await` (исходящие шифртексты копим под локом, шлём — отпустив лок).

use super::obfs::AwgObfs;
use super::tunnel::Stack;
use boringtun::noise::{Tunn, TunnResult};
use smoltcp::time::Instant as SmolInstant;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as StdInstant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};

/// Период тика `update_timers` (handshake/keepalive/rekey).
const TIMER_TICK: Duration = Duration::from_millis(250);
/// Размер scratch-буфера (макс. UDP-датаграмма WG).
const SCRATCH: usize = 65535;

/// Тело driver-task. Завершается, когда `WgTunnel` сброшен (JoinHandle abort).
#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
    stack: Arc<Mutex<Stack>>,
    udp: Arc<UdpSocket>,
    mut tunn: Tunn,
    obfs: AwgObfs,
    notify: Arc<Notify>,
    mut wake_rx: mpsc::UnboundedReceiver<()>,
    base: StdInstant,
) {
    let mut scratch = vec![0u8; SCRATCH];
    let mut udp_buf = vec![0u8; SCRATCH];
    let mut ticker = tokio::time::interval(TIMER_TICK);

    // Инициируем handshake сразу: encapsulate(&[]) → MessageInitiation.
    if let TunnResult::WriteToNetwork(b) = tunn.encapsulate(&[], &mut scratch) {
        send_datagrams(&udp, obfs.wrap(b)).await;
    }

    loop {
        // 1. Поллим smoltcp, шифруем исходящие IP-пакеты, копим под локом.
        let (outbox, timeout) = {
            let mut st = stack.lock().unwrap();
            let now = SmolInstant::from_micros(base.elapsed().as_micros() as i64);
            let Stack {
                iface,
                device,
                sockets,
            } = &mut *st;
            iface.poll(now, device, sockets);

            let mut outbox: Vec<Vec<u8>> = Vec::new();
            while let Some(ip_pkt) = device.tx.pop_front() {
                match tunn.encapsulate(&ip_pkt, &mut scratch) {
                    TunnResult::WriteToNetwork(b) => outbox.extend(obfs.wrap(b)),
                    TunnResult::Err(e) => log::debug!("wg: encapsulate: {e:?}"),
                    _ => {}
                }
            }
            let delay = iface.poll_delay(now, sockets);
            (outbox, delay)
        };

        // 2. Отправляем шифртексты (лок уже отпущен).
        send_datagrams(&udp, outbox).await;
        // 3. Будим ожидающих (connect / потоки).
        notify.notify_waiters();

        // 4. Ждём событие: входящий UDP / тик таймеров / smoltcp-таймаут / kick.
        let sleep = sleep_opt(timeout.map(|d| Duration::from_micros(d.total_micros())));
        tokio::pin!(sleep);
        tokio::select! {
            r = udp.recv(&mut udp_buf) => {
                if let Ok(n) = r {
                    if let Some(clean) = obfs.unwrap(&udp_buf[..n]) {
                        handle_incoming(&stack, &udp, &obfs, &mut tunn, &mut scratch, &clean).await;
                    }
                }
            }
            _ = ticker.tick() => {
                if let TunnResult::WriteToNetwork(b) = tunn.update_timers(&mut scratch) {
                    send_datagrams(&udp, obfs.wrap(b)).await;
                }
            }
            _ = &mut sleep => {}
            _ = wake_rx.recv() => {}
        }
    }
}

/// Обрабатывает один входящий (уже де-обфусцированный) WG-пакет: расшифровывает
/// и кладёт внутренний IP-пакет в `device.rx`. boringtun требует «дренировать»
/// очередь пустыми вызовами `decapsulate` после непустого.
async fn handle_incoming(
    stack: &Arc<Mutex<Stack>>,
    udp: &UdpSocket,
    obfs: &AwgObfs,
    tunn: &mut Tunn,
    scratch: &mut [u8],
    packet: &[u8],
) {
    let mut first = true;
    loop {
        let input: &[u8] = if first { packet } else { &[] };
        first = false;
        match tunn.decapsulate(None, input, scratch) {
            TunnResult::WriteToNetwork(b) => {
                send_datagrams(udp, obfs.wrap(b)).await;
                // продолжаем дренировать (input=&[]).
            }
            TunnResult::WriteToTunnelV4(pkt, _) | TunnResult::WriteToTunnelV6(pkt, _) => {
                stack.lock().unwrap().device.rx.push_back(pkt.to_vec());
                break;
            }
            _ => break,
        }
    }
}

async fn send_datagrams(udp: &UdpSocket, datagrams: Vec<Vec<u8>>) {
    for dg in datagrams {
        if let Err(e) = udp.send(&dg).await {
            log::debug!("wg: udp send: {e}");
        }
    }
}

async fn sleep_opt(d: Option<Duration>) {
    match d {
        Some(d) => tokio::time::sleep(d).await,
        None => std::future::pending::<()>().await,
    }
}
