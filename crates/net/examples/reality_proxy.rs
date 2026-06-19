//! Локальный SOCKS5-прокси, тунелирующий ВЕСЬ трафик через REALITY (демо).
//!
//! Usage:
//!   cargo run --example reality_proxy -- <listen host:port> <server host:port> <uuid> <pbk> <sid> <sni>
//!
//! Затем, например:
//!   curl --socks5-hostname 127.0.0.1:1080 http://icanhazip.com

use jammvpn_net::vless;
use jammvpn_net::{serve_socks_routed, Engine, Outbound, RealityTransport, Transport, VlessConfig};
use std::sync::Arc;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 7 {
        eprintln!("usage: reality_proxy <listen> <server> <uuid> <pbk> <sid> <sni>");
        std::process::exit(2);
    }
    let listen = a[1].clone();
    let uuid = vless::parse_uuid(&a[3]).expect("bad uuid");
    let outbound = Outbound::Vless(VlessConfig {
        server: a[2].clone(),
        uuid,
        flow: None,
        transport: Transport::Reality(RealityTransport {
            public_key: a[4].clone(),
            short_id: a[5].clone(),
            server_name: a[6].clone(),
        }),
        encryption: None,
    });

    let engine = Engine::single_proxy(outbound);
    let listener = TcpListener::bind(&listen).await.expect("bind");
    eprintln!(
        "[+] SOCKS5 на {listen} → весь трафик через REALITY {}",
        a[2]
    );
    eprintln!("    проверка: curl --socks5-hostname {listen} http://icanhazip.com");
    serve_socks_routed(listener, Arc::new(engine))
        .await
        .expect("serve");
}
