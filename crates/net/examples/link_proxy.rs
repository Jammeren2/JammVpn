//! Локальный SOCKS5, тунелирующий ВЕСЬ трафик через узел из share-ссылки.
//!
//! Поддерживает всё, что умеет [`jammvpn_core::parse_link`] +
//! [`jammvpn_net::outbound_from_profile`]: vless:// (в т.ч. REALITY и
//! flow=xtls-rprx-vision), trojan://, ss://, socks://.
//!
//! Usage:
//!   cargo run --example link_proxy -- <listen host:port> "<share-link>"
//!
//! Проверка:
//!   curl --socks5-hostname <listen> https://icanhazip.com

use jammvpn_core::parse_link;
use jammvpn_net::{outbound_from_profile, serve_socks_routed, Engine};
use std::sync::Arc;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 {
        eprintln!("usage: link_proxy <listen host:port> <share-link>");
        std::process::exit(2);
    }
    let listen = a[1].clone();
    let profile = parse_link(&a[2]).expect("разбор share-ссылки");
    let flow = profile.param("flow").unwrap_or("-");
    eprintln!(
        "[+] узел: {:?} {}:{} (flow={flow})",
        profile.protocol, profile.address, profile.port
    );
    let outbound = outbound_from_profile(&profile).expect("сборка outbound");

    let engine = Engine::single_proxy(outbound);
    let listener = TcpListener::bind(&listen).await.expect("bind");
    eprintln!("[+] SOCKS5 на {listen} → весь трафик через узел");
    eprintln!("    проверка: curl --socks5-hostname {listen} https://icanhazip.com");
    serve_socks_routed(listener, Arc::new(engine))
        .await
        .expect("serve");
}
