//! Async-проверка боевого пути: `Outbound::Vless` + `Transport::Reality`.
//!
//! Usage: vless_reality <host:port> <uuid> <pbk> <sid> <sni> <target host:port>

use jammvpn_net::vless;
use jammvpn_net::{Outbound, RealityTransport, Target, Transport, VlessConfig};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 7 {
        eprintln!("usage: vless_reality <host:port> <uuid> <pbk> <sid> <sni> <target host:port>");
        std::process::exit(2);
    }
    let uuid = vless::parse_uuid(&a[2]).expect("bad uuid");
    let ob = Outbound::Vless(VlessConfig {
        server: a[1].clone(),
        uuid,
        flow: None,
        transport: Transport::Reality(RealityTransport {
            public_key: a[3].clone(),
            short_id: a[4].clone(),
            server_name: a[5].clone(),
        }),
    });
    let (thost, tport) = a[6].rsplit_once(':').expect("target host:port");
    let target = Target::Domain(thost.to_string(), tport.parse().expect("port"));

    let mut s = match ob.connect_tcp(&target).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[!] connect_tcp: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("[+] VLESS+REALITY connect OK");

    let http = format!(
        "GET / HTTP/1.1\r\nHost: {thost}\r\nUser-Agent: curl/8\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    s.write_all(http.as_bytes()).await.expect("write");
    s.flush().await.expect("flush");

    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    for _ in 0..30 {
        match tokio::time::timeout(Duration::from_secs(8), s.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                out.extend_from_slice(&chunk[..n]);
                if out.len() > 4096 {
                    break;
                }
            }
            Ok(Err(e)) => {
                eprintln!("[!] read: {e}");
                break;
            }
            Err(_) => {
                eprintln!("[!] timeout");
                break;
            }
        }
    }
    eprintln!(
        "[+] получено {} байт (заголовок VLESS снят обёрткой)",
        out.len()
    );
    println!("{}", String::from_utf8_lossy(&out[..out.len().min(1200)]));
}
