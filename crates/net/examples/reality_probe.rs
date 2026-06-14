//! Живой probe REALITY-интеропа (dev-инструмент, синхронный).
//!
//! Использование:
//!   cargo run --example reality_probe -- <server host:port> <uuid> <pbk> <sid> <sni> <target host:port>
//!
//! Делает: TCP → REALITY-хендшейк → VLESS-запрос (без flow) → HTTP GET к target
//! через туннель → печатает ответ. Подтверждает интероп против реального сервера.

use jammvpn_net::reality::{
    decode_public_key, decode_short_id, feed_reality_client_connection, RealityClientConfig,
    RealityClientConnection,
};
use jammvpn_net::{vless, Target};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn main() {
    if let Err(e) = run() {
        eprintln!("[!] ОШИБКА: {e}");
        std::process::exit(1);
    }
}

fn run() -> std::io::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 7 {
        eprintln!("usage: reality_probe <host:port> <uuid> <pbk> <sid> <sni> <target host:port>");
        std::process::exit(2);
    }
    let server = &a[1];
    let uuid = vless::parse_uuid(&a[2]).expect("bad uuid");
    let public_key = decode_public_key(&a[3])?;
    let short_id = decode_short_id(&a[4])?;
    let sni = a[5].clone();
    let (thost, tport) = a[6].rsplit_once(':').expect("target host:port");
    let target = Target::Domain(thost.to_string(), tport.parse().expect("port"));

    eprintln!("[*] connect {server}, sni={sni}");
    let mut stream = TcpStream::connect(server)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    let cfg = RealityClientConfig {
        public_key,
        short_id,
        server_name: sni,
        cipher_suites: vec![],
    };
    let mut conn = RealityClientConnection::new(cfg)?;

    // --- REALITY / TLS 1.3 handshake ---
    let mut rbuf = [0u8; 16384];
    let mut guard = 0;
    loop {
        while conn.wants_write() {
            let mut out = Vec::new();
            conn.write_tls(&mut out)?;
            if out.is_empty() {
                break;
            }
            stream.write_all(&out)?;
        }
        if !conn.is_handshaking() {
            break;
        }
        let n = stream.read(&mut rbuf)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "сервер закрыл соединение во время хендшейка",
            ));
        }
        feed_reality_client_connection(&mut conn, &rbuf[..n])?;
        conn.process_new_packets()?;
        guard += 1;
        if guard > 100 {
            return Err(std::io::Error::other("хендшейк не сошёлся (guard)"));
        }
    }
    eprintln!("[+] REALITY/TLS1.3 ХЕНДШЕЙК OK");

    // --- VLESS request (без flow) + HTTP GET через туннель ---
    let vless_req = vless::encode_request(&uuid, None, &target);
    let http = format!(
        "GET / HTTP/1.1\r\nHost: {thost}\r\nUser-Agent: curl/8\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    {
        let mut w = conn.writer();
        w.write_all(&vless_req)?;
        w.write_all(http.as_bytes())?;
    }
    while conn.wants_write() {
        let mut out = Vec::new();
        conn.write_tls(&mut out)?;
        if out.is_empty() {
            break;
        }
        stream.write_all(&out)?;
    }
    eprintln!("[*] VLESS-запрос + GET отправлены, читаю ответ…");

    // --- read decrypted response ---
    let mut plaintext = Vec::new();
    loop {
        let n = match stream.read(&mut rbuf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break
            }
            Err(e) => return Err(e),
        };
        feed_reality_client_connection(&mut conn, &rbuf[..n])?;
        conn.process_new_packets()?;
        let mut buf = [0u8; 8192];
        loop {
            match conn.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(r) => plaintext.extend_from_slice(&buf[..r]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        if plaintext.len() > 8192 {
            break;
        }
    }

    // первые байты — VLESS-ответный заголовок: версия(1)+len_addon(1)+addon.
    let body_start = if plaintext.len() >= 2 {
        2 + plaintext[1] as usize
    } else {
        0
    };
    let body = plaintext.get(body_start..).unwrap_or(&[]);
    eprintln!("[+] получено {} байт plaintext через туннель", body.len());
    println!("{}", String::from_utf8_lossy(&body[..body.len().min(1200)]));
    Ok(())
}
