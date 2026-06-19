//! HTTP/3-аутентификация Hysteria2: один `POST /auth` с заголовком
//! `Hysteria-Auth`, успех = статус `233`. Используем крейт `h3` (QPACK/Huffman
//! и фрейминг HTTP/3 — на нём), а проксирование идёт по сырым QUIC-стримам того
//! же соединения (см. [`super::tunnel`]).

use super::config::Hysteria2Params;
use rand::Rng;
use std::future;
use std::io;

/// Результат аутентификации.
pub(crate) struct AuthOutcome {
    /// Сервер разрешил проксирование UDP.
    #[allow(dead_code)] // UDP — отдельным шагом; пока только TCP.
    pub udp: bool,
}

/// Удерживает h3-ресурсы живыми на время жизни туннеля: драйвер HTTP/3-соединения
/// (его нужно поллить) и `SendRequest` (его дроп послал бы GOAWAY). Само
/// QUIC-соединение для прокси-стримов держит [`super::tunnel::Hysteria2Tunnel`].
pub(crate) struct H3Guard {
    _drive: tokio::task::JoinHandle<()>,
    // `Mutex` делает хранилище `Sync` (туннель живёт в `Arc` между потоками);
    // сам `SendRequest` нам больше не нужен — лишь удерживаем от дропа.
    _send_request: std::sync::Mutex<Box<dyn std::any::Any + Send>>,
}

fn io_other<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

/// Случайный паддинг для заголовка `Hysteria-Padding` (обфускация длины).
fn padding() -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    let len = rng.random_range(64..=256);
    (0..len)
        .map(|_| CHARS[rng.random_range(0..CHARS.len())] as char)
        .collect()
}

/// Выполняет HTTP/3-аутентификацию поверх установленного QUIC-соединения.
pub(crate) async fn authenticate(
    conn: quinn::Connection,
    params: &Hysteria2Params,
) -> io::Result<(AuthOutcome, H3Guard)> {
    let h3_conn = h3_quinn::Connection::new(conn);
    let (mut driver, mut send_request) = h3::client::new(h3_conn).await.map_err(io_other)?;

    // Драйвер HTTP/3-соединения нужно поллить — иначе send_request «зависнет».
    // Завершится сам, когда QUIC-соединение закроется (туннель сбросит conn).
    let drive = tokio::spawn(async move {
        let _ = future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    // Hysteria2 различает auth-запрос по магическому `:authority = "hysteria"`
    // (фиксированная строка протокола, НЕ реальный хост — иначе сервер уводит
    // запрос в masquerade и отвечает 404). SNI при этом — настоящий домен.
    let uri: http::Uri = "https://hysteria/auth".parse().map_err(io_other)?;
    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header("hysteria-auth", params.auth.as_str())
        .header("hysteria-cc-rx", "0") // 0 = BBR-авто (сервер сам выберет)
        .header("hysteria-padding", padding())
        .body(())
        .map_err(io_other)?;

    let mut stream = send_request.send_request(req).await.map_err(io_other)?;
    stream.finish().await.map_err(io_other)?; // тело пустое
    let resp = stream.recv_response().await.map_err(io_other)?;

    let status = resp.status().as_u16();
    if status != 233 {
        return Err(io::Error::other(format!(
            "hysteria2: аутентификация отклонена (HTTP-статус {status}, ожидался 233) — проверьте пароль/SNI"
        )));
    }
    let udp = resp
        .headers()
        .get("hysteria-udp")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    Ok((
        AuthOutcome { udp },
        H3Guard {
            _drive: drive,
            _send_request: std::sync::Mutex::new(Box::new(send_request)),
        },
    ))
}
