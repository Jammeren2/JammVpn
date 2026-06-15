//! Shadowsocks 2022 (SIP022) поток: BLAKE3-сессионный подключ + структурный
//! заголовок (защита от replay по timestamp + привязка ответа к соли запроса).
//!
//! Формат запроса: `соль | seal(type=0 | ts(8) | len(2)) | seal(addr | pad_len(2) |
//! pad) | чанки`. Формат ответа: `соль | seal(type=1 | ts(8) | req_salt | len(2)) |
//! seal(первый payload[len]) | чанки`. После заголовка payload — стандартные
//! AEAD-чанки `[seal(len:2)][seal(data)]`. nonce — счётчик с нуля (на направление).

use super::crypto::{session_subkey_2022, Crypto, Method};
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_CHUNK: usize = 0xFFFF;
const TAG: usize = 16;
const TYPE_REQUEST: u8 = 0;
const TYPE_RESPONSE: u8 = 1;

enum ReadStage {
    ServerSalt,
    RespHeader,
    FirstPayload(usize),
    Len,
    Data(usize),
}

/// Поток Shadowsocks 2022 поверх `inner`.
pub struct Ss2022Stream<S> {
    inner: S,
    method: Method,
    psk: Vec<u8>,
    client_salt: Vec<u8>,
    send: Crypto,
    wbuf: Vec<u8>,
    wpos: usize,
    recv: Option<Crypto>,
    stage: ReadStage,
    rtmp: Vec<u8>,
    plain: Vec<u8>,
    ppos: usize,
}

impl<S> Ss2022Stream<S> {
    /// Оборачивает `inner` и СРАЗУ формирует заголовок запроса (соль + sealed
    /// fixed/variable) в `wbuf` — вызывающий должен сделать `flush`, чтобы сервер
    /// получил запрос (важно для server-speaks-first протоколов).
    ///
    /// `psk` — PSK (key_len байт), `addr` — закодированный SOCKS-адрес цели.
    pub fn new(inner: S, method: Method, psk: Vec<u8>, addr: Vec<u8>) -> io::Result<Self> {
        let mut salt = vec![0u8; method.salt_len()];
        getrandom::getrandom(&mut salt).map_err(|e| io::Error::other(format!("getrandom: {e}")))?;
        let subkey = session_subkey_2022(method, &psk, &salt);
        let mut send = Crypto::new(method, &subkey)?;

        // variable header: addr | padding_len(2)=0
        let mut variable = addr;
        variable.extend_from_slice(&[0u8, 0u8]);
        // fixed header: type(0) | timestamp(8) | length(2)
        let mut fixed = Vec::with_capacity(11);
        fixed.push(TYPE_REQUEST);
        fixed.extend_from_slice(&now_unix().to_be_bytes());
        fixed.extend_from_slice(&(variable.len() as u16).to_be_bytes());

        let mut wbuf = Vec::new();
        wbuf.extend_from_slice(&salt);
        wbuf.extend_from_slice(&send.seal(&fixed)?);
        wbuf.extend_from_slice(&send.seal(&variable)?);

        Ok(Self {
            inner,
            method,
            psk,
            client_salt: salt,
            send,
            wbuf,
            wpos: 0,
            recv: None,
            stage: ReadStage::ServerSalt,
            rtmp: Vec::new(),
            plain: Vec::new(),
            ppos: 0,
        })
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Ss2022Stream<S> {
    /// Дочитывает `rtmp` до `need` байт. `Ok(false)` — чистый EOF на границе.
    fn fill(&mut self, cx: &mut Context<'_>, need: usize) -> Poll<io::Result<bool>> {
        while self.rtmp.len() < need {
            let mut tmp = [0u8; 4096];
            let want = (need - self.rtmp.len()).min(tmp.len());
            let mut rb = ReadBuf::new(&mut tmp[..want]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled();
                    if filled.is_empty() {
                        if self.rtmp.is_empty() {
                            return Poll::Ready(Ok(false));
                        }
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                    }
                    self.rtmp.extend_from_slice(filled);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(true))
    }

    fn flush_wbuf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.wpos < self.wbuf.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.wbuf[self.wpos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)))
                }
                Poll::Ready(Ok(n)) => self.wpos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.wbuf.clear();
        self.wpos = 0;
        Poll::Ready(Ok(()))
    }

    /// Отдаёт `me.plain[ppos..]` в `out`, чистит буфер при исчерпании.
    fn deliver(&mut self, out: &mut ReadBuf<'_>) {
        let n = out.remaining().min(self.plain.len() - self.ppos);
        out.put_slice(&self.plain[self.ppos..self.ppos + n]);
        self.ppos += n;
        if self.ppos == self.plain.len() {
            self.plain.clear();
            self.ppos = 0;
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Ss2022Stream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        if me.ppos < me.plain.len() {
            me.deliver(out);
            return Poll::Ready(Ok(()));
        }

        loop {
            match me.stage {
                ReadStage::ServerSalt => {
                    match ready!(me.fill(cx, me.method.salt_len())) {
                        Ok(false) => return Poll::Ready(Ok(())), // EOF до ответа
                        Ok(true) => {}
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                    let salt = std::mem::take(&mut me.rtmp);
                    let subkey = session_subkey_2022(me.method, &me.psk, &salt);
                    me.recv = Some(match Crypto::new(me.method, &subkey) {
                        Ok(c) => c,
                        Err(e) => return Poll::Ready(Err(e)),
                    });
                    me.stage = ReadStage::RespHeader;
                }
                ReadStage::RespHeader => {
                    let hdr = 1 + 8 + me.method.salt_len() + 2;
                    match ready!(me.fill(cx, hdr + TAG)) {
                        Ok(false) => return Poll::Ready(Ok(())),
                        Ok(true) => {}
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                    let frame = std::mem::take(&mut me.rtmp);
                    let recv = me.recv.as_mut().expect("recv после соли");
                    let pt = match recv.open(&frame) {
                        Ok(p) => p,
                        Err(e) => return Poll::Ready(Err(e)),
                    };
                    // Защита: AEAD-open даёт ровно `hdr` байт, но проверяем явно.
                    if pt.len() != hdr {
                        return Poll::Ready(Err(io::Error::other("ss2022: размер заголовка")));
                    }
                    if pt[0] != TYPE_RESPONSE {
                        return Poll::Ready(Err(io::Error::other("ss2022: не ответ (type)")));
                    }
                    // Защита от replay: timestamp ответа в окне ±30с (SIP022).
                    let ts = u64::from_be_bytes(pt[1..9].try_into().unwrap());
                    if now_unix().abs_diff(ts) > 30 {
                        return Poll::Ready(Err(io::Error::other("ss2022: timestamp вне окна")));
                    }
                    let sl = me.method.salt_len();
                    let req_salt = &pt[9..9 + sl];
                    if req_salt != me.client_salt.as_slice() {
                        return Poll::Ready(Err(io::Error::other(
                            "ss2022: соль запроса в ответе не совпала",
                        )));
                    }
                    let len = ((pt[9 + sl] as usize) << 8) | pt[10 + sl] as usize;
                    me.stage = ReadStage::FirstPayload(len);
                }
                ReadStage::FirstPayload(len) => {
                    match ready!(me.fill(cx, len + TAG)) {
                        Ok(false) => {
                            return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)))
                        }
                        Ok(true) => {}
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                    let frame = std::mem::take(&mut me.rtmp);
                    let recv = me.recv.as_mut().expect("recv после соли");
                    me.plain = match recv.open(&frame) {
                        Ok(p) => p,
                        Err(e) => return Poll::Ready(Err(e)),
                    };
                    me.ppos = 0;
                    me.stage = ReadStage::Len;
                    if me.plain.is_empty() {
                        continue; // пустой первый payload → к стандартным чанкам
                    }
                    me.deliver(out);
                    return Poll::Ready(Ok(()));
                }
                ReadStage::Len => {
                    match ready!(me.fill(cx, 2 + TAG)) {
                        Ok(false) => return Poll::Ready(Ok(())),
                        Ok(true) => {}
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                    let frame = std::mem::take(&mut me.rtmp);
                    let recv = me.recv.as_mut().expect("recv после соли");
                    let pt = match recv.open(&frame) {
                        Ok(p) => p,
                        Err(e) => return Poll::Ready(Err(e)),
                    };
                    let len = ((pt[0] as usize) << 8) | pt[1] as usize;
                    if len == 0 || len > MAX_CHUNK {
                        return Poll::Ready(Err(io::Error::other("ss2022: неверная длина чанка")));
                    }
                    me.stage = ReadStage::Data(len);
                }
                ReadStage::Data(len) => {
                    match ready!(me.fill(cx, len + TAG)) {
                        Ok(false) => {
                            return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)))
                        }
                        Ok(true) => {}
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                    let frame = std::mem::take(&mut me.rtmp);
                    let recv = me.recv.as_mut().expect("recv после соли");
                    me.plain = match recv.open(&frame) {
                        Ok(p) => p,
                        Err(e) => return Poll::Ready(Err(e)),
                    };
                    me.ppos = 0;
                    me.stage = ReadStage::Len;
                    me.deliver(out);
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Ss2022Stream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();

        match ready!(me.flush_wbuf(cx)) {
            Ok(()) => {}
            Err(e) => return Poll::Ready(Err(e)),
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Заголовок запроса уже сформирован в new(); здесь — payload-чанки.
        let take = buf.len().min(MAX_CHUNK);
        let len_be = [(take >> 8) as u8, take as u8];
        match me.send.seal(&len_be) {
            Ok(ct) => me.wbuf.extend_from_slice(&ct),
            Err(e) => return Poll::Ready(Err(e)),
        }
        match me.send.seal(&buf[..take]) {
            Ok(ct) => me.wbuf.extend_from_slice(&ct),
            Err(e) => return Poll::Ready(Err(e)),
        }

        if let Poll::Ready(Err(e)) = me.flush_wbuf(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match ready!(me.flush_wbuf(cx)) {
            Ok(()) => {}
            Err(e) => return Poll::Ready(Err(e)),
        }
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match ready!(me.flush_wbuf(cx)) {
            Ok(()) => {}
            Err(e) => return Poll::Ready(Err(e)),
        }
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn ss_addr(host: &str, port: u16) -> Vec<u8> {
        let mut b = vec![0x03, host.len() as u8];
        b.extend_from_slice(host.as_bytes());
        b.extend_from_slice(&port.to_be_bytes());
        b
    }

    /// Mock SS-2022-сервер на одно соединение: разбирает заголовок запроса,
    /// читает один payload-чанк и эхо-ит его в заголовок/первый-payload ответа.
    async fn mock_server(mut sock: TcpStream, method: Method, psk: Vec<u8>) {
        let sl = method.salt_len();
        // соль клиента → подключ запроса.
        let mut salt = vec![0u8; sl];
        sock.read_exact(&mut salt).await.unwrap();
        let mut req = Crypto::new(method, &session_subkey_2022(method, &psk, &salt)).unwrap();

        // fixed (11) + variable (length).
        let mut fbuf = vec![0u8; 11 + TAG];
        sock.read_exact(&mut fbuf).await.unwrap();
        let fixed = req.open(&fbuf).unwrap();
        assert_eq!(fixed[0], TYPE_REQUEST);
        let vlen = ((fixed[9] as usize) << 8) | fixed[10] as usize;
        let mut vbuf = vec![0u8; vlen + TAG];
        sock.read_exact(&mut vbuf).await.unwrap();
        let _variable = req.open(&vbuf).unwrap(); // address + padding (не парсим)

        // один payload-чанк: len(2) + data.
        let mut lbuf = vec![0u8; 2 + TAG];
        sock.read_exact(&mut lbuf).await.unwrap();
        let lpt = req.open(&lbuf).unwrap();
        let dlen = ((lpt[0] as usize) << 8) | lpt[1] as usize;
        let mut dbuf = vec![0u8; dlen + TAG];
        sock.read_exact(&mut dbuf).await.unwrap();
        let data = req.open(&dbuf).unwrap();

        // Ответ: соль сервера + fixed(type=1 | ts | request_salt | length) + payload.
        let mut ssalt = vec![0u8; sl];
        getrandom::getrandom(&mut ssalt).unwrap();
        let mut resp = Crypto::new(method, &session_subkey_2022(method, &psk, &ssalt)).unwrap();
        let mut fixed_resp = vec![TYPE_RESPONSE];
        fixed_resp.extend_from_slice(&now_unix().to_be_bytes());
        fixed_resp.extend_from_slice(&salt); // request_salt = соль клиента
        fixed_resp.extend_from_slice(&(data.len() as u16).to_be_bytes());

        sock.write_all(&ssalt).await.unwrap();
        sock.write_all(&resp.seal(&fixed_resp).unwrap())
            .await
            .unwrap();
        sock.write_all(&resp.seal(&data).unwrap()).await.unwrap();
        sock.flush().await.unwrap();
    }

    #[test]
    fn subkey_2022_deterministic_and_sized() {
        let psk = vec![1u8; 32];
        let salt = vec![2u8; 32];
        let k = session_subkey_2022(Method::Ss2022Aes256Gcm, &psk, &salt);
        assert_eq!(k.len(), 32);
        assert_eq!(k, session_subkey_2022(Method::Ss2022Aes256Gcm, &psk, &salt));
        assert_eq!(
            session_subkey_2022(Method::Ss2022Aes128Gcm, &psk, &salt).len(),
            16
        );
        // разные соли → разные подключи.
        assert_ne!(
            k,
            session_subkey_2022(Method::Ss2022Aes256Gcm, &psk, &[3u8; 32])
        );
    }

    #[tokio::test]
    async fn ss2022_echo_roundtrip_all_methods() {
        for method in [
            Method::Ss2022Aes256Gcm,
            Method::Ss2022Aes128Gcm,
            Method::Ss2022Chacha20Poly1305,
        ] {
            let psk = vec![0x5Au8; method.key_len()];
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let psk_s = psk.clone();
            tokio::spawn(async move {
                let (sock, _) = listener.accept().await.unwrap();
                mock_server(sock, method, psk_s).await;
            });

            let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let mut stream =
                Ss2022Stream::new(tcp, method, psk, ss_addr("example.com", 443)).unwrap();
            stream.flush().await.unwrap();
            stream.write_all(b"hello ss2022").await.unwrap();

            let mut buf = vec![0u8; 12];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello ss2022", "method={method:?}");
        }
    }

    #[tokio::test]
    async fn ss2022_rejects_wrong_request_salt() {
        // Сервер кладёт в ответ НЕ ту request_salt → клиент должен отвергнуть.
        let method = Method::Ss2022Aes256Gcm;
        let psk = vec![7u8; 32];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let psk_s = psk.clone();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let sl = method.salt_len();
            let mut salt = vec![0u8; sl];
            sock.read_exact(&mut salt).await.unwrap();
            let mut req = Crypto::new(method, &session_subkey_2022(method, &psk_s, &salt)).unwrap();
            let mut fbuf = vec![0u8; 11 + TAG];
            sock.read_exact(&mut fbuf).await.unwrap();
            let fixed = req.open(&fbuf).unwrap();
            let vlen = ((fixed[9] as usize) << 8) | fixed[10] as usize;
            let mut vbuf = vec![0u8; vlen + TAG];
            sock.read_exact(&mut vbuf).await.unwrap();
            let _ = req.open(&vbuf).unwrap();

            let mut ssalt = vec![0u8; sl];
            getrandom::getrandom(&mut ssalt).unwrap();
            let mut resp =
                Crypto::new(method, &session_subkey_2022(method, &psk_s, &ssalt)).unwrap();
            let mut fixed_resp = vec![TYPE_RESPONSE];
            fixed_resp.extend_from_slice(&now_unix().to_be_bytes());
            let wrong_salt = vec![0xFFu8; sl]; // ЧУЖАЯ request_salt
            fixed_resp.extend_from_slice(&wrong_salt);
            fixed_resp.extend_from_slice(&0u16.to_be_bytes());
            sock.write_all(&ssalt).await.unwrap();
            sock.write_all(&resp.seal(&fixed_resp).unwrap())
                .await
                .unwrap();
            sock.flush().await.unwrap();
        });

        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut stream = Ss2022Stream::new(tcp, method, psk, ss_addr("h", 1)).unwrap();
        stream.flush().await.unwrap();
        stream.write_all(b"x").await.unwrap();
        let mut buf = [0u8; 1];
        assert!(
            stream.read_exact(&mut buf).await.is_err(),
            "чужая соль отвергается"
        );
    }
}
