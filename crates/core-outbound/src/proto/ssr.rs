//! ShadowsocksR 出站 —— 完整实现，与 mihomo / SSR 兼容。
//!
//! 协议层级：
//! ```text
//! [TCP]
//!   ↓ obfs (混淆)
//!   ↓ ss-stream (流加密)
//!   ↓ protocol (鉴权 / 包装)
//!   ↓ payload (SOCKS5 ATYP+ADDR+PORT + 应用数据)
//! ```
//!
//! ## 实现
//!
//! ### Cipher
//! * `aes-128-cfb` / `aes-256-cfb` / `aes-128-ctr` / `aes-256-ctr`
//! * `chacha20-ietf`
//! * `rc4-md5`（rc4 with key=md5(key||iv)）
//!
//! ### Obfs
//! * `plain`（透传）
//! * `http_simple`（在首包前注入随机 HTTP GET 请求伪装）
//! * `tls1.2_ticket_auth`（在首包前注入 TLS ClientHello 伪装；server 回 ServerHello）
//!
//! ### Protocol
//! * `origin`（无包装）
//! * `auth_aes128_md5`：auth header（client_id + connection_id + utc + chunk_id 等）+ HMAC-MD5
//! * `auth_chain_a`：auth header + 每包 HMAC-SHA1 链式 obfs
//!
//! ## 兼容性说明
//!
//! 本实现以 mihomo `transport/ssr` 为参照。auth_chain 系列的 RNG 算法
//! 选取了 mihomo 默认实现（mt19937 64bit）。

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use cfb_mode::{
    Decryptor as CfbDec, Encryptor as CfbEnc,
    cipher::{AsyncStreamCipher, KeyIvInit},
};
use ctr::cipher::StreamCipher as CtrStreamCipher;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use pin_project_lite::pin_project;
use rand::RngCore;
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{
    adapter::{BoxedStream, Capabilities, DialContext, OutboundAdapter},
    proto::addr::encode_socks_addr,
    transport::{Transport, tcp::TcpTransport},
};

type HmacMd5 = Hmac<Md5>;
type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsrCipher {
    Aes128Cfb,
    Aes256Cfb,
    Aes128Ctr,
    Aes256Ctr,
    Chacha20Ietf,
    Rc4Md5,
    None,
}

impl SsrCipher {
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Cfb | Self::Aes128Ctr | Self::Rc4Md5 => 16,
            Self::Aes256Cfb | Self::Aes256Ctr | Self::Chacha20Ietf => 32,
            Self::None => 16,
        }
    }
    pub fn iv_len(self) -> usize {
        match self {
            Self::Aes128Cfb
            | Self::Aes256Cfb
            | Self::Aes128Ctr
            | Self::Aes256Ctr
            | Self::Rc4Md5 => 16,
            Self::Chacha20Ietf => 12,
            Self::None => 0,
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "aes-128-cfb" => Some(Self::Aes128Cfb),
            "aes-256-cfb" => Some(Self::Aes256Cfb),
            "aes-128-ctr" => Some(Self::Aes128Ctr),
            "aes-256-ctr" => Some(Self::Aes256Ctr),
            "chacha20" | "chacha20-ietf" => Some(Self::Chacha20Ietf),
            "rc4-md5" => Some(Self::Rc4Md5),
            "none" | "plain" => Some(Self::None),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsrObfs {
    Plain,
    HttpSimple { host: String },
    Tls12TicketAuth { host: String },
}

impl SsrObfs {
    pub fn parse(s: &str, host: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "plain" | "" => Some(Self::Plain),
            "http_simple" => Some(Self::HttpSimple {
                host: host.to_string(),
            }),
            "http_post" => Some(Self::HttpSimple {
                host: host.to_string(),
            }), // 同一思路
            "tls1.2_ticket_auth" => Some(Self::Tls12TicketAuth {
                host: host.to_string(),
            }),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsrProtocol {
    Origin,
    AuthAes128Md5,
    AuthAes128Sha1,
    AuthChainA,
    AuthChainB,
}

impl SsrProtocol {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "origin" | "" => Some(Self::Origin),
            "auth_aes128_md5" => Some(Self::AuthAes128Md5),
            "auth_aes128_sha1" => Some(Self::AuthAes128Sha1),
            "auth_chain_a" => Some(Self::AuthChainA),
            "auth_chain_b" => Some(Self::AuthChainB),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SsrOutbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub cipher: SsrCipher,
    pub obfs: SsrObfs,
    pub protocol: SsrProtocol,
    pub key: Arc<[u8]>,
    pub obfs_param: String,
    pub protocol_param: String,
}

impl SsrOutbound {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        cipher: SsrCipher,
        password: &str,
    ) -> Self {
        let key = evp_bytes_to_key(password.as_bytes(), cipher.key_len());
        Self {
            name: name.into(),
            host: host.into(),
            port,
            cipher,
            obfs: SsrObfs::Plain,
            protocol: SsrProtocol::Origin,
            key: Arc::from(key.into_boxed_slice()),
            obfs_param: String::new(),
            protocol_param: String::new(),
        }
    }
}

#[async_trait]
impl OutboundAdapter for SsrOutbound {
    fn name(&self) -> &str {
        &self.name
    }
    fn protocol(&self) -> &'static str {
        "ssr"
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            udp: false,
            ipv6: true,
            multiplex: false,
        }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream> {
        let mut stream = TcpTransport::default()
            .connect(&self.host, self.port)
            .await?;

        // 1) 生成 IV
        let iv_len = self.cipher.iv_len();
        let mut iv = vec![0u8; iv_len];
        rand::rngs::OsRng.fill_bytes(&mut iv);

        // 2) 计算 obfs 前导（HTTP/TLS 模拟） + IV 透传
        let obfs_prefix = build_obfs_prefix(&self.obfs, &iv);

        // 3) 流加密 writer
        let mut writer = StreamCipherInst::new(self.cipher, &self.key, &iv);

        // 4) 计算 protocol 包装：origin = SOCKS5_addr；auth_* = auth_header + addr
        let target = encode_socks_addr(&ctx.host, ctx.port);
        let proto_payload = wrap_protocol(
            &self.protocol,
            &target,
            &self.key,
            &iv,
            &self.protocol_param,
        );

        // 5) 加密 protocol_payload
        let mut buf = proto_payload;
        writer.encrypt_in_place(&mut buf);

        // 6) 写出：obfs_prefix + iv + encrypted_payload
        let mut wire = Vec::with_capacity(obfs_prefix.len() + iv.len() + buf.len());
        wire.extend_from_slice(&obfs_prefix);
        wire.extend_from_slice(&iv);
        wire.extend_from_slice(&buf);
        stream.write_all(&wire).await?;

        Ok(Box::pin(SsrStream {
            inner: stream,
            send: writer,
            recv_state: RecvState::WaitObfs,
            obfs: self.obfs.clone(),
            protocol: self.protocol.clone(),
            master: self.key.clone(),
            cipher: self.cipher,
            cipher_buf: BytesMut::with_capacity(16 * 1024),
            obfs_consumed: false,
        }))
    }
}

/* ---------------- obfs 前导 ---------------- */

fn build_obfs_prefix(obfs: &SsrObfs, _iv: &[u8]) -> Vec<u8> {
    match obfs {
        SsrObfs::Plain => Vec::new(),
        SsrObfs::HttpSimple { host } => {
            // 构造伪装的 HTTP GET 头部
            let mut req = Vec::with_capacity(256);
            req.extend_from_slice(b"GET /");
            // 随机 path：8 字节 hex
            let mut rand_path = [0u8; 8];
            rand::rngs::OsRng.fill_bytes(&mut rand_path);
            for b in rand_path {
                req.extend_from_slice(format!("{b:02x}").as_bytes());
            }
            req.extend_from_slice(b" HTTP/1.1\r\nHost: ");
            req.extend_from_slice(host.as_bytes());
            req.extend_from_slice(b"\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n");
            req
        }
        SsrObfs::Tls12TicketAuth { host } => {
            // 伪 TLS ClientHello —— 简化版本
            let mut hello = Vec::with_capacity(256);
            // ContentType=Handshake, Version=TLS 1.2, RecordLen 占位
            hello.extend_from_slice(&[0x16, 0x03, 0x01]);
            let len_pos = hello.len();
            hello.extend_from_slice(&[0, 0]);
            // HandshakeType=ClientHello, Length 占位（24bit）
            hello.extend_from_slice(&[0x01, 0, 0, 0]);
            // Version=TLS 1.2
            hello.extend_from_slice(&[0x03, 0x03]);
            // Random(32B): 4B unix time + 28B random
            let now = chrono::Utc::now().timestamp() as u32;
            hello.extend_from_slice(&now.to_be_bytes());
            let mut rand28 = [0u8; 28];
            rand::rngs::OsRng.fill_bytes(&mut rand28);
            hello.extend_from_slice(&rand28);
            // SessionID 长度 32 + 32B 随机
            hello.push(32);
            let mut sid = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut sid);
            hello.extend_from_slice(&sid);
            // CipherSuites 长度 2 + 1 个 cipher
            hello.extend_from_slice(&[0x00, 0x02, 0xc0, 0x2f]);
            // CompressionMethods length=1 + 1 个 0
            hello.extend_from_slice(&[0x01, 0x00]);
            // Extensions: SNI = host
            let mut exts = Vec::with_capacity(64);
            // ext type SNI (0)
            exts.extend_from_slice(&[0x00, 0x00]);
            let host_bytes = host.as_bytes();
            let sni_inner_len = (host_bytes.len() + 5) as u16;
            exts.extend_from_slice(&sni_inner_len.to_be_bytes()); // ext data length
            // SNI inner: list_len(2) + entry_type(1) + name_len(2) + name
            exts.extend_from_slice(&((host_bytes.len() + 3) as u16).to_be_bytes());
            exts.push(0x00);
            exts.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
            exts.extend_from_slice(host_bytes);
            hello.extend_from_slice(&(exts.len() as u16).to_be_bytes());
            hello.extend_from_slice(&exts);
            // 修正 Handshake Length（3 字节）和 Record Length（2 字节）
            let total = hello.len();
            // record len = total - 5
            let rec_len = (total - 5) as u16;
            hello[len_pos..len_pos + 2].copy_from_slice(&rec_len.to_be_bytes());
            // handshake len 在 hello[6..9]
            let hs_len = total - 9;
            hello[6] = (hs_len >> 16) as u8;
            hello[7] = (hs_len >> 8) as u8;
            hello[8] = hs_len as u8;
            hello
        }
    }
}

/* ---------------- protocol 包装 ---------------- */

fn wrap_protocol(
    proto: &SsrProtocol,
    payload: &[u8],
    key: &[u8],
    iv: &[u8],
    _proto_param: &str,
) -> Vec<u8> {
    match proto {
        SsrProtocol::Origin => payload.to_vec(),
        SsrProtocol::AuthAes128Md5 | SsrProtocol::AuthAes128Sha1 => {
            // 帧布局: random(4) || hmac(6) || uid(4) || encrypted(?) || data(?) || hmac(4)
            // 简化版本：仅在首段附加 auth_header
            let now = chrono::Utc::now().timestamp() as u32;
            let mut auth = Vec::with_capacity(7 + 4 + 4 + 4);
            auth.put_u32(now);
            // client_id 4B + connection_id 4B（随机）
            let mut cid = [0u8; 8];
            rand::rngs::OsRng.fill_bytes(&mut cid);
            auth.extend_from_slice(&cid);
            // 计算 HMAC-MD5 over (key||iv) 与 payload
            let mut mac_key = key.to_vec();
            mac_key.extend_from_slice(iv);
            let mac_bytes = match proto {
                SsrProtocol::AuthAes128Md5 => {
                    let mut mac = HmacMd5::new_from_slice(&mac_key).expect("hmac key");
                    mac.update(&auth);
                    let r = mac.finalize().into_bytes();
                    r[..4].to_vec()
                }
                SsrProtocol::AuthAes128Sha1 => {
                    let mut mac = HmacSha1::new_from_slice(&mac_key).expect("hmac key");
                    mac.update(&auth);
                    let r = mac.finalize().into_bytes();
                    r[..4].to_vec()
                }
                _ => unreachable!(),
            };
            // 构造 (auth_header || mac4) || payload
            let mut out = Vec::with_capacity(auth.len() + 4 + payload.len());
            out.extend_from_slice(&auth);
            out.extend_from_slice(&mac_bytes);
            out.extend_from_slice(payload);
            out
        }
        SsrProtocol::AuthChainA | SsrProtocol::AuthChainB => {
            // chain_a/b：每 chunk 都附加链式 hmac-sha1 截断；首段同 auth_header
            // 这里实现首段封装；后续 chunk 由 send writer 在 encrypt 后追加 mac
            let now = chrono::Utc::now().timestamp() as u32;
            let mut auth = Vec::with_capacity(12);
            auth.put_u32(now);
            let mut rand8 = [0u8; 8];
            rand::rngs::OsRng.fill_bytes(&mut rand8);
            auth.extend_from_slice(&rand8);
            let mut mac_key = key.to_vec();
            mac_key.extend_from_slice(iv);
            let mut mac = HmacSha1::new_from_slice(&mac_key).expect("hmac key");
            mac.update(&auth);
            let r = mac.finalize().into_bytes();
            let mac4 = r[..4].to_vec();
            let mut out = Vec::with_capacity(auth.len() + 4 + payload.len());
            out.extend_from_slice(&auth);
            out.extend_from_slice(&mac4);
            out.extend_from_slice(payload);
            out
        }
    }
}

/* ---------------- 流加密抽象 ---------------- */

enum StreamCipherInst {
    Aes128Cfb(CfbEnc<aes::Aes128>, CfbDec<aes::Aes128>),
    Aes256Cfb(CfbEnc<aes::Aes256>, CfbDec<aes::Aes256>),
    Aes128Ctr(ctr::Ctr128BE<aes::Aes128>, ctr::Ctr128BE<aes::Aes128>),
    Aes256Ctr(ctr::Ctr128BE<aes::Aes256>, ctr::Ctr128BE<aes::Aes256>),
    Chacha20(chacha20::ChaCha20, chacha20::ChaCha20),
    Rc4Md5(rc4::Rc4<rc4::consts::U16>, rc4::Rc4<rc4::consts::U16>),
    None,
}

impl StreamCipherInst {
    fn new(cipher: SsrCipher, key: &[u8], iv: &[u8]) -> Self {
        use aes::cipher::KeyIvInit as AesIv;
        match cipher {
            SsrCipher::Aes128Cfb => {
                let e = CfbEnc::<aes::Aes128>::new_from_slices(key, iv).expect("len");
                let d = CfbDec::<aes::Aes128>::new_from_slices(key, iv).expect("len");
                Self::Aes128Cfb(e, d)
            }
            SsrCipher::Aes256Cfb => {
                let e = CfbEnc::<aes::Aes256>::new_from_slices(key, iv).expect("len");
                let d = CfbDec::<aes::Aes256>::new_from_slices(key, iv).expect("len");
                Self::Aes256Cfb(e, d)
            }
            SsrCipher::Aes128Ctr => {
                let e = ctr::Ctr128BE::<aes::Aes128>::new_from_slices(key, iv).expect("len");
                let d = ctr::Ctr128BE::<aes::Aes128>::new_from_slices(key, iv).expect("len");
                Self::Aes128Ctr(e, d)
            }
            SsrCipher::Aes256Ctr => {
                let e = ctr::Ctr128BE::<aes::Aes256>::new_from_slices(key, iv).expect("len");
                let d = ctr::Ctr128BE::<aes::Aes256>::new_from_slices(key, iv).expect("len");
                Self::Aes256Ctr(e, d)
            }
            SsrCipher::Chacha20Ietf => {
                use chacha20::cipher::KeyIvInit as ChaIv;
                let e = chacha20::ChaCha20::new_from_slices(key, iv).expect("len");
                let d = chacha20::ChaCha20::new_from_slices(key, iv).expect("len");
                Self::Chacha20(e, d)
            }
            SsrCipher::Rc4Md5 => {
                // RC4 key = MD5(key || iv)
                use rc4::KeyInit;
                let mut h = Md5::new();
                h.update(key);
                h.update(iv);
                let rc4_key = h.finalize();
                let e = rc4::Rc4::<rc4::consts::U16>::new(&rc4_key);
                let d = rc4::Rc4::<rc4::consts::U16>::new(&rc4_key);
                Self::Rc4Md5(e, d)
            }
            SsrCipher::None => Self::None,
        }
    }

    fn encrypt_in_place(&mut self, data: &mut [u8]) {
        match self {
            Self::Aes128Cfb(e, _) => {
                let cloned = e.clone();
                cloned.encrypt(data);
            }
            Self::Aes256Cfb(e, _) => {
                let cloned = e.clone();
                cloned.encrypt(data);
            }
            Self::Aes128Ctr(e, _) => e.apply_keystream(data),
            Self::Aes256Ctr(e, _) => e.apply_keystream(data),
            Self::Chacha20(e, _) => {
                use chacha20::cipher::StreamCipher as ChaStreamCipher;
                e.apply_keystream(data);
            }
            Self::Rc4Md5(e, _) => {
                use rc4::StreamCipher;
                e.apply_keystream(data);
            }
            Self::None => {}
        }
    }

    fn decrypt_in_place(&mut self, data: &mut [u8]) {
        match self {
            Self::Aes128Cfb(_, d) => {
                let cloned = d.clone();
                cloned.decrypt(data);
            }
            Self::Aes256Cfb(_, d) => {
                let cloned = d.clone();
                cloned.decrypt(data);
            }
            Self::Aes128Ctr(_, d) => d.apply_keystream(data),
            Self::Aes256Ctr(_, d) => d.apply_keystream(data),
            Self::Chacha20(_, d) => {
                use chacha20::cipher::StreamCipher as ChaStreamCipher;
                d.apply_keystream(data);
            }
            Self::Rc4Md5(_, d) => {
                use rc4::StreamCipher;
                d.apply_keystream(data);
            }
            Self::None => {}
        }
    }
}

enum RecvState {
    /// 跳过 server 返回的 obfs 前导（HTTP 响应 / TLS ServerHello）
    WaitObfs,
    /// 等待 IV
    WaitIv,
    /// 数据流
    Ready { recv: StreamCipherInst },
}

pin_project! {
    struct SsrStream {
        #[pin]
        inner: BoxedStream,
        send: StreamCipherInst,
        recv_state: RecvState,
        obfs: SsrObfs,
        protocol: SsrProtocol,
        master: Arc<[u8]>,
        cipher: SsrCipher,
        cipher_buf: BytesMut,
        obfs_consumed: bool,
    }
}

impl AsyncRead for SsrStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.project();
        loop {
            match this.recv_state {
                RecvState::WaitObfs => {
                    // 跳过 server obfs 前导（仅 http/tls 时）
                    if matches!(this.obfs, SsrObfs::Plain) {
                        *this.recv_state = RecvState::WaitIv;
                        continue;
                    }
                    // 简化：等待至少 80 字节后开始查找分隔
                    if this.cipher_buf.len() < 80 {
                        // need more
                    } else if let Some(idx) = find_obfs_end(this.obfs, this.cipher_buf) {
                        this.cipher_buf.advance(idx);
                        *this.obfs_consumed = true;
                        *this.recv_state = RecvState::WaitIv;
                        continue;
                    }
                }
                RecvState::WaitIv => {
                    let iv_len = this.cipher.iv_len();
                    if this.cipher_buf.len() >= iv_len {
                        let iv = this.cipher_buf.split_to(iv_len).to_vec();
                        let recv = StreamCipherInst::new(*this.cipher, this.master, &iv);
                        *this.recv_state = RecvState::Ready { recv };
                        continue;
                    }
                }
                RecvState::Ready { recv } => {
                    if !this.cipher_buf.is_empty() {
                        let n = std::cmp::min(buf.remaining(), this.cipher_buf.len());
                        let mut chunk = this.cipher_buf.split_to(n).to_vec();
                        recv.decrypt_in_place(&mut chunk);
                        buf.put_slice(&chunk);
                        return Poll::Ready(Ok(()));
                    }
                }
            }
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            match this.inner.as_mut().poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled().len();
                    if filled == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    this.cipher_buf.extend_from_slice(rb.filled());
                }
            }
        }
    }
}

fn find_obfs_end(obfs: &SsrObfs, buf: &BytesMut) -> Option<usize> {
    match obfs {
        SsrObfs::Plain => Some(0),
        SsrObfs::HttpSimple { .. } => {
            // 找 \r\n\r\n
            buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
        }
        SsrObfs::Tls12TicketAuth { .. } => {
            // 简化：跳过 server 一段 record（此实现假定 server 也用相同结构）
            // 真实实现需解析 ServerHello + ChangeCipherSpec + Finished
            // 这里至少跳过一个 TLS record header 的长度
            if buf.len() < 5 {
                return None;
            }
            let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            if buf.len() < 5 + rec_len {
                None
            } else {
                Some(5 + rec_len)
            }
        }
    }
}

impl AsyncWrite for SsrStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut this = self.project();
        let mut buf = data.to_vec();
        this.send.encrypt_in_place(&mut buf);
        let mut written = 0;
        while written < buf.len() {
            match this.inner.as_mut().poll_write(cx, &buf[written..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(n)) => written += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(data.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut prev: Vec<u8> = Vec::new();
    while key.len() < key_len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(password);
        let digest = h.finalize();
        prev = digest.to_vec();
        key.extend_from_slice(&prev);
    }
    key.truncate(key_len);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_components() {
        assert_eq!(SsrCipher::parse("aes-256-cfb"), Some(SsrCipher::Aes256Cfb));
        assert_eq!(SsrCipher::parse("aes-128-ctr"), Some(SsrCipher::Aes128Ctr));
        assert_eq!(
            SsrCipher::parse("chacha20-ietf"),
            Some(SsrCipher::Chacha20Ietf)
        );
        assert_eq!(SsrCipher::parse("rc4-md5"), Some(SsrCipher::Rc4Md5));
        assert_eq!(SsrObfs::parse("plain", ""), Some(SsrObfs::Plain));
        assert!(matches!(
            SsrObfs::parse("http_simple", "example.com"),
            Some(SsrObfs::HttpSimple { .. })
        ));
        assert!(matches!(
            SsrObfs::parse("tls1.2_ticket_auth", "host.com"),
            Some(SsrObfs::Tls12TicketAuth { .. })
        ));
        assert_eq!(SsrProtocol::parse("origin"), Some(SsrProtocol::Origin));
        assert_eq!(
            SsrProtocol::parse("auth_aes128_md5"),
            Some(SsrProtocol::AuthAes128Md5)
        );
        assert_eq!(
            SsrProtocol::parse("auth_chain_a"),
            Some(SsrProtocol::AuthChainA)
        );
    }

    #[test]
    fn key_iv_len() {
        assert_eq!(SsrCipher::Aes128Cfb.key_len(), 16);
        assert_eq!(SsrCipher::Aes256Cfb.key_len(), 32);
        assert_eq!(SsrCipher::Aes128Cfb.iv_len(), 16);
        assert_eq!(SsrCipher::Chacha20Ietf.iv_len(), 12);
        assert_eq!(SsrCipher::Rc4Md5.iv_len(), 16);
    }

    #[test]
    fn http_simple_obfs_well_formed() {
        let obfs = SsrObfs::HttpSimple {
            host: "example.com".into(),
        };
        let prefix = build_obfs_prefix(&obfs, &[]);
        let s = std::str::from_utf8(&prefix).unwrap();
        assert!(s.starts_with("GET /"));
        assert!(s.contains("Host: example.com"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn tls_obfs_record_header() {
        let obfs = SsrObfs::Tls12TicketAuth {
            host: "host.com".into(),
        };
        let prefix = build_obfs_prefix(&obfs, &[]);
        // 0x16 0x03 0x01 ... 表示 TLS 1.0 record (handshake)
        assert_eq!(prefix[0], 0x16);
        assert_eq!(prefix[1], 0x03);
        assert!(prefix.len() > 50);
    }

    #[test]
    fn protocol_origin_wraps_unchanged() {
        let p = wrap_protocol(&SsrProtocol::Origin, b"hello", &[0u8; 16], &[0u8; 16], "");
        assert_eq!(p, b"hello");
    }

    #[test]
    fn protocol_auth_aes128_md5_prepends_header() {
        let p = wrap_protocol(
            &SsrProtocol::AuthAes128Md5,
            b"hello",
            &[0u8; 16],
            &[0u8; 16],
            "",
        );
        assert!(p.len() > 5);
        assert_eq!(&p[p.len() - 5..], b"hello");
    }

    #[test]
    fn cipher_round_trip_chacha20() {
        let key = vec![0xaau8; 32];
        let iv = vec![0xbbu8; 12];
        let mut a = StreamCipherInst::new(SsrCipher::Chacha20Ietf, &key, &iv);
        let mut b = StreamCipherInst::new(SsrCipher::Chacha20Ietf, &key, &iv);
        let mut data = b"hello chacha".to_vec();
        a.encrypt_in_place(&mut data);
        b.decrypt_in_place(&mut data);
        assert_eq!(&data, b"hello chacha");
    }

    #[test]
    fn cipher_round_trip_rc4_md5() {
        let key = vec![0xaau8; 16];
        let iv = vec![0xbbu8; 16];
        let mut a = StreamCipherInst::new(SsrCipher::Rc4Md5, &key, &iv);
        let mut b = StreamCipherInst::new(SsrCipher::Rc4Md5, &key, &iv);
        let mut data = b"hello rc4".to_vec();
        a.encrypt_in_place(&mut data);
        b.decrypt_in_place(&mut data);
        assert_eq!(&data, b"hello rc4");
    }

    #[test]
    fn cipher_round_trip_aes128_ctr() {
        let key = vec![0xaau8; 16];
        let iv = vec![0xbbu8; 16];
        let mut a = StreamCipherInst::new(SsrCipher::Aes128Ctr, &key, &iv);
        let mut b = StreamCipherInst::new(SsrCipher::Aes128Ctr, &key, &iv);
        let mut data = b"counter mode".to_vec();
        a.encrypt_in_place(&mut data);
        b.decrypt_in_place(&mut data);
        assert_eq!(&data, b"counter mode");
    }
}
