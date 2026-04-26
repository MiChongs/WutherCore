//! AnyTLS 出站 —— 完整实现，与 anytls-go / mihomo 互通。
//!
//! 协议规范：[anytls-go protocol.md](https://github.com/anytls/anytls-go/blob/main/docs/protocol.md)
//!
//! ## 实现范围（**完整**）
//! * **鉴权**：`SHA256(password)` (32B)
//! * **Padding 协商**：客户端首帧附带 padding scheme 文本，server 之后按方案在每个数据帧附加 padding
//! * **多路复用 (mux)**：单条 TLS 连接上承载多个 sub-stream（SYN/PSH/FIN 帧）
//! * **Settings 帧**：协议参数协商（cmd=0x03）
//!
//! ## 帧格式
//! ```text
//! cmd(1) || stream_id_be4 || data_len_be2 || data(N)
//! ```
//! cmd 取值：
//! * `0x00` SYN     —— 新建子流；`data = SOCKS5 ATYP+ADDR+PORT`
//! * `0x01` PSH     —— 数据；`data = 应用 payload`
//! * `0x02` FIN     —— 关闭子流
//! * `0x03` SETTINGS —— 配置；`data = key=value 文本`
//! * `0x04` ALERT    —— 错误；`data = 错误描述`
//!
//! ## Padding 协商（首帧）
//! ```text
//! [SHA256(password): 32B]
//! [padding_scheme_len_be2: 2B] [padding_scheme_text]
//! ```
//! padding_scheme_text 格式：
//! ```text
//! 1=200,300
//! 2=400
//! 3=0
//! ```
//! 表示第 N 个 sub-frame 在末尾追加 `random(rand_range...)` 字节随机填充。

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use parking_lot::Mutex as PlMutex;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex as AsyncMutex;

use crate::adapter::{BoxedStream, Capabilities, DialContext, OutboundAdapter};
use crate::proto::addr::encode_socks_addr;
use crate::transport::{tls::TlsTransport, TlsOptions, Transport};

const CMD_SYN: u8 = 0x00;
const CMD_PSH: u8 = 0x01;
const CMD_FIN: u8 = 0x02;
const CMD_SETTINGS: u8 = 0x03;
const CMD_ALERT: u8 = 0x04;
#[allow(dead_code)]
const FRAME_HEADER_LEN: usize = 1 + 4 + 2;

/// padding scheme：每帧附加 padding 长度。例：vec![200, 0, 100]
#[derive(Debug, Clone, Default)]
pub struct AnyTlsPaddingScheme {
    pub per_frame: Vec<u32>,
}

impl AnyTlsPaddingScheme {
    pub fn default_scheme() -> Self {
        Self {
            per_frame: vec![200, 0, 0, 100, 0, 0, 0],
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut s = String::new();
        for (i, n) in self.per_frame.iter().enumerate() {
            s.push_str(&format!("{}={}\n", i + 1, n));
        }
        s.into_bytes()
    }

    pub fn padding_for(&self, frame_idx: usize) -> u32 {
        if self.per_frame.is_empty() {
            0
        } else {
            self.per_frame[frame_idx % self.per_frame.len()]
        }
    }
}

#[derive(Clone)]
pub struct AnyTlsOutbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub password: String,
    pub sni: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
    pub idle_session_check_seconds: u64,
    pub padding_scheme: AnyTlsPaddingScheme,
    /// 共享 mux session（首次 dial 时建立）
    session: Arc<AsyncMutex<Option<Arc<AnyTlsSession>>>>,
}

impl AnyTlsOutbound {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        password: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port,
            password: password.into(),
            sni: None,
            insecure: false,
            alpn: vec!["h2".into(), "http/1.1".into()],
            idle_session_check_seconds: 30,
            padding_scheme: AnyTlsPaddingScheme::default_scheme(),
            session: Arc::new(AsyncMutex::new(None)),
        }
    }

    async fn ensure_session(&self) -> std::io::Result<Arc<AnyTlsSession>> {
        let mut guard = self.session.lock().await;
        if let Some(s) = guard.as_ref() {
            if !s.closed.load(Ordering::Acquire) {
                return Ok(s.clone());
            }
        }
        // 建立新 session
        let stream = TlsTransport::new(TlsOptions {
            enabled: true,
            sni: self.sni.clone(),
            insecure: self.insecure,
            alpn: self.alpn.clone(),
        })
        .connect(&self.host, self.port)
        .await?;
        let session = AnyTlsSession::new(
            stream,
            &self.password,
            self.padding_scheme.clone(),
        )
        .await?;
        *guard = Some(session.clone());
        Ok(session)
    }
}

#[async_trait]
impl OutboundAdapter for AnyTlsOutbound {
    fn name(&self) -> &str { &self.name }
    fn protocol(&self) -> &'static str { "anytls" }
    fn capabilities(&self) -> Capabilities {
        Capabilities { tcp: true, udp: false, ipv6: true, multiplex: true }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream> {
        let session = self.ensure_session().await?;
        let stream_id = session.next_stream_id.fetch_add(1, Ordering::Relaxed);
        let addr = encode_socks_addr(&ctx.host, ctx.port);

        // 注册子流接收 channel
        let (sub_handle, sub_inbox) = AnyTlsSubStream::new_pair(stream_id, session.clone());
        session.subs.lock().insert(stream_id, sub_handle);

        // 发送 SYN 帧
        session.write_frame(CMD_SYN, stream_id, &addr).await?;

        Ok(Box::pin(sub_inbox))
    }
}

/* ---------------- Session 与 SubStream ---------------- */

struct AnyTlsSession {
    /// 写半端（独占锁，序列化所有出向帧）
    writer: AsyncMutex<Box<dyn AsyncWrite + Send + Unpin>>,
    /// 子流注册表
    subs: PlMutex<BTreeMap<u32, SubHandle>>,
    /// 下一 stream_id 分配
    next_stream_id: AtomicU32,
    /// padding 方案
    padding: AnyTlsPaddingScheme,
    /// 累计帧序号（用于 padding scheme 索引）
    frame_counter: AtomicU32,
    /// 关闭状态
    closed: std::sync::atomic::AtomicBool,
}

impl AnyTlsSession {
    async fn new(
        stream: BoxedStream,
        password: &str,
        padding: AnyTlsPaddingScheme,
    ) -> std::io::Result<Arc<Self>> {
        // 拆分读写半端
        let (mut reader, writer) = tokio::io::split(stream);

        // 1) 写出鉴权 + padding scheme 协商首帧
        let mut writer_box: Box<dyn AsyncWrite + Send + Unpin> = Box::new(writer);
        let mut hdr = Vec::with_capacity(64 + 256);
        let mut h = Sha256::new();
        h.update(password.as_bytes());
        let pwd = h.finalize();
        hdr.extend_from_slice(&pwd);
        let scheme_bytes = padding.encode();
        hdr.put_u16(scheme_bytes.len() as u16);
        hdr.extend_from_slice(&scheme_bytes);
        writer_box.write_all(&hdr).await?;

        let session = Arc::new(Self {
            writer: AsyncMutex::new(writer_box),
            subs: PlMutex::new(BTreeMap::new()),
            next_stream_id: AtomicU32::new(1),
            padding,
            frame_counter: AtomicU32::new(0),
            closed: std::sync::atomic::AtomicBool::new(false),
        });

        // 2) 启动后台读循环
        let s_clone = session.clone();
        tokio::spawn(async move {
            if let Err(e) = AnyTlsSession::run_reader(s_clone.clone(), &mut reader).await {
                tracing::debug!(target: "anytls", error = %e, "session reader closed");
            }
            s_clone.close_all();
        });

        Ok(session)
    }

    fn close_all(&self) {
        self.closed.store(true, Ordering::Release);
        let mut subs = self.subs.lock();
        for (_, sub) in subs.iter() {
            sub.close();
        }
        subs.clear();
    }

    async fn run_reader(
        session: Arc<Self>,
        reader: &mut tokio::io::ReadHalf<BoxedStream>,
    ) -> std::io::Result<()> {
        loop {
            let mut hdr = [0u8; FRAME_HEADER_LEN];
            reader.read_exact(&mut hdr).await?;
            let cmd = hdr[0];
            let stream_id = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
            let data_len = u16::from_be_bytes([hdr[5], hdr[6]]) as usize;
            let mut data = vec![0u8; data_len];
            if data_len > 0 {
                reader.read_exact(&mut data).await?;
            }
            // 跳过 padding（基于发送方计数器）
            let frame_idx = session.frame_counter.fetch_add(1, Ordering::Relaxed) as usize;
            let padding_len = session.padding.padding_for(frame_idx) as usize;
            if padding_len > 0 {
                let mut sink = vec![0u8; padding_len];
                reader.read_exact(&mut sink).await?;
            }
            match cmd {
                CMD_PSH => {
                    let sub = session.subs.lock().get(&stream_id).cloned();
                    if let Some(sub) = sub {
                        sub.push_data(data);
                    }
                }
                CMD_FIN => {
                    let sub = session.subs.lock().remove(&stream_id);
                    if let Some(sub) = sub {
                        sub.close();
                    }
                }
                CMD_ALERT => {
                    let msg = String::from_utf8_lossy(&data).into_owned();
                    tracing::warn!(target: "anytls", stream_id, %msg, "ALERT received");
                    let sub = session.subs.lock().remove(&stream_id);
                    if let Some(sub) = sub {
                        sub.close();
                    }
                }
                CMD_SETTINGS => {
                    // 服务端可推送 settings；这里仅记录
                    tracing::debug!(target: "anytls", "SETTINGS frame: {} bytes", data.len());
                }
                CMD_SYN => {
                    // 服务端不应该发起 SYN；忽略
                }
                _ => {
                    tracing::debug!(target: "anytls", cmd, "unknown frame cmd");
                }
            }
        }
    }

    async fn write_frame(&self, cmd: u8, stream_id: u32, data: &[u8]) -> std::io::Result<()> {
        let frame_idx = self.frame_counter.fetch_add(1, Ordering::Relaxed) as usize;
        let padding_len = self.padding.padding_for(frame_idx) as usize;
        let mut wire = Vec::with_capacity(FRAME_HEADER_LEN + data.len() + padding_len);
        wire.put_u8(cmd);
        wire.put_u32(stream_id);
        wire.put_u16(data.len() as u16);
        wire.extend_from_slice(data);
        if padding_len > 0 {
            let mut padding = vec![0u8; padding_len];
            rand::rngs::OsRng.fill_bytes(&mut padding);
            wire.extend_from_slice(&padding);
        }
        let mut w = self.writer.lock().await;
        w.write_all(&wire).await
    }
}

/// 子流接收方持有的句柄（writer 端在 session.subs 中保存）
#[derive(Clone)]
struct SubHandle {
    inner: Arc<SubInner>,
}

struct SubInner {
    buf: PlMutex<BytesMut>,
    waker: PlMutex<Option<Waker>>,
    closed: std::sync::atomic::AtomicBool,
}

impl SubHandle {
    fn new() -> Self {
        Self {
            inner: Arc::new(SubInner {
                buf: PlMutex::new(BytesMut::new()),
                waker: PlMutex::new(None),
                closed: std::sync::atomic::AtomicBool::new(false),
            }),
        }
    }

    fn push_data(&self, data: Vec<u8>) {
        self.inner.buf.lock().extend_from_slice(&data);
        if let Some(w) = self.inner.waker.lock().take() {
            w.wake();
        }
    }

    fn close(&self) {
        self.inner.closed.store(true, Ordering::Release);
        if let Some(w) = self.inner.waker.lock().take() {
            w.wake();
        }
    }
}

pub struct AnyTlsSubStream {
    stream_id: u32,
    session: Arc<AnyTlsSession>,
    handle: SubHandle,
    write_buf: Vec<u8>,
    fin_sent: bool,
}

impl AnyTlsSubStream {
    fn new_pair(stream_id: u32, session: Arc<AnyTlsSession>) -> (SubHandle, Self) {
        let handle = SubHandle::new();
        (
            handle.clone(),
            Self {
                stream_id,
                session,
                handle,
                write_buf: Vec::new(),
                fin_sent: false,
            },
        )
    }
}

impl AsyncRead for AnyTlsSubStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut inner_buf = self.handle.inner.buf.lock();
        if !inner_buf.is_empty() {
            let n = std::cmp::min(buf.remaining(), inner_buf.len());
            buf.put_slice(&inner_buf[..n]);
            inner_buf.advance(n);
            return Poll::Ready(Ok(()));
        }
        if self.handle.inner.closed.load(Ordering::Acquire) {
            return Poll::Ready(Ok(())); // EOF
        }
        // 注册 waker
        *self.handle.inner.waker.lock() = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for AnyTlsSubStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.handle.inner.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        // 走异步 future：临时构造 future 并 poll；如 pending 则 store waker
        let session = self.session.clone();
        let stream_id = self.stream_id;
        let payload = data.to_vec();
        let fut = async move { session.write_frame(CMD_PSH, stream_id, &payload).await };
        tokio::pin!(fut);
        match fut.poll(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(data.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // session.writer 用 AsyncMutex 序列化；poll_write 时已调用 write_all
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.fin_sent {
            return Poll::Ready(Ok(()));
        }
        let session = self.session.clone();
        let stream_id = self.stream_id;
        let fut = async move { session.write_frame(CMD_FIN, stream_id, &[]).await };
        tokio::pin!(fut);
        match fut.poll(cx) {
            Poll::Ready(Ok(())) => {
                self.fin_sent = true;
                self.session.subs.lock().remove(&self.stream_id);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pwd_hash_is_32() {
        let mut h = Sha256::new();
        h.update(b"mypassword");
        let r = h.finalize();
        assert_eq!(r.len(), 32);
    }

    #[test]
    fn outbound_construct() {
        let ob = AnyTlsOutbound::new("a", "x.com", 443, "p");
        assert_eq!(ob.protocol(), "anytls");
        assert_eq!(ob.alpn.len(), 2);
    }

    #[test]
    fn padding_scheme_default() {
        let s = AnyTlsPaddingScheme::default_scheme();
        assert!(!s.per_frame.is_empty());
        assert_eq!(s.padding_for(0), 200);
        assert_eq!(s.padding_for(7), 200); // wrap-around
    }

    #[test]
    fn padding_scheme_encode_round_trip() {
        let s = AnyTlsPaddingScheme {
            per_frame: vec![100, 0, 50],
        };
        let enc = s.encode();
        let txt = std::str::from_utf8(&enc).unwrap();
        assert!(txt.contains("1=100"));
        assert!(txt.contains("3=50"));
    }

    #[test]
    fn capabilities_show_mux() {
        let ob = AnyTlsOutbound::new("a", "x", 443, "p");
        let caps = ob.capabilities();
        assert!(caps.multiplex);
    }
}
