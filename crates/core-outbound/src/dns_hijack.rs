//! DNS Hijack 出站 —— mihomo `proxies: - {name: DNS_Hijack, type: dns}` 等价。
//!
//! 不真正 dial 远端：把客户端发来的 DNS 报文喂给本机的 [`DnsResponder`]，
//! 把响应原路返回。常配合规则：`DST-PORT,53 → DNS_Hijack` 把 LAN 客户端的
//! DNS 流量截到 WutherCore resolver 上（fake-ip / 缓存 / nameserver-policy 全
//! 部生效）。
//!
//! ### 与 mihomo 行为对齐
//!
//! - **UDP**：每个数据包是一条完整 DNS 消息；调 [`DnsResponder::serve_packet`]，
//!   把响应作为下一次 `recv_from` 的返回；mihomo `dns.go::ListenPacketContext` 等价。
//! - **TCP**：DNS over TCP 用 2 字节大端长度前缀；循环 read-len → read-msg →
//!   serve → write-len → write-msg；mihomo `relay.go::RelayDnsConn` 等价。
//! - **无远端连接**：`dial_id` 仅用于日志；不打 SO_MARK，不走 TUN bypass，
//!   不创建出站 socket。

use std::{
    collections::VecDeque,
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
};

use async_trait::async_trait;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Mutex, Notify, mpsc},
};
use tracing::debug;

use crate::adapter::{
    BoxedStream, BoxedUdp, Capabilities, DialContext, OutboundAdapter, UdpSocketLike,
};

/// 处理 DNS 报文的本机服务 —— 由 core-resolver 的 `DnsService` 实现。
///
/// 抽出 trait 是为了避免 core-outbound → core-resolver 反向依赖。
#[async_trait]
pub trait DnsResponder: Send + Sync + std::fmt::Debug {
    /// 输入完整 DNS 请求字节，返回完整 DNS 响应字节。
    /// 解析失败也应返回空响应或 SERVFAIL，**不应** panic / 永久阻塞。
    async fn serve_packet(&self, req: &[u8]) -> Vec<u8>;
}

static DNS_RESPONDER: RwLock<Option<Arc<dyn DnsResponder>>> = RwLock::new(None);

/// Runtime 启动后注入 [`DnsResponder`]，让 [`DnsHijackOutbound`] 与 standalone
/// DNS listener 都能使用同一份 service。
pub fn set_global_dns_responder(r: Arc<dyn DnsResponder>) {
    let mut guard = DNS_RESPONDER.write().unwrap_or_else(|e| e.into_inner());
    *guard = Some(r);
}

pub fn global_dns_responder() -> Option<Arc<dyn DnsResponder>> {
    DNS_RESPONDER
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

#[cfg(test)]
fn clear_global_dns_responder() {
    let mut guard = DNS_RESPONDER.write().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

#[derive(Debug)]
pub struct DnsHijackOutbound {
    name: String,
}

impl DnsHijackOutbound {
    pub fn new(name: impl Into<String>) -> Arc<Self> {
        Arc::new(Self { name: name.into() })
    }
}

#[async_trait]
impl OutboundAdapter for DnsHijackOutbound {
    fn name(&self) -> &str {
        &self.name
    }
    fn protocol(&self) -> &'static str {
        "dns"
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            udp: true,
            ipv6: true,
            multiplex: false,
        }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream> {
        let responder = global_dns_responder().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "dns hijack: no DnsResponder injected (resolver not initialized)",
            )
        })?;
        debug!(
            target: "dial::dns_hijack",
            id = ctx.dial_id,
            host = %ctx.host,
            port = ctx.port,
            "tcp hijack accepted"
        );
        let stream = DnsTcpHijack::new(responder, ctx.dial_id);
        Ok(Box::pin(stream))
    }

    async fn dial_udp(&self, ctx: DialContext) -> std::io::Result<BoxedUdp> {
        let responder = global_dns_responder().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "dns hijack: no DnsResponder injected (resolver not initialized)",
            )
        })?;
        debug!(
            target: "dial::dns_hijack",
            id = ctx.dial_id,
            host = %ctx.host,
            port = ctx.port,
            "udp hijack accepted"
        );
        Ok(Box::new(DnsUdpHijack::new(responder, ctx)))
    }
}

/* ============================================================
UDP hijack —— 每个 send_to 是一个 DNS 请求，answer 排队给 recv_from。
============================================================ */

struct DnsUdpHijack {
    responder: Arc<dyn DnsResponder>,
    /// 排队待 recv_from 取走的响应包。
    answers: Mutex<VecDeque<Vec<u8>>>,
    /// 有新答复时唤醒等待的 recv_from。
    notify: Notify,
    /// dial 时的目标 host:port（仅日志用）。
    target: String,
    target_port: u16,
}

impl DnsUdpHijack {
    fn new(responder: Arc<dyn DnsResponder>, ctx: DialContext) -> Self {
        Self {
            responder,
            answers: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
            target: ctx.host,
            target_port: ctx.port,
        }
    }
}

#[async_trait]
impl UdpSocketLike for DnsUdpHijack {
    async fn send_to(&self, buf: &[u8], _target: &str, _port: u16) -> std::io::Result<usize> {
        let n = buf.len();
        let resp = self.responder.serve_packet(buf).await;
        // 即使 resp 为空也排进去：调用方 recv_from 会拿到 0 字节（与 socket 行为
        // 不完全一致，但避免无限阻塞；mihomo 也做空响应）。
        let mut q = self.answers.lock().await;
        q.push_back(resp);
        drop(q);
        self.notify.notify_one();
        Ok(n)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            // 先等待信号，再取队列 —— 避免与 send_to 的小窗口竞争。
            let waiter = self.notify.notified();
            {
                let mut q = self.answers.lock().await;
                if let Some(resp) = q.pop_front() {
                    let n = resp.len().min(buf.len());
                    buf[..n].copy_from_slice(&resp[..n]);
                    return Ok(n);
                }
            }
            waiter.await;
        }
    }

    async fn close(&self) -> std::io::Result<()> {
        // 唤醒所有等待者，让 recv_from 退出（返回 0）。下一次 send_to 仍然会
        // 排队 —— 按 UdpSocketLike 当前契约，调用方 drop 即可。
        self.notify.notify_waiters();
        debug!(
            target: "dial::dns_hijack",
            target = %self.target,
            port = self.target_port,
            "udp hijack closed"
        );
        Ok(())
    }
}

/* ============================================================
TCP hijack —— 把 (read, write) 端点用 channel 串起来，后台 task 读
length-prefixed DNS 消息，调 responder，写回响应。
============================================================ */

struct DnsTcpHijack {
    /// 调用方 → 后台 task 的请求字节流。
    req_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    /// 后台 task → 调用方的响应字节流。
    resp_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    /// 当前 read 的尾巴（一个 chunk 没读完时挂这里）。
    pending: Vec<u8>,
}

impl DnsTcpHijack {
    fn new(responder: Arc<dyn DnsResponder>, dial_id: u64) -> Self {
        let (req_tx, req_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (resp_tx, resp_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        tokio::spawn(dns_tcp_worker(responder, dial_id, req_rx, resp_tx));
        Self {
            req_tx: Some(req_tx),
            resp_rx,
            pending: Vec::new(),
        }
    }
}

async fn dns_tcp_worker(
    responder: Arc<dyn DnsResponder>,
    dial_id: u64,
    mut req_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    resp_tx: mpsc::UnboundedSender<Vec<u8>>,
) {
    // 累积 inbound 字节，按 RFC 1035 §4.2.2 解析 2-byte len + msg。
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    while let Some(chunk) = req_rx.recv().await {
        buf.extend_from_slice(&chunk);
        loop {
            if buf.len() < 2 {
                break;
            }
            let msg_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            if buf.len() < 2 + msg_len {
                break; // 等更多字节
            }
            let msg = buf[2..2 + msg_len].to_vec();
            buf.drain(..2 + msg_len);

            let resp = responder.serve_packet(&msg).await;
            let mut framed = Vec::with_capacity(2 + resp.len());
            framed.extend_from_slice(&(resp.len() as u16).to_be_bytes());
            framed.extend_from_slice(&resp);
            if resp_tx.send(framed).is_err() {
                debug!(
                    target: "dial::dns_hijack",
                    id = dial_id,
                    "tcp hijack: client closed read end, worker exits"
                );
                return;
            }
        }
    }
    debug!(
        target: "dial::dns_hijack",
        id = dial_id,
        "tcp hijack: client closed write end, worker exits"
    );
}

impl AsyncRead for DnsTcpHijack {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // 先吐 pending；再 poll channel。
        if !self.pending.is_empty() {
            let n = self.pending.len().min(out.remaining());
            out.put_slice(&self.pending[..n]);
            self.pending.drain(..n);
            return Poll::Ready(Ok(()));
        }
        match self.resp_rx.poll_recv(cx) {
            Poll::Ready(Some(chunk)) => {
                let n = chunk.len().min(out.remaining());
                out.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    self.pending = chunk[n..].to_vec();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for DnsTcpHijack {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.req_tx.as_ref() {
            Some(tx) => match tx.send(buf.to_vec()) {
                Ok(()) => Poll::Ready(Ok(buf.len())),
                Err(_) => Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "dns hijack worker exited",
                ))),
            },
            None => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "dns hijack write end closed",
            ))),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // 关闭请求通道 → worker 收到 None → 自然退出 → resp_rx 也会被关。
        self.req_tx = None;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[derive(Debug)]
    struct EchoLenResponder;

    #[async_trait]
    impl DnsResponder for EchoLenResponder {
        async fn serve_packet(&self, req: &[u8]) -> Vec<u8> {
            // 测试 stub：返回一个长度等于请求长度的响应（前 12 字节伪装成 DNS 头）。
            let mut out = vec![0u8; req.len().max(12)];
            // 复制 transaction id + 把 QR=1 翻起来（仅为可识别）
            if req.len() >= 12 {
                out[0..2].copy_from_slice(&req[0..2]);
                out[2] = 0x80;
            }
            out
        }
    }

    static DNS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_dns_test() -> std::sync::MutexGuard<'static, ()> {
        DNS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[tokio::test]
    async fn udp_hijack_returns_responder_output() {
        let _g = lock_dns_test();
        clear_global_dns_responder();
        set_global_dns_responder(Arc::new(EchoLenResponder));
        let ob = DnsHijackOutbound::new("DNS_Hijack");
        let udp = ob.dial_udp(DialContext::udp("8.8.8.8", 53)).await.unwrap();

        // 12 字节最小 DNS 头：txid=0x1234, flags=0, counts=0
        let mut req = vec![0u8; 12];
        req[0] = 0x12;
        req[1] = 0x34;
        let n = udp.send_to(&req, "8.8.8.8", 53).await.unwrap();
        assert_eq!(n, req.len());

        let mut buf = [0u8; 512];
        let n = udp.recv_from(&mut buf).await.unwrap();
        assert!(n >= 12);
        assert_eq!(&buf[0..2], &[0x12, 0x34]);
        assert_eq!(buf[2], 0x80, "QR bit should be set");

        clear_global_dns_responder();
    }

    #[tokio::test]
    async fn tcp_hijack_handles_length_prefixed_messages() {
        let _g = lock_dns_test();
        clear_global_dns_responder();
        set_global_dns_responder(Arc::new(EchoLenResponder));
        let ob = DnsHijackOutbound::new("DNS_Hijack");
        let mut stream = ob.dial_tcp(DialContext::tcp("8.8.8.8", 53)).await.unwrap();

        // 写入两条紧贴的 length-prefixed DNS 消息
        let req = {
            let mut m = vec![0u8; 12];
            m[0] = 0xde;
            m[1] = 0xad;
            m
        };
        let mut framed = Vec::new();
        framed.extend_from_slice(&(req.len() as u16).to_be_bytes());
        framed.extend_from_slice(&req);
        framed.extend_from_slice(&(req.len() as u16).to_be_bytes());
        framed.extend_from_slice(&req);
        stream.write_all(&framed).await.unwrap();

        // 读两条响应
        for _ in 0..2 {
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await.unwrap();
            let resp_len = u16::from_be_bytes(len_buf) as usize;
            assert!(resp_len >= 12);
            let mut resp = vec![0u8; resp_len];
            stream.read_exact(&mut resp).await.unwrap();
            assert_eq!(&resp[0..2], &[0xde, 0xad]);
            assert_eq!(resp[2], 0x80);
        }
        clear_global_dns_responder();
    }

    #[tokio::test]
    async fn dial_fails_when_no_responder_set() {
        let _g = lock_dns_test();
        clear_global_dns_responder();
        let ob = DnsHijackOutbound::new("DNS_Hijack");
        let err = match ob.dial_udp(DialContext::udp("1.1.1.1", 53)).await {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("DnsResponder"));
    }
}
