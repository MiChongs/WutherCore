//! Standalone DNS server —— mihomo `dns.listen: 0.0.0.0:1053` 等价。
//!
//! 同地址同时绑 UDP 和 TCP（DNS over TCP）。所有查询直接喂给
//! [`core_resolver::DnsService::serve_packet`]，与 capture / DNS hijack 出站
//! 共享同一份 service 实例（fake-ip pool / cache / nameserver-policy 全部一致）。
//!
//! ### 与 mihomo `dns/server.go` 行为对齐
//!
//! - **UDP**：`tokio::net::UdpSocket::bind`，单 socket 接所有客户端，每个
//!   datagram 对应一个查询；并发 spawn 处理（避免慢查询阻塞他人）。
//! - **TCP**：`tokio::net::TcpListener::accept`，每个连接 spawn 一个 task，
//!   loop 读 2-byte len + msg → serve → 写 2-byte len + resp，直到对端关闭。
//! - **错误处理**：单个查询 / 连接失败只记 debug 日志；listener 本身只在
//!   bind / accept 致命错误（端口被占用、socket 关闭）时退出。

use std::{net::SocketAddr, sync::Arc};

use core_resolver::DnsService;
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::{JoinHandle, JoinSet},
};
use tracing::{debug, info, warn};

#[derive(Debug, Error)]
pub enum DnsListenerError {
    #[error("dns listen 解析失败: {0}: {1}")]
    InvalidAddr(String, String),
    #[error("dns udp bind {0} 失败: {1}")]
    UdpBind(SocketAddr, std::io::Error),
    #[error("dns tcp bind {0} 失败: {1}")]
    TcpBind(SocketAddr, std::io::Error),
}

/// Parse the configured DNS listen address without binding a socket.
///
/// This is the single source of truth shared by startup and host-resource
/// arbitration. Empty input and port `0` are disabled, matching mihomo.
pub fn parse_dns_listen_addr(listen: &str) -> Result<Option<SocketAddr>, DnsListenerError> {
    let trimmed = listen.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let addr: SocketAddr = trimmed.parse().map_err(|e: std::net::AddrParseError| {
        DnsListenerError::InvalidAddr(trimmed.to_string(), e.to_string())
    })?;
    Ok((addr.port() != 0).then_some(addr))
}

/// 同时持有 UDP + TCP listener 句柄，drop 时取消两个后台 task。
///
/// `Disabled` 变体表示"配置上不启动"——按 mihomo 默认行为，空地址或 port=0
/// 都不会真正绑端口；返回此 handle 仅为统一调用方代码（不需要 `Option` 包裹）。
#[derive(Debug)]
pub struct DnsListener {
    kind: ListenerKind,
}

#[derive(Debug)]
enum ListenerKind {
    Disabled,
    Active {
        udp_addr: SocketAddr,
        tcp_addr: SocketAddr,
        udp_task: JoinHandle<()>,
        tcp_task: JoinHandle<()>,
    },
}

impl DnsListener {
    fn disabled() -> Self {
        Self {
            kind: ListenerKind::Disabled,
        }
    }

    /// 是否处于禁用状态（mihomo 行为：空地址 / port=0 → disabled）。
    pub fn is_disabled(&self) -> bool {
        matches!(self.kind, ListenerKind::Disabled)
    }

    /// UDP 实际监听地址；disabled 时返回 `None`。
    pub fn addr(&self) -> Option<SocketAddr> {
        match &self.kind {
            ListenerKind::Active { udp_addr, .. } => Some(*udp_addr),
            ListenerKind::Disabled => None,
        }
    }

    /// TCP 实际监听地址；disabled 时返回 `None`。
    pub fn tcp_addr(&self) -> Option<SocketAddr> {
        match &self.kind {
            ListenerKind::Active { tcp_addr, .. } => Some(*tcp_addr),
            ListenerKind::Disabled => None,
        }
    }

    /// Stop both protocol listeners and wait until their sockets and all
    /// per-query/per-connection tasks have been dropped.
    ///
    /// `Drop` remains a synchronous cancellation fallback, while lifecycle
    /// owners that need to re-bind the same port should use this method.
    pub async fn shutdown(mut self) {
        let kind = std::mem::replace(&mut self.kind, ListenerKind::Disabled);
        if let ListenerKind::Active {
            udp_task, tcp_task, ..
        } = kind
        {
            udp_task.abort();
            tcp_task.abort();
            let _ = udp_task.await;
            let _ = tcp_task.await;
        }
    }
}

impl Drop for DnsListener {
    fn drop(&mut self) {
        if let ListenerKind::Active {
            udp_task, tcp_task, ..
        } = &self.kind
        {
            udp_task.abort();
            tcp_task.abort();
        }
    }
}

/// 启动 DNS server。`listen` 形如 `0.0.0.0:1053` / `[::]:53` / `127.0.0.1:5353`。
///
/// **与 mihomo `dns/server.go::ReCreateServer` 对齐的默认行为**：
/// - 空串 / 仅空白 → 返回 `Disabled`，不绑定任何 socket（mihomo `addr == ""` 早退）。
/// - port = 0 → 同样视作禁用（mihomo `port == "0"` 早退；不做 OS-assigned 兜底）。
/// - 其余按 [`SocketAddr`] 解析；UDP + TCP 同址绑定，任一失败返回错误，不留半启动状态。
///
/// 调用方应当 `Option::transpose(...)` 后只在 `Some(_)` 时启动；同时尊重本函数
/// 的 `Disabled` 提前返回，避免绑到 unspecified port 上踩 mihomo 不会有的边界。
pub async fn spawn_dns_listener(
    listen: &str,
    service: Arc<DnsService>,
) -> Result<DnsListener, DnsListenerError> {
    let Some(addr) = parse_dns_listen_addr(listen)? else {
        let trimmed = listen.trim();
        if trimmed.is_empty() {
            debug!(target: "dns::listener", "listen empty; DNS server disabled (mihomo-aligned)");
        } else {
            // mihomo `dns/server.go:73-77`: port == "0" → return early, no listener.
            info!(
                target: "dns::listener",
                listen = %trimmed,
                "port=0 视为 disabled（mihomo 行为）；如需 OS 选端口请显式指定 :PORT"
            );
        }
        return Ok(DnsListener::disabled());
    };

    // ---- UDP ----
    let udp = UdpSocket::bind(addr)
        .await
        .map_err(|e| DnsListenerError::UdpBind(addr, e))?;
    let udp_actual = udp.local_addr().unwrap_or(addr);
    info!(target: "dns::listener", addr = %udp_actual, proto = "udp", "DNS server listening");

    // ---- TCP ----
    let tcp = TcpListener::bind(addr)
        .await
        .map_err(|e| DnsListenerError::TcpBind(addr, e))?;
    let tcp_actual = tcp.local_addr().unwrap_or(addr);
    info!(target: "dns::listener", addr = %tcp_actual, proto = "tcp", "DNS server listening");

    let udp_service = service.clone();
    let udp_task = tokio::spawn(async move { run_udp(udp, udp_service).await });
    let tcp_service = service.clone();
    let tcp_task = tokio::spawn(async move { run_tcp(tcp, tcp_service).await });

    Ok(DnsListener {
        kind: ListenerKind::Active {
            udp_addr: udp_actual,
            tcp_addr: tcp_actual,
            udp_task,
            tcp_task,
        },
    })
}

async fn run_udp(sock: UdpSocket, service: Arc<DnsService>) {
    let sock = Arc::new(sock);
    let mut queries = JoinSet::new();
    // RFC 6891 §6.2.5：DNS over UDP 报文最大 EDNS0 4096，不带 EDNS 时 512。
    // 给 4096 足够；超大查询客户端会重试 TCP。
    let mut buf = vec![0u8; 4096];
    loop {
        while queries.try_join_next().is_some() {}
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!(target: "dns::listener", error = %e, "udp recv_from failed; listener exits");
                return;
            }
        };
        if n == 0 {
            continue;
        }
        let req = buf[..n].to_vec();
        let sock_clone = sock.clone();
        let svc = service.clone();
        // 异步处理，避免 fake-ip 分配 / 上游查询阻塞下一个客户端。
        queries.spawn(async move {
            let resp = svc.serve_packet(&req).await;
            if resp.is_empty() {
                debug!(target: "dns::listener", peer = %peer, "udp empty response from service");
                return;
            }
            // RFC 1035 §4.2.1：UDP 响应 > 512 byte 时，需要置 TC 位让客户端重试 TCP。
            // 这里依赖 service / packet builder 已经打了 TC；不在 listener 层重新截断。
            if let Err(e) = sock_clone.send_to(&resp, peer).await {
                debug!(target: "dns::listener", peer = %peer, error = %e, "udp send_to failed");
            }
        });
    }
}

async fn run_tcp(listener: TcpListener, service: Arc<DnsService>) {
    let mut connections = JoinSet::new();
    loop {
        while connections.try_join_next().is_some() {}
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(target: "dns::listener", error = %e, "tcp accept failed; listener exits");
                return;
            }
        };
        let svc = service.clone();
        connections.spawn(async move {
            if let Err(e) = handle_tcp_conn(stream, svc).await {
                debug!(target: "dns::listener", peer = %peer, error = %e, "tcp conn ended");
            }
        });
    }
}

async fn handle_tcp_conn(mut stream: TcpStream, service: Arc<DnsService>) -> std::io::Result<()> {
    let _ = stream.set_nodelay(true);
    loop {
        // RFC 1035 §4.2.2: 2-byte big-endian length prefix
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 {
            continue;
        }
        let mut req = vec![0u8; msg_len];
        stream.read_exact(&mut req).await?;
        let resp = service.serve_packet(&req).await;
        let len = (resp.len() as u16).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(&resp).await?;
        stream.flush().await?;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::IpAddr,
        sync::atomic::{AtomicU32, Ordering},
    };

    use core_resolver::{
        DnsService, ResolverBuilder,
        group::{DnsGroup, GroupStrategy},
        upstream::{DnsError, DnsUpstream},
    };

    use super::*;

    #[derive(Debug)]
    struct StaticUp {
        ip: IpAddr,
        n: AtomicU32,
    }

    #[async_trait::async_trait]
    impl DnsUpstream for StaticUp {
        fn name(&self) -> &str {
            "static"
        }
        fn kind(&self) -> &'static str {
            "test"
        }
        async fn query_a(&self, _host: &str) -> Result<Vec<IpAddr>, DnsError> {
            self.n.fetch_add(1, Ordering::Relaxed);
            Ok(vec![self.ip])
        }
        async fn query_aaaa(&self, _host: &str) -> Result<Vec<IpAddr>, DnsError> {
            Err(DnsError::Empty)
        }
        // 不重写 query_records —— 用 trait 默认实现（基于 query_a/query_aaaa）。
    }

    fn test_service() -> Arc<DnsService> {
        let up = Arc::new(StaticUp {
            ip: "9.9.9.9".parse().unwrap(),
            n: AtomicU32::new(0),
        });
        let g = Arc::new(DnsGroup::new(
            "default",
            GroupStrategy::Fallback,
            vec![up as _],
        ));
        let r = ResolverBuilder::new()
            .group("default", g.clone())
            .bootstrap(g)
            .build();
        Arc::new(DnsService::new(Arc::new(r)))
    }

    /// 构造最小 DNS A 查询 for "example.com": 12-byte header + qname + qtype + qclass
    fn build_a_query(txid: u16) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&txid.to_be_bytes()); // ID
        q.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
        q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR=0
        // qname: 7 "example" 3 "com" 0
        q.push(7);
        q.extend_from_slice(b"example");
        q.push(3);
        q.extend_from_slice(b"com");
        q.push(0);
        q.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
        q.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
        q
    }

    /// 选一个本地未占用端口，再立即把 listener drop 掉，让上层重新 bind。
    /// 用于 disabled 测试以外的真实监听场景，避免依赖 OS-assigned `:0`。
    async fn pick_free_port() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    }

    #[test]
    fn parser_matches_disabled_and_active_listener_semantics() {
        assert_eq!(parse_dns_listen_addr("   ").unwrap(), None);
        assert_eq!(parse_dns_listen_addr("127.0.0.1:0").unwrap(), None);
        assert_eq!(
            parse_dns_listen_addr(" 127.0.0.1:5353 ").unwrap(),
            Some("127.0.0.1:5353".parse().unwrap())
        );
        assert!(matches!(
            parse_dns_listen_addr("localhost:5353"),
            Err(DnsListenerError::InvalidAddr(_, _))
        ));
    }

    #[tokio::test]
    async fn udp_listener_actual_query_roundtrip() {
        let svc = test_service();
        let port = pick_free_port().await;
        let listener = spawn_dns_listener(&format!("127.0.0.1:{port}"), svc)
            .await
            .unwrap();
        assert!(!listener.is_disabled());
        let listen_addr = listener.addr().expect("active listener");

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(listen_addr).await.unwrap();
        let q = build_a_query(0xCAFE);
        client.send(&q).await.unwrap();

        let mut buf = [0u8; 512];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("timeout")
            .unwrap();
        assert!(n >= 12);
        assert_eq!(&buf[0..2], &[0xCA, 0xFE], "txid roundtrip");
        assert!(buf[2] & 0x80 != 0, "QR bit should be set in response");
        drop(listener);
    }

    #[tokio::test]
    async fn tcp_listener_actual_query_roundtrip() {
        let svc = test_service();
        let port = pick_free_port().await;
        let listener = spawn_dns_listener(&format!("127.0.0.1:{port}"), svc)
            .await
            .unwrap();
        let tcp_addr = listener.tcp_addr().expect("active listener");
        // 等 listener 启动
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = TcpStream::connect(tcp_addr).await.unwrap();
        let q = build_a_query(0xBEEF);
        let len = (q.len() as u16).to_be_bytes();
        client.write_all(&len).await.unwrap();
        client.write_all(&q).await.unwrap();
        client.flush().await.unwrap();

        let mut len_buf = [0u8; 2];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read_exact(&mut len_buf),
        )
        .await
        .expect("read len timeout")
        .unwrap();
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        assert!(resp_len >= 12);
        let mut resp = vec![0u8; resp_len];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp[0..2], &[0xBE, 0xEF]);
        assert!(resp[2] & 0x80 != 0);
        drop(listener);
    }

    #[tokio::test]
    async fn shutdown_releases_udp_and_tcp_port_for_immediate_restart() {
        let svc = test_service();
        let port = pick_free_port().await;
        let listen = format!("127.0.0.1:{port}");
        let listener = spawn_dns_listener(&listen, svc.clone()).await.unwrap();

        listener.shutdown().await;

        let rebound = spawn_dns_listener(&listen, svc).await.unwrap();
        assert_eq!(rebound.addr().unwrap().port(), port);
        assert_eq!(rebound.tcp_addr().unwrap().port(), port);
        rebound.shutdown().await;
    }

    #[tokio::test]
    async fn rejects_invalid_listen_addr() {
        let svc = test_service();
        let err = spawn_dns_listener("not-a-host:port", svc)
            .await
            .unwrap_err();
        assert!(matches!(err, DnsListenerError::InvalidAddr(_, _)));
    }

    /// mihomo `dns/server.go:65-72`: addr == "" → return early, no listener bound.
    #[tokio::test]
    async fn empty_listen_addr_returns_disabled_handle() {
        let svc = test_service();
        let h = spawn_dns_listener("", svc.clone()).await.unwrap();
        assert!(h.is_disabled());
        assert!(h.addr().is_none());
        assert!(h.tcp_addr().is_none());

        // 同样接受全空白
        let h2 = spawn_dns_listener("   ", svc).await.unwrap();
        assert!(h2.is_disabled());
    }

    /// mihomo `dns/server.go:73-77`: port == "0" → return early.
    /// WutherCore 不做 OS-assigned 兜底，按 mihomo 同样视作 disabled。
    #[tokio::test]
    async fn port_zero_returns_disabled_handle() {
        let svc = test_service();
        let h = spawn_dns_listener("127.0.0.1:0", svc.clone())
            .await
            .unwrap();
        assert!(h.is_disabled());
        assert!(h.addr().is_none());

        let h6 = spawn_dns_listener("[::]:0", svc).await.unwrap();
        assert!(h6.is_disabled());
    }
}
