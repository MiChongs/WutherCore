//! SOCKS5 出站 —— TCP CONNECT + UDP ASSOCIATE，支持 user/pass 认证。

use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UdpSocket,
    sync::Mutex as AsyncMutex,
};
use tracing::{debug, info};

use crate::{
    adapter::{
        BoxedStream, BoxedUdp, Capabilities, DialContext, OutboundAdapter, UdpSocketLike,
        prepare_outbound_udp_socket_for_addr, resolve_host,
    },
    proto::addr::{decode_socks_addr, encode_socks_addr},
    transport::Transport,
};

#[derive(Debug, Clone)]
pub struct Socks5Outbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub auth: Option<(String, String)>,
    pub udp: bool,
}

impl Socks5Outbound {
    pub fn new(name: impl Into<String>, host: impl Into<String>, port: u16) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port,
            auth: None,
            udp: true,
        }
    }
    pub fn with_auth(mut self, u: impl Into<String>, p: impl Into<String>) -> Self {
        self.auth = Some((u.into(), p.into()));
        self
    }
    pub fn with_udp(mut self, enabled: bool) -> Self {
        self.udp = enabled;
        self
    }
    pub fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }

    async fn connect_control(&self) -> std::io::Result<BoxedStream> {
        crate::transport::tcp::TcpTransport::default()
            .connect(&self.host, self.port)
            .await
    }
}

#[async_trait]
impl OutboundAdapter for Socks5Outbound {
    fn name(&self) -> &str {
        &self.name
    }
    fn protocol(&self) -> &'static str {
        "socks5"
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            udp: self.udp,
            ipv6: true,
            multiplex: false,
        }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream> {
        // 走 TcpTransport：自带 WutherCore resolver + SO_MARK 绕 TUN。
        let mut s = self.connect_control().await?;

        socks5_authenticate(&mut s, self.auth.as_ref()).await?;
        write_socks5_request(&mut s, 0x01, &ctx.host, ctx.port).await?;
        let _ = read_socks5_reply(&mut s, "CONNECT").await?;
        info!(
            target: "dial::socks5",
            id = ctx.dial_id,
            proxy = %self.name,
            server = %format!("{}:{}", self.host, self.port),
            target = %format!("{}:{}", ctx.host, ctx.port),
            "tcp connect handshake ok",
        );
        Ok(Box::pin(s))
    }

    async fn dial_udp(&self, ctx: DialContext) -> std::io::Result<BoxedUdp> {
        if !self.udp {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("outbound `{}`/socks5 udp disabled by config", self.name),
            ));
        }
        debug!(
            target: "dial::socks5",
            id = ctx.dial_id,
            proxy = %self.name,
            server = %format!("{}:{}", self.host, self.port),
            target = %format!("{}:{}", ctx.host, ctx.port),
            "udp associate begin",
        );
        let mut control = self.connect_control().await?;
        socks5_authenticate(&mut control, self.auth.as_ref()).await?;
        write_socks5_request(&mut control, 0x03, "0.0.0.0", 0).await?;
        let mut bind = read_socks5_reply(&mut control, "UDP ASSOCIATE").await?;
        if bind.ip().is_unspecified() {
            let addrs = resolve_host(&self.host, self.port).await?;
            let ip = addrs
                .iter()
                .find(|addr| addr.is_ipv4() == bind.is_ipv4())
                .or_else(|| addrs.first())
                .map(|addr| addr.ip())
                .ok_or_else(|| {
                    io_err("socks5 udp bind address unspecified and server unresolved")
                })?;
            bind = SocketAddr::new(ip, bind.port());
        }

        let local_bind: SocketAddr = if bind.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let std_sock = std::net::UdpSocket::bind(local_bind)?;
        let loopback_guard = prepare_outbound_udp_socket_for_addr(&std_sock, bind)?;
        std_sock.set_nonblocking(true)?;
        let sock = UdpSocket::from_std(std_sock)?;
        sock.connect(bind).await?;
        if let Ok(local) = sock.local_addr() {
            loopback_guard.observe_local_addr(local);
        }
        info!(
            target: "dial::socks5",
            id = ctx.dial_id,
            proxy = %self.name,
            bind = %bind,
            "udp associate ok",
        );
        Ok(Box::new(Socks5Udp {
            sock: Arc::new(sock),
            control: AsyncMutex::new(Some(control)),
            loopback_guard,
        }))
    }
}

fn io_err(s: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, s.to_string())
}

async fn socks5_authenticate<S>(s: &mut S, auth: Option<&(String, String)>) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    if auth.is_some() {
        s.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    } else {
        s.write_all(&[0x05, 0x01, 0x00]).await?;
    }
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await?;
    if resp[0] != 0x05 {
        return Err(io_err("socks5 版本错误"));
    }
    match resp[1] {
        0x00 => Ok(()),
        0x02 => {
            let (u, p) = auth.ok_or_else(|| io_err("服务器要求 USER_PASS 但未配置"))?;
            let mut buf = vec![0x01, u.len() as u8];
            buf.extend_from_slice(u.as_bytes());
            buf.push(p.len() as u8);
            buf.extend_from_slice(p.as_bytes());
            s.write_all(&buf).await?;
            let mut ar = [0u8; 2];
            s.read_exact(&mut ar).await?;
            if ar[1] != 0x00 {
                return Err(io_err("socks5 user/pass 鉴权失败"));
            }
            Ok(())
        }
        other => Err(io_err(&format!("socks5 不支持的方法: {other}"))),
    }
}

async fn write_socks5_request<S>(
    s: &mut S,
    command: u8,
    host: &str,
    port: u16,
) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    let addr = encode_socks_addr(host, port);
    let mut req = Vec::with_capacity(3 + addr.len());
    req.extend_from_slice(&[0x05, command, 0x00]);
    req.extend_from_slice(&addr);
    s.write_all(&req).await
}

async fn read_socks5_reply<S>(s: &mut S, phase: &str) -> std::io::Result<SocketAddr>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(io_err("socks5 reply version invalid"));
    }
    if head[1] != 0x00 {
        return Err(io_err(&format!("socks5 {phase} 失败: rep={}", head[1])));
    }
    let addr = read_socks_addr_tail(s, head[3]).await?;
    Ok(addr)
}

async fn read_socks_addr_tail<S>(s: &mut S, atyp: u8) -> std::io::Result<SocketAddr>
where
    S: AsyncRead + Unpin + ?Sized,
{
    match atyp {
        0x01 => {
            let mut buf = [0u8; 6];
            s.read_exact(&mut buf).await?;
            Ok(SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3])),
                u16::from_be_bytes([buf[4], buf[5]]),
            ))
        }
        0x04 => {
            let mut buf = [0u8; 18];
            s.read_exact(&mut buf).await?;
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[..16]);
            Ok(SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip)),
                u16::from_be_bytes([buf[16], buf[17]]),
            ))
        }
        0x03 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await?;
            let mut rest = vec![0u8; len[0] as usize + 2];
            s.read_exact(&mut rest).await?;
            let host = std::str::from_utf8(&rest[..len[0] as usize])
                .map_err(|_| io_err("socks5 reply domain invalid"))?;
            let port = u16::from_be_bytes([rest[len[0] as usize], rest[len[0] as usize + 1]]);
            let mut addrs = resolve_host(host, port).await?;
            addrs
                .pop()
                .ok_or_else(|| io_err("socks5 reply domain unresolved"))
        }
        _ => Err(io_err("socks5 BND.ADDR 类型错误")),
    }
}

struct Socks5Udp {
    sock: Arc<UdpSocket>,
    control: AsyncMutex<Option<BoxedStream>>,
    loopback_guard: crate::loopback::LoopbackUdpGuard,
}

#[async_trait]
impl UdpSocketLike for Socks5Udp {
    async fn send_to(&self, buf: &[u8], target: &str, port: u16) -> std::io::Result<usize> {
        let addr = encode_socks_addr(target, port);
        let mut packet = Vec::with_capacity(3 + addr.len() + buf.len());
        packet.extend_from_slice(&[0x00, 0x00, 0x00]);
        packet.extend_from_slice(&addr);
        packet.extend_from_slice(buf);
        self.sock.send(&packet).await?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut packet = vec![0u8; buf.len().saturating_add(512).max(1500)];
        let n = self.sock.recv(&mut packet).await?;
        if n < 3 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
            return Err(io_err("invalid socks5 udp header"));
        }
        let (_, _, used) = decode_socks_addr(&packet[3..n])?;
        let payload = &packet[3 + used..n];
        let copy_len = payload.len().min(buf.len());
        buf[..copy_len].copy_from_slice(&payload[..copy_len]);
        Ok(copy_len)
    }

    async fn close(&self) -> std::io::Result<()> {
        let mut control = self.control.lock().await;
        if let Some(mut c) = control.take() {
            let _ = c.shutdown().await;
        }
        let _ = &self.loopback_guard;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };

    use super::*;
    use crate::adapter::OutboundAdapter;

    #[test]
    fn socks5_udp_capability_is_declared_when_enabled() {
        let ob = Socks5Outbound::new("socks", "127.0.0.1", 1080);
        assert!(ob.capabilities().udp);
    }

    #[tokio::test]
    async fn socks5_udp_associate_wraps_udp_payloads() {
        let udp_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp_server.local_addr().unwrap();
        let tcp_server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp_server.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = tcp_server.accept().await.unwrap();

            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            stream.write_all(&[0x05, 0x00]).await.unwrap();

            let mut req = [0u8; 10];
            stream.read_exact(&mut req).await.unwrap();
            assert_eq!(&req[..4], &[0x05, 0x03, 0x00, 0x01]);

            let mut resp = vec![0x05, 0x00, 0x00, 0x01];
            resp.extend_from_slice(&[127, 0, 0, 1]);
            resp.extend_from_slice(&udp_addr.port().to_be_bytes());
            stream.write_all(&resp).await.unwrap();

            let mut buf = [0u8; 1500];
            let (n, peer) = udp_server.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..3], &[0x00, 0x00, 0x00]);
            assert_eq!(buf[3], 0x03);
            let len = buf[4] as usize;
            assert_eq!(&buf[5..5 + len], b"example.com");
            let port = u16::from_be_bytes([buf[5 + len], buf[6 + len]]);
            assert_eq!(port, 53);
            assert_eq!(&buf[7 + len..n], b"ping");

            udp_server.send_to(&buf[..n], peer).await.unwrap();
        });

        let ob = Socks5Outbound::new("socks", tcp_addr.ip().to_string(), tcp_addr.port());
        let udp = ob
            .dial_udp(DialContext::udp("example.com", 53))
            .await
            .unwrap();
        udp.send_to(b"ping", "example.com", 53).await.unwrap();
        let mut out = [0u8; 32];
        let n = udp.recv_from(&mut out).await.unwrap();
        assert_eq!(&out[..n], b"ping");

        server.await.unwrap();
    }
}
