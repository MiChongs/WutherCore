//! DNS hijack listener for capture mode.
//!
//! Packet parsing, fake-ip allocation and response synthesis live in
//! `core-resolver::DnsService`; capture only owns socket I/O.

use std::{net::SocketAddr, sync::Arc};

use core_resolver::DnsService;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UdpSocket,
};
use tracing::{debug, trace, warn};

pub async fn run_fake_dns(bind: SocketAddr, service: Arc<DnsService>) -> std::io::Result<()> {
    let sock = UdpSocket::bind(bind).await?;
    debug!(target: "capture::dns", addr = %bind, "fake-dns listening");
    let mut buf = vec![0u8; 1500];
    loop {
        let (n, src) = sock.recv_from(&mut buf).await?;
        if n < 12 {
            continue;
        }
        let resp = service.serve_packet(&buf[..n]).await;
        trace!(
            target: "capture::dns",
            src = %src,
            query_bytes = n,
            response_bytes = resp.len(),
            "dns packet served"
        );
        if resp.is_empty() {
            continue;
        }
        if let Err(e) = sock.send_to(&resp, src).await {
            warn!(target: "capture::dns", error = %e, "fake-dns send failed");
        }
    }
}

pub async fn synthesize(req: &[u8], service: &DnsService) -> Vec<u8> {
    service.serve_packet(req).await
}

pub async fn serve_tcp_stream<S>(mut stream: S, service: Arc<DnsService>) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let len = match stream.read_u16().await {
            Ok(len) => len as usize,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        if len == 0 {
            continue;
        }
        let mut req = vec![0u8; len];
        stream.read_exact(&mut req).await?;
        let resp = service.serve_packet(&req).await;
        trace!(
            target: "capture::dns",
            query_bytes = len,
            response_bytes = resp.len(),
            "dns tcp query served"
        );
        if resp.is_empty() || resp.len() > u16::MAX as usize {
            continue;
        }
        stream.write_u16(resp.len() as u16).await?;
        stream.write_all(&resp).await?;
        stream.flush().await?;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use core_resolver::{DnsService, FakeIpPool};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::synthesize;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0);
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt
    }

    #[tokio::test]
    async fn synthesize_uses_resolver_dns_service() {
        let pool = Arc::new(FakeIpPool::default());
        let service = DnsService::fake_only(pool.clone());

        let resp = synthesize(&query("a.com", 1), &service).await;

        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
        assert!(pool.lookup("198.18.0.1".parse().unwrap()).is_some());
    }

    #[tokio::test]
    async fn serve_tcp_stream_handles_dns_length_prefixed_query() {
        let pool = Arc::new(FakeIpPool::default());
        let service = Arc::new(DnsService::fake_only(pool.clone()));
        let (mut client, server) = tokio::io::duplex(2048);

        let task = tokio::spawn(async move {
            super::serve_tcp_stream(server, service).await.unwrap();
        });

        let req = query("tcp.example", 1);
        client.write_u16(req.len() as u16).await.unwrap();
        client.write_all(&req).await.unwrap();
        client.flush().await.unwrap();

        let n = client.read_u16().await.unwrap() as usize;
        let mut resp = vec![0u8; n];
        client.read_exact(&mut resp).await.unwrap();
        drop(client);
        task.await.unwrap();

        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
        assert!(pool.lookup("198.18.0.1".parse().unwrap()).is_some());
    }
}
