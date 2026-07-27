//! Young outbound over Mozilla Neqo HTTP/3/WebTransport.

use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use async_trait::async_trait;
use core_young::{Target, YoungClient, YoungClientConfig, YoungUdpChannel};

use crate::adapter::{
    BoxedStream, BoxedUdp, Capabilities, DialContext, OutboundAdapter, UdpSocketLike,
};

#[derive(Debug)]
pub struct YoungOutbound {
    name: String,
    config: YoungClientConfig,
    client: Mutex<Option<YoungClient>>,
}

impl YoungOutbound {
    #[must_use]
    pub fn new(name: impl Into<String>, config: YoungClientConfig) -> Self {
        Self {
            name: name.into(),
            config,
            client: Mutex::new(None),
        }
    }

    fn client(&self) -> io::Result<YoungClient> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| io::Error::other("Young client lock poisoned"))?;
        if let Some(client) = client.as_ref() {
            return Ok(client.clone());
        }
        let started = YoungClient::start(self.config.clone())?;
        *client = Some(started.clone());
        Ok(started)
    }
}

#[async_trait]
impl OutboundAdapter for YoungOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> &'static str {
        "young"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            udp: true,
            ipv6: true,
            multiplex: true,
        }
    }

    async fn dial_tcp(&self, context: DialContext) -> io::Result<BoxedStream> {
        let target = Target::new(context.host, context.port)?;
        Ok(Box::pin(self.client()?.open_tcp(target).await?))
    }

    async fn dial_udp(&self, context: DialContext) -> io::Result<BoxedUdp> {
        let target = Target::new(context.host, context.port)?;
        let channel = self.client()?.open_udp(target).await?;
        Ok(Box::new(YoungUdpSocket {
            channel: Arc::new(channel),
            closed: AtomicBool::new(false),
        }))
    }
}

struct YoungUdpSocket {
    channel: Arc<YoungUdpChannel>,
    closed: AtomicBool,
}

#[async_trait]
impl UdpSocketLike for YoungUdpSocket {
    async fn send_to(&self, payload: &[u8], target: &str, port: u16) -> io::Result<usize> {
        if self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Young UDP socket 已关闭",
            ));
        }
        let configured = self.channel.target();
        if configured.host != target || configured.port != port {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Young UDP association 固定到 dial_udp 的目标",
            ));
        }
        self.channel.send(payload).await
    }

    async fn recv_from(&self, output: &mut [u8]) -> io::Result<usize> {
        if self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Young UDP socket 已关闭",
            ));
        }
        self.channel.recv(output).await
    }

    async fn close(&self) -> io::Result<()> {
        self.closed.store(true, Ordering::Release);
        self.channel.close()
    }
}
