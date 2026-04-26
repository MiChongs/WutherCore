use std::sync::Arc;

use async_trait::async_trait;

use crate::adapter::{BoxedStream, BoxedUdp, Capabilities, DialContext, OutboundAdapter};

#[derive(Debug, Default)]
pub struct BlockOutbound;

impl BlockOutbound {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

#[async_trait]
impl OutboundAdapter for BlockOutbound {
    fn name(&self) -> &str {
        "BLOCK"
    }
    fn protocol(&self) -> &'static str {
        "block"
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            udp: true,
            ipv6: true,
            multiplex: false,
        }
    }
    async fn dial_tcp(&self, _ctx: DialContext) -> std::io::Result<BoxedStream> {
        Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "blocked by route",
        ))
    }
    async fn dial_udp(&self, _ctx: DialContext) -> std::io::Result<BoxedUdp> {
        Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "blocked by route (udp)",
        ))
    }
}
