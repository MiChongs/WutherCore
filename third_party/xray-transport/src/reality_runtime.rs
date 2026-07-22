use std::{
    fmt,
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use xray_routing::{Target, TargetAddr};

use crate::{
    connect_tcp_stream,
    reality_connector::{
        RealityClientHelloRequest, RealityConnector, RealityHandshakeContext,
        RealityTlsSessionProvider,
    },
    BoxedTransportStream, DnsResolver, RealityClientConfig, RealityTlsEngine, SocketProtector,
    SystemDnsResolver, TransportError,
};

const REALITY_HANDSHAKE_VERSION: [u8; 3] = [1, 8, 0];

pub trait RealityHandshakeContextProvider: Send + Sync {
    fn context(&self) -> RealityHandshakeContext;
}

#[derive(Debug, Clone, Default)]
pub struct SystemRealityHandshakeContextProvider;

impl RealityHandshakeContextProvider for SystemRealityHandshakeContextProvider {
    fn context(&self) -> RealityHandshakeContext {
        let unix_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs().min(u32::MAX as u64) as u32);

        RealityHandshakeContext {
            version: REALITY_HANDSHAKE_VERSION,
            unix_time,
        }
    }
}

#[derive(Clone)]
pub struct RealityRuntimeEngine {
    session_provider: Arc<dyn RealityTlsSessionProvider>,
    dns_resolver: Arc<dyn DnsResolver>,
    context_provider: Arc<dyn RealityHandshakeContextProvider>,
    socket_protector: Option<Arc<dyn SocketProtector>>,
}

impl fmt::Debug for RealityRuntimeEngine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityRuntimeEngine")
            .field("session_provider", &"<dyn RealityTlsSessionProvider>")
            .field("dns_resolver", &"<dyn DnsResolver>")
            .field("context_provider", &"<dyn RealityHandshakeContextProvider>")
            .field("socket_protector", &self.socket_protector.is_some())
            .finish()
    }
}

impl RealityRuntimeEngine {
    pub fn new(session_provider: Arc<dyn RealityTlsSessionProvider>) -> Self {
        Self {
            session_provider,
            dns_resolver: Arc::new(SystemDnsResolver),
            context_provider: Arc::new(SystemRealityHandshakeContextProvider),
            socket_protector: None,
        }
    }

    pub fn with_dns_resolver(mut self, dns_resolver: Arc<dyn DnsResolver>) -> Self {
        self.dns_resolver = dns_resolver;
        self
    }

    pub fn with_context_provider(
        mut self,
        context_provider: Arc<dyn RealityHandshakeContextProvider>,
    ) -> Self {
        self.context_provider = context_provider;
        self
    }

    pub fn with_socket_protector(mut self, protector: Arc<dyn SocketProtector>) -> Self {
        self.socket_protector = Some(protector);
        self
    }

    async fn resolve_socket_addr(&self, target: &Target) -> Result<SocketAddr, TransportError> {
        match &target.addr {
            TargetAddr::Ip(ip) => Ok(SocketAddr::new(*ip, target.port)),
            TargetAddr::Domain(domain) => self.dns_resolver.resolve(domain, target.port).await,
        }
    }
}

#[async_trait]
impl RealityTlsEngine for RealityRuntimeEngine {
    async fn connect(
        &self,
        config: &RealityClientConfig,
        target: &Target,
    ) -> Result<BoxedTransportStream, TransportError> {
        let connector = RealityConnector::new(config.clone());
        connector.validate_fingerprint()?;

        let session = self
            .session_provider
            .create_session(RealityClientHelloRequest {
                server_name: &config.server_name,
                fingerprint: &config.fingerprint,
            })?;
        let prepared_client_hello = session.prepared_client_hello()?;
        let context = self.context_provider.context();
        let prepared =
            connector.prepare_handshake_with_client_hello(prepared_client_hello, context)?;
        let addr = self.resolve_socket_addr(target).await?;
        let stream = connect_tcp_stream(addr, self.socket_protector.as_deref()).await?;

        session
            .complete(stream, prepared, config.mldsa65_verify.clone())
            .await
    }
}
