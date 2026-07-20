use std::{fmt, sync::Arc};

use crate::{
    connect_tcp_target, BoxedTransportStream, ConnectorConfig, RealityRuntimeEngine,
    RealityTlsEngine, RustlsRealityTlsSessionProvider, SocketProtector, TlsConnector,
    TransportError,
};
use xray_routing::Target;

#[derive(Clone)]
pub struct TransportDialer {
    tls: TlsConnector,
    reality: Option<Arc<dyn RealityTlsEngine>>,
    socket_protector: Option<Arc<dyn SocketProtector>>,
}

impl fmt::Debug for TransportDialer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportDialer")
            .field("tls", &self.tls)
            .field("reality_engine", &self.reality.is_some())
            .field("socket_protector", &self.socket_protector.is_some())
            .finish()
    }
}

impl TransportDialer {
    pub fn system() -> Result<Self, TransportError> {
        Self::system_with_socket_protector(None)
    }

    pub fn system_with_socket_protector(
        socket_protector: Option<Arc<dyn SocketProtector>>,
    ) -> Result<Self, TransportError> {
        let tls = match socket_protector.clone() {
            Some(protector) => TlsConnector::system()?.with_socket_protector(protector),
            None => TlsConnector::system()?,
        };
        let mut reality =
            RealityRuntimeEngine::new(Arc::new(RustlsRealityTlsSessionProvider::new()));
        if let Some(protector) = socket_protector.clone() {
            reality = reality.with_socket_protector(protector);
        }

        Ok(Self {
            tls,
            reality: Some(Arc::new(reality)),
            socket_protector,
        })
    }

    pub fn with_tls_connector(tls: TlsConnector) -> Self {
        Self {
            tls,
            reality: None,
            socket_protector: None,
        }
    }

    pub fn with_reality_engine(mut self, reality: Arc<dyn RealityTlsEngine>) -> Self {
        self.reality = Some(reality);
        self
    }

    pub fn with_socket_protector(mut self, protector: Arc<dyn SocketProtector>) -> Self {
        self.tls = self.tls.with_socket_protector(Arc::clone(&protector));
        self.socket_protector = Some(protector);
        self
    }

    pub fn socket_protector(&self) -> Option<&dyn SocketProtector> {
        self.socket_protector.as_deref()
    }

    pub async fn connect(
        &self,
        config: &ConnectorConfig,
        target: &Target,
    ) -> Result<BoxedTransportStream, TransportError> {
        match config {
            ConnectorConfig::Tcp => Ok(Box::new(
                connect_tcp_target(target, self.socket_protector.as_deref()).await?,
            )),
            ConnectorConfig::Tls(tls_config) => self.tls.connect(target, tls_config).await,
            ConnectorConfig::Reality(reality_config) => match &self.reality {
                Some(reality) => reality.connect(reality_config, target).await,
                None => Err(TransportError::UnsupportedConnectorConfig("reality")),
            },
        }
    }
}
