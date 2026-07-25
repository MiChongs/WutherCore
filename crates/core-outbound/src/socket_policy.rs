//! Per-outbound Xray `streamSettings` execution context.
//!
//! Protocol adapters in this crate intentionally share the transport dialers.
//! This task-local context lets the registry attach a policy to an adapter
//! without adding a socket-options argument to every protocol constructor.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use core_config::{NodeStreamSettings, OutboundSocketConfig};

use crate::adapter::{
    BoxedStream, BoxedUdp, Capabilities, DialContext, OutboundAdapter, SharedOutbound,
};

tokio::task_local! {
    static ACTIVE_STREAM_POLICY: Arc<ActiveStreamPolicy>;
}

/// Immutable policy installed while an outbound adapter is dialing its own
/// carrier connection. `dialer_proxy` is filled in a second registry pass so
/// forward references work and the final target is itself policy-wrapped.
pub(crate) struct ActiveStreamPolicy {
    pub(crate) settings: NodeStreamSettings,
    dialer_proxy: OnceLock<SharedOutbound>,
}

impl ActiveStreamPolicy {
    fn new(settings: NodeStreamSettings) -> Self {
        Self {
            settings,
            dialer_proxy: OnceLock::new(),
        }
    }

    fn empty() -> Self {
        Self::new(NodeStreamSettings::default())
    }

    pub(crate) fn socket(&self) -> Option<&OutboundSocketConfig> {
        self.settings.sockopt.as_ref()
    }

    pub(crate) fn proxy(&self) -> Option<SharedOutbound> {
        self.dialer_proxy.get().cloned()
    }
}

/// Registry wrapper that scopes all transport dials performed by `inner`.
pub(crate) struct ConfiguredOutbound {
    inner: SharedOutbound,
    policy: Arc<ActiveStreamPolicy>,
}

impl ConfiguredOutbound {
    pub(crate) fn new(
        inner: SharedOutbound,
        settings: NodeStreamSettings,
    ) -> (Arc<Self>, Arc<ActiveStreamPolicy>) {
        let policy = Arc::new(ActiveStreamPolicy::new(settings));
        (
            Arc::new(Self {
                inner,
                policy: policy.clone(),
            }),
            policy,
        )
    }

    pub(crate) fn set_dialer_proxy(
        policy: &ActiveStreamPolicy,
        proxy: SharedOutbound,
    ) -> Result<(), SharedOutbound> {
        policy.dialer_proxy.set(proxy)
    }
}

#[async_trait]
impl OutboundAdapter for ConfiguredOutbound {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn protocol(&self) -> &'static str {
        self.inner.protocol()
    }

    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }

    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream> {
        ACTIVE_STREAM_POLICY
            .scope(self.policy.clone(), self.inner.dial_tcp(ctx))
            .await
    }

    async fn dial_udp(&self, ctx: DialContext) -> std::io::Result<BoxedUdp> {
        // UDP masks belong on the protocol's real PacketConn carrier, not on
        // the application-level association returned here. Carrier-owning
        // protocols read this task-local policy while constructing that
        // socket; QUIC transports do the same below Quinn.
        ACTIVE_STREAM_POLICY
            .scope(self.policy.clone(), self.inner.dial_udp(ctx))
            .await
    }
}

pub(crate) fn current() -> Option<Arc<ActiveStreamPolicy>> {
    ACTIVE_STREAM_POLICY.try_with(|policy| policy.clone()).ok()
}

/// Invoke a dialer-proxy with a cleared inherited context. A configured proxy
/// installs its own context in `ConfiguredOutbound::dial_tcp`; built-in
/// DIRECT/BLOCK remain empty. Clearing here is what prevents DIRECT from
/// recursively observing the caller's `dialerProxy`.
pub(crate) async fn dial_through_proxy(
    proxy: SharedOutbound,
    host: String,
    port: u16,
) -> std::io::Result<BoxedStream> {
    ACTIVE_STREAM_POLICY
        .scope(
            Arc::new(ActiveStreamPolicy::empty()),
            proxy.dial_tcp(DialContext::tcp(host, port)),
        )
        .await
}

/// UDP counterpart of [`dial_through_proxy`]. Clearing the inherited policy is
/// equally important here: otherwise a DIRECT proxy observes the caller's
/// `dialerProxy` and recursively dials itself.
pub(crate) async fn dial_udp_through_proxy(
    proxy: SharedOutbound,
    host: String,
    port: u16,
) -> std::io::Result<BoxedUdp> {
    ACTIVE_STREAM_POLICY
        .scope(
            Arc::new(ActiveStreamPolicy::empty()),
            proxy.dial_udp(DialContext::udp(host, port)),
        )
        .await
}

/// Run a nested control-plane dial with the same socket policy and registered
/// dialer proxy, but without applying data-plane final masks. Realm's HTTPS
/// rendezvous connection is independent from the UDP carrier and must not be
/// obfuscated as if it were a QUIC packet.
pub(crate) async fn without_finalmask<F>(future: F) -> F::Output
where
    F: std::future::Future,
{
    let Some(parent) = current() else {
        return future.await;
    };
    let mut settings = parent.settings.clone();
    settings.finalmask = None;
    let child = Arc::new(ActiveStreamPolicy::new(settings));
    if let Some(proxy) = parent.proxy() {
        let _ = child.dialer_proxy.set(proxy);
    }
    ACTIVE_STREAM_POLICY.scope(child, future).await
}

#[cfg(test)]
mod tests {
    use core_config::{FinalMaskConfig, MkcpLegacyMaskConfig, QuicParamsConfig, UdpMaskConfig};

    use super::*;

    #[tokio::test]
    async fn configured_udp_mask_is_compiled_before_inner_error() {
        let settings = NodeStreamSettings {
            finalmask: Some(FinalMaskConfig {
                udp: vec![UdpMaskConfig::MkcpLegacy(MkcpLegacyMaskConfig::default())],
                ..Default::default()
            }),
            ..Default::default()
        };
        let (outbound, _) = ConfiguredOutbound::new(crate::block::BlockOutbound::new(), settings);
        let Err(error) = outbound.dial_udp(DialContext::udp("example.com", 53)).await else {
            panic!("UDP finalmask unexpectedly succeeded")
        };
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
    }

    #[tokio::test]
    async fn quic_params_are_available_to_inner_dial_without_generic_rejection() {
        let settings = NodeStreamSettings {
            finalmask: Some(FinalMaskConfig {
                quic_params: Some(QuicParamsConfig::default()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let (outbound, _) = ConfiguredOutbound::new(crate::block::BlockOutbound::new(), settings);
        let Err(error) = outbound
            .dial_tcp(DialContext::tcp("example.com", 443))
            .await
        else {
            panic!("QUIC params unexpectedly succeeded")
        };
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
    }
}
