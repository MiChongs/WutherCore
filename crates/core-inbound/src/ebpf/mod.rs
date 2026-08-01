//! Aya-based Linux and Android root inbound.
//!
//! The data plane is independent from the legacy capture subsystem:
//! cgroup socket-address programs select eligible local TCP/UDP sockets,
//! a TC ingress classifier selects hotspot and forwarded-device traffic,
//! policy routing feeds marked packets back into the local transport lookup,
//! and an `sk_lookup` program assigns them directly to proxy-owned sockets.

mod aya_runtime;
mod capability;
mod relay;
mod route;
mod ruleset;
mod socket;

use std::{sync::Arc, time::Duration};

use core_config::model::EbpfInboundOptions;
use core_runtime::Runtime;
use thiserror::Error;
use tokio::{
    sync::{oneshot, watch},
    task::{JoinHandle, JoinSet},
};
use tracing::{info, warn};

pub use aya_runtime::EbpfStats;
pub use capability::{EbpfBpfAuthority, EbpfCapabilityReport, EbpfMemlockStatus};

use aya_runtime::AyaDataPlane;
use route::PolicyRoute;

#[derive(Debug, Clone, Default)]
pub struct BypassPrefixSnapshot {
    pub revision: u64,
    pub ipv4: Arc<Vec<ipnet::Ipv4Net>>,
    pub ipv6: Arc<Vec<ipnet::Ipv6Net>>,
}

pub trait EbpfRuleSetProvider: Send + Sync + std::fmt::Debug {
    /// Return one atomic, fully ready merged prefix snapshot.
    ///
    /// Missing, pending, non-IP, oversized, or invalid rule sets must be
    /// reported as an error. The running data plane keeps its previous snapshot
    /// on refresh errors.
    fn snapshot(&self, names: &[String]) -> Result<BypassPrefixSnapshot, String>;

    fn subscribe(&self) -> Option<watch::Receiver<u64>> {
        None
    }

    fn snapshot_and_subscribe(
        &self,
        names: &[String],
    ) -> Result<(BypassPrefixSnapshot, watch::Receiver<u64>), String> {
        let snapshot = self.snapshot(names)?;
        let receiver = self
            .subscribe()
            .ok_or_else(|| "rule-set provider does not support updates".to_owned())?;
        Ok((snapshot, receiver))
    }
}

#[derive(Debug, Error)]
pub enum EbpfInboundError {
    #[error("eBPF inbound configuration error: {0}")]
    Configuration(String),
    #[error("Aya eBPF error: {0}")]
    Aya(String),
    #[error("eBPF capability error: {0}")]
    Capability(String),
    #[error("eBPF socket error: {0}")]
    Socket(String),
    #[error("eBPF policy-route error: {0}")]
    Route(String),
    #[error("eBPF rule-set error: {0}")]
    RuleSet(String),
    #[error("eBPF controller task failed: {0}")]
    Task(String),
}

#[derive(Debug, Clone)]
pub struct EbpfInboundStatus {
    pub tag: String,
    pub running: bool,
    pub anchors: Vec<std::net::SocketAddr>,
    pub shared_interfaces: Vec<String>,
    pub rule_set_revision: u64,
    pub capabilities: EbpfCapabilityReport,
    pub stats: EbpfStats,
}

pub struct EbpfInboundHandle {
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<(), EbpfInboundError>>>,
    status: watch::Receiver<EbpfInboundStatus>,
}

impl EbpfInboundHandle {
    pub fn status(&self) -> EbpfInboundStatus {
        self.status.borrow().clone()
    }

    pub fn subscribe_status(&self) -> watch::Receiver<EbpfInboundStatus> {
        self.status.clone()
    }

    pub async fn shutdown(mut self) -> Result<(), EbpfInboundError> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.task
            .take()
            .expect("eBPF inbound task is present")
            .await
            .map_err(|error| EbpfInboundError::Task(error.to_string()))?
    }
}

impl Drop for EbpfInboundHandle {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

pub async fn start_ebpf_inbound(
    options: EbpfInboundOptions,
    runtime: Arc<Runtime>,
    provider: Option<Arc<dyn EbpfRuleSetProvider>>,
) -> Result<EbpfInboundHandle, EbpfInboundError> {
    if !options.enabled {
        return Err(EbpfInboundError::Configuration(
            "cannot start a disabled eBPF inbound".into(),
        ));
    }
    let (snapshot, updates) = initial_snapshot(&options, provider.as_deref())?;
    let mut plane = AyaDataPlane::load(&options, &snapshot)?;
    let (tcp, udp, anchors) = plane.take_sockets()?;
    plane.attach_lookup(options.shared_network.tc_priority)?;

    let has_ipv4 = options
        .redirect_address
        .iter()
        .any(|value| matches!(value.parse::<ipnet::IpNet>(), Ok(ipnet::IpNet::V4(_))));
    let has_ipv6 = options
        .redirect_address
        .iter()
        .any(|value| matches!(value.parse::<ipnet::IpNet>(), Ok(ipnet::IpNet::V6(_))));
    let policy = match PolicyRoute::install(
        &options.capabilities,
        options.mark,
        options.route_table,
        options.rule_priority,
        has_ipv4,
        has_ipv6,
    )
    .await
    {
        Ok(policy) => policy,
        Err(error) => {
            let _ = plane.detach_lookup();
            return Err(error);
        }
    };
    let shared_interfaces = match plane.reconcile_shared_interfaces(&options.shared_network) {
        Ok(interfaces) => interfaces,
        Err(error) => {
            let _ = plane.detach_shared_interfaces();
            policy.remove().await;
            let _ = plane.detach_lookup();
            return Err(error);
        }
    };
    if let Err(error) = plane.attach_cgroup(&options.cgroup_path) {
        let _ = plane.detach_cgroup();
        let _ = plane.detach_shared_interfaces();
        policy.remove().await;
        let _ = plane.detach_lookup();
        return Err(error);
    }

    let (relay_stop_tx, relay_stop_rx) = watch::channel(false);
    let mut relays = JoinSet::new();
    let tag: Arc<str> = Arc::from(options.tag.as_str());
    let hijack_dns = matches!(
        options.resolver,
        core_config::model::CaptureResolver::Hijack
    );
    for listener in tcp {
        relays.spawn(relay::run_tcp(
            listener,
            runtime.clone(),
            tag.clone(),
            hijack_dns,
            relay_stop_rx.clone(),
        ));
    }
    for socket in udp {
        relays.spawn(relay::run_udp(
            socket,
            runtime.clone(),
            tag.clone(),
            hijack_dns,
            relay_stop_rx.clone(),
        ));
    }

    let initial_stats = plane.stats().unwrap_or_default();
    let capabilities = plane.capability_report().clone();
    let initial_status = EbpfInboundStatus {
        tag: options.tag.clone(),
        running: true,
        anchors: anchors.clone(),
        shared_interfaces: shared_interfaces.clone(),
        rule_set_revision: snapshot.revision,
        capabilities: capabilities.clone(),
        stats: initial_stats,
    };
    let (status_tx, status_rx) = watch::channel(initial_status);
    let (stop_tx, stop_rx) = oneshot::channel();
    let task = tokio::spawn(run_controller(
        options,
        provider,
        updates,
        plane,
        policy,
        relays,
        relay_stop_tx,
        stop_rx,
        status_tx,
        anchors.clone(),
        capabilities,
    ));
    info!(
        target: "inbound::ebpf",
        tag = %tag,
        ?anchors,
        ?shared_interfaces,
        revision = snapshot.revision,
        "Aya eBPF inbound started"
    );
    Ok(EbpfInboundHandle {
        stop: Some(stop_tx),
        task: Some(task),
        status: status_rx,
    })
}

fn initial_snapshot(
    options: &EbpfInboundOptions,
    provider: Option<&dyn EbpfRuleSetProvider>,
) -> Result<(BypassPrefixSnapshot, Option<watch::Receiver<u64>>), EbpfInboundError> {
    if options.bypass_rule_set.is_empty() {
        return Ok((BypassPrefixSnapshot::default(), None));
    }
    let provider = provider.ok_or_else(|| {
        EbpfInboundError::RuleSet(
            "bypass_rule_set is configured but no rule-set provider was supplied".into(),
        )
    })?;
    match provider.snapshot_and_subscribe(&options.bypass_rule_set) {
        Ok((snapshot, updates)) => Ok((snapshot, Some(updates))),
        Err(error) => Err(EbpfInboundError::RuleSet(error)),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_controller(
    options: EbpfInboundOptions,
    provider: Option<Arc<dyn EbpfRuleSetProvider>>,
    mut updates: Option<watch::Receiver<u64>>,
    mut plane: AyaDataPlane,
    policy: PolicyRoute,
    mut relays: JoinSet<()>,
    relay_stop: watch::Sender<bool>,
    mut stop: oneshot::Receiver<()>,
    status: watch::Sender<EbpfInboundStatus>,
    anchors: Vec<std::net::SocketAddr>,
    capabilities: EbpfCapabilityReport,
) -> Result<(), EbpfInboundError> {
    let mut stats_tick = tokio::time::interval(Duration::from_secs(10));
    stats_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut interface_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + options.shared_network.interface_refresh_interval,
        options.shared_network.interface_refresh_interval,
    );
    interface_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut revision = status.borrow().rule_set_revision;
    loop {
        tokio::select! {
            biased;
            _ = &mut stop => break,
            _ = stats_tick.tick() => {
                if let Ok(stats) = plane.stats() {
                    status.send_modify(|current| current.stats = stats);
                }
            }
            _ = interface_tick.tick(), if options.shared_network.enabled => {
                match plane.reconcile_shared_interfaces(&options.shared_network) {
                    Ok(interfaces) => {
                        let changed = status.borrow().shared_interfaces != interfaces;
                        if changed {
                            status.send_modify(|current| current.shared_interfaces = interfaces);
                        }
                    }
                    Err(error) => warn!(
                        target: "inbound::ebpf",
                        %error,
                        "failed to reconcile shared-network eBPF interfaces"
                    ),
                }
            }
            changed = async {
                match updates.as_mut() {
                    Some(receiver) => receiver.changed().await,
                    None => std::future::pending().await,
                }
            } => {
                if changed.is_err() {
                    updates = None;
                    continue;
                }
                let Some(provider) = provider.as_deref() else {
                    continue;
                };
                match provider.snapshot(&options.bypass_rule_set) {
                    Ok(snapshot) => match plane.replace_bypass(&options, &snapshot) {
                        Ok(()) => {
                            revision = snapshot.revision;
                            status.send_modify(|current| current.rule_set_revision = revision);
                        }
                        Err(error) => warn!(
                            target: "inbound::ebpf",
                            %error,
                            "failed to synchronize eBPF bypass maps; keeping previous snapshot"
                        ),
                    },
                    Err(error) => warn!(
                        target: "inbound::ebpf",
                        %error,
                        "rule-set snapshot rejected; keeping previous eBPF bypass maps"
                    ),
                }
            }
            joined = relays.join_next(), if !relays.is_empty() => {
                if let Some(Err(error)) = joined {
                    warn!(target: "inbound::ebpf", %error, "eBPF relay task failed");
                }
            }
        }
    }

    let shared_detach_result = plane.detach_shared_interfaces();
    let detach_result = plane.detach_cgroup();
    policy.remove().await;
    let lookup_result = plane.detach_lookup();
    let _ = relay_stop.send(true);
    relays.shutdown().await;
    let stats = plane.stats().unwrap_or_default();
    let _ = status.send(EbpfInboundStatus {
        tag: options.tag.clone(),
        running: false,
        anchors,
        shared_interfaces: plane.shared_interfaces(),
        rule_set_revision: revision,
        capabilities,
        stats,
    });
    shared_detach_result?;
    detach_result?;
    lookup_result?;
    info!(target: "inbound::ebpf", tag = %options.tag, "Aya eBPF inbound stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct StaticProvider(BypassPrefixSnapshot);

    impl EbpfRuleSetProvider for StaticProvider {
        fn snapshot(&self, _names: &[String]) -> Result<BypassPrefixSnapshot, String> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn empty_bypass_does_not_require_provider() {
        let options: EbpfInboundOptions = serde_json::from_value(serde_json::json!({})).unwrap();
        let (snapshot, updates) = initial_snapshot(&options, None).unwrap();
        assert_eq!(snapshot.revision, 0);
        assert!(updates.is_none());
    }

    #[test]
    fn configured_bypass_requires_atomic_updates() {
        let mut options: EbpfInboundOptions =
            serde_json::from_value(serde_json::json!({"bypass_rule_set": ["cnip"]})).unwrap();
        options.enabled = true;
        let provider = StaticProvider(BypassPrefixSnapshot::default());
        let error = initial_snapshot(&options, Some(&provider)).unwrap_err();
        assert!(error.to_string().contains("does not support updates"));
    }
}
