//! TUN UDP NAT association table.
//!
//! The table is the production implementation of `endpoint_independent_nat`:
//! symmetric mode keys associations by `(source, destination)`, while EIM keys
//! them only by the internal source endpoint. Pending dial and established
//! state share one DashMap entry, making first-packet reservation atomic.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use core_observe::ConnectionGuard;
use core_outbound::adapter::BoxedUdp;
use dashmap::{DashMap, mapref::entry::Entry};
use parking_lot::RwLock;
use tokio::sync::{mpsc, watch};

pub const UDP_PENDING_QUEUE_CAPACITY: usize = 64;
pub const UDP_SESSION_QUEUE_CAPACITY: usize = 256;
pub const UDP_EIM_DESTINATION_LIMIT: usize = 1024;

#[derive(Debug)]
pub struct UdpDatagram {
    pub outer_dst: SocketAddr,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct UdpFlowKey {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum UdpNatKey {
    Symmetric(UdpFlowKey),
    EndpointIndependent { src: SocketAddr },
}

impl UdpNatKey {
    pub fn new(src: SocketAddr, dst: SocketAddr, endpoint_independent: bool) -> Self {
        if endpoint_independent {
            Self::EndpointIndependent { src }
        } else {
            Self::Symmetric(UdpFlowKey { src, dst })
        }
    }

    pub fn source(self) -> SocketAddr {
        match self {
            Self::Symmetric(flow) => flow.src,
            Self::EndpointIndependent { src } => src,
        }
    }

    pub fn is_endpoint_independent(self) -> bool {
        matches!(self, Self::EndpointIndependent { .. })
    }
}

#[derive(Debug, Clone)]
struct UdpDestination {
    target_host: String,
    target_port: u16,
}

pub struct UdpSession {
    pub socket: BoxedUdp,
    pub guard: ConnectionGuard,
    destinations: RwLock<HashMap<SocketAddr, UdpDestination>>,
    endpoint_independent: bool,
    sender: mpsc::Sender<UdpDatagram>,
    cancel: watch::Sender<bool>,
    last_seen: AtomicU64,
}

impl UdpSession {
    pub fn new(
        socket: BoxedUdp,
        guard: ConnectionGuard,
        outer_dst: SocketAddr,
        target_host: String,
        target_port: u16,
        endpoint_independent: bool,
        queue_capacity: usize,
    ) -> (Self, mpsc::Receiver<UdpDatagram>) {
        let (sender, receiver) = mpsc::channel(queue_capacity);
        let (cancel, _) = watch::channel(false);
        let mut destinations = HashMap::with_capacity(2);
        destinations.insert(
            outer_dst,
            UdpDestination {
                target_host,
                target_port,
            },
        );
        (
            Self {
                socket,
                guard,
                destinations: RwLock::new(destinations),
                endpoint_independent,
                sender,
                cancel,
                last_seen: AtomicU64::new(activity_tick()),
            },
            receiver,
        )
    }

    pub fn touch(&self) {
        self.last_seen.store(activity_tick(), Ordering::Relaxed);
    }

    fn last_seen(&self) -> u64 {
        self.last_seen.load(Ordering::Relaxed)
    }

    pub fn destination(&self, outer_dst: SocketAddr) -> Option<(String, u16)> {
        self.destinations
            .read()
            .get(&outer_dst)
            .map(|destination| (destination.target_host.clone(), destination.target_port))
    }

    pub fn try_send(
        &self,
        datagram: UdpDatagram,
    ) -> Result<(), mpsc::error::TrySendError<UdpDatagram>> {
        self.sender.try_send(datagram)?;
        self.touch();
        Ok(())
    }

    pub fn cancel(&self) {
        self.cancel.send_replace(true);
        self.guard.cancel.notify_waiters();
    }

    pub fn cancel_receiver(&self) -> watch::Receiver<bool> {
        self.cancel.subscribe()
    }

    pub fn register_destination(
        &self,
        outer_dst: SocketAddr,
        target_host: String,
        target_port: u16,
    ) -> bool {
        let mut destinations = self.destinations.write();
        if !destinations.contains_key(&outer_dst) && destinations.len() >= UDP_EIM_DESTINATION_LIMIT
        {
            return false;
        }
        destinations.insert(
            outer_dst,
            UdpDestination {
                target_host,
                target_port,
            },
        );
        true
    }

    /// Translate a carrier source back to the logical address visible in TUN.
    ///
    /// For direct/IP-aware carriers this is an exact endpoint match. Carriers
    /// that cannot expose a source are safe only while the association has a
    /// single logical destination; ambiguous multi-target replies fail closed.
    pub fn logical_response_source(
        &self,
        transport_source: Option<SocketAddr>,
    ) -> Option<SocketAddr> {
        let destinations = self.destinations.read();
        select_logical_response_source(&destinations, transport_source, self.endpoint_independent)
    }

    pub fn destination_count(&self) -> usize {
        self.destinations.read().len()
    }
}

fn select_logical_response_source(
    destinations: &HashMap<SocketAddr, UdpDestination>,
    transport_source: Option<SocketAddr>,
    endpoint_independent: bool,
) -> Option<SocketAddr> {
    if let Some(source) = transport_source {
        if destinations.contains_key(&source) {
            return Some(source);
        }
        if let Some((logical, _)) = destinations.iter().find(|(_, destination)| {
            destination.target_port == source.port()
                && parse_ip_literal(&destination.target_host) == Some(source.ip())
        }) {
            return Some(*logical);
        }
        let mut same_port = destinations
            .iter()
            .filter(|(_, destination)| destination.target_port == source.port())
            .map(|(logical, _)| *logical);
        if let Some(logical) = same_port.next()
            && same_port.next().is_none()
        {
            // Fake-IP/domain targets do not expose their resolved address
            // to capture. A unique destination port is still sufficient
            // to restore the logical source without leaking the real IP.
            return Some(logical);
        }
        if endpoint_independent {
            return Some(source);
        }
        return None;
    }
    (destinations.len() == 1)
        .then(|| destinations.keys().next().copied())
        .flatten()
}

fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    host.trim()
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host.trim())
        .parse()
        .ok()
}

pub struct PendingUdpSession {
    sender: mpsc::Sender<UdpDatagram>,
    last_seen: AtomicU64,
}

impl PendingUdpSession {
    fn new(capacity: usize) -> (Arc<Self>, mpsc::Receiver<UdpDatagram>) {
        let (sender, receiver) = mpsc::channel(capacity);
        (
            Arc::new(Self {
                sender,
                last_seen: AtomicU64::new(activity_tick()),
            }),
            receiver,
        )
    }

    pub fn try_send(
        &self,
        datagram: UdpDatagram,
    ) -> Result<(), mpsc::error::TrySendError<UdpDatagram>> {
        self.sender.try_send(datagram)?;
        self.touch();
        Ok(())
    }

    fn touch(&self) {
        self.last_seen.store(activity_tick(), Ordering::Relaxed);
    }

    fn last_seen(&self) -> u64 {
        self.last_seen.load(Ordering::Relaxed)
    }
}

enum UdpSessionState {
    Pending(Arc<PendingUdpSession>),
    Established(Arc<UdpSession>),
}

pub enum UdpSessionReservation {
    Pending(Arc<PendingUdpSession>),
    Established(Arc<UdpSession>),
    Created {
        pending: Arc<PendingUdpSession>,
        receiver: mpsc::Receiver<UdpDatagram>,
    },
}

pub struct UdpSessionTable {
    inner: DashMap<UdpNatKey, UdpSessionState>,
    idle_ticks: u64,
}

impl std::fmt::Debug for UdpSessionTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSessionTable")
            .field("len", &self.len())
            .field("pending_len", &self.pending_len())
            .field("idle_ms", &self.idle_ticks)
            .finish()
    }
}

impl UdpSessionTable {
    pub fn new(idle: Duration) -> Self {
        Self {
            inner: DashMap::new(),
            idle_ticks: duration_ticks(idle),
        }
    }

    /// Atomically observe or reserve an association. Exactly one caller gets
    /// `Created`, so packet bursts cannot start duplicate outbound dials.
    pub fn reserve(&self, key: UdpNatKey, capacity: usize) -> UdpSessionReservation {
        match self.inner.entry(key) {
            Entry::Occupied(entry) => match entry.get() {
                UdpSessionState::Pending(pending) => {
                    UdpSessionReservation::Pending(pending.clone())
                }
                UdpSessionState::Established(session) => {
                    UdpSessionReservation::Established(session.clone())
                }
            },
            Entry::Vacant(entry) => {
                let (pending, receiver) = PendingUdpSession::new(capacity);
                entry.insert(UdpSessionState::Pending(pending.clone()));
                UdpSessionReservation::Created { pending, receiver }
            }
        }
    }

    pub fn promote(
        &self,
        key: UdpNatKey,
        pending: &Arc<PendingUdpSession>,
        session: Arc<UdpSession>,
    ) -> bool {
        let Entry::Occupied(mut entry) = self.inner.entry(key) else {
            return false;
        };
        let matches = matches!(
            entry.get(),
            UdpSessionState::Pending(current) if Arc::ptr_eq(current, pending)
        );
        if matches {
            entry.insert(UdpSessionState::Established(session));
        }
        matches
    }

    pub fn remove_pending_if(&self, key: UdpNatKey, pending: &Arc<PendingUdpSession>) {
        if let Entry::Occupied(entry) = self.inner.entry(key)
            && matches!(
                entry.get(),
                UdpSessionState::Pending(current) if Arc::ptr_eq(current, pending)
            )
        {
            entry.remove();
        }
    }

    pub fn remove_session_if(&self, key: UdpNatKey, session: &Arc<UdpSession>) {
        if let Entry::Occupied(entry) = self.inner.entry(key)
            && matches!(
                entry.get(),
                UdpSessionState::Established(current) if Arc::ptr_eq(current, session)
            )
        {
            entry.remove();
            session.cancel();
        }
    }

    pub fn len(&self) -> usize {
        self.inner
            .iter()
            .filter(|entry| matches!(entry.value(), UdpSessionState::Established(_)))
            .count()
    }

    pub fn pending_len(&self) -> usize {
        self.inner
            .iter()
            .filter(|entry| matches!(entry.value(), UdpSessionState::Pending(_)))
            .count()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn purge(&self) -> usize {
        let cutoff = activity_tick().saturating_sub(self.idle_ticks);
        let keys = self
            .inner
            .iter()
            .filter_map(|entry| {
                let last_seen = match entry.value() {
                    UdpSessionState::Pending(pending) => pending.last_seen(),
                    UdpSessionState::Established(session) => session.last_seen(),
                };
                (last_seen <= cutoff).then_some(*entry.key())
            })
            .collect::<Vec<_>>();
        let mut removed = 0;
        for key in keys {
            if let Entry::Occupied(entry) = self.inner.entry(key) {
                let last_seen = match entry.get() {
                    UdpSessionState::Pending(pending) => pending.last_seen(),
                    UdpSessionState::Established(session) => session.last_seen(),
                };
                if last_seen <= cutoff {
                    let (_, state) = entry.remove_entry();
                    if let UdpSessionState::Established(session) = state {
                        session.cancel();
                    }
                    removed += 1;
                }
            }
        }
        removed
    }

    /// Cancel every association, for example after the physical outbound
    /// interface changes and existing bound UDP sockets are no longer valid.
    pub fn clear(&self) -> usize {
        let keys = self
            .inner
            .iter()
            .map(|entry| *entry.key())
            .collect::<Vec<_>>();
        let mut removed = 0;
        for key in keys {
            if let Some((_, state)) = self.inner.remove(&key) {
                if let UdpSessionState::Established(session) = state {
                    session.cancel();
                }
                removed += 1;
            }
        }
        removed
    }
}

fn activity_tick() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let elapsed = EPOCH.get_or_init(Instant::now).elapsed().as_millis();
    elapsed.min(u64::MAX as u128) as u64 + 1
}

fn duration_ticks(duration: Duration) -> u64 {
    duration.as_millis().max(1).min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(src_port: u16, dst_port: u16, eim: bool) -> UdpNatKey {
        UdpNatKey::new(
            format!("10.0.0.1:{src_port}").parse().unwrap(),
            format!("8.8.8.8:{dst_port}").parse().unwrap(),
            eim,
        )
    }

    #[test]
    fn eim_key_ignores_destination_but_symmetric_key_does_not() {
        assert_eq!(key(5000, 53, true), key(5000, 443, true));
        assert_ne!(key(5000, 53, false), key(5000, 443, false));
    }

    #[test]
    fn reservation_is_atomic_and_reuses_pending_entry() {
        let table = UdpSessionTable::new(Duration::from_secs(60));
        let key = key(5000, 53, true);
        let first = table.reserve(key, 2);
        let second = table.reserve(key, 2);
        let UdpSessionReservation::Created { pending, .. } = first else {
            panic!("first reservation must create");
        };
        let UdpSessionReservation::Pending(existing) = second else {
            panic!("second reservation must reuse pending");
        };
        assert!(Arc::ptr_eq(&pending, &existing));
        assert_eq!(table.pending_len(), 1);
    }

    #[test]
    fn concurrent_burst_has_exactly_one_dial_owner() {
        let table = Arc::new(UdpSessionTable::new(Duration::from_secs(60)));
        let key = key(5001, 3478, true);
        let owners = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        std::thread::scope(|scope| {
            for _ in 0..32 {
                let table = table.clone();
                let owners = owners.clone();
                scope.spawn(move || {
                    if matches!(
                        table.reserve(key, UDP_PENDING_QUEUE_CAPACITY),
                        UdpSessionReservation::Created { .. }
                    ) {
                        owners.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });
        assert_eq!(owners.load(Ordering::Relaxed), 1);
        assert_eq!(table.pending_len(), 1);
    }

    #[tokio::test]
    async fn pending_queue_buffers_packets() {
        let table = UdpSessionTable::new(Duration::from_secs(60));
        let key = key(5000, 443, false);
        let UdpSessionReservation::Created {
            pending,
            mut receiver,
        } = table.reserve(key, 2)
        else {
            panic!("must create");
        };
        pending
            .try_send(UdpDatagram {
                outer_dst: "8.8.8.8:443".parse().unwrap(),
                payload: vec![1, 2, 3],
            })
            .unwrap();
        assert_eq!(receiver.recv().await.unwrap().payload, vec![1, 2, 3]);
        table.remove_pending_if(key, &pending);
        assert!(table.is_empty());
    }

    #[test]
    fn purge_expires_idle_pending_association() {
        let table = UdpSessionTable::new(Duration::from_millis(5));
        let _ = table.reserve(key(5002, 443, false), 1);
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(table.purge(), 1);
        assert!(table.is_empty());
    }

    #[test]
    fn clear_removes_pending_associations_immediately() {
        let table = UdpSessionTable::new(Duration::from_secs(60));
        let _ = table.reserve(key(5003, 443, true), 1);
        assert_eq!(table.clear(), 1);
        assert!(table.is_empty());
    }

    #[test]
    fn endpoint_filtering_is_full_cone_only_in_eim_mode() {
        let known: SocketAddr = "198.51.100.1:3478".parse().unwrap();
        let unsolicited: SocketAddr = "203.0.113.7:5000".parse().unwrap();
        let mut destinations = HashMap::new();
        destinations.insert(
            known,
            UdpDestination {
                target_host: known.ip().to_string(),
                target_port: known.port(),
            },
        );
        assert_eq!(
            select_logical_response_source(&destinations, Some(unsolicited), true),
            Some(unsolicited)
        );
        assert_eq!(
            select_logical_response_source(&destinations, Some(unsolicited), false),
            None
        );
    }

    #[test]
    fn fake_ip_response_is_restored_when_target_port_is_unambiguous() {
        let fake: SocketAddr = "198.18.0.10:443".parse().unwrap();
        let real: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let mut destinations = HashMap::new();
        destinations.insert(
            fake,
            UdpDestination {
                target_host: "example.test".into(),
                target_port: 443,
            },
        );
        assert_eq!(
            select_logical_response_source(&destinations, Some(real), true),
            Some(fake)
        );
    }
}
