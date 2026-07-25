//! Xray Hysteria UDP port hopping with one current and one previous socket.
//!
//! The implementation follows `transport/internet/hysteria/udphop/conn.go`
//! from Xray 26.7.11: a random configured port is selected per interval, the
//! preceding socket remains readable for one more hop, and receive buffering
//! is bounded. A fresh socket is opened on every hop so NAT mappings really do
//! change; merely rewriting the destination port on one socket is insufficient.

use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use parking_lot::RwLock;
use rand::{Rng, seq::SliceRandom};
use tokio::{sync::Mutex, task::JoinHandle};

use crate::{
    adapter::{BoxedUdp, SharedOutbound, UdpSocketLike},
    transport::finalmask::quic::UdpHopPlan,
};

const RECEIVE_QUEUE_PACKETS: usize = 1024;
const MAX_PACKET: usize = 4096;

#[derive(Clone)]
struct SocketFactory {
    proxy: Option<SharedOutbound>,
    target_host: Arc<str>,
    target_addr: SocketAddr,
}

impl SocketFactory {
    async fn open(&self, port: u16) -> io::Result<(Arc<dyn UdpSocketLike>, SocketAddr)> {
        let peer = SocketAddr::new(self.target_addr.ip(), port);
        let (socket, local) = if let Some(proxy) = &self.proxy {
            let local = if peer.is_ipv6() {
                "[::]:0".parse().expect("IPv6 wildcard")
            } else {
                "0.0.0.0:0".parse().expect("IPv4 wildcard")
            };
            let socket = crate::socket_policy::dial_udp_through_proxy(
                proxy.clone(),
                self.target_host.to_string(),
                port,
            )
            .await?;
            (socket, local)
        } else {
            super::open_direct_carrier(self.target_host.to_string(), peer)?
        };
        Ok((Arc::from(socket), local))
    }
}

struct HopState {
    current: Arc<dyn UdpSocketLike>,
    previous: Option<Arc<dyn UdpSocketLike>>,
    port: u16,
}

struct ReceivedPacket {
    bytes: Vec<u8>,
    source: Option<SocketAddr>,
}

pub(crate) struct UdpHopCarrier {
    state: Arc<RwLock<HopState>>,
    target_host: Arc<str>,
    receive: Mutex<tokio::sync::mpsc::Receiver<io::Result<ReceivedPacket>>>,
    closed: Arc<AtomicBool>,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl UdpHopCarrier {
    pub(crate) async fn open(
        plan: UdpHopPlan,
        proxy: Option<SharedOutbound>,
        target_host: String,
        target_addr: SocketAddr,
    ) -> io::Result<(BoxedUdp, SocketAddr)> {
        let factory = SocketFactory {
            proxy,
            target_host: target_host.into(),
            target_addr,
        };
        let initial_port = *plan
            .ports
            .choose(&mut rand::thread_rng())
            .ok_or_else(|| invalid("UDP hop has no ports"))?;
        let (initial, local) = factory.open(initial_port).await?;
        let state = Arc::new(RwLock::new(HopState {
            current: initial.clone(),
            previous: None,
            port: initial_port,
        }));
        let closed = Arc::new(AtomicBool::new(false));
        let (receive_tx, receive_rx) = tokio::sync::mpsc::channel(RECEIVE_QUEUE_PACKETS);
        let tasks = Arc::new(Mutex::new(Vec::new()));
        let target_host = factory.target_host.clone();
        tasks
            .lock()
            .await
            .push(spawn_receiver(initial, receive_tx.clone(), closed.clone()));
        tasks.lock().await.push(spawn_hopper(
            plan,
            factory,
            state.clone(),
            receive_tx,
            closed.clone(),
            tasks.clone(),
        ));

        Ok((
            Box::new(Self {
                state,
                target_host,
                receive: Mutex::new(receive_rx),
                closed,
                tasks,
            }),
            local,
        ))
    }
}

fn spawn_receiver(
    socket: Arc<dyn UdpSocketLike>,
    output: tokio::sync::mpsc::Sender<io::Result<ReceivedPacket>>,
    closed: Arc<AtomicBool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = vec![0; MAX_PACKET];
        while !closed.load(Ordering::Acquire) {
            let result = socket
                .recv_from_endpoint(&mut buffer)
                .await
                .map(|(length, source)| ReceivedPacket {
                    bytes: buffer[..length].to_vec(),
                    source,
                });
            let terminal = result.is_err();
            if output.try_send(result).is_err() && terminal {
                return;
            }
            if terminal {
                return;
            }
        }
    })
}

fn spawn_hopper(
    plan: UdpHopPlan,
    factory: SocketFactory,
    state: Arc<RwLock<HopState>>,
    output: tokio::sync::mpsc::Sender<io::Result<ReceivedPacket>>,
    closed: Arc<AtomicBool>,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let interval = random_interval(plan.interval_min, plan.interval_max);
            tokio::select! {
                () = tokio::time::sleep(interval) => {}
                () = wait_closed(closed.clone()) => return,
            }
            if closed.load(Ordering::Acquire) {
                return;
            }
            let port = *plan
                .ports
                .choose(&mut rand::thread_rng())
                .expect("validated non-empty UDP hop ports");
            let Ok((next, _)) = factory.open(port).await else {
                tracing::debug!(
                    port,
                    "UDP hop socket creation failed; retaining current socket"
                );
                continue;
            };
            let obsolete = {
                let mut state = state.write();
                let obsolete = state.previous.take();
                state.previous = Some(state.current.clone());
                state.current = next.clone();
                state.port = port;
                obsolete
            };
            if let Some(obsolete) = obsolete {
                let _ = obsolete.close().await;
            }
            let mut tasks = tasks.lock().await;
            tasks.retain(|task| !task.is_finished());
            tasks.push(spawn_receiver(next, output.clone(), closed.clone()));
        }
    })
}

async fn wait_closed(closed: Arc<AtomicBool>) {
    while !closed.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn random_interval(min: Duration, max: Duration) -> Duration {
    if min == max {
        return min;
    }
    let min_ms = min.as_millis() as u64;
    let max_ms = max.as_millis() as u64;
    Duration::from_millis(rand::thread_rng().gen_range(min_ms..=max_ms))
}

#[async_trait]
impl UdpSocketLike for UdpHopCarrier {
    async fn send_to(&self, payload: &[u8], _target: &str, _port: u16) -> io::Result<usize> {
        if self.closed.load(Ordering::Acquire) {
            return Err(io::ErrorKind::NotConnected.into());
        }
        let (socket, port) = {
            let state = self.state.read();
            (state.current.clone(), state.port)
        };
        // SocketFactory opened this association for the selected port. The
        // configured hostname keeps proxy associations' target checks intact.
        socket.send_to(payload, &self.target_host, port).await
    }

    async fn recv_from(&self, output: &mut [u8]) -> io::Result<usize> {
        self.recv_from_endpoint(output)
            .await
            .map(|(length, _)| length)
    }

    async fn recv_from_endpoint(
        &self,
        output: &mut [u8],
    ) -> io::Result<(usize, Option<SocketAddr>)> {
        let packet = self
            .receive
            .lock()
            .await
            .recv()
            .await
            .ok_or(io::ErrorKind::UnexpectedEof)??;
        if packet.bytes.len() > output.len() {
            return Err(invalid(format!(
                "UDP hop received {} bytes into a {} byte buffer",
                packet.bytes.len(),
                output.len()
            )));
        }
        output[..packet.bytes.len()].copy_from_slice(&packet.bytes);
        Ok((packet.bytes.len(), packet.source))
    }

    async fn close(&self) -> io::Result<()> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let (current, previous) = {
            let state = self.state.read();
            (state.current.clone(), state.previous.clone())
        };
        let _ = current.close().await;
        if let Some(previous) = previous {
            let _ = previous.close().await;
        }
        for task in self.tasks.lock().await.drain(..) {
            task.abort();
        }
        Ok(())
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.state.read().current.local_addr()
    }
}

fn invalid(message: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intervals_stay_inside_inclusive_range() {
        let min = Duration::from_secs(5);
        let max = Duration::from_secs(6);
        for _ in 0..100 {
            let actual = random_interval(min, max);
            assert!(actual >= min && actual <= max);
        }
        assert_eq!(random_interval(min, min), min);
    }
}
