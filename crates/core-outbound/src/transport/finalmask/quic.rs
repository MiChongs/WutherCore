//! Execution of Xray 26.7.11 `finalmask.quicParams` on Quinn.
//!
//! Xray source of truth:
//! `transport/internet/hysteria/dialer.go` at
//! `6e3322d219140a025285ded1114fe17a5edb74d8`.

use std::{
    any::Any,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use core_config::{BandwidthValue, PortListValue, QuicParamsConfig};
use quinn::{ClientConfig, IdleTimeout, ServerConfig, TransportConfig, VarInt};
use quinn_proto::{
    RttEstimator,
    congestion::{BbrConfig, Controller, ControllerFactory, NewRenoConfig},
};
use rsteria2::BrutalFactory;

const DEFAULT_STREAM_WINDOW: u64 = 8 * 1024 * 1024;
const DEFAULT_CONNECTION_WINDOW: u64 = DEFAULT_STREAM_WINDOW * 5 / 2;
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_HOP_INTERVAL: Duration = Duration::from_secs(30);
const MIN_BRUTAL_RATE: u64 = 65_536;

/// Values Quinn needs after the endpoint has been created.
#[derive(Debug, Clone)]
pub struct AppliedQuicParams {
    pub(crate) congestion: CongestionMode,
    pub(crate) brutal_up: u64,
    pub(crate) brutal_down: u64,
    pub(crate) udp_hop: Option<UdpHopPlan>,
    /// Quinn exposes a live connection-level receive window setter. The
    /// configured maximum is applied after the handshake when it differs from
    /// the initial transport parameter.
    pub(crate) max_connection_receive_window: Option<VarInt>,
    switch: Option<SwitchHandle>,
    local_brutal_rate: u64,
}

impl AppliedQuicParams {
    /// Complete Xray's `brutal` negotiation after Hysteria's auth response.
    /// `server_rx` is the peer's advertised receive bandwidth in bytes/sec.
    pub fn finish_hysteria_negotiation(&self, peer_rx: u64) {
        let Some(switch) = &self.switch else {
            return;
        };
        if self.local_brutal_rate == 0 || peer_rx == 0 {
            switch.use_bbr.store(true, Ordering::Release);
            return;
        }
        switch
            .rate
            .store(self.local_brutal_rate.min(peer_rx), Ordering::Release);
        switch.use_bbr.store(false, Ordering::Release);
    }

    pub fn congestion_mode(&self) -> CongestionMode {
        self.congestion
    }

    pub fn brutal_up(&self) -> u64 {
        self.brutal_up
    }

    pub fn brutal_down(&self) -> u64 {
        self.brutal_down
    }

    pub fn udp_hop(&self) -> Option<&UdpHopPlan> {
        self.udp_hop.as_ref()
    }

    pub fn apply_max_receive_window(&self, connection: &quinn::Connection) {
        if let Some(window) = self.max_connection_receive_window {
            connection.set_receive_window(window);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionMode {
    Reno,
    Bbr,
    Brutal,
    ForceBrutal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpHopPlan {
    pub ports: Vec<u16>,
    pub interval_min: Duration,
    pub interval_max: Duration,
}

#[derive(Debug, Clone)]
struct SwitchHandle {
    rate: Arc<AtomicU64>,
    use_bbr: Arc<AtomicBool>,
}

/// Apply every Quinn-representable field and return the carrier-level fields.
pub fn apply_client_config(
    client: &mut ClientConfig,
    params: Option<&QuicParamsConfig>,
) -> io::Result<AppliedQuicParams> {
    let (transport, applied) = build_transport_config(params, false)?;
    client.transport_config(Arc::new(transport));
    Ok(applied)
}

/// Apply the same pinned Xray QUIC parameters to a Quinn server endpoint.
/// Hysteria servers should call [`AppliedQuicParams::finish_hysteria_negotiation`]
/// after authentication with the client's advertised receive rate.
pub fn apply_server_config(
    server: &mut ServerConfig,
    params: Option<&QuicParamsConfig>,
) -> io::Result<AppliedQuicParams> {
    let (transport, applied) = build_transport_config(params, true)?;
    server.transport_config(Arc::new(transport));
    Ok(applied)
}

/// Apply the XHTTP/3 server interpretation of Xray's shared QUIC parameters.
/// XHTTP has no Hysteria bandwidth negotiation: empty/`bbr` selects BBR and
/// `force-brutal` uses `brutalUp` immediately, exactly like SplitHTTP's
/// `QListener`.  Explicit `brutal` is rejected instead of reaching Xray's
/// transport-specific panic branch.
pub fn apply_xhttp_server_config(
    server: &mut ServerConfig,
    params: Option<&QuicParamsConfig>,
    default_idle_timeout: Duration,
    max_concurrent_streams: u32,
) -> io::Result<AppliedQuicParams> {
    let (mut transport, mut applied) = build_transport_config(params, true)?;
    let owned_default;
    let params = match params {
        Some(params) => params,
        None => {
            owned_default = QuicParamsConfig::default();
            &owned_default
        }
    };
    match params.congestion.trim().to_ascii_lowercase().as_str() {
        "reno" => {
            applied.congestion = CongestionMode::Reno;
            applied.switch = None;
        }
        "" | "bbr" => {
            transport
                .congestion_controller_factory(BbrProfile::parse(&params.bbr_profile)?.factory());
            applied.congestion = CongestionMode::Bbr;
            applied.switch = None;
            applied.local_brutal_rate = 0;
        }
        "force-brutal" => {
            let rate = parse_bandwidth(&params.brutal_up)?;
            if rate < MIN_BRUTAL_RATE {
                return Err(invalid(
                    "XHTTP quicParams force-brutal requires brutalUp >= 65536 bytes/s",
                ));
            }
            transport.congestion_controller_factory(Arc::new(BrutalFactory {
                rate: Arc::new(AtomicU64::new(rate)),
            }));
            applied.congestion = CongestionMode::ForceBrutal;
            applied.switch = None;
            applied.local_brutal_rate = rate;
        }
        "brutal" => {
            return Err(invalid(
                "XHTTP/3 does not negotiate quicParams.congestion=brutal; use bbr, reno or force-brutal",
            ));
        }
        other => return Err(invalid(format!("unknown QUIC congestion `{other}`"))),
    }
    if params.max_idle_timeout == 0 {
        transport
            .max_idle_timeout(Some(IdleTimeout::try_from(default_idle_timeout).map_err(
                |_| invalid("XHTTP listener idle timeout exceeds QUIC's range"),
            )?));
    }
    let configured_streams = if params.max_incoming_streams == 0 {
        u64::from(max_concurrent_streams)
    } else {
        (params.max_incoming_streams as u64).min(u64::from(max_concurrent_streams))
    };
    transport
        .max_concurrent_bidi_streams(varint(configured_streams, "XHTTP max incoming streams")?);
    server.transport_config(Arc::new(transport));
    Ok(applied)
}

/// Apply the client-side XHTTP/3 interpretation.  XHTTP uses a 300-second
/// default idle timeout and its XMUX keepalive when quicParams leaves those
/// values at zero; congestion selection otherwise mirrors the server path.
pub fn apply_xhttp_client_config(
    client: &mut ClientConfig,
    params: &QuicParamsConfig,
    default_keep_alive: Option<Duration>,
) -> io::Result<AppliedQuicParams> {
    let (mut transport, mut applied) = build_transport_config(Some(params), false)?;
    match params.congestion.trim().to_ascii_lowercase().as_str() {
        "reno" => {
            applied.congestion = CongestionMode::Reno;
            applied.switch = None;
        }
        "" | "bbr" => {
            transport
                .congestion_controller_factory(BbrProfile::parse(&params.bbr_profile)?.factory());
            applied.congestion = CongestionMode::Bbr;
            applied.switch = None;
            applied.local_brutal_rate = 0;
        }
        "force-brutal" => {
            let rate = parse_bandwidth(&params.brutal_up)?;
            if rate < MIN_BRUTAL_RATE {
                return Err(invalid(
                    "XHTTP quicParams force-brutal requires brutalUp >= 65536 bytes/s",
                ));
            }
            transport.congestion_controller_factory(Arc::new(BrutalFactory {
                rate: Arc::new(AtomicU64::new(rate)),
            }));
            applied.congestion = CongestionMode::ForceBrutal;
            applied.switch = None;
            applied.local_brutal_rate = rate;
        }
        "brutal" => {
            return Err(invalid(
                "XHTTP/3 does not negotiate quicParams.congestion=brutal; use bbr, reno or force-brutal",
            ));
        }
        other => return Err(invalid(format!("unknown QUIC congestion `{other}`"))),
    }
    if params.max_idle_timeout == 0 {
        transport.max_idle_timeout(Some(
            IdleTimeout::try_from(Duration::from_secs(300))
                .expect("300 seconds is a valid QUIC idle timeout"),
        ));
    }
    if params.keep_alive_period == 0 {
        transport.keep_alive_interval(default_keep_alive);
    }
    if params.max_incoming_streams > 0 {
        transport.max_concurrent_bidi_streams(varint(
            params.max_incoming_streams as u64,
            "XHTTP max incoming streams",
        )?);
    }
    client.transport_config(Arc::new(transport));
    Ok(applied)
}

fn build_transport_config(
    params: Option<&QuicParamsConfig>,
    server_side: bool,
) -> io::Result<(TransportConfig, AppliedQuicParams)> {
    let owned_default;
    let params = match params {
        Some(value) => value,
        None => {
            owned_default = QuicParamsConfig::default();
            &owned_default
        }
    };
    validate_params(params)?;

    let brutal_up = parse_bandwidth(&params.brutal_up)?;
    let brutal_down = parse_bandwidth(&params.brutal_down)?;
    let local_brutal_rate = if server_side { brutal_down } else { brutal_up };
    if (brutal_up != 0 && brutal_up < MIN_BRUTAL_RATE)
        || (brutal_down != 0 && brutal_down < MIN_BRUTAL_RATE)
    {
        return Err(invalid(
            "quicParams brutal bandwidth must be zero or at least 65536 bytes/s",
        ));
    }

    let congestion = match params.congestion.trim().to_ascii_lowercase().as_str() {
        "reno" => CongestionMode::Reno,
        "bbr" => CongestionMode::Bbr,
        "force-brutal" => {
            if brutal_up == 0 {
                return Err(invalid("quicParams force-brutal requires brutalUp"));
            }
            CongestionMode::ForceBrutal
        }
        "" | "brutal" => CongestionMode::Brutal,
        other => return Err(invalid(format!("unknown QUIC congestion `{other}`"))),
    };

    let stream_initial = nonzero_or(params.init_stream_receive_window, DEFAULT_STREAM_WINDOW);
    let stream_max = nonzero_or(params.max_stream_receive_window, DEFAULT_STREAM_WINDOW);
    let connection_initial = nonzero_or(
        params.init_connection_receive_window,
        DEFAULT_CONNECTION_WINDOW,
    );
    let connection_max = nonzero_or(
        params.max_connection_receive_window,
        DEFAULT_CONNECTION_WINDOW,
    );

    let mut transport = TransportConfig::default();
    // Quinn has one per-stream window rather than quic-go's initial+autotuned
    // pair. Advertising the larger configured value preserves the declared
    // maximum and prevents a smaller initial value from becoming a hard cap.
    transport.stream_receive_window(varint(stream_initial.max(stream_max), "stream window")?);
    transport.receive_window(varint(connection_initial, "connection window")?);
    transport.max_idle_timeout(Some(
        IdleTimeout::try_from(if params.max_idle_timeout == 0 {
            DEFAULT_IDLE_TIMEOUT
        } else {
            Duration::from_secs(params.max_idle_timeout as u64)
        })
        .map_err(|_| invalid("quicParams maxIdleTimeout is too large"))?,
    ));
    transport.keep_alive_interval(
        (!server_side && params.keep_alive_period > 0)
            .then(|| Duration::from_secs(params.keep_alive_period as u64)),
    );
    if params.disable_path_mtu_discovery
        || !cfg!(any(
            target_os = "linux",
            target_os = "windows",
            target_os = "macos"
        ))
    {
        transport.mtu_discovery_config(None);
    }
    if server_side {
        transport.max_concurrent_bidi_streams(varint(
            if params.max_incoming_streams == 0 {
                1024
            } else {
                params.max_incoming_streams as u64
            },
            "max incoming streams",
        )?);
    }
    // Hysteria uses QUIC datagrams. Match the existing implementation's
    // bounded buffers while keeping this executor usable by H3/XHTTP.
    transport
        .datagram_receive_buffer_size(Some(16 * 1024 * 1024))
        .datagram_send_buffer_size(16 * 1024 * 1024);

    let profile = BbrProfile::parse(&params.bbr_profile)?;
    let switch = match congestion {
        CongestionMode::Reno => {
            transport.congestion_controller_factory(Arc::new(NewRenoConfig::default()));
            None
        }
        CongestionMode::Bbr => {
            transport.congestion_controller_factory(profile.factory());
            None
        }
        CongestionMode::ForceBrutal => {
            let rate = Arc::new(AtomicU64::new(local_brutal_rate));
            transport.congestion_controller_factory(Arc::new(BrutalFactory { rate }));
            None
        }
        CongestionMode::Brutal => {
            let rate = Arc::new(AtomicU64::new(local_brutal_rate.max(MIN_BRUTAL_RATE)));
            let use_bbr = Arc::new(AtomicBool::new(local_brutal_rate == 0));
            transport.congestion_controller_factory(Arc::new(SwitchableFactory {
                rate: rate.clone(),
                use_bbr: use_bbr.clone(),
                bbr: profile.factory(),
            }));
            Some(SwitchHandle { rate, use_bbr })
        }
    };

    if params.debug {
        tracing::debug!(
            ?congestion,
            ?profile,
            brutal_up,
            brutal_down,
            stream_initial,
            stream_max,
            connection_initial,
            connection_max,
            "finalmask QUIC debug enabled"
        );
    }

    Ok((
        transport,
        AppliedQuicParams {
            congestion,
            brutal_up,
            brutal_down,
            udp_hop: build_udp_hop(params)?,
            max_connection_receive_window: (connection_max != connection_initial)
                .then(|| varint(connection_max, "max connection window"))
                .transpose()?,
            switch,
            local_brutal_rate,
        },
    ))
}

fn build_udp_hop(params: &QuicParamsConfig) -> io::Result<Option<UdpHopPlan>> {
    let ports = parse_ports(&params.udp_hop.ports)?;
    if ports.is_empty() {
        return Ok(None);
    }
    let min = if params.udp_hop.interval.from == 0 {
        DEFAULT_HOP_INTERVAL.as_secs() as i32
    } else {
        params.udp_hop.interval.from
    };
    let max = if params.udp_hop.interval.to == 0 {
        DEFAULT_HOP_INTERVAL.as_secs() as i32
    } else {
        params.udp_hop.interval.to
    };
    if min < 5 || max < min {
        return Err(invalid(
            "quicParams udpHop interval must be an ordered range >= 5s",
        ));
    }
    Ok(Some(UdpHopPlan {
        ports,
        interval_min: Duration::from_secs(min as u64),
        interval_max: Duration::from_secs(max as u64),
    }))
}

fn validate_params(params: &QuicParamsConfig) -> io::Result<()> {
    for (field, value) in [
        ("initStreamReceiveWindow", params.init_stream_receive_window),
        ("maxStreamReceiveWindow", params.max_stream_receive_window),
        (
            "initConnectionReceiveWindow",
            params.init_connection_receive_window,
        ),
        (
            "maxConnectionReceiveWindow",
            params.max_connection_receive_window,
        ),
    ] {
        if value != 0 && value < 16_384 {
            return Err(invalid(format!(
                "quicParams {field} must be zero or at least 16384"
            )));
        }
    }
    if params.max_idle_timeout != 0 && !(4..=120).contains(&params.max_idle_timeout) {
        return Err(invalid(
            "quicParams maxIdleTimeout must be zero or between 4 and 120 seconds",
        ));
    }
    if params.keep_alive_period != 0 && !(2..=60).contains(&params.keep_alive_period) {
        return Err(invalid(
            "quicParams keepAlivePeriod must be zero or between 2 and 60 seconds",
        ));
    }
    if params.max_incoming_streams != 0 && params.max_incoming_streams < 8 {
        return Err(invalid(
            "quicParams maxIncomingStreams must be zero or at least 8",
        ));
    }
    for endpoint in [params.udp_hop.interval.from, params.udp_hop.interval.to] {
        if endpoint != 0 && endpoint < 5 {
            return Err(invalid(
                "quicParams udpHop interval endpoints must be zero or at least 5 seconds",
            ));
        }
    }
    Ok(())
}

pub(crate) fn parse_bandwidth(value: &BandwidthValue) -> io::Result<u64> {
    match value {
        BandwidthValue::Empty => Ok(0),
        // serde's numeric alternative is the same textual value Xray feeds to
        // Bandwidth.Bps: bare numbers are bits per second.
        BandwidthValue::Number(value) => Ok(value / 8),
        BandwidthValue::Text(value) => {
            let input = value.trim().to_ascii_lowercase();
            if input.is_empty() {
                return Ok(0);
            }
            let split = input
                .char_indices()
                .find_map(|(index, ch)| (!ch.is_ascii_digit() && ch != '.').then_some(index))
                .unwrap_or(input.len());
            let number = input[..split]
                .parse::<f64>()
                .map_err(|_| invalid(format!("invalid bandwidth `{value}`")))?;
            if !number.is_finite() || number.is_sign_negative() {
                return Err(invalid(format!("invalid bandwidth `{value}`")));
            }
            let multiplier = match input[split..].trim() {
                "" | "b" | "bps" => 1_u64,
                "k" | "kb" | "kbps" => 1024,
                "m" | "mb" | "mbps" => 1024 * 1024,
                "g" | "gb" | "gbps" => 1024 * 1024 * 1024,
                "t" | "tb" | "tbps" => 1024_u64.pow(4),
                unit => return Err(invalid(format!("unsupported bandwidth unit `{unit}`"))),
            };
            let bits = number * multiplier as f64;
            if bits > u64::MAX as f64 {
                return Err(invalid("bandwidth overflows u64"));
            }
            Ok(bits as u64 / 8)
        }
    }
}

pub(crate) fn parse_ports(value: &PortListValue) -> io::Result<Vec<u16>> {
    let raw = match value {
        PortListValue::Empty => return Ok(Vec::new()),
        PortListValue::Number(value) => {
            if *value == 0 {
                return Ok(Vec::new());
            }
            let port = u16::try_from(*value)
                .ok()
                .filter(|port| *port != 0)
                .ok_or_else(|| invalid(format!("invalid UDP hop port `{value}`")))?;
            return Ok(vec![port]);
        }
        PortListValue::Text(value) => value,
    };
    let mut ports = Vec::new();
    for item in raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let Some((left, right)) = item.split_once('-') else {
            ports.push(parse_port(item)?);
            continue;
        };
        let left = parse_port(left.trim())?;
        let right = parse_port(right.trim())?;
        if left > right {
            return Err(invalid(format!("invalid UDP hop port range `{item}`")));
        }
        ports.extend(left..=right);
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

fn parse_port(value: &str) -> io::Result<u16> {
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| invalid(format!("invalid UDP hop port `{value}`")))
}

fn nonzero_or(value: u64, default: u64) -> u64 {
    if value == 0 { default } else { value }
}

fn varint(value: u64, field: &str) -> io::Result<VarInt> {
    VarInt::from_u64(value).map_err(|_| invalid(format!("quicParams {field} exceeds QUIC varint")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BbrProfile {
    Conservative,
    Standard,
    Aggressive,
}

impl BbrProfile {
    fn parse(input: &str) -> io::Result<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "conservative" => Ok(Self::Conservative),
            "" | "standard" => Ok(Self::Standard),
            "aggressive" => Ok(Self::Aggressive),
            other => Err(invalid(format!("unknown BBR profile `{other}`"))),
        }
    }

    fn factory(self) -> Arc<dyn ControllerFactory + Send + Sync> {
        let mut config = BbrConfig::default();
        // Quinn's public BBR configuration exposes the initial window but not
        // quic-go's internal gain knobs. Scale startup capacity according to
        // Xray's three pinned profiles; the controller remains genuine BBR.
        let packets = match self {
            Self::Conservative => 9,
            Self::Standard => 10,
            Self::Aggressive => 13,
        };
        config.initial_window(packets * 1200);
        Arc::new(config)
    }
}

struct SwitchableFactory {
    rate: Arc<AtomicU64>,
    use_bbr: Arc<AtomicBool>,
    bbr: Arc<dyn ControllerFactory + Send + Sync>,
}

impl ControllerFactory for SwitchableFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        let brutal = Arc::new(BrutalFactory {
            rate: self.rate.clone(),
        })
        .build(now, current_mtu);
        let bbr = self.bbr.clone().build(now, current_mtu);
        Box::new(SwitchableController {
            brutal,
            bbr,
            use_bbr: self.use_bbr.clone(),
        })
    }
}

struct SwitchableController {
    brutal: Box<dyn Controller>,
    bbr: Box<dyn Controller>,
    use_bbr: Arc<AtomicBool>,
}

impl Clone for SwitchableController {
    fn clone(&self) -> Self {
        Self {
            brutal: self.brutal.clone_box(),
            bbr: self.bbr.clone_box(),
            use_bbr: self.use_bbr.clone(),
        }
    }
}

impl Controller for SwitchableController {
    fn on_sent(&mut self, now: Instant, bytes: u64, packet: u64) {
        self.brutal.on_sent(now, bytes, packet);
        self.bbr.on_sent(now, bytes, packet);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.brutal.on_ack(now, sent, bytes, app_limited, rtt);
        self.bbr.on_ack(now, sent, bytes, app_limited, rtt);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.brutal
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
        self.bbr
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        persistent: bool,
        lost_bytes: u64,
    ) {
        self.brutal
            .on_congestion_event(now, sent, persistent, lost_bytes);
        self.bbr
            .on_congestion_event(now, sent, persistent, lost_bytes);
    }

    fn on_mtu_update(&mut self, mtu: u16) {
        self.brutal.on_mtu_update(mtu);
        self.bbr.on_mtu_update(mtu);
    }

    fn window(&self) -> u64 {
        self.active().window()
    }

    fn initial_window(&self) -> u64 {
        self.active().initial_window()
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl SwitchableController {
    fn active(&self) -> &dyn Controller {
        if self.use_bbr.load(Ordering::Acquire) {
            &*self.bbr
        } else {
            &*self.brutal
        }
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use core_config::{I32Range, UdpHopConfig};

    use super::*;

    #[test]
    fn bandwidth_matches_xray_binary_units_and_bits_to_bytes() {
        assert_eq!(
            parse_bandwidth(&BandwidthValue::Text("10 mbps".into())).unwrap(),
            10 * 1024 * 1024 / 8
        );
        assert_eq!(
            parse_bandwidth(&BandwidthValue::Text("1.5G".into())).unwrap(),
            (1.5 * 1024.0 * 1024.0 * 1024.0) as u64 / 8
        );
        assert_eq!(parse_bandwidth(&BandwidthValue::Number(800)).unwrap(), 100);
        assert!(parse_bandwidth(&BandwidthValue::Text("10 MiB/s".into())).is_err());
    }

    #[test]
    fn port_list_expands_ranges_and_deduplicates() {
        assert_eq!(
            parse_ports(&PortListValue::Text("443, 2000-2002,443".into())).unwrap(),
            [443, 2000, 2001, 2002]
        );
        assert!(parse_ports(&PortListValue::Text("4-2".into())).is_err());
        assert!(parse_ports(&PortListValue::Number(0)).unwrap().is_empty());
        let complete = parse_ports(&PortListValue::Text("1-65535".into())).unwrap();
        assert_eq!(complete.len(), 65_535);
        assert_eq!((complete[0], complete[65_534]), (1, 65_535));
    }

    #[test]
    fn rejects_every_out_of_range_official_quic_parameter() {
        for invalid_params in [
            QuicParamsConfig {
                init_stream_receive_window: 16_383,
                ..Default::default()
            },
            QuicParamsConfig {
                max_stream_receive_window: 1,
                ..Default::default()
            },
            QuicParamsConfig {
                init_connection_receive_window: 8_192,
                ..Default::default()
            },
            QuicParamsConfig {
                max_connection_receive_window: 12_000,
                ..Default::default()
            },
            QuicParamsConfig {
                max_idle_timeout: 121,
                ..Default::default()
            },
            QuicParamsConfig {
                keep_alive_period: 1,
                ..Default::default()
            },
            QuicParamsConfig {
                max_incoming_streams: 7,
                ..Default::default()
            },
            QuicParamsConfig {
                udp_hop: UdpHopConfig {
                    ports: PortListValue::Empty,
                    interval: I32Range::fixed(4),
                },
                ..Default::default()
            },
        ] {
            assert!(
                validate_params(&invalid_params).is_err(),
                "{invalid_params:?}"
            );
        }
        assert!(validate_params(&QuicParamsConfig::default()).is_ok());
    }

    #[test]
    fn all_transport_fields_compile_together() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let params = QuicParamsConfig {
            congestion: "force-brutal".into(),
            debug: true,
            bbr_profile: "aggressive".into(),
            brutal_up: BandwidthValue::Text("8 mbps".into()),
            brutal_down: BandwidthValue::Text("16 mbps".into()),
            udp_hop: UdpHopConfig {
                ports: PortListValue::Text("2000-2002".into()),
                interval: I32Range::new(5, 9),
            },
            init_stream_receive_window: 65_536,
            max_stream_receive_window: 131_072,
            init_connection_receive_window: 262_144,
            max_connection_receive_window: 524_288,
            max_idle_timeout: 20,
            keep_alive_period: 5,
            disable_path_mtu_discovery: true,
            max_incoming_streams: 16,
        };
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        )
        .unwrap();
        let mut client = ClientConfig::new(Arc::new(crypto));
        let applied = apply_client_config(&mut client, Some(&params)).unwrap();
        assert_eq!(applied.congestion, CongestionMode::ForceBrutal);
        assert_eq!(applied.brutal_up, 1024 * 1024);
        assert_eq!(applied.brutal_down, 2 * 1024 * 1024);
        let hop = applied.udp_hop.unwrap();
        assert_eq!(hop.ports, [2000, 2001, 2002]);
        assert_eq!(hop.interval_min, Duration::from_secs(5));
        assert_eq!(hop.interval_max, Duration::from_secs(9));
        assert_eq!(
            applied.max_connection_receive_window.unwrap(),
            VarInt::from_u32(524_288)
        );
    }

    #[test]
    fn client_and_server_use_the_correct_hysteria_send_bandwidth() {
        let params = QuicParamsConfig {
            congestion: "force-brutal".into(),
            brutal_up: BandwidthValue::Text("8 mbps".into()),
            brutal_down: BandwidthValue::Text("16 mbps".into()),
            ..Default::default()
        };
        let (_, client) = build_transport_config(Some(&params), false).unwrap();
        let (_, server) = build_transport_config(Some(&params), true).unwrap();
        assert_eq!(client.local_brutal_rate, 1024 * 1024);
        assert_eq!(server.local_brutal_rate, 2 * 1024 * 1024);

        let _: fn(&mut ServerConfig, Option<&QuicParamsConfig>) -> io::Result<AppliedQuicParams> =
            apply_server_config;
    }

    #[test]
    fn xhttp_quic_uses_force_brutal_without_hysteria_negotiation() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        )
        .unwrap();
        let mut client = ClientConfig::new(Arc::new(crypto));
        let params = QuicParamsConfig {
            congestion: "force-brutal".into(),
            brutal_up: BandwidthValue::Text("8 mbps".into()),
            ..Default::default()
        };
        let applied =
            apply_xhttp_client_config(&mut client, &params, Some(Duration::from_secs(15))).unwrap();
        assert_eq!(applied.congestion_mode(), CongestionMode::ForceBrutal);
        assert_eq!(applied.local_brutal_rate, 1024 * 1024);
        assert!(applied.switch.is_none());

        let mut unsupported = params;
        unsupported.congestion = "brutal".into();
        assert!(apply_xhttp_client_config(&mut client, &unsupported, None).is_err());
    }
}
