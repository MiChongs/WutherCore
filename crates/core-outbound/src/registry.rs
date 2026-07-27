//! 出站注册表 —— 把 [`ParsedNode`] 转化为 [`Arc<dyn OutboundAdapter>`]。
//!
//! 内置规则：direct / block 自动注册；其它协议按 [`NodeProtocol`] 选择。

use std::{collections::BTreeMap, net::IpAddr, sync::Arc};

use base64::Engine as _;
use core_config::{
    I32Range, PortListValue, QuicParamsConfig,
    model::{
        XhttpConfig as TypedXhttpConfig, XhttpDownloadSettings as TypedDownloadSettings,
        XhttpDownloadTlsCertificate, XhttpRange as TypedRange, XhttpTlsCertificateUsage,
    },
    node_uri::{NodeProtocol, ParsedNode},
};
use uuid::Uuid;

#[cfg(feature = "with_http")]
use crate::http::HttpOutbound;
#[cfg(feature = "with_naive")]
use crate::proto::naive::{NaiveOutbound, NaiveOutboundConfig};
#[cfg(feature = "with_young")]
use crate::proto::young::YoungOutbound;
#[cfg(feature = "with_socks")]
use crate::socks5::Socks5Outbound;
#[cfg(any(feature = "with_naive", feature = "with_young"))]
use crate::stub::StubOutbound;
#[cfg(feature = "with_naive")]
use cronet::Header;

use crate::{
    adapter::SharedOutbound,
    block::BlockOutbound,
    direct::DirectOutbound,
    dns_hijack::DnsHijackOutbound,
    proto::{
        anytls::AnyTlsOutbound,
        hysteria::HysteriaOutbound,
        hysteria2::{Hysteria2Obfs, Hysteria2Outbound},
        mieru::{MieruCipher, MieruOutbound},
        shadowsocks::ShadowsocksOutbound,
        snell::{SnellCipher, SnellOutbound},
        ssh::SshOutbound,
        ssr::{SsrCipher, SsrObfs, SsrOutbound, SsrProtocol},
        sudoku::{AeadMethod as SudokuAead, SudokuOutbound},
        trojan::TrojanOutbound,
        trusttunnel::TrustTunnelOutbound,
        tuic::{TuicOutbound, TuicUdpMode},
        vless::{VlessNetwork, VlessOutbound},
        vmess::{VmessNetwork, VmessOutbound, VmessSecurity},
        vmess_legacy::VmessLegacyOutbound,
        wireguard::{WireGuardConfig, WireGuardOutbound, WireGuardPeerConfig},
        xhttp::config::{
            Config as XhttpConfig, DownloadRealitySettings, DownloadSettings,
            DownloadSocketSettings, DownloadTlsSettings, DownloadTransportSettings,
        },
    },
    socket_policy::ConfiguredOutbound,
    transport::{
        GrpcOptions, H2Options, HttpOptions, RealityOptions, TlsOptions, WsOptions, XhttpOptions,
    },
};

pub type ResolveFn = Arc<dyn Fn(&str) -> Option<SharedOutbound> + Send + Sync>;

/// Canonical compile-time component tags accepted by `wuther-core`.
pub const COMPONENT_TAGS: &[&str] = &[
    "with_anytls",
    "with_grpc",
    "with_hysteria",
    "with_hysteria2",
    "with_http",
    "with_http_transport",
    "with_mieru",
    "with_naive",
    "with_quic",
    "with_reality",
    "with_shadowsocks",
    "with_shadowsocksr",
    "with_snell",
    "with_socks",
    "with_ssh",
    "with_sudoku",
    "with_trojan",
    "with_trusttunnel",
    "with_tuic",
    "with_utls",
    "with_vless",
    "with_vmess",
    "with_wireguard",
    "with_ws",
    "with_xhttp",
    "with_young",
];

/// Return the build tag controlling one protocol. Direct, block and DNS are
/// foundational and intentionally remain available in every build.
pub fn protocol_component_tag(protocol: &NodeProtocol) -> Option<&'static str> {
    match protocol {
        NodeProtocol::Direct | NodeProtocol::Block | NodeProtocol::Dns => None,
        NodeProtocol::Http => Some("with_http"),
        NodeProtocol::Socks5 => Some("with_socks"),
        NodeProtocol::Shadowsocks => Some("with_shadowsocks"),
        NodeProtocol::ShadowsocksR => Some("with_shadowsocksr"),
        NodeProtocol::Vmess => Some("with_vmess"),
        NodeProtocol::Vless => Some("with_vless"),
        NodeProtocol::Trojan => Some("with_trojan"),
        NodeProtocol::Naive => Some("with_naive"),
        NodeProtocol::Snell => Some("with_snell"),
        NodeProtocol::AnyTls => Some("with_anytls"),
        NodeProtocol::Ssh => Some("with_ssh"),
        NodeProtocol::Hysteria => Some("with_hysteria"),
        NodeProtocol::Hysteria2 => Some("with_hysteria2"),
        NodeProtocol::Tuic => Some("with_tuic"),
        NodeProtocol::Wireguard => Some("with_wireguard"),
        NodeProtocol::Mieru => Some("with_mieru"),
        NodeProtocol::Sudoku => Some("with_sudoku"),
        NodeProtocol::TrustTunnel => Some("with_trusttunnel"),
        NodeProtocol::Young => Some("with_young"),
        NodeProtocol::Other(_) => None,
    }
}

pub fn protocol_component_enabled(protocol: &NodeProtocol) -> bool {
    match protocol {
        NodeProtocol::Direct | NodeProtocol::Block | NodeProtocol::Dns => true,
        NodeProtocol::Http => cfg!(feature = "with_http"),
        NodeProtocol::Socks5 => cfg!(feature = "with_socks"),
        NodeProtocol::Shadowsocks => cfg!(feature = "with_shadowsocks"),
        NodeProtocol::ShadowsocksR => cfg!(feature = "with_shadowsocksr"),
        NodeProtocol::Vmess => cfg!(feature = "with_vmess"),
        NodeProtocol::Vless => cfg!(feature = "with_vless"),
        NodeProtocol::Trojan => cfg!(feature = "with_trojan"),
        NodeProtocol::Naive => cfg!(feature = "with_naive"),
        NodeProtocol::Snell => cfg!(feature = "with_snell"),
        NodeProtocol::AnyTls => cfg!(feature = "with_anytls"),
        NodeProtocol::Ssh => cfg!(feature = "with_ssh"),
        NodeProtocol::Hysteria => cfg!(feature = "with_hysteria"),
        NodeProtocol::Hysteria2 => cfg!(feature = "with_hysteria2"),
        NodeProtocol::Tuic => cfg!(feature = "with_tuic"),
        NodeProtocol::Wireguard => cfg!(feature = "with_wireguard"),
        NodeProtocol::Mieru => cfg!(feature = "with_mieru"),
        NodeProtocol::Sudoku => cfg!(feature = "with_sudoku"),
        NodeProtocol::TrustTunnel => cfg!(feature = "with_trusttunnel"),
        NodeProtocol::Young => cfg!(feature = "with_young"),
        NodeProtocol::Other(_) => true,
    }
}

/// Fail closed when a configuration asks for code omitted by this build.
pub fn validate_node_components(node: &ParsedNode) -> Result<(), String> {
    if !protocol_component_enabled(&node.protocol) {
        let tag = protocol_component_tag(&node.protocol).expect("disabled protocols have a tag");
        return Err(format!(
            "protocol `{}` is not compiled in; rebuild with `{tag}`",
            node.protocol.as_str()
        ));
    }

    let transport = node.transport.trim().to_ascii_lowercase();
    let required_transport = match transport.as_str() {
        "ws" | "websocket" => (!cfg!(feature = "with_ws")).then_some("with_ws"),
        "http" | "h2" => (!cfg!(feature = "with_http_transport")).then_some("with_http_transport"),
        "grpc" | "gun" => (!cfg!(feature = "with_grpc")).then_some("with_grpc"),
        "xhttp" | "splithttp" => (!cfg!(feature = "with_xhttp")).then_some("with_xhttp"),
        "quic" | "h3" => (!cfg!(feature = "with_quic")).then_some("with_quic"),
        _ => None,
    };
    if let Some(tag) = required_transport {
        return Err(format!(
            "transport `{transport}` is not compiled in; rebuild with `{tag}`"
        ));
    }

    if (node.reality.is_some() || node.reality_settings.is_some())
        && !cfg!(feature = "with_reality")
    {
        return Err("REALITY is not compiled in; rebuild with `with_reality`".into());
    }

    let fingerprint = node
        .tls_settings
        .as_ref()
        .and_then(|settings| settings.fingerprint.as_deref())
        .or_else(|| node.params.get("fingerprint").map(String::as_str))
        .unwrap_or_default()
        .trim();
    if !fingerprint.is_empty()
        && !fingerprint.eq_ignore_ascii_case("unsafe")
        && !cfg!(feature = "with_utls")
    {
        return Err("uTLS fingerprinting is not compiled in; rebuild with `with_utls`".into());
    }
    Ok(())
}

#[derive(Default)]
pub struct OutboundRegistry {
    map: BTreeMap<String, SharedOutbound>,
}

impl OutboundRegistry {
    pub fn new() -> Self {
        let mut s = Self::default();
        s.insert("DIRECT", DirectOutbound::new());
        s.insert("BLOCK", BlockOutbound::new());
        s
    }

    pub fn insert(&mut self, name: impl Into<String>, ob: SharedOutbound) {
        self.map.insert(name.into(), ob);
    }

    pub fn get(&self, name: &str) -> Option<SharedOutbound> {
        self.map.get(name).cloned()
    }

    pub fn remove(&mut self, name: &str) -> Option<SharedOutbound> {
        if name == "DIRECT" || name == "BLOCK" {
            return None;
        }
        self.map.remove(name)
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.map.keys().map(|s| s.as_str())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &SharedOutbound)> {
        self.map.iter().map(|(k, v)| (k.as_str(), v))
    }
}

/// 把 [`ParsedNode`] 数组注册为一组出站。
pub fn register_nodes(reg: &mut OutboundRegistry, nodes: &[ParsedNode]) -> Result<(), String> {
    let mut pending_proxies = Vec::new();
    for source_node in nodes {
        let expanded;
        let node = if source_node.protocol == NodeProtocol::Hysteria2 {
            expanded = expand_hysteria2_official_objects(source_node)?;
            &expanded
        } else {
            source_node
        };
        let mut ob = build_outbound(node)
            .map_err(|error| format!("node `{}` outbound config invalid: {error}", node.name))?;
        if let Some(settings) = node.stream_settings.clone() {
            let proxy_name = settings
                .sockopt
                .as_ref()
                .map(|sockopt| sockopt.dialer_proxy.trim().to_string())
                .filter(|name| !name.is_empty());
            let (configured, policy) = ConfiguredOutbound::new(ob, settings);
            ob = configured;
            if let Some(proxy_name) = proxy_name {
                pending_proxies.push((node.name.clone(), proxy_name, policy));
            }
        }
        reg.insert(node.name.clone(), ob);
    }

    // Resolve only after every wrapper has been inserted: Xray permits a
    // dialerProxy to reference a node declared later in the configuration.
    for (owner, proxy_name, policy) in pending_proxies {
        let lookup_name = if proxy_name.eq_ignore_ascii_case("direct") {
            "DIRECT"
        } else if proxy_name.eq_ignore_ascii_case("block") {
            "BLOCK"
        } else {
            &proxy_name
        };
        if let Some(proxy) = reg.get(lookup_name) {
            let _ = ConfiguredOutbound::set_dialer_proxy(&policy, proxy);
        } else {
            return Err(format!(
                "node `{owner}` streamSettings.sockopt.dialerProxy target `{proxy_name}` was not registered"
            ));
        }
    }
    Ok(())
}

pub fn build_outbound(node: &ParsedNode) -> Result<SharedOutbound, String> {
    validate_node_components(node)?;

    macro_rules! compiled {
        ($feature:literal, $expression:expr) => {{
            #[cfg(feature = $feature)]
            {
                $expression
            }
            #[cfg(not(feature = $feature))]
            {
                unreachable!("component availability was validated before dispatch")
            }
        }};
    }

    let outbound: SharedOutbound = match node.protocol {
        NodeProtocol::Direct => DirectOutbound::new(),
        NodeProtocol::Block => BlockOutbound::new(),
        NodeProtocol::Dns => DnsHijackOutbound::new(node.name.clone()),
        NodeProtocol::Http => compiled!("with_http", {
            let mut ob = HttpOutbound::new(&node.name, &node.host, node.port);
            if let (Some(u), Some(p)) = (node.user.clone(), node.password.clone()) {
                ob = ob.with_auth(u, p);
            }
            ob.into_arc()
        }),
        NodeProtocol::Socks5 => compiled!("with_socks", {
            let mut ob = Socks5Outbound::new(&node.name, &node.host, node.port).with_udp(node.udp);
            if let (Some(u), Some(p)) = (node.user.clone(), node.password.clone()) {
                ob = ob.with_auth(u, p);
            }
            ob.into_arc()
        }),
        NodeProtocol::Shadowsocks => {
            compiled!("with_shadowsocks", build_shadowsocks(node)?)
        }
        NodeProtocol::ShadowsocksR => compiled!("with_shadowsocksr", build_ssr(node)?),
        NodeProtocol::Vmess => compiled!("with_vmess", build_vmess(node)?),
        NodeProtocol::Vless => compiled!("with_vless", build_vless(node)?),
        NodeProtocol::Trojan => compiled!("with_trojan", Arc::new(build_trojan(node)?)),
        NodeProtocol::Naive => compiled!("with_naive", build_naive(node)),
        NodeProtocol::Snell => compiled!("with_snell", build_snell(node)?),
        NodeProtocol::AnyTls => compiled!("with_anytls", build_anytls(node)?),
        NodeProtocol::Ssh => compiled!("with_ssh", build_ssh(node)?),
        NodeProtocol::Hysteria => compiled!("with_hysteria", build_hysteria_v1(node)?),
        NodeProtocol::Hysteria2 => compiled!("with_hysteria2", build_hysteria2(node)?),
        NodeProtocol::Tuic => compiled!("with_tuic", build_tuic(node)?),
        NodeProtocol::Wireguard => compiled!("with_wireguard", build_wireguard(node)?),
        NodeProtocol::Mieru => compiled!("with_mieru", build_mieru(node)),
        NodeProtocol::Sudoku => compiled!("with_sudoku", build_sudoku(node)?),
        NodeProtocol::TrustTunnel => {
            compiled!("with_trusttunnel", build_trusttunnel(node))
        }
        NodeProtocol::Young => compiled!("with_young", build_young(node)),
        NodeProtocol::Other(ref protocol) => {
            return Err(format!("unsupported outbound protocol `{protocol}`"));
        }
    };
    Ok(outbound)
}

/// 源码兼容别名；所有调用路径现在都会保留 XHTTP 配置错误。
pub fn try_build_outbound(node: &ParsedNode) -> Result<SharedOutbound, String> {
    build_outbound(node)
}

#[cfg(feature = "with_naive")]
fn build_naive(node: &ParsedNode) -> SharedOutbound {
    let mut config = NaiveOutboundConfig::new(&node.host, node.port);
    config.username = node.user.clone();
    config.password = node.password.clone();
    config.server_name = node.sni.clone().filter(|value| !value.is_empty());
    config.insecure_concurrency =
        param_usize(node, &["insecure-concurrency", "insecure_concurrency"], 1).max(1);
    config.udp_over_tcp = node.udp && param_bool(node, &["udp-over-tcp", "udp_over_tcp"], false);
    config.quic = param_bool(node, &["quic"], false);
    config.quic_congestion_control = node
        .params
        .get("quic-congestion-control")
        .or_else(|| node.params.get("quic_congestion_control"))
        .map(|value| match value.to_ascii_lowercase().as_str() {
            "" => "",
            "bbr" => "TBBR",
            "bbr2" => "B2ON",
            "cubic" => "QBIC",
            "reno" => "RENO",
            _ => value.as_str(),
        })
        .unwrap_or_default()
        .to_owned();
    config.receive_window = param_u64(node, &["stream-receive-window", "stream_receive_window"], 0);
    config.quic_session_receive_window = param_u64(
        node,
        &["quic-session-receive-window", "quic_session_receive_window"],
        0,
    );
    config.extra_headers = node
        .params
        .iter()
        .filter_map(|(key, value)| {
            key.strip_prefix("extra-header.")
                .or_else(|| key.strip_prefix("header."))
                .map(|name| Header {
                    name: name.to_owned(),
                    value: value.clone(),
                })
        })
        .collect();

    if param_bool(
        node,
        &[
            "insecure",
            "allow-insecure",
            "allowInsecure",
            "skip-cert-verify",
        ],
        false,
    ) {
        tracing::warn!(
            target: "naive",
            node = %node.name,
            "Cronet Naive rejects insecure TLS; configure certificate/certificate_path instead"
        );
        return StubOutbound::new(node.name.clone(), "naive(insecure-tls-unsupported)");
    }
    if let Some(path) = node
        .params
        .get("certificate-path")
        .or_else(|| node.params.get("certificate_path"))
    {
        match std::fs::read_to_string(path) {
            Ok(certificate) => config.trusted_root_certificates = Some(certificate),
            Err(error) => {
                tracing::warn!(
                    target: "naive",
                    node = %node.name,
                    path,
                    error = %error,
                    "failed to read Naive certificate_path"
                );
                return StubOutbound::new(node.name.clone(), "naive(invalid-certificate-path)");
            }
        }
    } else if let Some(certificate) = node.params.get("certificate") {
        config.trusted_root_certificates = Some(certificate.clone());
    }
    config.ech_enabled = param_bool(
        node,
        &["ech", "ech-enabled", "ech_enabled", "ech-enable"],
        false,
    );
    if let Some(encoded) = node
        .params
        .get("ech-config")
        .or_else(|| node.params.get("ech_config"))
    {
        match decode_config_blob(encoded) {
            Some(config_list) => {
                config.ech_enabled = true;
                config.ech_config_list = config_list;
            }
            None => {
                return StubOutbound::new(node.name.clone(), "naive(invalid-ech-config)");
            }
        }
    }
    config.ech_query_server_name = node
        .params
        .get("ech-query-server-name")
        .or_else(|| node.params.get("ech_query_server_name"))
        .cloned();

    match NaiveOutbound::new(&node.name, config) {
        Ok(outbound) => Arc::new(outbound),
        Err(error) => {
            tracing::warn!(target: "naive", node = %node.name, error = %error, "invalid Naive node");
            StubOutbound::new(node.name.clone(), "naive(invalid-config)")
        }
    }
}

#[cfg(feature = "with_naive")]
fn param_bool(node: &ParsedNode, keys: &[&str], default: bool) -> bool {
    keys.iter()
        .find_map(|key| node.params.get(*key))
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(default)
}

#[cfg(feature = "with_naive")]
fn param_usize(node: &ParsedNode, keys: &[&str], default: usize) -> usize {
    keys.iter()
        .find_map(|key| node.params.get(*key))
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

#[cfg(feature = "with_naive")]
fn param_u64(node: &ParsedNode, keys: &[&str], default: u64) -> u64 {
    keys.iter()
        .find_map(|key| node.params.get(*key))
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

#[cfg(feature = "with_naive")]
fn decode_config_blob(value: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    let encoded = value
        .lines()
        .filter(|line| !line.trim_start().starts_with("-----"))
        .collect::<String>()
        .replace(char::is_whitespace, "");
    if encoded.len().is_multiple_of(2)
        && !encoded.is_empty()
        && encoded.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return hex::decode(&encoded).ok();
    }
    STANDARD
        .decode(&encoded)
        .ok()
        .or_else(|| URL_SAFE_NO_PAD.decode(encoded.trim_end_matches('=')).ok())
}

fn build_shadowsocks(node: &ParsedNode) -> Result<SharedOutbound, String> {
    let method = node.method.as_deref().unwrap_or("aes-256-gcm");
    let pwd = node.password.as_deref().unwrap_or("");
    if pwd.is_empty() {
        return Err("shadowsocks password must not be empty".into());
    }
    let method = ShadowsocksOutbound::parse_method(method).map_err(|error| error.to_string())?;
    let is_2022 = method.is_aead_2022();
    let mut outbound = ShadowsocksOutbound::new(&node.name, &node.host, node.port, method, pwd)
        .map_err(|error| {
            if is_2022 {
                format!("invalid Shadowsocks 2022 PSK: {error}")
            } else {
                format!("invalid Shadowsocks configuration: {error}")
            }
        })?;
    outbound.udp = node.udp;
    if let Some(spec) = node.params.get("plugin") {
        let (plugin, inline_opts) = spec
            .split_once(';')
            .map_or((spec.as_str(), None), |(name, opts)| (name, Some(opts)));
        if plugin.trim().is_empty() {
            return Err("Shadowsocks SIP003 plugin name must not be empty".into());
        }
        let plugin_opts = node
            .params
            .get("plugin-opts")
            .or_else(|| node.params.get("plugin_opts"))
            .map(String::as_str)
            .or(inline_opts)
            .map(ToOwned::to_owned);
        let plugin_mode = match node
            .params
            .get("plugin-mode")
            .or_else(|| node.params.get("plugin_mode"))
            .map(|value| value.to_ascii_lowercase().replace('-', "_"))
            .as_deref()
            .unwrap_or("tcp_only")
        {
            "tcp" | "tcp_only" => shadowsocks::config::Mode::TcpOnly,
            "udp" | "udp_only" => shadowsocks::config::Mode::UdpOnly,
            "tcp_and_udp" | "tcp_udp" => shadowsocks::config::Mode::TcpAndUdp,
            mode => return Err(format!("invalid Shadowsocks SIP003 plugin mode `{mode}`")),
        };
        let plugin_args = node
            .params
            .get("plugin-args")
            .or_else(|| node.params.get("plugin_args"))
            .map(|value| {
                if value.trim().is_empty() {
                    Ok(Vec::new())
                } else if value.trim_start().starts_with('[') {
                    serde_json::from_str::<Vec<String>>(value).map_err(|error| {
                        format!("invalid Shadowsocks SIP003 plugin-args JSON array: {error}")
                    })
                } else {
                    Ok(vec![value.clone()])
                }
            })
            .transpose()?
            .unwrap_or_default();
        outbound.set_plugin(Some(shadowsocks::plugin::PluginConfig {
            plugin: plugin.to_owned(),
            plugin_opts,
            plugin_args,
            plugin_mode,
        }));
    } else if [
        "plugin-opts",
        "plugin_opts",
        "plugin-args",
        "plugin_args",
        "plugin-mode",
        "plugin_mode",
    ]
    .iter()
    .any(|key| node.params.contains_key(*key))
    {
        return Err("Shadowsocks SIP003 plugin options require the `plugin` parameter".to_owned());
    }
    Ok(Arc::new(outbound))
}

fn build_ssr(node: &ParsedNode) -> Result<SharedOutbound, String> {
    let method = node.method.as_deref().unwrap_or("aes-256-cfb");
    let pwd = node.password.as_deref().unwrap_or("");
    if pwd.is_empty() {
        return Err("ShadowsocksR password must not be empty".into());
    }
    let obfs_str = node
        .params
        .get("obfs")
        .map(|s| s.as_str())
        .unwrap_or("plain");
    let proto_str = node
        .params
        .get("protocol")
        .map(|s| s.as_str())
        .unwrap_or("origin");
    let obfs = match SsrObfs::parse(obfs_str, &node.host) {
        Some(o) => o,
        None => return Err(format!("unsupported ShadowsocksR obfs `{obfs_str}`")),
    };
    let proto = match SsrProtocol::parse(proto_str) {
        Some(p) => p,
        None => return Err(format!("unsupported ShadowsocksR protocol `{proto_str}`")),
    };
    match SsrCipher::parse(method) {
        Some(c) => {
            let mut ob = SsrOutbound::new(&node.name, &node.host, node.port, c, pwd);
            ob.obfs = obfs;
            ob.protocol = proto;
            ob.obfs_param = node.params.get("obfs-param").cloned().unwrap_or_default();
            ob.protocol_param = node
                .params
                .get("protocol-param")
                .cloned()
                .unwrap_or_default();
            Ok(Arc::new(ob))
        }
        None => Err(format!("unsupported ShadowsocksR cipher `{method}`")),
    }
}

fn build_vmess(node: &ParsedNode) -> Result<SharedOutbound, String> {
    let uuid = node
        .uuid
        .as_deref()
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(Uuid::nil);
    let alter_id = node
        .params
        .get("aid")
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    // alter_id > 0：使用 legacy MD5 模式
    if alter_id > 0 {
        let mut ob = VmessLegacyOutbound::new(&node.name, &node.host, node.port, uuid, alter_id);
        if let Some(sec) = node
            .params
            .get("security")
            .and_then(|s| VmessSecurity::parse(s))
        {
            ob.security = sec;
        }
        if let Some(scy) = node.params.get("scy").and_then(|s| VmessSecurity::parse(s)) {
            ob.security = scy;
        }
        ob.tls = node.tls
            || node
                .params
                .get("tls")
                .map(|s| s == "tls" || s == "true")
                .unwrap_or(false);
        ob.sni = node
            .sni
            .clone()
            .or_else(|| node.params.get("host").cloned())
            .or(Some(node.host.clone()));
        ob.insecure = node
            .params
            .get("allowInsecure")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false);
        if let Some(alpn) = node.params.get("alpn") {
            ob.alpn = alpn.split(',').map(|s| s.trim().to_string()).collect();
        }
        let tls_options =
            build_node_tls_options(node, ob.tls, ob.sni.clone(), ob.insecure, ob.alpn.clone())?;
        if ob.tls {
            ob.tls_options = Some(tls_options);
        }
        // VMess Legacy uses the same outer transport stack as AEAD VMess.
        let net = resolve_network_string(node);
        match VmessNetwork::parse(&net) {
            VmessNetwork::Ws => ob.ws = Some(build_ws_options(node)),
            VmessNetwork::Grpc => ob.grpc = Some(build_grpc_options(node)?),
            _ => {}
        }
        return Ok(Arc::new(ob));
    }

    let mut ob = VmessOutbound::new(&node.name, &node.host, node.port, uuid);
    if let Some(sec) = node
        .params
        .get("security")
        .and_then(|s| VmessSecurity::parse(s))
    {
        ob.security = sec;
    }
    if let Some(scy) = node.params.get("scy").and_then(|s| VmessSecurity::parse(s)) {
        ob.security = scy;
    }
    ob.tls = node.tls
        || node
            .params
            .get("tls")
            .map(|s| s == "tls" || s == "true")
            .unwrap_or(false);
    ob.sni = node
        .sni
        .clone()
        .or_else(|| node.params.get("host").cloned())
        .or(Some(node.host.clone()));
    ob.insecure = node
        .params
        .get("allowInsecure")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    if let Some(alpn) = node.params.get("alpn") {
        ob.alpn = alpn.split(',').map(|s| s.trim().to_string()).collect();
    }
    let tls_options =
        build_node_tls_options(node, ob.tls, ob.sni.clone(), ob.insecure, ob.alpn.clone())?;
    if ob.tls {
        ob.tls_options = Some(tls_options);
    }
    // VMess network 分发：tcp / ws / http / h2 / grpc / xhttp
    let network_str = resolve_network_string(node);
    ob.network = VmessNetwork::parse(&network_str);
    apply_vmess_network_options(node, &mut ob)?;
    Ok(Arc::new(ob))
}

/// 从 ParsedNode 解析 network 字段：优先 params["net"]（VMess JSON）/
/// params["network"]（Clash YAML）/ params["type"]（VLESS URI）
fn resolve_network_string(node: &ParsedNode) -> String {
    if let Some(v) = node.params.get("network") {
        return v.clone();
    }
    if let Some(v) = node.params.get("net") {
        return v.clone();
    }
    if !node.transport.is_empty() && node.transport != "tcp" {
        return node.transport.clone();
    }
    "tcp".into()
}

fn apply_vmess_network_options(node: &ParsedNode, ob: &mut VmessOutbound) -> Result<(), String> {
    match ob.network {
        VmessNetwork::Tcp => {}
        VmessNetwork::Ws => {
            ob.ws = Some(build_ws_options(node));
        }
        VmessNetwork::Http => {
            ob.http = Some(build_http_options(node));
        }
        VmessNetwork::H2 => {
            ob.h2 = Some(build_h2_options(node));
        }
        VmessNetwork::Grpc => {
            ob.grpc = Some(build_grpc_options(node)?);
        }
        VmessNetwork::Xhttp => {
            ob.xhttp = Some(build_xhttp_options(
                node,
                ob.sni.clone(),
                ob.insecure,
                ob.alpn.clone(),
            )?);
        }
    }
    Ok(())
}

fn build_vless(node: &ParsedNode) -> Result<SharedOutbound, String> {
    let uuid = node
        .uuid
        .as_deref()
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(Uuid::nil);
    let mut ob = VlessOutbound::new(&node.name, &node.host, node.port, uuid);
    ob.tls = node.tls && node.reality.is_none();
    ob.sni = node
        .sni
        .clone()
        .filter(|s| !s.is_empty())
        .or(Some(node.host.clone()));
    ob.insecure = node
        .params
        .get("allowInsecure")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    if let Some(alpn) = node.params.get("alpn") {
        ob.alpn = alpn.split(',').map(|s| s.trim().to_string()).collect();
    }
    if let Some(reality) = &node.reality {
        let encoded_public_key = reality
            .password
            .as_ref()
            .or(reality.public_key.as_ref())
            .expect("core-config validated REALITY password/publicKey");
        let decoded_public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded_public_key)
            .expect("core-config validated REALITY public key base64url");
        let public_key: [u8; 32] = decoded_public_key
            .try_into()
            .expect("core-config validated REALITY public key length");
        let short_id = hex::decode(&reality.short_id)
            .expect("core-config validated REALITY shortId hexadecimal");
        let mldsa65_verify = reality.mldsa65_verify.as_ref().map(|encoded| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(encoded)
                .expect("core-config validated REALITY mldsa65Verify")
        });
        ob.sni = Some(reality.server_name.clone());
        ob.reality = Some(RealityOptions {
            config: core_reality::RealityClientConfig {
                server_name: reality.server_name.clone(),
                fingerprint: reality.fingerprint.clone(),
                public_key,
                short_id,
                spider_x: reality.spider_x.clone(),
                mldsa65_verify,
                ..core_reality::RealityClientConfig::default()
            },
        });
    }
    if ob.reality.is_some() {
        reject_ordinary_tls_with_reality(node)?;
    } else {
        let tls_options =
            build_node_tls_options(node, ob.tls, ob.sni.clone(), ob.insecure, ob.alpn.clone())?;
        if ob.tls {
            ob.tls_options = Some(tls_options);
        }
    }
    let network_str = resolve_network_string(node);
    ob.network = VlessNetwork::parse(&network_str);
    apply_vless_network_options(node, &mut ob)?;
    Ok(Arc::new(ob))
}

fn apply_vless_network_options(node: &ParsedNode, ob: &mut VlessOutbound) -> Result<(), String> {
    match ob.network {
        VlessNetwork::Tcp => {}
        VlessNetwork::Ws => {
            ob.ws = Some(build_ws_options(node));
        }
        VlessNetwork::Http => {
            ob.http = Some(build_http_options(node));
        }
        VlessNetwork::H2 => {
            ob.h2 = Some(build_h2_options(node));
        }
        VlessNetwork::Grpc => {
            ob.grpc = Some(build_grpc_options(node)?);
        }
        VlessNetwork::Xhttp => {
            ob.xhttp = Some(build_xhttp_options(
                node,
                ob.sni.clone(),
                ob.insecure,
                ob.alpn.clone(),
            )?);
        }
    }
    Ok(())
}

fn build_ws_options(node: &ParsedNode) -> WsOptions {
    WsOptions {
        enabled: true,
        path: node
            .params
            .get("path")
            .cloned()
            .unwrap_or_else(|| "/".into()),
        host: node.params.get("host").cloned(),
        headers: vec![],
    }
}

fn build_http_options(node: &ParsedNode) -> HttpOptions {
    let path: Vec<String> = node
        .params
        .get("path")
        .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_else(|| vec!["/".into()]);
    let host: Vec<String> = node
        .params
        .get("host")
        .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();
    HttpOptions {
        enabled: true,
        method: node.params.get("http-method").cloned().unwrap_or_default(),
        path,
        host,
        headers: vec![],
    }
}

fn build_h2_options(node: &ParsedNode) -> H2Options {
    let host: Vec<String> = node
        .params
        .get("host")
        .or_else(|| node.params.get("h2-host"))
        .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();
    H2Options {
        enabled: true,
        host,
        path: node
            .params
            .get("path")
            .cloned()
            .unwrap_or_else(|| "/".into()),
        method: node.params.get("h2-method").cloned().unwrap_or_default(),
    }
}

fn build_grpc_options(node: &ParsedNode) -> Result<GrpcOptions, &'static str> {
    let authority = grpc_param(node, &["authority", "grpc-authority", "grpc_authority"])?
        .unwrap_or_default()
        .to_owned();
    let service_name = grpc_param(
        node,
        &[
            "serviceName",
            "service_name",
            "service-name",
            "grpc-service-name",
            "grpc_service_name",
        ],
    )?
    .unwrap_or_default()
    .to_owned();
    let multi_mode = parse_grpc_bool(grpc_param(
        node,
        &["multiMode", "multi_mode", "multi-mode", "grpc-multi-mode"],
    )?)?
    .unwrap_or(false);
    let idle_timeout = parse_grpc_duration(grpc_param(
        node,
        &[
            "idle_timeout",
            "idleTimeout",
            "idle-timeout",
            "grpc-idle-timeout",
        ],
    )?)?;
    let health_check_timeout = parse_grpc_duration(grpc_param(
        node,
        &[
            "health_check_timeout",
            "healthCheckTimeout",
            "health-check-timeout",
            "grpc-health-check-timeout",
        ],
    )?)?;
    let permit_without_stream = parse_grpc_bool(grpc_param(
        node,
        &[
            "permit_without_stream",
            "permitWithoutStream",
            "permit-without-stream",
            "grpc-permit-without-stream",
        ],
    )?)?
    .unwrap_or(false);
    let initial_window_size = parse_grpc_window(grpc_param(
        node,
        &[
            "initial_windows_size",
            "initial_window_size",
            "initialWindowSize",
            "initial-window-size",
            "initial-windows-size",
            "grpc-initial-window-size",
        ],
    )?)?;
    let user_agent = grpc_param(
        node,
        &[
            "user_agent",
            "userAgent",
            "user-agent",
            "grpc-user-agent",
            "grpc_user_agent",
        ],
    )?
    .unwrap_or_default()
    .to_owned();
    let max_message_size = parse_grpc_positive_usize(
        grpc_param(
            node,
            &[
                "max_message_size",
                "maxMessageSize",
                "max-message-size",
                "grpc-max-message-size",
            ],
        )?,
        core_grpc::DEFAULT_MAX_MESSAGE_SIZE,
        core_grpc::MIN_MESSAGE_SIZE,
        core_grpc::MAX_MESSAGE_SIZE_LIMIT,
    )?;
    let queue_capacity = parse_grpc_positive_usize(
        grpc_param(
            node,
            &[
                "queue_capacity",
                "queueCapacity",
                "queue-capacity",
                "grpc-queue-capacity",
            ],
        )?,
        core_grpc::DEFAULT_QUEUE_CAPACITY,
        1,
        core_grpc::MAX_QUEUE_CAPACITY,
    )?;

    Ok(GrpcOptions {
        enabled: true,
        authority,
        service_name,
        multi_mode,
        idle_timeout,
        health_check_timeout,
        permit_without_stream,
        initial_window_size,
        user_agent,
        max_message_size,
        queue_capacity,
        host: node.params.get("host").cloned().unwrap_or_default(),
    })
}

fn build_node_tls_options(
    node: &ParsedNode,
    enabled: bool,
    fallback_sni: Option<String>,
    fallback_insecure: bool,
    fallback_alpn: Vec<String>,
) -> Result<TlsOptions, String> {
    const ADVANCED_KEYS: &[&str] = &[
        "serverName",
        "server-name",
        "server_name",
        "sni",
        "alpn",
        "allowInsecure",
        "allow-insecure",
        "allow_insecure",
        "fingerprint",
        "fp",
        "utls",
        "enableSessionResumption",
        "enable-session-resumption",
        "enable_session_resumption",
        "disableSystemRoot",
        "disable-system-root",
        "disable_system_root",
        "minVersion",
        "min-version",
        "min_version",
        "maxVersion",
        "max-version",
        "max_version",
        "cipherSuites",
        "cipher-suites",
        "cipher_suites",
        "curvePreferences",
        "curve-preferences",
        "curve_preferences",
        "masterKeyLog",
        "master-key-log",
        "master_key_log",
        "pinnedPeerCertSha256",
        "pinned-peer-cert-sha256",
        "pinned_peer_cert_sha256",
        "pinSHA256",
        "pin-sha256",
        "pin_sha256",
        "verifyPeerCertByName",
        "verify-peer-cert-by-name",
        "verify_peer_cert_by_name",
        "echConfigList",
        "ech-config-list",
        "ech_config_list",
    ];
    let (ech_toggle, ech_inline_config) = match first_param(node, &["ech"]) {
        None => (None, None),
        Some(value)
            if matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on" | "0" | "false" | "no" | "off"
            ) =>
        {
            (Some(parse_bool_param("ech", value)?), None)
        }
        // The official Hysteria 2 URI puts the base64 ECHConfigList directly
        // in `ech`; Xray names the same bytes `echConfigList`.
        Some(value) if !value.trim().is_empty() => (Some(true), Some(value.to_owned())),
        Some(_) => return Err("ech cannot be empty".into()),
    };
    let has_complete_settings = node.tls_settings.is_some()
        || ech_toggle == Some(true)
        || ADVANCED_KEYS
            .iter()
            .any(|key| node.params.contains_key(*key));
    if has_complete_settings && !enabled {
        return Err("TLS/ECH settings are present while TLS is disabled".into());
    }
    if !has_complete_settings {
        return Ok(TlsOptions {
            enabled,
            sni: fallback_sni,
            insecure: fallback_insecure,
            alpn: fallback_alpn,
            ..TlsOptions::default()
        });
    }

    let mut settings = node.tls_settings.clone().unwrap_or_default();
    if let Some(value) = ech_inline_config {
        if settings
            .ech_config_list
            .as_ref()
            .is_some_and(|typed| typed != &value)
        {
            return Err("typed TLS echConfigList conflicts with protocol ech".into());
        }
        settings.ech_config_list = Some(value);
    }
    let fingerprint = first_param(node, &["fingerprint", "fp"]);
    let utls = first_param(node, &["utls"]);
    if fingerprint
        .zip(utls)
        .is_some_and(|(fingerprint, utls)| !fingerprint.eq_ignore_ascii_case(utls))
    {
        return Err("TLS fingerprint conflicts with utls".into());
    }
    if let Some(value) = fingerprint.or(utls) {
        if settings
            .fingerprint
            .as_deref()
            .is_some_and(|typed| !typed.eq_ignore_ascii_case(value))
        {
            return Err("typed TLS fingerprint conflicts with URI fingerprint".into());
        }
        settings.fingerprint = Some(value.to_owned());
    }

    let explicit_server_name = node
        .sni
        .as_deref()
        .or_else(|| first_param(node, &["serverName", "server-name", "server_name", "sni"]));
    if let Some(explicit) = explicit_server_name {
        if settings
            .server_name
            .as_ref()
            .is_some_and(|typed| typed != explicit)
        {
            return Err("typed TLS serverName conflicts with protocol SNI".into());
        }
        settings.server_name = Some(explicit.to_owned());
    } else if settings.server_name.is_none() {
        settings.server_name = fallback_sni;
    }
    settings.server_name = merge_optional_string_param(
        node,
        &["serverName", "server-name", "server_name", "sni"],
        "serverName",
        settings.server_name,
        true,
    )?;
    settings.allow_insecure = merge_optional_bool_param(
        node,
        &["allowInsecure", "allow-insecure", "allow_insecure"],
        "allowInsecure",
        settings.allow_insecure,
    )?;
    if fallback_insecure {
        if settings.allow_insecure == Some(false) {
            return Err("typed TLS allowInsecure conflicts with protocol setting".into());
        }
        settings.allow_insecure = Some(true);
    }
    settings.enable_session_resumption = merge_optional_bool_param(
        node,
        &[
            "enableSessionResumption",
            "enable-session-resumption",
            "enable_session_resumption",
        ],
        "enableSessionResumption",
        settings.enable_session_resumption,
    )?;
    settings.disable_system_root = merge_optional_bool_param(
        node,
        &[
            "disableSystemRoot",
            "disable-system-root",
            "disable_system_root",
        ],
        "disableSystemRoot",
        settings.disable_system_root,
    )?;
    settings.min_version = merge_optional_string_param(
        node,
        &["minVersion", "min-version", "min_version"],
        "minVersion",
        settings.min_version,
        true,
    )?;
    settings.max_version = merge_optional_string_param(
        node,
        &["maxVersion", "max-version", "max_version"],
        "maxVersion",
        settings.max_version,
        true,
    )?;
    settings.cipher_suites = merge_optional_string_param(
        node,
        &["cipherSuites", "cipher-suites", "cipher_suites"],
        "cipherSuites",
        settings.cipher_suites,
        false,
    )?;
    settings.curve_preferences = merge_optional_string_list_param(
        node,
        &["curvePreferences", "curve-preferences", "curve_preferences"],
        "curvePreferences",
        settings.curve_preferences,
    )?;
    settings.master_key_log = merge_optional_string_param(
        node,
        &["masterKeyLog", "master-key-log", "master_key_log"],
        "masterKeyLog",
        settings.master_key_log,
        false,
    )?;
    settings.pinned_peer_cert_sha256 = merge_optional_string_param(
        node,
        &[
            "pinnedPeerCertSha256",
            "pinned-peer-cert-sha256",
            "pinned_peer_cert_sha256",
            "pinSHA256",
            "pin-sha256",
            "pin_sha256",
        ],
        "pinnedPeerCertSha256",
        settings.pinned_peer_cert_sha256,
        true,
    )?;
    settings.verify_peer_cert_by_name = merge_optional_string_param(
        node,
        &[
            "verifyPeerCertByName",
            "verify-peer-cert-by-name",
            "verify_peer_cert_by_name",
        ],
        "verifyPeerCertByName",
        settings.verify_peer_cert_by_name,
        true,
    )?;
    settings.ech_config_list = merge_optional_string_param(
        node,
        &["echConfigList", "ech-config-list", "ech_config_list"],
        "echConfigList",
        settings.ech_config_list,
        false,
    )?;
    if let Some(enabled) = ech_toggle {
        if enabled != settings.ech_config_list.is_some() {
            return Err(if enabled {
                "ech=true requires a non-empty echConfigList".into()
            } else {
                "ech=false conflicts with echConfigList".into()
            });
        }
    }
    if !fallback_alpn.is_empty() {
        if settings
            .alpn
            .as_ref()
            .is_some_and(|typed| typed != &fallback_alpn)
        {
            return Err("typed TLS alpn conflicts with protocol ALPN".into());
        }
        settings.alpn = Some(fallback_alpn);
    }

    settings
        .validate()
        .map_err(|error| format!("TLS settings: {error}"))?;
    TlsOptions::from_xray_settings(settings).map_err(|error| error.to_string())
}

fn reject_ordinary_tls_with_reality(node: &ParsedNode) -> Result<(), String> {
    const TLS_ONLY_KEYS: &[&str] = &[
        "enableSessionResumption",
        "enable-session-resumption",
        "enable_session_resumption",
        "disableSystemRoot",
        "disable-system-root",
        "disable_system_root",
        "minVersion",
        "min-version",
        "min_version",
        "maxVersion",
        "max-version",
        "max_version",
        "cipherSuites",
        "cipher-suites",
        "cipher_suites",
        "curvePreferences",
        "curve-preferences",
        "curve_preferences",
        "pinnedPeerCertSha256",
        "pinned-peer-cert-sha256",
        "pinned_peer_cert_sha256",
        "verifyPeerCertByName",
        "verify-peer-cert-by-name",
        "verify_peer_cert_by_name",
        "echConfigList",
        "ech-config-list",
        "ech_config_list",
        "alpn",
        "allowInsecure",
        "allow-insecure",
        "allow_insecure",
        "utls",
    ];
    let ech_enabled = first_param(node, &["ech"])
        .map(|value| parse_bool_param("ech", value))
        .transpose()?
        .unwrap_or(false);
    if node.tls_settings.is_some()
        || ech_enabled
        || TLS_ONLY_KEYS
            .iter()
            .any(|key| node.params.contains_key(*key))
    {
        return Err("ordinary TLS/ECH settings cannot be combined with REALITY".into());
    }
    Ok(())
}

fn grpc_param<'a>(node: &'a ParsedNode, keys: &[&str]) -> Result<Option<&'a str>, &'static str> {
    let mut value = None;
    for key in keys {
        let Some(candidate) = node.params.get(*key).map(String::as_str) else {
            continue;
        };
        if let Some(existing) = value
            && existing != candidate
        {
            return Err("grpc(conflicting-options)");
        }
        value = Some(candidate);
    }
    Ok(value)
}

fn parse_grpc_bool(value: Option<&str>) -> Result<Option<bool>, &'static str> {
    let Some(value) = value else {
        return Ok(None);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(Some(true)),
        "false" | "0" | "no" | "off" => Ok(Some(false)),
        _ => Err("grpc(invalid-boolean-option)"),
    }
}

fn parse_grpc_duration(value: Option<&str>) -> Result<std::time::Duration, &'static str> {
    let Some(value) = value else {
        return Ok(std::time::Duration::ZERO);
    };
    let value = value.trim();
    if let Ok(seconds) = value.parse::<i64>() {
        if seconds > i64::from(i32::MAX) {
            return Err("grpc(invalid-duration)");
        }
        return Ok(std::time::Duration::from_secs(seconds.max(0) as u64));
    }
    let duration = parse_tuic_duration(value).ok_or("grpc(invalid-duration)")?;
    if duration.subsec_nanos() != 0 || duration.as_secs() > i32::MAX as u64 {
        return Err("grpc(invalid-duration)");
    }
    Ok(duration)
}

fn parse_grpc_window(value: Option<&str>) -> Result<Option<u32>, &'static str> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value
        .trim()
        .parse::<i64>()
        .map_err(|_| "grpc(invalid-initial-window-size)")?;
    if value <= 0 {
        return Ok(None);
    }
    if value > i64::from(i32::MAX) {
        return Err("grpc(invalid-initial-window-size)");
    }
    Ok(Some(value as u32))
}

fn parse_grpc_positive_usize(
    value: Option<&str>,
    default: usize,
    minimum: usize,
    maximum: usize,
) -> Result<usize, &'static str> {
    let Some(value) = value else {
        return Ok(default);
    };
    let parsed = value
        .trim()
        .parse::<usize>()
        .map_err(|_| "grpc(invalid-resource-limit)")?;
    if !(minimum..=maximum).contains(&parsed) {
        return Err("grpc(invalid-resource-limit)");
    }
    Ok(parsed)
}

fn build_xhttp_options(
    node: &ParsedNode,
    sni: Option<String>,
    insecure: bool,
    alpn: Vec<String>,
) -> Result<XhttpOptions, String> {
    build_xhttp_options_with_tls_requirement(node, sni, insecure, alpn, false)
}

fn build_xhttp_options_with_tls_requirement(
    node: &ParsedNode,
    sni: Option<String>,
    insecure: bool,
    alpn: Vec<String>,
    require_tls: bool,
) -> Result<XhttpOptions, String> {
    let mut cfg = XhttpConfig::default();
    apply_legacy_xhttp_params(node, &mut cfg)?;
    if let Some(typed) = &node.xhttp {
        overlay_typed_xhttp(&mut cfg, typed)?;
    }
    let cfg = cfg.into_normalized()?;
    let has_reality = node
        .params
        .get("security")
        .map(|security| security.eq_ignore_ascii_case("reality"))
        .unwrap_or(false);
    let mut tls_settings = node.tls_settings.clone().unwrap_or_default();
    let fingerprint_param = first_param(node, &["fingerprint", "fp"]);
    let utls_param = first_param(node, &["utls"]);
    if let (Some(fingerprint), Some(utls)) = (fingerprint_param, utls_param) {
        if !fingerprint.eq_ignore_ascii_case(utls) {
            return Err(format!(
                "XHTTP TLS fingerprint={fingerprint:?} conflicts with utls={utls:?}"
            ));
        }
    }
    let param_fingerprint = fingerprint_param.or(utls_param);
    if let (Some(typed), Some(param)) = (tls_settings.fingerprint.as_deref(), param_fingerprint) {
        if !typed.eq_ignore_ascii_case(param) {
            return Err(format!(
                "XHTTP typed TLS fingerprint={typed:?} conflicts with URI fingerprint={param:?}"
            ));
        }
    } else if let Some(param) = param_fingerprint {
        tls_settings.fingerprint = Some(param.to_owned());
    }
    tls_settings.server_name = merge_optional_string_param(
        node,
        &["serverName", "server-name", "server_name", "sni"],
        "serverName",
        tls_settings.server_name,
        true,
    )?;
    tls_settings.allow_insecure = merge_optional_bool_param(
        node,
        &[
            "allowInsecure",
            "allow-insecure",
            "allow_insecure",
            "insecure",
            "skip-cert-verify",
        ],
        "allowInsecure",
        tls_settings.allow_insecure,
    )?;
    tls_settings.enable_session_resumption = merge_optional_bool_param(
        node,
        &[
            "enableSessionResumption",
            "enable-session-resumption",
            "enable_session_resumption",
        ],
        "enableSessionResumption",
        tls_settings.enable_session_resumption,
    )?;
    tls_settings.disable_system_root = merge_optional_bool_param(
        node,
        &[
            "disableSystemRoot",
            "disable-system-root",
            "disable_system_root",
        ],
        "disableSystemRoot",
        tls_settings.disable_system_root,
    )?;
    tls_settings.min_version = merge_optional_string_param(
        node,
        &["minVersion", "min-version", "min_version"],
        "minVersion",
        tls_settings.min_version,
        true,
    )?;
    tls_settings.max_version = merge_optional_string_param(
        node,
        &["maxVersion", "max-version", "max_version"],
        "maxVersion",
        tls_settings.max_version,
        true,
    )?;
    tls_settings.cipher_suites = merge_optional_string_param(
        node,
        &["cipherSuites", "cipher-suites", "cipher_suites"],
        "cipherSuites",
        tls_settings.cipher_suites,
        false,
    )?;
    tls_settings.curve_preferences = merge_optional_string_list_param(
        node,
        &["curvePreferences", "curve-preferences", "curve_preferences"],
        "curvePreferences",
        tls_settings.curve_preferences,
    )?;
    tls_settings.master_key_log = merge_optional_string_param(
        node,
        &["masterKeyLog", "master-key-log", "master_key_log"],
        "masterKeyLog",
        tls_settings.master_key_log,
        false,
    )?;
    tls_settings.pinned_peer_cert_sha256 = merge_optional_string_param(
        node,
        &[
            "pinnedPeerCertSha256",
            "pinned-peer-cert-sha256",
            "pinned_peer_cert_sha256",
        ],
        "pinnedPeerCertSha256",
        tls_settings.pinned_peer_cert_sha256,
        true,
    )?;
    tls_settings.verify_peer_cert_by_name = merge_optional_string_param(
        node,
        &[
            "verifyPeerCertByName",
            "verify-peer-cert-by-name",
            "verify_peer_cert_by_name",
        ],
        "verifyPeerCertByName",
        tls_settings.verify_peer_cert_by_name,
        true,
    )?;
    tls_settings.ech_config_list = merge_optional_string_param(
        node,
        &["echConfigList", "ech-config-list", "ech_config_list"],
        "echConfigList",
        tls_settings.ech_config_list,
        false,
    )?;
    if !alpn.is_empty() {
        if let Some(typed_alpn) = tls_settings
            .alpn
            .as_ref()
            .filter(|values| !values.is_empty())
        {
            if typed_alpn != &alpn {
                return Err(format!(
                    "XHTTP typed TLS alpn={typed_alpn:?} conflicts with URI alpn={alpn:?}"
                ));
            }
        } else {
            tls_settings.alpn = Some(alpn.clone());
        }
    }
    let uri_tls_keys = [
        "fingerprint",
        "fp",
        "utls",
        "serverName",
        "server-name",
        "server_name",
        "sni",
        "allowInsecure",
        "allow-insecure",
        "allow_insecure",
        "insecure",
        "skip-cert-verify",
        "enableSessionResumption",
        "enable-session-resumption",
        "enable_session_resumption",
        "disableSystemRoot",
        "disable-system-root",
        "disable_system_root",
        "minVersion",
        "min-version",
        "min_version",
        "maxVersion",
        "max-version",
        "max_version",
        "cipherSuites",
        "cipher-suites",
        "cipher_suites",
        "curvePreferences",
        "curve-preferences",
        "curve_preferences",
        "masterKeyLog",
        "master-key-log",
        "master_key_log",
        "pinnedPeerCertSha256",
        "pinned-peer-cert-sha256",
        "pinned_peer_cert_sha256",
        "verifyPeerCertByName",
        "verify-peer-cert-by-name",
        "verify_peer_cert_by_name",
        "echConfigList",
        "ech-config-list",
        "ech_config_list",
    ];
    let has_typed_tls_settings = node.tls_settings.is_some()
        || uri_tls_keys
            .iter()
            .any(|key| node.params.contains_key(*key));
    let tls = require_tls || node.tls || has_reality;
    if tls && !has_reality && (insecure || tls_settings.allow_insecure.unwrap_or(false)) {
        return Err(
            "XHTTP TLS allowInsecure=true has been removed by Xray; use pinnedPeerCertSha256 or verifyPeerCertByName"
                .into(),
        );
    }
    let alpn = if tls && !has_reality && alpn.is_empty() {
        vec!["h2".into(), "http/1.1".into()]
    } else {
        alpn
    };
    Ok(XhttpOptions {
        enabled: true,
        config: cfg,
        tls,
        sni,
        insecure,
        alpn,
        enable_session_resumption: tls_settings.enable_session_resumption.unwrap_or(false),
        fingerprint: tls_settings.fingerprint.clone(),
        pinned_peer_cert_sha256: Vec::new(),
        verify_peer_cert_by_name: Vec::new(),
        tls_settings: has_typed_tls_settings.then_some(tls_settings),
        reality_settings: node.reality_settings.clone(),
        has_reality,
    })
}

/// Convert the shared strongly typed configuration model into the executable
/// XHTTP transport configuration. Inbound and outbound wiring use this single
/// mapping so nested/defaulted fields cannot drift between directions.
pub fn typed_xhttp_config(typed: &TypedXhttpConfig) -> Result<XhttpConfig, String> {
    let mut config = XhttpConfig::default();
    overlay_typed_xhttp(&mut config, typed)?;
    config.into_normalized()
}

fn apply_legacy_xhttp_params(node: &ParsedNode, cfg: &mut XhttpConfig) -> Result<(), String> {
    if let Some(host) = node
        .transport_host
        .as_deref()
        .or_else(|| first_param(node, &["host", "xhttp-host", "xhttpHost"]))
    {
        cfg.host = host.into();
    }
    if let Some(path) = node
        .transport_path
        .as_deref()
        .or_else(|| first_param(node, &["path", "xhttp-path", "xhttpPath"]))
    {
        cfg.path = path.into();
    }
    copy_param(node, &["mode", "xhttp-mode", "xhttpMode"], &mut cfg.mode);

    if let Some(raw) = first_param(node, &["headers", "xhttp-headers", "xhttpHeaders"]) {
        cfg.headers = serde_json::from_str::<BTreeMap<String, String>>(raw)
            .map_err(|error| format!("invalid XHTTP headers JSON: {error}"))?;
    }
    if let Some(value) = first_param(
        node,
        &["xPaddingBytes", "x-padding-bytes", "x_padding_bytes"],
    ) {
        cfg.x_padding_bytes = value.into();
    }
    if let Some(value) = first_param(
        node,
        &[
            "xPaddingObfsMode",
            "x-padding-obfs-mode",
            "x_padding_obfs_mode",
        ],
    ) {
        cfg.x_padding_obfs_mode = parse_bool_param("xPaddingObfsMode", value)?;
    }
    copy_param(
        node,
        &["xPaddingKey", "x-padding-key", "x_padding_key"],
        &mut cfg.x_padding_key,
    );
    copy_param(
        node,
        &["xPaddingHeader", "x-padding-header", "x_padding_header"],
        &mut cfg.x_padding_header,
    );
    copy_param(
        node,
        &[
            "xPaddingPlacement",
            "x-padding-placement",
            "x_padding_placement",
        ],
        &mut cfg.x_padding_placement,
    );
    copy_param(
        node,
        &["xPaddingMethod", "x-padding-method", "x_padding_method"],
        &mut cfg.x_padding_method,
    );
    copy_param(
        node,
        &[
            "uplinkHTTPMethod",
            "uplinkHttpMethod",
            "uplink-http-method",
            "uplink_http_method",
        ],
        &mut cfg.uplink_http_method,
    );
    if let Some(value) = first_param(
        node,
        &[
            "noGRPCHeader",
            "noGrpcHeader",
            "no-grpc-header",
            "no_grpc_header",
        ],
    ) {
        cfg.no_grpc_header = parse_bool_param("noGRPCHeader", value)?;
    }
    if let Some(value) = first_param(
        node,
        &[
            "noSSEHeader",
            "noSseHeader",
            "no-sse-header",
            "no_sse_header",
        ],
    ) {
        cfg.no_sse_header = parse_bool_param("noSSEHeader", value)?;
    }
    copy_param(
        node,
        &[
            "sessionIDPlacement",
            "sessionIdPlacement",
            "session-id-placement",
            "session-placement",
            "session_id_placement",
        ],
        &mut cfg.session_placement,
    );
    copy_param(
        node,
        &[
            "sessionIDKey",
            "sessionIdKey",
            "session-id-key",
            "session-key",
            "session_id_key",
        ],
        &mut cfg.session_key,
    );
    copy_param(
        node,
        &[
            "sessionIDTable",
            "sessionIdTable",
            "session-id-table",
            "session-table",
            "session_id_table",
        ],
        &mut cfg.session_id_table,
    );
    copy_param(
        node,
        &[
            "sessionIDLength",
            "sessionIdLength",
            "session-id-length",
            "session-length",
            "session_id_length",
        ],
        &mut cfg.session_id_length,
    );
    copy_param(
        node,
        &["seqPlacement", "seq-placement", "seq_placement"],
        &mut cfg.seq_placement,
    );
    copy_param(node, &["seqKey", "seq-key", "seq_key"], &mut cfg.seq_key);
    copy_param(
        node,
        &[
            "uplinkDataPlacement",
            "uplink-data-placement",
            "uplink_data_placement",
        ],
        &mut cfg.uplink_data_placement,
    );
    copy_param(
        node,
        &["uplinkDataKey", "uplink-data-key", "uplink_data_key"],
        &mut cfg.uplink_data_key,
    );
    copy_param(
        node,
        &["uplinkChunkSize", "uplink-chunk-size", "uplink_chunk_size"],
        &mut cfg.uplink_chunk_size,
    );
    copy_param(
        node,
        &[
            "scMaxEachPostBytes",
            "sc-max-each-post-bytes",
            "sc_max_each_post_bytes",
        ],
        &mut cfg.sc_max_each_post_bytes,
    );
    copy_param(
        node,
        &[
            "scMinPostsIntervalMs",
            "sc-min-posts-interval-ms",
            "sc_min_posts_interval_ms",
        ],
        &mut cfg.sc_min_posts_interval_ms,
    );
    if let Some(value) = first_param(
        node,
        &[
            "scMaxBufferedPosts",
            "sc-max-buffered-posts",
            "sc_max_buffered_posts",
        ],
    ) {
        cfg.sc_max_buffered_posts = value
            .parse()
            .map_err(|_| format!("invalid scMaxBufferedPosts: {value}"))?;
    }
    copy_param(
        node,
        &[
            "scStreamUpServerSecs",
            "sc-stream-up-server-secs",
            "sc_stream_up_server_secs",
        ],
        &mut cfg.sc_stream_up_server_secs,
    );
    if let Some(value) = first_param(
        node,
        &[
            "serverMaxHeaderBytes",
            "server-max-header-bytes",
            "server_max_header_bytes",
        ],
    ) {
        cfg.server_max_header_bytes = value
            .parse()
            .map_err(|_| format!("invalid serverMaxHeaderBytes: {value}"))?;
    }

    copy_param(
        node,
        &[
            "xmux.maxConcurrency",
            "maxConcurrency",
            "max-concurrency",
            "max_concurrency",
        ],
        &mut cfg.xmux.max_concurrency,
    );
    copy_param(
        node,
        &[
            "xmux.maxConnections",
            "maxConnections",
            "max-connections",
            "max_connections",
        ],
        &mut cfg.xmux.max_connections,
    );
    copy_param(
        node,
        &[
            "xmux.cMaxReuseTimes",
            "cMaxReuseTimes",
            "c-max-reuse-times",
            "c_max_reuse_times",
        ],
        &mut cfg.xmux.c_max_reuse_times,
    );
    copy_param(
        node,
        &[
            "xmux.hMaxRequestTimes",
            "hMaxRequestTimes",
            "h-max-request-times",
            "h_max_request_times",
        ],
        &mut cfg.xmux.h_max_request_times,
    );
    copy_param(
        node,
        &[
            "xmux.hMaxReusableSecs",
            "hMaxReusableSecs",
            "h-max-reusable-secs",
            "h_max_reusable_secs",
        ],
        &mut cfg.xmux.h_max_reusable_secs,
    );
    if let Some(value) = first_param(
        node,
        &[
            "xmux.hKeepAlivePeriod",
            "hKeepAlivePeriod",
            "h-keep-alive-period",
            "h_keep_alive_period",
        ],
    ) {
        cfg.xmux.h_keep_alive_period = value
            .parse()
            .map_err(|_| format!("invalid hKeepAlivePeriod: {value}"))?;
    }

    if let Some(raw) = first_param(
        node,
        &["downloadSettings", "download-settings", "download_config"],
    ) {
        let typed = serde_json::from_str::<TypedDownloadSettings>(raw)
            .map_err(|error| format!("invalid typed downloadSettings JSON: {error}"))?;
        cfg.download_settings = Some(Box::new(map_typed_download_settings(&typed)?));
    }
    if let Some(raw) = first_param(node, &["extra", "xhttp-extra"]) {
        let typed = serde_json::from_str::<TypedXhttpConfig>(raw)
            .map_err(|error| format!("invalid typed XHTTP extra JSON: {error}"))?;
        let mut extra = XhttpConfig::default();
        overlay_typed_xhttp(&mut extra, &typed)?;
        cfg.extra = Some(Box::new(extra));
    }
    Ok(())
}

fn overlay_typed_xhttp(target: &mut XhttpConfig, typed: &TypedXhttpConfig) -> Result<(), String> {
    typed.validate()?;
    let typed = typed.resolved()?;
    overlay_string(&mut target.host, typed.host.as_deref());
    overlay_string(&mut target.path, typed.path.as_deref());
    overlay_string(&mut target.mode, typed.mode.as_deref());
    if let Some(headers) = typed.headers {
        target.headers = headers;
    }
    overlay_range(&mut target.x_padding_bytes, typed.x_padding_bytes);
    if let Some(value) = typed.x_padding_obfs_mode {
        target.x_padding_obfs_mode = value;
    }
    overlay_string(&mut target.x_padding_key, typed.x_padding_key.as_deref());
    overlay_string(
        &mut target.x_padding_header,
        typed.x_padding_header.as_deref(),
    );
    overlay_string(
        &mut target.x_padding_placement,
        typed.x_padding_placement.as_deref(),
    );
    overlay_string(
        &mut target.x_padding_method,
        typed.x_padding_method.as_deref(),
    );
    overlay_string(
        &mut target.uplink_http_method,
        typed.uplink_http_method.as_deref(),
    );
    overlay_string(
        &mut target.session_placement,
        typed.session_id_placement.as_deref(),
    );
    overlay_string(&mut target.session_key, typed.session_id_key.as_deref());
    overlay_string(
        &mut target.session_id_table,
        typed.session_id_table.as_deref(),
    );
    overlay_range(&mut target.session_id_length, typed.session_id_length);
    overlay_string(&mut target.seq_placement, typed.seq_placement.as_deref());
    overlay_string(&mut target.seq_key, typed.seq_key.as_deref());
    overlay_string(
        &mut target.uplink_data_placement,
        typed.uplink_data_placement.as_deref(),
    );
    overlay_string(
        &mut target.uplink_data_key,
        typed.uplink_data_key.as_deref(),
    );
    overlay_range(&mut target.uplink_chunk_size, typed.uplink_chunk_size);
    if let Some(value) = typed.no_grpc_header {
        target.no_grpc_header = value;
    }
    if let Some(value) = typed.no_sse_header {
        target.no_sse_header = value;
    }
    overlay_range(
        &mut target.sc_max_each_post_bytes,
        typed.sc_max_each_post_bytes,
    );
    overlay_range(
        &mut target.sc_min_posts_interval_ms,
        typed.sc_min_posts_interval_ms,
    );
    if let Some(value) = typed.sc_max_buffered_posts {
        target.sc_max_buffered_posts = value;
    }
    overlay_range(
        &mut target.sc_stream_up_server_secs,
        typed.sc_stream_up_server_secs,
    );
    if let Some(value) = typed.server_max_header_bytes {
        target.server_max_header_bytes = value;
    }
    if let Some(xmux) = typed.xmux {
        target.xmux = Default::default();
        overlay_range(&mut target.xmux.max_concurrency, xmux.max_concurrency);
        overlay_range(&mut target.xmux.max_connections, xmux.max_connections);
        overlay_range(&mut target.xmux.c_max_reuse_times, xmux.c_max_reuse_times);
        overlay_range(
            &mut target.xmux.h_max_request_times,
            xmux.h_max_request_times,
        );
        overlay_range(
            &mut target.xmux.h_max_reusable_secs,
            xmux.h_max_reusable_secs,
        );
        if let Some(value) = xmux.h_keep_alive_period {
            target.xmux.h_keep_alive_period = value;
        }
    }
    if let Some(download) = typed.download_settings {
        target.download_settings = Some(Box::new(map_typed_download_settings(&download)?));
    }
    Ok(())
}

fn map_typed_download_settings(typed: &TypedDownloadSettings) -> Result<DownloadSettings, String> {
    // This mapper is also reached by the legacy URI `downloadSettings` JSON
    // parameter. Validate the typed model before any aliases are collapsed so
    // legacy input cannot bypass core-config's ambiguity checks.
    typed.validate()?;

    // Runtime keeps the same strict nested types as core-config. This avoids a
    // lossy "recognized by serde but dropped before dial" boundary.
    let tls: Option<DownloadTlsSettings> = typed.tls_settings.clone();
    let reality: Option<DownloadRealitySettings> = typed.reality_settings.clone();
    let socket: Option<DownloadSocketSettings> = typed.socket_settings.clone();

    let mut transport = typed
        .transport
        .as_deref()
        .map(|settings| DownloadTransportSettings {
            kind: settings.kind.clone().unwrap_or_default(),
            host: settings.host.clone().unwrap_or_default(),
            path: settings.path.clone().unwrap_or_default(),
            service: settings.service.clone().unwrap_or_default(),
            xhttp: None,
        })
        .unwrap_or_default();
    let direct_xhttp = typed
        .xhttp_settings
        .as_deref()
        .map(|config| map_typed_download_xhttp(config, &transport.host, &transport.path))
        .transpose()?
        .map(Box::new);
    transport.xhttp = typed
        .transport
        .as_deref()
        .and_then(|value| value.xhttp.as_ref())
        .map(|config| map_typed_download_xhttp(config, &transport.host, &transport.path))
        .transpose()?
        .map(Box::new);
    if direct_xhttp.is_none() && transport.xhttp.is_none() {
        return Err("downloadSettings requires independent XHTTP config".to_string());
    }

    let security = typed
        .security
        .as_deref()
        .filter(|security| !security.is_empty())
        .unwrap_or("none")
        .to_owned();
    let alpn = if security.eq_ignore_ascii_case("tls")
        && typed.alpn.as_ref().is_none_or(Vec::is_empty)
        && tls
            .as_ref()
            .and_then(|settings| settings.alpn.as_ref())
            .is_none_or(Vec::is_empty)
    {
        vec!["h2".into(), "http/1.1".into()]
    } else {
        typed.alpn.clone().unwrap_or_default()
    };

    let download = DownloadSettings {
        address: typed.address.clone().unwrap_or_default(),
        host: typed.host.clone().unwrap_or_default(),
        port: typed.port,
        method: typed.method.clone().unwrap_or_default(),
        network: typed.network.clone().unwrap_or_else(|| "xhttp".into()),
        transport: Some(transport),
        xhttp_settings: direct_xhttp,
        security,
        tls,
        reality,
        alpn,
        socket,
        final_mask: typed.final_mask.clone(),
    };
    download.validate(0)?;
    Ok(download)
}

fn map_typed_download_xhttp(
    typed: &TypedXhttpConfig,
    transport_host: &str,
    transport_path: &str,
) -> Result<XhttpConfig, String> {
    let mut config = XhttpConfig::default();
    overlay_typed_xhttp(&mut config, typed)?;
    if config.host.is_empty() {
        config.host = transport_host.into();
    }
    if config.path.is_empty() {
        config.path = transport_path.into();
    }
    config.into_normalized()
}

fn first_param<'a>(node: &'a ParsedNode, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| node.params.get(*key).map(String::as_str))
}

fn merge_optional_string_param(
    node: &ParsedNode,
    keys: &[&str],
    field: &str,
    typed: Option<String>,
    ascii_case_insensitive: bool,
) -> Result<Option<String>, String> {
    let Some(param) = first_param(node, keys) else {
        return Ok(typed);
    };
    if let Some(typed) = typed.as_deref() {
        let equal = if ascii_case_insensitive {
            typed.eq_ignore_ascii_case(param)
        } else {
            typed == param
        };
        if !equal {
            return Err(format!(
                "XHTTP typed TLS {field}={typed:?} conflicts with URI {field}={param:?}"
            ));
        }
    }
    Ok(Some(param.to_owned()))
}

fn merge_optional_bool_param(
    node: &ParsedNode,
    keys: &[&str],
    field: &str,
    typed: Option<bool>,
) -> Result<Option<bool>, String> {
    let Some(raw) = first_param(node, keys) else {
        return Ok(typed);
    };
    let param = parse_bool_param(field, raw)?;
    if typed.is_some_and(|typed| typed != param) {
        return Err(format!(
            "XHTTP typed TLS {field}={typed:?} conflicts with URI {field}={param:?}"
        ));
    }
    Ok(Some(param))
}

fn merge_optional_string_list_param(
    node: &ParsedNode,
    keys: &[&str],
    field: &str,
    typed: Option<Vec<String>>,
) -> Result<Option<Vec<String>>, String> {
    let Some(raw) = first_param(node, keys) else {
        return Ok(typed);
    };
    let param = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if param.is_empty() {
        return Err(format!("XHTTP TLS {field} cannot be empty"));
    }
    if typed.as_ref().is_some_and(|typed| typed != &param) {
        return Err(format!(
            "XHTTP typed TLS {field}={typed:?} conflicts with URI {field}={param:?}"
        ));
    }
    Ok(Some(param))
}

fn copy_param(node: &ParsedNode, keys: &[&str], target: &mut String) {
    if let Some(value) = first_param(node, keys) {
        *target = value.into();
    }
}

fn parse_bool_param(field: &str, value: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("invalid boolean for {field}: {value}")),
    }
}

fn overlay_string(target: &mut String, value: Option<&str>) {
    if let Some(value) = value {
        *target = value.into();
    }
}

fn overlay_range(target: &mut String, value: Option<TypedRange>) {
    if let Some(value) = value {
        *target = value.to_string();
    }
}

fn build_trojan(node: &ParsedNode) -> Result<TrojanOutbound, String> {
    let pwd = node.password.clone().unwrap_or_default();
    let mut ob = TrojanOutbound::new(&node.name, &node.host, node.port, pwd);
    if node
        .params
        .get("security")
        .is_some_and(|value| value.eq_ignore_ascii_case("none"))
        || node
            .params
            .get("tls")
            .is_some_and(|value| value.eq_ignore_ascii_case("false") || value == "0")
    {
        ob.tls = false;
    }
    ob.udp = node.udp;
    ob.sni = node
        .sni
        .clone()
        .filter(|s| !s.is_empty())
        .or(Some(node.host.clone()));
    ob.insecure = node
        .params
        .get("allowInsecure")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    if let Some(alpn) = node.params.get("alpn") {
        ob.alpn = alpn.split(',').map(|s| s.trim().to_string()).collect();
    }
    let tls_options =
        build_node_tls_options(node, ob.tls, ob.sni.clone(), ob.insecure, ob.alpn.clone())?;
    if ob.tls {
        ob.tls_options = Some(tls_options);
    }
    match resolve_network_string(node).to_ascii_lowercase().as_str() {
        "xhttp" | "splithttp" => {
            ob.xhttp = Some(build_xhttp_options_with_tls_requirement(
                node,
                ob.sni.clone(),
                ob.insecure,
                ob.alpn.clone(),
                true,
            )?);
        }
        "grpc" | "gun" => {
            ob.grpc = Some(build_grpc_options(node)?);
        }
        _ => {}
    }
    Ok(ob)
}

fn build_snell(node: &ParsedNode) -> Result<SharedOutbound, String> {
    let cipher = match node.params.get("cipher").or_else(|| node.method.as_ref()) {
        Some(value) => SnellCipher::parse(value)
            .ok_or_else(|| format!("unsupported Snell cipher `{value}`"))?,
        None => SnellCipher::Aes128Gcm,
    };
    let pwd = node
        .password
        .as_deref()
        .or_else(|| node.params.get("psk").map(|s| s.as_str()))
        .unwrap_or("");
    if pwd.is_empty() {
        return Err("Snell PSK must not be empty".into());
    }
    let mut ob = SnellOutbound::new(&node.name, &node.host, node.port, cipher, pwd);
    ob.udp = node.udp;
    if let Some(value) = node.params.get("version") {
        ob.version = value
            .parse::<u8>()
            .map_err(|_| format!("invalid Snell version `{value}`"))?;
    }
    if let Some(obfs_type) = node.params.get("obfs").map(|s| s.as_str()) {
        let obfs_host = node
            .params
            .get("obfs-host")
            .cloned()
            .unwrap_or_else(|| node.host.clone());
        match obfs_type {
            "http" => ob = ob.with_obfs_http(obfs_host),
            "tls" => ob = ob.with_obfs_tls(obfs_host),
            other => return Err(format!("unsupported Snell obfs `{other}`")),
        }
    }
    Ok(Arc::new(ob))
}

fn build_anytls(node: &ParsedNode) -> Result<SharedOutbound, String> {
    let pwd = node
        .password
        .clone()
        .filter(|password| !password.is_empty())
        .ok_or_else(|| "AnyTLS password must not be empty".to_string())?;
    let mut ob = AnyTlsOutbound::new(&node.name, &node.host, node.port, pwd);
    if let Some(client_id) = first_param(
        node,
        &[
            "clientId",
            "client-id",
            "client_id",
            "anytls-client-id",
            "anytls_client_id",
        ],
    ) {
        ob.set_client_id(client_id.to_owned())?;
    }
    let disable_sni = node
        .params
        .get("disable-sni")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    ob.sni = if disable_sni {
        None
    } else {
        node.sni
            .clone()
            .filter(|s| !s.is_empty())
            .or(Some(node.host.clone()))
    };
    ob.insecure = node
        .params
        .get("insecure")
        .or_else(|| node.params.get("allowInsecure"))
        .or_else(|| node.params.get("allow-insecure"))
        .or_else(|| node.params.get("allow_insecure"))
        .map(|value| parse_bool_param("AnyTLS insecure", value))
        .transpose()?
        .unwrap_or(false);
    if let Some(alpn) = node.params.get("alpn") {
        ob.alpn = alpn
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect();
    }
    if let Some(fingerprint) = first_param(node, &["fingerprint", "fp"]) {
        ob.fingerprint = fingerprint.to_owned();
    }
    if let Some(value) = first_param(
        node,
        &[
            "enableSessionResumption",
            "enable-session-resumption",
            "enable_session_resumption",
        ],
    ) {
        ob.enable_session_resumption = parse_bool_param("AnyTLS enableSessionResumption", value)?;
    }
    if let Some(value) = first_param(
        node,
        &[
            "idleSessionCheckInterval",
            "idle-session-check-interval",
            "idle_session_check_interval",
        ],
    ) {
        ob.options.idle_session_check_interval = parse_tuic_duration(value)
            .ok_or_else(|| format!("invalid AnyTLS idleSessionCheckInterval `{value}`"))?;
    }
    if let Some(value) = first_param(
        node,
        &[
            "idleSessionTimeout",
            "idle-session-timeout",
            "idle_session_timeout",
        ],
    ) {
        ob.options.idle_session_timeout = parse_tuic_duration(value)
            .ok_or_else(|| format!("invalid AnyTLS idleSessionTimeout `{value}`"))?;
    }
    if let Some(value) = first_param(
        node,
        &["minIdleSession", "min-idle-session", "min_idle_session"],
    ) {
        ob.options.min_idle_session = value
            .parse::<usize>()
            .map_err(|_| format!("invalid AnyTLS minIdleSession `{value}`"))?;
    }
    if let Some(value) = first_param(node, &["disableReuse", "disable-reuse", "disable_reuse"]) {
        ob.options.disable_reuse = parse_bool_param("AnyTLS disableReuse", value)?;
    }
    ob.options.udp_over_tcp = node.udp;
    if let Some(value) = first_param(node, &["udp-over-tcp", "udp_over_tcp"]) {
        ob.options.udp_over_tcp = parse_bool_param("AnyTLS udp-over-tcp", value)?;
    }
    Ok(Arc::new(ob))
}

fn build_ssh(node: &ParsedNode) -> Result<SharedOutbound, String> {
    let user = node.user.clone().unwrap_or_default();
    if user.trim().is_empty() {
        return Err("SSH username is required".into());
    }
    let mut ob = SshOutbound::new(&node.name, &node.host, node.port, user);
    if let Some(private_key) = node.params.get("private-key") {
        let passphrase = node
            .params
            .get("private-key-passphrase")
            .filter(|value| !value.is_empty())
            .cloned();
        ob = if private_key.contains("PRIVATE KEY") {
            ob.with_private_key_content(private_key, passphrase)?
        } else {
            ob.with_private_key_path(private_key, passphrase)?
        };
    }
    if let Some(password) = node.password.as_ref().filter(|value| !value.is_empty()) {
        // Match mihomo: public-key authentication is attempted before password
        // when both fields are configured.
        ob = ob.with_password(password);
    }
    if let Some(host_keys) = node
        .params
        .get("host-key")
        .or_else(|| node.params.get("known-hosts"))
    {
        let keys = host_keys
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(crate::proto::ssh::parse_host_key)
            .collect::<Result<Vec<_>, _>>()?;
        if !keys.is_empty() {
            ob = ob.with_host_keys(keys);
        }
    }
    if let Some(algorithms) = node.params.get("host-key-algorithms") {
        let algorithms = algorithms
            .split([',', '\n'])
            .map(str::trim)
            .filter(|algorithm| !algorithm.is_empty())
            .map(str::to_string)
            .collect();
        ob = ob.with_host_key_algorithms(algorithms)?;
    }
    if let Some(version) = node.params.get("client-version") {
        ob = ob.with_client_version(version)?;
    }
    if let Some(value) = node.params.get("keepalive-interval") {
        ob.keepalive_interval_secs = value
            .parse()
            .map_err(|_| format!("invalid SSH keepalive-interval `{value}`"))?;
    }
    Ok(Arc::new(ob))
}

fn build_hysteria_v1(node: &ParsedNode) -> Result<SharedOutbound, String> {
    if let Some(protocol) = first_param(node, &["protocol"])
        && !protocol.eq_ignore_ascii_case("udp")
    {
        return Err(format!(
            "Hysteria 1 packet transport `{protocol}` is unsupported; the official UDP carrier is required"
        ));
    }
    let auth = first_param(node, &["auth", "auth-str", "auth_str"])
        .or(node.password.as_deref())
        .or(node.user.as_deref())
        .ok_or_else(|| "Hysteria 1 requires auth/auth-str".to_owned())?
        .as_bytes()
        .to_vec();
    let tx_bps = parse_hysteria_bandwidth(
        node,
        &["up", "upmbps", "up-mbps", "up_mbps"],
        "Hysteria 1 upload bandwidth",
        true,
        HysteriaBandwidthSyntax::V1,
    )?;
    let rx_bps = parse_hysteria_bandwidth(
        node,
        &["down", "downmbps", "down-mbps", "down_mbps"],
        "Hysteria 1 download bandwidth",
        true,
        HysteriaBandwidthSyntax::V1,
    )?;
    let mut outbound =
        HysteriaOutbound::new(&node.name, &node.host, node.port, auth, tx_bps, rx_bps)
            .map_err(|error| error.to_string())?;
    outbound.udp = node.udp;
    outbound.fast_open = first_param(node, &["fastOpen", "fast-open", "fast_open"])
        .map(|value| parse_bool_param("Hysteria 1 fastOpen", value))
        .transpose()?
        .unwrap_or(false);
    reject_eager_hysteria_start(node, "Hysteria 1")?;
    let insecure = first_param(
        node,
        &[
            "insecure",
            "skip-cert-verify",
            "skip_cert_verify",
            "allowInsecure",
        ],
    )
    .map(|value| parse_bool_param("Hysteria 1 insecure", value))
    .transpose()?
    .unwrap_or(false);
    let alpn = first_param(node, &["alpn"])
        .map(parse_hysteria_alpn)
        .transpose()?
        .unwrap_or_else(|| vec!["hysteria".into()]);
    outbound.tls = build_node_tls_options(
        node,
        true,
        node.sni.clone().or_else(|| Some(node.host.clone())),
        insecure,
        alpn,
    )?;
    outbound.quic_params = hysteria1_quic_params(node)?;
    if outbound.quic_params.brutal_disable_loss_compensation {
        return Err(
            "Hysteria 1 does not define Brutal disableLossCompensation; this field is Hysteria 2-only"
                .into(),
        );
    }
    outbound.handshake_timeout = first_param(
        node,
        &["handshakeTimeout", "handshake-timeout", "handshake_timeout"],
    )
    .map(|value| {
        parse_tuic_duration(value)
            .filter(|duration| duration.as_secs_f64() >= 2.0)
            .ok_or_else(|| {
                format!("Hysteria 1 handshake timeout `{value}` must be at least 2 seconds")
            })
    })
    .transpose()?;
    if let Some(password) = first_param(node, &["obfs", "obfs-password", "obfs_password"]) {
        outbound = outbound
            .with_obfs(password.as_bytes().to_vec())
            .map_err(|error| error.to_string())?;
    }
    Ok(Arc::new(outbound))
}

fn build_hysteria2(node: &ParsedNode) -> Result<SharedOutbound, String> {
    let expanded = expand_hysteria2_official_objects(node)?;
    let node = &expanded;
    let password = first_param(node, &["auth", "password"])
        .or(node.password.as_deref())
        .or(node.user.as_deref())
        .ok_or_else(|| "Hysteria 2 requires auth/password".to_owned())?;
    if password.is_empty() {
        return Err("Hysteria 2 auth/password cannot be empty".into());
    }
    let mut outbound = Hysteria2Outbound::new(&node.name, &node.host, node.port, password);
    outbound.udp = node.udp;
    outbound.tx_bps = parse_hysteria_bandwidth(
        node,
        &["up", "upmbps", "up-mbps", "up_mbps"],
        "Hysteria 2 upload bandwidth",
        false,
        HysteriaBandwidthSyntax::V2,
    )?;
    outbound.rx_bps = parse_hysteria_bandwidth(
        node,
        &["down", "downmbps", "down-mbps", "down_mbps"],
        "Hysteria 2 download bandwidth",
        false,
        HysteriaBandwidthSyntax::V2,
    )?;
    outbound.fast_open = first_param(node, &["fastOpen", "fast-open", "fast_open"])
        .map(|value| parse_bool_param("Hysteria 2 fastOpen", value))
        .transpose()?
        .unwrap_or(false);
    reject_eager_hysteria_start(node, "Hysteria 2")?;
    outbound.disable_loss_compensation = first_param(
        node,
        &[
            "disableLossCompensation",
            "disable-loss-compensation",
            "disable_loss_compensation",
        ],
    )
    .map(|value| parse_bool_param("Hysteria 2 disableLossCompensation", value))
    .transpose()?
    .unwrap_or(false);
    let insecure = first_param(
        node,
        &[
            "insecure",
            "skip-cert-verify",
            "skip_cert_verify",
            "allowInsecure",
        ],
    )
    .map(|value| parse_bool_param("Hysteria 2 insecure", value))
    .transpose()?
    .unwrap_or(false);
    outbound.tls = build_node_tls_options(
        node,
        true,
        node.sni.clone().or_else(|| Some(node.host.clone())),
        insecure,
        vec!["h3".into()],
    )?;
    outbound.quic_params = hysteria_quic_params(node)?;
    outbound.quic_params.brutal_disable_loss_compensation = outbound.disable_loss_compensation;

    let obfs_kind = first_param(node, &["obfs"]).map(str::trim).filter(|value| {
        !value.is_empty()
            && !value.eq_ignore_ascii_case("none")
            && !value.eq_ignore_ascii_case("plain")
    });
    let obfs_password = first_param(node, &["obfs-password", "obfs_password", "obfsPassword"]);
    outbound.obfs = match (obfs_kind, obfs_password) {
        (None, None) => Hysteria2Obfs::None,
        (None, Some(_)) => {
            return Err("Hysteria 2 obfs-password requires obfs=salamander or obfs=gecko".into());
        }
        (Some(_), None) => return Err("Hysteria 2 obfs requires obfs-password".into()),
        (Some(kind), Some(password)) if kind.eq_ignore_ascii_case("salamander") => {
            Hysteria2Obfs::Salamander {
                password: password.to_owned(),
            }
        }
        (Some(kind), Some(password)) if kind.eq_ignore_ascii_case("gecko") => {
            let minimum = parse_i32_param(
                node,
                &[
                    "obfs-min-packet-size",
                    "obfs_min_packet_size",
                    "obfsMinPacketSize",
                ],
                512,
            )?;
            let maximum = parse_i32_param(
                node,
                &[
                    "obfs-max-packet-size",
                    "obfs_max_packet_size",
                    "obfsMaxPacketSize",
                ],
                1200,
            )?;
            Hysteria2Obfs::Gecko {
                password: password.to_owned(),
                min_packet_size: minimum,
                max_packet_size: maximum,
            }
        }
        (Some(kind), Some(_)) => {
            return Err(format!("unsupported Hysteria 2 obfs `{kind}`"));
        }
    };
    Ok(Arc::new(outbound))
}

fn expand_hysteria2_official_objects(node: &ParsedNode) -> Result<ParsedNode, String> {
    let mut node = node.clone();

    if let Some(object) = remove_json_object(&mut node, "bandwidth", false)? {
        reject_unknown_object_fields(
            &object,
            &["up", "down", "disableLossCompensation"],
            "Hysteria 2 bandwidth",
        )?;
        merge_json_scalar_param(&mut node, &object, "up", "up", "bandwidth.up")?;
        merge_json_scalar_param(&mut node, &object, "down", "down", "bandwidth.down")?;
        merge_json_scalar_param(
            &mut node,
            &object,
            "disableLossCompensation",
            "disableLossCompensation",
            "bandwidth.disableLossCompensation",
        )?;
    }

    if let Some(object) = remove_json_object(&mut node, "congestion", true)? {
        reject_unknown_object_fields(&object, &["type", "bbrProfile"], "Hysteria 2 congestion")?;
        merge_json_scalar_param(&mut node, &object, "type", "congestion", "congestion.type")?;
        merge_json_scalar_param(
            &mut node,
            &object,
            "bbrProfile",
            "bbrProfile",
            "congestion.bbrProfile",
        )?;
    }

    if let Some(object) = remove_json_object(&mut node, "obfs", true)? {
        reject_unknown_object_fields(&object, &["type", "salamander", "gecko"], "Hysteria 2 obfs")?;
        let kind = object
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "Hysteria 2 obfs.type must be a string".to_owned())?;
        insert_expanded_param(&mut node, "obfs", kind.to_owned(), "obfs.type")?;
        let section_name = kind.to_ascii_lowercase();
        if matches!(section_name.as_str(), "" | "plain" | "none") {
            if object.get("salamander").is_some() || object.get("gecko").is_some() {
                return Err("Hysteria 2 plain obfs cannot contain an obfs section".into());
            }
        } else if matches!(section_name.as_str(), "salamander" | "gecko") {
            let section = object
                .get(&section_name)
                .and_then(serde_json::Value::as_object)
                .ok_or_else(|| format!("Hysteria 2 obfs.{section_name} must be an object"))?;
            let allowed = if section_name == "gecko" {
                &["password", "minPacketSize", "maxPacketSize"][..]
            } else {
                &["password"][..]
            };
            reject_unknown_object_fields(
                section,
                allowed,
                &format!("Hysteria 2 obfs.{section_name}"),
            )?;
            merge_json_scalar_param(
                &mut node,
                section,
                "password",
                "obfs-password",
                &format!("obfs.{section_name}.password"),
            )?;
            if section_name == "gecko" {
                merge_json_scalar_param(
                    &mut node,
                    section,
                    "minPacketSize",
                    "obfsMinPacketSize",
                    "obfs.gecko.minPacketSize",
                )?;
                merge_json_scalar_param(
                    &mut node,
                    section,
                    "maxPacketSize",
                    "obfsMaxPacketSize",
                    "obfs.gecko.maxPacketSize",
                )?;
            }
        }
    }

    if let Some(object) = remove_json_object(&mut node, "quic", false)? {
        reject_unknown_object_fields(
            &object,
            &[
                "initStreamReceiveWindow",
                "maxStreamReceiveWindow",
                "initConnReceiveWindow",
                "maxConnReceiveWindow",
                "maxIdleTimeout",
                "keepAlivePeriod",
                "disablePathMTUDiscovery",
                "sockopts",
            ],
            "Hysteria 2 quic",
        )?;
        for key in [
            "initStreamReceiveWindow",
            "maxStreamReceiveWindow",
            "initConnReceiveWindow",
            "maxConnReceiveWindow",
            "maxIdleTimeout",
            "keepAlivePeriod",
            "disablePathMTUDiscovery",
        ] {
            merge_json_scalar_param(&mut node, &object, key, key, &format!("quic.{key}"))?;
        }
        if let Some(sockopts) = object.get("sockopts") {
            let sockopts = sockopts
                .as_object()
                .ok_or_else(|| "Hysteria 2 quic.sockopts must be an object".to_owned())?;
            reject_unknown_object_fields(
                sockopts,
                &["bindInterface", "fwmark", "fdControlUnixSocket"],
                "Hysteria 2 quic.sockopts",
            )?;
            if sockopts.get("fdControlUnixSocket").is_some() {
                return Err(
                    "Hysteria 2 quic.sockopts.fdControlUnixSocket is not available in the Rust socket backend"
                        .into(),
                );
            }
            let settings = node.stream_settings.get_or_insert_with(Default::default);
            let socket = settings.sockopt.get_or_insert_with(Default::default);
            if let Some(interface) = sockopts.get("bindInterface") {
                let interface = interface.as_str().ok_or_else(|| {
                    "Hysteria 2 quic.sockopts.bindInterface must be a string".to_owned()
                })?;
                if !socket.interface.is_empty() && socket.interface != interface {
                    return Err(
                        "Hysteria 2 quic.sockopts.bindInterface conflicts with streamSettings.sockopt.interface"
                            .into(),
                    );
                }
                socket.interface = interface.to_owned();
            }
            if let Some(mark) = sockopts.get("fwmark") {
                let mark = mark
                    .as_u64()
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or_else(|| "Hysteria 2 quic.sockopts.fwmark must be a uint32".to_owned())?
                    as i32;
                if socket.mark != 0 && socket.mark != mark {
                    return Err(
                        "Hysteria 2 quic.sockopts.fwmark conflicts with streamSettings.sockopt.mark"
                            .into(),
                    );
                }
                socket.mark = mark;
            }
        }
    }

    if let Some(object) = remove_json_object(&mut node, "tls", false)? {
        reject_unknown_object_fields(
            &object,
            &[
                "sni",
                "insecure",
                "pinSHA256",
                "ca",
                "clientCertificate",
                "clientKey",
                "ech",
            ],
            "Hysteria 2 tls",
        )?;
        for (source, target) in [
            ("sni", "sni"),
            ("insecure", "insecure"),
            ("pinSHA256", "pinSHA256"),
            ("ech", "ech"),
        ] {
            merge_json_scalar_param(&mut node, &object, source, target, &format!("tls.{source}"))?;
        }
        let ca = object.get("ca").map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "Hysteria 2 tls.ca must be a non-empty path".to_owned())
        });
        let client_certificate = object.get("clientCertificate").map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    "Hysteria 2 tls.clientCertificate must be a non-empty path".to_owned()
                })
        });
        let client_key = object.get("clientKey").map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "Hysteria 2 tls.clientKey must be a non-empty path".to_owned())
        });
        let ca = ca.transpose()?;
        let client_certificate = client_certificate.transpose()?;
        let client_key = client_key.transpose()?;
        if client_certificate.is_some() != client_key.is_some() {
            return Err(
                "Hysteria 2 tls.clientCertificate and tls.clientKey must be configured together"
                    .into(),
            );
        }
        if ca.is_some() || client_certificate.is_some() {
            let settings = node.tls_settings.get_or_insert_with(Default::default);
            if let Some(ca) = ca {
                settings.certificates.push(XhttpDownloadTlsCertificate {
                    certificate_file: Some(ca.to_owned()),
                    usage: Some(XhttpTlsCertificateUsage::Verify),
                    ..Default::default()
                });
            }
            if let (Some(certificate), Some(key)) = (client_certificate, client_key) {
                settings.certificates.push(XhttpDownloadTlsCertificate {
                    certificate_file: Some(certificate.to_owned()),
                    key_file: Some(key.to_owned()),
                    usage: Some(XhttpTlsCertificateUsage::Encipherment),
                    ..Default::default()
                });
            }
        }
    }

    if let Some(object) = remove_json_object(&mut node, "transport", false)? {
        reject_unknown_object_fields(&object, &["type", "udp"], "Hysteria 2 transport")?;
        if let Some(kind) = object.get("type") {
            let kind = kind
                .as_str()
                .ok_or_else(|| "Hysteria 2 transport.type must be a string".to_owned())?;
            if !kind.is_empty() && !kind.eq_ignore_ascii_case("udp") {
                return Err(format!("unsupported Hysteria 2 transport.type `{kind}`"));
            }
        }
        if let Some(udp) = object.get("udp") {
            let udp = udp
                .as_object()
                .ok_or_else(|| "Hysteria 2 transport.udp must be an object".to_owned())?;
            reject_unknown_object_fields(
                udp,
                &["hopInterval", "minHopInterval", "maxHopInterval"],
                "Hysteria 2 transport.udp",
            )?;
            let fixed = json_duration_seconds(udp.get("hopInterval"), "transport.udp.hopInterval")?;
            let minimum =
                json_duration_seconds(udp.get("minHopInterval"), "transport.udp.minHopInterval")?;
            let maximum =
                json_duration_seconds(udp.get("maxHopInterval"), "transport.udp.maxHopInterval")?;
            if fixed.is_some() && (minimum.is_some() || maximum.is_some()) {
                return Err(
                    "Hysteria 2 hopInterval conflicts with minHopInterval/maxHopInterval".into(),
                );
            }
            let interval = match (fixed, minimum, maximum) {
                (Some(value), None, None) => Some(I32Range::fixed(value)),
                (None, Some(minimum), Some(maximum)) => {
                    if minimum > maximum {
                        return Err("Hysteria 2 minHopInterval cannot exceed maxHopInterval".into());
                    }
                    Some(I32Range::new(minimum, maximum))
                }
                (None, None, None) => None,
                _ => {
                    return Err(
                        "Hysteria 2 minHopInterval and maxHopInterval must be configured together"
                            .into(),
                    );
                }
            };
            if let Some(interval) = interval {
                let settings = node.stream_settings.get_or_insert_with(Default::default);
                let finalmask = settings.finalmask.get_or_insert_with(Default::default);
                let params = finalmask.quic_params.get_or_insert_with(Default::default);
                if params.udp_hop.interval != I32Range::default()
                    && params.udp_hop.interval != interval
                {
                    return Err(
                        "Hysteria 2 transport.udp hop interval conflicts with finalmask.quicParams.udpHop.interval"
                            .into(),
                    );
                }
                params.udp_hop.interval = interval;
            }
        }
    }

    Ok(node)
}

fn remove_json_object(
    node: &mut ParsedNode,
    key: &str,
    allow_plain_string: bool,
) -> Result<Option<serde_json::Map<String, serde_json::Value>>, String> {
    let Some(raw) = node.params.get(key).cloned() else {
        return Ok(None);
    };
    if allow_plain_string && !raw.trim_start().starts_with('{') {
        return Ok(None);
    }
    let value: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|error| format!("Hysteria 2 {key} object is invalid JSON: {error}"))?;
    let object = value
        .as_object()
        .cloned()
        .ok_or_else(|| format!("Hysteria 2 {key} must be an object"))?;
    node.params.remove(key);
    Ok(Some(object))
}

fn reject_unknown_object_fields(
    object: &serde_json::Map<String, serde_json::Value>,
    allowed: &[&str],
    context: &str,
) -> Result<(), String> {
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.iter().any(|allowed| field.as_str() == *allowed))
    {
        Err(format!("{context} contains unsupported field `{field}`"))
    } else {
        Ok(())
    }
}

fn merge_json_scalar_param(
    node: &mut ParsedNode,
    object: &serde_json::Map<String, serde_json::Value>,
    source: &str,
    target: &str,
    context: &str,
) -> Result<(), String> {
    let Some(value) = object.get(source) else {
        return Ok(());
    };
    let value = match value {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        _ => return Err(format!("Hysteria 2 {context} must be a scalar value")),
    };
    insert_expanded_param(node, target, value, context)
}

fn insert_expanded_param(
    node: &mut ParsedNode,
    target: &str,
    value: String,
    context: &str,
) -> Result<(), String> {
    if let Some(existing) = node.params.get(target) {
        if existing != &value {
            return Err(format!(
                "Hysteria 2 {context} conflicts with params.{target}"
            ));
        }
    } else {
        node.params.insert(target.to_owned(), value);
    }
    Ok(())
}

fn json_duration_seconds(
    value: Option<&serde_json::Value>,
    context: &str,
) -> Result<Option<i32>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let duration = match value {
        serde_json::Value::String(value) => parse_tuic_duration(value),
        serde_json::Value::Number(value) => value.as_u64().map(std::time::Duration::from_secs),
        _ => None,
    }
    .ok_or_else(|| format!("Hysteria 2 {context} is not a valid duration"))?;
    if duration.subsec_nanos() != 0 {
        return Err(format!(
            "Hysteria 2 {context} must resolve to whole seconds"
        ));
    }
    let seconds = i32::try_from(duration.as_secs())
        .map_err(|_| format!("Hysteria 2 {context} exceeds i32 seconds"))?;
    Ok(Some(seconds))
}

#[derive(Clone, Copy)]
enum HysteriaBandwidthSyntax {
    V1,
    V2,
}

fn parse_hysteria_bandwidth(
    node: &ParsedNode,
    keys: &[&str],
    field: &str,
    required: bool,
    syntax: HysteriaBandwidthSyntax,
) -> Result<u64, String> {
    let Some(raw) = first_param(node, keys) else {
        return if required {
            Err(format!("{field} is required"))
        } else {
            Ok(0)
        };
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    let bps = match syntax {
        HysteriaBandwidthSyntax::V1 => parse_hysteria1_bandwidth(raw),
        HysteriaBandwidthSyntax::V2 => parse_hysteria2_bandwidth(raw),
    }
    .map_err(|error| format!("{field}: {error}"))?;
    if required && bps == 0 {
        return Err(format!("{field} must be non-zero"));
    }
    Ok(bps)
}

fn parse_hysteria1_bandwidth(raw: &str) -> Result<u64, String> {
    if raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return raw
            .parse::<u64>()
            .map_err(|_| "invalid Mbps integer".to_owned())?
            .checked_mul(125_000)
            .ok_or_else(|| "bandwidth overflows bytes per second".to_owned());
    }
    let Some(unit_start) = raw.bytes().position(|byte| !byte.is_ascii_digit()) else {
        return Err("invalid bandwidth format".into());
    };
    if unit_start == 0 {
        return Err("invalid bandwidth format".into());
    }
    let value = raw[..unit_start]
        .parse::<u64>()
        .map_err(|_| "invalid bandwidth integer".to_owned())?;
    let unit = raw[unit_start..].trim_start();
    let (prefix, bytes) = match unit.as_bytes() {
        [letter @ (b'B' | b'b'), b'p', b's'] => (None, *letter == b'B'),
        [
            prefix @ (b'K' | b'M' | b'G' | b'T'),
            letter @ (b'B' | b'b'),
            b'p',
            b's',
        ] => (Some(*prefix), *letter == b'B'),
        _ => return Err("unsupported Hysteria 1 bandwidth unit".into()),
    };
    let multiplier = match prefix {
        None => 1_u64,
        Some(b'K') => 1_u64 << 10,
        Some(b'M') => 1_u64 << 20,
        Some(b'G') => 1_u64 << 30,
        Some(b'T') => 1_u64 << 40,
        _ => unreachable!("validated Hysteria 1 unit"),
    };
    value
        .checked_mul(multiplier)
        .map(|value| if bytes { value } else { value / 8 })
        .ok_or_else(|| "bandwidth overflows bytes per second".to_owned())
}

fn parse_hysteria2_bandwidth(raw: &str) -> Result<u64, String> {
    // Official ConvBandwidth accepts integer values as bytes/second. Structured
    // JSON numbers reach this representation as bare decimal strings.
    if raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return raw
            .parse::<u64>()
            .map_err(|_| "invalid bytes-per-second integer".to_owned());
    }
    let normalized = raw.trim().to_ascii_lowercase();
    let split = normalized
        .bytes()
        .position(|byte| !byte.is_ascii_digit())
        .ok_or_else(|| "bandwidth string requires a unit".to_owned())?;
    if split == 0 {
        return Err("invalid bandwidth format".into());
    }
    let value = normalized[..split]
        .parse::<u64>()
        .map_err(|_| "invalid bandwidth integer".to_owned())?;
    let multiplier = match normalized[split..].trim() {
        "b" | "bps" => 1_u64,
        "k" | "kb" | "kbps" => 1_000,
        "m" | "mb" | "mbps" => 1_000_000,
        "g" | "gb" | "gbps" => 1_000_000_000,
        "t" | "tb" | "tbps" => 1_000_000_000_000,
        _ => return Err("unsupported Hysteria 2 bandwidth unit".into()),
    };
    value
        .checked_mul(multiplier)
        .map(|bits| bits / 8)
        .ok_or_else(|| "bandwidth overflows bytes per second".to_owned())
}

fn reject_eager_hysteria_start(node: &ParsedNode, protocol: &str) -> Result<(), String> {
    if first_param(node, &["lazy"])
        .map(|value| parse_bool_param(&format!("{protocol} lazy"), value))
        .transpose()?
        == Some(false)
    {
        return Err(format!(
            "{protocol} lazy=false is incompatible with WutherCore's on-demand outbound lifecycle"
        ));
    }
    Ok(())
}

fn parse_hysteria_alpn(raw: &str) -> Result<Vec<String>, String> {
    let values = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if values.is_empty() {
        Err("Hysteria ALPN cannot be empty".into())
    } else {
        Ok(values)
    }
}

fn parse_i32_param(node: &ParsedNode, keys: &[&str], default: i32) -> Result<i32, String> {
    first_param(node, keys)
        .map(|value| {
            value
                .parse()
                .map_err(|_| format!("invalid integer `{value}` for {}", keys[0]))
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn hysteria_quic_params(node: &ParsedNode) -> Result<QuicParamsConfig, String> {
    let mut params = node
        .stream_settings
        .as_ref()
        .and_then(|settings| settings.finalmask.as_ref())
        .and_then(|finalmask| finalmask.quic_params.clone())
        .unwrap_or_default();
    if let Some(value) = first_param(node, &["congestion"]) {
        params.congestion = value.to_owned();
    }
    if let Some(value) = first_param(node, &["bbrProfile", "bbr-profile", "bbr_profile"]) {
        params.bbr_profile = value.to_owned();
    }
    overlay_u64_param(
        node,
        &["initialStreamReceiveWindow", "initStreamReceiveWindow"],
        &mut params.init_stream_receive_window,
    )?;
    overlay_u64_param(
        node,
        &["maxStreamReceiveWindow"],
        &mut params.max_stream_receive_window,
    )?;
    overlay_u64_param(
        node,
        &[
            "initialConnectionReceiveWindow",
            "initConnectionReceiveWindow",
            "initConnReceiveWindow",
        ],
        &mut params.init_connection_receive_window,
    )?;
    overlay_u64_param(
        node,
        &["maxConnectionReceiveWindow", "maxConnReceiveWindow"],
        &mut params.max_connection_receive_window,
    )?;
    overlay_i64_param(
        node,
        &["maxIdleTimeout", "max-idle-timeout", "max_idle_timeout"],
        &mut params.max_idle_timeout,
    )?;
    overlay_i64_param(
        node,
        &["keepAlivePeriod", "keep-alive-period", "keep_alive_period"],
        &mut params.keep_alive_period,
    )?;
    if let Some(value) = first_param(
        node,
        &[
            "disablePathMTUDiscovery",
            "disable-path-mtu-discovery",
            "disable_mtu_discovery",
        ],
    ) {
        params.disable_path_mtu_discovery =
            parse_bool_param("Hysteria disablePathMTUDiscovery", value)?;
    }
    if let Some(value) = first_param(node, &["hopPorts", "hop-ports", "hop_ports"]) {
        params.udp_hop.ports = PortListValue::Text(value.to_owned());
    }
    if let Some(value) = first_param(node, &["hopInterval", "hop-interval", "hop_interval"]) {
        let seconds = parse_tuic_duration(value)
            .filter(|duration| duration.subsec_nanos() == 0)
            .and_then(|duration| i32::try_from(duration.as_secs()).ok())
            .ok_or_else(|| format!("invalid Hysteria hop interval `{value}`"))?;
        params.udp_hop.interval = I32Range::fixed(seconds);
    }
    Ok(params)
}

fn hysteria1_quic_params(node: &ParsedNode) -> Result<QuicParamsConfig, String> {
    let mut params = hysteria_quic_params(node)?;
    overlay_hysteria1_window(
        node,
        &["recvWindowConn", "recv-window-conn", "recv_window_conn"],
        "recv_window_conn",
        &mut params.init_stream_receive_window,
        &mut params.max_stream_receive_window,
    )?;
    overlay_hysteria1_window(
        node,
        &["recvWindow", "recv-window", "recv_window"],
        "recv_window",
        &mut params.init_connection_receive_window,
        &mut params.max_connection_receive_window,
    )?;
    overlay_i64_param(
        node,
        &["idleTimeout", "idle-timeout", "idle_timeout"],
        &mut params.max_idle_timeout,
    )?;
    Ok(params)
}

fn overlay_hysteria1_window(
    node: &ParsedNode,
    keys: &[&str],
    field: &str,
    initial: &mut u64,
    maximum: &mut u64,
) -> Result<(), String> {
    let Some(raw) = first_param(node, keys) else {
        return Ok(());
    };
    let value = raw
        .parse::<u64>()
        .map_err(|_| format!("invalid integer `{raw}` for {}", keys[0]))?;
    if (*initial != 0 && *initial != value) || (*maximum != 0 && *maximum != value) {
        return Err(format!(
            "Hysteria 1 {field} conflicts with explicit initial/max QUIC receive windows"
        ));
    }
    *initial = value;
    *maximum = value;
    Ok(())
}

fn overlay_u64_param(node: &ParsedNode, keys: &[&str], target: &mut u64) -> Result<(), String> {
    if let Some(value) = first_param(node, keys) {
        *target = value
            .parse::<u64>()
            .map_err(|_| format!("invalid integer `{value}` for {}", keys[0]))?;
    }
    Ok(())
}

fn overlay_i64_param(node: &ParsedNode, keys: &[&str], target: &mut i64) -> Result<(), String> {
    if let Some(value) = first_param(node, keys) {
        *target = match value.parse::<i64>() {
            Ok(value) => value,
            Err(_) => parse_tuic_duration(value)
                .filter(|duration| duration.subsec_nanos() == 0)
                .and_then(|duration| i64::try_from(duration.as_secs()).ok())
                .ok_or_else(|| format!("invalid duration `{value}` for {}", keys[0]))?,
        };
    }
    Ok(())
}

fn build_tuic(node: &ParsedNode) -> Result<SharedOutbound, String> {
    tuic_from_node(node)
        .map(|outbound| Arc::new(outbound) as SharedOutbound)
        .map_err(str::to_owned)
}

fn tuic_from_node(node: &ParsedNode) -> Result<TuicOutbound, &'static str> {
    let uuid = node
        .uuid
        .as_deref()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or("tuic(invalid-uuid)")?;
    let pwd = node.password.clone().ok_or("tuic(missing-password)")?;
    let mut ob = TuicOutbound::new(&node.name, &node.host, node.port, uuid, pwd);
    if let Some(s) = node.sni.clone() {
        ob.sni = Some(s);
    }
    ob.insecure = [
        "insecure",
        "allowInsecure",
        "allow-insecure",
        "allow_insecure",
        "skip-cert-verify",
        "skipCertVerify",
    ]
    .iter()
    .filter_map(|key| node.params.get(*key))
    .any(|value| value == "1" || value.eq_ignore_ascii_case("true"));
    ob.disable_sni = ["disable-sni", "disable_sni"]
        .iter()
        .filter_map(|key| node.params.get(*key))
        .any(|value| value == "1" || value.eq_ignore_ascii_case("true"));
    ob.udp = node.udp;

    if let Some(mode) = node
        .params
        .get("udp-relay-mode")
        .or_else(|| node.params.get("udp_relay_mode"))
    {
        ob.udp_relay_mode = match mode.as_str() {
            mode if mode.eq_ignore_ascii_case("native") => TuicUdpMode::Native,
            mode if mode.eq_ignore_ascii_case("quic") => TuicUdpMode::Quic,
            _ => return Err("tuic(invalid-udp-relay-mode)"),
        };
    }
    if let Some(alpn) = node.params.get("alpn") {
        let values = alpn
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if !values.is_empty() {
            ob.alpn = values;
        }
    }
    if let Some(milliseconds) = node
        .params
        .get("heartbeat-interval")
        .and_then(|value| value.parse::<u64>().ok())
    {
        ob.heartbeat_interval = std::time::Duration::from_millis(milliseconds);
    } else if let Some(interval) = node
        .params
        .get("heartbeat")
        .and_then(|value| parse_tuic_duration(value))
    {
        ob.heartbeat_interval = interval;
    }
    Ok(ob)
}

fn parse_tuic_duration(value: &str) -> Option<std::time::Duration> {
    let value = value.trim();
    let (number, unit_seconds) = [
        ("ms", 1e-3),
        ("us", 1e-6),
        ("µs", 1e-6),
        ("μs", 1e-6),
        ("ns", 1e-9),
        ("s", 1.0),
        ("m", 60.0),
        ("h", 3600.0),
    ]
    .into_iter()
    .find_map(|(suffix, multiplier)| {
        value
            .strip_suffix(suffix)
            .map(|number| (number.trim(), multiplier))
    })
    .unwrap_or((value, 1.0));
    let seconds = number.parse::<f64>().ok()? * unit_seconds;
    if !seconds.is_finite() || seconds < 0.0 {
        return None;
    }
    std::time::Duration::try_from_secs_f64(seconds).ok()
}

fn build_wireguard(node: &ParsedNode) -> Result<SharedOutbound, String> {
    wireguard_from_node(node).map(|outbound| Arc::new(outbound) as SharedOutbound)
}

fn wireguard_from_node(node: &ParsedNode) -> Result<WireGuardOutbound, String> {
    for unsupported in [
        "system-interface",
        "system_interface",
        "dialer-proxy",
        "dialer_proxy",
        "amnezia-wg-option",
        "amnezia_wg_option",
    ] {
        if node.params.contains_key(unsupported) {
            return Err(format!("unsupported-{unsupported}"));
        }
    }
    const SUPPORTED_PARAMETERS: &[&str] = &[
        "private-key",
        "private_key",
        "address",
        "local-address",
        "local_address",
        "ip",
        "ipv6",
        "peers",
        "public-key",
        "public_key",
        "peer-public-key",
        "peer_public_key",
        "pre-shared-key",
        "pre_shared_key",
        "preshared-key",
        "preshared_key",
        "allowed-ips",
        "allowed_ips",
        "reserved",
        "persistent-keepalive",
        "persistent_keepalive",
        "persistent-keepalive-interval",
        "persistent_keepalive_interval",
        "keepalive",
        "mtu",
        "tcp-buffer-size",
        "tcp_buffer_size",
        "udp-buffer-size",
        "udp_buffer_size",
        "max-tcp-sessions",
        "max_tcp_sessions",
        "max-udp-sessions",
        "max_udp_sessions",
        "packet-queue",
        "packet_queue",
        "workers",
        "connect-timeout",
        "connect_timeout",
        "udp-timeout",
        "udp_timeout",
        "udp-idle-timeout",
        "udp_idle_timeout",
        "remote-dns-resolve",
        "remote_dns_resolve",
        "dns",
        "network",
    ];
    if let Some(unknown) = node
        .params
        .keys()
        .find(|key| !SUPPORTED_PARAMETERS.contains(&key.as_str()))
    {
        return Err(format!("unknown-parameter-{unknown}"));
    }
    let private_key = param_alias(node, &["private-key", "private_key"])?
        .or(node.password.as_deref())
        .or(node.uuid.as_deref())
        .ok_or_else(|| "missing-private-key".to_string())
        .and_then(|value| decode_b64_32(value).ok_or_else(|| "invalid-private-key".into()))?;

    let mut local_addresses = Vec::new();
    if let Some(value) = param_alias(node, &["address", "local-address", "local_address"])? {
        local_addresses.extend(parse_ip_nets(value, "address")?);
    }
    for key in ["ip", "ipv6"] {
        if let Some(value) = node.params.get(key) {
            local_addresses.extend(parse_ip_nets(value, key)?);
        }
    }
    if local_addresses.is_empty() {
        return Err("missing-local-address".into());
    }

    let peers = if let Some(value) = node.params.get("peers") {
        for field in [
            "public-key",
            "public_key",
            "peer-public-key",
            "peer_public_key",
            "pre-shared-key",
            "pre_shared_key",
            "preshared-key",
            "preshared_key",
            "allowed-ips",
            "allowed_ips",
            "persistent-keepalive",
            "persistent_keepalive",
            "persistent-keepalive-interval",
            "persistent_keepalive_interval",
            "keepalive",
        ] {
            if node.params.contains_key(field) {
                return Err(format!("peers-conflicts-with-{field}"));
            }
        }
        let default_reserved = node
            .params
            .get("reserved")
            .map(|value| parse_reserved(value))
            .transpose()?
            .unwrap_or([0; 3]);
        parse_wireguard_peers(value, default_reserved)?
    } else {
        vec![parse_single_wireguard_peer(node, &local_addresses)?]
    };
    if peers.is_empty() {
        return Err("peers-must-not-be-empty".into());
    }
    let mut config = WireGuardConfig::new(private_key, peers[0].clone());
    config.peers = peers;
    config.local_addresses = local_addresses;
    config.mtu = parse_usize_param(node, &["mtu"], config.mtu)?;
    config.tcp_buffer_size = parse_usize_param(
        node,
        &["tcp-buffer-size", "tcp_buffer_size"],
        config.tcp_buffer_size,
    )?;
    config.udp_buffer_size = parse_usize_param(
        node,
        &["udp-buffer-size", "udp_buffer_size"],
        config.udp_buffer_size,
    )?;
    config.max_tcp_sessions = parse_usize_param(
        node,
        &["max-tcp-sessions", "max_tcp_sessions"],
        config.max_tcp_sessions,
    )?;
    config.max_udp_sessions = parse_usize_param(
        node,
        &["max-udp-sessions", "max_udp_sessions"],
        config.max_udp_sessions,
    )?;
    config.packet_queue =
        parse_usize_param(node, &["packet-queue", "packet_queue"], config.packet_queue)?;
    if let Some(workers) = param_alias(node, &["workers"])? {
        let workers = workers
            .parse::<usize>()
            .map_err(|_| "invalid-workers".to_string())?;
        if workers != 0 {
            config.workers = workers;
        }
    }
    if let Some(value) = param_alias(node, &["connect-timeout", "connect_timeout"])? {
        config.connect_timeout =
            parse_tuic_duration(value).ok_or_else(|| "invalid-connect-timeout".to_string())?;
    }
    if let Some(value) = param_alias(
        node,
        &[
            "udp-timeout",
            "udp_timeout",
            "udp-idle-timeout",
            "udp_idle_timeout",
        ],
    )? {
        config.udp_idle_timeout =
            parse_tuic_duration(value).ok_or_else(|| "invalid-udp-timeout".to_string())?;
    }

    config.remote_dns_resolve = param_alias(node, &["remote-dns-resolve", "remote_dns_resolve"])?
        .map(parse_strict_bool)
        .transpose()?
        .unwrap_or(false);
    if let Some(value) = node.params.get("dns") {
        config.dns = parse_string_list(value)?
            .into_iter()
            .map(|value| {
                value
                    .parse::<IpAddr>()
                    .map_err(|_| format!("invalid-dns-address-{value}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
    }

    if let Some(network) = node.params.get("network") {
        match network
            .trim()
            .to_ascii_lowercase()
            .replace(' ', "")
            .as_str()
        {
            "tcp" => {
                config.tcp = true;
                config.udp = false;
            }
            "udp" => {
                config.tcp = false;
                config.udp = true;
            }
            "tcp,udp" | "udp,tcp" | "both" => {
                config.tcp = true;
                config.udp = true;
            }
            _ => return Err("invalid-network".into()),
        }
    } else {
        config.udp = node.udp;
    }
    config.validate().map_err(|error| error.to_string())?;
    Ok(WireGuardOutbound::from_config(&node.name, config))
}

fn parse_single_wireguard_peer(
    node: &ParsedNode,
    local_addresses: &[ipnet::IpNet],
) -> Result<WireGuardPeerConfig, String> {
    let public_key = param_alias(
        node,
        &[
            "public-key",
            "public_key",
            "peer-public-key",
            "peer_public_key",
        ],
    )?
    .ok_or_else(|| "missing-public-key".to_string())
    .and_then(|value| decode_b64_32(value).ok_or_else(|| "invalid-public-key".into()))?;
    let mut peer = WireGuardPeerConfig::new(&node.host, node.port, public_key);
    peer.preshared_key = param_alias(
        node,
        &[
            "pre-shared-key",
            "pre_shared_key",
            "preshared-key",
            "preshared_key",
        ],
    )?
    .map(|value| decode_b64_32(value).ok_or_else(|| String::from("invalid-preshared-key")))
    .transpose()?;
    peer.allowed_ips = match param_alias(node, &["allowed-ips", "allowed_ips"])? {
        Some(value) => parse_ip_nets(value, "allowed-ips")?,
        None => default_allowed_ips(local_addresses),
    };
    if let Some(value) = node.params.get("reserved") {
        peer.reserved = parse_reserved(value)?;
    }
    if let Some(value) = param_alias(
        node,
        &[
            "persistent-keepalive",
            "persistent_keepalive",
            "persistent-keepalive-interval",
            "persistent_keepalive_interval",
            "keepalive",
        ],
    )? {
        peer.persistent_keepalive = parse_keepalive(value)?;
    }
    Ok(peer)
}

fn parse_wireguard_peers(
    value: &str,
    default_reserved: [u8; 3],
) -> Result<Vec<WireGuardPeerConfig>, String> {
    let peers: serde_json::Value =
        serde_json::from_str(value).map_err(|_| "invalid-peers-json".to_string())?;
    let peers = peers
        .as_array()
        .ok_or_else(|| "peers-must-be-an-array".to_string())?;
    if peers.is_empty() || peers.len() > super::proto::wireguard::config::MAX_PEERS {
        return Err(format!(
            "peers-must-contain-1-to-{}-entries",
            super::proto::wireguard::config::MAX_PEERS
        ));
    }
    peers
        .iter()
        .enumerate()
        .map(|(index, peer)| {
            let peer = peer
                .as_object()
                .ok_or_else(|| format!("peer-{index}-must-be-an-object"))?;
            const PEER_FIELDS: &[&str] = &[
                "server",
                "address",
                "port",
                "server_port",
                "server-port",
                "endpoint",
                "public-key",
                "public_key",
                "pre-shared-key",
                "pre_shared_key",
                "preshared-key",
                "preshared_key",
                "allowed-ips",
                "allowed_ips",
                "reserved",
                "persistent-keepalive",
                "persistent_keepalive",
                "persistent-keepalive-interval",
                "persistent_keepalive_interval",
                "keepalive",
            ];
            if let Some(unknown) = peer.keys().find(|key| !PEER_FIELDS.contains(&key.as_str())) {
                return Err(format!("peer-{index}-unknown-field-{unknown}"));
            }
            let get = |keys: &[&str]| -> Result<Option<&serde_json::Value>, String> {
                let mut found = None;
                for key in keys {
                    if let Some(value) = peer.get(*key) {
                        if let Some(previous) = found
                            && previous != value
                        {
                            return Err(format!("peer-{index}-conflicting-{key}"));
                        }
                        found = Some(value);
                    }
                }
                Ok(found)
            };
            let endpoint = get(&["endpoint"])?;
            let server = get(&["server", "address"])?;
            let port_value = get(&["port", "server_port", "server-port"])?;
            let (host, port) = if let Some(endpoint) = endpoint {
                if server.is_some() || port_value.is_some() {
                    return Err(format!("peer-{index}-endpoint-conflicts-with-server-port"));
                }
                endpoint
                    .as_str()
                    .ok_or_else(|| format!("peer-{index}-invalid-endpoint"))
                    .and_then(|endpoint| parse_wireguard_endpoint(endpoint, index))?
            } else {
                let host = server
                    .and_then(serde_json::Value::as_str)
                    .filter(|host| !host.trim().is_empty())
                    .ok_or_else(|| format!("peer-{index}-missing-server"))?;
                let port = port_value
                    .and_then(json_u64)
                    .and_then(|value| u16::try_from(value).ok())
                    .filter(|port| *port != 0)
                    .ok_or_else(|| format!("peer-{index}-invalid-port"))?;
                (host.to_owned(), port)
            };
            let public_key = get(&["public-key", "public_key"])?
                .and_then(serde_json::Value::as_str)
                .and_then(decode_b64_32)
                .ok_or_else(|| format!("peer-{index}-invalid-public-key"))?;
            let mut parsed = WireGuardPeerConfig::new(host, port, public_key);
            parsed.reserved = default_reserved;
            parsed.preshared_key = get(&[
                "pre-shared-key",
                "pre_shared_key",
                "preshared-key",
                "preshared_key",
            ])?
            .map(|value| {
                value
                    .as_str()
                    .and_then(decode_b64_32)
                    .ok_or_else(|| format!("peer-{index}-invalid-preshared-key"))
            })
            .transpose()?;
            let allowed = get(&["allowed-ips", "allowed_ips"])?
                .ok_or_else(|| format!("peer-{index}-missing-allowed-ips"))?;
            parsed.allowed_ips = parse_json_ip_nets(allowed, &format!("peer-{index}-allowed-ips"))?;
            if let Some(reserved) = get(&["reserved"])? {
                parsed.reserved = parse_reserved_json(reserved)?;
            }
            if let Some(keepalive) = get(&[
                "persistent-keepalive",
                "persistent_keepalive",
                "persistent-keepalive-interval",
                "persistent_keepalive_interval",
                "keepalive",
            ])? {
                let keepalive = json_u64(keepalive)
                    .and_then(|value| u16::try_from(value).ok())
                    .ok_or_else(|| format!("peer-{index}-invalid-persistent-keepalive"))?;
                parsed.persistent_keepalive = (keepalive != 0).then_some(keepalive);
            }
            Ok(parsed)
        })
        .collect()
}

fn parse_wireguard_endpoint(value: &str, peer_index: usize) -> Result<(String, u16), String> {
    let value = value.trim();
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| format!("peer-{peer_index}-invalid-endpoint"))?;
    let host = host
        .trim()
        .trim_matches(|character| character == '[' || character == ']');
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| format!("peer-{peer_index}-invalid-endpoint-port"))?;
    if host.is_empty() {
        return Err(format!("peer-{peer_index}-invalid-endpoint-host"));
    }
    Ok((host.to_owned(), port))
}

fn default_allowed_ips(local_addresses: &[ipnet::IpNet]) -> Vec<ipnet::IpNet> {
    let mut routes = Vec::new();
    if local_addresses
        .iter()
        .any(|address| address.addr().is_ipv4())
    {
        routes.push("0.0.0.0/0".parse().expect("static IPv4 route"));
    }
    if local_addresses
        .iter()
        .any(|address| address.addr().is_ipv6())
    {
        routes.push("::/0".parse().expect("static IPv6 route"));
    }
    routes
}

fn parse_ip_nets(value: &str, field: &str) -> Result<Vec<ipnet::IpNet>, String> {
    parse_string_list(value)?
        .into_iter()
        .map(|value| parse_ip_net(&value).map_err(|_| format!("invalid-{field}-{value}")))
        .collect()
}

fn parse_json_ip_nets(value: &serde_json::Value, field: &str) -> Result<Vec<ipnet::IpNet>, String> {
    let values = match value {
        serde_json::Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| format!("invalid-{field}"))
            })
            .collect::<Result<Vec<_>, _>>()?,
        serde_json::Value::String(value) => parse_string_list(value)?,
        _ => return Err(format!("invalid-{field}")),
    };
    values
        .into_iter()
        .map(|value| parse_ip_net(&value).map_err(|_| format!("invalid-{field}-{value}")))
        .collect()
}

fn parse_ip_net(value: &str) -> Result<ipnet::IpNet, ()> {
    if let Ok(network) = value.trim().parse::<ipnet::IpNet>() {
        return Ok(network);
    }
    let ip = value.trim().parse::<IpAddr>().map_err(|_| ())?;
    ipnet::IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 }).map_err(|_| ())
}

fn parse_string_list(value: &str) -> Result<Vec<String>, String> {
    let value = value.trim();
    if value.starts_with('[') {
        let values: Vec<serde_json::Value> =
            serde_json::from_str(value).map_err(|_| "invalid-list-json".to_string())?;
        return values
            .into_iter()
            .map(|value| match value {
                serde_json::Value::String(value) => Ok(value),
                serde_json::Value::Number(value) => Ok(value.to_string()),
                _ => Err("list-values-must-be-scalars".into()),
            })
            .collect();
    }
    let values = value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if values.is_empty() {
        Err("list-must-not-be-empty".into())
    } else {
        Ok(values)
    }
}

fn parse_reserved(value: &str) -> Result<[u8; 3], String> {
    if value.trim().starts_with('[') {
        let value = serde_json::from_str(value).map_err(|_| "invalid-reserved".to_string())?;
        return parse_reserved_json(&value);
    }
    let comma = value
        .split(',')
        .map(str::trim)
        .map(str::parse::<u8>)
        .collect::<Result<Vec<_>, _>>();
    if let Ok(bytes) = comma
        && let Ok(bytes) = <[u8; 3]>::try_from(bytes)
    {
        return Ok(bytes);
    }
    use base64::Engine;
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(value.trim())
            && let Ok(bytes) = <[u8; 3]>::try_from(bytes)
        {
            return Ok(bytes);
        }
    }
    Err("invalid-reserved".into())
}

fn parse_reserved_json(value: &serde_json::Value) -> Result<[u8; 3], String> {
    match value {
        serde_json::Value::String(value) => parse_reserved(value),
        serde_json::Value::Array(values) if values.len() == 3 => {
            let mut output = [0; 3];
            for (index, value) in values.iter().enumerate() {
                output[index] = json_u64(value)
                    .and_then(|value| u8::try_from(value).ok())
                    .ok_or_else(|| "invalid-reserved".to_string())?;
            }
            Ok(output)
        }
        _ => Err("invalid-reserved".into()),
    }
}

fn parse_keepalive(value: &str) -> Result<Option<u16>, String> {
    let value = value
        .trim()
        .parse::<u16>()
        .map_err(|_| "invalid-persistent-keepalive".to_string())?;
    Ok((value != 0).then_some(value))
}

fn parse_usize_param(node: &ParsedNode, aliases: &[&str], default: usize) -> Result<usize, String> {
    param_alias(node, aliases)?
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| format!("invalid-{}", aliases[0]))
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn param_alias<'a>(node: &'a ParsedNode, aliases: &[&str]) -> Result<Option<&'a str>, String> {
    let mut found = None;
    for alias in aliases {
        if let Some(value) = node.params.get(*alias) {
            if let Some(previous) = found
                && previous != value
            {
                return Err(format!("conflicting-{}", aliases[0]));
            }
            found = Some(value.as_str());
        }
    }
    Ok(found)
}

fn parse_strict_bool(value: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("invalid-boolean-{value}")),
    }
}

fn json_u64(value: &serde_json::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

fn build_mieru(node: &ParsedNode) -> SharedOutbound {
    let user = node.user.clone().unwrap_or_default();
    let pwd = node.password.clone().unwrap_or_default();
    let mut ob = MieruOutbound::new(&node.name, &node.host, node.port, user, pwd);
    if let Some(c) = node
        .params
        .get("cipher")
        .and_then(|s| MieruCipher::parse(s))
    {
        ob.cipher = c;
    }
    Arc::new(ob)
}

fn build_sudoku(node: &ParsedNode) -> Result<SharedOutbound, String> {
    let key = node
        .params
        .get("key")
        .cloned()
        .or_else(|| node.password.clone())
        .unwrap_or_default();
    if key.is_empty() {
        return Err("Sudoku key must not be empty".into());
    }
    let mut cfg = crate::proto::sudoku::outbound::SudokuConfig::default();
    cfg.key = key;
    if let Some(method) = node
        .params
        .get("aead-method")
        .or_else(|| node.method.as_ref())
    {
        match SudokuAead::parse(method) {
            Ok(m) => cfg.aead_method = m,
            Err(error) => return Err(format!("invalid Sudoku AEAD method `{method}`: {error}")),
        }
    }
    if let Some(t) = node.params.get("table-type") {
        cfg.table_mode = t.clone();
    }
    if let Some(t) = node.params.get("custom-table") {
        cfg.custom_table = t.clone();
    }
    if let Some(value) = node.params.get("padding-min") {
        cfg.padding_min = value
            .parse::<i32>()
            .map_err(|_| format!("invalid Sudoku padding-min `{value}`"))?;
    }
    if let Some(value) = node.params.get("padding-max") {
        cfg.padding_max = value
            .parse::<i32>()
            .map_err(|_| format!("invalid Sudoku padding-max `{value}`"))?;
    }
    if let Some(d) = node
        .params
        .get("disable-http-mask")
        .map(|v| v == "1" || v == "true")
    {
        cfg.disable_http_mask = d;
    }
    if let Some(pr) = node.params.get("path-root") {
        cfg.http_mask_path_root = pr.clone();
    }
    SudokuOutbound::new(&node.name, &node.host, node.port, cfg)
        .map(|ob| Arc::new(ob) as SharedOutbound)
        .map_err(|error| format!("invalid Sudoku table configuration: {error}"))
}

fn build_trusttunnel(node: &ParsedNode) -> SharedOutbound {
    let user = node.user.clone().unwrap_or_default();
    let pwd = node.password.clone().unwrap_or_default();
    let mut ob = TrustTunnelOutbound::new(&node.name, &node.host, node.port, user, pwd);
    ob.sni = node
        .sni
        .clone()
        .filter(|s| !s.is_empty())
        .or(Some(node.host.clone()));
    ob.insecure = node
        .params
        .get("skip-cert-verify")
        .or_else(|| node.params.get("insecure"))
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    if let Some(alpn) = node.params.get("alpn") {
        ob.alpn = alpn.split(',').map(|s| s.trim().to_string()).collect();
    }
    if let Some(mc) = node
        .params
        .get("max-connections")
        .and_then(|s| s.parse::<usize>().ok())
    {
        ob.max_connections = mc;
    }
    if let Some(min_s) = node
        .params
        .get("min-streams")
        .and_then(|s| s.parse::<usize>().ok())
    {
        ob.min_streams = min_s;
    }
    if let Some(max_s) = node
        .params
        .get("max-streams")
        .and_then(|s| s.parse::<usize>().ok())
    {
        ob.max_streams = max_s;
    }
    if let Some(hc) = node
        .params
        .get("health-check")
        .map(|v| v == "1" || v == "true")
    {
        ob.health_check = hc;
    }
    Arc::new(ob)
}

#[cfg(feature = "with_young")]
fn build_young(node: &ParsedNode) -> SharedOutbound {
    let encoded_key = node
        .user
        .as_deref()
        .or(node.password.as_deref())
        .unwrap_or_default();
    let key = match core_young::YoungKey::parse_base64url(encoded_key) {
        Ok(key) => key,
        Err(_) => return StubOutbound::new(node.name.clone(), "young(invalid-key)"),
    };
    let encoded_pin = node
        .params
        .get("pin-sha256")
        .or_else(|| node.params.get("pin_sha256"))
        .or_else(|| node.params.get("pin"))
        .map(String::as_str)
        .unwrap_or_default();
    let pin = if encoded_pin.len() == 64 && encoded_pin.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        hex::decode(encoded_pin).ok()
    } else {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded_pin)
            .ok()
    };
    let Some(certificate_sha256) = pin.and_then(|pin| pin.try_into().ok()) else {
        return StubOutbound::new(node.name.clone(), "young(invalid-certificate-pin)");
    };
    let server_name = node.sni.clone().unwrap_or_else(|| node.host.clone());
    let authority = node
        .params
        .get("authority")
        .cloned()
        .unwrap_or_else(|| server_name.clone());
    let padding_min = node
        .params
        .get("padding-min")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(64);
    let padding_max = node
        .params
        .get("padding-max")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(512);
    if padding_min > padding_max || usize::from(padding_max) > core_young::MAX_PADDING_BYTES {
        return StubOutbound::new(node.name.clone(), "young(invalid-padding)");
    }
    let config = core_young::YoungClientConfig {
        server: node.host.clone(),
        port: node.port,
        server_name,
        authority,
        path: node
            .params
            .get("path")
            .cloned()
            .unwrap_or_else(|| "/assets".into()),
        key,
        certificate_sha256,
        idle_timeout: std::time::Duration::from_secs(
            node.params
                .get("idle-secs")
                .and_then(|value| value.parse().ok())
                .unwrap_or(300),
        ),
        max_streams: node
            .params
            .get("max-streams")
            .and_then(|value| value.parse().ok())
            .unwrap_or(1024),
        padding_min,
        padding_max,
    };
    Arc::new(YoungOutbound::new(&node.name, config))
}

fn decode_b64_32(s: &str) -> Option<[u8; 32]> {
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let value = s.trim();
    let v = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(value).ok())?;
    if v.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Some(out)
}

#[cfg(all(test, feature = "standard"))]
mod tests {
    use base64::Engine;
    use core_config::{
        I32Range, PortListValue,
        model::{XhttpConfig as TypedXhttpConfig, XhttpDownloadTlsSettings},
        node_uri::{NodeProtocol, ParsedNode},
    };
    use uuid::Uuid;

    #[cfg(feature = "with_naive")]
    use super::decode_config_blob;
    use super::{
        DownloadTlsSettings, build_node_tls_options, build_outbound, build_trojan,
        build_xhttp_options, expand_hysteria2_official_objects, hysteria_quic_params,
        tuic_from_node, wireguard_from_node,
    };
    use crate::proto::tuic::TuicUdpMode;

    const VALID_ECH_CONFIG_LIST: &str =
        "AD7+DQA6AAAgACC7Lynj4wV+BBnVL8X0QRh3b422HOpP33YHm5NgbFpiSAAIAAEAAQABAAMAB2VjaC5jb20AAA==";

    #[cfg(feature = "with_naive")]
    #[test]
    fn naive_registry_enables_uot_and_rejects_unsafe_combinations() {
        let mut node = ParsedNode::new("naive", NodeProtocol::Naive, "proxy.example", 443);
        node.udp = true;
        node.params.insert("udp-over-tcp".into(), "true".into());
        let outbound = build_outbound(&node).unwrap();
        assert_eq!(outbound.protocol(), "naive");
        assert!(outbound.capabilities().tcp);
        assert!(outbound.capabilities().udp);

        node.params.insert("quic".into(), "true".into());
        node.params
            .insert("insecure-concurrency".into(), "2".into());
        assert_eq!(
            build_outbound(&node).unwrap().protocol(),
            "naive(invalid-config)"
        );

        node.params.insert("insecure".into(), "true".into());
        assert_eq!(
            build_outbound(&node).unwrap().protocol(),
            "naive(insecure-tls-unsupported)"
        );
    }

    #[cfg(feature = "with_naive")]
    #[test]
    fn naive_registry_decodes_ech_config_formats() {
        assert_eq!(decode_config_blob("000102ff"), Some(vec![0, 1, 2, 255]));
        assert_eq!(decode_config_blob("AAEC/w=="), Some(vec![0, 1, 2, 255]));
        assert_eq!(decode_config_blob("%%%"), None);
    }

    fn node(protocol: NodeProtocol) -> ParsedNode {
        ParsedNode::new("validation-test", protocol, "127.0.0.1", 443)
    }

    fn build_error(node: &ParsedNode) -> String {
        match build_outbound(node) {
            Err(error) => error,
            Ok(_) => panic!("invalid test node unexpectedly registered"),
        }
    }

    #[test]
    fn registry_rejects_unknown_protocol_and_missing_required_credentials() {
        let cases = [
            (
                node(NodeProtocol::Other("future-protocol".into())),
                "unsupported outbound protocol `future-protocol`",
            ),
            (
                node(NodeProtocol::Shadowsocks),
                "shadowsocks password must not be empty",
            ),
            (
                node(NodeProtocol::ShadowsocksR),
                "ShadowsocksR password must not be empty",
            ),
            (node(NodeProtocol::Snell), "Snell PSK must not be empty"),
            (
                node(NodeProtocol::AnyTls),
                "AnyTLS password must not be empty",
            ),
            (node(NodeProtocol::Wireguard), "missing-private-key"),
            (node(NodeProtocol::Sudoku), "Sudoku key must not be empty"),
        ];

        for (node, expected) in cases {
            let error = build_error(&node);
            assert!(error.contains(expected), "error={error:?}");
        }
    }

    #[test]
    fn anytls_registry_enables_official_v2_features_and_validates_options() {
        let mut anytls = node(NodeProtocol::AnyTls);
        anytls.password = Some("secret".into());
        anytls.udp = true;
        anytls.params.insert("insecure".into(), "0".into());
        anytls
            .params
            .insert("idleSessionCheckInterval".into(), "31s".into());
        anytls
            .params
            .insert("idle-session-timeout".into(), "45s".into());
        anytls.params.insert("min_idle_session".into(), "2".into());
        anytls
            .params
            .insert("clientId".into(), "sing-anytls/0.0.11".into());
        let outbound = build_outbound(&anytls).unwrap();
        assert_eq!(outbound.protocol(), "anytls");
        assert!(outbound.capabilities().tcp);
        assert!(outbound.capabilities().udp);
        assert!(outbound.capabilities().multiplex);

        anytls
            .params
            .insert("disable-reuse".into(), "sometimes".into());
        assert!(build_error(&anytls).contains("invalid boolean"));

        anytls.params.insert("disable-reuse".into(), "false".into());
        anytls
            .params
            .insert("clientId".into(), "injected\npadding-md5=bad".into());
        assert!(build_error(&anytls).contains("must not contain"));
    }

    #[test]
    fn registry_rejects_invalid_protocol_options_instead_of_registering_stubs() {
        let mut ss = node(NodeProtocol::Shadowsocks);
        ss.password = Some("secret".into());
        ss.method = Some("not-a-cipher".into());
        assert!(build_error(&ss).contains("unsupported Shadowsocks cipher"));

        let mut ss2022 = node(NodeProtocol::Shadowsocks);
        ss2022.password = Some("not-a-valid-2022-key".into());
        ss2022.method = Some("2022-blake3-aes-128-gcm".into());
        assert!(build_error(&ss2022).contains("invalid Shadowsocks 2022 PSK"));

        let mut ss_plugin = node(NodeProtocol::Shadowsocks);
        ss_plugin.password = Some("secret".into());
        ss_plugin.params.insert("plugin-opts".into(), "tls".into());
        assert!(build_error(&ss_plugin).contains("require the `plugin`"));
        ss_plugin
            .params
            .insert("plugin".into(), "v2ray-plugin".into());
        ss_plugin
            .params
            .insert("plugin-args".into(), "[not-json".into());
        assert!(build_error(&ss_plugin).contains("plugin-args JSON array"));
        ss_plugin
            .params
            .insert("plugin-args".into(), r#"["--loglevel","warning"]"#.into());
        assert!(build_outbound(&ss_plugin).is_ok());

        let mut ssr = node(NodeProtocol::ShadowsocksR);
        ssr.password = Some("secret".into());
        ssr.params.insert("obfs".into(), "unknown-obfs".into());
        assert!(build_error(&ssr).contains("unsupported ShadowsocksR obfs"));
        ssr.params.insert("obfs".into(), "plain".into());
        ssr.params
            .insert("protocol".into(), "unknown-protocol".into());
        assert!(build_error(&ssr).contains("unsupported ShadowsocksR protocol"));
        ssr.params.insert("protocol".into(), "origin".into());
        ssr.method = Some("unknown-cipher".into());
        assert!(build_error(&ssr).contains("unsupported ShadowsocksR cipher"));

        let mut snell = node(NodeProtocol::Snell);
        snell.password = Some("secret".into());
        snell.method = Some("unknown-cipher".into());
        assert!(build_error(&snell).contains("unsupported Snell cipher"));
        snell.method = None;
        snell.params.insert("version".into(), "not-a-number".into());
        assert!(build_error(&snell).contains("invalid Snell version"));
        snell.params.insert("version".into(), "3".into());
        snell.params.insert("obfs".into(), "unknown-obfs".into());
        assert!(build_error(&snell).contains("unsupported Snell obfs"));

        let valid_key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let mut wireguard = node(NodeProtocol::Wireguard);
        wireguard
            .params
            .insert("private-key".into(), valid_key.clone());
        wireguard
            .params
            .insert("public-key".into(), valid_key.clone());
        wireguard
            .params
            .insert("address".into(), "10.0.0.2/32".into());
        wireguard
            .params
            .insert("preshared-key".into(), "invalid".into());
        assert!(build_error(&wireguard).contains("invalid-preshared-key"));
        wireguard.params.remove("preshared-key");
        wireguard
            .params
            .insert("address".into(), "not-an-address".into());
        assert!(build_error(&wireguard).contains("invalid-address"));

        let mut sudoku = node(NodeProtocol::Sudoku);
        sudoku.password = Some("secret".into());
        sudoku
            .params
            .insert("aead-method".into(), "unknown-aead".into());
        assert!(build_error(&sudoku).contains("invalid Sudoku AEAD"));
        sudoku.params.remove("aead-method");
        sudoku
            .params
            .insert("padding-min".into(), "not-a-number".into());
        assert!(build_error(&sudoku).contains("invalid Sudoku padding-min"));
        sudoku.params.remove("padding-min");
        sudoku
            .params
            .insert("padding-max".into(), "not-a-number".into());
        assert!(build_error(&sudoku).contains("invalid Sudoku padding-max"));
    }

    #[test]
    fn ssh_registry_validates_every_security_field_before_network_io() {
        let missing_user = node(NodeProtocol::Ssh);
        assert!(build_error(&missing_user).contains("SSH username is required"));

        let mut ssh = node(NodeProtocol::Ssh);
        ssh.user = Some("alice".into());
        ssh.password = Some("secret".into());
        assert!(build_outbound(&ssh).is_ok());

        ssh.params
            .insert("host-key".into(), "ssh-ed25519 not-base64".into());
        assert!(build_error(&ssh).contains("invalid SSH host-key"));
        ssh.params.remove("host-key");

        ssh.params
            .insert("host-key-algorithms".into(), "not-an-algorithm".into());
        assert!(build_error(&ssh).contains("unsupported SSH host-key algorithm"));
        ssh.params.remove("host-key-algorithms");

        ssh.params
            .insert("client-version".into(), "SSH-2.0-good\r\ninjected".into());
        assert!(build_error(&ssh).contains("SSH client version"));
        ssh.params.remove("client-version");

        ssh.params
            .insert("keepalive-interval".into(), "not-a-number".into());
        assert!(build_error(&ssh).contains("invalid SSH keepalive-interval"));
    }

    #[test]
    fn ss2022_registry_preserves_udp_flag_and_eih_chain() {
        let identity = base64::engine::general_purpose::STANDARD.encode([0x11u8; 16]);
        let user = base64::engine::general_purpose::STANDARD.encode([0x22u8; 16]);
        let mut node = ParsedNode::new("ss22", NodeProtocol::Shadowsocks, "127.0.0.1", 8388);
        node.method = Some("2022-blake3-aes-128-gcm".into());
        node.password = Some(format!("{identity}:{user}"));
        node.udp = false;

        let outbound = build_outbound(&node).unwrap();
        assert_eq!(outbound.protocol(), "ss2022");
        assert!(!outbound.capabilities().udp);

        node.udp = true;
        let outbound = build_outbound(&node).unwrap();
        assert!(outbound.capabilities().udp);
    }

    #[test]
    fn grpc_registry_maps_every_xray_field_and_alias() {
        let mut node = ParsedNode::new("grpc", NodeProtocol::Vless, "grpc.example", 443);
        node.transport = "grpc".into();
        node.params
            .insert("grpc-authority".into(), "authority.example".into());
        node.params
            .insert("grpc-service-name".into(), "/pkg.Service/TunX".into());
        node.params.insert("multiMode".into(), "true".into());
        node.params.insert("idleTimeout".into(), "30".into());
        node.params
            .insert("health_check_timeout".into(), "5s".into());
        node.params
            .insert("permit-without-stream".into(), "1".into());
        node.params
            .insert("initialWindowSize".into(), "1048576".into());
        node.params.insert("user_agent".into(), "golang".into());
        node.params
            .insert("max-message-size".into(), "8388608".into());
        node.params.insert("queueCapacity".into(), "32".into());

        let options = super::build_grpc_options(&node).unwrap();
        assert_eq!(options.authority, "authority.example");
        assert_eq!(options.service_name, "/pkg.Service/TunX");
        assert!(options.multi_mode);
        assert_eq!(options.idle_timeout, std::time::Duration::from_secs(30));
        assert_eq!(
            options.health_check_timeout,
            std::time::Duration::from_secs(5)
        );
        assert!(options.permit_without_stream);
        assert_eq!(options.initial_window_size, Some(1_048_576));
        assert_eq!(options.user_agent, "golang");
        assert_eq!(options.max_message_size, 8_388_608);
        assert_eq!(options.queue_capacity, 32);
    }

    #[test]
    fn hysteria1_requires_real_bandwidth_and_exposes_udp_only_when_enabled() {
        let mut node = ParsedNode::new("hy1", NodeProtocol::Hysteria, "hy.example", 443);
        node.params.insert("auth".into(), "secret".into());
        assert_eq!(
            build_outbound(&node).err().as_deref(),
            Some("Hysteria 1 upload bandwidth is required")
        );
        node.params.insert("up".into(), "100".into());
        node.params.insert("down".into(), "200 Mbps".into());
        node.params.insert("obfs".into(), "xplus-secret".into());
        let outbound = build_outbound(&node).unwrap();
        assert_eq!(outbound.protocol(), "hysteria");
        assert!(outbound.capabilities().udp);

        node.udp = false;
        let outbound = build_outbound(&node).unwrap();
        assert!(!outbound.capabilities().udp);
    }

    #[test]
    fn hysteria_bandwidth_parsers_match_each_official_generation() {
        assert_eq!(super::parse_hysteria1_bandwidth("10").unwrap(), 1_250_000);
        assert_eq!(
            super::parse_hysteria1_bandwidth("10 Mbps").unwrap(),
            10 * 1024 * 1024 / 8
        );
        assert_eq!(
            super::parse_hysteria1_bandwidth("10 MBps").unwrap(),
            10 * 1024 * 1024
        );
        assert!(super::parse_hysteria1_bandwidth("1.5 Mbps").is_err());

        assert_eq!(
            super::parse_hysteria2_bandwidth("100 Mbps").unwrap(),
            12_500_000
        );
        assert_eq!(super::parse_hysteria2_bandwidth("125000").unwrap(), 125_000);
        assert!(super::parse_hysteria2_bandwidth("1.5 Mbps").is_err());
    }

    #[test]
    fn hysteria1_official_windows_and_timers_map_to_runtime_fields() {
        let mut node = ParsedNode::new("hy1", NodeProtocol::Hysteria, "hy.example", 443);
        node.params
            .insert("recv_window_conn".into(), "65536".into());
        node.params.insert("recv_window".into(), "131072".into());
        node.params.insert("idle_timeout".into(), "25".into());
        node.params.insert("hop_interval".into(), "9".into());
        let params = super::hysteria1_quic_params(&node).unwrap();
        assert_eq!(params.init_stream_receive_window, 65_536);
        assert_eq!(params.max_stream_receive_window, 65_536);
        assert_eq!(params.init_connection_receive_window, 131_072);
        assert_eq!(params.max_connection_receive_window, 131_072);
        assert_eq!(params.max_idle_timeout, 25);
        assert_eq!(params.udp_hop.interval, I32Range::fixed(9));

        node.params
            .insert("initStreamReceiveWindow".into(), "262144".into());
        assert!(
            super::hysteria1_quic_params(&node)
                .unwrap_err()
                .contains("conflicts")
        );
    }

    #[test]
    fn hysteria2_rejects_orphan_obfs_and_consumes_quic_fields() {
        let mut node = ParsedNode::new("hy2", NodeProtocol::Hysteria2, "hy.example", 443);
        node.password = Some("secret".into());
        node.params
            .insert("obfs-password".into(), "mask-secret".into());
        assert_eq!(
            build_outbound(&node).err().as_deref(),
            Some("Hysteria 2 obfs-password requires obfs=salamander or obfs=gecko")
        );
        node.params.insert("obfs".into(), "gecko".into());
        node.params.insert("obfsMinPacketSize".into(), "600".into());
        node.params
            .insert("obfsMaxPacketSize".into(), "1300".into());
        node.params.insert("up".into(), "100 Mbps".into());
        node.params.insert("down".into(), "200".into());
        node.params.insert("congestion".into(), "brutal".into());
        node.params
            .insert("disableLossCompensation".into(), "true".into());
        node.params
            .insert("maxStreamReceiveWindow".into(), "1048576".into());
        node.params
            .insert("hopPorts".into(), "2000,3000-3002".into());
        node.params.insert("hopInterval".into(), "8s".into());
        let params = hysteria_quic_params(&node).unwrap();
        assert_eq!(params.congestion, "brutal");
        assert_eq!(params.max_stream_receive_window, 1_048_576);
        assert_eq!(
            params.udp_hop.ports,
            PortListValue::Text("2000,3000-3002".into())
        );
        assert_eq!(params.udp_hop.interval, I32Range::fixed(8));
        let outbound = build_outbound(&node).unwrap();
        assert_eq!(outbound.protocol(), "hysteria2");
        assert!(outbound.capabilities().udp);
    }

    #[test]
    fn hysteria2_official_tls_aliases_reach_shared_tls_executor() {
        let mut node = ParsedNode::new("hy2", NodeProtocol::Hysteria2, "hy.example", 443);
        node.password = Some("secret".into());
        node.params.insert("pinSHA256".into(), "11".repeat(32));
        node.params
            .insert("ech".into(), VALID_ECH_CONFIG_LIST.into());
        let tls = build_node_tls_options(
            &node,
            true,
            Some("hy.example".into()),
            false,
            vec!["h3".into()],
        )
        .unwrap();
        assert_eq!(tls.pinned_peer_cert_sha256, [[0x11; 32]]);
        assert_eq!(
            tls.xray_settings
                .as_ref()
                .and_then(|settings| settings.ech_config_list.as_deref()),
            Some(VALID_ECH_CONFIG_LIST)
        );
    }

    #[test]
    fn hysteria2_official_nested_objects_are_expanded_without_field_loss() {
        let mut node = ParsedNode::new("hy2", NodeProtocol::Hysteria2, "hy.example", 443);
        node.password = Some("secret".into());
        node.params.insert(
            "bandwidth".into(),
            r#"{"up":"100 mbps","down":"200 mbps","disableLossCompensation":true}"#.into(),
        );
        node.params.insert(
            "congestion".into(),
            r#"{"type":"bbr","bbrProfile":"aggressive"}"#.into(),
        );
        node.params.insert(
            "obfs".into(),
            r#"{"type":"gecko","gecko":{"password":"mask-secret","minPacketSize":600,"maxPacketSize":1300}}"#
                .into(),
        );
        node.params.insert(
            "quic".into(),
            r#"{"initStreamReceiveWindow":65536,"maxStreamReceiveWindow":131072,"initConnReceiveWindow":262144,"maxConnReceiveWindow":524288,"maxIdleTimeout":"30s","keepAlivePeriod":"10s","disablePathMTUDiscovery":true,"sockopts":{"bindInterface":"eth0","fwmark":123}}"#
                .into(),
        );
        node.params.insert(
            "tls".into(),
            format!(
                r#"{{"sni":"edge.example","insecure":false,"pinSHA256":"1111111111111111111111111111111111111111111111111111111111111111","ech":"{VALID_ECH_CONFIG_LIST}"}}"#
            ),
        );
        node.params.insert(
            "transport".into(),
            r#"{"type":"udp","udp":{"minHopInterval":"5s","maxHopInterval":"9s"}}"#.into(),
        );

        let expanded = expand_hysteria2_official_objects(&node).unwrap();
        assert_eq!(
            expanded
                .params
                .get("disableLossCompensation")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            expanded.params.get("congestion").map(String::as_str),
            Some("bbr")
        );
        assert_eq!(
            expanded.params.get("bbrProfile").map(String::as_str),
            Some("aggressive")
        );
        assert_eq!(
            expanded.params.get("obfs").map(String::as_str),
            Some("gecko")
        );
        assert_eq!(
            expanded.params.get("obfs-password").map(String::as_str),
            Some("mask-secret")
        );
        let settings = expanded.stream_settings.as_ref().unwrap();
        assert_eq!(settings.sockopt.as_ref().unwrap().interface, "eth0");
        assert_eq!(settings.sockopt.as_ref().unwrap().mark, 123);
        assert_eq!(
            settings
                .finalmask
                .as_ref()
                .unwrap()
                .quic_params
                .as_ref()
                .unwrap()
                .udp_hop
                .interval,
            I32Range::new(5, 9)
        );
        let outbound = build_outbound(&node).unwrap();
        assert_eq!(outbound.protocol(), "hysteria2");
    }

    #[test]
    fn grpc_registry_fails_closed_on_conflicts_and_invalid_limits() {
        let mut node = ParsedNode::new("grpc", NodeProtocol::Vless, "grpc.example", 443);
        node.transport = "grpc".into();
        node.params.insert("serviceName".into(), "one".into());
        node.params.insert("grpc-service-name".into(), "two".into());
        assert_eq!(
            super::build_grpc_options(&node).unwrap_err(),
            "grpc(conflicting-options)"
        );

        node.params.remove("grpc-service-name");
        node.params.insert("max-message-size".into(), "0".into());
        assert_eq!(
            super::build_grpc_options(&node).unwrap_err(),
            "grpc(invalid-resource-limit)"
        );

        node.params.remove("max-message-size");
        node.params.insert("multiMode".into(), "maybe".into());
        let error = match super::build_outbound(&node) {
            Ok(_) => panic!("invalid gRPC boolean must fail closed"),
            Err(error) => error,
        };
        assert_eq!(error, "grpc(invalid-boolean-option)");

        node.params.remove("multiMode");
        node.params.insert("idleTimeout".into(), "500ms".into());
        assert_eq!(
            super::build_grpc_options(&node).unwrap_err(),
            "grpc(invalid-duration)"
        );

        node.params
            .insert("idleTimeout".into(), (i32::MAX as u64 + 1).to_string());
        assert_eq!(
            super::build_grpc_options(&node).unwrap_err(),
            "grpc(invalid-duration)"
        );

        node.params.remove("idleTimeout");
        node.params.insert(
            "initialWindowSize".into(),
            (i32::MAX as u64 + 1).to_string(),
        );
        assert_eq!(
            super::build_grpc_options(&node).unwrap_err(),
            "grpc(invalid-initial-window-size)"
        );
    }

    #[test]
    fn grpc_registry_preserves_complete_tls_settings_and_rejects_disabled_tls() {
        let mut node = ParsedNode::new("grpc-tls", NodeProtocol::Vless, "grpc.example", 443);
        node.uuid = Some("2dd61d93-75d8-4da4-ac0e-6aece7eac365".into());
        node.transport = "grpc".into();
        node.params.insert("serviceName".into(), "full-tls".into());
        node.tls_settings = Some(XhttpDownloadTlsSettings {
            server_name: Some("certificate.example".into()),
            alpn: Some(vec!["h2".into()]),
            enable_session_resumption: Some(true),
            fingerprint: Some("chrome".into()),
            min_version: Some("1.2".into()),
            max_version: Some("1.3".into()),
            cipher_suites: Some("TLS_AES_128_GCM_SHA256".into()),
            curve_preferences: Some(vec!["X25519".into()]),
            pinned_peer_cert_sha256: Some("11".repeat(32)),
            verify_peer_cert_by_name: Some("certificate.example".into()),
            ..Default::default()
        });

        let error = match build_outbound(&node) {
            Ok(_) => panic!("advanced TLS fields must not be ignored while TLS is disabled"),
            Err(error) => error,
        };
        assert_eq!(error, "TLS/ECH settings are present while TLS is disabled");

        let mut disabled = ParsedNode::new(
            "grpc-disabled-tls",
            NodeProtocol::Vless,
            "grpc.example",
            443,
        );
        disabled.uuid = node.uuid.clone();
        disabled.transport = "grpc".into();
        disabled
            .params
            .insert("sni".into(), "ignored.example".into());
        assert!(build_outbound(&disabled).is_err());

        node.tls = true;
        node.sni = Some("certificate.example".into());
        let options =
            super::build_node_tls_options(&node, true, node.sni.clone(), false, vec!["h2".into()])
                .unwrap();
        assert_eq!(options.sni.as_deref(), Some("certificate.example"));
        assert_eq!(options.alpn, ["h2"]);
        assert_eq!(options.fingerprint, "chrome");
        assert!(options.enable_session_resumption);
        assert_eq!(options.pinned_peer_cert_sha256, [[0x11; 32]]);
        assert_eq!(options.verify_peer_cert_by_name, ["certificate.example"]);
        let settings = options.xray_settings.unwrap();
        assert_eq!(settings.min_version.as_deref(), Some("1.2"));
        assert_eq!(settings.max_version.as_deref(), Some("1.3"));
        assert_eq!(
            settings.cipher_suites.as_deref(),
            Some("TLS_AES_128_GCM_SHA256")
        );
        assert_eq!(settings.curve_preferences.unwrap(), ["X25519"]);

        node.tls_settings = None;
        node.params.insert("ech".into(), "true".into());
        assert_eq!(
            super::build_node_tls_options(&node, true, node.sni.clone(), false, vec!["h2".into()])
                .unwrap_err(),
            "ech=true requires a non-empty echConfigList"
        );
    }

    #[test]
    fn trojan_uses_registered_grpc_carrier_without_forcing_direct_tls() {
        let mut node = ParsedNode::new("trojan-grpc", NodeProtocol::Trojan, "grpc.example", 443);
        node.password = Some("secret".into());
        node.transport = "grpc".into();
        node.params.insert("security".into(), "none".into());
        node.params.insert("serviceName".into(), "trojan".into());
        node.params.insert("multiMode".into(), "true".into());

        let concrete = super::build_trojan(&node).unwrap();
        assert!(!concrete.tls);
        assert!(concrete.grpc.as_ref().is_some_and(|grpc| grpc.multi_mode));
    }

    #[test]
    fn tuic_registry_maps_sing_box_and_mihomo_options() {
        let mut node = ParsedNode::new("tuic", NodeProtocol::Tuic, "127.0.0.1", 443);
        node.uuid = Some("2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365".into());
        let test_password = Uuid::new_v4().to_string();
        node.password = Some(test_password.clone());
        node.udp = false;
        node.params.insert("udp_relay_mode".into(), "quic".into());
        node.params.insert("allow_insecure".into(), "true".into());
        node.params.insert("disable-sni".into(), "1".into());
        node.params.insert("heartbeat".into(), "1500ms".into());
        node.params.insert("alpn".into(), "h3, custom".into());

        let outbound = tuic_from_node(&node).unwrap();
        assert_eq!(
            outbound.uuid,
            Uuid::parse_str(node.uuid.as_deref().unwrap()).unwrap()
        );
        assert_eq!(outbound.password, test_password);
        assert_eq!(outbound.udp_relay_mode, TuicUdpMode::Quic);
        assert!(!outbound.udp);
        assert!(outbound.insecure);
        assert!(outbound.disable_sni);
        assert_eq!(
            outbound.heartbeat_interval,
            std::time::Duration::from_millis(1500)
        );
        assert_eq!(outbound.alpn, ["h3", "custom"]);

        let mut mihomo = ParsedNode::new("tuic", NodeProtocol::Tuic, "127.0.0.1", 443);
        mihomo.uuid = node.uuid.clone();
        mihomo.password = node.password.clone();
        mihomo
            .params
            .insert("heartbeat-interval".into(), "10000".into());
        let outbound = tuic_from_node(&mihomo).unwrap();
        assert_eq!(
            outbound.heartbeat_interval,
            std::time::Duration::from_secs(10)
        );
        assert_eq!(outbound.udp_relay_mode, TuicUdpMode::Native);
    }

    #[test]
    fn tuic_registry_parses_sing_box_duration_units() {
        for (value, expected) in [
            ("250ms", std::time::Duration::from_millis(250)),
            ("1.5s", std::time::Duration::from_millis(1500)),
            ("2m", std::time::Duration::from_secs(120)),
            ("0.5h", std::time::Duration::from_secs(1800)),
        ] {
            assert_eq!(super::parse_tuic_duration(value), Some(expected));
        }
        assert_eq!(super::parse_tuic_duration("-1s"), None);
        assert_eq!(super::parse_tuic_duration("forever"), None);
    }

    #[test]
    fn tuic_registry_rejects_invalid_required_options() {
        let mut node = ParsedNode::new("tuic", NodeProtocol::Tuic, "127.0.0.1", 443);
        node.password = Some("secret".into());
        assert_eq!(
            build_outbound(&node).err().as_deref(),
            Some("tuic(invalid-uuid)")
        );

        node.uuid = Some("not-a-uuid".into());
        assert_eq!(
            build_outbound(&node).err().as_deref(),
            Some("tuic(invalid-uuid)")
        );

        node.uuid = Some("2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365".into());
        node.password = None;
        assert_eq!(
            build_outbound(&node).err().as_deref(),
            Some("tuic(missing-password)")
        );

        node.password = Some("secret".into());
        node.params
            .insert("udp-relay-mode".into(), "unsupported".into());
        assert_eq!(
            build_outbound(&node).err().as_deref(),
            Some("tuic(invalid-udp-relay-mode)")
        );
    }

    #[test]
    fn primary_typed_tls_reaches_xhttp_options_without_string_map_loss() {
        let mut node = ParsedNode::new("typed-tls", NodeProtocol::Vless, "origin.example", 443);
        node.tls = true;
        node.transport = "xhttp".into();
        node.xhttp = Some(TypedXhttpConfig::default());
        node.tls_settings = Some(
            serde_json::from_str(
                r#"{
                    "serverName": "sni.example",
                    "alpn": ["h2"],
                    "enableSessionResumption": true,
                    "fingerprint": "firefox",
                    "pinnedPeerCertSha256": "1111111111111111111111111111111111111111111111111111111111111111",
                    "verifyPeerCertByName": "edge.example,127.0.0.1",
                    "echConfigList": "AAECAwQ="
                }"#,
            )
            .unwrap(),
        );

        let options = build_xhttp_options(&node, None, false, Vec::new()).unwrap();
        assert!(options.tls);
        assert!(options.enable_session_resumption);
        assert_eq!(options.fingerprint.as_deref(), Some("firefox"));
        let settings = options.tls_settings.as_ref().unwrap();
        assert_eq!(settings.server_name.as_deref(), Some("sni.example"));
        assert_eq!(settings.alpn.as_deref(), Some(["h2".to_owned()].as_slice()));
        assert_eq!(
            settings.verify_peer_cert_by_name.as_deref(),
            Some("edge.example,127.0.0.1")
        );
        assert_eq!(settings.ech_config_list.as_deref(), Some("AAECAwQ="));
    }

    #[test]
    fn primary_uri_tls_aliases_are_merged_and_conflicts_fail_closed() {
        let mut node = ParsedNode::new("uri-tls", NodeProtocol::Vless, "origin.example", 443);
        node.tls = true;
        node.transport = "xhttp".into();
        node.params.insert("fp".into(), "chrome".into());
        node.params
            .insert("enable-session-resumption".into(), "true".into());
        node.params
            .insert("pinned-peer-cert-sha256".into(), "22".repeat(32));
        node.params.insert(
            "verify-peer-cert-by-name".into(),
            "edge.example,127.0.0.1".into(),
        );
        node.params
            .insert("curve-preferences".into(), "X25519,MLKEM768".into());
        node.params
            .insert("ech-config-list".into(), "AAECAwQ=".into());

        let options = build_xhttp_options(&node, None, false, Vec::new()).unwrap();
        let settings = options.tls_settings.as_ref().unwrap();
        assert_eq!(settings.fingerprint.as_deref(), Some("chrome"));
        assert_eq!(settings.enable_session_resumption, Some(true));
        assert_eq!(
            settings.pinned_peer_cert_sha256.as_deref(),
            Some("2222222222222222222222222222222222222222222222222222222222222222")
        );
        assert_eq!(
            settings.curve_preferences.as_deref(),
            Some(["X25519".to_owned(), "MLKEM768".to_owned()].as_slice())
        );
        assert_eq!(settings.ech_config_list.as_deref(), Some("AAECAwQ="));

        node.tls_settings = Some(DownloadTlsSettings {
            enable_session_resumption: Some(false),
            ..Default::default()
        });
        let error = build_xhttp_options(&node, None, false, Vec::new()).unwrap_err();
        assert!(error.contains("enableSessionResumption"));
        assert!(error.contains("conflicts"));
    }

    #[test]
    fn typed_xhttp_maps_every_config_and_download_stream_field() {
        let mut node = ParsedNode::new("typed", NodeProtocol::Vless, "origin.example", 443);
        node.transport = "xhttp".into();
        node.params.insert("security".into(), "reality".into());
        node.xhttp = Some(
            serde_json::from_str::<TypedXhttpConfig>(
                r#"
{
  "host": "cdn.example",
  "path": "/split",
  "mode": "packet-up",
  "headers": {"User-Agent": "Wuther", "X-Test": "yes"},
  "xPaddingBytes": "101-202",
  "xPaddingObfsMode": true,
  "xPaddingKey": "pad_key",
  "xPaddingHeader": "X-Pad",
  "xPaddingPlacement": "header",
  "xPaddingMethod": "tokenish",
  "uplinkHTTPMethod": "PUT",
  "sessionIDPlacement": "cookie",
  "sessionIDKey": "sid",
  "sessionIDTable": "Base62",
  "sessionIDLength": "16-24",
  "seqPlacement": "query",
  "seqKey": "seq",
  "uplinkDataPlacement": "header",
  "uplinkDataKey": "X-Uplink",
  "uplinkChunkSize": "3000-4000",
  "noGRPCHeader": true,
  "noSSEHeader": true,
  "scMaxEachPostBytes": "200-300",
  "scMinPostsIntervalMs": "31-61",
  "scMaxBufferedPosts": 32,
  "scStreamUpServerSecs": "21-81",
  "serverMaxHeaderBytes": 16384,
  "xmux": {
    "maxConcurrency": 0,
    "maxConnections": "4-8",
    "cMaxReuseTimes": 16,
    "hMaxRequestTimes": "601-901",
    "hMaxReusableSecs": "1801-3001",
    "hKeepAlivePeriod": -1
  },
  "downloadSettings": {
    "address": "download.example",
    "host": "download-cdn.example",
    "port": 8443,
    "method": "xhttp",
    "network": "tcp",
    "transport": {
      "kind": "xhttp",
      "host": "nested.example",
      "path": "/download",
      "xhttp": {
        "host": "nested.example",
        "path": "/download",
        "mode": "packet-up",
        "noGRPCHeader": true
      }
    },
    "security": "tls",
    "tlsSettings": {
      "serverName": "download.example",
      "allowInsecure": false,
      "fingerprint": "chrome",
      "alpn": ["h2"],
      "curvePreferences": ["X25519"]
    },
    "realitySettings": {
      "serverName": "reality.example",
      "publicKey": "public-key",
      "shortId": "abcd",
      "fingerprint": "firefox",
      "spiderX": "/spider"
    },
    "alpn": ["h2"],
    "sockopt": {
      "mark": 123,
      "tfo": true,
      "tcpMptcp": false,
      "interface": "Ethernet",
      "domainStrategy": "UseIP",
      "dialerProxy": "DIRECT",
      "tcpKeepAliveInterval": 30,
      "tcpKeepAliveIdle": 60,
      "tcpUserTimeout": 90,
      "tcpMaxSeg": 1400,
      "tcpCongestion": "bbr",
      "customSockopt": [{"system": "linux", "opt": "SO_MARK", "value": "1"}]
    },
    "finalmask": {
      "tcp": [{"type": "fragment", "settings": {"length": 64}}],
      "quicParams": {"maxIdleTimeout": 30}
    }
  }
}
"#,
            )
            .unwrap(),
        );

        let options = build_xhttp_options(
            &node,
            Some("sni.example".into()),
            true,
            vec!["h2".into(), "h3".into()],
        )
        .unwrap();
        assert!(options.enabled);
        assert_eq!(options.sni.as_deref(), Some("sni.example"));
        assert!(options.insecure);
        assert_eq!(options.alpn, ["h2", "h3"]);
        assert!(options.has_reality);
        assert!(options.tls);

        let config = &options.config;
        assert_eq!(config.host, "cdn.example");
        assert_eq!(config.path, "/split");
        assert_eq!(config.mode, "packet-up");
        assert_eq!(config.headers.get("User-Agent").unwrap(), "Wuther");
        assert_eq!(config.headers.get("X-Test").unwrap(), "yes");
        assert_eq!(config.x_padding_bytes, "101-202");
        assert!(config.x_padding_obfs_mode);
        assert_eq!(config.x_padding_key, "pad_key");
        assert_eq!(config.x_padding_header, "X-Pad");
        assert_eq!(config.x_padding_placement, "header");
        assert_eq!(config.x_padding_method, "tokenish");
        assert_eq!(config.uplink_http_method, "PUT");
        assert_eq!(config.session_placement, "cookie");
        assert_eq!(config.session_key, "sid");
        assert_eq!(config.session_id_table, "Base62");
        assert_eq!(config.session_id_length, "16-24");
        assert_eq!(config.seq_placement, "query");
        assert_eq!(config.seq_key, "seq");
        assert_eq!(config.uplink_data_placement, "header");
        assert_eq!(config.uplink_data_key, "X-Uplink");
        assert_eq!(config.uplink_chunk_size, "3000-4000");
        assert!(config.no_grpc_header);
        assert!(config.no_sse_header);
        assert_eq!(config.sc_max_each_post_bytes, "200-300");
        assert_eq!(config.sc_min_posts_interval_ms, "31-61");
        assert_eq!(config.sc_max_buffered_posts, 32);
        assert_eq!(config.sc_stream_up_server_secs, "21-81");
        assert_eq!(config.server_max_header_bytes, 16384);
        assert_eq!(config.xmux.max_concurrency, "0");
        assert_eq!(config.xmux.max_connections, "4-8");
        assert_eq!(config.xmux.c_max_reuse_times, "16");
        assert_eq!(config.xmux.h_max_request_times, "601-901");
        assert_eq!(config.xmux.h_max_reusable_secs, "1801-3001");
        assert_eq!(config.xmux.h_keep_alive_period, -1);

        let download = config.download_settings.as_deref().unwrap();
        assert_eq!(download.address, "download.example");
        assert_eq!(download.host, "download-cdn.example");
        assert_eq!(download.port, Some(8443));
        assert_eq!(download.method, "xhttp");
        assert_eq!(download.network, "tcp");
        assert_eq!(download.security, "tls");
        assert_eq!(download.alpn, ["h2"]);

        let tls = download.tls.as_ref().unwrap();
        assert_eq!(tls.server_name.as_deref(), Some("download.example"));
        assert_eq!(tls.allow_insecure, Some(false));
        assert_eq!(tls.fingerprint.as_deref(), Some("chrome"));
        assert_eq!(tls.alpn.as_deref(), Some(["h2".to_owned()].as_slice()));
        assert_eq!(
            tls.curve_preferences.as_deref(),
            Some(["X25519".to_owned()].as_slice())
        );

        let reality = download.reality.as_ref().unwrap();
        assert_eq!(reality.server_name.as_deref(), Some("reality.example"));
        assert_eq!(reality.public_key.as_deref(), Some("public-key"));
        assert_eq!(reality.short_id.as_deref(), Some("abcd"));
        assert_eq!(reality.fingerprint.as_deref(), Some("firefox"));
        assert_eq!(reality.spider_x.as_deref(), Some("/spider"));

        let socket = download.socket.as_ref().unwrap();
        assert_eq!(socket.mark, Some(123));
        assert_eq!(
            socket.tcp_fast_open,
            Some(core_config::model::XhttpTcpFastOpen::Enabled(true))
        );
        assert_eq!(socket.tcp_mptcp, Some(false));
        assert_eq!(socket.interface.as_deref(), Some("Ethernet"));
        assert_eq!(
            socket.domain_strategy,
            Some(core_config::model::XhttpDomainStrategy::UseIp)
        );
        assert_eq!(socket.dialer_proxy.as_deref(), Some("DIRECT"));
        assert_eq!(socket.tcp_keep_alive_interval, Some(30));
        assert_eq!(socket.tcp_keep_alive_idle, Some(60));
        assert_eq!(socket.tcp_user_timeout, Some(90));
        assert_eq!(socket.tcp_max_seg, Some(1400));
        assert_eq!(socket.tcp_congestion.as_deref(), Some("bbr"));
        assert_eq!(socket.custom_sockopt.len(), 1);

        let final_mask = download.final_mask.as_ref().unwrap();
        assert_eq!(final_mask.tcp.len(), 1);
        assert_eq!(
            final_mask
                .quic_params
                .as_ref()
                .and_then(|params| params.max_idle_timeout),
            Some(30)
        );

        let transport = download.transport.as_ref().unwrap();
        assert_eq!(transport.kind, "xhttp");
        assert_eq!(transport.host, "nested.example");
        assert_eq!(transport.path, "/download");
        assert!(transport.service.is_empty());
        let nested = transport.xhttp.as_deref().unwrap();
        assert_eq!(nested.host, "nested.example");
        assert_eq!(nested.path, "/download");
        assert_eq!(nested.mode, "packet-up");
        assert!(nested.no_grpc_header);
        assert!(std::ptr::eq(
            config.download_xhttp_config().unwrap(),
            nested
        ));
    }

    #[test]
    fn xhttp_tls_rejects_removed_allow_insecure_and_defaults_alpn() {
        let mut node = ParsedNode::new("tls", NodeProtocol::Vless, "origin.example", 443);
        node.transport = "xhttp".into();
        node.tls = true;

        let error = build_xhttp_options(&node, None, true, Vec::new()).unwrap_err();
        assert!(error.contains("allowInsecure=true has been removed"));

        node.params.insert("skip-cert-verify".into(), "true".into());
        let error = build_xhttp_options(&node, None, false, Vec::new()).unwrap_err();
        assert!(error.contains("allowInsecure=true has been removed"));
        node.params.remove("skip-cert-verify");

        let options = build_xhttp_options(&node, None, false, Vec::new()).unwrap();
        assert_eq!(options.alpn, ["h2", "http/1.1"]);
    }

    #[test]
    fn xhttp_download_mapper_normalizes_security_and_tls_default_alpn() {
        let mut node = ParsedNode::new("download", NodeProtocol::Vless, "origin.example", 443);
        node.transport = "xhttp".into();
        node.xhttp = Some(
            serde_json::from_str(
                r#"{
                    "mode":"packet-up",
                    "downloadSettings":{
                        "address":"download.example",
                        "port":443,
                        "security":"tls",
                        "tlsSettings":{"allowInsecure":false},
                        "xhttpSettings":{"mode":"packet-up"}
                    }
                }"#,
            )
            .unwrap(),
        );

        let options = build_xhttp_options(&node, None, false, Vec::new()).unwrap();
        let download = options.config.download_settings.as_deref().unwrap();
        assert_eq!(download.security, "tls");
        assert_eq!(download.alpn, ["h2", "http/1.1"]);

        node.xhttp
            .as_mut()
            .unwrap()
            .download_settings
            .as_mut()
            .unwrap()
            .security = Some(String::new());
        let options = build_xhttp_options(&node, None, false, Vec::new()).unwrap();
        let download = options.config.download_settings.as_deref().unwrap();
        assert_eq!(download.security, "none");
        assert!(download.alpn.is_empty());
    }

    #[test]
    fn structured_xhttp_overrides_uri_params_and_extra_keeps_xray_precedence() {
        let mut node = ParsedNode::new("priority", NodeProtocol::Vless, "origin.example", 443);
        node.transport = "xhttp".into();
        node.transport_host = Some("legacy-host.example".into());
        node.transport_path = Some("/legacy".into());
        node.params.insert("mode".into(), "stream-one".into());
        node.params.insert("xPaddingBytes".into(), "1".into());
        node.params.insert("noSSEHeader".into(), "false".into());
        node.xhttp = Some(
            serde_json::from_str(
                r#"
{
  "host": "outer.example",
  "path": "/outer",
  "mode": "packet-up",
  "xPaddingBytes": 999,
  "extra": {
    "host": "ignored.example",
    "path": "/ignored",
    "mode": "stream-up",
    "xPaddingBytes": "200-300",
    "noSSEHeader": true,
    "headers": {"X-Source": "extra"}
  }
}
"#,
            )
            .unwrap(),
        );

        let config = build_xhttp_options(&node, None, false, vec![])
            .unwrap()
            .config;
        assert_eq!(config.host, "outer.example");
        assert_eq!(config.path, "/outer");
        assert_eq!(config.mode, "packet-up");
        assert_eq!(config.x_padding_bytes, "200-300");
        assert!(config.no_sse_header);
        assert_eq!(
            config.headers.get("X-Source").map(String::as_str),
            Some("extra")
        );
    }

    #[test]
    fn legacy_uri_xhttp_fields_are_typed_and_invalid_values_propagate() {
        let mut node = ParsedNode::new("legacy", NodeProtocol::Vless, "origin.example", 443);
        node.transport = "xhttp".into();
        for (key, value) in [
            ("host", "legacy.example"),
            ("path", "/legacy"),
            ("mode", "packet-up"),
            ("headers", r#"{"X-Legacy":"yes"}"#),
            ("xPaddingBytes", "100-200"),
            ("xPaddingObfsMode", "true"),
            ("xPaddingKey", "legacy_pad"),
            ("xPaddingHeader", "X-Legacy-Pad"),
            ("xPaddingPlacement", "query"),
            ("xPaddingMethod", "tokenish"),
            ("uplinkHTTPMethod", "PATCH"),
            ("noGRPCHeader", "true"),
            ("noSSEHeader", "true"),
            ("sessionIDPlacement", "header"),
            ("sessionIDKey", "X-Sid"),
            ("sessionIDTable", "Base62"),
            ("sessionIDLength", "16"),
            ("seqPlacement", "cookie"),
            ("seqKey", "seq"),
            ("uplinkDataPlacement", "body"),
            ("uplinkDataKey", "data"),
            ("uplinkChunkSize", "4096"),
            ("scMaxEachPostBytes", "1048576"),
            ("scMinPostsIntervalMs", "30-60"),
            ("scMaxBufferedPosts", "31"),
            ("scStreamUpServerSecs", "20-80"),
            ("serverMaxHeaderBytes", "12288"),
            ("xmux.maxConnections", "3-5"),
            ("xmux.cMaxReuseTimes", "12"),
            ("xmux.hMaxRequestTimes", "500-700"),
            ("xmux.hMaxReusableSecs", "1700-2700"),
            ("xmux.hKeepAlivePeriod", "-1"),
        ] {
            node.params.insert(key.into(), value.into());
        }
        node.params.insert(
            "downloadSettings".into(),
            r#"{"address":"down.example","port":443,"xhttpSettings":{"path":"/down","mode":"packet-up"}}"#
                .into(),
        );

        let config = build_xhttp_options(&node, None, false, vec![])
            .unwrap()
            .config;
        assert_eq!(config.host, "legacy.example");
        assert_eq!(config.headers.get("X-Legacy").unwrap(), "yes");
        assert!(config.x_padding_obfs_mode);
        assert_eq!(config.uplink_http_method, "PATCH");
        assert_eq!(config.session_id_length, "16");
        assert_eq!(config.sc_max_buffered_posts, 31);
        assert_eq!(config.server_max_header_bytes, 12288);
        assert_eq!(config.xmux.max_connections, "3-5");
        assert_eq!(config.xmux.h_keep_alive_period, -1);
        assert_eq!(
            config
                .download_settings
                .as_ref()
                .and_then(|settings| settings.port),
            Some(443)
        );

        node.params.insert("xPaddingBytes".into(), "100-1".into());
        let error = build_xhttp_options(&node, None, false, vec![]).unwrap_err();
        assert!(error.contains("min>max"), "error={error}");
        let error = build_outbound(&node)
            .err()
            .expect("invalid XHTTP must fail");
        assert!(error.contains("min>max"), "error={error}");
    }

    #[test]
    fn trojan_xhttp_transport_is_typed_and_invalid_config_propagates() {
        let mut node = ParsedNode::new("trojan-xhttp", NodeProtocol::Trojan, "origin.example", 443);
        node.password = Some("test-password".into());
        node.transport = "splithttp".into();
        node.tls = false;
        node.sni = Some("tls.example".into());
        node.params.insert("host".into(), "cdn.example".into());
        node.params.insert("path".into(), "/trojan".into());
        node.params.insert("mode".into(), "packet-up".into());

        let outbound = build_trojan(&node).unwrap();
        let xhttp = outbound
            .xhttp
            .as_ref()
            .expect("splithttp alias must select XHTTP");
        assert!(xhttp.enabled);
        assert!(xhttp.tls, "Trojan over XHTTP must retain mandatory TLS");
        assert_eq!(xhttp.sni.as_deref(), Some("tls.example"));
        assert_eq!(xhttp.config.host, "cdn.example");
        assert_eq!(xhttp.config.path, "/trojan");
        assert_eq!(xhttp.config.mode, "packet-up");

        node.params.insert("xPaddingBytes".into(), "100-1".into());
        let error = build_trojan(&node).unwrap_err();
        assert!(error.contains("min>max"), "error={error}");
        let error = build_outbound(&node)
            .err()
            .expect("invalid Trojan XHTTP must fail");
        assert!(error.contains("min>max"), "error={error}");
    }

    #[test]
    fn legacy_download_settings_validates_aliases_before_mapping() {
        let mut equivalent = ParsedNode::new(
            "legacy-equivalent",
            NodeProtocol::Vless,
            "origin.example",
            443,
        );
        equivalent.transport = "xhttp".into();
        equivalent.params.insert(
            "downloadSettings".into(),
            r#"{
  "address": "download.example",
  "port": 443,
  "alpn": ["h2"],
  "tlsSettings": {"alpn": ["h2"]},
  "transport": {
    "kind": "xhttp",
    "host": "cdn.example",
    "path": "/download",
    "xhttp": {"host": "cdn.example", "path": "/download", "mode": "packet-up"}
  },
  "xhttpSettings": {"host": "cdn.example", "path": "/download", "mode": "packet-up"}
}"#
            .into(),
        );
        build_xhttp_options(&equivalent, None, false, vec![]).unwrap();

        let mut conflicting = ParsedNode::new(
            "legacy-conflict",
            NodeProtocol::Vless,
            "origin.example",
            443,
        );
        conflicting.transport = "xhttp".into();
        conflicting.params.insert(
            "downloadSettings".into(),
            r#"{
  "address": "download.example",
  "port": 443,
  "transport": {
    "kind": "xhttp",
    "xhttp": {"mode": "stream-up"}
  },
  "xhttpSettings": {"mode": "packet-up"}
}"#
            .into(),
        );
        let error = build_xhttp_options(&conflicting, None, false, vec![]).unwrap_err();
        assert!(error.contains("必须语义等价"), "error={error}");
    }

    fn wireguard_node() -> ParsedNode {
        let mut node = ParsedNode::new("wg", NodeProtocol::Wireguard, "127.0.0.1", 51_820);
        node.params.insert(
            "private-key".into(),
            base64::engine::general_purpose::STANDARD.encode([1u8; 32]),
        );
        node.params.insert(
            "public-key".into(),
            base64::engine::general_purpose::STANDARD.encode([2u8; 32]),
        );
        node.params.insert("ip".into(), "10.0.0.2/32".into());
        node.params.insert("ipv6".into(), "fd00::2/128".into());
        node
    }

    #[test]
    fn wireguard_registry_maps_complete_single_peer_config() {
        let mut node = wireguard_node();
        node.params
            .insert("allowed-ips".into(), "[\"10.0.0.0/8\",\"fd00::/8\"]".into());
        node.params.insert("reserved".into(), "[1,2,3]".into());
        node.params
            .insert("persistent-keepalive".into(), "17".into());
        node.params.insert("mtu".into(), "1380".into());
        node.params
            .insert("tcp-buffer-size".into(), "131072".into());
        node.params.insert("udp-buffer-size".into(), "65536".into());
        node.params.insert("max-tcp-sessions".into(), "99".into());
        node.params.insert("max-udp-sessions".into(), "88".into());
        node.params.insert("packet-queue".into(), "256".into());
        node.params.insert("workers".into(), "4".into());
        node.params.insert("connect-timeout".into(), "3s".into());
        node.params.insert("udp-timeout".into(), "45s".into());
        node.params
            .insert("remote-dns-resolve".into(), "true".into());
        node.params.insert("dns".into(), "[\"10.0.0.53\"]".into());
        node.params.insert("network".into(), "tcp,udp".into());

        let outbound = wireguard_from_node(&node).unwrap();
        let config = outbound.config();
        assert_eq!(config.local_addresses.len(), 2);
        assert_eq!(config.peers[0].allowed_ips.len(), 2);
        assert_eq!(config.peers[0].reserved, [1, 2, 3]);
        assert_eq!(config.peers[0].persistent_keepalive, Some(17));
        assert_eq!(config.mtu, 1380);
        assert_eq!(config.tcp_buffer_size, 131_072);
        assert_eq!(config.udp_buffer_size, 65_536);
        assert_eq!(config.max_tcp_sessions, 99);
        assert_eq!(config.max_udp_sessions, 88);
        assert_eq!(config.packet_queue, 256);
        assert_eq!(config.workers, 4);
        assert_eq!(config.connect_timeout, std::time::Duration::from_secs(3));
        assert_eq!(config.udp_idle_timeout, std::time::Duration::from_secs(45));
        assert!(config.remote_dns_resolve);
        assert_eq!(
            config.dns,
            ["10.0.0.53".parse::<std::net::IpAddr>().unwrap()]
        );
        assert!(config.tcp && config.udp);
    }

    #[test]
    fn wireguard_registry_maps_multi_peer_and_url_safe_keys() {
        let mut node = wireguard_node();
        node.params.insert(
            "private-key".into(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xfbu8; 32]),
        );
        node.params.remove("public-key");
        node.params.insert("reserved".into(), "[5,6,7]".into());
        node.params.insert("workers".into(), "0".into());
        node.params.insert(
            "peers".into(),
            serde_json::json!([
                {
                    "server": "127.0.0.1",
                    "port": 51820,
                    "public_key": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([3u8; 32]),
                    "allowed_ips": ["10.0.0.0/8"],
                    "reserved": [9, 8, 7]
                },
                {
                    "endpoint": "[::1]:51821",
                    "public-key": base64::engine::general_purpose::STANDARD.encode([4u8; 32]),
                    "allowed-ips": ["fd00::/8"],
                    "persistent_keepalive_interval": 0
                }
            ])
            .to_string(),
        );
        let outbound = wireguard_from_node(&node).unwrap();
        assert_eq!(outbound.config().peers.len(), 2);
        assert_eq!(outbound.config().peers[0].reserved, [9, 8, 7]);
        assert_eq!(outbound.config().peers[1].endpoint_host, "::1");
        assert_eq!(outbound.config().peers[1].endpoint_port, 51_821);
        assert_eq!(outbound.config().peers[1].reserved, [5, 6, 7]);
        assert_eq!(outbound.config().peers[1].persistent_keepalive, None);
        assert!((1..=64).contains(&outbound.config().workers));
    }

    #[test]
    fn wireguard_registry_rejects_conflicts_and_invalid_bounds() {
        let mut node = wireguard_node();
        node.params.insert("private_key".into(), "different".into());
        assert!(
            wireguard_from_node(&node)
                .unwrap_err()
                .contains("conflicting")
        );

        let mut node = wireguard_node();
        node.params.insert("mtu".into(), "70000".into());
        assert!(build_outbound(&node).is_err());

        let mut node = wireguard_node();
        node.params.insert("workres".into(), "8".into());
        assert_eq!(
            wireguard_from_node(&node).unwrap_err(),
            "unknown-parameter-workres"
        );

        let mut node = wireguard_node();
        node.params.remove("public-key");
        node.params.insert(
            "peers".into(),
            serde_json::json!([{
                "endpoint": "127.0.0.1:51820",
                "public-key": base64::engine::general_purpose::STANDARD.encode([3u8; 32]),
                "allowed-ips": ["10.0.0.0/8"],
                "typo": true
            }])
            .to_string(),
        );
        assert!(
            wireguard_from_node(&node)
                .unwrap_err()
                .contains("unknown-field-typo")
        );
    }
}
