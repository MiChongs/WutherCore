//! 出站注册表 —— 把 [`ParsedNode`] 转化为 [`Arc<dyn OutboundAdapter>`]。
//!
//! 内置规则：direct / block 自动注册；其它协议按 [`NodeProtocol`] 选择。

use std::{collections::BTreeMap, net::IpAddr, sync::Arc};

use base64::Engine as _;
use core_config::node_uri::{NodeProtocol, ParsedNode};
use uuid::Uuid;

use crate::{
    adapter::SharedOutbound,
    block::BlockOutbound,
    direct::DirectOutbound,
    dns_hijack::DnsHijackOutbound,
    http::HttpOutbound,
    proto::{
        anytls::AnyTlsOutbound,
        hysteria::HysteriaOutbound,
        hysteria2::Hysteria2Outbound,
        mieru::{MieruCipher, MieruOutbound},
        shadowsocks::{ShadowsocksOutbound, SsCipher},
        snell::{SnellCipher, SnellOutbound},
        ss2022::{Ss22Cipher, Ss2022Outbound},
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
        xhttp::Config as XhttpConfig,
    },
    socks5::Socks5Outbound,
    stub::StubOutbound,
    transport::{GrpcOptions, H2Options, HttpOptions, RealityOptions, WsOptions, XhttpOptions},
};

pub type ResolveFn = Arc<dyn Fn(&str) -> Option<SharedOutbound> + Send + Sync>;

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
pub fn register_nodes(reg: &mut OutboundRegistry, nodes: &[ParsedNode]) {
    for node in nodes {
        let ob = build_outbound(node);
        reg.insert(node.name.clone(), ob);
    }
}

pub fn build_outbound(node: &ParsedNode) -> SharedOutbound {
    match node.protocol {
        NodeProtocol::Direct => DirectOutbound::new(),
        NodeProtocol::Block => BlockOutbound::new(),
        NodeProtocol::Dns => DnsHijackOutbound::new(node.name.clone()),
        NodeProtocol::Http => {
            let mut ob = HttpOutbound::new(&node.name, &node.host, node.port);
            if let (Some(u), Some(p)) = (node.user.clone(), node.password.clone()) {
                ob = ob.with_auth(u, p);
            }
            ob.into_arc()
        }
        NodeProtocol::Socks5 => {
            let mut ob = Socks5Outbound::new(&node.name, &node.host, node.port).with_udp(node.udp);
            if let (Some(u), Some(p)) = (node.user.clone(), node.password.clone()) {
                ob = ob.with_auth(u, p);
            }
            ob.into_arc()
        }
        NodeProtocol::Shadowsocks => build_shadowsocks(node),
        NodeProtocol::ShadowsocksR => build_ssr(node),
        NodeProtocol::Vmess => build_vmess(node),
        NodeProtocol::Vless => build_vless(node),
        NodeProtocol::Trojan => build_trojan(node),
        NodeProtocol::Snell => build_snell(node),
        NodeProtocol::AnyTls => build_anytls(node),
        NodeProtocol::Ssh => build_ssh(node),
        NodeProtocol::Hysteria => build_hysteria_v1(node),
        NodeProtocol::Hysteria2 => build_hysteria2(node),
        NodeProtocol::Tuic => build_tuic(node),
        NodeProtocol::Wireguard => build_wireguard(node),
        NodeProtocol::Mieru => build_mieru(node),
        NodeProtocol::Sudoku => build_sudoku(node),
        NodeProtocol::TrustTunnel => build_trusttunnel(node),
        ref other => StubOutbound::new(node.name.clone(), proto_static_name(other)),
    }
}

fn build_shadowsocks(node: &ParsedNode) -> SharedOutbound {
    let method = node.method.as_deref().unwrap_or("aes-256-gcm");
    let pwd = node.password.as_deref().unwrap_or("");
    if let Some(c) = Ss22Cipher::parse(method)
        && !pwd.is_empty()
    {
        return match Ss2022Outbound::new(&node.name, &node.host, node.port, c, pwd) {
            Ok(mut ob) => {
                ob.udp = node.udp;
                Arc::new(ob)
            }
            Err(_) => StubOutbound::new(node.name.clone(), "ss2022(invalid-psk)"),
        };
    }
    match SsCipher::parse(method) {
        Some(c) if !pwd.is_empty() => {
            let mut ob = ShadowsocksOutbound::new(&node.name, &node.host, node.port, c, pwd);
            ob.udp = node.udp;
            Arc::new(ob)
        }
        _ => StubOutbound::new(node.name.clone(), "shadowsocks(unknown-cipher)"),
    }
}

fn build_ssr(node: &ParsedNode) -> SharedOutbound {
    let method = node.method.as_deref().unwrap_or("aes-256-cfb");
    let pwd = node.password.as_deref().unwrap_or("");
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
        None => return StubOutbound::new(node.name.clone(), "ssr(unsupported-obfs)"),
    };
    let proto = match SsrProtocol::parse(proto_str) {
        Some(p) => p,
        None => return StubOutbound::new(node.name.clone(), "ssr(unsupported-protocol)"),
    };
    match SsrCipher::parse(method) {
        Some(c) if !pwd.is_empty() => {
            let mut ob = SsrOutbound::new(&node.name, &node.host, node.port, c, pwd);
            ob.obfs = obfs;
            ob.protocol = proto;
            ob.obfs_param = node.params.get("obfs-param").cloned().unwrap_or_default();
            ob.protocol_param = node
                .params
                .get("protocol-param")
                .cloned()
                .unwrap_or_default();
            Arc::new(ob)
        }
        _ => StubOutbound::new(node.name.clone(), "ssr(unsupported-cipher)"),
    }
}

fn build_vmess(node: &ParsedNode) -> SharedOutbound {
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
        // VMess Legacy 也支持 ws transport
        let net = resolve_network_string(node);
        if VmessNetwork::parse(&net) == VmessNetwork::Ws {
            ob.ws = Some(build_ws_options(node));
        }
        return Arc::new(ob);
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
    // VMess network 分发：tcp / ws / http / h2 / grpc / xhttp
    let network_str = resolve_network_string(node);
    ob.network = VmessNetwork::parse(&network_str);
    apply_vmess_network_options(node, &mut ob);
    Arc::new(ob)
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

fn apply_vmess_network_options(node: &ParsedNode, ob: &mut VmessOutbound) {
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
            ob.grpc = Some(build_grpc_options(node));
        }
        VmessNetwork::Xhttp => {
            ob.xhttp = Some(build_xhttp_options(
                node,
                ob.sni.clone(),
                ob.insecure,
                ob.alpn.clone(),
            ));
        }
    }
}

fn build_vless(node: &ParsedNode) -> SharedOutbound {
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
    let network_str = resolve_network_string(node);
    ob.network = VlessNetwork::parse(&network_str);
    apply_vless_network_options(node, &mut ob);
    Arc::new(ob)
}

fn apply_vless_network_options(node: &ParsedNode, ob: &mut VlessOutbound) {
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
            ob.grpc = Some(build_grpc_options(node));
        }
        VlessNetwork::Xhttp => {
            ob.xhttp = Some(build_xhttp_options(
                node,
                ob.sni.clone(),
                ob.insecure,
                ob.alpn.clone(),
            ));
        }
    }
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

fn build_grpc_options(node: &ParsedNode) -> GrpcOptions {
    GrpcOptions {
        enabled: true,
        service_name: node
            .params
            .get("serviceName")
            .or_else(|| node.params.get("grpc-service-name"))
            .cloned()
            .unwrap_or_default(),
        user_agent: node
            .params
            .get("grpc-user-agent")
            .cloned()
            .unwrap_or_default(),
        host: node.params.get("host").cloned().unwrap_or_default(),
    }
}

fn build_xhttp_options(
    node: &ParsedNode,
    sni: Option<String>,
    insecure: bool,
    alpn: Vec<String>,
) -> XhttpOptions {
    let mut cfg = XhttpConfig::default();
    if let Some(host) = node
        .params
        .get("host")
        .or_else(|| node.params.get("xhttp-host"))
    {
        cfg.host = host.clone();
    }
    if let Some(path) = node.params.get("path") {
        cfg.path = path.clone();
    }
    if let Some(mode) = node
        .params
        .get("mode")
        .or_else(|| node.params.get("xhttp-mode"))
    {
        cfg.mode = mode.clone();
    }
    if let Some(method) = node.params.get("uplink-http-method") {
        cfg.uplink_http_method = method.clone();
    }
    if let Some(no_grpc) = node.params.get("no-grpc-header") {
        cfg.no_grpc_header = no_grpc == "1" || no_grpc == "true";
    }
    if let Some(p) = node.params.get("x-padding-bytes") {
        cfg.x_padding_bytes = p.clone();
    }
    if let Some(m) = node.params.get("x-padding-method") {
        cfg.x_padding_method = m.clone();
    }
    if let Some(o) = node.params.get("x-padding-obfs-mode") {
        cfg.x_padding_obfs_mode = o == "1" || o == "true";
    }
    if let Some(p) = node.params.get("session-placement") {
        cfg.session_placement = p.clone();
    }
    if let Some(p) = node.params.get("seq-placement") {
        cfg.seq_placement = p.clone();
    }
    if let Some(p) = node.params.get("uplink-data-placement") {
        cfg.uplink_data_placement = p.clone();
    }
    if let Some(s) = node.params.get("sc-max-each-post-bytes") {
        cfg.sc_max_each_post_bytes = s.clone();
    }
    if let Some(s) = node.params.get("sc-min-posts-interval-ms") {
        cfg.sc_min_posts_interval_ms = s.clone();
    }
    let alpn_eff = if alpn.is_empty() {
        vec!["h2".into()]
    } else {
        alpn
    };
    XhttpOptions {
        enabled: true,
        config: cfg,
        sni,
        insecure,
        alpn: alpn_eff,
        has_reality: node
            .params
            .get("security")
            .map(|s| s == "reality")
            .unwrap_or(false),
    }
}

fn build_trojan(node: &ParsedNode) -> SharedOutbound {
    let pwd = node.password.clone().unwrap_or_default();
    let mut ob = TrojanOutbound::new(&node.name, &node.host, node.port, pwd);
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
    Arc::new(ob)
}

fn build_snell(node: &ParsedNode) -> SharedOutbound {
    let cipher = node
        .params
        .get("cipher")
        .or_else(|| node.method.as_ref())
        .and_then(|s| SnellCipher::parse(s))
        .unwrap_or(SnellCipher::Aes128Gcm);
    let pwd = node
        .password
        .as_deref()
        .or_else(|| node.params.get("psk").map(|s| s.as_str()))
        .unwrap_or("");
    if pwd.is_empty() {
        return StubOutbound::new(node.name.clone(), "snell(missing-psk)");
    }
    let mut ob = SnellOutbound::new(&node.name, &node.host, node.port, cipher, pwd);
    ob.udp = node.udp;
    if let Some(v) = node
        .params
        .get("version")
        .and_then(|s| s.parse::<u8>().ok())
    {
        ob.version = v;
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
            _ => {}
        }
    }
    Arc::new(ob)
}

fn build_anytls(node: &ParsedNode) -> SharedOutbound {
    let pwd = node.password.clone().unwrap_or_default();
    let mut ob = AnyTlsOutbound::new(&node.name, &node.host, node.port, pwd);
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
        .get("allowInsecure")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    if let Some(alpn) = node.params.get("alpn") {
        ob.alpn = alpn.split(',').map(|s| s.trim().to_string()).collect();
    }
    Arc::new(ob)
}

fn build_ssh(node: &ParsedNode) -> SharedOutbound {
    let user = node.user.clone().unwrap_or_default();
    let mut ob = SshOutbound::new(&node.name, &node.host, node.port, user);
    if let Some(pwd) = &node.password {
        ob = ob.with_password(pwd);
    } else if let Some(key_path) = node.params.get("private-key") {
        let pp = node.params.get("private-key-passphrase").cloned();
        ob = ob.with_private_key_path(key_path, pp);
    }
    if let Some(known) = node.params.get("known-hosts") {
        let lines: Vec<String> = known.lines().map(|s| s.to_string()).collect();
        ob = ob.with_known_hosts(lines);
    }
    Arc::new(ob)
}

fn build_hysteria_v1(node: &ParsedNode) -> SharedOutbound {
    let auth_b = node
        .params
        .get("auth")
        .cloned()
        .unwrap_or_default()
        .into_bytes();
    let mut ob = HysteriaOutbound::new(&node.name, &node.host, node.port, auth_b);
    if let Some(s) = node.sni.clone() {
        ob.sni = Some(s);
    }
    ob.insecure = node
        .params
        .get("insecure")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    if let Some(up) = node.params.get("up").and_then(|s| s.parse::<u32>().ok()) {
        ob.up_mbps = up;
    }
    if let Some(down) = node.params.get("down").and_then(|s| s.parse::<u32>().ok()) {
        ob.down_mbps = down;
    }
    if let Some(obfs) = node.params.get("obfs") {
        ob = ob.with_obfs(obfs.as_bytes().to_vec());
    }
    Arc::new(ob)
}

fn build_hysteria2(node: &ParsedNode) -> SharedOutbound {
    let pwd = node.password.clone().unwrap_or_default();
    let mut ob = Hysteria2Outbound::new(&node.name, &node.host, node.port, pwd);
    if let Some(s) = node.sni.clone() {
        ob.sni = Some(s);
    }
    ob.insecure = node
        .params
        .get("insecure")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    if let Some(obfs_pwd) = node.params.get("obfs-password") {
        ob = ob.with_obfs(obfs_pwd);
    }
    if let Some(up) = node.params.get("up").and_then(|s| s.parse::<u32>().ok()) {
        ob.up_mbps = up;
    }
    if let Some(down) = node.params.get("down").and_then(|s| s.parse::<u32>().ok()) {
        ob.down_mbps = down;
    }
    Arc::new(ob)
}

fn build_tuic(node: &ParsedNode) -> SharedOutbound {
    match tuic_from_node(node) {
        Ok(outbound) => Arc::new(outbound),
        Err(protocol) => StubOutbound::new(node.name.clone(), protocol),
    }
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

fn build_wireguard(node: &ParsedNode) -> SharedOutbound {
    match wireguard_from_node(node) {
        Ok(outbound) => Arc::new(outbound),
        Err(reason) => Arc::new(InvalidWireGuardOutbound {
            name: node.name.clone(),
            reason,
        }),
    }
}

#[derive(Debug)]
struct InvalidWireGuardOutbound {
    name: String,
    reason: String,
}

#[async_trait::async_trait]
impl crate::adapter::OutboundAdapter for InvalidWireGuardOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> &'static str {
        "wireguard"
    }

    fn capabilities(&self) -> crate::adapter::Capabilities {
        crate::adapter::Capabilities::default()
    }

    async fn dial_tcp(
        &self,
        _context: crate::adapter::DialContext,
    ) -> std::io::Result<crate::adapter::BoxedStream> {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("wireguard node `{}` is invalid: {}", self.name, self.reason),
        ))
    }

    async fn dial_udp(
        &self,
        _context: crate::adapter::DialContext,
    ) -> std::io::Result<crate::adapter::BoxedUdp> {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("wireguard node `{}` is invalid: {}", self.name, self.reason),
        ))
    }
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

fn build_sudoku(node: &ParsedNode) -> SharedOutbound {
    let key = node
        .params
        .get("key")
        .cloned()
        .or_else(|| node.password.clone())
        .unwrap_or_default();
    if key.is_empty() {
        return StubOutbound::new(node.name.clone(), "sudoku(missing-key)");
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
            Err(_) => {
                return StubOutbound::new(node.name.clone(), "sudoku(invalid-aead)");
            }
        }
    }
    if let Some(t) = node.params.get("table-type") {
        cfg.table_mode = t.clone();
    }
    if let Some(t) = node.params.get("custom-table") {
        cfg.custom_table = t.clone();
    }
    if let Some(min) = node
        .params
        .get("padding-min")
        .and_then(|s| s.parse::<i32>().ok())
    {
        cfg.padding_min = min;
    }
    if let Some(max) = node
        .params
        .get("padding-max")
        .and_then(|s| s.parse::<i32>().ok())
    {
        cfg.padding_max = max;
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
    match SudokuOutbound::new(&node.name, &node.host, node.port, cfg) {
        Ok(ob) => Arc::new(ob),
        Err(_) => StubOutbound::new(node.name.clone(), "sudoku(table-build-error)"),
    }
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

fn proto_static_name(p: &NodeProtocol) -> &'static str {
    match p {
        NodeProtocol::Dns => "dns",
        NodeProtocol::Shadowsocks => "shadowsocks",
        NodeProtocol::ShadowsocksR => "shadowsocksr",
        NodeProtocol::Vmess => "vmess",
        NodeProtocol::Vless => "vless",
        NodeProtocol::Trojan => "trojan",
        NodeProtocol::Hysteria => "hysteria",
        NodeProtocol::Hysteria2 => "hysteria2",
        NodeProtocol::Tuic => "tuic",
        NodeProtocol::Wireguard => "wireguard",
        NodeProtocol::Ssh => "ssh",
        NodeProtocol::Snell => "snell",
        NodeProtocol::AnyTls => "anytls",
        NodeProtocol::Mieru => "mieru",
        NodeProtocol::Sudoku => "sudoku",
        NodeProtocol::TrustTunnel => "trusttunnel",
        _ => "stub",
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use core_config::node_uri::{NodeProtocol, ParsedNode};
    use uuid::Uuid;

    use super::{build_outbound, tuic_from_node, wireguard_from_node};
    use crate::proto::tuic::TuicUdpMode;

    #[test]
    fn ss2022_registry_preserves_udp_flag_and_eih_chain() {
        let identity = base64::engine::general_purpose::STANDARD.encode([0x11u8; 16]);
        let user = base64::engine::general_purpose::STANDARD.encode([0x22u8; 16]);
        let mut node = ParsedNode::new("ss22", NodeProtocol::Shadowsocks, "127.0.0.1", 8388);
        node.method = Some("2022-blake3-aes-128-gcm".into());
        node.password = Some(format!("{identity}:{user}"));
        node.udp = false;

        let outbound = build_outbound(&node);
        assert_eq!(outbound.protocol(), "ss2022");
        assert!(!outbound.capabilities().udp);

        node.udp = true;
        let outbound = build_outbound(&node);
        assert!(outbound.capabilities().udp);
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
        assert_eq!(build_outbound(&node).protocol(), "tuic(invalid-uuid)");

        node.uuid = Some("not-a-uuid".into());
        assert_eq!(build_outbound(&node).protocol(), "tuic(invalid-uuid)");

        node.uuid = Some("2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365".into());
        node.password = None;
        assert_eq!(build_outbound(&node).protocol(), "tuic(missing-password)");

        node.password = Some("secret".into());
        node.params
            .insert("udp-relay-mode".into(), "unsupported".into());
        assert_eq!(
            build_outbound(&node).protocol(),
            "tuic(invalid-udp-relay-mode)"
        );
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
        let outbound = build_outbound(&node);
        assert_eq!(outbound.protocol(), "wireguard");
        assert!(!outbound.capabilities().tcp);
        assert!(!outbound.capabilities().udp);

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
