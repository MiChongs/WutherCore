//! 出站注册表 —— 把 [`ParsedNode`] 转化为 [`Arc<dyn OutboundAdapter>`]。
//!
//! 内置规则：direct / block 自动注册；其它协议按 [`NodeProtocol`] 选择。

use std::{collections::BTreeMap, sync::Arc};

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
        wireguard::WireGuardOutbound,
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
    let priv_b64 = match node
        .params
        .get("private-key")
        .or_else(|| node.password.as_ref())
    {
        Some(s) => s,
        None => return StubOutbound::new(node.name.clone(), "wireguard(missing-private-key)"),
    };
    let peer_b64 = match node.params.get("public-key") {
        Some(s) => s,
        None => return StubOutbound::new(node.name.clone(), "wireguard(missing-public-key)"),
    };
    let priv_key = match decode_b64_32(priv_b64) {
        Some(k) => k,
        None => return StubOutbound::new(node.name.clone(), "wireguard(invalid-private-key)"),
    };
    let peer_key = match decode_b64_32(peer_b64) {
        Some(k) => k,
        None => return StubOutbound::new(node.name.clone(), "wireguard(invalid-public-key)"),
    };
    let mut ob = WireGuardOutbound::new(&node.name, &node.host, node.port, priv_key, peer_key);
    if let Some(psk_b64) = node.params.get("preshared-key") {
        if let Some(psk) = decode_b64_32(psk_b64) {
            ob = ob.with_preshared_key(psk);
        }
    }
    if let Some(addr) = node.params.get("address") {
        for a in addr.split(',') {
            let a = a.trim().split('/').next().unwrap_or("");
            if let Ok(ip) = a.parse() {
                ob = ob.with_local_address(ip);
            }
        }
    }
    Arc::new(ob)
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
    let v = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .ok()?;
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

    use super::{build_outbound, tuic_from_node};
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
}
