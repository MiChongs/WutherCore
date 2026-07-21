//! 出站注册表 —— 把 [`ParsedNode`] 转化为 [`Arc<dyn OutboundAdapter>`]。
//!
//! 内置规则：direct / block 自动注册；其它协议按 [`NodeProtocol`] 选择。

use std::{collections::BTreeMap, sync::Arc};

use base64::Engine as _;
use core_config::{
    model::{
        XhttpConfig as TypedXhttpConfig, XhttpDownloadSettings as TypedDownloadSettings,
        XhttpRange as TypedRange,
    },
    node_uri::{NodeProtocol, ParsedNode},
};
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
        xhttp::config::{
            Config as XhttpConfig, DownloadRealitySettings, DownloadSettings,
            DownloadSocketSettings, DownloadTlsSettings, DownloadTransportSettings,
        },
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
pub fn register_nodes(reg: &mut OutboundRegistry, nodes: &[ParsedNode]) -> Result<(), String> {
    for node in nodes {
        let ob = build_outbound(node)
            .map_err(|error| format!("node `{}` outbound config invalid: {error}", node.name))?;
        reg.insert(node.name.clone(), ob);
    }
    Ok(())
}

pub fn build_outbound(node: &ParsedNode) -> Result<SharedOutbound, String> {
    let outbound: SharedOutbound = match node.protocol {
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
        NodeProtocol::Vmess => return build_vmess(node),
        NodeProtocol::Vless => return build_vless(node),
        NodeProtocol::Trojan => Arc::new(build_trojan(node)?),
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
    };
    Ok(outbound)
}

/// 源码兼容别名；所有调用路径现在都会保留 XHTTP 配置错误。
pub fn try_build_outbound(node: &ParsedNode) -> Result<SharedOutbound, String> {
    build_outbound(node)
}

fn build_shadowsocks(node: &ParsedNode) -> SharedOutbound {
    let method = node.method.as_deref().unwrap_or("aes-256-gcm");
    let pwd = node.password.as_deref().unwrap_or("");
    if let Some(c) = Ss22Cipher::parse(method) {
        if !pwd.is_empty() {
            return match Ss2022Outbound::new(&node.name, &node.host, node.port, c, pwd) {
                Ok(mut ob) => {
                    ob.udp = node.udp;
                    Arc::new(ob)
                }
                Err(_) => StubOutbound::new(node.name.clone(), "ss2022(invalid-psk)"),
            };
        }
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
        // VMess Legacy 也支持 ws transport
        let net = resolve_network_string(node);
        if VmessNetwork::parse(&net) == VmessNetwork::Ws {
            ob.ws = Some(build_ws_options(node));
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
            ob.grpc = Some(build_grpc_options(node));
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
            ob.grpc = Some(build_grpc_options(node));
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
    if matches!(
        node.transport.to_ascii_lowercase().as_str(),
        "xhttp" | "splithttp"
    ) {
        ob.xhttp = Some(build_xhttp_options_with_tls_requirement(
            node,
            ob.sni.clone(),
            ob.insecure,
            ob.alpn.clone(),
            true,
        )?);
    }
    Ok(ob)
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
    use core_config::{
        model::XhttpConfig as TypedXhttpConfig,
        node_uri::{NodeProtocol, ParsedNode},
    };
    use uuid::Uuid;

    use super::{
        DownloadTlsSettings, build_outbound, build_trojan, build_xhttp_options, tuic_from_node,
    };
    use crate::proto::tuic::TuicUdpMode;

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
}
