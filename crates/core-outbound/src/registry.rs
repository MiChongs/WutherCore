//! 出站注册表 —— 把 [`ParsedNode`] 转化为 [`Arc<dyn OutboundAdapter>`]。
//!
//! 内置规则：direct / block 自动注册；其它协议按 [`NodeProtocol`] 选择。

use std::collections::BTreeMap;
use std::sync::Arc;

use core_config::node_uri::{NodeProtocol, ParsedNode};
use uuid::Uuid;

use crate::adapter::SharedOutbound;
use crate::block::BlockOutbound;
use crate::direct::DirectOutbound;
use crate::http::HttpOutbound;
use crate::proto::anytls::AnyTlsOutbound;
use crate::proto::hysteria::HysteriaOutbound;
use crate::proto::hysteria2::Hysteria2Outbound;
use crate::proto::mieru::{MieruCipher, MieruOutbound};
use crate::proto::shadowsocks::{ShadowsocksOutbound, SsCipher};
use crate::proto::snell::{SnellCipher, SnellOutbound};
use crate::proto::ss2022::{Ss22Cipher, Ss2022Outbound};
use crate::proto::ssh::SshOutbound;
use crate::proto::ssr::{SsrCipher, SsrObfs, SsrOutbound, SsrProtocol};
use crate::proto::trojan::TrojanOutbound;
use crate::proto::tuic::TuicOutbound;
use crate::proto::vless::VlessOutbound;
use crate::proto::vmess::{VmessOutbound, VmessSecurity};
use crate::proto::vmess_legacy::VmessLegacyOutbound;
use crate::proto::wireguard::WireGuardOutbound;
use crate::socks5::Socks5Outbound;
use crate::stub::StubOutbound;
use crate::transport::WsOptions;

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
        NodeProtocol::Http => {
            let mut ob = HttpOutbound::new(&node.name, &node.host, node.port);
            if let (Some(u), Some(p)) = (node.user.clone(), node.password.clone()) {
                ob = ob.with_auth(u, p);
            }
            ob.into_arc()
        }
        NodeProtocol::Socks5 => {
            let mut ob = Socks5Outbound::new(&node.name, &node.host, node.port);
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
        NodeProtocol::Sudoku | NodeProtocol::TrustTunnel => {
            // mihomo 私有协议；保留 stub 接口，后续 PR 完整迁移
            StubOutbound::new(node.name.clone(), proto_static_name(&node.protocol))
        }
        ref other => StubOutbound::new(node.name.clone(), proto_static_name(other)),
    }
}

fn build_shadowsocks(node: &ParsedNode) -> SharedOutbound {
    let method = node.method.as_deref().unwrap_or("aes-256-gcm");
    let pwd = node.password.as_deref().unwrap_or("");
    if let Some(c) = Ss22Cipher::parse(method) {
        if !pwd.is_empty() {
            return match Ss2022Outbound::new(&node.name, &node.host, node.port, c, pwd) {
                Ok(ob) => Arc::new(ob),
                Err(_) => StubOutbound::new(node.name.clone(), "ss2022(invalid-psk)"),
            };
        }
    }
    match SsCipher::parse(method) {
        Some(c) if !pwd.is_empty() => Arc::new(ShadowsocksOutbound::new(
            &node.name, &node.host, node.port, c, pwd,
        )),
        _ => StubOutbound::new(node.name.clone(), "shadowsocks(unknown-cipher)"),
    }
}

fn build_ssr(node: &ParsedNode) -> SharedOutbound {
    let method = node.method.as_deref().unwrap_or("aes-256-cfb");
    let pwd = node.password.as_deref().unwrap_or("");
    let obfs_str = node.params.get("obfs").map(|s| s.as_str()).unwrap_or("plain");
    let proto_str = node.params.get("protocol").map(|s| s.as_str()).unwrap_or("origin");
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
            ob.protocol_param = node.params.get("protocol-param").cloned().unwrap_or_default();
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
            || node.params.get("tls").map(|s| s == "tls" || s == "true").unwrap_or(false);
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
        if node.transport == "ws" || node.params.get("net").map(|s| s == "ws").unwrap_or(false) {
            ob.ws = Some(WsOptions {
                enabled: true,
                path: node.params.get("path").cloned().unwrap_or_else(|| "/".into()),
                host: node.params.get("host").cloned(),
                headers: vec![],
            });
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
        || node.params.get("tls").map(|s| s == "tls" || s == "true").unwrap_or(false);
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
    if node.transport == "ws" || node.params.get("net").map(|s| s == "ws").unwrap_or(false) {
        ob.ws = Some(WsOptions {
            enabled: true,
            path: node.params.get("path").cloned().unwrap_or_else(|| "/".into()),
            host: node.params.get("host").cloned(),
            headers: vec![],
        });
    }
    Arc::new(ob)
}

fn build_vless(node: &ParsedNode) -> SharedOutbound {
    let uuid = node
        .uuid
        .as_deref()
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(Uuid::nil);
    let mut ob = VlessOutbound::new(&node.name, &node.host, node.port, uuid);
    ob.tls = node.tls;
    ob.sni = node.sni.clone().or(Some(node.host.clone()));
    ob.insecure = node
        .params
        .get("allowInsecure")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    if let Some(alpn) = node.params.get("alpn") {
        ob.alpn = alpn.split(',').map(|s| s.trim().to_string()).collect();
    }
    if node.transport == "ws" {
        ob.ws = Some(WsOptions {
            enabled: true,
            path: node.params.get("path").cloned().unwrap_or_else(|| "/".into()),
            host: node.params.get("host").cloned(),
            headers: vec![],
        });
    }
    Arc::new(ob)
}

fn build_trojan(node: &ParsedNode) -> SharedOutbound {
    let pwd = node.password.clone().unwrap_or_default();
    let mut ob = TrojanOutbound::new(&node.name, &node.host, node.port, pwd);
    ob.sni = node.sni.clone().or(Some(node.host.clone()));
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
    if let Some(v) = node.params.get("version").and_then(|s| s.parse::<u8>().ok()) {
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
    ob.sni = node.sni.clone().or(Some(node.host.clone()));
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
    let auth_b = node.params.get("auth").cloned().unwrap_or_default().into_bytes();
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
    let uuid = node
        .uuid
        .as_deref()
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(Uuid::nil);
    let pwd = node.password.clone().unwrap_or_default();
    let mut ob = TuicOutbound::new(&node.name, &node.host, node.port, uuid, pwd);
    if let Some(s) = node.sni.clone() {
        ob.sni = Some(s);
    }
    ob.insecure = node
        .params
        .get("insecure")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    Arc::new(ob)
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
    if let Some(c) = node.params.get("cipher").and_then(|s| MieruCipher::parse(s)) {
        ob.cipher = c;
    }
    Arc::new(ob)
}

fn decode_b64_32(s: &str) -> Option<[u8; 32]> {
    use base64::Engine;
    let v = base64::engine::general_purpose::STANDARD.decode(s.trim()).ok()?;
    if v.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Some(out)
}

fn proto_static_name(p: &NodeProtocol) -> &'static str {
    match p {
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
