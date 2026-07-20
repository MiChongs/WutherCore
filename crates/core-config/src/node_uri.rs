//! 节点 URI 解析 —— §5.4 / §5.5。
//!
//! 把 `ss://`, `vless://`, `vmess://`, `trojan://`, `hysteria2://`,
//! `tuic://`, `wireguard://`, `ssh://`, `http://`, `socks5://` 解析成
//! 结构化 [`ParsedNode`]。MVP 阶段不需要把所有协议字段全部建模，只要满足
//! 后续 outbound 组装即可。

use base64::Engine;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{ConfigError, ConfigResult};

/// 出站类型枚举（与 `core-outbound::OutboundKind` 对齐）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NodeProtocol {
    Direct,
    Block,
    Http,
    Socks5,
    Shadowsocks,
    ShadowsocksR,
    Vmess,
    Vless,
    Trojan,
    Hysteria,
    Hysteria2,
    Tuic,
    Wireguard,
    Ssh,
    Snell,
    AnyTls,
    Mieru,
    Sudoku,
    TrustTunnel,
    /// DNS hijack outbound (mihomo `type: dns`)：把 port-53 流量在本地直接
    /// 用 resolver 应答，不连远端。常配合 `RULE-SET / DST-PORT 53 → DNS_Hijack`
    /// 把 LAN 客户端的 DNS 截到本机解析。
    Dns,
    Other(String),
}

impl NodeProtocol {
    pub fn from_scheme(scheme: &str) -> Self {
        match scheme.to_ascii_lowercase().as_str() {
            "direct" => Self::Direct,
            "block" => Self::Block,
            "http" | "https" => Self::Http,
            "socks5" | "socks" => Self::Socks5,
            "ss" => Self::Shadowsocks,
            "ssr" => Self::ShadowsocksR,
            "vmess" => Self::Vmess,
            "vless" => Self::Vless,
            "trojan" => Self::Trojan,
            "hysteria" => Self::Hysteria,
            "hysteria2" | "hy2" => Self::Hysteria2,
            "tuic" => Self::Tuic,
            "wireguard" | "wg" => Self::Wireguard,
            "ssh" => Self::Ssh,
            "snell" => Self::Snell,
            "anytls" => Self::AnyTls,
            "mieru" => Self::Mieru,
            "sudoku" => Self::Sudoku,
            "trusttunnel" => Self::TrustTunnel,
            "dns" => Self::Dns,
            other => Self::Other(other.into()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Direct => "direct",
            Self::Block => "block",
            Self::Http => "http",
            Self::Socks5 => "socks5",
            Self::Shadowsocks => "ss",
            Self::ShadowsocksR => "ssr",
            Self::Vmess => "vmess",
            Self::Vless => "vless",
            Self::Trojan => "trojan",
            Self::Hysteria => "hysteria",
            Self::Hysteria2 => "hysteria2",
            Self::Tuic => "tuic",
            Self::Wireguard => "wireguard",
            Self::Ssh => "ssh",
            Self::Snell => "snell",
            Self::AnyTls => "anytls",
            Self::Mieru => "mieru",
            Self::Sudoku => "sudoku",
            Self::TrustTunnel => "trusttunnel",
            Self::Dns => "dns",
            Self::Other(s) => s.as_str(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedNode {
    pub name: String,
    pub protocol: NodeProtocol,
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
    pub uuid: Option<String>,
    pub method: Option<String>,
    pub tls: bool,
    pub sni: Option<String>,
    pub transport: String,
    pub udp: bool,
    /// 原始 URI，便于调试与 explain。
    pub raw: String,
    /// 协议自定义参数（query / json 字段）。
    pub params: std::collections::BTreeMap<String, String>,
}

impl ParsedNode {
    pub fn new(
        name: impl Into<String>,
        protocol: NodeProtocol,
        host: impl Into<String>,
        port: u16,
    ) -> Self {
        Self {
            name: name.into(),
            protocol,
            host: host.into(),
            port,
            user: None,
            password: None,
            uuid: None,
            method: None,
            tls: false,
            sni: None,
            transport: "tcp".into(),
            udp: true,
            raw: String::new(),
            params: Default::default(),
        }
    }
}

/// 解析任意 URI 形式的节点。
pub fn parse_uri(uri: &str) -> ConfigResult<ParsedNode> {
    let uri = uri.trim();
    if uri.is_empty() {
        return Err(ConfigError::bad_node("空 URI"));
    }
    let scheme_end = uri
        .find("://")
        .ok_or_else(|| ConfigError::bad_node(format!("URI 缺少 scheme://: {uri}")))?;
    let scheme = uri[..scheme_end].to_ascii_lowercase();
    let proto = NodeProtocol::from_scheme(&scheme);

    let parsed = match proto {
        NodeProtocol::Shadowsocks => parse_ss(uri)?,
        NodeProtocol::Vmess => parse_vmess(uri)?,
        NodeProtocol::Vless
        | NodeProtocol::Trojan
        | NodeProtocol::Hysteria2
        | NodeProtocol::Tuic
        | NodeProtocol::Hysteria => parse_url_like(uri, proto)?,
        NodeProtocol::Http | NodeProtocol::Socks5 => parse_http_socks(uri, proto)?,
        NodeProtocol::Ssh => parse_url_like(uri, NodeProtocol::Ssh)?,
        NodeProtocol::Wireguard => parse_url_like(uri, NodeProtocol::Wireguard)?,
        NodeProtocol::Dns => parse_dns_hijack(uri)?,
        _ => parse_url_like(uri, proto)?,
    };
    Ok(parsed)
}

/// `dns://...` —— DNS hijack 出站。host/port 仅占位（实际不连），
/// fragment 是节点名，缺省时取 `DNS`。
fn parse_dns_hijack(uri: &str) -> ConfigResult<ParsedNode> {
    // dns:// 后面允许空，name 从 fragment 取，缺省为 "DNS"。
    let (rest, fragment) = uri[6..].split_once('#').unwrap_or((&uri[6..], ""));
    let name = if fragment.is_empty() {
        "DNS".to_string()
    } else {
        pct_decode(fragment)
    };
    let _ = rest; // 忽略 host/port —— 不需要实际目标
    let mut node = ParsedNode::new(name, NodeProtocol::Dns, "0.0.0.0", 0);
    node.raw = uri.to_string();
    node.udp = true;
    Ok(node)
}

fn pct_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

fn fragment_name(url: &Url, fallback: &str) -> String {
    url.fragment()
        .map(pct_decode)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

fn collect_params(url: &Url) -> std::collections::BTreeMap<String, String> {
    url.query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn require_host_port(url: &Url) -> ConfigResult<(String, u16)> {
    let host = url
        .host_str()
        .ok_or_else(|| ConfigError::bad_node(format!("URI 缺少主机: {url}")))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| ConfigError::bad_node(format!("URI 缺少端口: {url}")))?;
    Ok((host.to_string(), port))
}

fn parse_url_like(uri: &str, proto: NodeProtocol) -> ConfigResult<ParsedNode> {
    let url = Url::parse(uri).map_err(|e| ConfigError::bad_node(format!("非法 URI: {e}")))?;
    let (host, port) = require_host_port(&url)?;
    let name = fragment_name(&url, &format!("{}-{}", proto.as_str(), host));
    let params = collect_params(&url);

    let mut node = ParsedNode::new(name, proto.clone(), host, port);
    node.raw = uri.to_string();
    node.tls = matches!(
        proto,
        NodeProtocol::Trojan | NodeProtocol::Hysteria2 | NodeProtocol::Tuic
    ) || params
        .get("security")
        .map(|s| matches!(s.as_str(), "tls" | "reality"))
        .unwrap_or(false);
    node.sni = params
        .get("sni")
        .cloned()
        .or_else(|| params.get("peer").cloned());
    node.transport = params.get("type").cloned().unwrap_or_else(|| "tcp".into());
    let user = url.username();
    if !user.is_empty() {
        let decoded = pct_decode(user);
        match proto {
            NodeProtocol::Trojan | NodeProtocol::Hysteria2 => {
                node.password = Some(decoded);
            }
            NodeProtocol::Tuic => {
                // TUIC v5 share links use `tuic://uuid:password@host:port`.
                // Treating the username as the password silently produced a nil UUID
                // and a non-interoperable authentication token.
                node.uuid = Some(decoded);
                node.password = url.password().map(pct_decode);
            }
            NodeProtocol::Vless | NodeProtocol::Vmess | NodeProtocol::Wireguard => {
                node.uuid = Some(decoded);
            }
            _ => {
                node.user = Some(decoded);
                if let Some(pw) = url.password() {
                    node.password = Some(pct_decode(pw));
                }
            }
        }
    }
    node.params = params;
    Ok(node)
}

fn parse_http_socks(uri: &str, proto: NodeProtocol) -> ConfigResult<ParsedNode> {
    let url = Url::parse(uri).map_err(|e| ConfigError::bad_node(format!("非法 URI: {e}")))?;
    let (host, port) = require_host_port(&url)?;
    let name = fragment_name(&url, &format!("{}-{}", proto.as_str(), host));
    let mut node = ParsedNode::new(name, proto, host, port);
    node.raw = uri.to_string();
    if !url.username().is_empty() {
        node.user = Some(pct_decode(url.username()));
    }
    if let Some(pw) = url.password() {
        node.password = Some(pct_decode(pw));
    }
    node.params = collect_params(&url);
    Ok(node)
}

/// 解析 `ss://` —— 兼容 `ss://base64(method:password)@host:port#name`
/// 与 `ss://method:password@host:port` 两种写法。
fn parse_ss(uri: &str) -> ConfigResult<ParsedNode> {
    // 兼容 SIP002（首段为 base64-userinfo）与遗留 base64 整段编码。
    let (body, fragment) = match uri.find('#') {
        Some(idx) => (&uri[..idx], Some(&uri[idx + 1..])),
        None => (uri, None),
    };
    let body = body.trim_start_matches("ss://");

    // 尝试 SIP002：userinfo@host:port[/?plugin]
    if let Some(at_idx) = body.rfind('@') {
        let (userinfo, hostpart) = body.split_at(at_idx);
        let hostpart = &hostpart[1..]; // 跳过 '@'
        let userinfo = decode_base64_loose(userinfo).unwrap_or_else(|| userinfo.to_string());
        let (method, password) = userinfo.split_once(':').ok_or_else(|| {
            ConfigError::bad_node(format!("ss userinfo 缺少 method:password: {uri}"))
        })?;

        let (host_port, query) = match hostpart.find('?') {
            Some(idx) => (&hostpart[..idx], Some(&hostpart[idx + 1..])),
            None => (hostpart, None),
        };
        let host_port = host_port.trim_start_matches('/');
        let (host, port) = split_host_port(host_port)?;
        let name = fragment
            .map(pct_decode)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("ss-{host}"));

        let mut node = ParsedNode::new(name, NodeProtocol::Shadowsocks, host, port);
        node.method = Some(method.to_string());
        node.password = Some(password.to_string());
        node.raw = uri.to_string();
        if let Some(q) = query {
            node.params = q
                .split('&')
                .filter_map(|kv| kv.split_once('='))
                .map(|(k, v)| (k.to_string(), pct_decode(v)))
                .collect();
        }
        return Ok(node);
    }

    // 整段 base64 编码：ss://base64(method:password@host:port)
    let decoded = decode_base64_loose(body)
        .ok_or_else(|| ConfigError::bad_node(format!("ss URI base64 解码失败: {uri}")))?;
    let at_idx = decoded
        .rfind('@')
        .ok_or_else(|| ConfigError::bad_node(format!("ss URI 缺少 @: {uri}")))?;
    let (userinfo, hostpart) = decoded.split_at(at_idx);
    let hostpart = &hostpart[1..];
    let (method, password) = userinfo
        .split_once(':')
        .ok_or_else(|| ConfigError::bad_node(format!("ss userinfo 缺少 method:password: {uri}")))?;
    let (host, port) = split_host_port(hostpart)?;
    let name = fragment
        .map(pct_decode)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("ss-{host}"));
    let mut node = ParsedNode::new(name, NodeProtocol::Shadowsocks, host, port);
    node.method = Some(method.to_string());
    node.password = Some(password.to_string());
    node.raw = uri.to_string();
    Ok(node)
}

fn parse_vmess(uri: &str) -> ConfigResult<ParsedNode> {
    // vmess://base64(json)
    let body = uri.trim_start_matches("vmess://");
    let decoded = decode_base64_loose(body)
        .ok_or_else(|| ConfigError::bad_node(format!("vmess base64 解码失败: {uri}")))?;
    let v: serde_json::Value = serde_json::from_str(&decoded)
        .map_err(|e| ConfigError::bad_node(format!("vmess JSON 解析失败: {e}")))?;
    let host = v
        .get("add")
        .and_then(|x| x.as_str())
        .ok_or_else(|| ConfigError::bad_node(format!("vmess 缺少 add: {uri}")))?;
    let port = v
        .get("port")
        .and_then(|x| {
            x.as_u64()
                .or_else(|| x.as_str().and_then(|s| s.parse().ok()))
        })
        .ok_or_else(|| ConfigError::bad_node(format!("vmess 缺少 port: {uri}")))?
        as u16;
    let name = v
        .get("ps")
        .and_then(|x| x.as_str())
        .map(String::from)
        .unwrap_or_else(|| format!("vmess-{host}"));
    let uuid = v.get("id").and_then(|x| x.as_str()).map(String::from);
    let mut node = ParsedNode::new(name, NodeProtocol::Vmess, host, port);
    node.uuid = uuid;
    node.tls = v
        .get("tls")
        .and_then(|x| x.as_str())
        .map(|s| s == "tls")
        .unwrap_or(false);
    node.transport = v
        .get("net")
        .and_then(|x| x.as_str())
        .unwrap_or("tcp")
        .to_string();
    node.raw = uri.to_string();
    if let Some(obj) = v.as_object() {
        for (k, val) in obj {
            if let Some(s) = val.as_str() {
                node.params.insert(k.clone(), s.to_string());
            } else {
                node.params.insert(k.clone(), val.to_string());
            }
        }
    }
    Ok(node)
}

fn split_host_port(s: &str) -> ConfigResult<(String, u16)> {
    if let Some(idx) = s.rfind(':') {
        let host = &s[..idx];
        let port: u16 = s[idx + 1..]
            .parse()
            .map_err(|_| ConfigError::bad_node(format!("端口非法: {s}")))?;
        let host = host.trim_matches(|c| c == '[' || c == ']');
        Ok((host.to_string(), port))
    } else {
        Err(ConfigError::bad_node(format!("缺少端口: {s}")))
    }
}

fn decode_base64_loose(s: &str) -> Option<String> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .ok()
        .or_else(|| STANDARD.decode(s).ok())
        .and_then(|b| String::from_utf8(b).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ss_sip002() {
        let n = parse_uri("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK").unwrap();
        assert_eq!(n.protocol, NodeProtocol::Shadowsocks);
        assert_eq!(n.host, "1.2.3.4");
        assert_eq!(n.port, 8388);
        assert_eq!(n.method.as_deref(), Some("aes-256-gcm"));
        assert_eq!(n.password.as_deref(), Some("password"));
        assert_eq!(n.name, "HK");
    }

    #[test]
    fn parse_vless() {
        let n = parse_uri("vless://uuid-here@1.1.1.1:443?security=tls&type=ws#JP").unwrap();
        assert_eq!(n.protocol, NodeProtocol::Vless);
        assert_eq!(n.uuid.as_deref(), Some("uuid-here"));
        assert_eq!(n.host, "1.1.1.1");
        assert_eq!(n.port, 443);
        assert!(n.tls);
        assert_eq!(n.transport, "ws");
    }

    #[test]
    fn parse_trojan() {
        let n = parse_uri("trojan://pwd@example.com:443?sni=example.com#US-1").unwrap();
        assert_eq!(n.protocol, NodeProtocol::Trojan);
        assert_eq!(n.password.as_deref(), Some("pwd"));
        assert_eq!(n.sni.as_deref(), Some("example.com"));
        assert!(n.tls);
    }

    #[test]
    fn parse_tuic_v5_credentials_and_options() {
        let n = parse_uri(
            "tuic://2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365:p%40ss@example.com:443?udp_relay_mode=quic&heartbeat=10s&allow_insecure=1#TUIC",
        )
        .unwrap();
        assert_eq!(n.protocol, NodeProtocol::Tuic);
        assert_eq!(
            n.uuid.as_deref(),
            Some("2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365")
        );
        assert_eq!(n.password.as_deref(), Some("p@ss"));
        assert_eq!(
            n.params.get("udp_relay_mode").map(String::as_str),
            Some("quic")
        );
        assert_eq!(n.params.get("heartbeat").map(String::as_str), Some("10s"));
        assert_eq!(
            n.params.get("allow_insecure").map(String::as_str),
            Some("1")
        );
        assert!(n.tls);
    }

    #[test]
    fn parse_http_socks() {
        let n = parse_uri("http://user:pass@1.1.1.1:8080#HTTP1").unwrap();
        assert_eq!(n.protocol, NodeProtocol::Http);
        assert_eq!(n.user.as_deref(), Some("user"));
        assert_eq!(n.password.as_deref(), Some("pass"));
    }
}
