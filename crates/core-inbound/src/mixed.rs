//! Mixed 入站 —— 通过首字节判定 HTTP 还是 SOCKS5。
//!
//! * 首字节 0x05：进入 SOCKS5 协议握手；
//! * 否则按 HTTP 解析；支持 CONNECT 与普通代理（GET/POST 等）。
//!
//! 每个连接：
//! 1. 解析目标 host/port；
//! 2. 调用 [`Runtime::dial`] 建立到代理出口的流；
//! 3. 双向 splice 转发字节。

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine;
use core_observe::{copy_bidirectional_counted, ConnectionMeta};
use core_route::NetworkKind;
use core_runtime::Runtime;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct MixedListener {
    pub listen: SocketAddr,
    pub auth: Option<Vec<core_config::runtime_plan::UserPass>>,
}

pub async fn run_mixed(listener: MixedListener, runtime: Arc<Runtime>) -> io::Result<()> {
    let report = crate::privilege::PrivilegeReport::detect();
    let l = crate::listener::bind_with_fallback(listener.listen, &report, None).await?;
    let bound = l.local_addr()?;
    if bound != listener.listen {
        info!(want = %listener.listen, got = %bound, "mixed inbound bound to fallback");
    } else {
        info!(addr = %bound, "mixed inbound listening");
    }
    let auth = listener.auth.map(Arc::new);
    loop {
        let (sock, peer) = l.accept().await?;
        let _ = sock.set_nodelay(true);
        let runtime = runtime.clone();
        let auth = auth.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(sock, peer, runtime, auth).await {
                debug!(error = %e, peer = %peer, "mixed handle error");
            }
        });
    }
}

async fn handle(
    sock: TcpStream,
    peer: SocketAddr,
    runtime: Arc<Runtime>,
    auth: Option<Arc<Vec<core_config::runtime_plan::UserPass>>>,
) -> io::Result<()> {
    let mut peek = [0u8; 1];
    let n = sock.peek(&mut peek).await?;
    if n == 0 {
        return Ok(());
    }
    if peek[0] == 0x05 {
        handle_socks5(sock, peer, runtime, auth.as_deref().map(|v| v.as_slice())).await
    } else {
        handle_http(sock, peer, runtime, auth.as_deref().map(|v| v.as_slice())).await
    }
}

/* ---------------- SOCKS5 ---------------- */

async fn handle_socks5(
    mut sock: TcpStream,
    peer: SocketAddr,
    runtime: Arc<Runtime>,
    auth: Option<&[core_config::runtime_plan::UserPass]>,
) -> io::Result<()> {
    // VER + NMETHODS
    let mut head = [0u8; 2];
    sock.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(other("非 socks5"));
    }
    let mut methods = vec![0u8; head[1] as usize];
    sock.read_exact(&mut methods).await?;

    let need_auth = auth.map(|v| !v.is_empty()).unwrap_or(false);
    let chosen = if need_auth {
        if methods.contains(&0x02) {
            0x02
        } else {
            sock.write_all(&[0x05, 0xff]).await?;
            return Err(other("client 不支持 USER_PASS"));
        }
    } else if methods.contains(&0x00) {
        0x00
    } else {
        sock.write_all(&[0x05, 0xff]).await?;
        return Err(other("client 不支持 NO_AUTH"));
    };
    sock.write_all(&[0x05, chosen]).await?;

    if chosen == 0x02 {
        let mut ver = [0u8; 2];
        sock.read_exact(&mut ver).await?;
        let mut user = vec![0u8; ver[1] as usize];
        sock.read_exact(&mut user).await?;
        let mut plen = [0u8; 1];
        sock.read_exact(&mut plen).await?;
        let mut pwd = vec![0u8; plen[0] as usize];
        sock.read_exact(&mut pwd).await?;
        let user = String::from_utf8_lossy(&user).into_owned();
        let pwd = String::from_utf8_lossy(&pwd).into_owned();
        let ok = auth
            .map(|v| v.iter().any(|u| u.user == user && u.pass == pwd))
            .unwrap_or(false);
        if !ok {
            sock.write_all(&[0x01, 0x01]).await?;
            return Err(other("socks5 auth failed"));
        }
        sock.write_all(&[0x01, 0x00]).await?;
    }

    // request
    let mut h = [0u8; 4];
    sock.read_exact(&mut h).await?;
    if h[1] != 0x01 {
        // 仅支持 CONNECT；其它（BIND/UDP）回 0x07。
        let _ = sock.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
        return Err(other("socks5 仅支持 CONNECT"));
    }
    let host: String = match h[3] {
        0x01 => {
            let mut buf = [0u8; 4];
            sock.read_exact(&mut buf).await?;
            std::net::Ipv4Addr::from(buf).to_string()
        }
        0x04 => {
            let mut buf = [0u8; 16];
            sock.read_exact(&mut buf).await?;
            std::net::Ipv6Addr::from(buf).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize];
            sock.read_exact(&mut buf).await?;
            String::from_utf8_lossy(&buf).into_owned()
        }
        _ => return Err(other("不支持的地址类型")),
    };
    let mut port_buf = [0u8; 2];
    sock.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    match runtime.dial(&host, port, NetworkKind::Tcp).await {
        Ok(res) => {
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            relay(sock, res, &host, port, "socks5", "Socks5", peer, &runtime).await
        }
        Err(e) => {
            sock.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            Err(e)
        }
    }
}

/* ---------------- HTTP ---------------- */

async fn handle_http(
    sock: TcpStream,
    peer: SocketAddr,
    runtime: Arc<Runtime>,
    auth: Option<&[core_config::runtime_plan::UserPass]>,
) -> io::Result<()> {
    let mut reader = BufReader::new(sock);
    let mut head = Vec::with_capacity(2048);
    // 读到 \r\n\r\n
    loop {
        let mut byte = [0u8; 1];
        if reader.read(&mut byte).await? == 0 {
            return Ok(());
        }
        head.push(byte[0]);
        if head.len() >= 4 && &head[head.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if head.len() > 16 * 1024 {
            return Err(other("HTTP 请求头过大"));
        }
    }

    let head_str = std::str::from_utf8(&head).map_err(|_| other("HTTP 请求头非 utf8"))?;
    let mut lines = head_str.split("\r\n");
    let req_line = lines.next().ok_or_else(|| other("空请求行"))?;
    let mut parts = req_line.split_whitespace();
    let method = parts.next().ok_or_else(|| other("缺少 method"))?.to_uppercase();
    let target = parts.next().ok_or_else(|| other("缺少 target"))?.to_string();
    let _version = parts.next().unwrap_or("HTTP/1.1");

    // 鉴权
    if let Some(slot) = auth {
        if !slot.is_empty() {
            let mut authed = false;
            for line in lines.clone() {
                if let Some((k, v)) = line.split_once(':') {
                    if k.trim().eq_ignore_ascii_case("Proxy-Authorization") {
                        let v = v.trim();
                        if let Some(rest) = v.strip_prefix("Basic ") {
                            if let Ok(decoded) =
                                base64::engine::general_purpose::STANDARD.decode(rest)
                            {
                                if let Ok(s) = std::str::from_utf8(&decoded) {
                                    if let Some((u, p)) = s.split_once(':') {
                                        authed =
                                            slot.iter().any(|x| x.user == u && x.pass == p);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if !authed {
                let mut sock = reader.into_inner();
                let body = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                let _ = sock.write_all(body).await;
                return Err(other("HTTP 407 unauthorized"));
            }
        }
    }

    if method == "CONNECT" {
        let (host, port) = parse_host_port(&target)?;
        let res = runtime.dial(&host, port, NetworkKind::Tcp).await;
        let mut sock = reader.into_inner();
        match res {
            Ok(r) => {
                sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
                relay(sock, r, &host, port, "http-connect", "HTTP", peer, &runtime).await
            }
            Err(e) => {
                let _ = sock
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                    .await;
                Err(e)
            }
        }
    } else {
        // 普通代理：target 可能是 http://host[:port]/path
        let (host, port, path) = parse_absolute_target(&target)?;
        // 重组请求：把 absolute-form 改成 origin-form。
        let mut new_head = format!("{method} {path} HTTP/1.1\r\n");
        let mut have_host = false;
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("proxy-authorization:") {
                continue;
            }
            if lower.starts_with("proxy-connection:") {
                continue;
            }
            if lower.starts_with("host:") {
                have_host = true;
            }
            new_head.push_str(line);
            new_head.push_str("\r\n");
        }
        if !have_host {
            new_head.push_str(&format!("Host: {host}\r\n"));
        }
        new_head.push_str("\r\n");

        let res = runtime.dial(&host, port, NetworkKind::Tcp).await;
        let mut sock = reader.into_inner();
        match res {
            Ok(mut r) => {
                r.stream.write_all(new_head.as_bytes()).await?;
                relay(sock, r, &host, port, "http", "HTTP", peer, &runtime).await
            }
            Err(e) => {
                let _ = sock
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                    .await;
                Err(e)
            }
        }
    }
}

fn parse_host_port(s: &str) -> io::Result<(String, u16)> {
    if let Some((h, p)) = s.rsplit_once(':') {
        let h = h.trim_matches(|c| c == '[' || c == ']');
        let port: u16 = p.parse().map_err(|_| other("端口非法"))?;
        Ok((h.to_string(), port))
    } else {
        Err(other("缺少端口"))
    }
}

fn parse_absolute_target(s: &str) -> io::Result<(String, u16, String)> {
    let s = s.trim_start_matches("http://").trim_start_matches("https://");
    let (host_part, path) = match s.find('/') {
        Some(i) => (&s[..i], s[i..].to_string()),
        None => (s, "/".to_string()),
    };
    let (host, port) = if host_part.contains(':') {
        let (h, p) = host_part.rsplit_once(':').unwrap();
        (h.to_string(), p.parse().map_err(|_| other("端口非法"))?)
    } else {
        (host_part.to_string(), 80u16)
    };
    Ok((host, port, path))
}

fn other(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, s.to_string())
}

async fn relay(
    mut inbound: TcpStream,
    mut out: core_runtime::engine::DialResult,
    host: &str,
    port: u16,
    inbound_label: &'static str,
    metadata_kind: &'static str,
    peer: SocketAddr,
    runtime: &Arc<Runtime>,
) -> io::Result<()> {
    let started = std::time::Instant::now();
    runtime.metrics.inc_connection();

    // 构造 mihomo Metadata 兼容信息：source = 浏览器 / curl 端 socket；
    // destination = 解析后的目标 host:port；inbound = 监听器名 + 类型 + ip:port。
    let inbound_addr = inbound.local_addr().ok();
    let meta = ConnectionMeta {
        network: "tcp".into(),
        kind: metadata_kind.into(),
        source_ip: peer.ip().to_string(),
        source_port: peer.port().to_string(),
        destination_ip: host.parse::<std::net::IpAddr>().map(|ip| ip.to_string()).unwrap_or_default(),
        destination_port: port.to_string(),
        inbound_ip: inbound_addr.map(|a| a.ip().to_string()).unwrap_or_default(),
        inbound_port: inbound_addr.map(|a| a.port().to_string()).unwrap_or_default(),
        inbound_name: inbound_label.into(),
        host: host.to_string(),
        dns_mode: "normal".into(),
        chains: out.chain.clone(),
        rule: format!("{:?}", out.decision),
        ..ConnectionMeta::default()
    };
    let guard = runtime.connections.open(meta);
    let id = guard.id;
    let (up_counter, down_counter) = guard.counters();
    let cancel = guard.cancel_token();
    tracing::info!(
        target: "relay",
        conn_id = id,
        inbound = inbound_label,
        host, port,
        outbound = %out.outbound,
        decision = ?out.decision,
        dial_ms = out.elapsed.as_millis() as u64,
        "session begin",
    );

    let metrics = runtime.metrics.clone();
    let result = copy_bidirectional_counted(
        &mut inbound,
        &mut out.stream,
        up_counter.clone(),
        down_counter.clone(),
        cancel,
        Some(metrics.clone()),
    )
    .await;
    metrics.dec_connection();
    // guard drop 时自动从 ConnectionTable 移除；无需显式 close

    let up = up_counter.load(std::sync::atomic::Ordering::Relaxed);
    let down = down_counter.load(std::sync::atomic::Ordering::Relaxed);
    let total_ms = started.elapsed().as_millis() as u64;
    match &result {
        Ok(_) => tracing::info!(
            target: "relay",
            conn_id = id,
            inbound = inbound_label,
            host, port,
            outbound = %out.outbound,
            bytes_up = up,
            bytes_down = down,
            duration_ms = total_ms,
            "session end (ok)",
        ),
        Err(e) => tracing::warn!(
            target: "relay",
            conn_id = id,
            inbound = inbound_label,
            host, port,
            outbound = %out.outbound,
            bytes_up = up,
            bytes_down = down,
            duration_ms = total_ms,
            error = %e,
            "session end (error)",
        ),
    }
    result.map(|_| ())
}
