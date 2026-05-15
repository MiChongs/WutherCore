//! HTTP mask (legacy 模式) —— 在 sudoku 流量前注入伪装的 HTTP 头。
//!
//! 与 mihomo `transport/sudoku/obfs/httpmask/masker.go` 等价。
//! 仅实现客户端 write 方向的 legacy mode（最常用且与 CDN 不兼容但不用握手）。

use rand::{Rng, seq::SliceRandom};

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
];

const ACCEPTS: &[&str] = &[
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "application/json, text/plain, */*",
    "application/octet-stream",
    "*/*",
];

const ACCEPT_LANGS: &[&str] = &[
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
    "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
];

const ACCEPT_ENCODINGS: &[&str] = &["gzip, deflate, br", "gzip, deflate", "br, gzip, deflate"];

const PATHS: &[&str] = &[
    "/api/v1/upload",
    "/data/sync",
    "/uploads/raw",
    "/api/report",
    "/feed/update",
    "/v2/events",
    "/v1/telemetry",
    "/session",
    "/stream",
    "/ws",
];

const CONTENT_TYPES: &[&str] = &[
    "application/octet-stream",
    "application/x-protobuf",
    "application/json",
];

fn join_path_root(path_root: &str, p: &str) -> String {
    let trimmed = path_root.trim().trim_matches('/');
    if trimmed.is_empty() {
        return p.to_string();
    }
    format!("/{}{}", trimmed, p)
}

/// 构造一段 HTTP/1.1 伪装请求头部，与 mihomo WriteRandomRequestHeaderWithPathRoot 等价。
pub fn build_random_request_header(host: &str, path_root: &str) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let path = join_path_root(path_root, PATHS.choose(&mut rng).unwrap());
    let ctype = CONTENT_TYPES.choose(&mut rng).unwrap();
    let mut buf = Vec::with_capacity(1024);

    // 20% 概率 WebSocket 升级伪装
    let pick = rng.gen_range(0..10);
    let host_no_port = strip_port(host);
    if pick < 2 {
        let mut ws_key_bytes = [0u8; 16];
        for b in ws_key_bytes.iter_mut() {
            *b = rng.r#gen();
        }
        let ws_key = base64_std(&ws_key_bytes);
        buf.extend_from_slice(b"GET ");
        buf.extend_from_slice(path.as_bytes());
        buf.extend_from_slice(b" HTTP/1.1\r\n");
        append_common_headers(&mut buf, host, &mut rng);
        buf.extend_from_slice(b"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ");
        buf.extend_from_slice(ws_key.as_bytes());
        buf.extend_from_slice(b"\r\nOrigin: https://");
        buf.extend_from_slice(host_no_port.as_bytes());
        buf.extend_from_slice(b"\r\n\r\n");
    } else {
        let min_cl: i64 = 4 * 1024;
        let max_cl: i64 = 10 * 1024 * 1024;
        let cl: i64 = rng.gen_range(min_cl..=max_cl);
        buf.extend_from_slice(b"POST ");
        buf.extend_from_slice(path.as_bytes());
        buf.extend_from_slice(b" HTTP/1.1\r\n");
        append_common_headers(&mut buf, host, &mut rng);
        buf.extend_from_slice(b"Content-Type: ");
        buf.extend_from_slice(ctype.as_bytes());
        buf.extend_from_slice(b"\r\nContent-Length: ");
        buf.extend_from_slice(cl.to_string().as_bytes());
        if rng.gen_range(0..2) == 0 {
            buf.extend_from_slice(b"\r\nX-Requested-With: XMLHttpRequest");
        }
        if rng.gen_range(0..3) == 0 {
            buf.extend_from_slice(b"\r\nReferer: https://");
            buf.extend_from_slice(host_no_port.as_bytes());
            buf.extend_from_slice(b"/");
        }
        buf.extend_from_slice(b"\r\n\r\n");
    }
    buf
}

fn append_common_headers(buf: &mut Vec<u8>, host: &str, rng: &mut impl Rng) {
    let ua = USER_AGENTS.choose(rng).unwrap();
    let accept = ACCEPTS.choose(rng).unwrap();
    let lang = ACCEPT_LANGS.choose(rng).unwrap();
    let enc = ACCEPT_ENCODINGS.choose(rng).unwrap();

    buf.extend_from_slice(b"Host: ");
    buf.extend_from_slice(host.as_bytes());
    buf.extend_from_slice(b"\r\nUser-Agent: ");
    buf.extend_from_slice(ua.as_bytes());
    buf.extend_from_slice(b"\r\nAccept: ");
    buf.extend_from_slice(accept.as_bytes());
    buf.extend_from_slice(b"\r\nAccept-Language: ");
    buf.extend_from_slice(lang.as_bytes());
    buf.extend_from_slice(b"\r\nAccept-Encoding: ");
    buf.extend_from_slice(enc.as_bytes());
    buf.extend_from_slice(
        b"\r\nConnection: keep-alive\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n",
    );
}

fn strip_port(host: &str) -> String {
    if let Some(idx) = host.rfind(':') {
        // 忽略 IPv6 [::1]:80 形式
        if !host.starts_with('[') {
            return host[..idx].to_string();
        }
        if let Some(end) = host.find(']') {
            return host[..=end].to_string();
        }
    }
    host.to_string()
}

fn base64_std(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_starts_with_method() {
        let h = build_random_request_header("example.com", "");
        let s = String::from_utf8_lossy(&h);
        assert!(s.starts_with("GET ") || s.starts_with("POST "));
        assert!(s.contains("Host: example.com"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn path_root_prefix() {
        let h = build_random_request_header("example.com", "aabbcc");
        let s = String::from_utf8_lossy(&h);
        assert!(s.contains("/aabbcc/"));
    }

    #[test]
    fn strip_port_works() {
        assert_eq!(strip_port("example.com:443"), "example.com");
        assert_eq!(strip_port("1.2.3.4:80"), "1.2.3.4");
        assert_eq!(strip_port("noport.com"), "noport.com");
    }
}
