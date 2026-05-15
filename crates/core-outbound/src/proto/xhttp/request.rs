//! XHTTP 请求构造 —— 应用 placement / x-padding / meta 到 hyper Request。
//!
//! 与 mihomo `transport/xhttp/config.go` 中的 `FillStreamRequest` /
//! `FillPacketRequest` / `FillDownloadRequest` / `ApplyMetaToRequest` /
//! `ApplyXPaddingToRequest` 等价。

use base64::Engine;
use http::{HeaderName, HeaderValue, Request as HttpRequest};

use super::{
    config::{
        Config, PLACEMENT_AUTO, PLACEMENT_BODY, PLACEMENT_COOKIE, PLACEMENT_HEADER, PLACEMENT_PATH,
        PLACEMENT_QUERY, PLACEMENT_QUERY_IN_HEADER, Range,
    },
    xpadding::{PaddingMethod, XPaddingConfig, XPaddingPlacement, generate_padding},
};

pub struct PreparedRequest {
    pub method: String,
    pub url: String,
    pub host: String,
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub content_length: Option<u64>,
}

impl PreparedRequest {
    pub fn into_http_request(self, body_unit: ()) -> Result<HttpRequest<()>, String> {
        let mut url = url::Url::parse(&self.url).map_err(|e| format!("url parse: {e}"))?;
        if !self.cookies.is_empty() {
            // cookie 拼接到 Cookie 头
        }
        // 重新构造完整 URL（含 query）
        let full_url = url.as_str().to_string();
        let mut req = HttpRequest::builder()
            .method(self.method.as_str())
            .uri(full_url.as_str())
            .body(body_unit)
            .map_err(|e| format!("request build: {e}"))?;
        // host 头
        let host_val =
            HeaderValue::from_str(&self.host).map_err(|e| format!("host header: {e}"))?;
        req.headers_mut()
            .insert(HeaderName::from_static("host"), host_val);
        // 普通 headers
        for (k, v) in &self.headers {
            let name = HeaderName::try_from(k.as_str()).map_err(|e| format!("hdr name: {e}"))?;
            let val = HeaderValue::from_str(v).map_err(|e| format!("hdr val: {e}"))?;
            req.headers_mut().insert(name, val);
        }
        // cookies → 单个 Cookie 头
        if !self.cookies.is_empty() {
            let joined = self
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            if let Ok(val) = HeaderValue::from_str(&joined) {
                req.headers_mut()
                    .insert(HeaderName::from_static("cookie"), val);
            }
        }
        let _ = url; // url 已被消费
        Ok(req)
    }
}

impl PreparedRequest {
    pub fn new(method: &str, url: &str, host: &str) -> Self {
        Self {
            method: method.into(),
            url: url.into(),
            host: host.into(),
            headers: Vec::new(),
            cookies: Vec::new(),
            body: None,
            content_length: None,
        }
    }

    pub fn add_header(&mut self, key: &str, value: &str) {
        self.headers.push((key.into(), value.into()));
    }

    pub fn add_cookie(&mut self, key: &str, value: &str) {
        self.cookies.push((key.into(), value.into()));
    }

    pub fn set_query(&mut self, key: &str, value: &str) {
        // 简单 query merge
        let mut url = match url::Url::parse(&self.url) {
            Ok(u) => u,
            Err(_) => return,
        };
        url.query_pairs_mut().append_pair(key, value);
        self.url = url.to_string();
    }

    pub fn append_path(&mut self, segment: &str) {
        let mut url = match url::Url::parse(&self.url) {
            Ok(u) => u,
            Err(_) => return,
        };
        let mut path = url.path().to_string();
        if path.ends_with('/') {
            path.push_str(segment);
        } else {
            path.push('/');
            path.push_str(segment);
        }
        url.set_path(&path);
        self.url = url.to_string();
    }
}

/// 应用 session_id / seq 到 request（path/query/header/cookie）
pub fn apply_meta(cfg: &Config, req: &mut PreparedRequest, session_id: &str, seq_str: &str) {
    let s_place = cfg.normalized_session_placement().to_string();
    let q_place = cfg.normalized_seq_placement().to_string();
    let s_key = cfg.normalized_session_key().to_string();
    let q_key = cfg.normalized_seq_key().to_string();

    if !session_id.is_empty() {
        match s_place.as_str() {
            PLACEMENT_PATH => req.append_path(session_id),
            PLACEMENT_QUERY => req.set_query(&s_key, session_id),
            PLACEMENT_HEADER => req.add_header(&s_key, session_id),
            PLACEMENT_COOKIE => req.add_cookie(&s_key, session_id),
            _ => {}
        }
    }
    if !seq_str.is_empty() {
        match q_place.as_str() {
            PLACEMENT_PATH => req.append_path(seq_str),
            PLACEMENT_QUERY => req.set_query(&q_key, seq_str),
            PLACEMENT_HEADER => req.add_header(&q_key, seq_str),
            PLACEMENT_COOKIE => req.add_cookie(&q_key, seq_str),
            _ => {}
        }
    }
}

/// 应用 x-padding 到 request
pub fn apply_x_padding(cfg: &Config, req: &mut PreparedRequest) -> Result<(), String> {
    let r = cfg.normalized_x_padding_bytes()?;
    let length = r.rand();
    let pcfg = if cfg.x_padding_obfs_mode {
        XPaddingConfig {
            length,
            placement: XPaddingPlacement {
                placement: cfg.x_padding_placement.clone(),
                key: cfg.x_padding_key.clone(),
                header: cfg.x_padding_header.clone(),
                raw_url: req.url.clone(),
            },
            method: PaddingMethod::parse(&cfg.x_padding_method),
        }
    } else {
        XPaddingConfig {
            length,
            placement: XPaddingPlacement {
                placement: PLACEMENT_QUERY_IN_HEADER.into(),
                key: "x_padding".into(),
                header: "Referer".into(),
                raw_url: req.url.clone(),
            },
            method: PaddingMethod::RepeatX,
        }
    };
    let value = generate_padding(pcfg.method, pcfg.length);
    if value.is_empty() {
        return Ok(());
    }
    match pcfg.placement.placement.as_str() {
        PLACEMENT_HEADER => req.add_header(&pcfg.placement.header, &value),
        PLACEMENT_QUERY_IN_HEADER => {
            // 把 padding 放在某 header 里的 url query
            let mut url =
                url::Url::parse(&pcfg.placement.raw_url).map_err(|e| format!("url: {e}"))?;
            url.set_query(Some(&format!("{}={}", pcfg.placement.key, value)));
            req.add_header(&pcfg.placement.header, url.as_str());
        }
        PLACEMENT_COOKIE => req.add_cookie(&pcfg.placement.key, &value),
        PLACEMENT_QUERY => req.set_query(&pcfg.placement.key, &value),
        _ => {}
    }
    Ok(())
}

/// 应用 user-defined headers + 默认 fetch 头
pub fn apply_default_headers(cfg: &Config, req: &mut PreparedRequest) {
    for (k, v) in &cfg.headers {
        req.add_header(k, v);
    }
    if !req
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
    {
        req.add_header(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        );
    }
    if !req
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("accept"))
    {
        req.add_header("Accept", "*/*");
    }
}

/// 构造 stream-up / stream-one 的 upload request（gRPC content-type）
pub fn fill_stream_request(
    cfg: &Config,
    req: &mut PreparedRequest,
    session_id: &str,
) -> Result<(), String> {
    apply_default_headers(cfg, req);
    apply_x_padding(cfg, req)?;
    apply_meta(cfg, req, session_id, "");
    if !cfg.no_grpc_header {
        req.add_header("Content-Type", "application/grpc");
    }
    Ok(())
}

/// 构造 stream-up 的 download GET request
pub fn fill_download_request(
    cfg: &Config,
    req: &mut PreparedRequest,
    session_id: &str,
) -> Result<(), String> {
    fill_stream_request(cfg, req, session_id)
}

/// 构造 packet-up 的 POST request：把数据放到 body / header / cookie
pub fn fill_packet_request(
    cfg: &Config,
    req: &mut PreparedRequest,
    session_id: &str,
    seq_str: &str,
    data: &[u8],
) -> Result<(), String> {
    apply_default_headers(cfg, req);
    let placement = cfg.normalized_uplink_data_placement().to_string();
    if placement == PLACEMENT_BODY || placement == PLACEMENT_AUTO {
        req.body = Some(data.to_vec());
        req.content_length = Some(data.len() as u64);
    } else {
        req.body = None;
        req.content_length = Some(0);
        let chunk_size = cfg.normalized_uplink_chunk_size()?;
        match placement.as_str() {
            PLACEMENT_HEADER => apply_uplink_data_to_header(cfg, req, data, chunk_size),
            PLACEMENT_COOKIE => apply_uplink_data_to_cookie(cfg, req, data, chunk_size),
            _ => {}
        }
    }
    apply_x_padding(cfg, req)?;
    apply_meta(cfg, req, session_id, seq_str);
    Ok(())
}

fn apply_uplink_data_to_header(
    cfg: &Config,
    req: &mut PreparedRequest,
    data: &[u8],
    chunk_size: Range,
) {
    let key = if cfg.uplink_data_key.is_empty() {
        "X-Data"
    } else {
        &cfg.uplink_data_key
    };
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data);
    let mut bytes = encoded.as_bytes();
    let mut i = 0usize;
    while !bytes.is_empty() {
        let n = chunk_size.rand().min(bytes.len());
        let chunk = &bytes[..n];
        let header_key = format!("{key}-{i}");
        if let Ok(val) = std::str::from_utf8(chunk) {
            req.add_header(&header_key, val);
        }
        bytes = &bytes[n..];
        i += 1;
    }
}

fn apply_uplink_data_to_cookie(
    cfg: &Config,
    req: &mut PreparedRequest,
    data: &[u8],
    chunk_size: Range,
) {
    let key = if cfg.uplink_data_key.is_empty() {
        "x_data"
    } else {
        &cfg.uplink_data_key
    };
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data);
    let mut bytes = encoded.as_bytes();
    let mut i = 0usize;
    while !bytes.is_empty() {
        let n = chunk_size.rand().min(bytes.len());
        let chunk = &bytes[..n];
        let cookie_name = format!("{key}_{i}");
        if let Ok(val) = std::str::from_utf8(chunk) {
            req.add_cookie(&cookie_name, val);
        }
        bytes = &bytes[n..];
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_path_placement() {
        let cfg = Config::default();
        let mut req = PreparedRequest::new("POST", "https://e.com/p/", "e.com");
        apply_meta(&cfg, &mut req, "sess123", "42");
        assert!(req.url.contains("/p/sess123/42"));
    }

    #[test]
    fn meta_query_placement() {
        let mut cfg = Config::default();
        cfg.session_placement = "query".into();
        cfg.seq_placement = "query".into();
        let mut req = PreparedRequest::new("POST", "https://e.com/p/", "e.com");
        apply_meta(&cfg, &mut req, "sess", "1");
        assert!(req.url.contains("x_session=sess"));
        assert!(req.url.contains("x_seq=1"));
    }

    #[test]
    fn meta_header_placement() {
        let mut cfg = Config::default();
        cfg.session_placement = "header".into();
        cfg.seq_placement = "header".into();
        let mut req = PreparedRequest::new("POST", "https://e.com/p/", "e.com");
        apply_meta(&cfg, &mut req, "ABC", "99");
        assert!(
            req.headers
                .iter()
                .any(|(k, v)| k == "X-Session" && v == "ABC")
        );
        assert!(req.headers.iter().any(|(k, v)| k == "X-Seq" && v == "99"));
    }

    #[test]
    fn x_padding_referer_obfs_off() {
        let cfg = Config::default(); // obfs off → 默认 queryInHeader/Referer
        let mut req = PreparedRequest::new("POST", "https://e.com/p/", "e.com");
        apply_x_padding(&cfg, &mut req).unwrap();
        assert!(
            req.headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("Referer"))
        );
    }

    #[test]
    fn x_padding_header_obfs_on() {
        let mut cfg = Config::default();
        cfg.x_padding_obfs_mode = true;
        cfg.x_padding_placement = "header".into();
        cfg.x_padding_header = "X-Pad".into();
        cfg.x_padding_key = "_p".into();
        cfg.x_padding_method = "tokenish".into();
        cfg.x_padding_bytes = "50".into();
        let mut req = PreparedRequest::new("POST", "https://e.com/p/", "e.com");
        apply_x_padding(&cfg, &mut req).unwrap();
        assert!(req.headers.iter().any(|(k, _)| k == "X-Pad"));
    }

    #[test]
    fn fill_stream_adds_grpc() {
        let cfg = Config::default();
        let mut req = PreparedRequest::new("POST", "https://e.com/p/", "e.com");
        fill_stream_request(&cfg, &mut req, "sess").unwrap();
        assert!(
            req.headers
                .iter()
                .any(|(k, v)| k == "Content-Type" && v == "application/grpc")
        );
    }

    #[test]
    fn fill_packet_body_placement() {
        let cfg = Config::default();
        let mut req = PreparedRequest::new("POST", "https://e.com/p/", "e.com");
        fill_packet_request(&cfg, &mut req, "s", "0", b"hello").unwrap();
        assert_eq!(req.body.as_deref(), Some(b"hello".as_ref()));
        assert_eq!(req.content_length, Some(5));
    }

    #[test]
    fn fill_packet_header_placement() {
        let mut cfg = Config::default();
        cfg.uplink_data_placement = "header".into();
        cfg.uplink_data_key = "X-Data".into();
        let mut req = PreparedRequest::new("POST", "https://e.com/p/", "e.com");
        fill_packet_request(&cfg, &mut req, "s", "0", b"hello world").unwrap();
        assert!(req.body.is_none());
        let count = req
            .headers
            .iter()
            .filter(|(k, _)| k.starts_with("X-Data-"))
            .count();
        assert!(count >= 1);
    }
}
