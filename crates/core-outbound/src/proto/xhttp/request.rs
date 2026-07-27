//! XHTTP 请求构造 —— 应用 placement / x-padding / meta 到 hyper Request。
//!
//! 与 mihomo `transport/xhttp/config.go` 中的 `FillStreamRequest` /
//! `FillPacketRequest` / `FillDownloadRequest` / `ApplyMetaToRequest` /
//! `ApplyXPaddingToRequest` 等价。

use std::collections::BTreeMap;

use base64::Engine;
use http::{HeaderName, HeaderValue, Request as HttpRequest};

use super::{
    browser_headers::browser_identity,
    config::{
        Config, PLACEMENT_AUTO, PLACEMENT_BODY, PLACEMENT_COOKIE, PLACEMENT_HEADER, PLACEMENT_PATH,
        PLACEMENT_QUERY, PLACEMENT_QUERY_IN_HEADER, Range,
    },
    xpadding::{PaddingMethod, XPaddingConfig, XPaddingPlacement, generate_padding},
};

const GO_MAX_QUERY_PARAMS: usize = 10_000;

/// The subset of Go's `url.URL` state used by Xray's XHTTP transport.
///
/// Xray assigns the configured path to `URL.Path`, rather than parsing it as
/// an already-escaped URL. Keeping the decoded path and encoded query apart is
/// important: `URL.String` escapes every literal `%` in `Path`, while
/// `RawQuery` is emitted verbatim. WHATWG URL implementations also normalize
/// `.`/`..` segments, which Xray deliberately leaves untouched here.
#[derive(Clone, Debug, PartialEq, Eq)]
struct XrayUrlState {
    scheme: String,
    authority: String,
    path: String,
    raw_query: String,
}

impl XrayUrlState {
    fn from_absolute(value: &str) -> Self {
        let (scheme, remainder) = value.split_once("://").unwrap_or(("", value));
        let authority_end = remainder
            .bytes()
            .position(|byte| matches!(byte, b'/' | b'?'))
            .unwrap_or(remainder.len());
        let authority = &remainder[..authority_end];
        let path_and_query = &remainder[authority_end..];
        let (path, raw_query) = path_and_query
            .split_once('?')
            .map_or((path_and_query, ""), |(path, query)| (path, query));
        Self {
            scheme: scheme.to_owned(),
            authority: authority.to_owned(),
            path: path.to_owned(),
            raw_query: raw_query.to_owned(),
        }
    }

    fn absolute(&self) -> String {
        let mut rendered = String::with_capacity(
            self.scheme.len() + self.authority.len() + self.path.len() + self.raw_query.len() + 4,
        );
        rendered.push_str(&self.scheme);
        rendered.push_str("://");
        rendered.push_str(&self.authority);
        rendered.push_str(&go_escape_path(&self.path));
        if !self.raw_query.is_empty() {
            rendered.push('?');
            rendered.push_str(&self.raw_query);
        }
        rendered
    }

    fn origin_form(&self) -> String {
        let mut rendered = go_escape_path(&self.path);
        if rendered.is_empty() {
            rendered.push('/');
        }
        if !self.raw_query.is_empty() {
            rendered.push('?');
            rendered.push_str(&self.raw_query);
        }
        rendered
    }

    fn set_query(&mut self, key: &str, value: &str) {
        let mut values = go_parse_query(&self.raw_query);
        values.insert(key.as_bytes().to_vec(), vec![value.as_bytes().to_vec()]);
        self.raw_query = go_encode_query(&values);
    }

    fn append_path(&mut self, value: &str) {
        if !self.path.ends_with('/') {
            self.path.push('/');
        }
        self.path.push_str(value);
    }
}

#[derive(Clone, Debug)]
pub struct PreparedRequest {
    pub method: String,
    url: XrayUrlState,
    pub host: String,
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub content_length: Option<u64>,
}

impl PreparedRequest {
    pub fn into_http_request(self, body_unit: ()) -> Result<HttpRequest<()>, String> {
        let full_url = self.absolute_url();
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
        let existing_cookie = req
            .headers()
            .get(http::header::COOKIE)
            .and_then(|value| value.to_str().ok());
        if let Some(joined) = self.cookie_header(existing_cookie) {
            let value =
                HeaderValue::from_str(&joined).map_err(|e| format!("cookie header: {e}"))?;
            req.headers_mut()
                .insert(HeaderName::from_static("cookie"), value);
        }
        Ok(req)
    }
}

impl PreparedRequest {
    pub fn new(method: &str, url: &str, host: &str) -> Self {
        Self {
            method: method.into(),
            url: XrayUrlState::from_absolute(url),
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

    /// Match Go's `http.Header.Set`: remove every case-insensitive occurrence
    /// before inserting the authoritative value.
    pub fn set_header(&mut self, key: &str, value: &str) {
        self.headers
            .retain(|(existing, _)| !existing.eq_ignore_ascii_case(key));
        self.headers.push((key.into(), value.into()));
    }

    pub fn remove_header(&mut self, key: &str) {
        self.headers
            .retain(|(existing, _)| !existing.eq_ignore_ascii_case(key));
    }

    pub fn add_cookie(&mut self, key: &str, value: &str) {
        self.cookies.push((key.into(), value.into()));
    }

    pub fn set_query(&mut self, key: &str, value: &str) {
        self.url.set_query(key, value);
    }

    pub fn append_path(&mut self, segment: &str) {
        self.url.append_path(segment);
    }

    pub(crate) fn absolute_url(&self) -> String {
        self.url.absolute()
    }

    pub(crate) fn origin_form(&self) -> String {
        self.url.origin_form()
    }

    /// Render generated cookies exactly like repeated Go `Request.AddCookie`
    /// calls. Existing user-supplied Cookie text is intentionally preserved.
    pub(crate) fn cookie_header(&self, existing: Option<&str>) -> Option<String> {
        if self.cookies.is_empty() {
            return existing
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
        }
        let mut rendered = existing
            .filter(|value| !value.is_empty())
            .unwrap_or("")
            .to_owned();
        for (name, value) in &self.cookies {
            if !rendered.is_empty() {
                rendered.push_str("; ");
            }
            rendered.push_str(&go_sanitize_cookie_name(name));
            rendered.push('=');
            rendered.push_str(&go_sanitize_cookie_value(value));
        }
        Some(rendered)
    }
}

fn go_escape_path(path: &str) -> String {
    let mut escaped = String::with_capacity(path.len());
    for &byte in path.as_bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_'
                    | b'.'
                    | b'~'
                    | b'/'
                    | b'$'
                    | b'&'
                    | b'+'
                    | b','
                    | b':'
                    | b';'
                    | b'='
                    | b'@'
            )
        {
            escaped.push(char::from(byte));
        } else {
            push_percent_encoded(&mut escaped, byte);
        }
    }
    escaped
}

fn go_parse_query(raw_query: &str) -> BTreeMap<Vec<u8>, Vec<Vec<u8>>> {
    if raw_query.bytes().filter(|byte| *byte == b'&').count() + 1 > GO_MAX_QUERY_PARAMS {
        return BTreeMap::new();
    }

    let mut values = BTreeMap::<Vec<u8>, Vec<Vec<u8>>>::new();
    for pair in raw_query.as_bytes().split(|byte| *byte == b'&') {
        if pair.is_empty() || pair.contains(&b';') {
            continue;
        }
        let separator = pair
            .iter()
            .position(|byte| *byte == b'=')
            .unwrap_or(pair.len());
        let (raw_key, raw_value) = if separator == pair.len() {
            (pair, &[][..])
        } else {
            (&pair[..separator], &pair[separator + 1..])
        };
        let (Some(key), Some(value)) = (go_query_unescape(raw_key), go_query_unescape(raw_value))
        else {
            continue;
        };
        values.entry(key).or_default().push(value);
    }
    values
}

fn go_query_unescape(value: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut offset = 0;
    while offset < value.len() {
        match value[offset] {
            b'%' if offset + 2 < value.len() => {
                let high = go_hex_nibble(value[offset + 1])?;
                let low = go_hex_nibble(value[offset + 2])?;
                decoded.push((high << 4) | low);
                offset += 3;
            }
            b'%' => return None,
            b'+' => {
                decoded.push(b' ');
                offset += 1;
            }
            byte => {
                decoded.push(byte);
                offset += 1;
            }
        }
    }
    Some(decoded)
}

fn go_encode_query(values: &BTreeMap<Vec<u8>, Vec<Vec<u8>>>) -> String {
    let mut encoded = String::new();
    for (key, entries) in values {
        let key = go_query_escape(key);
        for value in entries {
            if !encoded.is_empty() {
                encoded.push('&');
            }
            encoded.push_str(&key);
            encoded.push('=');
            encoded.push_str(&go_query_escape(value));
        }
    }
    encoded
}

fn go_query_escape(value: &[u8]) -> String {
    let mut escaped = String::with_capacity(value.len());
    for &byte in value {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            escaped.push(char::from(byte));
        } else if byte == b' ' {
            escaped.push('+');
        } else {
            push_percent_encoded(&mut escaped, byte);
        }
    }
    escaped
}

fn push_percent_encoded(output: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    output.push('%');
    output.push(char::from(HEX[(byte >> 4) as usize]));
    output.push(char::from(HEX[(byte & 0x0f) as usize]));
}

fn go_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn go_sanitize_cookie_name(name: &str) -> String {
    name.replace(['\r', '\n'], "-")
}

fn go_sanitize_cookie_value(value: &str) -> String {
    let sanitized = value
        .bytes()
        .filter(|byte| (0x20..0x7f).contains(byte) && !matches!(byte, b'"' | b';' | b'\\'))
        .map(char::from)
        .collect::<String>();
    if sanitized.contains([' ', ',']) {
        format!("\"{sanitized}\"")
    } else {
        sanitized
    }
}

fn replace_raw_query(url: &str, raw_query: &str) -> String {
    let base = url.split_once('?').map_or(url, |(base, _)| base);
    format!("{base}?{raw_query}")
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
            PLACEMENT_HEADER => req.set_header(&s_key, session_id),
            PLACEMENT_COOKIE => req.add_cookie(&s_key, session_id),
            _ => {}
        }
    }
    if !seq_str.is_empty() {
        match q_place.as_str() {
            PLACEMENT_PATH => req.append_path(seq_str),
            PLACEMENT_QUERY => req.set_query(&q_key, seq_str),
            PLACEMENT_HEADER => req.set_header(&q_key, seq_str),
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
                placement: value_or(&cfg.x_padding_placement, PLACEMENT_QUERY_IN_HEADER).into(),
                key: value_or(&cfg.x_padding_key, "x_padding").into(),
                header: value_or(&cfg.x_padding_header, "X-Padding").into(),
                raw_url: req.absolute_url(),
            },
            method: PaddingMethod::parse(value_or(&cfg.x_padding_method, "repeat-x")),
        }
    } else {
        XPaddingConfig {
            length,
            placement: XPaddingPlacement {
                placement: PLACEMENT_QUERY_IN_HEADER.into(),
                key: "x_padding".into(),
                header: "Referer".into(),
                raw_url: req.absolute_url(),
            },
            method: PaddingMethod::RepeatX,
        }
    };
    let value = generate_padding(pcfg.method, pcfg.length);
    if value.is_empty() {
        return Ok(());
    }
    match pcfg.placement.placement.as_str() {
        PLACEMENT_HEADER => req.set_header(&pcfg.placement.header, &value),
        PLACEMENT_QUERY_IN_HEADER => {
            // Go assigns `RawQuery` directly here. Do not QueryEscape the key
            // or reparse through a WHATWG URL implementation, which would
            // normalize dot segments and alter the already escaped path.
            let raw_query = format!("{}={}", pcfg.placement.key, value);
            let url = replace_raw_query(&pcfg.placement.raw_url, &raw_query);
            req.set_header(&pcfg.placement.header, &url);
        }
        PLACEMENT_COOKIE => req.add_cookie(&pcfg.placement.key, &value),
        PLACEMENT_QUERY => req.set_query(&pcfg.placement.key, &value),
        _ => {}
    }
    Ok(())
}

fn value_or<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() { fallback } else { value }
}

/// 应用 user-defined headers + 默认 fetch 头
pub fn apply_default_headers(cfg: &Config, req: &mut PreparedRequest) {
    for (k, v) in &cfg.headers {
        req.set_header(k, v);
    }
    let user_agent = req
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("user-agent"))
        .map(|(_, value)| value.clone());

    // Xray's global transport UA handler is intentionally opt-in for a
    // caller-supplied ordinary UA: in that case it leaves all camouflage
    // headers untouched. An absent UA selects Chrome.
    let browser = match user_agent.as_deref() {
        None | Some("chrome") => "chrome",
        Some("edge") => "edge",
        Some("firefox") => "firefox",
        Some("safari") => "safari",
        Some("curl") => "curl",
        Some("golang") => "golang",
        Some(_) => return,
    };

    let identity = browser_identity();
    match browser {
        "chrome" => {
            req.set_header("Sec-CH-UA", &identity.chrome_ua_ch);
            req.set_header("Sec-CH-UA-Mobile", "?0");
            req.set_header("Sec-CH-UA-Platform", r#""Windows""#);
            req.set_header("DNT", "1");
            req.set_header("User-Agent", &identity.chrome_ua);
            req.set_header("Accept-Language", "en-US,en;q=0.9");
        }
        "edge" => {
            req.set_header("Sec-CH-UA", &identity.edge_ua_ch);
            req.set_header("Sec-CH-UA-Mobile", "?0");
            req.set_header("Sec-CH-UA-Platform", r#""Windows""#);
            req.set_header("DNT", "1");
            req.set_header("User-Agent", &identity.edge_ua);
            req.set_header("Accept-Language", "en-US,en;q=0.9");
        }
        "firefox" => {
            req.set_header("User-Agent", &identity.firefox_ua);
            req.set_header("DNT", "1");
            req.set_header("Accept-Language", "en-US,en;q=0.5");
        }
        "safari" => {
            req.set_header("User-Agent", &identity.safari_ua);
            req.set_header("Accept-Language", "en-US,en;q=0.9");
        }
        "curl" => {
            req.set_header("User-Agent", &identity.curl_ua);
            return;
        }
        "golang" => {
            // Go's net/http injects this value after Xray deletes its marker.
            // hyper has no implicit UA, so materialize the same wire value.
            req.set_header("User-Agent", "Go-http-client/1.1");
            return;
        }
        _ => unreachable!(),
    }

    // The fetch context uses Set for the three Sec-Fetch fields, so stale
    // user values cannot create a contradictory fingerprint.
    req.set_header("Sec-Fetch-Mode", "cors");
    req.set_header("Sec-Fetch-Dest", "empty");
    req.set_header("Sec-Fetch-Site", "same-origin");
    let priority = match browser {
        "firefox" => "u=4",
        "safari" => "u=3, i",
        _ => "u=1, i",
    };
    set_header_if_get_empty(req, "Priority", priority);
    set_header_if_get_empty(req, "Cache-Control", "no-cache");
    set_header_if_get_empty(req, "Pragma", "no-cache");
    set_header_if_get_empty(req, "Accept", "*/*");
}

/// Match Go `http.Header.Get(key) == ""`: both a missing header and a present
/// header whose first value is empty are replaced.
fn set_header_if_get_empty(req: &mut PreparedRequest, key: &str, value: &str) {
    if req
        .headers
        .iter()
        .find(|(existing, _)| existing.eq_ignore_ascii_case(key))
        .is_none_or(|(_, current)| current.is_empty())
    {
        req.set_header(key, value);
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
        req.set_header("Content-Type", "application/grpc");
    }
    Ok(())
}

/// 构造 stream-up 的 download GET request
pub fn fill_download_request(
    cfg: &Config,
    req: &mut PreparedRequest,
    session_id: &str,
) -> Result<(), String> {
    // Xray only adds the gRPC content type when the request actually carries
    // an upload body.  A stream-down GET must therefore apply the same
    // camouflage/padding/meta pipeline without advertising a gRPC body.
    apply_default_headers(cfg, req);
    apply_x_padding(cfg, req)?;
    apply_meta(cfg, req, session_id, "");
    Ok(())
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
            req.set_header(&header_key, val);
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
        assert!(req.absolute_url().contains("/p/sess123/42"));
    }

    #[test]
    fn meta_query_placement() {
        let mut cfg = Config::default();
        cfg.session_placement = "query".into();
        cfg.seq_placement = "query".into();
        let mut req = PreparedRequest::new("POST", "https://e.com/p/", "e.com");
        apply_meta(&cfg, &mut req, "sess", "1");
        assert!(req.absolute_url().contains("x_session=sess"));
        assert!(req.absolute_url().contains("x_seq=1"));
    }

    #[test]
    fn query_placement_replaces_existing_metadata() {
        let mut cfg = Config::default();
        cfg.session_placement = "query".into();
        let mut req =
            PreparedRequest::new("POST", "https://e.com/p/?x_session=stale&keep=1", "e.com");
        apply_meta(&cfg, &mut req, "fresh", "");
        let rendered = req.absolute_url();
        let parsed = url::Url::parse(&rendered).unwrap();
        let values = parsed
            .query_pairs()
            .filter(|(key, _)| key == "x_session")
            .map(|(_, value)| value.into_owned())
            .collect::<Vec<_>>();
        assert_eq!(values, ["fresh"]);
        assert!(
            parsed
                .query_pairs()
                .any(|(key, value)| { key == "keep" && value == "1" })
        );
    }

    #[test]
    fn path_rendering_matches_go_url_string_byte_for_byte() {
        let cfg = Config::default();
        let mut request = PreparedRequest::new("POST", "https://example.com/p%2F/", "example.com");
        apply_meta(&cfg, &mut request, "A%2F B!\"';\\\0\t\r\n?#[ ]~*", "17");
        assert_eq!(
            request.absolute_url(),
            "https://example.com/p%252F/A%252F%20B%21%22%27;%5C%00%09%0D%0A%3F%23%5B%20%5D~%2A/17"
        );
    }

    #[test]
    fn path_metadata_does_not_normalize_special_segments() {
        for (session, expected) in [
            (".", "https://example.com/x/./17"),
            ("..", "https://example.com/x/../17"),
            ("%2F", "https://example.com/x/%252F/17"),
            ("/", "https://example.com/x//17"),
        ] {
            let cfg = Config::default();
            let mut request = PreparedRequest::new("POST", "https://example.com/x/", "example.com");
            apply_meta(&cfg, &mut request, session, "17");
            assert_eq!(request.absolute_url(), expected, "session={session:?}");
        }
    }

    #[test]
    fn query_codec_matches_go_126_values_set_and_encode() {
        let mut cfg = Config::default();
        cfg.session_placement = PLACEMENT_QUERY.into();
        cfg.session_key = "a".into();
        cfg.seq_placement = PLACEMENT_QUERY.into();
        cfg.seq_key = "m".into();
        let mut request = PreparedRequest::new(
            "POST",
            "https://example.com/x/?z=%7e&b=2&a=old&a=second&d=1&d=2",
            "example.com",
        );
        apply_meta(&cfg, &mut request, "~* /?%\";\0", "17");
        assert_eq!(
            request.absolute_url(),
            "https://example.com/x/?a=~%2A+%2F%3F%25%22%3B%00&b=2&d=1&d=2&m=17&z=~"
        );
    }

    #[test]
    fn query_codec_skips_invalid_pairs_and_enforces_go_limit() {
        let mut state = XrayUrlState::from_absolute(
            "https://example.com/x/?keep=1&bad;pair=2&escape=%ZZ&keep=second&bare",
        );
        state.set_query("new", "value");
        assert_eq!(
            state.absolute(),
            "https://example.com/x/?bare=&keep=1&keep=second&new=value"
        );

        let oversized = std::iter::repeat_n("x=1", GO_MAX_QUERY_PARAMS + 1)
            .collect::<Vec<_>>()
            .join("&");
        let mut state = XrayUrlState::from_absolute(&format!("https://example.com/x/?{oversized}"));
        state.set_query("only", "survives");
        assert_eq!(state.absolute(), "https://example.com/x/?only=survives");
    }

    #[test]
    fn padding_and_metadata_queries_are_sorted_after_each_go_values_set() {
        let mut cfg = Config::default();
        cfg.x_padding_obfs_mode = true;
        cfg.x_padding_placement = PLACEMENT_QUERY.into();
        cfg.x_padding_key = "pad".into();
        cfg.x_padding_bytes = "4".into();
        cfg.session_placement = PLACEMENT_QUERY.into();
        cfg.session_key = "sid".into();
        cfg.seq_placement = PLACEMENT_QUERY.into();
        cfg.seq_key = "seq".into();
        let mut request =
            PreparedRequest::new("POST", "https://example.com/x/?z=9&a=1", "example.com");

        apply_x_padding(&cfg, &mut request).unwrap();
        assert_eq!(
            request.absolute_url(),
            "https://example.com/x/?a=1&pad=XXXX&z=9"
        );
        apply_meta(&cfg, &mut request, "S", "");
        assert_eq!(
            request.absolute_url(),
            "https://example.com/x/?a=1&pad=XXXX&sid=S&z=9"
        );
        apply_meta(&cfg, &mut request, "", "7");
        assert_eq!(
            request.absolute_url(),
            "https://example.com/x/?a=1&pad=XXXX&seq=7&sid=S&z=9"
        );
    }

    #[test]
    fn query_in_header_uses_pre_meta_snapshot_and_direct_raw_query() {
        let mut cfg = Config::default();
        cfg.x_padding_bytes = "4".into();
        cfg.session_placement = PLACEMENT_QUERY.into();
        cfg.session_key = "sid".into();
        cfg.seq_placement = PLACEMENT_QUERY.into();
        cfg.seq_key = "seq".into();
        let mut request =
            PreparedRequest::new("POST", "https://example.com/p%2F/?token=old", "example.com");

        fill_packet_request(&cfg, &mut request, "S", "7", b"body").unwrap();
        let referer = request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("referer"))
            .map(|(_, value)| value.as_str());
        assert_eq!(referer, Some("https://example.com/p%252F/?x_padding=XXXX"));
        assert_eq!(
            request.absolute_url(),
            "https://example.com/p%252F/?seq=7&sid=S&token=old"
        );
    }

    #[test]
    fn generated_cookie_header_matches_go_add_cookie_sanitization() {
        let mut request = PreparedRequest::new("POST", "https://example.com/x/", "example.com");
        request.add_cookie("data_0", "-_8");
        request.add_cookie("pad", "XXXX");
        request.add_cookie("sid", "a b,c\";d\\e\t\0%");
        request.add_cookie("seq", "7");
        assert_eq!(
            request.cookie_header(Some("user=1")),
            Some("user=1; data_0=-_8; pad=XXXX; sid=\"a b,cde%\"; seq=7".into())
        );

        let mut dangerous_name =
            PreparedRequest::new("POST", "https://example.com/x/", "example.com");
        dangerous_name.add_cookie("se\r\nq", "7");
        assert_eq!(
            dangerous_name.cookie_header(None).as_deref(),
            Some("se--q=7")
        );
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
    fn x_padding_obfs_defaults_match_xray() {
        let mut cfg = Config::default();
        cfg.x_padding_obfs_mode = true;
        cfg.x_padding_bytes = "32".into();
        let mut req = PreparedRequest::new("POST", "https://e.com/p/", "e.com");
        apply_x_padding(&cfg, &mut req).unwrap();
        let padded = req
            .headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("X-Padding"))
            .map(|(_, value)| value);
        // Xray's obfs defaults are queryInHeader + X-Padding + x_padding.
        assert!(padded.is_some());
        let url = url::Url::parse(padded.unwrap()).unwrap();
        assert_eq!(
            url.query_pairs()
                .find(|(key, _)| key == "x_padding")
                .unwrap()
                .1
                .len(),
            32
        );
    }

    #[test]
    fn default_fetch_headers_are_complete_and_user_values_win() {
        let mut cfg = Config::default();
        cfg.headers.insert("Priority".into(), "custom".into());
        let mut req = PreparedRequest::new("GET", "https://e.com/p/", "e.com");
        apply_default_headers(&cfg, &mut req);
        for key in [
            "User-Agent",
            "Accept",
            "Accept-Language",
            "Sec-Fetch-Mode",
            "Sec-Fetch-Dest",
            "Sec-Fetch-Site",
            "Cache-Control",
            "Pragma",
        ] {
            assert!(
                req.headers
                    .iter()
                    .any(|(existing, _)| existing.eq_ignore_ascii_case(key)),
                "missing default header {key}"
            );
        }
        assert!(
            req.headers
                .iter()
                .any(|(key, value)| { key.eq_ignore_ascii_case("Priority") && value == "custom" })
        );
    }

    #[test]
    fn fetch_context_overwrites_sec_fetch_but_not_explicit_priority() {
        let mut cfg = Config::default();
        cfg.headers
            .insert("Sec-Fetch-Mode".into(), "navigate".into());
        cfg.headers
            .insert("Sec-Fetch-Dest".into(), "document".into());
        cfg.headers.insert("Priority".into(), "custom".into());
        let mut req = PreparedRequest::new("GET", "https://e.com/p/", "e.com");
        apply_default_headers(&cfg, &mut req);

        assert_eq!(
            req.headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("Sec-Fetch-Mode"))
                .map(|(_, value)| value.as_str()),
            Some("cors")
        );
        assert_eq!(
            req.headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("Sec-Fetch-Dest"))
                .map(|(_, value)| value.as_str()),
            Some("empty")
        );
        assert_eq!(
            req.headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("Priority"))
                .map(|(_, value)| value.as_str()),
            Some("custom")
        );
    }

    #[test]
    fn special_user_agents_match_xray_fetch_profiles() {
        let identity = browser_identity();
        for (browser, expected_ua, priority) in [
            ("chrome", identity.chrome_ua.as_str(), Some("u=1, i")),
            ("edge", identity.edge_ua.as_str(), Some("u=1, i")),
            ("firefox", identity.firefox_ua.as_str(), Some("u=4")),
            ("safari", identity.safari_ua.as_str(), Some("u=3, i")),
            ("curl", identity.curl_ua.as_str(), None),
        ] {
            let mut cfg = Config::default();
            cfg.headers.insert("User-Agent".into(), browser.into());
            let mut req = PreparedRequest::new("GET", "https://e.com/p/", "e.com");
            apply_default_headers(&cfg, &mut req);
            let header = |name: &str| {
                req.headers
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(name))
                    .map(|(_, value)| value.as_str())
            };
            assert_eq!(header("User-Agent"), Some(expected_ua), "browser={browser}");
            assert_eq!(header("Priority"), priority, "browser={browser}");
            assert_eq!(
                header("Sec-Fetch-Mode"),
                priority.map(|_| "cors"),
                "browser={browser}"
            );
        }
    }

    #[test]
    fn golang_and_custom_user_agents_do_not_receive_fetch_camouflage() {
        for user_agent in ["golang", "my-client/1.0"] {
            let mut cfg = Config::default();
            cfg.headers
                .insert("User-Agent".into(), user_agent.to_owned());
            let mut req = PreparedRequest::new("GET", "https://e.com/p/", "e.com");
            apply_default_headers(&cfg, &mut req);
            assert!(
                !req.headers
                    .iter()
                    .any(|(key, _)| key.eq_ignore_ascii_case("Sec-Fetch-Mode")),
                "user-agent={user_agent}"
            );
            let emitted = req
                .headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("User-Agent"))
                .map(|(_, value)| value.as_str());
            assert_eq!(
                emitted,
                Some(if user_agent == "golang" {
                    "Go-http-client/1.1"
                } else {
                    user_agent
                })
            );
        }
    }

    #[test]
    fn empty_fetch_values_are_replaced_like_go_header_get() {
        let mut cfg = Config::default();
        for key in ["Priority", "Cache-Control", "Pragma", "Accept"] {
            cfg.headers.insert(key.into(), String::new());
        }
        let mut req = PreparedRequest::new("GET", "https://e.com/p/", "e.com");
        apply_default_headers(&cfg, &mut req);
        let header = |name: &str| {
            req.headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(header("Priority"), Some("u=1, i"));
        assert_eq!(header("Cache-Control"), Some("no-cache"));
        assert_eq!(header("Pragma"), Some("no-cache"));
        assert_eq!(header("Accept"), Some("*/*"));
    }

    #[test]
    fn authoritative_headers_replace_case_insensitive_user_values() {
        let mut cfg = Config::default();
        cfg.session_placement = "header".into();
        cfg.headers
            .insert("x-session".into(), "attacker-controlled".into());
        cfg.headers
            .insert("content-type".into(), "text/plain".into());
        let mut req = PreparedRequest::new("POST", "https://e.com/p/", "e.com");
        fill_stream_request(&cfg, &mut req, "trusted").unwrap();

        let values = |name: &str| {
            req.headers
                .iter()
                .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(values("X-Session"), ["trusted"]);
        assert_eq!(values("Content-Type"), ["application/grpc"]);
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
    fn fill_download_does_not_add_grpc_content_type() {
        let cfg = Config::default();
        let mut req = PreparedRequest::new("GET", "https://e.com/p/", "e.com");
        fill_download_request(&cfg, &mut req, "sess").unwrap();
        assert!(
            !req.headers
                .iter()
                .any(|(k, _)| { k.eq_ignore_ascii_case("Content-Type") })
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
