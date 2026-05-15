//! XHTTP Config —— 与 mihomo `transport/xhttp/config.go` 等价。
//!
//! XHTTP 是 v2ray/xray 设计的高性能 HTTP 传输层，把代理流量伪装成普通 HTTP/1.1、
//! HTTP/2 或 HTTP/3 流量。三种工作模式：
//!
//! * **stream-one**：单一长连接 POST，请求/响应 body 双向流式
//! * **stream-up**：上行 POST + 下行独立 GET 长连接
//! * **packet-up**：上行多次短 POST，下行 GET 长连接（CDN 友好）
//!
//! ## Placement（数据放置位置）
//!
//! session_id / seq / uplink_data / x_padding 都可放在不同位置：
//! * `path`：拼接到 URL 路径
//! * `query`：URL 查询参数
//! * `header`：HTTP 头
//! * `cookie`：Cookie
//! * `body`：请求体
//! * `queryInHeader`：放在某个 header 里的 URL query（如 Referer）

use std::collections::BTreeMap;

use rand::Rng;

pub const PLACEMENT_QUERY_IN_HEADER: &str = "queryInHeader";
pub const PLACEMENT_COOKIE: &str = "cookie";
pub const PLACEMENT_HEADER: &str = "header";
pub const PLACEMENT_QUERY: &str = "query";
pub const PLACEMENT_PATH: &str = "path";
pub const PLACEMENT_BODY: &str = "body";
pub const PLACEMENT_AUTO: &str = "auto";

#[derive(Debug, Clone, Default)]
pub struct ReuseConfig {
    pub max_concurrency: String,
    pub max_connections: String,
    pub c_max_reuse_times: String,
    pub h_max_request_times: String,
    pub h_max_reusable_secs: String,
}

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub host: String,
    pub path: String,
    /// "auto" | "stream-one" | "stream-up" | "packet-up"
    pub mode: String,
    pub headers: BTreeMap<String, String>,
    pub no_grpc_header: bool,

    /// "100-1000" 默认
    pub x_padding_bytes: String,
    pub x_padding_obfs_mode: bool,
    pub x_padding_key: String,
    pub x_padding_header: String,
    pub x_padding_placement: String,
    /// "repeat-x" | "tokenish"
    pub x_padding_method: String,

    pub uplink_http_method: String, // 默认 POST

    pub session_placement: String, // 默认 path
    pub session_key: String,
    pub seq_placement: String, // 默认 path
    pub seq_key: String,
    pub uplink_data_placement: String, // 默认 body
    pub uplink_data_key: String,
    pub uplink_chunk_size: String,

    pub sc_max_each_post_bytes: String,
    pub sc_min_posts_interval_ms: String,

    pub reuse_config: Option<ReuseConfig>,
    pub download_config: Option<Box<Config>>,
}

impl Config {
    pub fn normalized_mode(&self) -> &str {
        if self.mode.is_empty() {
            "auto"
        } else {
            &self.mode
        }
    }

    pub fn effective_mode(&self, has_reality: bool) -> &str {
        let mode = self.normalized_mode();
        if mode != "auto" {
            return mode;
        }
        if has_reality {
            if self.download_config.is_some() {
                "stream-up"
            } else {
                "stream-one"
            }
        } else {
            "packet-up"
        }
    }

    pub fn normalized_path(&self) -> String {
        let mut path = self.path.clone();
        if path.is_empty() {
            path = "/".into();
        }
        if !path.starts_with('/') {
            path.insert(0, '/');
        }
        if !path.ends_with('/') {
            path.push('/');
        }
        path
    }

    pub fn normalized_uplink_http_method(&self) -> &str {
        if self.uplink_http_method.is_empty() {
            "POST"
        } else {
            &self.uplink_http_method
        }
    }

    pub fn normalized_session_placement(&self) -> &str {
        if self.session_placement.is_empty() {
            PLACEMENT_PATH
        } else {
            &self.session_placement
        }
    }

    pub fn normalized_seq_placement(&self) -> &str {
        if self.seq_placement.is_empty() {
            PLACEMENT_PATH
        } else {
            &self.seq_placement
        }
    }

    pub fn normalized_uplink_data_placement(&self) -> &str {
        if self.uplink_data_placement.is_empty() {
            PLACEMENT_BODY
        } else {
            &self.uplink_data_placement
        }
    }

    pub fn normalized_session_key(&self) -> &str {
        if !self.session_key.is_empty() {
            return &self.session_key;
        }
        match self.normalized_session_placement() {
            PLACEMENT_HEADER => "X-Session",
            PLACEMENT_COOKIE | PLACEMENT_QUERY => "x_session",
            _ => "",
        }
    }

    pub fn normalized_seq_key(&self) -> &str {
        if !self.seq_key.is_empty() {
            return &self.seq_key;
        }
        match self.normalized_seq_placement() {
            PLACEMENT_HEADER => "X-Seq",
            PLACEMENT_COOKIE | PLACEMENT_QUERY => "x_seq",
            _ => "",
        }
    }

    pub fn normalized_x_padding_bytes(&self) -> Result<Range, String> {
        Range::parse(&self.x_padding_bytes, "100-1000")
    }

    pub fn normalized_sc_max_each_post_bytes(&self) -> Result<Range, String> {
        let r = Range::parse(&self.sc_max_each_post_bytes, "1000000")?;
        if r.max == 0 {
            return Err("sc-max-each-post-bytes must be > 0".into());
        }
        Ok(r)
    }

    pub fn normalized_sc_min_posts_interval_ms(&self) -> Result<Range, String> {
        let r = Range::parse(&self.sc_min_posts_interval_ms, "30")?;
        if r.max == 0 {
            return Err("sc-min-posts-interval-ms must be > 0".into());
        }
        Ok(r)
    }

    pub fn normalized_uplink_chunk_size(&self) -> Result<Range, String> {
        let mut r = Range::parse(&self.uplink_chunk_size, "")?;
        if r.max == 0 {
            return match self.normalized_uplink_data_placement() {
                PLACEMENT_COOKIE => Ok(Range::new(2 * 1024, 3 * 1024)),
                PLACEMENT_HEADER => Ok(Range::new(3 * 1024, 4 * 1024)),
                _ => self.normalized_sc_max_each_post_bytes(),
            };
        }
        if r.min < 64 {
            r.min = 64;
            if r.max < 64 {
                r.max = 64;
            }
        }
        Ok(r)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub min: usize,
    pub max: usize,
}

impl Range {
    pub fn new(min: usize, max: usize) -> Self {
        Self { min, max }
    }

    pub fn rand(self) -> usize {
        if self.min == self.max {
            self.min
        } else {
            let mut rng = rand::thread_rng();
            self.min + rng.gen_range(0..=(self.max - self.min))
        }
    }

    pub fn parse(s: &str, fallback: &str) -> Result<Self, String> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Self::parse_inner(fallback);
        }
        Self::parse_inner(trimmed)
    }

    fn parse_inner(s: &str) -> Result<Self, String> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Ok(Self { min: 0, max: 0 });
        }
        let parts: Vec<&str> = trimmed.split('-').collect();
        if parts.len() == 1 {
            let v: usize = parts[0]
                .trim()
                .parse()
                .map_err(|e| format!("invalid range: {e}"))?;
            return Ok(Self { min: v, max: v });
        }
        if parts.len() != 2 {
            return Err(format!("invalid range: {trimmed}"));
        }
        let min: usize = parts[0]
            .trim()
            .parse()
            .map_err(|e| format!("invalid range min: {e}"))?;
        let max: usize = parts[1]
            .trim()
            .parse()
            .map_err(|e| format!("invalid range max: {e}"))?;
        if max < min {
            return Err(format!("invalid range (min>max): {trimmed}"));
        }
        Ok(Self { min, max })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_parse_single() {
        let r = Range::parse("42", "0").unwrap();
        assert_eq!(r, Range::new(42, 42));
        assert_eq!(r.rand(), 42);
    }

    #[test]
    fn range_parse_min_max() {
        let r = Range::parse("10-100", "0").unwrap();
        assert_eq!(r.min, 10);
        assert_eq!(r.max, 100);
        for _ in 0..10 {
            let v = r.rand();
            assert!(v >= 10 && v <= 100);
        }
    }

    #[test]
    fn range_fallback() {
        let r = Range::parse("", "5-10").unwrap();
        assert_eq!(r.min, 5);
        assert_eq!(r.max, 10);
    }

    #[test]
    fn range_invalid() {
        assert!(Range::parse("abc", "0").is_err());
        assert!(Range::parse("100-50", "0").is_err());
        assert!(Range::parse("1-2-3", "0").is_err());
    }

    #[test]
    fn config_normalized_mode() {
        let mut c = Config::default();
        assert_eq!(c.normalized_mode(), "auto");
        c.mode = "packet-up".into();
        assert_eq!(c.normalized_mode(), "packet-up");
    }

    #[test]
    fn config_effective_mode() {
        let c = Config::default();
        assert_eq!(c.effective_mode(false), "packet-up");
        assert_eq!(c.effective_mode(true), "stream-one");
        let mut c2 = c.clone();
        c2.download_config = Some(Box::new(Config::default()));
        assert_eq!(c2.effective_mode(true), "stream-up");
    }

    #[test]
    fn config_normalized_path() {
        let mut c = Config::default();
        assert_eq!(c.normalized_path(), "/");
        c.path = "abc".into();
        assert_eq!(c.normalized_path(), "/abc/");
        c.path = "/a/b".into();
        assert_eq!(c.normalized_path(), "/a/b/");
        c.path = "/c/".into();
        assert_eq!(c.normalized_path(), "/c/");
    }

    #[test]
    fn config_default_session_keys() {
        let mut c = Config::default();
        c.session_placement = "header".into();
        assert_eq!(c.normalized_session_key(), "X-Session");
        c.session_placement = "cookie".into();
        assert_eq!(c.normalized_session_key(), "x_session");
        c.session_key = "custom".into();
        assert_eq!(c.normalized_session_key(), "custom");
    }

    #[test]
    fn config_uplink_chunk_default_for_cookie() {
        let mut c = Config::default();
        c.uplink_data_placement = "cookie".into();
        let r = c.normalized_uplink_chunk_size().unwrap();
        assert_eq!(r.min, 2 * 1024);
        assert_eq!(r.max, 3 * 1024);
    }

    #[test]
    fn config_uplink_chunk_min_floor() {
        let mut c = Config::default();
        c.uplink_chunk_size = "10-50".into();
        let r = c.normalized_uplink_chunk_size().unwrap();
        assert_eq!(r.min, 64);
        assert_eq!(r.max, 64);
    }
}
