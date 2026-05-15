//! DNS 上游抽象：所有具体实现（系统 / DoH / DoT / UDP / QUIC）都通过同一个 trait 接入 group。

use std::{net::IpAddr, sync::Arc};

use async_trait::async_trait;
use hickory_resolver::proto::rr::{
    Name, RData, Record, RecordType,
    rdata::{A, AAAA},
};
use thiserror::Error;

pub mod hickory;
pub mod marked;
pub mod quic;
pub mod system;

#[derive(Debug, Error, Clone)]
pub enum DnsError {
    #[error("解析失败: {0}")]
    Failed(String),
    #[error("查询超时")]
    Timeout,
    #[error("空响应")]
    Empty,
    #[error("被策略拒绝: {0}")]
    Rejected(String),
}

#[async_trait]
pub trait DnsUpstream: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &str;
    fn kind(&self) -> &'static str;
    async fn query_a(&self, host: &str) -> Result<Vec<IpAddr>, DnsError>;
    async fn query_aaaa(&self, host: &str) -> Result<Vec<IpAddr>, DnsError>;
    async fn query_records(
        &self,
        host: &str,
        record_type: RecordType,
    ) -> Result<Vec<Record>, DnsError> {
        let ips = match record_type {
            RecordType::A => self.query_a(host).await?,
            RecordType::AAAA => self.query_aaaa(host).await?,
            other => {
                return Err(DnsError::Failed(format!(
                    "{} upstream does not support raw {other} lookups",
                    self.kind()
                )));
            }
        };
        let name = Name::from_ascii(host.trim_end_matches('.'))
            .map_err(|e| DnsError::Failed(e.to_string()))?;
        let records = ips
            .into_iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(ip) if record_type == RecordType::A => {
                    Some(Record::from_rdata(name.clone(), 60, RData::A(A(ip))))
                }
                IpAddr::V6(ip) if record_type == RecordType::AAAA => {
                    Some(Record::from_rdata(name.clone(), 60, RData::AAAA(AAAA(ip))))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        if records.is_empty() {
            Err(DnsError::Empty)
        } else {
            Ok(records)
        }
    }

    /// 此 server 默认 EDNS0 client_subnet 提示。
    /// rule 级 [`crate::policy::QueryOptions::client_subnet`] 优先级更高 —— 当 rule 提供时覆盖此默认。
    /// 与 sing-box `dns.servers[].client_subnet` 一一对应。
    fn default_client_subnet(&self) -> Option<ipnet::IpNet> {
        None
    }

    /// Reset persistent connections (DoT pool, DoQ session, etc.)
    /// Called on network interface change to force re-establishment on new NIC.
    async fn reset_connections(&self) {
        // Default: no-op for stateless upstreams (UDP, system)
    }
}

/* ---------- Per-Upstream Parameters ---------- */

#[derive(Debug, Clone, Default)]
pub struct UpstreamParams {
    pub skip_cert_verify: bool,
    pub disable_ipv4: bool,
    pub disable_ipv6: bool,
    pub prefer_h3: bool,
    pub disable_reuse: bool,
    pub ecs: Option<ipnet::IpNet>,
}

impl UpstreamParams {
    pub fn parse(query: &str) -> Self {
        let mut params = Self::default();
        for pair in query.split('&') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            let (key, value) = match pair.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => (pair, "true"),
            };
            match key {
                "skip-cert-verify" | "skip_cert_verify" => {
                    params.skip_cert_verify = value == "true" || value == "1";
                }
                "disable-ipv4" | "disable_ipv4" => {
                    params.disable_ipv4 = value == "true" || value == "1";
                }
                "disable-ipv6" | "disable_ipv6" => {
                    params.disable_ipv6 = value == "true" || value == "1";
                }
                "h3" | "prefer-h3" | "prefer_h3" => {
                    params.prefer_h3 = value == "true" || value == "1";
                }
                "disable-reuse" | "disable_reuse" => {
                    params.disable_reuse = value == "true" || value == "1";
                }
                "ecs" => {
                    params.ecs = value.parse().ok();
                }
                _ => {}
            }
        }
        params
    }

    pub fn has_filters(&self) -> bool {
        self.disable_ipv4 || self.disable_ipv6 || self.ecs.is_some()
    }
}

/* ---------- FilteredUpstream Wrapper ---------- */

/// Wraps a DnsUpstream to apply per-upstream parameter filtering (disable-ipv4/ipv6, ECS).
#[derive(Debug)]
pub struct FilteredUpstream {
    inner: Arc<dyn DnsUpstream>,
    params: UpstreamParams,
}

impl FilteredUpstream {
    pub fn new(inner: Arc<dyn DnsUpstream>, params: UpstreamParams) -> Self {
        Self { inner, params }
    }

    pub fn wrap_if_needed(
        inner: Arc<dyn DnsUpstream>,
        params: &UpstreamParams,
    ) -> Arc<dyn DnsUpstream> {
        if params.has_filters() {
            Arc::new(Self::new(inner, params.clone()))
        } else {
            inner
        }
    }
}

#[async_trait]
impl DnsUpstream for FilteredUpstream {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn kind(&self) -> &'static str {
        self.inner.kind()
    }

    async fn query_a(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        if self.params.disable_ipv4 {
            return Ok(vec![]);
        }
        self.inner.query_a(host).await
    }

    async fn query_aaaa(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        if self.params.disable_ipv6 {
            return Ok(vec![]);
        }
        self.inner.query_aaaa(host).await
    }

    async fn query_records(
        &self,
        host: &str,
        record_type: RecordType,
    ) -> Result<Vec<Record>, DnsError> {
        match record_type {
            RecordType::A if self.params.disable_ipv4 => Ok(vec![]),
            RecordType::AAAA if self.params.disable_ipv6 => Ok(vec![]),
            _ => self.inner.query_records(host, record_type).await,
        }
    }

    fn default_client_subnet(&self) -> Option<ipnet::IpNet> {
        self.params
            .ecs
            .or_else(|| self.inner.default_client_subnet())
    }

    async fn reset_connections(&self) {
        self.inner.reset_connections().await;
    }
}
