//! 系统 resolver：A/AAAA 使用 `getaddrinfo`，其余记录类型沿用系统 DNS 配置查询。

use std::net::{IpAddr, ToSocketAddrs};

use async_trait::async_trait;
use hickory_resolver::{
    TokioAsyncResolver,
    proto::rr::{Record, RecordType},
};

use super::{DnsError, DnsUpstream};

#[derive(Debug, Clone)]
pub struct SystemUpstream {
    pub name: String,
    pub client_subnet: Option<ipnet::IpNet>,
}

impl SystemUpstream {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            client_subnet: None,
        }
    }
    pub fn with_client_subnet(mut self, n: ipnet::IpNet) -> Self {
        self.client_subnet = Some(n);
        self
    }
}

#[async_trait]
impl DnsUpstream for SystemUpstream {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &'static str {
        "system"
    }
    fn default_client_subnet(&self) -> Option<ipnet::IpNet> {
        self.client_subnet
    }

    async fn query_a(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        query_filtered(host, true).await
    }
    async fn query_aaaa(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        query_filtered(host, false).await
    }
    async fn query_records(
        &self,
        host: &str,
        record_type: RecordType,
    ) -> Result<Vec<Record>, DnsError> {
        match record_type {
            RecordType::A => return records_from_ips(host, record_type, self.query_a(host).await?),
            RecordType::AAAA => {
                return records_from_ips(host, record_type, self.query_aaaa(host).await?);
            }
            _ => {}
        }

        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .map_err(|e| DnsError::Failed(format!("读取系统 DNS 配置失败: {e}")))?;
        let lookup = resolver
            .lookup(host.trim_end_matches('.'), record_type)
            .await
            .map_err(|e| DnsError::Failed(e.to_string()))?;
        let records = lookup.records().to_vec();
        if records.is_empty() {
            Err(DnsError::Empty)
        } else {
            Ok(records)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_server_client_subnet_is_kept() {
        let net: ipnet::IpNet = "1.2.3.0/24".parse().unwrap();
        let up = SystemUpstream::new("ali").with_client_subnet(net);
        assert_eq!(up.default_client_subnet(), Some(net));
        // 默认 None
        assert_eq!(SystemUpstream::new("x").default_client_subnet(), None);
    }
}

async fn query_filtered(host: &str, want_v4: bool) -> Result<Vec<IpAddr>, DnsError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let host = host.to_string();
    let res = tokio::task::spawn_blocking(move || {
        format!("{host}:0").to_socket_addrs().map(|it| {
            it.map(|sa| sa.ip())
                .filter(|ip| if want_v4 { ip.is_ipv4() } else { ip.is_ipv6() })
                .collect::<Vec<_>>()
        })
    })
    .await
    .map_err(|e| DnsError::Failed(e.to_string()))?
    .map_err(|e| DnsError::Failed(e.to_string()))?;
    if res.is_empty() {
        Err(DnsError::Empty)
    } else {
        Ok(res)
    }
}

fn records_from_ips(
    host: &str,
    record_type: RecordType,
    ips: Vec<IpAddr>,
) -> Result<Vec<Record>, DnsError> {
    use hickory_resolver::proto::rr::{
        Name, RData,
        rdata::{A, AAAA},
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
