//! DNS message service used by capture DNS hijack and future local listeners.
//!
//! The service is the packet-level equivalent of mihomo's DNS service chain:
//! it parses a DNS request, applies fake-ip/enhanced-mode handling when a pool
//! is attached, otherwise delegates A/AAAA lookups to the resolver policy flow.

use std::{sync::Arc, time::Duration};

use core_config::model::FakeMode;
use tracing::{debug, trace};

use crate::{
    Resolver,
    cache::QType,
    fake_ip::{AddressFamily, FakeIpFilter, FakeIpPool},
    mapping::IpHostMapping,
    packet::{
        TYPE_A, TYPE_AAAA, TYPE_HTTPS, TYPE_SVCB, build_empty_response, build_ip_response,
        build_record_response, parse_first_question,
    },
};

#[derive(Clone)]
pub struct DnsService {
    resolver: Option<Arc<Resolver>>,
    fake_pool: Option<Arc<FakeIpPool>>,
    fake_filter: Option<Arc<FakeIpFilter>>,
    mapping: Option<Arc<IpHostMapping>>,
    ipv6_enabled: bool,
    ttl: Duration,
}

impl std::fmt::Debug for DnsService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsService")
            .field("resolver", &self.resolver.is_some())
            .field("fake_pool", &self.fake_pool.is_some())
            .field("fake_filter", &self.fake_filter.is_some())
            .field("ipv6_enabled", &self.ipv6_enabled)
            .field("ttl", &self.ttl)
            .finish()
    }
}

impl DnsService {
    pub fn new(resolver: Arc<Resolver>) -> Self {
        let ttl = resolver.cfg().cache;
        let ipv6_enabled = resolver.ipv6_enabled();
        let fake_filter = resolver.fake_filter();
        let mapping = Some(resolver.mapping());
        Self {
            resolver: Some(resolver),
            fake_pool: None,
            fake_filter,
            mapping,
            ipv6_enabled,
            ttl,
        }
    }

    pub fn fake_only(pool: Arc<FakeIpPool>) -> Self {
        Self {
            resolver: None,
            fake_pool: Some(pool),
            fake_filter: None,
            mapping: None,
            ipv6_enabled: true,
            ttl: Duration::from_secs(60),
        }
    }

    pub fn with_fake_pool(mut self, pool: Arc<FakeIpPool>) -> Self {
        self.fake_pool = Some(pool);
        self
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    pub async fn serve_packet(&self, req: &[u8]) -> Vec<u8> {
        let Some(question) = parse_first_question(req) else {
            return build_empty_response(req, None);
        };
        trace!(
            target: "resolver::dns_service",
            host = %question.name,
            qtype = question.qtype,
            qclass = question.qclass,
            "dns query"
        );

        match question.qtype {
            TYPE_A | TYPE_AAAA => {
                // IPv6 disabled: return empty for AAAA
                if !self.ipv6_enabled && question.qtype == TYPE_AAAA {
                    return build_empty_response(req, Some(&question));
                }

                // Fake-IP path (with filter check)
                if self.fake_enabled() {
                    let skip_fake = self
                        .fake_filter
                        .as_ref()
                        .map(|f| f.should_skip(&question.name))
                        .unwrap_or(false);

                    if !skip_fake {
                        let pool = self.fake_pool.as_ref().expect("fake_enabled requires pool");
                        let family = if question.qtype == TYPE_A {
                            AddressFamily::V4
                        } else {
                            AddressFamily::V6
                        };
                        let ips = pool
                            .alloc(&question.name, family)
                            .into_iter()
                            .collect::<Vec<_>>();
                        debug!(
                            target: "resolver::dns_service",
                            host = %question.name,
                            qtype = question.qtype,
                            answers = ips.len(),
                            mode = "fake-ip",
                            "dns response"
                        );
                        let ttl = self.ttl.min(pool.config().ttl);
                        return build_ip_response(
                            req,
                            &question,
                            &ips,
                            ttl.as_secs().min(u32::MAX as u64) as u32,
                        );
                    }
                    // Filter said skip: fall through to resolver path
                }

                let Some(resolver) = &self.resolver else {
                    return build_empty_response(req, Some(&question));
                };
                let qtype = if question.qtype == TYPE_A {
                    QType::A
                } else {
                    QType::AAAA
                };
                match resolver.resolve_qtype_answer(&question.name, qtype).await {
                    Ok(answer) => {
                        let ttl = if answer.stale {
                            resolver.cache().config().stale_answer_ttl
                        } else {
                            self.ttl
                        };
                        debug!(
                            target: "resolver::dns_service",
                            host = %question.name,
                            qtype = question.qtype,
                            answers = answer.ips.len(),
                            stale = answer.stale,
                            mode = "resolver",
                            "dns response"
                        );
                        // Write IP→host mapping
                        let mapping_ttl = ttl.max(Duration::from_secs(1));
                        for ip in answer
                            .ips
                            .iter()
                            .copied()
                            .filter(|ip| is_global_unicast(*ip))
                        {
                            if let Some(m) = &self.mapping {
                                m.insert(ip, &question.name, mapping_ttl);
                            }
                            if let Some(pool) = &self.fake_pool {
                                pool.insert_mapping(ip, &question.name, mapping_ttl);
                            }
                        }
                        build_ip_response(
                            req,
                            &question,
                            &answer.ips,
                            ttl.as_secs().min(u32::MAX as u64) as u32,
                        )
                    }
                    Err(e) => {
                        debug!(
                            target: "resolver::dns_service",
                            host = %question.name,
                            qtype = question.qtype,
                            error = %e,
                            "dns resolver returned empty response"
                        );
                        build_empty_response(req, Some(&question))
                    }
                }
            }
            TYPE_SVCB | TYPE_HTTPS if self.fake_enabled() => {
                trace!(
                    target: "resolver::dns_service",
                    host = %question.name,
                    qtype = question.qtype,
                    "dns synthetic empty response for fake-ip service binding query"
                );
                build_empty_response(req, Some(&question))
            }
            _ => {
                let Some(resolver) = &self.resolver else {
                    return build_empty_response(req, Some(&question));
                };
                match resolver
                    .resolve_records_answer(&question.name, question.qtype)
                    .await
                {
                    Ok(records) => {
                        debug!(
                            target: "resolver::dns_service",
                            host = %question.name,
                            qtype = question.qtype,
                            answers = records.len(),
                            mode = "normal",
                            "dns response"
                        );
                        build_record_response(req, &question, &records)
                    }
                    Err(e) => {
                        debug!(
                            target: "resolver::dns_service",
                            host = %question.name,
                            qtype = question.qtype,
                            error = %e,
                            "dns normal resolver returned empty response"
                        );
                        build_empty_response(req, Some(&question))
                    }
                }
            }
        }
    }

    fn fake_enabled(&self) -> bool {
        self.fake_pool.is_some()
            && self
                .resolver
                .as_ref()
                .map(|r| !matches!(r.cfg().fake, FakeMode::Off))
                .unwrap_or(true)
    }
}

fn is_global_unicast(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            let o = ip.octets();
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || o[0] >= 240)
        }
        std::net::IpAddr::V6(ip) => {
            let s = ip.segments();
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || (s[0] == 0x2001 && s[1] == 0x0db8))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        net::{IpAddr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    use async_trait::async_trait;
    use core_config::model::{FakeMode, Resolver as ResolverCfg, ResolverMode};
    use tokio::net::UdpSocket;

    use crate::{
        DnsAction, DnsError, DnsGroup, DnsService, DnsUpstream, FakeIpPool, GroupStrategy,
        PolicyEngine, Resolver, ResolverBuilder,
    };

    #[derive(Debug)]
    struct StaticUpstream;

    #[async_trait]
    impl DnsUpstream for StaticUpstream {
        fn name(&self) -> &str {
            "static"
        }
        fn kind(&self) -> &'static str {
            "test"
        }
        async fn query_a(&self, _: &str) -> Result<Vec<IpAddr>, DnsError> {
            Ok(vec!["9.9.9.9".parse().unwrap()])
        }
        async fn query_aaaa(&self, _: &str) -> Result<Vec<IpAddr>, DnsError> {
            Ok(vec!["2001:db8::9".parse().unwrap()])
        }
    }

    #[derive(Debug)]
    struct FailingAfterFirstUp {
        n: std::sync::atomic::AtomicU32,
    }

    #[async_trait]
    impl DnsUpstream for FailingAfterFirstUp {
        fn name(&self) -> &str {
            "failing-after-first"
        }
        fn kind(&self) -> &'static str {
            "test"
        }
        async fn query_a(&self, _: &str) -> Result<Vec<IpAddr>, DnsError> {
            let n = self.n.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if n == 0 {
                Ok(vec!["1.1.1.1".parse().unwrap()])
            } else {
                Err(DnsError::Timeout)
            }
        }
        async fn query_aaaa(&self, _: &str) -> Result<Vec<IpAddr>, DnsError> {
            Err(DnsError::Timeout)
        }
    }

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0);
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt
    }

    fn txt_response(req: &[u8], text: &[u8]) -> Vec<u8> {
        let question = crate::packet::parse_first_question(req).unwrap();
        let mut resp = req[..question.question_end].to_vec();
        resp[2] = 0x81;
        resp[3] = 0x80;
        resp[4..6].copy_from_slice(&1u16.to_be_bytes());
        resp[6..8].copy_from_slice(&1u16.to_be_bytes());
        resp[8..10].copy_from_slice(&0u16.to_be_bytes());
        resp[10..12].copy_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&[0xc0, 0x0c]);
        resp.extend_from_slice(&16u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&60u32.to_be_bytes());
        resp.extend_from_slice(&((text.len() + 1) as u16).to_be_bytes());
        resp.push(text.len() as u8);
        resp.extend_from_slice(text);
        resp
    }

    async fn spawn_txt_dns_server(text: &'static [u8]) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let resp = txt_response(&buf[..n], text);
            let _ = sock.send_to(&resp, peer).await;
        });
        addr
    }

    #[tokio::test]
    async fn fake_ip_service_answers_a_and_records_reverse_lookup() {
        let pool = Arc::new(FakeIpPool::default());
        let service = DnsService::fake_only(pool.clone());

        let resp = service.serve_packet(&query("www.example.com", 1)).await;

        assert!(resp.len() > 12);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
        let ip = IpAddr::V4(
            [
                resp[resp.len() - 4],
                resp[resp.len() - 3],
                resp[resp.len() - 2],
                resp[resp.len() - 1],
            ]
            .into(),
        );
        assert_eq!(pool.lookup(ip).as_deref(), Some("www.example.com"));
    }

    #[tokio::test]
    async fn fake_ip_service_returns_empty_for_https_query() {
        let service = DnsService::fake_only(Arc::new(FakeIpPool::default()));

        let resp = service.serve_packet(&query("www.example.com", 65)).await;

        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);
        assert_eq!(resp[3] & 0x0f, 0);
    }

    #[tokio::test]
    async fn service_honors_fake_off_and_uses_resolver_flow() {
        let up = Arc::new(StaticUpstream);
        let group = Arc::new(DnsGroup::new(
            "g",
            GroupStrategy::Fallback,
            vec![up as Arc<dyn DnsUpstream>],
        ));
        let resolver = Arc::new(
            ResolverBuilder::new()
                .cfg(ResolverCfg {
                    fake: FakeMode::Off,
                    ..ResolverCfg::default()
                })
                .group("g", group.clone())
                .bootstrap(group.clone())
                .policy(PolicyEngine::new().with_default(DnsAction::Direct("g".into())))
                .build(),
        );
        let pool = Arc::new(FakeIpPool::default());
        let service = DnsService::new(resolver).with_fake_pool(pool.clone());

        let resp = service.serve_packet(&query("www.example.com", 1)).await;

        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
        assert_eq!(&resp[resp.len() - 4..], &[9, 9, 9, 9]);
        assert_eq!(
            pool.lookup("9.9.9.9".parse().unwrap()).as_deref(),
            Some("www.example.com")
        );
        assert_eq!(pool.len(), 0);
    }

    #[tokio::test]
    async fn normal_dns_service_forwards_non_address_qtype() {
        let dns_addr = spawn_txt_dns_server(b"normal-mode-real-dns").await;
        let mut servers = BTreeMap::new();
        servers.insert("local".into(), format!("udp://{dns_addr}"));
        let resolver = Arc::new(
            Resolver::try_new(ResolverCfg {
                mode: ResolverMode::Normal,
                fake: FakeMode::Off,
                nameserver: vec!["local".into()],
                fallback: Vec::new(),
                servers,
                ..ResolverCfg::default()
            })
            .unwrap(),
        );
        let service = DnsService::new(resolver);

        let resp = service.serve_packet(&query("txt.example.com", 16)).await;

        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
        assert!(
            resp.windows(b"normal-mode-real-dns".len())
                .any(|w| w == b"normal-mode-real-dns")
        );
    }

    #[tokio::test]
    async fn stale_dns_response_uses_short_ttl() {
        let up = Arc::new(FailingAfterFirstUp {
            n: std::sync::atomic::AtomicU32::new(0),
        });
        let group = Arc::new(DnsGroup::new(
            "g",
            GroupStrategy::Fallback,
            vec![up as Arc<dyn DnsUpstream>],
        ));
        let resolver = Arc::new(
            ResolverBuilder::new()
                .group("g", group.clone())
                .bootstrap(group.clone())
                .policy(PolicyEngine::new().with_default(DnsAction::Direct("g".into())))
                .cache_cfg(crate::CacheConfig {
                    grace: Duration::from_secs(60),
                    prefetch_threshold: Duration::from_millis(0),
                    client_response_timeout: Duration::from_millis(20),
                    failure_recheck: Duration::from_secs(5),
                    stale_answer_ttl: Duration::from_secs(30),
                    ..crate::CacheConfig::default()
                })
                .default_ttl(Duration::from_millis(1))
                .build(),
        );
        let service = DnsService::new(resolver);

        let _ = service.serve_packet(&query("ttl.example.com", 1)).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
        let resp = service.serve_packet(&query("ttl.example.com", 1)).await;

        let ttl_offset = resp.len() - 10;
        let ttl = u32::from_be_bytes([
            resp[ttl_offset],
            resp[ttl_offset + 1],
            resp[ttl_offset + 2],
            resp[ttl_offset + 3],
        ]);
        assert_eq!(ttl, 30);
    }
}
