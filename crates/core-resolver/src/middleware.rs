//! DNS middleware pipeline — processes DNS requests through an ordered chain.
//!
//! Each middleware can short-circuit with a response or pass to the next layer.
//! Order: IPv6Filter → Hosts → FakeIP → Mapping → Resolver.

use std::{net::IpAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use tracing::{debug, trace};

use crate::{
    Resolver,
    cache::QType,
    fake_ip::{AddressFamily, FakeIpFilter, FakeIpPool},
    hosts::HostsTable,
    mapping::IpHostMapping,
    packet::{
        DnsQuestion, TYPE_A, TYPE_AAAA, TYPE_HTTPS, TYPE_SVCB, build_empty_response,
        build_ip_response, parse_first_question,
    },
};

pub enum MiddlewareResult {
    Response(Vec<u8>),
    Continue,
}

#[async_trait]
pub trait DnsMiddleware: Send + Sync {
    async fn process(&self, ctx: &mut DnsRequestCtx) -> MiddlewareResult;
}

pub struct DnsRequestCtx {
    pub raw_request: Vec<u8>,
    pub question: DnsQuestion,
    pub response_ips: Vec<IpAddr>,
    pub response_ttl: Duration,
}

pub struct MiddlewareChain {
    layers: Vec<Box<dyn DnsMiddleware>>,
}

impl MiddlewareChain {
    pub fn new(layers: Vec<Box<dyn DnsMiddleware>>) -> Self {
        Self { layers }
    }

    pub async fn execute(&self, req: &[u8]) -> Vec<u8> {
        let Some(question) = parse_first_question(req) else {
            return build_empty_response(req, None);
        };
        trace!(
            target: "resolver::middleware",
            host = %question.name,
            qtype = question.qtype,
            "dns query entering middleware chain"
        );

        let mut ctx = DnsRequestCtx {
            raw_request: req.to_vec(),
            question,
            response_ips: Vec::new(),
            response_ttl: Duration::from_secs(600),
        };

        for layer in &self.layers {
            match layer.process(&mut ctx).await {
                MiddlewareResult::Response(resp) => return resp,
                MiddlewareResult::Continue => {}
            }
        }

        build_empty_response(req, Some(&ctx.question))
    }
}

/* ---------- IPv6 Filter Middleware ---------- */

pub struct Ipv6FilterMiddleware {
    ipv6_enabled: bool,
}

impl Ipv6FilterMiddleware {
    pub fn new(ipv6_enabled: bool) -> Self {
        Self { ipv6_enabled }
    }
}

#[async_trait]
impl DnsMiddleware for Ipv6FilterMiddleware {
    async fn process(&self, ctx: &mut DnsRequestCtx) -> MiddlewareResult {
        if !self.ipv6_enabled && ctx.question.qtype == TYPE_AAAA {
            debug!(
                target: "resolver::middleware",
                host = %ctx.question.name,
                "ipv6 disabled, returning empty AAAA"
            );
            return MiddlewareResult::Response(build_empty_response(
                &ctx.raw_request,
                Some(&ctx.question),
            ));
        }
        MiddlewareResult::Continue
    }
}

/* ---------- Hosts Middleware ---------- */

pub struct HostsMiddleware {
    table: Arc<HostsTable>,
}

impl HostsMiddleware {
    pub fn new(table: Arc<HostsTable>) -> Self {
        Self { table }
    }
}

#[async_trait]
impl DnsMiddleware for HostsMiddleware {
    async fn process(&self, ctx: &mut DnsRequestCtx) -> MiddlewareResult {
        let qtype = match ctx.question.qtype {
            TYPE_A => QType::A,
            TYPE_AAAA => QType::AAAA,
            _ => return MiddlewareResult::Continue,
        };

        if let Some(ips) = self.table.lookup(&ctx.question.name, qtype) {
            debug!(
                target: "resolver::middleware",
                host = %ctx.question.name,
                answers = ips.len(),
                "hosts hit"
            );
            let resp = build_ip_response(&ctx.raw_request, &ctx.question, &ips, 10);
            return MiddlewareResult::Response(resp);
        }
        MiddlewareResult::Continue
    }
}

/* ---------- Fake-IP Middleware ---------- */

pub struct FakeIpMiddleware {
    pool: Arc<FakeIpPool>,
    filter: Option<Arc<FakeIpFilter>>,
    ttl: Duration,
}

impl FakeIpMiddleware {
    pub fn new(pool: Arc<FakeIpPool>, filter: Option<Arc<FakeIpFilter>>, ttl: Duration) -> Self {
        Self { pool, filter, ttl }
    }
}

#[async_trait]
impl DnsMiddleware for FakeIpMiddleware {
    async fn process(&self, ctx: &mut DnsRequestCtx) -> MiddlewareResult {
        // Check filter — if domain should skip fake, pass through
        if let Some(filter) = &self.filter {
            if filter.should_skip(&ctx.question.name) {
                trace!(
                    target: "resolver::middleware",
                    host = %ctx.question.name,
                    "fake-ip filter: skip"
                );
                return MiddlewareResult::Continue;
            }
        }

        match ctx.question.qtype {
            TYPE_A | TYPE_AAAA => {
                let family = if ctx.question.qtype == TYPE_A {
                    AddressFamily::V4
                } else {
                    AddressFamily::V6
                };
                let ips: Vec<IpAddr> = self
                    .pool
                    .alloc(&ctx.question.name, family)
                    .into_iter()
                    .collect();
                if ips.is_empty() {
                    return MiddlewareResult::Continue;
                }
                debug!(
                    target: "resolver::middleware",
                    host = %ctx.question.name,
                    qtype = ctx.question.qtype,
                    answers = ips.len(),
                    "fake-ip allocated"
                );
                let ttl_secs = self.ttl.as_secs().min(u32::MAX as u64) as u32;
                let resp = build_ip_response(&ctx.raw_request, &ctx.question, &ips, ttl_secs);
                MiddlewareResult::Response(resp)
            }
            TYPE_SVCB | TYPE_HTTPS => MiddlewareResult::Response(build_empty_response(
                &ctx.raw_request,
                Some(&ctx.question),
            )),
            _ => MiddlewareResult::Continue,
        }
    }
}

/* ---------- Mapping Middleware ---------- */

pub struct MappingMiddleware {
    mapping: Arc<IpHostMapping>,
    fake_pool: Option<Arc<FakeIpPool>>,
}

impl MappingMiddleware {
    pub fn new(mapping: Arc<IpHostMapping>, fake_pool: Option<Arc<FakeIpPool>>) -> Self {
        Self { mapping, fake_pool }
    }
}

#[async_trait]
impl DnsMiddleware for MappingMiddleware {
    async fn process(&self, ctx: &mut DnsRequestCtx) -> MiddlewareResult {
        // This middleware doesn't intercept — it records mappings from response_ips
        // set by the resolver middleware. It's called after resolver sets response_ips.
        if !ctx.response_ips.is_empty() {
            let ttl = ctx.response_ttl.max(Duration::from_secs(1));
            for ip in &ctx.response_ips {
                if is_global_unicast(*ip) {
                    self.mapping.insert(*ip, &ctx.question.name, ttl);
                    if let Some(pool) = &self.fake_pool {
                        pool.insert_mapping(*ip, &ctx.question.name, ttl);
                    }
                }
            }
        }
        MiddlewareResult::Continue
    }
}

/* ---------- Resolver Middleware ---------- */

pub struct ResolverMiddleware {
    resolver: Arc<Resolver>,
    mapping: Arc<IpHostMapping>,
    fake_pool: Option<Arc<FakeIpPool>>,
    ttl: Duration,
}

impl ResolverMiddleware {
    pub fn new(
        resolver: Arc<Resolver>,
        mapping: Arc<IpHostMapping>,
        fake_pool: Option<Arc<FakeIpPool>>,
        ttl: Duration,
    ) -> Self {
        Self {
            resolver,
            mapping,
            fake_pool,
            ttl,
        }
    }
}

#[async_trait]
impl DnsMiddleware for ResolverMiddleware {
    async fn process(&self, ctx: &mut DnsRequestCtx) -> MiddlewareResult {
        match ctx.question.qtype {
            TYPE_A | TYPE_AAAA => {
                let qtype = if ctx.question.qtype == TYPE_A {
                    QType::A
                } else {
                    QType::AAAA
                };
                match self
                    .resolver
                    .resolve_qtype_answer(&ctx.question.name, qtype)
                    .await
                {
                    Ok(answer) => {
                        let ttl = if answer.stale {
                            self.resolver.cache().config().stale_answer_ttl
                        } else {
                            self.ttl
                        };
                        // Store IP→host mapping for redir-host mode
                        let ttl_for_mapping = ttl.max(Duration::from_secs(1));
                        for ip in answer
                            .ips
                            .iter()
                            .copied()
                            .filter(|ip| is_global_unicast(*ip))
                        {
                            self.mapping.insert(ip, &ctx.question.name, ttl_for_mapping);
                            if let Some(pool) = &self.fake_pool {
                                pool.insert_mapping(ip, &ctx.question.name, ttl_for_mapping);
                            }
                        }
                        debug!(
                            target: "resolver::middleware",
                            host = %ctx.question.name,
                            qtype = ctx.question.qtype,
                            answers = answer.ips.len(),
                            stale = answer.stale,
                            "resolver response"
                        );
                        let ttl_secs = ttl.as_secs().min(u32::MAX as u64) as u32;
                        let resp = build_ip_response(
                            &ctx.raw_request,
                            &ctx.question,
                            &answer.ips,
                            ttl_secs,
                        );
                        MiddlewareResult::Response(resp)
                    }
                    Err(e) => {
                        debug!(
                            target: "resolver::middleware",
                            host = %ctx.question.name,
                            error = %e,
                            "resolver error"
                        );
                        MiddlewareResult::Response(build_empty_response(
                            &ctx.raw_request,
                            Some(&ctx.question),
                        ))
                    }
                }
            }
            _ => {
                use crate::packet::build_record_response;
                match self
                    .resolver
                    .resolve_records_answer(&ctx.question.name, ctx.question.qtype)
                    .await
                {
                    Ok(records) => {
                        let resp = build_record_response(&ctx.raw_request, &ctx.question, &records);
                        MiddlewareResult::Response(resp)
                    }
                    Err(_) => MiddlewareResult::Response(build_empty_response(
                        &ctx.raw_request,
                        Some(&ctx.question),
                    )),
                }
            }
        }
    }
}

fn is_global_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
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
        IpAddr::V6(ip) => {
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
