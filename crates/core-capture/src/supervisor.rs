//! CaptureSupervisor —— 把 [`CaptureEngine`] 与 [`Runtime`] 串起来。
//!
//! 流程：
//! 1. 由配置生成 [`CapturePlan`]；
//! 2. 平台 `build_engine` 创建 engine；
//! 3. spawn 一条事件协程：每一个 [`CaptureEvent`] →
//!    a) 路由白/黑名单（`route_address(_set)` / `route_exclude_address(_set)`）→
//!    b) `loopback_address` 跳过 → c) NAT 写入（5-tuple 索引 + 可选 EIM）→
//!    d) 调用 `runtime.dial`（fake-host / fake-IP 还原）；
//! 4. （可选）启动 fake-dns server；
//! 5. 周期性 NAT / EIM purge（GC）。
//!
//! 通过 [`CaptureSupervisor::with_ip_set_provider`] 注入 `IpSetProvider`
//! 后，supervisor 会按集合名查询 ruleset（动态 IP 集）。

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Instant;

use core_config::model::{Capture, Mesh};
use core_resolver::fake_ip::{FakeIpConfig, FakeIpPool};
use core_runtime::Runtime;
use parking_lot::RwLock;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::eim_nat::EimNatTable;
use crate::engine::{CaptureEngine, CaptureError, CaptureEvent, CapturePlan, EngineKind};
use crate::ipset::{noop, IpSetProvider};
use crate::nat::{NatEntry, NatTable};
use crate::sys_proxy::SystemProxyGuard;
use crate::tun_dispatch::{TunDispatcher, TunDispatcherHandles};

pub struct CaptureSupervisor {
    pub plan: CapturePlan,
    pub engine: Arc<dyn CaptureEngine>,
    pub fake_pool: Arc<FakeIpPool>,
    pub nat: Arc<NatTable>,
    pub eim: Arc<EimNatTable>,
    ipset: RwLock<Arc<dyn IpSetProvider>>,
    handle: parking_lot::Mutex<Option<JoinHandle<()>>>,
    stopper: parking_lot::Mutex<Option<oneshot::Sender<()>>>,
    dns_handle: parking_lot::Mutex<Option<JoinHandle<()>>>,
    purge_handle: parking_lot::Mutex<Option<JoinHandle<()>>>,
    /// 当 stack=gvisor/mixed/smoltcp 且 engine 暴露了 TunIo 时，dispatcher 接管 TUN。
    dispatcher: parking_lot::Mutex<Option<TunDispatcherHandles>>,
    /// platform.http_proxy 启用时持有的系统 proxy 还原句柄。
    sys_proxy: parking_lot::Mutex<Option<SystemProxyGuard>>,
}

impl CaptureSupervisor {
    /// 由 capture+mesh 配置 + Runtime 生成 supervisor。off 时返回 None。
    pub fn build(capture: &Capture, _mesh: &Mesh) -> Result<Option<Arc<Self>>, CaptureError> {
        let plan = CapturePlan::from_config(capture)?;
        if plan.kind == EngineKind::None {
            return Ok(None);
        }
        let engine = crate::platform::build_engine(plan.clone())?;
        let pool = Arc::new(FakeIpPool::new(FakeIpConfig {
            v4_cidr: plan.tun_v4_cidr,
            v6_cidr: plan.tun_v6_cidr,
            ..FakeIpConfig::default()
        }));
        // udp_timeout 同步驱动 NAT + EIM-NAT TTL。
        let nat = Arc::new(NatTable::new(plan.udp_timeout));
        let eim = Arc::new(EimNatTable::new(plan.udp_timeout));
        Ok(Some(Arc::new(Self {
            plan,
            engine,
            fake_pool: pool,
            nat,
            eim,
            ipset: RwLock::new(noop()),
            handle: parking_lot::Mutex::new(None),
            stopper: parking_lot::Mutex::new(None),
            dns_handle: parking_lot::Mutex::new(None),
            purge_handle: parking_lot::Mutex::new(None),
            dispatcher: parking_lot::Mutex::new(None),
            sys_proxy: parking_lot::Mutex::new(None),
        })))
    }

    /// 注入 IP 集合 provider（main.rs 用 RulesetIndex 桥接）。
    pub fn set_ip_set_provider(&self, p: Arc<dyn IpSetProvider>) {
        *self.ipset.write() = p;
    }

    /// 综合判断：route_address(_set) + route_exclude_address(_set) + loopback。
    fn allow_ip(&self, ip: IpAddr) -> bool {
        // 1. loopback_address：明确不接管。
        if self.plan.loopback_addresses.contains(&ip) {
            return false;
        }
        // 2. CIDR 黑名单
        if self
            .plan
            .route_exclude_addresses
            .iter()
            .any(|n| n.contains(&ip))
        {
            return false;
        }
        // 3. 动态 IP 集黑名单
        let ipset = self.ipset.read().clone();
        for set in &self.plan.route_exclude_address_set {
            if ipset.contains(set, ip) {
                return false;
            }
        }
        // 4. 白名单（CIDR + set 任一命中即可）。空白名单 = 全开放。
        if self.plan.route_addresses.is_empty() && self.plan.route_address_set.is_empty() {
            return true;
        }
        if self.plan.route_addresses.iter().any(|n| n.contains(&ip)) {
            return true;
        }
        for set in &self.plan.route_address_set {
            if ipset.contains(set, ip) {
                return true;
            }
        }
        false
    }

    /// 启动 capture：让 engine 就绪，并把事件转发给 runtime.dial。
    pub async fn start(self: &Arc<Self>, runtime: Arc<Runtime>) -> Result<(), CaptureError> {
        let (tx, mut rx) = mpsc::channel::<CaptureEvent>(1024);
        let (stop_tx, mut stop_rx) = oneshot::channel();
        self.engine.clone().start(tx, runtime.clone()).await?;

        // platform.http_proxy 透传 —— 系统级 HTTP/HTTPS proxy 写入。
        if let Some(http_opts) = &self.plan.platform_http_proxy {
            let guard = SystemProxyGuard::install(http_opts);
            *self.sys_proxy.lock() = Some(guard);
        }

        // stack = gvisor / mixed / smoltcp（且引擎是 TUN 且暴露了底层设备）→
        // 启用用户态栈：TunDispatcher 接管 TUN 读写、TCP user-stack splice、UDP forwarder。
        let want_user_stack = matches!(
            self.plan.stack,
            core_config::model::CaptureStack::Gvisor
                | core_config::model::CaptureStack::Mixed
                | core_config::model::CaptureStack::Smoltcp
        );
        if want_user_stack {
            if let Some(tun_io) = self.engine.tun_io() {
                let disp = Arc::new(TunDispatcher::new(
                    self.plan.clone(),
                    self.nat.clone(),
                    self.eim.clone(),
                    self.fake_pool.clone(),
                ));
                let handles = disp.start(tun_io, runtime.clone());
                *self.dispatcher.lock() = Some(handles);
                info!(
                    target: "capture",
                    stack = ?self.plan.stack,
                    "user-stack dispatcher attached (TCP user-stack + UDP forwarder)"
                );
            } else {
                warn!(
                    target: "capture",
                    stack = ?self.plan.stack,
                    "user-stack requested but engine has no TunIo; falling back to dispatch-only"
                );
            }
        }

        let _ = runtime; // 保留参数；TUN+user-stack 模式由 TunDispatcher 自带 dial+splice。
        let pool = self.fake_pool.clone();
        let nat = self.nat.clone();
        let sup = self.clone();
        let handle = tokio::spawn(async move {
            // 本 loop 仅做 NAT 登记 + 调试日志：实际的 dial+splice 由
            //   * TUN+user-stack:  `TunDispatcher::run_accept_consumer`
            //   * TPROXY/Redirect: 平台 listener 自身（带 Arc<Runtime>，未来扩展）
            // 负责。绝对不能在此处 `runtime.dial(..).drop(stream)` —— 之前那条
            // 路径会建一条到代理服务器的 TCP，但永远不把它 splice 给真正的
            // 入站连接，导致"拨号成功，应用却收不到任何数据"。
            loop {
                tokio::select! {
                    _ = &mut stop_rx => break,
                    event = rx.recv() => {
                        let Some(evt) = event else { break };
                        if !sup.allow_ip(evt.original_dst.ip()) {
                            tracing::debug!(
                                target: "capture::dispatch",
                                ip = %evt.original_dst.ip(),
                                "skipped by route rules / loopback / ipset"
                            );
                            continue;
                        }
                        let now = Instant::now();
                        let nat_id = nat.insert(NatEntry {
                            source: evt.source,
                            original_dst: evt.original_dst,
                            fake_host: evt.fake_host.clone(),
                            network: evt.network,
                            created_at: now,
                            last_seen: now,
                        });
                        // 与 tun_dispatch 同源：调 build_dial_target 走完整 mihomo
                        // preHandleMetadata 等价语义（fake-IP 反查 + missing 检测）。
                        let target = crate::dial_meta::build_dial_target(
                            &pool,
                            evt.original_dst,
                            evt.fake_host.as_deref(),
                        );
                        if target.fake_ip_missing {
                            tracing::warn!(
                                target: "capture::dispatch",
                                ip = %evt.original_dst.ip(),
                                "fake DNS record missing; skip dispatch"
                            );
                            continue;
                        }
                        let host = target.host;
                        debug!(
                            target: "capture::dispatch",
                            host = %host,
                            port = evt.original_dst.port(),
                            net = evt.network,
                            nat_id,
                            "flow seen (NAT registered; actual dial owned by stack/listener)"
                        );
                    }
                }
            }
        });
        *self.handle.lock() = Some(handle);
        *self.stopper.lock() = Some(stop_tx);

        // 可选 fake-dns
        if self.plan.hijack_dns {
            let pool = self.fake_pool.clone();
            let dns_handle = tokio::spawn(async move {
                let bind: SocketAddr = "127.0.0.1:5454".parse().unwrap();
                if let Err(e) = crate::fakeip_dns::run_fake_dns(bind, pool).await {
                    warn!(target: "capture::dns", error = %e, "fake-dns exited");
                }
            });
            *self.dns_handle.lock() = Some(dns_handle);
        }

        // NAT + EIM-NAT 周期性 purge：udp_timeout/2，下限 5s。
        let purge_period = std::cmp::max(
            std::time::Duration::from_secs(5),
            self.plan.udp_timeout / 2,
        );
        let nat_for_gc = self.nat.clone();
        let eim_for_gc = self.eim.clone();
        let purge_handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(purge_period);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                let r1 = nat_for_gc.purge();
                let r2 = eim_for_gc.purge();
                if r1 + r2 > 0 {
                    debug!(
                        target: "capture::nat",
                        nat_removed = r1,
                        eim_removed = r2,
                        nat_remaining = nat_for_gc.len(),
                        eim_remaining = eim_for_gc.len(),
                        "purge"
                    );
                }
            }
        });
        *self.purge_handle.lock() = Some(purge_handle);

        info!(
            target: "capture",
            kind = ?self.plan.kind,
            iface = %self.plan.interface_name,
            mtu = self.plan.mtu,
            hijack_dns = self.plan.hijack_dns,
            eim_nat = self.plan.endpoint_independent_nat,
            "capture supervisor running"
        );
        Ok(())
    }

    pub async fn stop(self: &Arc<Self>) -> Result<(), CaptureError> {
        if let Some(g) = self.sys_proxy.lock().take() {
            g.revert();
        }
        if let Some(disp) = self.dispatcher.lock().take() {
            disp.stop();
        }
        if let Some(tx) = self.stopper.lock().take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.lock().take() {
            h.abort();
        }
        if let Some(h) = self.dns_handle.lock().take() {
            h.abort();
        }
        if let Some(h) = self.purge_handle.lock().take() {
            h.abort();
        }
        self.engine.clone().stop().await?;
        Ok(())
    }

    pub fn report(&self) -> serde_json::Value {
        serde_json::json!({
            "engine": self.engine.report(),
            "fake_pool_size": self.fake_pool.len(),
            "nat_size": self.nat.len(),
            "eim_size": self.eim.len(),
            "exclude_cidrs": self.plan.exclude_cidrs.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
            "route_address_sets": self.plan.route_address_set.clone(),
            "route_exclude_address_sets": self.plan.route_exclude_address_set.clone(),
            "ipset_known": self.ipset.read().names(),
            "hijack_dns": self.plan.hijack_dns,
            "endpoint_independent_nat": self.plan.endpoint_independent_nat,
            "host_pin_size": self.nat.host_pin.len(),
            "sys_proxy_active": self.sys_proxy.lock().is_some(),
        })
    }
}

/// 工具：把字符串地址解析。
pub fn first_addr(s: &str) -> Option<SocketAddr> {
    s.to_socket_addrs().ok().and_then(|mut it| it.next())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_config::model::{
        Capture, CaptureExclude, CaptureMethod, CaptureResolver, CaptureStack, CaptureTraffic,
        TunInboundOptions,
    };
    use std::net::IpAddr;

    fn capture() -> Capture {
        Capture {
            on: true,
            method: CaptureMethod::VirtualNic,
            traffic: CaptureTraffic::System,
            resolver: CaptureResolver::Off,
            stack: CaptureStack::System,
            mtu: None,
            offload: true,
            exclude: CaptureExclude::default(),
            tun: TunInboundOptions::default(),
        }
    }

    #[derive(Debug)]
    struct FakeSet(Vec<(String, IpAddr)>);
    impl IpSetProvider for FakeSet {
        fn contains(&self, name: &str, ip: IpAddr) -> bool {
            self.0.iter().any(|(n, i)| n == name && *i == ip)
        }
    }

    #[test]
    fn allow_ip_loopback_blocked() {
        let mut c = capture();
        c.tun.loopback_address = vec!["10.7.0.1".into()];
        let plan = CapturePlan::from_config(&c).unwrap();
        let pool = Arc::new(FakeIpPool::new(FakeIpConfig {
            v4_cidr: plan.tun_v4_cidr,
            v6_cidr: plan.tun_v6_cidr,
            ..FakeIpConfig::default()
        }));
        let sup = CaptureSupervisor {
            plan,
            engine: dummy_engine(),
            fake_pool: pool,
            nat: Arc::new(NatTable::default()),
            eim: Arc::new(EimNatTable::new(std::time::Duration::from_secs(60))),
            ipset: RwLock::new(noop()),
            handle: parking_lot::Mutex::new(None),
            stopper: parking_lot::Mutex::new(None),
            dns_handle: parking_lot::Mutex::new(None),
            purge_handle: parking_lot::Mutex::new(None),
            dispatcher: parking_lot::Mutex::new(None),
            sys_proxy: parking_lot::Mutex::new(None),
        };
        assert!(!sup.allow_ip("10.7.0.1".parse().unwrap()));
        assert!(sup.allow_ip("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn allow_ip_uses_ipset_blacklist() {
        let mut c = capture();
        c.tun.route_exclude_address_set = vec!["geoip-cn".into()];
        let plan = CapturePlan::from_config(&c).unwrap();
        let pool = Arc::new(FakeIpPool::new(FakeIpConfig {
            v4_cidr: plan.tun_v4_cidr,
            v6_cidr: plan.tun_v6_cidr,
            ..FakeIpConfig::default()
        }));
        let sup = CaptureSupervisor {
            plan,
            engine: dummy_engine(),
            fake_pool: pool,
            nat: Arc::new(NatTable::default()),
            eim: Arc::new(EimNatTable::new(std::time::Duration::from_secs(60))),
            ipset: RwLock::new(Arc::new(FakeSet(vec![(
                "geoip-cn".into(),
                "114.114.114.114".parse().unwrap(),
            )]))),
            handle: parking_lot::Mutex::new(None),
            stopper: parking_lot::Mutex::new(None),
            dns_handle: parking_lot::Mutex::new(None),
            purge_handle: parking_lot::Mutex::new(None),
            dispatcher: parking_lot::Mutex::new(None),
            sys_proxy: parking_lot::Mutex::new(None),
        };
        assert!(!sup.allow_ip("114.114.114.114".parse().unwrap()));
        assert!(sup.allow_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn allow_ip_whitelist_via_ipset() {
        let mut c = capture();
        c.tun.route_address_set = vec!["geoip-cloudflare".into()];
        let plan = CapturePlan::from_config(&c).unwrap();
        let pool = Arc::new(FakeIpPool::new(FakeIpConfig {
            v4_cidr: plan.tun_v4_cidr,
            v6_cidr: plan.tun_v6_cidr,
            ..FakeIpConfig::default()
        }));
        let sup = CaptureSupervisor {
            plan,
            engine: dummy_engine(),
            fake_pool: pool,
            nat: Arc::new(NatTable::default()),
            eim: Arc::new(EimNatTable::new(std::time::Duration::from_secs(60))),
            ipset: RwLock::new(Arc::new(FakeSet(vec![(
                "geoip-cloudflare".into(),
                "1.1.1.1".parse().unwrap(),
            )]))),
            handle: parking_lot::Mutex::new(None),
            stopper: parking_lot::Mutex::new(None),
            dns_handle: parking_lot::Mutex::new(None),
            purge_handle: parking_lot::Mutex::new(None),
            dispatcher: parking_lot::Mutex::new(None),
            sys_proxy: parking_lot::Mutex::new(None),
        };
        assert!(sup.allow_ip("1.1.1.1".parse().unwrap()));
        assert!(!sup.allow_ip("8.8.8.8".parse().unwrap()));
    }

    fn dummy_engine() -> Arc<dyn CaptureEngine> {
        struct Dummy;
        #[async_trait::async_trait]
        impl CaptureEngine for Dummy {
            fn kind(&self) -> EngineKind {
                EngineKind::Tun
            }
            fn plan(&self) -> &CapturePlan {
                panic!("not used in test")
            }
            async fn start(
                self: Arc<Self>,
                _events: mpsc::Sender<CaptureEvent>,
                _runtime: Arc<core_runtime::Runtime>,
            ) -> Result<(), CaptureError> {
                Ok(())
            }
            async fn stop(self: Arc<Self>) -> Result<(), CaptureError> {
                Ok(())
            }
        }
        Arc::new(Dummy)
    }
}
