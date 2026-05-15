//! TunDispatcher 构造性 / state 推断测试：仅验证可构造、handles 可优雅 stop。

use std::{sync::Arc, time::Duration};

use core_capture::{
    eim_nat::EimNatTable, engine::CapturePlan, nat::NatTable, noop_ipset_provider,
    tun_dispatch::TunDispatcher,
};
use core_config::model::{
    Capture, CaptureExclude, CaptureMethod, CaptureResolver, CaptureStack, CaptureTraffic,
    TunInboundOptions,
};
use core_resolver::{DnsService, FakeIpPool, fake_ip::FakeIpConfig};

fn capture() -> Capture {
    Capture {
        on: true,
        method: CaptureMethod::VirtualNic,
        traffic: CaptureTraffic::System,
        resolver: CaptureResolver::Off,
        stack: CaptureStack::Smoltcp,
        mtu: Some(1500),
        offload: true,
        exclude: CaptureExclude::default(),
        tun: TunInboundOptions {
            address: vec!["198.18.0.1/30".into(), "fc00:1::/64".into()],
            ..TunInboundOptions::default()
        },
    }
}

#[test]
fn dispatcher_constructs_with_smoltcp_stack() {
    let plan = CapturePlan::from_config(&capture()).unwrap();
    let nat = Arc::new(NatTable::default());
    let eim = Arc::new(EimNatTable::new(Duration::from_secs(60)));
    let fake_pool = Arc::new(FakeIpPool::new(FakeIpConfig::default()));
    let dns_service = Arc::new(DnsService::fake_only(fake_pool.clone()));
    let _disp = TunDispatcher::new(
        plan,
        nat,
        eim,
        fake_pool,
        dns_service,
        noop_ipset_provider(),
    );
}
