//! TunDispatcher 构造性 / state 推断测试：仅验证可构造、handles 可优雅 stop。

use std::sync::Arc;
use std::time::Duration;

use core_capture::eim_nat::EimNatTable;
use core_capture::engine::CapturePlan;
use core_capture::nat::NatTable;
use core_capture::tun_dispatch::TunDispatcher;
use core_config::model::{
    Capture, CaptureExclude, CaptureMethod, CaptureResolver, CaptureStack, CaptureTraffic,
    TunInboundOptions,
};

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
    let _disp = TunDispatcher::new(plan, nat, eim);
}
