//! 集成测试：smoltcp 用户态栈与虚拟设备的端到端 happy-path。

use core_capture::stack::{UserSpaceStack, VirtualTunDevice};
use smoltcp::{
    phy::{Device, RxToken, TxToken},
    time::Instant as SmolInstant,
    wire::{Ipv4Address, Ipv6Address},
};

#[test]
fn user_stack_can_be_polled_with_listener() {
    let mut stack = UserSpaceStack::new(
        1500,
        Ipv4Address::new(198, 18, 0, 1),
        Some(Ipv6Address::new(0xfc00, 0, 1, 0, 0, 0, 0, 1)),
    );
    stack.ensure_listener_for(80, 1);
    for _ in 0..3 {
        let _ = stack.poll();
    }
    // 空 socket 应没有 established 流
    assert!(stack.drain_accepted().is_empty());
}

#[test]
fn virtual_device_drains_outbound_after_tx() {
    let mut d = VirtualTunDevice::new(1500);
    let now = SmolInstant::from_millis(0);
    let tx = d.transmit(now).unwrap();
    tx.consume(8, |buf| buf.copy_from_slice(b"abcdefgh"));
    let outs: Vec<_> = d.drain_outbound().collect();
    assert_eq!(outs.len(), 1);
    assert_eq!(&outs[0], b"abcdefgh");
    // drain 后应清空
    assert!(d.drain_outbound().next().is_none());
}

#[test]
fn virtual_device_rx_token_consumes_injected_packet() {
    let mut d = VirtualTunDevice::new(1500);
    d.inject(b"\x45\x00\x00\x14".to_vec()); // 假装一个 IPv4 头前 4 字节
    let now = SmolInstant::from_millis(0);
    let (rx, _tx) = d.receive(now).expect("rx");
    let mut got = Vec::new();
    rx.consume(|buf| got.extend_from_slice(buf));
    assert_eq!(got.len(), 4);
    assert_eq!(got[0] >> 4, 4); // version=4
}
