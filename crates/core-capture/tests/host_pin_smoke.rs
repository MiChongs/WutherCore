//! Smart NAT pinning：同 host 在 udp_timeout 内复用同一 outbound。

use core_capture::nat::NatTable;
use std::time::Duration;

#[test]
fn pin_and_lookup_host() {
    let nat = NatTable::new(Duration::from_secs(60));
    nat.pin_host("example.com", "Proxy-A");
    assert_eq!(nat.lookup_pin("example.com").as_deref(), Some("Proxy-A"));
    // 重新 pin 覆盖旧值。
    nat.pin_host("example.com", "Proxy-B");
    assert_eq!(nat.lookup_pin("example.com").as_deref(), Some("Proxy-B"));
}

#[test]
fn purge_drops_expired_pin() {
    let nat = NatTable::new(Duration::from_millis(20));
    nat.pin_host("a.test", "P");
    std::thread::sleep(Duration::from_millis(40));
    let removed = nat.purge();
    assert!(removed >= 1);
    assert!(nat.lookup_pin("a.test").is_none());
}

#[test]
fn unrelated_hosts_do_not_collide() {
    let nat = NatTable::new(Duration::from_secs(60));
    nat.pin_host("a.test", "P-a");
    nat.pin_host("b.test", "P-b");
    assert_eq!(nat.lookup_pin("a.test").as_deref(), Some("P-a"));
    assert_eq!(nat.lookup_pin("b.test").as_deref(), Some("P-b"));
}
