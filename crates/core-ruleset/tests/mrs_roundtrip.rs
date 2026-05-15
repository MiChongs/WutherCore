//! 端到端：用 mihomo 官方 `convert-ruleset` 工具把 yaml 转成 .mrs 后，验证
//! Rust 侧 [`core_ruleset::parser::mrs::parse`] 能读出且查询语义与 mihomo
//! 完全一致。
//!
//! 样本文件由仓库脚本预先生成（`build.cmd` 或手动 `mihomo convert-ruleset`），
//! 直接 commit 到 `tests/data/`。这样 CI 不需要 Go 环境。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use core_ruleset::{
    RulesetFormat,
    matcher::RulesetMatcher,
    parser::{RulesetCompiled, parse_ruleset_compiled},
};

fn load(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"))
}

#[test]
fn domain_mrs_round_trip_matches_mihomo_semantics() {
    let body = load("sample_domain.mrs");
    let compiled =
        parse_ruleset_compiled(RulesetFormat::Mrs, &body).expect("parse sample_domain.mrs");
    assert!(matches!(compiled, RulesetCompiled::Mrs(_)), "must be MRS");
    let matcher = RulesetMatcher::compile_any("sample_domain", compiled);

    // sample_domain.yaml 包含：
    //   baidu.com / qq.com / +.example.com / +.cn / www.bilibili.com / sub.test.org
    //
    // 命中：
    assert!(
        matcher.matches("baidu.com", None, None, None),
        "exact baidu.com"
    );
    assert!(
        matcher.matches("BAIDU.COM", None, None, None),
        "case insensitive"
    );
    assert!(matcher.matches("qq.com", None, None, None));
    assert!(matcher.matches("www.bilibili.com", None, None, None));
    // +.example.com → 任何子域命中（含本域）
    assert!(
        matcher.matches("example.com", None, None, None),
        "+.example.com base"
    );
    assert!(
        matcher.matches("a.example.com", None, None, None),
        "+.example.com sub"
    );
    assert!(
        matcher.matches("a.b.c.example.com", None, None, None),
        "+.example.com deep"
    );
    // +.cn → 任何 .cn 域名
    assert!(matcher.matches("anything.cn", None, None, None));
    assert!(matcher.matches("foo.bar.cn", None, None, None));
    // 不命中：
    assert!(!matcher.matches("google.com", None, None, None));
    assert!(!matcher.matches("notmatch.org", None, None, None));
    assert!(
        !matcher.matches("bilibili.com", None, None, None),
        "exact only on www.bilibili.com"
    );
}

#[test]
fn ipcidr_mrs_round_trip_matches_mihomo_semantics() {
    let body = load("sample_ipcidr.mrs");
    let compiled =
        parse_ruleset_compiled(RulesetFormat::Mrs, &body).expect("parse sample_ipcidr.mrs");
    let matcher = RulesetMatcher::compile_any("sample_ipcidr", compiled);

    // sample_ipcidr.yaml 包含：
    //   10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 1.1.1.1/32, 8.8.8.8/32,
    //   fc00::/7, 2001:db8::/32
    //
    // 命中：
    assert!(matcher.matches(
        "10.1.2.3",
        Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
        None,
        None
    ));
    assert!(matcher.matches(
        "172.20.30.40",
        Some(IpAddr::V4(Ipv4Addr::new(172, 20, 30, 40))),
        None,
        None
    ));
    assert!(matcher.matches(
        "192.168.0.1",
        Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))),
        None,
        None
    ));
    assert!(matcher.matches(
        "1.1.1.1",
        Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
        None,
        None
    ));
    assert!(matcher.matches(
        "8.8.8.8",
        Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        None,
        None
    ));
    // IPv6
    let fc00 = "fc00::1".parse::<Ipv6Addr>().unwrap();
    assert!(matcher.matches("fc00::1", Some(IpAddr::V6(fc00)), None, None));
    let dbg = "2001:db8::dead:beef".parse::<Ipv6Addr>().unwrap();
    assert!(matcher.matches("2001:db8::dead:beef", Some(IpAddr::V6(dbg)), None, None));

    // 不命中：
    assert!(!matcher.matches(
        "8.8.4.4",
        Some(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))),
        None,
        None
    ));
    assert!(!matcher.matches(
        "1.1.1.2",
        Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2))),
        None,
        None
    ));
    assert!(!matcher.matches(
        "11.0.0.1",
        Some(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))),
        None,
        None
    ));
    let public_v6 = "2606:4700::1111".parse::<Ipv6Addr>().unwrap();
    assert!(!matcher.matches("2606:4700::1111", Some(IpAddr::V6(public_v6)), None, None));
}

#[test]
fn mrs_stats_includes_count() {
    let body = load("sample_domain.mrs");
    let compiled = parse_ruleset_compiled(RulesetFormat::Mrs, &body).unwrap();
    let matcher = RulesetMatcher::compile_any("dom", compiled);
    let stats = matcher.stats();
    // sample_domain.yaml 6 条记录 → MRS header.count = 6
    assert_eq!(stats.domains, 6, "domain count from MRS header");
}
