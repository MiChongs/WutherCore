//! 内核级身份旁路（identity bypass）—— root TUN 模式下排除特定 UID/GID/Package
//! 的流量，使其在内核侧就绕开 TUN，根本不会进入用户空间 dispatcher。
//!
//! ## 设计
//!
//! `install_auto_route()` 已经安装了一条 `ip rule add fwmark <out_mark> lookup
//! main pref <bypass_prio>`，目的是让代理出站 socket（带 SO_MARK = out_mark）
//! 走主路由表绕开 TUN。本模块复用同一个 `out_mark`：在 `iptables -t mangle
//! -A OUTPUT -m owner --uid-owner X -j MARK --set-xmark <mark>/<mask>` 给
//! 命中的包打标。当 `MARK` 改变 `skb->mark` 后，内核 `iptable_mangle`
//! `ipt_mangle_out` 会调用 `ip_route_me_harder` 重做路由决策——根据 fwmark
//! 命中 main 表，包从物理 NIC 出站，不再经过 TUN。
//!
//! ## 与 mihomo / sing-tun 对齐
//!
//! sing-tun 的 `redirect_nftables_rules.go` 在 OUTPUT/mangle 链里对
//! `MetaKeySKUID` / `MetaKeySKGID` 做匹配；命中 `IncludeUID` 反集或
//! `ExcludeUID` 命中后 `Verdict: Return`。这对应 mihomo `IncludePackage` /
//! `ExcludePackage` → 不进 VPN 的语义。我们用 iptables 等价表达，对 Android
//! root 与裸 Linux 都生效（iptables-nft 兼容层在桌面 Linux 上同样工作）。
//!
//! ## 语义
//!
//! - `exclude_*` 命中：标记 → bypass（不进 TUN，走真实出站）
//! - `include_*` 非空但不命中：同样标记 → bypass
//! - 两者都不命中：不标记 → 进 TUN（被代理）
//!
//! 这与 user-space `UidPacketFilter::FilterDecision::Bypass` 语义一致；用户
//! 态那条路径仅作为兜底（理论上不会触发，因为内核已经把包转走）。

#![cfg(any(target_os = "linux", target_os = "android"))]

use std::{collections::HashMap, process::Command};

use tracing::{debug, info, warn};

use crate::engine::{CaptureFilters, CapturePlan};

const CHAIN_NAME: &str = "WUTHERCORE_BYPASS";
const PHASE: &str = "root-tun.identity-bypass";

#[derive(Debug, Default)]
pub struct InstallReport {
    /// 安装/可用的 iptables 二进制集合（"iptables" / "ip6tables"）。
    pub backends: Vec<&'static str>,
    /// 解析后用于匹配的 UID 数（包含 exclude_package 解析得到的 Android UID）。
    pub resolved_excluded_uids: usize,
    /// 是否任何后端的全部规则都成功安装。失败也安装一部分，由 revert 兜底。
    pub all_ok: bool,
}

/// 安装内核级 identity bypass 规则（在 OUTPUT/mangle 链上为 excluded
/// UID/GID/package 打 fwmark = `mark`，触发 ip rule 走 main 表绕过 TUN）。
///
/// 仅在 `auto_route` 启用时调用才有意义：`install_auto_route` 已经在
/// 同样的 `out_mark` 上注册了 `ip rule add fwmark ... lookup main` —— 我们
/// 的 MARK 自动接力到那条规则。
pub fn install(plan: &CapturePlan, mark: u32) -> InstallReport {
    let filters = &plan.filters;
    if !has_identity_filters(filters) {
        return InstallReport::default();
    }

    let resolved_excl_uids = resolve_excluded_uids(filters);
    let resolved_incl_uids = resolve_included_uids(filters);
    let mark_s = format!("{:#x}", mark);
    let mark_xmark = format!("{:#x}/{:#x}", mark, mark);

    info!(
        target: "capture::linux::identity-bypass",
        mark = %mark_s,
        excl_uids = resolved_excl_uids.len(),
        excl_uid_ranges = filters.exclude_uid_range.len(),
        excl_gids = filters.exclude_gid.len(),
        excl_gid_ranges = filters.exclude_gid_range.len(),
        incl_uids = resolved_incl_uids.len(),
        incl_uid_ranges = filters.include_uid_range.len(),
        incl_gids = filters.include_gid.len(),
        incl_gid_ranges = filters.include_gid_range.len(),
        "installing kernel-level identity bypass via iptables OUTPUT/mangle MARK"
    );

    let mut report = InstallReport {
        all_ok: true,
        resolved_excluded_uids: resolved_excl_uids.len(),
        ..Default::default()
    };
    for ipt in iptables_binaries() {
        // 旧规则清理（防御性，避免重复 -I OUTPUT）。
        revert_for_family(ipt);
        let ok = install_for_family(
            ipt,
            &mark_s,
            &mark_xmark,
            &resolved_excl_uids,
            &resolved_incl_uids,
            filters,
        );
        if ok {
            report.backends.push(ipt);
        } else {
            report.all_ok = false;
            warn!(
                target: "capture::linux::identity-bypass",
                backend = ipt,
                "some identity bypass rules failed to install (continuing)"
            );
        }
    }
    if report.backends.is_empty() {
        warn!(
            target: "capture::linux::identity-bypass",
            "no iptables backend available — identity bypass NOT installed at kernel level; \
             user-space TunInbound will still bypass these packets but they'll already be inside TUN"
        );
        report.all_ok = false;
    }
    report
}

pub fn revert(plan: &CapturePlan) {
    if !has_identity_filters(&plan.filters) {
        return;
    }
    debug!(
        target: "capture::linux::identity-bypass",
        "reverting kernel-level identity bypass"
    );
    for ipt in iptables_binaries() {
        revert_for_family(ipt);
    }
}

fn has_identity_filters(filters: &CaptureFilters) -> bool {
    crate::resource_claims::has_linux_identity_filters(filters)
}

fn install_for_family(
    ipt: &str,
    mark_s: &str,
    mark_xmark: &str,
    excl_uids: &[u32],
    incl_uids: &[u32],
    filters: &CaptureFilters,
) -> bool {
    let mut all_ok = true;

    // 1. 创建链（如果存在则忽略 EEXIST）
    let _ = run_quiet(ipt, &["-t", "mangle", "-N", CHAIN_NAME]);
    let _ = run_quiet(ipt, &["-t", "mangle", "-F", CHAIN_NAME]);

    // 2. 幂等保护：若已有 bypass mark 则直接 RETURN
    let r = run_quiet(
        ipt,
        &[
            "-t", "mangle", "-A", CHAIN_NAME, "-m", "mark", "--mark", mark_s, "-j", "RETURN",
        ],
    );
    all_ok &= ok(&r);

    // 3. 排除规则：命中即打 mark + RETURN（不再进入 include 段）
    for uid in excl_uids {
        let val = uid.to_string();
        all_ok &= ok(&run_quiet(
            ipt,
            &[
                "-t",
                "mangle",
                "-A",
                CHAIN_NAME,
                "-m",
                "owner",
                "--uid-owner",
                &val,
                "-j",
                "MARK",
                "--set-xmark",
                mark_xmark,
            ],
        ));
    }
    for (lo, hi) in &filters.exclude_uid_range {
        let val = format!("{lo}-{hi}");
        all_ok &= ok(&run_quiet(
            ipt,
            &[
                "-t",
                "mangle",
                "-A",
                CHAIN_NAME,
                "-m",
                "owner",
                "--uid-owner",
                &val,
                "-j",
                "MARK",
                "--set-xmark",
                mark_xmark,
            ],
        ));
    }
    for gid in &filters.exclude_gid {
        let val = gid.to_string();
        all_ok &= ok(&run_quiet(
            ipt,
            &[
                "-t",
                "mangle",
                "-A",
                CHAIN_NAME,
                "-m",
                "owner",
                "--gid-owner",
                &val,
                "-j",
                "MARK",
                "--set-xmark",
                mark_xmark,
            ],
        ));
    }
    for (lo, hi) in &filters.exclude_gid_range {
        let val = format!("{lo}-{hi}");
        all_ok &= ok(&run_quiet(
            ipt,
            &[
                "-t",
                "mangle",
                "-A",
                CHAIN_NAME,
                "-m",
                "owner",
                "--gid-owner",
                &val,
                "-j",
                "MARK",
                "--set-xmark",
                mark_xmark,
            ],
        ));
    }
    // 排除段命中后退出（mark 已在上一条规则被设置）
    let r = run_quiet(
        ipt,
        &[
            "-t", "mangle", "-A", CHAIN_NAME, "-m", "mark", "--mark", mark_s, "-j", "RETURN",
        ],
    );
    all_ok &= ok(&r);

    // 4. 包含段：仅当 include_uid/gid 非空时启用"白名单"语义。
    // 命中 include 的包 RETURN（不打标 → 进 TUN）；其它包尾部 catch-all 打标 → bypass。
    let has_include = !incl_uids.is_empty()
        || !filters.include_uid_range.is_empty()
        || !filters.include_gid.is_empty()
        || !filters.include_gid_range.is_empty();

    if has_include {
        for uid in incl_uids {
            let val = uid.to_string();
            all_ok &= ok(&run_quiet(
                ipt,
                &[
                    "-t",
                    "mangle",
                    "-A",
                    CHAIN_NAME,
                    "-m",
                    "owner",
                    "--uid-owner",
                    &val,
                    "-j",
                    "RETURN",
                ],
            ));
        }
        for (lo, hi) in &filters.include_uid_range {
            let val = format!("{lo}-{hi}");
            all_ok &= ok(&run_quiet(
                ipt,
                &[
                    "-t",
                    "mangle",
                    "-A",
                    CHAIN_NAME,
                    "-m",
                    "owner",
                    "--uid-owner",
                    &val,
                    "-j",
                    "RETURN",
                ],
            ));
        }
        for gid in &filters.include_gid {
            let val = gid.to_string();
            all_ok &= ok(&run_quiet(
                ipt,
                &[
                    "-t",
                    "mangle",
                    "-A",
                    CHAIN_NAME,
                    "-m",
                    "owner",
                    "--gid-owner",
                    &val,
                    "-j",
                    "RETURN",
                ],
            ));
        }
        for (lo, hi) in &filters.include_gid_range {
            let val = format!("{lo}-{hi}");
            all_ok &= ok(&run_quiet(
                ipt,
                &[
                    "-t",
                    "mangle",
                    "-A",
                    CHAIN_NAME,
                    "-m",
                    "owner",
                    "--gid-owner",
                    &val,
                    "-j",
                    "RETURN",
                ],
            ));
        }
        // catch-all：未命中 include → 打标
        let r = run_quiet(
            ipt,
            &[
                "-t",
                "mangle",
                "-A",
                CHAIN_NAME,
                "-j",
                "MARK",
                "--set-xmark",
                mark_xmark,
            ],
        );
        all_ok &= ok(&r);
    }

    // 5. 接入 OUTPUT 链（顶部 -I 让本链率先生效）
    let r = run_quiet(ipt, &["-t", "mangle", "-I", "OUTPUT", "-j", CHAIN_NAME]);
    all_ok &= ok(&r);

    if all_ok {
        debug!(
            target: "capture::linux::identity-bypass",
            backend = ipt,
            "identity bypass chain installed"
        );
    }
    all_ok
}

fn revert_for_family(ipt: &str) {
    // 先解除 OUTPUT 引用，再 flush + 删除链。
    let _ = run_quiet(ipt, &["-t", "mangle", "-D", "OUTPUT", "-j", CHAIN_NAME]);
    let _ = run_quiet(ipt, &["-t", "mangle", "-F", CHAIN_NAME]);
    let _ = run_quiet(ipt, &["-t", "mangle", "-X", CHAIN_NAME]);
}

fn iptables_binaries() -> Vec<&'static str> {
    let mut out = Vec::new();
    if has_tool("iptables") {
        out.push("iptables");
    }
    if has_tool("ip6tables") {
        out.push("ip6tables");
    }
    out
}

fn has_tool(name: &str) -> bool {
    let r = Command::new(name).arg("--version").output();
    matches!(r, Ok(o) if o.status.success())
}

fn run_quiet(prog: &str, args: &[&str]) -> Option<std::process::ExitStatus> {
    Command::new(prog)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok()
}

fn ok(s: &Option<std::process::ExitStatus>) -> bool {
    matches!(s, Some(s) if s.success())
}

fn resolve_excluded_uids(f: &CaptureFilters) -> Vec<u32> {
    let mut uids: Vec<u32> = f.exclude_uid.clone();
    if !f.exclude_package.is_empty() {
        let map = load_package_to_uid();
        for pkg in &f.exclude_package {
            if let Some(&uid) = map.get(pkg.as_str()) {
                debug!(
                    target: "capture::linux::identity-bypass",
                    package = %pkg,
                    uid,
                    "exclude_package resolved to uid"
                );
                // Apply per Android multi-user offsets (10000 step) when configured.
                if f.include_android_user.is_empty() {
                    uids.push(uid);
                } else {
                    for &user in &f.include_android_user {
                        uids.push(uid + user * ANDROID_USER_RANGE);
                    }
                }
            } else {
                debug!(
                    target: "capture::linux::identity-bypass",
                    package = %pkg,
                    "exclude_package not found in /data/system/packages.list (skipping kernel rule)"
                );
            }
        }
    }
    uids.sort_unstable();
    uids.dedup();
    uids
}

fn resolve_included_uids(f: &CaptureFilters) -> Vec<u32> {
    let mut uids: Vec<u32> = f.include_uid.clone();
    if !f.include_package.is_empty() {
        let map = load_package_to_uid();
        for pkg in &f.include_package {
            if let Some(&uid) = map.get(pkg.as_str()) {
                if f.include_android_user.is_empty() {
                    uids.push(uid);
                } else {
                    for &user in &f.include_android_user {
                        uids.push(uid + user * ANDROID_USER_RANGE);
                    }
                }
            }
        }
    }
    uids.sort_unstable();
    uids.dedup();
    uids
}

const ANDROID_USER_RANGE: u32 = 100_000;

#[cfg(target_os = "android")]
fn load_package_to_uid() -> HashMap<String, u32> {
    let content = std::fs::read_to_string("/data/system/packages.list").unwrap_or_default();
    let mut map = HashMap::new();
    for line in content.lines() {
        let mut it = line.split_whitespace();
        let pkg = it.next().unwrap_or("");
        let uid_s = it.next().unwrap_or("");
        if pkg.is_empty() {
            continue;
        }
        if let Ok(uid) = uid_s.parse::<u32>() {
            map.insert(pkg.to_string(), uid);
        }
    }
    map
}

#[cfg(not(target_os = "android"))]
fn load_package_to_uid() -> HashMap<String, u32> {
    HashMap::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_filters() -> CaptureFilters {
        CaptureFilters {
            include_interface: vec![],
            exclude_interface: vec![],
            include_uid: vec![],
            include_uid_range: vec![],
            exclude_uid: vec![],
            exclude_uid_range: vec![],
            include_gid: vec![],
            include_gid_range: vec![],
            exclude_gid: vec![],
            exclude_gid_range: vec![],
            include_android_user: vec![],
            include_package: vec![],
            exclude_package: vec![],
            include_mac: vec![],
            exclude_mac: vec![],
        }
    }

    #[test]
    fn empty_filters_means_no_install() {
        let f = empty_filters();
        assert!(!has_identity_filters(&f));
    }

    #[test]
    fn detects_uid_filters() {
        let mut f = empty_filters();
        f.exclude_uid = vec![1000];
        assert!(has_identity_filters(&f));
    }

    #[test]
    fn detects_gid_filters() {
        let mut f = empty_filters();
        f.include_gid = vec![3003];
        assert!(has_identity_filters(&f));
    }

    #[test]
    fn detects_package_filters() {
        let mut f = empty_filters();
        f.exclude_package = vec!["com.example".into()];
        assert!(has_identity_filters(&f));
    }

    #[test]
    fn resolved_excluded_uids_dedup_and_sort() {
        let mut f = empty_filters();
        f.exclude_uid = vec![5000, 1000, 1000, 3000];
        let r = resolve_excluded_uids(&f);
        assert_eq!(r, vec![1000, 3000, 5000]);
    }

    #[test]
    fn resolved_excluded_uids_handles_android_user_offset() {
        let mut f = empty_filters();
        f.exclude_uid = vec![10001];
        f.include_android_user = vec![0, 10];
        // exclude_uid is *not* multiplied — only package resolution applies the offset
        let r = resolve_excluded_uids(&f);
        assert_eq!(r, vec![10001]);
    }
}
