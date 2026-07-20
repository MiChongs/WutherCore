//! Linux TUN `auto_redirect` 的 TCP NAT REDIRECT 规则后端。
//!
//! 这个模块只负责 TCP NAT 快路径，不创建策略路由，也不接管 UDP/ICMP。
//! TCP 被重定向到调用方已预绑定的本地临时端口；UDP/ICMP 是否进入 TUN
//! 由独立 policy-route lease 决定。这里的 `return` 只表示“不走 TCP REDIRECT”，绝不
//! 等价于绕过 TUN；调用方必须用 policy-route bypass/用户态策略补齐全协议
//! 语义，或在激活阶段拒绝无法补齐的配置。生产激活只使用经过校验后单批
//! 原子加载的 nftables；iptables/ip6tables 生成器保留测试覆盖，等待跨错误
//! lease 后再开放。任何路径都不生成 TPROXY、NFQUEUE、reset 或 packet mark。

use std::{
    collections::BTreeSet,
    fmt::Write as _,
    io::{self, Write as _},
    net::IpAddr,
    process::{Command, Stdio},
};

use core_config::model::{CaptureTraffic, DEFAULT_AUTO_REDIRECT_OUTPUT_MARK};

use crate::engine::{CaptureError, CapturePlan};

const NFT_TABLE: &str = "wuther_auto_redirect";
#[cfg(test)]
const IPTABLES_CHAIN: &str = "WUTHER_AUTO_REDIRECT";
#[cfg(test)]
const IPTABLES_HOOK_COMMENT: &str = "wuther:auto-redirect";
const MAX_INTERFACE_NAME_BYTES: usize = 15;
#[cfg(test)]
const MAX_IPTABLES_REDIRECT_RULES: usize = 4_096;

/// 调用方已预绑定的 TCP REDIRECT 监听端口。
///
/// IPv4 端口始终必须存在；仅当 TUN 计划启用 IPv6 且存在 IPv6 TUN 网段时
/// 才允许提供 IPv6 端口。端口 `0` 不是已绑定的临时端口，因此会被拒绝。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedirectPorts {
    pub ipv4: u16,
    pub ipv6: Option<u16>,
}

impl RedirectPorts {
    pub const fn new(ipv4: u16, ipv6: Option<u16>) -> Self {
        Self { ipv4, ipv6 }
    }
}

/// iptables 后端实际挂载的 netfilter hook。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoRedirectHook {
    Output,
    Prerouting,
}

impl AutoRedirectHook {
    #[cfg(test)]
    fn chain(self) -> &'static str {
        match self {
            Self::Output => "OUTPUT",
            Self::Prerouting => "PREROUTING",
        }
    }
}

/// 成功安装后的精确规则账本。
///
/// 生产后端仅使用 nftables 独立表作为清理边界。iptables 变体只在测试
/// fallback harness 中存在，用于验证未来事务账本的规则生成与回滚。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoRedirectBackend {
    Nftables,
    #[cfg(test)]
    Iptables {
        hook: AutoRedirectHook,
        ipv4: bool,
        ipv6: bool,
    },
}

/// 无 shell 的规则命令描述；参数始终逐项传给 `Command`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleCommand {
    program: &'static str,
    args: Vec<String>,
    stdin: Option<String>,
}

impl RuleCommand {
    fn new(program: &'static str, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            program,
            args: args.into_iter().map(Into::into).collect(),
            stdin: None,
        }
    }

    fn with_stdin(mut self, stdin: String) -> Self {
        self.stdin = Some(stdin);
        self
    }

    pub fn program(&self) -> &'static str {
        self.program
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }

    pub fn stdin(&self) -> Option<&str> {
        self.stdin.as_deref()
    }
}

/// 规则命令的最小执行结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleCommandOutput {
    pub success: bool,
    pub stderr: String,
}

impl RuleCommandOutput {
    #[cfg(test)]
    pub fn success() -> Self {
        Self {
            success: true,
            stderr: String::new(),
        }
    }

    #[cfg(test)]
    pub fn failure(stderr: impl Into<String>) -> Self {
        Self {
            success: false,
            stderr: stderr.into(),
        }
    }
}

/// 可替换的命令执行边界，便于验证失败回滚且保证生产路径不经过 shell。
pub trait RuleExecutor {
    fn execute(&self, command: &RuleCommand) -> io::Result<RuleCommandOutput>;
}

/// 使用 `std::process::Command` 的生产执行器。
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemRuleExecutor;

impl RuleExecutor for SystemRuleExecutor {
    fn execute(&self, command: &RuleCommand) -> io::Result<RuleCommandOutput> {
        let mut child = Command::new(command.program())
            .args(command.args())
            .stdin(if command.stdin().is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;

        if let Some(input) = command.stdin() {
            let write_result = child
                .stdin
                .take()
                .ok_or_else(|| io::Error::other("rule command stdin unavailable"))?
                .write_all(input.as_bytes());
            if let Err(error) = write_result {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }

        let output = child.wait_with_output()?;
        Ok(RuleCommandOutput {
            success: output.status.success(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// 使用系统命令安装规则。
///
/// 当前激活路径只接受 nftables：单个 batch 具备原子提交语义，失败时不会把
/// 无法表达的“部分所有权”丢给 supervisor。iptables 生成/回滚器保留为纯测试
/// 覆盖，待其 lease 能跨错误返回后再开放生产回落。
pub fn install(
    plan: &CapturePlan,
    ports: RedirectPorts,
) -> Result<AutoRedirectBackend, CaptureError> {
    install_nftables_with_executor(plan, ports, &SystemRuleExecutor)
}

/// 按成功安装时返回的账本精确卸载规则。
pub fn uninstall(backend: AutoRedirectBackend) -> Result<(), CaptureError> {
    uninstall_with_executor(backend, &SystemRuleExecutor)
}

fn install_nftables_with_executor<E: RuleExecutor + ?Sized>(
    plan: &CapturePlan,
    ports: RedirectPorts,
    executor: &E,
) -> Result<AutoRedirectBackend, CaptureError> {
    let script = build_nft_script(plan, ports)?;
    match probe_nft_table(executor) {
        NftTableProbe::Absent => {}
        NftTableProbe::Present => {
            return Err(nat_error(format!(
                "nftables 表 inet {NFT_TABLE} 已存在；可能是仍在工作的实例或崩溃后遗留规则，拒绝覆盖"
            )));
        }
        NftTableProbe::ToolUnavailable => {
            return Err(nat_error(
                "nft 命令不可用；当前事务化 auto_redirect 激活路径要求 nftables",
            ));
        }
        NftTableProbe::Unknown(reason) => {
            return Err(nat_error(format!(
                "无法证明 nftables 表 inet {NFT_TABLE} 不存在: {reason}"
            )));
        }
    }

    let check = RuleCommand::new("nft", ["-c", "-f", "-"]).with_stdin(script.clone());
    execute_checked(executor, &check)
        .map_err(|error| nat_error(format!("nft 原子批次校验失败: {error}")))?;
    let load = RuleCommand::new("nft", ["-f", "-"]).with_stdin(script);
    execute_checked(executor, &load)
        .map_err(|error| nat_error(format!("nft 原子批次加载失败: {error}")))?;
    Ok(AutoRedirectBackend::Nftables)
}

/// 测试专用 fallback harness。先对 nft 脚本执行 `nft -c -f -`，通过后才以
/// 单次 `nft -f -` 原子加载。nft 不可用时，仅在 iptables 能无损表达当前
/// TCP NAT 快路径的静态决策时回落。
#[cfg(test)]
pub fn install_with_executor<E: RuleExecutor + ?Sized>(
    plan: &CapturePlan,
    ports: RedirectPorts,
    executor: &E,
) -> Result<AutoRedirectBackend, CaptureError> {
    let script = build_nft_script(plan, ports)?;
    let initial_probe = probe_nft_table(executor);
    if let NftTableProbe::Present = initial_probe {
        return Err(nat_error(format!(
            "nftables 表 inet {NFT_TABLE} 已存在；可能是仍在工作的实例或崩溃后遗留规则，拒绝叠加后端"
        )));
    }
    let check = RuleCommand::new("nft", ["-c", "-f", "-"]).with_stdin(script.clone());
    let nft_check_error = match execute_checked(executor, &check) {
        Ok(()) => {
            let load = RuleCommand::new("nft", ["-f", "-"]).with_stdin(script);
            match execute_checked(executor, &load) {
                Ok(()) => return Ok(AutoRedirectBackend::Nftables),
                Err(error) => {
                    // 标准 nft batch 是原子事务，加载失败不会遗留本批规则。
                    // 再探测一次可捕获 check/load 间的并发建表；若发现表，
                    // 无法证明所有权，必须保留现场并拒绝叠加 iptables。
                    ensure_nft_absent_before_fallback(executor, initial_probe, &error)?;
                    format!("nft 原子加载失败: {error}")
                }
            }
        }
        Err(error) => {
            ensure_nft_absent_before_fallback(executor, initial_probe, &error)?;
            format!("nft 校验不可用: {error}")
        }
    };

    let ledgers = build_iptables_ledgers(plan, ports).map_err(|error| {
        CaptureError::Nat(format!(
            "{nft_check_error}；禁止有损回落到 iptables: {error}"
        ))
    })?;

    install_iptables_ledgers(executor, &ledgers).map_err(|error| {
        CaptureError::Nat(format!(
            "auto_redirect 安装失败；{nft_check_error}；iptables 回落失败: {error}"
        ))
    })
}

/// 使用指定执行器按账本卸载，始终尝试完整清理后再汇总错误。
pub fn uninstall_with_executor<E: RuleExecutor + ?Sized>(
    backend: AutoRedirectBackend,
    executor: &E,
) -> Result<(), CaptureError> {
    let commands = match backend {
        AutoRedirectBackend::Nftables => vec![nft_cleanup_command()],
        #[cfg(test)]
        AutoRedirectBackend::Iptables { hook, ipv4, ipv6 } => {
            let mut commands = Vec::new();
            if ipv4 {
                commands.extend(iptables_cleanup_commands("iptables", hook));
            }
            if ipv6 {
                commands.extend(iptables_cleanup_commands("ip6tables", hook));
            }
            commands
        }
    };

    let failures = execute_cleanup_all(executor, &commands);
    if failures.is_empty() {
        Ok(())
    } else {
        Err(CaptureError::Nat(format!(
            "auto_redirect 卸载未完全成功: {}",
            failures.join("；")
        )))
    }
}

/// 生成完整 nftables batch。该函数是纯函数，不读取环境也不执行命令。
pub fn build_nft_script(plan: &CapturePlan, ports: RedirectPorts) -> Result<String, CaptureError> {
    validate_plan(plan, ports)?;

    let hook = hook_for(plan.traffic);
    let chain = match hook {
        AutoRedirectHook::Output => "output",
        AutoRedirectHook::Prerouting => "prerouting",
    };
    let mut script = String::new();
    writeln!(script, "add table inet {NFT_TABLE}").expect("write String");
    writeln!(
        script,
        "add chain inet {NFT_TABLE} {chain} {{ type nat hook {chain} priority -100; policy accept; }}"
    )
    .expect("write String");

    match hook {
        AutoRedirectHook::Output => write_nft_output_rules(&mut script, plan, ports)?,
        AutoRedirectHook::Prerouting => write_nft_lan_rules(&mut script, plan, ports)?,
    }

    debug_assert!(!contains_forbidden_rule_primitive(&script));
    Ok(script)
}

fn hook_for(traffic: CaptureTraffic) -> AutoRedirectHook {
    match traffic {
        CaptureTraffic::System | CaptureTraffic::Apps => AutoRedirectHook::Output,
        CaptureTraffic::Lan => AutoRedirectHook::Prerouting,
    }
}

fn validate_plan(plan: &CapturePlan, ports: RedirectPorts) -> Result<(), CaptureError> {
    if ports.ipv4 == 0 || ports.ipv6 == Some(0) {
        return Err(nat_error("REDIRECT 监听端口必须是已绑定的非零端口"));
    }
    if ports.ipv6.is_some() && (!plan.ipv6_enabled || plan.tun_v6_cidr.is_none()) {
        return Err(nat_error(
            "提供了 IPv6 REDIRECT 端口，但当前 TUN 计划没有启用 IPv6",
        ));
    }
    if !plan.route_address_set.is_empty() || !plan.route_exclude_address_set.is_empty() {
        return Err(nat_error(
            "auto_redirect 无法在内核 NAT 前无损解析动态 route_address_set/route_exclude_address_set",
        ));
    }
    if !plan.exclude_processes.is_empty()
        || !plan.filters.include_package.is_empty()
        || !plan.filters.exclude_package.is_empty()
    {
        return Err(nat_error(
            "auto_redirect 规则后端无法无损表达进程名或包名过滤，请先解析为 UID",
        ));
    }

    validate_interface("interface_name", &plan.interface_name)?;
    for interface in &plan.filters.include_interface {
        validate_interface("include_interface", interface)?;
    }
    for interface in &plan.filters.exclude_interface {
        validate_interface("exclude_interface", interface)?;
    }
    for mac in plan
        .filters
        .include_mac
        .iter()
        .chain(&plan.filters.exclude_mac)
    {
        validate_mac(mac)?;
    }
    validate_ranges("include_uid_range", &plan.filters.include_uid_range)?;
    validate_ranges("exclude_uid_range", &plan.filters.exclude_uid_range)?;
    validate_ranges("include_gid_range", &plan.filters.include_gid_range)?;
    validate_ranges("exclude_gid_range", &plan.filters.exclude_gid_range)?;
    for user in &plan.filters.include_android_user {
        user.checked_mul(100_000)
            .and_then(|low| low.checked_add(99_999))
            .ok_or_else(|| nat_error("include_android_user 转换 UID 范围时溢出"))?;
    }

    match hook_for(plan.traffic) {
        AutoRedirectHook::Output => {
            if !plan.filters.include_interface.is_empty()
                || !plan.filters.exclude_interface.is_empty()
                || !plan.filters.include_mac.is_empty()
                || !plan.filters.exclude_mac.is_empty()
            {
                return Err(nat_error(
                    "OUTPUT auto_redirect 不会把 LAN 接口/MAC 过滤误解释为本机流量过滤",
                ));
            }
        }
        AutoRedirectHook::Prerouting => {
            if has_owner_filters(plan) {
                return Err(nat_error(
                    "PREROUTING/LAN 流量没有可靠 socket owner，不能无损应用 UID/GID/Android user 过滤",
                ));
            }
        }
    }

    let captures_v4 = family_has_capture(plan, AddressFamily::V4);
    let captures_v6 = ports.ipv6.is_some() && family_has_capture(plan, AddressFamily::V6);
    if !captures_v4 && !captures_v6 {
        return Err(nat_error(
            "静态 route_address 白名单与已绑定 REDIRECT 地址族没有交集",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn validate_iptables_compatible(plan: &CapturePlan) -> Result<(), CaptureError> {
    if plan.exclude_mptcp {
        return Err(nat_error(
            "exclude_mptcp 需要 nftables TCP option 表达式，iptables 回落会改变 TCP NAT 快路径语义",
        ));
    }
    Ok(())
}

fn validate_interface(field: &str, value: &str) -> Result<(), CaptureError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_INTERFACE_NAME_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'@')
        });
    if valid {
        Ok(())
    } else {
        Err(nat_error(format!(
            "{field} 包含不安全字符或超过 Linux IFNAMSIZ: {value:?}"
        )))
    }
}

fn validate_mac(value: &str) -> Result<(), CaptureError> {
    let bytes = value.as_bytes();
    let valid = bytes.len() == 17
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 2 | 5 | 8 | 11 | 14) {
                *byte == b':'
            } else {
                byte.is_ascii_hexdigit()
            }
        });
    if valid {
        Ok(())
    } else {
        Err(nat_error(format!("无效或不安全的 MAC 地址: {value:?}")))
    }
}

fn validate_ranges(field: &str, ranges: &[(u32, u32)]) -> Result<(), CaptureError> {
    if let Some((start, end)) = ranges.iter().find(|(start, end)| start > end) {
        Err(nat_error(format!(
            "{field} 范围起点大于终点: {start}-{end}"
        )))
    } else {
        Ok(())
    }
}

fn has_owner_filters(plan: &CapturePlan) -> bool {
    !plan.filters.include_uid.is_empty()
        || !plan.filters.include_uid_range.is_empty()
        || !plan.filters.exclude_uid.is_empty()
        || !plan.filters.exclude_uid_range.is_empty()
        || !plan.filters.include_gid.is_empty()
        || !plan.filters.include_gid_range.is_empty()
        || !plan.filters.exclude_gid.is_empty()
        || !plan.filters.exclude_gid_range.is_empty()
        || !plan.filters.include_android_user.is_empty()
}

fn write_nft_output_rules(
    script: &mut String,
    plan: &CapturePlan,
    ports: RedirectPorts,
) -> Result<(), CaptureError> {
    let chain = "output";
    let outbound_mark = plan
        .auto_redirect_marks
        .output
        .unwrap_or(DEFAULT_AUTO_REDIRECT_OUTPUT_MARK);
    writeln!(
        script,
        "add rule inet {NFT_TABLE} {chain} meta mark {outbound_mark:#x} return"
    )
    .expect("write String");

    for (family, port) in active_families(plan, ports) {
        write_nft_listener_bypass(script, chain, family, port);
    }
    write_nft_owner_filters(script, chain, plan)?;
    write_nft_ip_exclusions(script, chain, plan);
    if plan.exclude_mptcp {
        writeln!(
            script,
            "add rule inet {NFT_TABLE} {chain} tcp option mptcp exists return"
        )
        .expect("write String");
    }

    let interface = nft_quoted(&plan.interface_name);
    for (family, port) in active_families(plan, ports) {
        write_nft_redirect_rules(script, chain, plan, family, port, Some(&interface));
    }
    Ok(())
}

fn write_nft_lan_rules(
    script: &mut String,
    plan: &CapturePlan,
    ports: RedirectPorts,
) -> Result<(), CaptureError> {
    let chain = "prerouting";
    for (family, port) in active_families(plan, ports) {
        write_nft_listener_bypass(script, chain, family, port);
    }

    writeln!(
        script,
        "add rule inet {NFT_TABLE} {chain} iifname {} return",
        nft_quoted(&plan.interface_name)
    )
    .expect("write String");
    for interface in sorted_strings(&plan.filters.exclude_interface) {
        writeln!(
            script,
            "add rule inet {NFT_TABLE} {chain} iifname {} return",
            nft_quoted(interface)
        )
        .expect("write String");
    }
    if !plan.filters.include_interface.is_empty() {
        let interfaces = sorted_strings(&plan.filters.include_interface)
            .into_iter()
            .map(nft_quoted)
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(
            script,
            "add rule inet {NFT_TABLE} {chain} iifname != {{ {interfaces} }} return"
        )
        .expect("write String");
    }

    for mac in normalized_macs(&plan.filters.exclude_mac) {
        writeln!(
            script,
            "add rule inet {NFT_TABLE} {chain} ether saddr {mac} return"
        )
        .expect("write String");
    }
    if !plan.filters.include_mac.is_empty() {
        let macs = normalized_macs(&plan.filters.include_mac).join(", ");
        writeln!(
            script,
            "add rule inet {NFT_TABLE} {chain} ether saddr != {{ {macs} }} return"
        )
        .expect("write String");
    }

    write_nft_ip_exclusions(script, chain, plan);
    if plan.exclude_mptcp {
        writeln!(
            script,
            "add rule inet {NFT_TABLE} {chain} tcp option mptcp exists return"
        )
        .expect("write String");
    }
    for (family, port) in active_families(plan, ports) {
        write_nft_redirect_rules(script, chain, plan, family, port, None);
    }
    Ok(())
}

fn write_nft_listener_bypass(script: &mut String, chain: &str, family: AddressFamily, port: u16) {
    writeln!(
        script,
        "add rule inet {NFT_TABLE} {chain} meta nfproto {} fib daddr type local tcp dport {port} return",
        family.nft_nfproto()
    )
    .expect("write String");
}

fn write_nft_owner_filters(
    script: &mut String,
    chain: &str,
    plan: &CapturePlan,
) -> Result<(), CaptureError> {
    for owner in numeric_values(&plan.filters.exclude_uid, &plan.filters.exclude_uid_range) {
        writeln!(
            script,
            "add rule inet {NFT_TABLE} {chain} meta skuid {owner} return"
        )
        .expect("write String");
    }
    let include_uid = include_uids(plan)?;
    if !include_uid.is_empty() {
        writeln!(
            script,
            "add rule inet {NFT_TABLE} {chain} meta skuid != {{ {} }} return",
            include_uid.join(", ")
        )
        .expect("write String");
    }

    for owner in numeric_values(&plan.filters.exclude_gid, &plan.filters.exclude_gid_range) {
        writeln!(
            script,
            "add rule inet {NFT_TABLE} {chain} meta skgid {owner} return"
        )
        .expect("write String");
    }
    let include_gid = numeric_values(&plan.filters.include_gid, &plan.filters.include_gid_range);
    if !include_gid.is_empty() {
        writeln!(
            script,
            "add rule inet {NFT_TABLE} {chain} meta skgid != {{ {} }} return",
            include_gid.join(", ")
        )
        .expect("write String");
    }
    Ok(())
}

fn write_nft_ip_exclusions(script: &mut String, chain: &str, plan: &CapturePlan) {
    for family in [AddressFamily::V4, AddressFamily::V6] {
        for network in family_exclusions(plan, family) {
            writeln!(
                script,
                "add rule inet {NFT_TABLE} {chain} {} daddr {network} return",
                family.nft_address_keyword()
            )
            .expect("write String");
        }
    }
}

fn write_nft_redirect_rules(
    script: &mut String,
    chain: &str,
    plan: &CapturePlan,
    family: AddressFamily,
    port: u16,
    output_interface: Option<&str>,
) {
    let includes = family_includes(plan, family);
    if !plan.route_addresses.is_empty() && includes.is_empty() {
        return;
    }

    let mut prefix = format!(
        "add rule inet {NFT_TABLE} {chain} meta nfproto {}",
        family.nft_nfproto()
    );
    if let Some(interface) = output_interface {
        write!(prefix, " oifname {interface}").expect("write String");
    }
    if includes.is_empty() {
        writeln!(script, "{prefix} meta l4proto tcp redirect to :{port}").expect("write String");
    } else {
        for network in includes {
            writeln!(
                script,
                "{prefix} {} daddr {network} meta l4proto tcp redirect to :{port}",
                family.nft_address_keyword()
            )
            .expect("write String");
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressFamily {
    V4,
    V6,
}

impl AddressFamily {
    fn nft_nfproto(self) -> &'static str {
        match self {
            Self::V4 => "ipv4",
            Self::V6 => "ipv6",
        }
    }

    fn nft_address_keyword(self) -> &'static str {
        match self {
            Self::V4 => "ip",
            Self::V6 => "ip6",
        }
    }

    #[cfg(test)]
    fn program(self) -> &'static str {
        match self {
            Self::V4 => "iptables",
            Self::V6 => "ip6tables",
        }
    }
}

fn active_families(
    plan: &CapturePlan,
    ports: RedirectPorts,
) -> impl Iterator<Item = (AddressFamily, u16)> {
    let mut families = Vec::with_capacity(2);
    if family_has_capture(plan, AddressFamily::V4) {
        families.push((AddressFamily::V4, ports.ipv4));
    }
    match ports.ipv6 {
        Some(port) if family_has_capture(plan, AddressFamily::V6) => {
            families.push((AddressFamily::V6, port));
        }
        _ => {}
    }
    families.into_iter()
}

fn family_has_capture(plan: &CapturePlan, family: AddressFamily) -> bool {
    plan.route_addresses.is_empty()
        || plan
            .route_addresses
            .iter()
            .any(|network| family.matches_ip(network.addr()))
}

impl AddressFamily {
    fn matches_ip(self, address: IpAddr) -> bool {
        matches!(
            (self, address),
            (Self::V4, IpAddr::V4(_)) | (Self::V6, IpAddr::V6(_))
        )
    }
}

fn family_includes(plan: &CapturePlan, family: AddressFamily) -> Vec<String> {
    let mut networks = plan
        .route_addresses
        .iter()
        .filter(|network| family.matches_ip(network.addr()))
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    networks.sort();
    networks.dedup();
    networks
}

fn family_exclusions(plan: &CapturePlan, family: AddressFamily) -> Vec<String> {
    let mut networks = BTreeSet::new();
    match family {
        AddressFamily::V4 => {
            networks.insert("127.0.0.0/8".to_owned());
            networks.insert(plan.tun_v4_cidr.to_string());
        }
        AddressFamily::V6 => {
            networks.insert("::1/128".to_owned());
            if let Some(network) = plan.tun_v6_cidr {
                networks.insert(network.to_string());
            }
        }
    }
    for network in plan
        .exclude_cidrs
        .iter()
        .chain(&plan.route_exclude_addresses)
    {
        if family.matches_ip(network.addr()) {
            networks.insert(network.to_string());
        }
    }
    for address in &plan.loopback_addresses {
        if family.matches_ip(*address) {
            let suffix = match address {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            networks.insert(format!("{address}/{suffix}"));
        }
    }
    networks.into_iter().collect()
}

fn sorted_strings(values: &[String]) -> Vec<&str> {
    values
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn normalized_macs(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn numeric_values(values: &[u32], ranges: &[(u32, u32)]) -> Vec<String> {
    let mut result = values
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    result.extend(ranges.iter().map(|(start, end)| format!("{start}-{end}")));
    result.into_iter().collect()
}

fn include_uids(plan: &CapturePlan) -> Result<Vec<String>, CaptureError> {
    let mut values = numeric_values(&plan.filters.include_uid, &plan.filters.include_uid_range);
    if values.is_empty() {
        for user in &plan.filters.include_android_user {
            let low = user
                .checked_mul(100_000)
                .ok_or_else(|| nat_error("include_android_user 转换 UID 范围时溢出"))?;
            let high = low
                .checked_add(99_999)
                .ok_or_else(|| nat_error("include_android_user 转换 UID 范围时溢出"))?;
            values.push(format!("{low}-{high}"));
        }
        values.sort();
        values.dedup();
    }
    Ok(values)
}

fn nft_quoted(value: &str) -> String {
    debug_assert!(value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'@')
    }));
    format!("\"{value}\"")
}

fn contains_forbidden_rule_primitive(script: &str) -> bool {
    let lower = script.to_ascii_lowercase();
    ["tproxy", "queue", "nfqueue", "reject", "reset"]
        .iter()
        .any(|token| lower.contains(token))
}

#[cfg(test)]
#[derive(Debug)]
struct IptablesLedger {
    family: AddressFamily,
    hook: AutoRedirectHook,
    install: Vec<RuleCommand>,
}

#[cfg(test)]
fn build_iptables_ledgers(
    plan: &CapturePlan,
    ports: RedirectPorts,
) -> Result<Vec<IptablesLedger>, CaptureError> {
    validate_plan(plan, ports)?;
    validate_iptables_compatible(plan)?;
    let hook = hook_for(plan.traffic);
    active_families(plan, ports)
        .map(|(family, port)| build_iptables_family(plan, hook, family, port))
        .collect()
}

#[cfg(test)]
fn build_iptables_family(
    plan: &CapturePlan,
    hook: AutoRedirectHook,
    family: AddressFamily,
    port: u16,
) -> Result<IptablesLedger, CaptureError> {
    let program = family.program();
    let mut commands = vec![RuleCommand::new(
        program,
        ["-t", "nat", "-N", IPTABLES_CHAIN],
    )];

    match hook {
        AutoRedirectHook::Output => {
            let mark = plan
                .auto_redirect_marks
                .output
                .unwrap_or(DEFAULT_AUTO_REDIRECT_OUTPUT_MARK);
            push_chain_rule(
                &mut commands,
                program,
                [
                    "-m",
                    "mark",
                    "--mark",
                    &format!("{mark:#x}"),
                    "-j",
                    "RETURN",
                ],
            );
            push_listener_bypass(&mut commands, program, port);
            push_owner_exclusions(&mut commands, program, plan);
        }
        AutoRedirectHook::Prerouting => {
            push_listener_bypass(&mut commands, program, port);
            push_chain_rule(
                &mut commands,
                program,
                ["-i", plan.interface_name.as_str(), "-j", "RETURN"],
            );
            for interface in sorted_strings(&plan.filters.exclude_interface) {
                push_chain_rule(&mut commands, program, ["-i", interface, "-j", "RETURN"]);
            }
            for mac in normalized_macs(&plan.filters.exclude_mac) {
                push_chain_rule(
                    &mut commands,
                    program,
                    ["-m", "mac", "--mac-source", &mac, "-j", "RETURN"],
                );
            }
        }
    }

    for network in family_exclusions(plan, family) {
        push_chain_rule(
            &mut commands,
            program,
            ["-d", network.as_str(), "-j", "RETURN"],
        );
    }

    let redirects = build_iptables_redirect_commands(plan, hook, family, port)?;
    commands.extend(redirects);
    commands.push(iptables_hook_install_command(program, hook));
    Ok(IptablesLedger {
        family,
        hook,
        install: commands,
    })
}

#[cfg(test)]
fn push_chain_rule<'a>(
    commands: &mut Vec<RuleCommand>,
    program: &'static str,
    args: impl IntoIterator<Item = &'a str>,
) {
    let mut full = vec![
        "-t".to_owned(),
        "nat".to_owned(),
        "-A".to_owned(),
        IPTABLES_CHAIN.to_owned(),
    ];
    full.extend(args.into_iter().map(str::to_owned));
    commands.push(RuleCommand::new(program, full));
}

#[cfg(test)]
fn push_listener_bypass(commands: &mut Vec<RuleCommand>, program: &'static str, port: u16) {
    push_chain_rule(
        commands,
        program,
        [
            "-p",
            "tcp",
            "-m",
            "addrtype",
            "--dst-type",
            "LOCAL",
            "--dport",
            &port.to_string(),
            "-j",
            "RETURN",
        ],
    );
}

#[cfg(test)]
fn push_owner_exclusions(
    commands: &mut Vec<RuleCommand>,
    program: &'static str,
    plan: &CapturePlan,
) {
    for owner in numeric_values(&plan.filters.exclude_uid, &plan.filters.exclude_uid_range) {
        push_chain_rule(
            commands,
            program,
            ["-m", "owner", "--uid-owner", &owner, "-j", "RETURN"],
        );
    }
    for owner in numeric_values(&plan.filters.exclude_gid, &plan.filters.exclude_gid_range) {
        push_chain_rule(
            commands,
            program,
            ["-m", "owner", "--gid-owner", &owner, "-j", "RETURN"],
        );
    }
}

#[cfg(test)]
fn build_iptables_redirect_commands(
    plan: &CapturePlan,
    hook: AutoRedirectHook,
    family: AddressFamily,
    port: u16,
) -> Result<Vec<RuleCommand>, CaptureError> {
    let routes = family_includes(plan, family);
    if !plan.route_addresses.is_empty() && routes.is_empty() {
        return Ok(Vec::new());
    }
    let routes = optional_values(routes);

    let (interfaces, macs, uids, gids) = match hook {
        AutoRedirectHook::Output => (
            vec![None],
            vec![None],
            optional_values(include_uids(plan)?),
            optional_values(numeric_values(
                &plan.filters.include_gid,
                &plan.filters.include_gid_range,
            )),
        ),
        AutoRedirectHook::Prerouting => (
            optional_values(
                sorted_strings(&plan.filters.include_interface)
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
            ),
            optional_values(normalized_macs(&plan.filters.include_mac)),
            vec![None],
            vec![None],
        ),
    };

    let count = [
        routes.len(),
        interfaces.len(),
        macs.len(),
        uids.len(),
        gids.len(),
    ]
    .into_iter()
    .try_fold(1usize, |total, next| total.checked_mul(next))
    .ok_or_else(|| nat_error("iptables REDIRECT 规则组合数量溢出"))?;
    if count > MAX_IPTABLES_REDIRECT_RULES {
        return Err(nat_error(format!(
            "iptables REDIRECT 需要 {count} 条组合规则，超过安全上限 {MAX_IPTABLES_REDIRECT_RULES}"
        )));
    }

    let mut commands = Vec::with_capacity(count);
    for route in &routes {
        for interface in &interfaces {
            for mac in &macs {
                for uid in &uids {
                    for gid in &gids {
                        let mut args = vec![
                            "-t".to_owned(),
                            "nat".to_owned(),
                            "-A".to_owned(),
                            IPTABLES_CHAIN.to_owned(),
                        ];
                        if hook == AutoRedirectHook::Output {
                            args.extend(["-o".to_owned(), plan.interface_name.clone()]);
                        }
                        if let Some(interface) = interface {
                            args.extend(["-i".to_owned(), interface.clone()]);
                        }
                        if let Some(mac) = mac {
                            args.extend([
                                "-m".to_owned(),
                                "mac".to_owned(),
                                "--mac-source".to_owned(),
                                mac.clone(),
                            ]);
                        }
                        if let Some(route) = route {
                            args.extend(["-d".to_owned(), route.clone()]);
                        }
                        if uid.is_some() || gid.is_some() {
                            args.extend(["-m".to_owned(), "owner".to_owned()]);
                        }
                        if let Some(uid) = uid {
                            args.extend(["--uid-owner".to_owned(), uid.clone()]);
                        }
                        if let Some(gid) = gid {
                            args.extend(["--gid-owner".to_owned(), gid.clone()]);
                        }
                        args.extend([
                            "-p".to_owned(),
                            "tcp".to_owned(),
                            "-j".to_owned(),
                            "REDIRECT".to_owned(),
                            "--to-ports".to_owned(),
                            port.to_string(),
                        ]);
                        commands.push(RuleCommand::new(family.program(), args));
                    }
                }
            }
        }
    }
    Ok(commands)
}

#[cfg(test)]
fn optional_values(values: Vec<String>) -> Vec<Option<String>> {
    if values.is_empty() {
        vec![None]
    } else {
        values.into_iter().map(Some).collect()
    }
}

#[cfg(test)]
fn install_iptables_ledgers<E: RuleExecutor + ?Sized>(
    executor: &E,
    ledgers: &[IptablesLedger],
) -> Result<AutoRedirectBackend, String> {
    let mut created = Vec::new();
    // 第一阶段只创建并填充私有链，不把任何链挂到活动 hook。这样缺少
    // ip6tables、某条过滤规则失败等常见错误不会留下“IPv4 已活动、IPv6
    // 未安装”的半配置。
    for ledger in ledgers {
        let prepare_len = ledger.install.len().saturating_sub(1);
        for (index, command) in ledger.install[..prepare_len].iter().enumerate() {
            if let Err(error) = execute_checked(executor, command) {
                return Err(iptables_failure_with_rollback(
                    executor, &created, command, error,
                ));
            }
            if index == 0 {
                created.push((ledger.family.program(), ledger.hook));
            }
        }
    }

    // 第二阶段才按确定位置挂载 hook；每个 ledger 的最后一条命令由构建器
    // 保证是带所有权 comment 的 `-I <HOOK> 1`。
    for ledger in ledgers {
        let command = ledger
            .install
            .last()
            .ok_or_else(|| "iptables 地址族账本为空".to_owned())?;
        if let Err(error) = execute_checked(executor, command) {
            return Err(iptables_failure_with_rollback(
                executor, &created, command, error,
            ));
        }
    }

    let hook = ledgers
        .first()
        .map(|ledger| ledger.hook)
        .ok_or_else(|| "没有可安装的地址族".to_owned())?;
    Ok(AutoRedirectBackend::Iptables {
        hook,
        ipv4: ledgers
            .iter()
            .any(|ledger| ledger.family == AddressFamily::V4),
        ipv6: ledgers
            .iter()
            .any(|ledger| ledger.family == AddressFamily::V6),
    })
}

#[cfg(test)]
fn iptables_failure_with_rollback<E: RuleExecutor + ?Sized>(
    executor: &E,
    created: &[(&'static str, AutoRedirectHook)],
    failed_command: &RuleCommand,
    error: String,
) -> String {
    let cleanup_failures = rollback_iptables(executor, created);
    let cleanup = if cleanup_failures.is_empty() {
        String::new()
    } else {
        format!("；回滚失败: {}", cleanup_failures.join("；"))
    };
    format!("{}: {error}{cleanup}", render_command(failed_command))
}

#[cfg(test)]
fn rollback_iptables<E: RuleExecutor + ?Sized>(
    executor: &E,
    created: &[(&'static str, AutoRedirectHook)],
) -> Vec<String> {
    let mut failures = Vec::new();
    for (program, hook) in created.iter().rev() {
        failures.extend(execute_cleanup_all(
            executor,
            &iptables_cleanup_commands(program, *hook),
        ));
    }
    failures
}

#[cfg(test)]
fn iptables_cleanup_commands(program: &'static str, hook: AutoRedirectHook) -> Vec<RuleCommand> {
    vec![
        RuleCommand::new(
            program,
            [
                "-t",
                "nat",
                "-D",
                hook.chain(),
                "-m",
                "comment",
                "--comment",
                IPTABLES_HOOK_COMMENT,
                "-j",
                IPTABLES_CHAIN,
            ],
        ),
        RuleCommand::new(program, ["-t", "nat", "-F", IPTABLES_CHAIN]),
        RuleCommand::new(program, ["-t", "nat", "-X", IPTABLES_CHAIN]),
    ]
}

#[cfg(test)]
fn iptables_hook_install_command(program: &'static str, hook: AutoRedirectHook) -> RuleCommand {
    RuleCommand::new(
        program,
        [
            "-t",
            "nat",
            "-I",
            hook.chain(),
            "1",
            "-m",
            "comment",
            "--comment",
            IPTABLES_HOOK_COMMENT,
            "-j",
            IPTABLES_CHAIN,
        ],
    )
}

fn nft_cleanup_command() -> RuleCommand {
    RuleCommand::new("nft", ["delete", "table", "inet", NFT_TABLE])
}

fn execute_checked<E: RuleExecutor + ?Sized>(
    executor: &E,
    command: &RuleCommand,
) -> Result<(), String> {
    let output = executor
        .execute(command)
        .map_err(|error| format!("无法执行 {}: {error}", command.program()))?;
    if output.success {
        Ok(())
    } else {
        let stderr = sanitize_stderr(&output.stderr);
        if stderr.is_empty() {
            Err("命令返回非零状态".to_owned())
        } else {
            Err(stderr)
        }
    }
}

fn execute_cleanup_all<E: RuleExecutor + ?Sized>(
    executor: &E,
    commands: &[RuleCommand],
) -> Vec<String> {
    commands
        .iter()
        .filter_map(|command| {
            execute_cleanup_checked(executor, command)
                .err()
                .map(|error| format!("{}: {error}", render_command(command)))
        })
        .collect()
}

fn execute_cleanup_checked<E: RuleExecutor + ?Sized>(
    executor: &E,
    command: &RuleCommand,
) -> Result<(), String> {
    let output = executor
        .execute(command)
        .map_err(|error| format!("无法执行 {}: {error}", command.program()))?;
    if output.success || is_absent_cleanup(command, &output.stderr) {
        Ok(())
    } else {
        let stderr = sanitize_stderr(&output.stderr);
        if stderr.is_empty() {
            Err("清理命令返回非零状态".to_owned())
        } else {
            Err(stderr)
        }
    }
}

fn is_absent_cleanup(command: &RuleCommand, stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    if command.program() == "nft" {
        // A generic loader/plugin/namespace "not found" does not prove that
        // our table is absent. Require nft's diagnostic to echo the exact
        // owned table before releasing the backend ledger.
        let names_owned_table = lower.contains(NFT_TABLE)
            && (lower.contains("table inet") || lower.contains("list table inet"));
        return names_owned_table
            && (lower.contains("no such file or directory") || lower.contains("does not exist"));
    }
    if matches!(command.program(), "iptables" | "ip6tables") {
        return lower.contains("bad rule")
            || lower.contains("does a matching rule exist")
            || lower.contains("no chain/target/match by that name")
            || lower.contains("chain already deleted");
    }
    false
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NftTableProbe {
    Absent,
    Present,
    ToolUnavailable,
    Unknown(String),
}

fn probe_nft_table<E: RuleExecutor + ?Sized>(executor: &E) -> NftTableProbe {
    let command = RuleCommand::new("nft", ["list", "table", "inet", NFT_TABLE]);
    match executor.execute(&command) {
        Ok(output) if output.success => NftTableProbe::Present,
        Ok(output) if is_absent_cleanup(&command, &output.stderr) => NftTableProbe::Absent,
        Ok(output) => NftTableProbe::Unknown(sanitize_stderr(&output.stderr)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => NftTableProbe::ToolUnavailable,
        Err(error) => NftTableProbe::Unknown(error.to_string()),
    }
}

#[cfg(test)]
fn ensure_nft_absent_before_fallback<E: RuleExecutor + ?Sized>(
    executor: &E,
    initial_probe: NftTableProbe,
    nft_error: &str,
) -> Result<(), CaptureError> {
    if initial_probe == NftTableProbe::ToolUnavailable {
        return Ok(());
    }
    match probe_nft_table(executor) {
        NftTableProbe::Absent => Ok(()),
        NftTableProbe::Present => Err(nat_error(format!(
            "nft 失败后发现 inet {NFT_TABLE} 仍处于活动状态，无法确认所有权，拒绝叠加 iptables: {nft_error}"
        ))),
        NftTableProbe::ToolUnavailable => Err(nat_error(format!(
            "nft 失败后工具又变得不可用，无法再次证明 inet {NFT_TABLE} 不存在，拒绝叠加 iptables: {nft_error}"
        ))),
        NftTableProbe::Unknown(reason) => Err(nat_error(format!(
            "nft 失败后无法证明 inet {NFT_TABLE} 不存在（{reason}），拒绝叠加 iptables: {nft_error}"
        ))),
    }
}

fn render_command(command: &RuleCommand) -> String {
    std::iter::once(command.program())
        .chain(command.args().iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ")
}

fn sanitize_stderr(stderr: &str) -> String {
    stderr
        .chars()
        .filter(|character| !character.is_control() || *character == ' ')
        .take(512)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn nat_error(message: impl Into<String>) -> CaptureError {
    CaptureError::Nat(message.into())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use core_config::model::{Capture, CaptureMethod};

    use super::*;

    struct RecordingExecutor<F> {
        handler: F,
        commands: Mutex<Vec<RuleCommand>>,
    }

    impl<F> RecordingExecutor<F> {
        fn new(handler: F) -> Self {
            Self {
                handler,
                commands: Mutex::new(Vec::new()),
            }
        }

        fn commands(&self) -> Vec<RuleCommand> {
            self.commands.lock().expect("commands lock").clone()
        }
    }

    impl<F> RuleExecutor for RecordingExecutor<F>
    where
        F: Fn(&RuleCommand, usize) -> io::Result<RuleCommandOutput>,
    {
        fn execute(&self, command: &RuleCommand) -> io::Result<RuleCommandOutput> {
            let index = {
                let mut commands = self.commands.lock().expect("commands lock");
                let index = commands.len();
                commands.push(command.clone());
                index
            };
            (self.handler)(command, index)
        }
    }

    fn base_plan(traffic: CaptureTraffic) -> CapturePlan {
        let mut plan = CapturePlan::from_config(&Capture {
            on: true,
            method: CaptureMethod::VirtualNic,
            ..Capture::default()
        })
        .expect("base capture plan");
        plan.traffic = traffic;
        plan.interface_name = "wuther0".to_owned();
        plan.ipv6_enabled = true;
        plan.tun_v6_cidr = Some("fdfe:dcba:9876::1/126".parse().expect("v6 TUN CIDR"));
        plan.exclude_mptcp = false;
        plan
    }

    fn dual_ports() -> RedirectPorts {
        RedirectPorts::new(41_231, Some(51_432))
    }

    fn command_text(command: &RuleCommand) -> String {
        render_command(command)
    }

    fn nft_table_absent_output() -> RuleCommandOutput {
        RuleCommandOutput::failure(format!(
            "Error: Could not process rule: No such file or directory\nlist table inet {NFT_TABLE}"
        ))
    }

    fn nft_absent_or_check_fails(
        command: &RuleCommand,
        _index: usize,
    ) -> io::Result<RuleCommandOutput> {
        if command.program() == "nft" && command.args().first().map(String::as_str) == Some("list")
        {
            Ok(nft_table_absent_output())
        } else if command.program() == "nft" {
            Ok(RuleCommandOutput::failure("nft unavailable"))
        } else {
            Ok(RuleCommandOutput::success())
        }
    }

    #[test]
    fn system_and_apps_use_only_output_while_lan_uses_only_prerouting() {
        for traffic in [CaptureTraffic::System, CaptureTraffic::Apps] {
            let script = build_nft_script(&base_plan(traffic), dual_ports()).unwrap();
            assert!(script.contains("type nat hook output priority -100"));
            assert!(!script.contains("hook prerouting"));
        }

        let script = build_nft_script(&base_plan(CaptureTraffic::Lan), dual_ports()).unwrap();
        assert!(script.contains("type nat hook prerouting priority -100"));
        assert!(!script.contains("hook output"));
    }

    #[test]
    fn output_redirects_only_tcp_originally_routed_to_tun_after_bypasses() {
        let plan = base_plan(CaptureTraffic::System);
        let script = build_nft_script(&plan, dual_ports()).unwrap();
        let mark = script.find("meta mark").unwrap();
        let listener = script
            .find("fib daddr type local tcp dport 41231 return")
            .unwrap();
        let redirect = script
            .find("oifname \"wuther0\" meta l4proto tcp redirect to :41231")
            .unwrap();
        assert!(mark < listener && listener < redirect);
        assert!(!script.contains("meta l4proto udp redirect"));
        assert!(!script.contains("icmp redirect"));
    }

    #[test]
    fn dynamic_ephemeral_ports_and_dual_stack_are_rendered_exactly() {
        let script = build_nft_script(
            &base_plan(CaptureTraffic::System),
            RedirectPorts::new(32_111, Some(48_222)),
        )
        .unwrap();
        assert!(script.contains("meta nfproto ipv4 fib daddr type local tcp dport 32111 return"));
        assert!(script.contains("meta nfproto ipv6 fib daddr type local tcp dport 48222 return"));
        assert!(
            script.contains(
                "meta nfproto ipv4 oifname \"wuther0\" meta l4proto tcp redirect to :32111"
            )
        );
        assert!(
            script.contains(
                "meta nfproto ipv6 oifname \"wuther0\" meta l4proto tcp redirect to :48222"
            )
        );
        assert!(!script.contains("7894"));
    }

    #[test]
    fn lan_tcp_redirect_fast_path_renders_interface_mac_and_static_address_filters() {
        let mut plan = base_plan(CaptureTraffic::Lan);
        plan.filters.include_interface = vec!["eth1".into(), "eth0".into()];
        plan.filters.exclude_interface = vec!["docker0".into()];
        plan.filters.include_mac = vec!["AA:BB:CC:DD:EE:02".into()];
        plan.filters.exclude_mac = vec!["AA:BB:CC:DD:EE:01".into()];
        plan.route_addresses = vec![
            "203.0.113.0/24".parse().unwrap(),
            "2001:db8:1::/48".parse().unwrap(),
        ];
        plan.route_exclude_addresses = vec!["203.0.113.64/26".parse().unwrap()];
        plan.exclude_cidrs = vec!["198.51.100.0/24".parse().unwrap()];
        plan.loopback_addresses = vec!["192.0.2.7".parse().unwrap()];

        let script = build_nft_script(&plan, dual_ports()).unwrap();
        assert!(script.contains("iifname \"wuther0\" return"));
        assert!(script.contains("iifname \"docker0\" return"));
        assert!(script.contains("iifname != { \"eth0\", \"eth1\" } return"));
        assert!(script.contains("ether saddr aa:bb:cc:dd:ee:01 return"));
        assert!(script.contains("ether saddr != { aa:bb:cc:dd:ee:02 } return"));
        assert!(script.contains("ip daddr 198.51.100.0/24 return"));
        assert!(script.contains("ip daddr 203.0.113.64/26 return"));
        assert!(script.contains("ip daddr 192.0.2.7/32 return"));
        assert!(script.contains(&format!("ip daddr {} return", plan.tun_v4_cidr)));
        assert!(script.contains("ip daddr 203.0.113.0/24 meta l4proto tcp redirect"));
        assert!(script.contains("ip6 daddr 2001:db8:1::/48 meta l4proto tcp redirect"));
    }

    #[test]
    fn output_tcp_redirect_fast_path_renders_owner_filters() {
        let mut plan = base_plan(CaptureTraffic::Apps);
        plan.filters.exclude_uid = vec![0, 999];
        plan.filters.include_uid_range = vec![(10_000, 19_999)];
        plan.filters.exclude_gid_range = vec![(20, 29)];
        plan.filters.include_gid = vec![3000, 3001];
        let script = build_nft_script(&plan, dual_ports()).unwrap();
        assert!(script.contains("meta skuid 0 return"));
        assert!(script.contains("meta skuid != { 10000-19999 } return"));
        assert!(script.contains("meta skgid 20-29 return"));
        assert!(script.contains("meta skgid != { 3000, 3001 } return"));
    }

    #[test]
    fn route_sets_fail_closed_before_any_command() {
        let mut plan = base_plan(CaptureTraffic::System);
        plan.route_address_set = vec!["geoip-cn".into()];
        let executor = RecordingExecutor::new(nft_absent_or_check_fails);
        let error = install_with_executor(&plan, dual_ports(), &executor).unwrap_err();
        assert!(error.to_string().contains("route_address_set"));
        assert!(executor.commands().is_empty());
    }

    #[test]
    fn injected_interface_and_mac_strings_are_rejected() {
        let mut output = base_plan(CaptureTraffic::System);
        output.interface_name = "tun0\"; delete table inet x".into();
        assert!(build_nft_script(&output, dual_ports()).is_err());

        let mut lan = base_plan(CaptureTraffic::Lan);
        lan.filters.include_interface = vec!["eth0\nadd rule".into()];
        assert!(build_nft_script(&lan, dual_ports()).is_err());

        let mut lan = base_plan(CaptureTraffic::Lan);
        lan.filters.exclude_mac = vec!["aa:bb:cc:dd:ee:ff;drop".into()];
        assert!(build_nft_script(&lan, dual_ports()).is_err());
    }

    #[test]
    fn generated_rules_never_use_tproxy_queue_reset_reject_udp_or_icmp() {
        let mut plan = base_plan(CaptureTraffic::Lan);
        plan.auto_redirect_marks.input = Some(0x2023);
        plan.auto_redirect_marks.reset = Some(0x2025);
        plan.auto_redirect_marks.nfqueue = Some(123);
        let script = build_nft_script(&plan, dual_ports()).unwrap();
        let lower = script.to_ascii_lowercase();
        for forbidden in ["tproxy", "queue", "nfqueue", "reset", "reject"] {
            assert!(
                !lower.contains(forbidden),
                "unexpected {forbidden}: {script}"
            );
        }
        assert!(!lower.contains("udp"));
        assert!(!lower.contains("icmp"));
    }

    #[test]
    fn nft_is_checked_before_single_atomic_load() {
        let executor = RecordingExecutor::new(|command: &RuleCommand, _| {
            if command.program() == "nft"
                && command.args().first().map(String::as_str) == Some("list")
            {
                Ok(nft_table_absent_output())
            } else {
                Ok(RuleCommandOutput::success())
            }
        });
        let backend =
            install_with_executor(&base_plan(CaptureTraffic::System), dual_ports(), &executor)
                .unwrap();
        assert_eq!(backend, AutoRedirectBackend::Nftables);
        let commands = executor.commands();
        assert_eq!(commands.len(), 3);
        assert_eq!(commands[0].args(), ["list", "table", "inet", NFT_TABLE]);
        assert_eq!(commands[1].args(), ["-c", "-f", "-"]);
        assert_eq!(commands[2].args(), ["-f", "-"]);
        assert_eq!(commands[1].stdin(), commands[2].stdin());
    }

    #[test]
    fn production_installer_is_nft_only_and_atomic() {
        let executor = RecordingExecutor::new(|command: &RuleCommand, _| {
            if command.program() == "nft"
                && command.args().first().map(String::as_str) == Some("list")
            {
                Ok(nft_table_absent_output())
            } else {
                Ok(RuleCommandOutput::success())
            }
        });

        let backend = install_nftables_with_executor(
            &base_plan(CaptureTraffic::System),
            dual_ports(),
            &executor,
        )
        .unwrap();

        assert_eq!(backend, AutoRedirectBackend::Nftables);
        assert!(
            executor
                .commands()
                .iter()
                .all(|command| command.program() == "nft")
        );
    }

    #[test]
    fn production_installer_never_falls_back_when_nft_is_unavailable() {
        let executor = RecordingExecutor::new(|_command: &RuleCommand, _index: usize| {
            Err(io::Error::new(io::ErrorKind::NotFound, "missing nft"))
        });

        let error = install_nftables_with_executor(
            &base_plan(CaptureTraffic::System),
            dual_ports(),
            &executor,
        )
        .unwrap_err();

        assert!(error.to_string().contains("要求 nftables"));
        assert_eq!(executor.commands().len(), 1);
    }

    #[test]
    fn stale_nft_table_fails_closed_without_touching_iptables() {
        let executor =
            RecordingExecutor::new(|_command: &RuleCommand, _| Ok(RuleCommandOutput::success()));
        let error =
            install_with_executor(&base_plan(CaptureTraffic::System), dual_ports(), &executor)
                .unwrap_err();
        assert!(error.to_string().contains("已存在"));
        let commands = executor.commands();
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].args().first().map(String::as_str), Some("list"));
    }

    #[test]
    fn nft_check_race_never_stacks_iptables_over_live_table() {
        let executor = RecordingExecutor::new(|command: &RuleCommand, index| {
            if command.program() == "nft"
                && command.args().first().map(String::as_str) == Some("list")
            {
                return if index == 0 {
                    Ok(nft_table_absent_output())
                } else {
                    Ok(RuleCommandOutput::success())
                };
            }
            Ok(RuleCommandOutput::failure("check conflict"))
        });
        let error =
            install_with_executor(&base_plan(CaptureTraffic::System), dual_ports(), &executor)
                .unwrap_err();
        assert!(error.to_string().contains("仍处于活动状态"));
        assert!(
            executor
                .commands()
                .iter()
                .all(|command| command.program() == "nft")
        );
    }

    #[test]
    fn failed_atomic_nft_load_falls_back_only_after_table_is_proven_absent() {
        let executor = RecordingExecutor::new(|command: &RuleCommand, _| {
            if command.program() != "nft" {
                return Ok(RuleCommandOutput::success());
            }
            match command.args().first().map(String::as_str) {
                Some("list") => Ok(nft_table_absent_output()),
                Some("-c") => Ok(RuleCommandOutput::success()),
                _ => Ok(RuleCommandOutput::failure("atomic load rejected")),
            }
        });
        let backend =
            install_with_executor(&base_plan(CaptureTraffic::System), dual_ports(), &executor)
                .unwrap();
        assert!(matches!(backend, AutoRedirectBackend::Iptables { .. }));
        let commands = executor.commands();
        assert_eq!(commands[0].args().first().map(String::as_str), Some("list"));
        assert_eq!(commands[1].args().first().map(String::as_str), Some("-c"));
        assert_eq!(commands[2].args(), ["-f", "-"]);
        assert_eq!(commands[3].args().first().map(String::as_str), Some("list"));
        assert!(!commands.iter().any(|command| {
            command.program() == "nft"
                && command.args().first().map(String::as_str) == Some("delete")
        }));
    }

    #[test]
    fn ambiguous_nft_ownership_failure_never_falls_back() {
        let executor = RecordingExecutor::new(|command: &RuleCommand, _| {
            if command.program() == "nft" {
                Ok(RuleCommandOutput::failure("Operation not permitted"))
            } else {
                Ok(RuleCommandOutput::success())
            }
        });
        let error =
            install_with_executor(&base_plan(CaptureTraffic::System), dual_ports(), &executor)
                .unwrap_err();
        assert!(error.to_string().contains("无法证明"));
        assert!(
            executor
                .commands()
                .iter()
                .all(|command| command.program() == "nft")
        );
    }

    #[test]
    fn iptables_fallback_uses_dynamic_ports_first_hook_position_and_comment() {
        let executor = RecordingExecutor::new(nft_absent_or_check_fails);
        let backend =
            install_with_executor(&base_plan(CaptureTraffic::System), dual_ports(), &executor)
                .unwrap();
        assert_eq!(
            backend,
            AutoRedirectBackend::Iptables {
                hook: AutoRedirectHook::Output,
                ipv4: true,
                ipv6: true,
            }
        );
        let commands = executor.commands();
        assert!(commands.iter().any(|command| {
            command_text(command).contains(
                "iptables -t nat -I OUTPUT 1 -m comment --comment wuther:auto-redirect -j WUTHER_AUTO_REDIRECT",
            )
        }));
        assert!(commands.iter().any(|command| {
            command.program() == "iptables"
                && command
                    .args()
                    .windows(2)
                    .any(|args| args == ["--to-ports", "41231"])
        }));
        assert!(commands.iter().any(|command| {
            command.program() == "ip6tables"
                && command
                    .args()
                    .windows(2)
                    .any(|args| args == ["--to-ports", "51432"])
        }));
        assert!(!commands.iter().any(|command| {
            command
                .args()
                .windows(2)
                .any(|args| args == ["-A", "OUTPUT"])
        }));
    }

    #[test]
    fn lan_iptables_tcp_fast_path_preserves_static_filters_and_prerouting_hook() {
        let mut plan = base_plan(CaptureTraffic::Lan);
        plan.filters.include_interface = vec!["eth0".into(), "eth1".into()];
        plan.filters.exclude_interface = vec!["docker0".into()];
        plan.filters.include_mac = vec!["aa:bb:cc:dd:ee:01".into()];
        plan.filters.exclude_mac = vec!["aa:bb:cc:dd:ee:02".into()];
        plan.route_addresses = vec![
            "203.0.113.0/24".parse().unwrap(),
            "2001:db8:1::/48".parse().unwrap(),
        ];
        plan.route_exclude_addresses = vec!["198.51.100.0/24".parse().unwrap()];
        let ledgers = build_iptables_ledgers(&plan, dual_ports()).unwrap();
        assert_eq!(ledgers.len(), 2);
        let rendered = ledgers
            .iter()
            .flat_map(|ledger| ledger.install.iter())
            .map(command_text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(rendered.contains("-i docker0 -j RETURN"));
        assert!(rendered.contains("--mac-source aa:bb:cc:dd:ee:02 -j RETURN"));
        assert!(rendered.contains("-i eth0 -m mac --mac-source aa:bb:cc:dd:ee:01"));
        assert!(rendered.contains("-d 203.0.113.0/24 -p tcp -j REDIRECT"));
        assert!(rendered.contains("-I PREROUTING 1 -m comment --comment wuther:auto-redirect"));
        assert!(!rendered.contains(" OUTPUT "));
        assert!(!rendered.to_ascii_lowercase().contains("tproxy"));
        assert!(!rendered.to_ascii_lowercase().contains("queue"));
    }

    #[test]
    fn iptables_failure_rolls_back_only_chains_created_by_this_attempt() {
        let executor = RecordingExecutor::new(|command: &RuleCommand, _| {
            if command.program() == "nft" {
                if command.args().first().map(String::as_str) == Some("list") {
                    return Ok(nft_table_absent_output());
                }
                return Ok(RuleCommandOutput::failure("nft unavailable"));
            }
            if command
                .args()
                .iter()
                .any(|argument| argument == "--to-ports")
            {
                return Ok(RuleCommandOutput::failure("permission denied"));
            }
            Ok(RuleCommandOutput::success())
        });
        let error =
            install_with_executor(&base_plan(CaptureTraffic::System), dual_ports(), &executor)
                .unwrap_err();
        assert!(error.to_string().contains("permission denied"));
        let commands = executor.commands();
        assert!(commands.iter().any(|command| {
            command.program() == "iptables"
                && command
                    .args()
                    .windows(2)
                    .any(|args| args == ["-F", IPTABLES_CHAIN])
        }));
        assert!(commands.iter().any(|command| {
            command.program() == "iptables"
                && command
                    .args()
                    .windows(2)
                    .any(|args| args == ["-X", IPTABLES_CHAIN])
        }));
    }

    #[test]
    fn dual_stack_chains_are_fully_prepared_before_either_hook_becomes_active() {
        let executor = RecordingExecutor::new(|command: &RuleCommand, _| {
            if command.program() == "nft" {
                if command.args().first().map(String::as_str) == Some("list") {
                    return Ok(nft_table_absent_output());
                }
                return Ok(RuleCommandOutput::failure("nft unavailable"));
            }
            if command.program() == "ip6tables"
                && command
                    .args()
                    .windows(2)
                    .any(|args| args == ["-N", IPTABLES_CHAIN])
            {
                return Ok(RuleCommandOutput::failure("ip6tables unavailable"));
            }
            Ok(RuleCommandOutput::success())
        });
        assert!(
            install_with_executor(&base_plan(CaptureTraffic::System), dual_ports(), &executor,)
                .is_err()
        );
        let commands = executor.commands();
        assert!(
            !commands
                .iter()
                .any(|command| command.args().iter().any(|argument| argument == "-I"))
        );
        assert!(commands.iter().any(|command| {
            command.program() == "iptables"
                && command
                    .args()
                    .windows(2)
                    .any(|args| args == ["-X", IPTABLES_CHAIN])
        }));
    }

    #[test]
    fn preexisting_iptables_chain_is_preserved_on_collision() {
        let executor = RecordingExecutor::new(|command: &RuleCommand, _| {
            if command.program() == "nft" {
                return Err(io::Error::new(io::ErrorKind::NotFound, "missing nft"));
            }
            if command
                .args()
                .windows(2)
                .any(|args| args == ["-N", IPTABLES_CHAIN])
            {
                return Ok(RuleCommandOutput::failure("Chain already exists"));
            }
            Ok(RuleCommandOutput::success())
        });
        assert!(
            install_with_executor(&base_plan(CaptureTraffic::System), dual_ports(), &executor,)
                .is_err()
        );
        let commands = executor.commands();
        assert!(!commands.iter().any(|command| {
            command.args().iter().any(|argument| argument == "-F")
                || command.args().iter().any(|argument| argument == "-X")
        }));
    }

    #[test]
    fn uninstall_is_idempotent_when_owned_table_or_chains_are_already_absent() {
        let executor = RecordingExecutor::new(|command: &RuleCommand, _| {
            if command.program() == "nft" {
                Ok(nft_table_absent_output())
            } else {
                Ok(RuleCommandOutput::failure(
                    "No chain/target/match by that name.",
                ))
            }
        });
        uninstall_with_executor(AutoRedirectBackend::Nftables, &executor).unwrap();
        uninstall_with_executor(
            AutoRedirectBackend::Iptables {
                hook: AutoRedirectHook::Prerouting,
                ipv4: true,
                ipv6: true,
            },
            &executor,
        )
        .unwrap();
    }

    #[test]
    fn unrelated_nft_not_found_does_not_release_owned_backend() {
        let executor = RecordingExecutor::new(|_command: &RuleCommand, _| {
            Ok(RuleCommandOutput::failure(
                "nft: error while loading shared libraries: libnftables.so: No such file or directory",
            ))
        });

        let error = uninstall_with_executor(AutoRedirectBackend::Nftables, &executor).unwrap_err();

        assert!(error.to_string().contains("libnftables.so"));
    }

    #[test]
    fn uninstall_attempts_all_symmetric_cleanup_commands_before_erroring() {
        let executor = RecordingExecutor::new(|_command: &RuleCommand, _| {
            Ok(RuleCommandOutput::failure("permission denied"))
        });
        let error = uninstall_with_executor(
            AutoRedirectBackend::Iptables {
                hook: AutoRedirectHook::Output,
                ipv4: true,
                ipv6: true,
            },
            &executor,
        )
        .unwrap_err();
        assert!(error.to_string().contains("permission denied"));
        let commands = executor.commands();
        assert_eq!(commands.len(), 6);
        for program in ["iptables", "ip6tables"] {
            assert!(commands.iter().any(|command| {
                command.program() == program
                    && command_text(command).contains(
                        "-D OUTPUT -m comment --comment wuther:auto-redirect -j WUTHER_AUTO_REDIRECT",
                    )
            }));
        }
    }

    #[test]
    fn nft_only_mptcp_fast_path_filter_forbids_lossy_iptables_fallback() {
        let mut plan = base_plan(CaptureTraffic::System);
        plan.exclude_mptcp = true;
        let executor = RecordingExecutor::new(nft_absent_or_check_fails);
        let error = install_with_executor(&plan, dual_ports(), &executor).unwrap_err();
        assert!(error.to_string().contains("exclude_mptcp"));
        assert!(
            executor
                .commands()
                .iter()
                .all(|command| command.program() == "nft")
        );
    }

    #[test]
    fn static_route_whitelist_omits_unmatched_address_family() {
        let mut plan = base_plan(CaptureTraffic::System);
        plan.route_addresses = vec!["203.0.113.0/24".parse().unwrap()];
        let script = build_nft_script(&plan, dual_ports()).unwrap();
        assert!(script.contains("redirect to :41231"));
        assert!(!script.contains("redirect to :51432"));

        let executor = RecordingExecutor::new(nft_absent_or_check_fails);
        let backend = install_with_executor(&plan, dual_ports(), &executor).unwrap();
        assert_eq!(
            backend,
            AutoRedirectBackend::Iptables {
                hook: AutoRedirectHook::Output,
                ipv4: true,
                ipv6: false,
            }
        );
        assert!(
            !executor
                .commands()
                .iter()
                .any(|command| command.program() == "ip6tables")
        );
    }

    #[test]
    fn zero_ports_and_semantically_unavailable_ipv6_fail_closed() {
        let plan = base_plan(CaptureTraffic::System);
        assert!(build_nft_script(&plan, RedirectPorts::new(0, None)).is_err());

        let mut v4_only = plan;
        v4_only.ipv6_enabled = false;
        v4_only.tun_v6_cidr = None;
        assert!(build_nft_script(&v4_only, RedirectPorts::new(12_345, Some(23_456))).is_err());
    }

    #[test]
    fn lan_owner_filters_and_output_lan_filters_fail_closed() {
        let mut lan = base_plan(CaptureTraffic::Lan);
        lan.filters.include_uid = vec![1000];
        assert!(build_nft_script(&lan, dual_ports()).is_err());

        let mut output = base_plan(CaptureTraffic::Apps);
        output.filters.include_mac = vec!["aa:bb:cc:dd:ee:ff".into()];
        assert!(build_nft_script(&output, dual_ports()).is_err());
    }

    #[test]
    fn reversed_owner_ranges_are_rejected() {
        let mut plan = base_plan(CaptureTraffic::Apps);
        plan.filters.include_uid_range = vec![(2000, 1000)];
        assert!(build_nft_script(&plan, dual_ports()).is_err());
    }
}
