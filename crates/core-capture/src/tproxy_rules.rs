#![cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]

use crate::engine::CapturePlan;

pub(crate) const TPROXY_FWMARK: u32 = 0x2d0;
pub(crate) const TPROXY_PORT: u16 = 7894;
pub(crate) const TPROXY_ROUTE_IFACE: &str = "lo";

pub(crate) const TPROXY_ROUTE_TABLE: u32 = 0x2d0;
const TPROXY_PREROUTING_CHAIN: &str = "WUTHERCORE_PREROUTING";
const TPROXY_OUTPUT_CHAIN: &str = "WUTHERCORE_OUTPUT";
const TPROXY_DIVERT_CHAIN: &str = "WUTHERCORE_DIVERT";

const IPV4_BYPASS_CIDRS: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",
];

const IPV6_BYPASS_CIDRS: &[&str] = &[
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "100::/64",
    "2001:db8::/32",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TproxyCommand {
    pub(crate) program: &'static str,
    pub(crate) args: Vec<String>,
}

impl TproxyCommand {
    fn new(program: &'static str, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            program,
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    pub(crate) fn render(&self) -> String {
        if self.args.is_empty() {
            self.program.to_string()
        } else {
            format!("{} {}", self.program, self.args.join(" "))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpFamily {
    Ipv4,
    Ipv6,
}

impl IpFamily {
    fn route_name(self) -> &'static str {
        match self {
            Self::Ipv4 => "inet",
            Self::Ipv6 => "inet6",
        }
    }

    fn firewall_program(self) -> &'static str {
        match self {
            Self::Ipv4 => "iptables",
            Self::Ipv6 => "ip6tables",
        }
    }

    fn matches(self, net: &ipnet::IpNet) -> bool {
        matches!(
            (self, net),
            (Self::Ipv4, ipnet::IpNet::V4(_)) | (Self::Ipv6, ipnet::IpNet::V6(_))
        )
    }

    fn bypass_cidrs(self) -> &'static [&'static str] {
        match self {
            Self::Ipv4 => IPV4_BYPASS_CIDRS,
            Self::Ipv6 => IPV6_BYPASS_CIDRS,
        }
    }
}

fn enabled_families(plan: &CapturePlan) -> Vec<IpFamily> {
    let mut families = vec![IpFamily::Ipv4];
    if plan.ipv6_enabled {
        families.push(IpFamily::Ipv6);
    }
    families
}

pub(crate) fn setup_commands(plan: &CapturePlan, outbound_mark: u32) -> Vec<TproxyCommand> {
    let proxy_mark = format!("{TPROXY_FWMARK:#x}");
    let proxy_mark_mask = format!("{TPROXY_FWMARK:#x}/{TPROXY_FWMARK:#x}");
    let route_table = format!("{TPROXY_ROUTE_TABLE:#x}");
    let outbound_mark = format!("{outbound_mark:#x}");
    let port = TPROXY_PORT.to_string();
    let mut commands = Vec::new();

    for family in enabled_families(plan) {
        append_policy_setup(&mut commands, family, &proxy_mark, &route_table);
        append_firewall_setup(
            &mut commands,
            family,
            plan,
            &proxy_mark,
            &proxy_mark_mask,
            &outbound_mark,
            &port,
        );
    }

    commands
}

fn append_policy_setup(
    commands: &mut Vec<TproxyCommand>,
    family: IpFamily,
    proxy_mark: &str,
    route_table: &str,
) {
    commands.extend([
        TproxyCommand::new(
            "ip",
            [
                "-f",
                family.route_name(),
                "rule",
                "add",
                "fwmark",
                proxy_mark,
                "lookup",
                route_table,
            ],
        ),
        TproxyCommand::new(
            "ip",
            [
                "-f",
                family.route_name(),
                "route",
                "add",
                "local",
                "default",
                "dev",
                TPROXY_ROUTE_IFACE,
                "table",
                route_table,
            ],
        ),
    ]);
}

fn append_firewall_setup(
    commands: &mut Vec<TproxyCommand>,
    family: IpFamily,
    plan: &CapturePlan,
    proxy_mark: &str,
    proxy_mark_mask: &str,
    outbound_mark: &str,
    port: &str,
) {
    let firewall = family.firewall_program();
    commands.extend([
        TproxyCommand::new(firewall, ["-t", "mangle", "-N", TPROXY_DIVERT_CHAIN]),
        TproxyCommand::new(firewall, ["-t", "mangle", "-F", TPROXY_DIVERT_CHAIN]),
        TproxyCommand::new(
            firewall,
            [
                "-t",
                "mangle",
                "-A",
                TPROXY_DIVERT_CHAIN,
                "-j",
                "MARK",
                "--set-mark",
                proxy_mark,
            ],
        ),
        TproxyCommand::new(
            firewall,
            ["-t", "mangle", "-A", TPROXY_DIVERT_CHAIN, "-j", "ACCEPT"],
        ),
        TproxyCommand::new(firewall, ["-t", "mangle", "-N", TPROXY_PREROUTING_CHAIN]),
        TproxyCommand::new(firewall, ["-t", "mangle", "-F", TPROXY_PREROUTING_CHAIN]),
    ]);

    // Docker's default bridge is IPv4-only. Keep this source bypass scoped to
    // iptables so the generated ip6tables program never receives an invalid
    // IPv4 literal.
    if family == IpFamily::Ipv4 {
        commands.push(TproxyCommand::new(
            firewall,
            [
                "-t",
                "mangle",
                "-A",
                TPROXY_PREROUTING_CHAIN,
                "-s",
                "172.17.0.0/16",
                "-j",
                "RETURN",
            ],
        ));
    }

    commands.push(TproxyCommand::new(
        firewall,
        [
            "-t",
            "mangle",
            "-A",
            TPROXY_PREROUTING_CHAIN,
            "-m",
            "addrtype",
            "--dst-type",
            "LOCAL",
            "-j",
            "RETURN",
        ],
    ));
    append_bypass_rules(commands, firewall, TPROXY_PREROUTING_CHAIN, plan, family);

    commands.extend([
        TproxyCommand::new(
            firewall,
            [
                "-t",
                "mangle",
                "-A",
                TPROXY_PREROUTING_CHAIN,
                "-p",
                "tcp",
                "-m",
                "socket",
                "-j",
                TPROXY_DIVERT_CHAIN,
            ],
        ),
        TproxyCommand::new(
            firewall,
            [
                "-t",
                "mangle",
                "-A",
                TPROXY_PREROUTING_CHAIN,
                "-p",
                "udp",
                "-m",
                "socket",
                "-j",
                TPROXY_DIVERT_CHAIN,
            ],
        ),
        TproxyCommand::new(
            firewall,
            [
                "-t",
                "mangle",
                "-A",
                TPROXY_PREROUTING_CHAIN,
                "-p",
                "tcp",
                "-j",
                "TPROXY",
                "--on-port",
                port,
                "--tproxy-mark",
                proxy_mark_mask,
            ],
        ),
        TproxyCommand::new(
            firewall,
            [
                "-t",
                "mangle",
                "-A",
                TPROXY_PREROUTING_CHAIN,
                "-p",
                "udp",
                "-j",
                "TPROXY",
                "--on-port",
                port,
                "--tproxy-mark",
                proxy_mark_mask,
            ],
        ),
        TproxyCommand::new(
            firewall,
            [
                "-t",
                "mangle",
                "-A",
                "PREROUTING",
                "-j",
                TPROXY_PREROUTING_CHAIN,
            ],
        ),
        TproxyCommand::new(firewall, ["-t", "mangle", "-N", TPROXY_OUTPUT_CHAIN]),
        TproxyCommand::new(firewall, ["-t", "mangle", "-F", TPROXY_OUTPUT_CHAIN]),
        TproxyCommand::new(
            firewall,
            [
                "-t",
                "mangle",
                "-A",
                TPROXY_OUTPUT_CHAIN,
                "-m",
                "mark",
                "--mark",
                outbound_mark,
                "-j",
                "RETURN",
            ],
        ),
        TproxyCommand::new(
            firewall,
            [
                "-t",
                "mangle",
                "-A",
                TPROXY_OUTPUT_CHAIN,
                "-m",
                "addrtype",
                "--dst-type",
                "LOCAL",
                "-j",
                "RETURN",
            ],
        ),
    ]);

    // `--dst-type BROADCAST` is an IPv4 route type and is rejected by
    // ip6tables' addrtype matcher.
    if family == IpFamily::Ipv4 {
        commands.push(TproxyCommand::new(
            firewall,
            [
                "-t",
                "mangle",
                "-A",
                TPROXY_OUTPUT_CHAIN,
                "-m",
                "addrtype",
                "--dst-type",
                "BROADCAST",
                "-j",
                "RETURN",
            ],
        ));
    }

    append_bypass_rules(commands, firewall, TPROXY_OUTPUT_CHAIN, plan, family);
    commands.extend([
        TproxyCommand::new(
            firewall,
            [
                "-t",
                "mangle",
                "-A",
                TPROXY_OUTPUT_CHAIN,
                "-p",
                "tcp",
                "-j",
                "MARK",
                "--set-mark",
                proxy_mark,
            ],
        ),
        TproxyCommand::new(
            firewall,
            [
                "-t",
                "mangle",
                "-A",
                TPROXY_OUTPUT_CHAIN,
                "-p",
                "udp",
                "-j",
                "MARK",
                "--set-mark",
                proxy_mark,
            ],
        ),
        TproxyCommand::new(
            firewall,
            [
                "-t",
                "mangle",
                "-I",
                "OUTPUT",
                "-o",
                TPROXY_ROUTE_IFACE,
                "-j",
                TPROXY_OUTPUT_CHAIN,
            ],
        ),
    ]);
}

pub(crate) fn cleanup_commands(plan: &CapturePlan) -> Vec<TproxyCommand> {
    let proxy_mark = format!("{TPROXY_FWMARK:#x}");
    let route_table = format!("{TPROXY_ROUTE_TABLE:#x}");
    let mut commands = Vec::new();

    for family in enabled_families(plan) {
        append_family_cleanup(&mut commands, family, &proxy_mark, &route_table);
    }

    commands
}

fn append_family_cleanup(
    commands: &mut Vec<TproxyCommand>,
    family: IpFamily,
    proxy_mark: &str,
    route_table: &str,
) {
    let firewall = family.firewall_program();
    commands.extend([
        TproxyCommand::new(
            "ip",
            [
                "-f",
                family.route_name(),
                "rule",
                "del",
                "fwmark",
                proxy_mark,
                "lookup",
                route_table,
            ],
        ),
        TproxyCommand::new(
            "ip",
            [
                "-f",
                family.route_name(),
                "route",
                "del",
                "local",
                "default",
                "dev",
                TPROXY_ROUTE_IFACE,
                "table",
                route_table,
            ],
        ),
        TproxyCommand::new(
            firewall,
            [
                "-t",
                "mangle",
                "-D",
                "PREROUTING",
                "-j",
                TPROXY_PREROUTING_CHAIN,
            ],
        ),
        TproxyCommand::new(
            firewall,
            [
                "-t",
                "mangle",
                "-D",
                "OUTPUT",
                "-o",
                TPROXY_ROUTE_IFACE,
                "-j",
                TPROXY_OUTPUT_CHAIN,
            ],
        ),
        TproxyCommand::new(firewall, ["-t", "mangle", "-F", TPROXY_PREROUTING_CHAIN]),
        TproxyCommand::new(firewall, ["-t", "mangle", "-X", TPROXY_PREROUTING_CHAIN]),
        TproxyCommand::new(firewall, ["-t", "mangle", "-F", TPROXY_DIVERT_CHAIN]),
        TproxyCommand::new(firewall, ["-t", "mangle", "-X", TPROXY_DIVERT_CHAIN]),
        TproxyCommand::new(firewall, ["-t", "mangle", "-F", TPROXY_OUTPUT_CHAIN]),
        TproxyCommand::new(firewall, ["-t", "mangle", "-X", TPROXY_OUTPUT_CHAIN]),
    ]);
}

fn append_bypass_rules(
    commands: &mut Vec<TproxyCommand>,
    firewall: &'static str,
    chain: &str,
    plan: &CapturePlan,
    family: IpFamily,
) {
    let mut seen = std::collections::BTreeSet::new();
    for net in plan
        .exclude_cidrs
        .iter()
        .chain(plan.route_exclude_addresses.iter())
    {
        if family.matches(net) {
            push_bypass_rule(commands, firewall, chain, net.to_string(), &mut seen);
        }
    }
    for cidr in family.bypass_cidrs() {
        push_bypass_rule(commands, firewall, chain, (*cidr).to_string(), &mut seen);
    }
}

fn push_bypass_rule(
    commands: &mut Vec<TproxyCommand>,
    firewall: &'static str,
    chain: &str,
    cidr: String,
    seen: &mut std::collections::BTreeSet<String>,
) {
    if seen.insert(cidr.clone()) {
        commands.push(TproxyCommand::new(
            firewall,
            ["-t", "mangle", "-A", chain, "-d", &cidr, "-j", "RETURN"],
        ));
    }
}

#[cfg(test)]
mod tests {
    use core_config::model::{Capture, CaptureMethod};

    use super::*;

    fn tproxy_plan(ipv6_enabled: bool) -> CapturePlan {
        let mut c = Capture::default();
        c.on = true;
        c.method = CaptureMethod::VirtualNic;
        let mut plan = CapturePlan::from_config(&c).unwrap();
        plan.kind = crate::engine::EngineKind::Tproxy;
        plan.ipv6_enabled = ipv6_enabled;
        plan
    }

    #[test]
    fn setup_commands_match_mihomo_mark_route_and_output_bypass() {
        let cmds = setup_commands(&tproxy_plan(true), TPROXY_FWMARK);
        let rendered: Vec<String> = cmds.iter().map(TproxyCommand::render).collect();

        assert!(rendered.contains(&"ip -f inet rule add fwmark 0x2d0 lookup 0x2d0".to_string()));
        assert!(
            rendered.contains(&"ip -f inet route add local default dev lo table 0x2d0".to_string())
        );
        assert!(rendered.contains(
            &"iptables -t mangle -A WUTHERCORE_OUTPUT -m mark --mark 0x2d0 -j RETURN".to_string()
        ));
        assert!(rendered.contains(
            &"iptables -t mangle -A WUTHERCORE_PREROUTING -p tcp -m socket -j WUTHERCORE_DIVERT"
                .to_string()
        ));
        assert!(rendered.contains(&"iptables -t mangle -A WUTHERCORE_PREROUTING -p tcp -j TPROXY --on-port 7894 --tproxy-mark 0x2d0/0x2d0".to_string()));
        assert!(rendered.contains(&"iptables -t mangle -A WUTHERCORE_PREROUTING -p udp -j TPROXY --on-port 7894 --tproxy-mark 0x2d0/0x2d0".to_string()));
        assert!(
            rendered
                .contains(&"iptables -t mangle -I OUTPUT -o lo -j WUTHERCORE_OUTPUT".to_string())
        );
    }

    #[test]
    fn ipv6_setup_installs_policy_route_and_ip6tables_tproxy() {
        let rendered: Vec<String> = setup_commands(&tproxy_plan(true), TPROXY_FWMARK)
            .iter()
            .map(TproxyCommand::render)
            .collect();

        assert!(rendered.contains(&"ip -f inet6 rule add fwmark 0x2d0 lookup 0x2d0".to_string()));
        assert!(
            rendered
                .contains(&"ip -f inet6 route add local default dev lo table 0x2d0".to_string())
        );
        assert!(rendered.contains(&"ip6tables -t mangle -A WUTHERCORE_PREROUTING -p tcp -j TPROXY --on-port 7894 --tproxy-mark 0x2d0/0x2d0".to_string()));
        assert!(rendered.contains(&"ip6tables -t mangle -A WUTHERCORE_PREROUTING -p udp -j TPROXY --on-port 7894 --tproxy-mark 0x2d0/0x2d0".to_string()));
        assert!(
            rendered
                .contains(&"ip6tables -t mangle -I OUTPUT -o lo -j WUTHERCORE_OUTPUT".to_string())
        );
        assert!(
            !rendered
                .iter()
                .any(|command| command.starts_with("ip6tables ") && command.contains("BROADCAST"))
        );
    }

    #[test]
    fn disabling_ipv6_omits_every_ipv6_command() {
        let setup: Vec<String> = setup_commands(&tproxy_plan(false), TPROXY_FWMARK)
            .iter()
            .map(TproxyCommand::render)
            .collect();
        let cleanup: Vec<String> = cleanup_commands(&tproxy_plan(false))
            .iter()
            .map(TproxyCommand::render)
            .collect();

        for command in setup.iter().chain(cleanup.iter()) {
            assert!(!command.starts_with("ip6tables "));
            assert!(!command.starts_with("ip -f inet6 "));
        }
    }

    #[test]
    fn bypass_cidrs_are_emitted_only_for_their_address_family() {
        let mut plan = tproxy_plan(true);
        plan.exclude_cidrs = vec![
            "198.19.0.0/16".parse().unwrap(),
            "2001:db8:1234::/48".parse().unwrap(),
        ];
        let rendered: Vec<String> = setup_commands(&plan, TPROXY_FWMARK)
            .iter()
            .map(TproxyCommand::render)
            .collect();

        assert!(rendered.iter().any(|command| {
            command.starts_with("iptables ") && command.contains("-d 198.19.0.0/16 -j RETURN")
        }));
        assert!(rendered.iter().any(|command| {
            command.starts_with("ip6tables ") && command.contains("-d 2001:db8:1234::/48 -j RETURN")
        }));
        assert!(!rendered.iter().any(|command| {
            command.starts_with("iptables ") && command.contains("2001:db8:1234::/48")
        }));
        assert!(!rendered.iter().any(|command| {
            command.starts_with("ip6tables ") && command.contains("198.19.0.0/16")
        }));
    }

    #[test]
    fn cleanup_commands_remove_dual_stack_mark_routes_and_chains() {
        let cmds = cleanup_commands(&tproxy_plan(true));
        let rendered: Vec<String> = cmds.iter().map(TproxyCommand::render).collect();

        assert!(rendered.contains(&"ip -f inet rule del fwmark 0x2d0 lookup 0x2d0".to_string()));
        assert!(
            rendered.contains(&"ip -f inet route del local default dev lo table 0x2d0".to_string())
        );
        assert!(
            rendered
                .contains(&"iptables -t mangle -D PREROUTING -j WUTHERCORE_PREROUTING".to_string())
        );
        assert!(
            rendered
                .contains(&"iptables -t mangle -D OUTPUT -o lo -j WUTHERCORE_OUTPUT".to_string())
        );
        assert!(rendered.contains(&"ip -f inet6 rule del fwmark 0x2d0 lookup 0x2d0".to_string()));
        assert!(
            rendered
                .contains(&"ip -f inet6 route del local default dev lo table 0x2d0".to_string())
        );
        assert!(
            rendered.contains(
                &"ip6tables -t mangle -D PREROUTING -j WUTHERCORE_PREROUTING".to_string()
            )
        );
        assert!(
            rendered
                .contains(&"ip6tables -t mangle -D OUTPUT -o lo -j WUTHERCORE_OUTPUT".to_string())
        );
    }
}
