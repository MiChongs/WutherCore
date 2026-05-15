#![cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]

use crate::engine::CapturePlan;

pub(crate) const TPROXY_FWMARK: u32 = 0x2d0;
pub(crate) const TPROXY_PORT: u16 = 7894;
pub(crate) const TPROXY_ROUTE_IFACE: &str = "lo";

const TPROXY_ROUTE_TABLE: u32 = 0x2d0;
const TPROXY_PREROUTING_CHAIN: &str = "WUTHERCORE_PREROUTING";
const TPROXY_OUTPUT_CHAIN: &str = "WUTHERCORE_OUTPUT";
const TPROXY_DIVERT_CHAIN: &str = "WUTHERCORE_DIVERT";

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

pub(crate) fn setup_commands(plan: &CapturePlan, outbound_mark: u32) -> Vec<TproxyCommand> {
    let proxy_mark = format!("{TPROXY_FWMARK:#x}");
    let proxy_mark_mask = format!("{TPROXY_FWMARK:#x}/{TPROXY_FWMARK:#x}");
    let route_table = format!("{TPROXY_ROUTE_TABLE:#x}");
    let outbound_mark = format!("{outbound_mark:#x}");
    let port = TPROXY_PORT.to_string();
    let mut cmds = vec![
        TproxyCommand::new(
            "ip",
            [
                "-f",
                "inet",
                "rule",
                "add",
                "fwmark",
                &proxy_mark,
                "lookup",
                &route_table,
            ],
        ),
        TproxyCommand::new(
            "ip",
            [
                "-f",
                "inet",
                "route",
                "add",
                "local",
                "default",
                "dev",
                TPROXY_ROUTE_IFACE,
                "table",
                &route_table,
            ],
        ),
        TproxyCommand::new("iptables", ["-t", "mangle", "-N", TPROXY_DIVERT_CHAIN]),
        TproxyCommand::new("iptables", ["-t", "mangle", "-F", TPROXY_DIVERT_CHAIN]),
        TproxyCommand::new(
            "iptables",
            [
                "-t",
                "mangle",
                "-A",
                TPROXY_DIVERT_CHAIN,
                "-j",
                "MARK",
                "--set-mark",
                &proxy_mark,
            ],
        ),
        TproxyCommand::new(
            "iptables",
            ["-t", "mangle", "-A", TPROXY_DIVERT_CHAIN, "-j", "ACCEPT"],
        ),
        TproxyCommand::new("iptables", ["-t", "mangle", "-N", TPROXY_PREROUTING_CHAIN]),
        TproxyCommand::new("iptables", ["-t", "mangle", "-F", TPROXY_PREROUTING_CHAIN]),
        TproxyCommand::new(
            "iptables",
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
        ),
        TproxyCommand::new(
            "iptables",
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
        ),
    ];
    append_bypass_rules(&mut cmds, TPROXY_PREROUTING_CHAIN, plan);
    cmds.extend([
        TproxyCommand::new(
            "iptables",
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
            "iptables",
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
            "iptables",
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
                &port,
                "--tproxy-mark",
                &proxy_mark_mask,
            ],
        ),
        TproxyCommand::new(
            "iptables",
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
                &port,
                "--tproxy-mark",
                &proxy_mark_mask,
            ],
        ),
        TproxyCommand::new(
            "iptables",
            [
                "-t",
                "mangle",
                "-A",
                "PREROUTING",
                "-j",
                TPROXY_PREROUTING_CHAIN,
            ],
        ),
        TproxyCommand::new("iptables", ["-t", "mangle", "-N", TPROXY_OUTPUT_CHAIN]),
        TproxyCommand::new("iptables", ["-t", "mangle", "-F", TPROXY_OUTPUT_CHAIN]),
        TproxyCommand::new(
            "iptables",
            [
                "-t",
                "mangle",
                "-A",
                TPROXY_OUTPUT_CHAIN,
                "-m",
                "mark",
                "--mark",
                &outbound_mark,
                "-j",
                "RETURN",
            ],
        ),
        TproxyCommand::new(
            "iptables",
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
        TproxyCommand::new(
            "iptables",
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
        ),
    ]);
    append_bypass_rules(&mut cmds, TPROXY_OUTPUT_CHAIN, plan);
    cmds.extend([
        TproxyCommand::new(
            "iptables",
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
                &proxy_mark,
            ],
        ),
        TproxyCommand::new(
            "iptables",
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
                &proxy_mark,
            ],
        ),
        TproxyCommand::new(
            "iptables",
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
    cmds
}

pub(crate) fn cleanup_commands(_plan: &CapturePlan) -> Vec<TproxyCommand> {
    let proxy_mark = format!("{TPROXY_FWMARK:#x}");
    let route_table = format!("{TPROXY_ROUTE_TABLE:#x}");
    vec![
        TproxyCommand::new(
            "ip",
            [
                "-f",
                "inet",
                "rule",
                "del",
                "fwmark",
                &proxy_mark,
                "lookup",
                &route_table,
            ],
        ),
        TproxyCommand::new(
            "ip",
            [
                "-f",
                "inet",
                "route",
                "del",
                "local",
                "default",
                "dev",
                TPROXY_ROUTE_IFACE,
                "table",
                &route_table,
            ],
        ),
        TproxyCommand::new(
            "iptables",
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
            "iptables",
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
        TproxyCommand::new("iptables", ["-t", "mangle", "-F", TPROXY_PREROUTING_CHAIN]),
        TproxyCommand::new("iptables", ["-t", "mangle", "-X", TPROXY_PREROUTING_CHAIN]),
        TproxyCommand::new("iptables", ["-t", "mangle", "-F", TPROXY_DIVERT_CHAIN]),
        TproxyCommand::new("iptables", ["-t", "mangle", "-X", TPROXY_DIVERT_CHAIN]),
        TproxyCommand::new("iptables", ["-t", "mangle", "-F", TPROXY_OUTPUT_CHAIN]),
        TproxyCommand::new("iptables", ["-t", "mangle", "-X", TPROXY_OUTPUT_CHAIN]),
    ]
}

fn append_bypass_rules(cmds: &mut Vec<TproxyCommand>, chain: &str, plan: &CapturePlan) {
    let mut seen = std::collections::BTreeSet::new();
    for net in plan
        .exclude_cidrs
        .iter()
        .chain(plan.route_exclude_addresses.iter())
    {
        if matches!(net, ipnet::IpNet::V4(_)) {
            push_bypass_rule(cmds, chain, net.to_string(), &mut seen);
        }
    }
    for cidr in [
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
    ] {
        push_bypass_rule(cmds, chain, cidr.to_string(), &mut seen);
    }
}

fn push_bypass_rule(
    cmds: &mut Vec<TproxyCommand>,
    chain: &str,
    cidr: String,
    seen: &mut std::collections::BTreeSet<String>,
) {
    if seen.insert(cidr.clone()) {
        cmds.push(TproxyCommand::new(
            "iptables",
            ["-t", "mangle", "-A", chain, "-d", &cidr, "-j", "RETURN"],
        ));
    }
}

#[cfg(test)]
mod tests {
    use core_config::model::{Capture, CaptureMethod};

    use super::*;

    fn tproxy_plan() -> CapturePlan {
        let mut c = Capture::default();
        c.on = true;
        c.method = CaptureMethod::VirtualNic;
        let mut plan = CapturePlan::from_config(&c).unwrap();
        plan.kind = crate::engine::EngineKind::Tproxy;
        plan
    }

    #[test]
    fn setup_commands_match_mihomo_mark_route_and_output_bypass() {
        let cmds = setup_commands(&tproxy_plan(), TPROXY_FWMARK);
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
    fn cleanup_commands_remove_mihomo_mark_route_and_chains() {
        let cmds = cleanup_commands(&tproxy_plan());
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
    }
}
