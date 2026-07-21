//! Profile 默认值合并 —— §2.3 表格"默认值必须可靠"。
//!
//! 用户写得越少，profile 给的默认越多。同一文件 + 同一 profile
//! 必须每次启动得到同一份运行时配置（确定性）。

use crate::model::*;

/// 给定 profile，把所有未填写的字段填上默认值。
pub fn apply_defaults(cfg: &mut UserConfig) {
    // listen
    let profile = cfg.profile;
    let listen = cfg.listen.get_or_insert_with(|| Listen {
        local: None,
        panel: None,
        share: None,
        auth: vec![],
        reality: vec![],
    });
    if listen.local.is_none() {
        listen.local = match profile {
            Profile::Server => None,
            _ => Some(ListenLocal::Port(7890)),
        };
    }
    if listen.panel.is_none() {
        listen.panel = match profile {
            Profile::Server => Some(PanelBind::Address("127.0.0.1:9090".into())),
            _ => Some(PanelBind::Port(9090)),
        };
    }
    if listen.share.is_none() {
        listen.share = match profile {
            Profile::Router => Some(Share::Home),
            _ => Some(Share::False),
        };
    }

    // groups —— 至少有一个 main 组
    if cfg.groups.is_empty() {
        let mut g = GroupSpec {
            choose: ChooseStrategy::Smart,
            r#use: vec![],
            prefer: vec![],
            avoid: vec![],
            check: None,
            sticky: None,
            path: vec![],
        };
        // 默认引用所有 feeds 与 nodes
        for k in cfg.feeds.keys() {
            g.r#use.push(k.clone());
        }
        if !cfg.nodes.is_empty() {
            g.r#use.push("nodes".into());
        }
        cfg.groups.insert("main".into(), g);
    }

    // route
    if cfg.route.is_none() {
        cfg.route = Some(Route {
            preset: match profile {
                Profile::Server => "global".into(),
                _ => "cn_smart".into(),
            },
            r#final: "main".into(),
            steps: vec![],
            sets: Default::default(),
            rule_set: vec![],
        });
    }

    // resolver
    if cfg.resolver.is_none() {
        cfg.resolver = Some(Resolver {
            mode: match profile {
                Profile::Server => ResolverMode::Normal,
                _ => ResolverMode::Normal,
            },
            ..Resolver::default()
        });
    }
    let resolver = cfg.resolver.as_mut().unwrap();
    if resolver.servers.is_empty() {
        // 与 mihomo 默认一致：IP-host DoH，SNI 默认 = host（rustls IpAddress 验证）。
        resolver
            .servers
            .insert("ali".into(), "https://223.5.5.5/dns-query".into());
        resolver
            .servers
            .insert("cloudflare".into(), "https://1.1.1.1/dns-query".into());
    }
    if resolver.nameserver.is_empty() {
        if resolver.servers.contains_key("ali") {
            resolver.nameserver.push("ali".into());
        } else if let Some(first) = resolver.servers.keys().next().cloned() {
            resolver.nameserver.push(first);
        }
    }
    if resolver.fallback.is_empty() && resolver.servers.contains_key("cloudflare") {
        resolver.fallback.push("cloudflare".into());
    }

    // capture
    if cfg.capture.is_none() {
        cfg.capture = Some(Capture {
            on: matches!(profile, Profile::Router),
            ..Capture::default()
        });
    }

    // smart
    if cfg.smart.is_none() {
        cfg.smart = Some(Smart::default());
    }

    // ui
    if cfg.ui.is_none() {
        cfg.ui = Some(Ui::default());
    }

    // mesh.tailscale.keep_tailnet_direct 默认 true
    let mesh = cfg.mesh.get_or_insert_with(Mesh::default);
    if mesh.tailscale.is_none() {
        mesh.tailscale = Some(MeshTailscale::default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_defaults_filled() {
        let mut cfg = UserConfig {
            version: 1,
            profile: Profile::Desktop,
            ..Default::default()
        };
        apply_defaults(&mut cfg);
        assert!(cfg.listen.is_some());
        assert!(cfg.groups.contains_key("main"));
        assert_eq!(cfg.route.as_ref().unwrap().preset, "cn_smart");
        assert!(matches!(
            cfg.resolver.as_ref().unwrap().mode,
            ResolverMode::Normal
        ));
        assert!(cfg.smart.as_ref().unwrap().on);
    }

    #[test]
    fn router_enables_capture() {
        let mut cfg = UserConfig {
            version: 1,
            profile: Profile::Router,
            ..Default::default()
        };
        apply_defaults(&mut cfg);
        assert!(cfg.capture.as_ref().unwrap().on);
    }

    #[test]
    fn server_disables_local_listen() {
        let mut cfg = UserConfig {
            version: 1,
            profile: Profile::Server,
            ..Default::default()
        };
        apply_defaults(&mut cfg);
        assert!(cfg.listen.as_ref().unwrap().local.is_none());
        assert_eq!(cfg.route.as_ref().unwrap().preset, "global");
    }
}
