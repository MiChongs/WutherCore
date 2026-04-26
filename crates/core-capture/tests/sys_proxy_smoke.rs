//! SystemProxyGuard 在 enabled=false 时无副作用。

use core_capture::sys_proxy::SystemProxyGuard;
use core_config::model::TunHttpProxyOptions;

#[test]
fn disabled_install_then_revert_no_panic() {
    let opts = TunHttpProxyOptions {
        enabled: false,
        server: "127.0.0.1".into(),
        server_port: 8080,
        bypass_domain: vec!["localhost".into(), "*.lan".into()],
        match_domain: vec![],
    };
    let g = SystemProxyGuard::install(&opts);
    g.revert();
}
