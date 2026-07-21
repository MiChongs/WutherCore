//! Pure capture-private DNS listener selection shared by startup and resource
//! arbitration.

const WINDOWS_FAKE_DNS_LISTEN_ADDRS: &[&str] = &["127.0.0.1:53", "[::1]:53"];
const UNIX_FAKE_DNS_LISTEN_ADDRS: &[&str] = &["127.0.0.1:5454"];

pub(crate) fn fake_dns_listen_addrs() -> &'static [&'static str] {
    fake_dns_listen_addrs_for_windows(cfg!(target_os = "windows"))
}

pub(crate) fn fake_dns_listen_addrs_for_windows(windows: bool) -> &'static [&'static str] {
    if windows {
        // WindowsTun redirects both IPv4 and IPv6 resolver families here.
        WINDOWS_FAKE_DNS_LISTEN_ADDRS
    } else {
        // Unix capture keeps the private listener away from privileged port 53.
        UNIX_FAKE_DNS_LISTEN_ADDRS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_listener_sets_are_explicit_and_stable() {
        assert_eq!(
            fake_dns_listen_addrs_for_windows(true),
            ["127.0.0.1:53", "[::1]:53"]
        );
        assert_eq!(fake_dns_listen_addrs_for_windows(false), ["127.0.0.1:5454"]);
    }
}
