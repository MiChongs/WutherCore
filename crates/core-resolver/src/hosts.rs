//! Hosts file parser and lookup table.
//!
//! Resolves domains from system `/etc/hosts` (or Windows equivalent)
//! and custom user-provided mappings before the DNS policy engine.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
};

use crate::cache::QType;

#[derive(Debug, Clone, Default)]
pub struct HostsEntry {
    pub ipv4: Vec<Ipv4Addr>,
    pub ipv6: Vec<Ipv6Addr>,
}

#[derive(Debug, Clone)]
pub struct HostsTable {
    entries: HashMap<String, HostsEntry>,
}

impl HostsTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn load_system() -> Self {
        let path = system_hosts_path();
        match std::fs::read_to_string(path) {
            Ok(content) => Self::parse(&content),
            Err(_) => Self::new(),
        }
    }

    pub fn load_mapping(map: &serde_yaml::Mapping) -> Self {
        let mut table = Self::new();
        for (key, value) in map {
            let Some(domain) = key.as_str() else {
                continue;
            };
            let domain_lc = domain.trim_end_matches('.').to_lowercase();
            let ips = match value {
                serde_yaml::Value::String(s) => vec![s.clone()],
                serde_yaml::Value::Sequence(seq) => seq
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect(),
                _ => continue,
            };
            let entry = table.entries.entry(domain_lc).or_default();
            for ip_str in &ips {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    match ip {
                        IpAddr::V4(v4) => entry.ipv4.push(v4),
                        IpAddr::V6(v6) => entry.ipv6.push(v6),
                    }
                }
            }
        }
        table
    }

    pub fn merge(&mut self, other: Self) {
        for (domain, other_entry) in other.entries {
            let entry = self.entries.entry(domain).or_default();
            entry.ipv4.extend(other_entry.ipv4);
            entry.ipv6.extend(other_entry.ipv6);
        }
    }

    pub fn lookup(&self, host: &str, qtype: QType) -> Option<Vec<IpAddr>> {
        let entry = self.entries.get(host)?;
        let ips: Vec<IpAddr> = match qtype {
            QType::A => entry.ipv4.iter().copied().map(IpAddr::V4).collect(),
            QType::AAAA => entry.ipv6.iter().copied().map(IpAddr::V6).collect(),
            QType::Both => entry
                .ipv4
                .iter()
                .copied()
                .map(IpAddr::V4)
                .chain(entry.ipv6.iter().copied().map(IpAddr::V6))
                .collect(),
        };
        if ips.is_empty() { None } else { Some(ips) }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    fn parse(content: &str) -> Self {
        let mut table = Self::new();
        for line in content.lines() {
            let line = line.trim();
            // strip comments
            let line = match line.find('#') {
                Some(pos) => &line[..pos],
                None => line,
            };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(ip_str) = parts.next() else {
                continue;
            };
            let Ok(ip) = ip_str.parse::<IpAddr>() else {
                continue;
            };
            for hostname in parts {
                let domain_lc = hostname.trim_end_matches('.').to_lowercase();
                let entry = table.entries.entry(domain_lc).or_default();
                match ip {
                    IpAddr::V4(v4) => {
                        if !entry.ipv4.contains(&v4) {
                            entry.ipv4.push(v4);
                        }
                    }
                    IpAddr::V6(v6) => {
                        if !entry.ipv6.contains(&v6) {
                            entry.ipv6.push(v6);
                        }
                    }
                }
            }
        }
        table
    }
}

impl Default for HostsTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "windows")]
fn system_hosts_path() -> &'static Path {
    Path::new(r"C:\Windows\System32\drivers\etc\hosts")
}

#[cfg(not(target_os = "windows"))]
fn system_hosts_path() -> &'static Path {
    Path::new("/etc/hosts")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_hosts() {
        let content = r#"
# comment line
127.0.0.1   localhost
::1         localhost ip6-localhost
192.168.1.1 myserver.local myserver
"#;
        let table = HostsTable::parse(content);
        // localhost, ip6-localhost, myserver.local, myserver = 4 unique hosts
        assert_eq!(table.len(), 4);

        let localhost = table.lookup("localhost", QType::A).unwrap();
        assert_eq!(localhost, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);

        let localhost6 = table.lookup("localhost", QType::AAAA).unwrap();
        assert_eq!(localhost6, vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]);

        let both = table.lookup("localhost", QType::Both).unwrap();
        assert_eq!(both.len(), 2);

        let server = table.lookup("myserver.local", QType::A).unwrap();
        assert_eq!(server, vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))]);

        let alias = table.lookup("myserver", QType::A).unwrap();
        assert_eq!(alias, vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))]);
    }

    #[test]
    fn inline_comments() {
        let content = "10.0.0.1 foo.bar # some comment\n";
        let table = HostsTable::parse(content);
        assert!(table.lookup("foo.bar", QType::A).is_some());
    }

    #[test]
    fn empty_and_missing() {
        let table = HostsTable::new();
        assert!(table.lookup("nope", QType::A).is_none());
    }

    #[test]
    fn merge_tables() {
        let content1 = "1.1.1.1 example.com\n";
        let content2 = "2.2.2.2 example.com\n8.8.8.8 dns.google\n";
        let mut t1 = HostsTable::parse(content1);
        let t2 = HostsTable::parse(content2);
        t1.merge(t2);

        let ips = t1.lookup("example.com", QType::A).unwrap();
        assert_eq!(ips.len(), 2);
        assert!(t1.lookup("dns.google", QType::A).is_some());
    }

    #[test]
    fn case_insensitive() {
        let content = "10.0.0.1 MyHost.Local\n";
        let table = HostsTable::parse(content);
        assert!(table.lookup("myhost.local", QType::A).is_some());
    }

    #[test]
    fn trailing_dot_stripped() {
        let content = "10.0.0.1 example.com.\n";
        let table = HostsTable::parse(content);
        assert!(table.lookup("example.com", QType::A).is_some());
    }

    #[test]
    fn load_mapping() {
        let mut map = serde_yaml::Mapping::new();
        map.insert(
            serde_yaml::Value::String("test.local".into()),
            serde_yaml::Value::String("192.168.0.1".into()),
        );
        map.insert(
            serde_yaml::Value::String("multi.local".into()),
            serde_yaml::Value::Sequence(vec![
                serde_yaml::Value::String("10.0.0.1".into()),
                serde_yaml::Value::String("10.0.0.2".into()),
            ]),
        );
        let table = HostsTable::load_mapping(&map);
        let ips = table.lookup("test.local", QType::A).unwrap();
        assert_eq!(ips.len(), 1);
        let ips = table.lookup("multi.local", QType::A).unwrap();
        assert_eq!(ips.len(), 2);
    }
}
