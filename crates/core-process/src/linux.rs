//! Linux finder —— 解析 `/proc/net/{tcp,tcp6,udp,udp6}` → inode → 扫
//! `/proc/*/fd/*` 找到对应 PID。
//!
//! 与 mihomo `process_linux.go` 在没有 netlink 的 fallback 路径相同。这里
//! 没用 netlink (`SOCK_DIAG_BY_FAMILY`) 是为了避免 unsafe + raw socket
//! 权限要求；纯文本解析在 100 进程 / 1000 fd 的台式机上 1-3ms 足够。
//!
//! Android 共用此实现（[`super::android`] 里直接 re-export）。Android 8+ 对
//! 跨 UID 的 `/proc/<pid>/fd/` 访问受限，反查只能命中 *自己* 进程的连接 ——
//! 多数 dashboard 使用场景里 WutherCore 自己进程的 socket 不会经过 TUN，
//! 所以 Android 上这个 finder 返回 None 是预期行为；建议 Android 用户用
//! `find-process-mode: off` 或单独走 `ConnectivityManager.getConnectionOwnerUid`。

use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
};

use crate::{NetworkProto, ProcessFinder, ProcessInfo};

#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxFinder;

impl LinuxFinder {
    pub fn new() -> Self {
        Self
    }
}

impl ProcessFinder for LinuxFinder {
    fn find(&self, proto: NetworkProto, src_ip: IpAddr, src_port: u16) -> Option<ProcessInfo> {
        let inode = match (proto, src_ip) {
            (NetworkProto::Tcp, IpAddr::V4(v4)) => find_inode_v4("/proc/net/tcp", v4, src_port)
                .or_else(|| find_inode_v6("/proc/net/tcp6", Ipv6Addr::UNSPECIFIED, src_port)),
            (NetworkProto::Tcp, IpAddr::V6(v6)) => find_inode_v6("/proc/net/tcp6", v6, src_port),
            (NetworkProto::Udp, IpAddr::V4(v4)) => find_inode_v4("/proc/net/udp", v4, src_port)
                .or_else(|| find_inode_v6("/proc/net/udp6", Ipv6Addr::UNSPECIFIED, src_port)),
            (NetworkProto::Udp, IpAddr::V6(v6)) => find_inode_v6("/proc/net/udp6", v6, src_port),
        }?;
        let (pid, uid) = find_pid_for_inode(inode)?;
        let path = read_link(&format!("/proc/{pid}/exe")).unwrap_or_default();
        let name = if !path.is_empty() {
            Path::new(&path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        } else {
            // 容器或权限受限时 /proc/<pid>/exe 读不到 —— 退回 /proc/<pid>/comm
            fs::read_to_string(format!("/proc/{pid}/comm"))
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        };
        Some(ProcessInfo { name, path, uid })
    }
}

fn find_inode_v4(path: &str, addr: Ipv4Addr, port: u16) -> Option<u64> {
    let content = fs::read_to_string(path).ok()?;
    for line in content.lines().skip(1) {
        let mut parts = line.split_ascii_whitespace();
        let _ = parts.next()?; // sl
        let local = parts.next()?;
        let _remote = parts.next()?;
        let _state = parts.next()?;
        let _tx_rx = parts.next()?;
        let _tr = parts.next()?;
        let _retrnsmt = parts.next()?;
        let uid_field = parts.next()?;
        let _timeout = parts.next()?;
        let inode = parts.next()?;
        let (laddr_hex, lport_hex) = local.split_once(':')?;
        if u16::from_str_radix(lport_hex, 16).ok()? != port {
            continue;
        }
        let laddr = parse_v4_hex(laddr_hex)?;
        let any = Ipv4Addr::UNSPECIFIED;
        if laddr != addr && laddr != any {
            continue;
        }
        let inode_u64 = inode.parse::<u64>().ok()?;
        if inode_u64 == 0 {
            // socket 已关闭但还在表里
            continue;
        }
        // uid_field 我们暂不向上传，find_pid_for_inode 会从 /proc/<pid>/status 读
        let _ = uid_field;
        return Some(inode_u64);
    }
    None
}

fn find_inode_v6(path: &str, addr: Ipv6Addr, port: u16) -> Option<u64> {
    let content = fs::read_to_string(path).ok()?;
    for line in content.lines().skip(1) {
        let mut parts = line.split_ascii_whitespace();
        let _ = parts.next()?; // sl
        let local = parts.next()?;
        let _remote = parts.next()?;
        let _state = parts.next()?;
        let _tx_rx = parts.next()?;
        let _tr = parts.next()?;
        let _retrnsmt = parts.next()?;
        let _uid = parts.next()?;
        let _timeout = parts.next()?;
        let inode = parts.next()?;
        let (laddr_hex, lport_hex) = local.split_once(':')?;
        if u16::from_str_radix(lport_hex, 16).ok()? != port {
            continue;
        }
        let laddr = parse_v6_hex(laddr_hex)?;
        let any = Ipv6Addr::UNSPECIFIED;
        if laddr != addr && laddr != any {
            continue;
        }
        let inode_u64 = inode.parse::<u64>().ok()?;
        if inode_u64 == 0 {
            continue;
        }
        return Some(inode_u64);
    }
    None
}

/// `/proc/net/tcp` 的 IPv4 地址是小端 `AABBCCDD` —— `0100007F` = `127.0.0.1`。
fn parse_v4_hex(s: &str) -> Option<Ipv4Addr> {
    if s.len() != 8 {
        return None;
    }
    let bytes = u32::from_str_radix(s, 16).ok()?.to_le_bytes();
    Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

/// `/proc/net/tcp6` 的 IPv6 地址是 32 hex 字符，按 4 个 32-bit 小端块拼接。
fn parse_v6_hex(s: &str) -> Option<Ipv6Addr> {
    if s.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let hex = &s[i * 8..(i + 1) * 8];
        let block_le = u32::from_str_radix(hex, 16).ok()?.to_le_bytes();
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&block_le);
    }
    Some(Ipv6Addr::from(bytes))
}

/// 扫 `/proc/<pid>/fd/*` 找 `socket:[inode]`，返回 (pid, uid)。
fn find_pid_for_inode(inode: u64) -> Option<(u32, u32)> {
    let target = format!("socket:[{inode}]");
    let proc = fs::read_dir("/proc").ok()?;
    for entry in proc.flatten() {
        let pid: u32 = match entry.file_name().to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let fd_dir = entry.path().join("fd");
        let fd_iter = match fs::read_dir(&fd_dir) {
            Ok(d) => d,
            Err(_) => continue,
        };
        for fd in fd_iter.flatten() {
            let link = match fs::read_link(fd.path()) {
                Ok(l) => l,
                Err(_) => continue,
            };
            if link.to_string_lossy() == target {
                let uid = read_status_uid(pid).unwrap_or(0);
                return Some((pid, uid));
            }
        }
    }
    None
}

fn read_link(path: &str) -> Option<String> {
    fs::read_link(path)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

fn read_status_uid(pid: u32) -> Option<u32> {
    let content = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            let real_uid = rest.split_ascii_whitespace().next()?;
            return real_uid.parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_v4_hex_loopback() {
        assert_eq!(
            parse_v4_hex("0100007F").unwrap(),
            Ipv4Addr::new(127, 0, 0, 1)
        );
    }

    #[test]
    fn parse_v4_hex_unspecified() {
        assert_eq!(parse_v4_hex("00000000").unwrap(), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn parse_v6_hex_loopback() {
        // ::1 in /proc/net/tcp6 little-endian-block layout
        assert_eq!(
            parse_v6_hex("00000000000000000000000001000000").unwrap(),
            Ipv6Addr::LOCALHOST
        );
    }

    #[test]
    fn parse_v6_hex_unspecified() {
        assert_eq!(
            parse_v6_hex("00000000000000000000000000000000").unwrap(),
            Ipv6Addr::UNSPECIFIED
        );
    }

    /// 当 /proc 不存在或为空时 finder 返回 None，不应 panic。
    #[test]
    fn missing_inode_returns_none() {
        let finder = LinuxFinder::new();
        // 用一个肯定没人监听的高端口
        let res = finder.find(NetworkProto::Tcp, "127.0.0.1".parse().unwrap(), 64999);
        // 在不是 Linux 的 CI 上 read /proc/net/tcp 会 fail → None；
        // 在 Linux 上 64999 没人监听 → None。
        assert!(res.is_none());
    }
}
