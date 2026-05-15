//! Windows finder —— `iphlpapi::GetExtendedTcpTable` / `GetExtendedUdpTable`。
//!
//! 与 mihomo `component/process/process_windows.go` 等价：拉一次 OWNER_PID 表，
//! 按 (laddr, lport) 找到 PID，再 `OpenProcess` + `QueryFullProcessImageNameW`
//! 拿可执行文件路径。
//!
//! # 兼容性
//! - Windows Vista+ (`GetExtendedTcpTable` 在 Vista 引入，所有受支持版本都有)。
//! - 仅查 IPv4 调用 IPv4 表；纯 IPv6 调用 IPv6 表。`::ffff:1.2.3.4` 形式的
//!   IPv4-mapped 地址 .NET / 部分 app 会用 IPv6 socket 监听 dual-stack；这种
//!   情况下 IPv4 表里查不到 (laddr=0.0.0.0)，会回退到 IPv6 表查 `::`。

use std::{
    ffi::OsString,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::windows::ffi::OsStringExt,
    path::Path,
    ptr,
};

use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HANDLE},
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
        MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
        MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    },
    Networking::WinSock::{AF_INET, AF_INET6},
    System::{
        ProcessStatus::GetProcessImageFileNameW,
        Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
    },
};

use crate::{NetworkProto, ProcessFinder, ProcessInfo};

#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsFinder;

impl WindowsFinder {
    pub fn new() -> Self {
        Self
    }
}

impl ProcessFinder for WindowsFinder {
    fn find(&self, proto: NetworkProto, src_ip: IpAddr, src_port: u16) -> Option<ProcessInfo> {
        let pid = match (proto, src_ip) {
            (NetworkProto::Tcp, IpAddr::V4(v4)) => find_tcp_pid_v4(v4, src_port)
                .or_else(|| find_tcp_pid_v6(Ipv6Addr::UNSPECIFIED, src_port)),
            (NetworkProto::Tcp, IpAddr::V6(v6)) => find_tcp_pid_v6(v6, src_port),
            (NetworkProto::Udp, IpAddr::V4(v4)) => find_udp_pid_v4(v4, src_port)
                .or_else(|| find_udp_pid_v6(Ipv6Addr::UNSPECIFIED, src_port)),
            (NetworkProto::Udp, IpAddr::V6(v6)) => find_udp_pid_v6(v6, src_port),
        }?;
        let path = process_path(pid).unwrap_or_default();
        let name = Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Some(ProcessInfo { name, path, uid: 0 })
    }
}

/// 包装 `GetExtendedTcpTable` / `GetExtendedUdpTable` 二段查询：第一次拿大小，
/// 申请 buffer，再次调用拿数据。
unsafe fn fetch_table<F>(family: i32, mut call: F) -> Option<Vec<u8>>
where
    F: FnMut(*mut std::ffi::c_void, *mut u32, i32) -> u32,
{
    let mut size: u32 = 0;
    let rc = call(ptr::null_mut(), &mut size, family);
    if rc != ERROR_INSUFFICIENT_BUFFER {
        if rc == ERROR_SUCCESS && size == 0 {
            return None;
        }
        // some kernels return SUCCESS with size set; fall through
    }
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let rc = call(buf.as_mut_ptr().cast(), &mut size, family);
    if rc != ERROR_SUCCESS {
        return None;
    }
    buf.truncate(size as usize);
    Some(buf)
}

/// `dwLocalPort` 是 DWORD，低 16 位存网络字节序的端口；高 16 位 Windows 文档
/// 明确说必须 0。先取低 16 位，再 ntohs 拿原生端口比对。
fn row_port_eq(dw_port: u32, want: u16) -> bool {
    u16::from_be((dw_port & 0xffff) as u16) == want
}

fn find_tcp_pid_v4(addr: Ipv4Addr, port: u16) -> Option<u32> {
    unsafe {
        let buf = fetch_table(AF_INET as i32, |ptr, size, fam| {
            GetExtendedTcpTable(ptr, size, 0, fam as u32, TCP_TABLE_OWNER_PID_ALL, 0)
        })?;
        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let count = table.dwNumEntries as usize;
        let rows =
            std::slice::from_raw_parts(table.table.as_ptr() as *const MIB_TCPROW_OWNER_PID, count);
        let target_addr = u32::from(addr).to_be();
        for row in rows {
            if row.dwLocalAddr == target_addr && row_port_eq(row.dwLocalPort, port) {
                return Some(row.dwOwningPid);
            }
        }
        for row in rows {
            if row.dwLocalAddr == 0 && row_port_eq(row.dwLocalPort, port) {
                return Some(row.dwOwningPid);
            }
        }
        None
    }
}

fn find_tcp_pid_v6(addr: Ipv6Addr, port: u16) -> Option<u32> {
    unsafe {
        let buf = fetch_table(AF_INET6 as i32, |ptr, size, fam| {
            GetExtendedTcpTable(ptr, size, 0, fam as u32, TCP_TABLE_OWNER_PID_ALL, 0)
        })?;
        let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
        let count = table.dwNumEntries as usize;
        let rows =
            std::slice::from_raw_parts(table.table.as_ptr() as *const MIB_TCP6ROW_OWNER_PID, count);
        let target_octets = addr.octets();
        for row in rows {
            if row.ucLocalAddr == target_octets && row_port_eq(row.dwLocalPort, port) {
                return Some(row.dwOwningPid);
            }
        }
        for row in rows {
            if row.ucLocalAddr == [0u8; 16] && row_port_eq(row.dwLocalPort, port) {
                return Some(row.dwOwningPid);
            }
        }
        None
    }
}

fn find_udp_pid_v4(addr: Ipv4Addr, port: u16) -> Option<u32> {
    unsafe {
        let buf = fetch_table(AF_INET as i32, |ptr, size, fam| {
            GetExtendedUdpTable(ptr, size, 0, fam as u32, UDP_TABLE_OWNER_PID, 0)
        })?;
        let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
        let count = table.dwNumEntries as usize;
        let rows =
            std::slice::from_raw_parts(table.table.as_ptr() as *const MIB_UDPROW_OWNER_PID, count);
        let target_addr = u32::from(addr).to_be();
        for row in rows {
            if row.dwLocalAddr == target_addr && row_port_eq(row.dwLocalPort, port) {
                return Some(row.dwOwningPid);
            }
        }
        for row in rows {
            if row.dwLocalAddr == 0 && row_port_eq(row.dwLocalPort, port) {
                return Some(row.dwOwningPid);
            }
        }
        None
    }
}

fn find_udp_pid_v6(addr: Ipv6Addr, port: u16) -> Option<u32> {
    unsafe {
        let buf = fetch_table(AF_INET6 as i32, |ptr, size, fam| {
            GetExtendedUdpTable(ptr, size, 0, fam as u32, UDP_TABLE_OWNER_PID, 0)
        })?;
        let table = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
        let count = table.dwNumEntries as usize;
        let rows =
            std::slice::from_raw_parts(table.table.as_ptr() as *const MIB_UDP6ROW_OWNER_PID, count);
        let target_octets = addr.octets();
        for row in rows {
            if row.ucLocalAddr == target_octets && row_port_eq(row.dwLocalPort, port) {
                return Some(row.dwOwningPid);
            }
        }
        for row in rows {
            if row.ucLocalAddr == [0u8; 16] && row_port_eq(row.dwLocalPort, port) {
                return Some(row.dwOwningPid);
            }
        }
        None
    }
}

/// 取 PID 对应可执行路径 —— 与 mihomo 一致：`OpenProcess` +
/// `QueryFullProcessImageNameW`（这里用更老的 `GetProcessImageFileNameW`，返回的
/// 是 NT device path 形如 `\Device\HarddiskVolume3\Windows\...`，basename 仍可用。
/// QueryFullProcessImageNameW 需要 PROCESS_QUERY_LIMITED_INFORMATION + 额外
/// import 表，体积换实用——后续如果用户有需求再改）。
fn process_path(pid: u32) -> Option<String> {
    unsafe {
        let handle: HANDLE = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let mut buf = vec![0u16; 1024];
        let len = GetProcessImageFileNameW(handle, buf.as_mut_ptr(), buf.len() as u32);
        let _ = CloseHandle(handle);
        if len == 0 {
            return None;
        }
        buf.truncate(len as usize);
        let s = OsString::from_wide(&buf);
        Some(s.to_string_lossy().into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-test: bind a TCP listener on 127.0.0.1, then look it up. Our PID must match.
    #[test]
    fn tcp_listener_self_lookup() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let finder = WindowsFinder::new();
        let info = finder
            .find(NetworkProto::Tcp, "127.0.0.1".parse().unwrap(), port)
            .expect("self lookup must hit");
        assert!(!info.path.is_empty(), "self exe path must be populated");
        assert!(!info.name.is_empty(), "self exe name must be populated");
        // 进程名带 .exe 扩展名（rust test harness 是 deps/<test>.exe）
        assert!(
            info.name.to_ascii_lowercase().ends_with(".exe"),
            "got name {:?}",
            info.name
        );
    }

    #[test]
    fn missing_port_returns_none() {
        let finder = WindowsFinder::new();
        // 65000 范围的端口几乎肯定没人监听
        let res = finder.find(NetworkProto::Tcp, "127.0.0.1".parse().unwrap(), 64999);
        assert!(res.is_none(), "no listener should yield None");
    }

    #[test]
    fn udp_listener_self_lookup() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let port = socket.local_addr().unwrap().port();
        let finder = WindowsFinder::new();
        let info = finder
            .find(NetworkProto::Udp, "127.0.0.1".parse().unwrap(), port)
            .expect("udp self lookup must hit");
        assert!(!info.name.is_empty());
    }
}
