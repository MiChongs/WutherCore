//! macOS finder —— `proc_listpids` + `proc_pidinfo(PROC_PIDLISTFDS)` +
//! `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)`，与 mihomo `process_darwin.go` 的
//! `findProcessName` 等价。
//!
//! 流程：
//! 1. `proc_listpids(PROC_ALL_PIDS)` —— 列出当前所有 PID；
//! 2. 对每个 PID `proc_pidinfo(PROC_PIDLISTFDS)` —— 拿到 fd 列表；
//! 3. 对每个 fd 中 fdtype==SOCKET 的，`proc_pidfdinfo(PROC_PIDFDSOCKETINFO)`
//!    填 `socket_fdinfo`，比对 (proto, laddr, lport)；
//! 4. 命中 → `proc_pidpath` 拿可执行路径。
//!
//! `proc_*` 系列 API 在 macOS 10.5 之后稳定；非特权进程能扫所有进程的 socket 列表
//! （内核只过滤了 ptrace / process_kernel 类的访问）。

use std::{
    ffi::{CStr, c_int, c_void},
    mem::{size_of, zeroed},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
};

use crate::{NetworkProto, ProcessFinder, ProcessInfo};

const PROC_ALL_PIDS: u32 = 1;
const PROC_PIDLISTFDS: c_int = 1;
const PROC_PIDFDSOCKETINFO: c_int = 3;
const PROX_FDTYPE_SOCKET: u32 = 2;
const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;

const SOCKINFO_TCP: i32 = 2;
const SOCKINFO_IN: i32 = 1;

const AF_INET: i32 = 2;
const AF_INET6: i32 = 30;

/// `struct proc_fdinfo` —— 16 字节，layout 与 sys/proc_info.h 一致。
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcFdInfo {
    proc_fd: i32,
    proc_fdtype: u32,
}

/// `struct in4in6_addr` —— sys/proc_info.h。
#[repr(C)]
#[derive(Clone, Copy)]
struct In4In6Addr {
    i46a_pad32: [u32; 3],
    i46a_addr4: u32, // network-byte-order
}

#[repr(C)]
#[derive(Clone, Copy)]
union InsiAddr4Or6 {
    insi_v4: In4In6Addr,
    insi_v6: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InSockInfo {
    insi_fport: i32, // foreign port (network byte order in low 16)
    insi_lport: i32, // local port (network byte order in low 16)
    insi_gencnt: u64,
    insi_flags: u32,
    insi_flow: u32,
    insi_vflag: u8, // INI_IPV4 / INI_IPV6
    insi_ip_ttl: u8,
    rfu_1: u32,
    insi_faddr: InsiAddr4Or6,
    insi_laddr: InsiAddr4Or6,
    insi_v4: u8, // tos
    insi_v6_hlim: u8,
    insi_v6_cksum: u8,
    insi_v6_ifindex: u16,
    insi_v6_hops: u16,
}

const INI_IPV4: u8 = 0x1;
const INI_IPV6: u8 = 0x2;

#[repr(C)]
#[derive(Clone, Copy)]
struct TcpSockInfo {
    tcpsi_ini: InSockInfo,
    tcpsi_state: i32,
    tcpsi_timer: [i32; 4],
    tcpsi_mss: i32,
    tcpsi_flags: u32,
    rfu_1: u32,
    tcpsi_tp: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
union ProSockInfoPri {
    pri_in: InSockInfo,
    pri_tcp: TcpSockInfo,
    /// 占位，确保 union 至少容纳 mihomo 关心的两种。
    /// 实际 sys/proc_info.h 还有 pri_un / pri_kern_event / pri_kern_ctl —
    /// 我们不会读它们，按字节对齐到最大成员即可。
    _pad: [u8; 524],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SocketInfo {
    soi_stat: [u8; 152], // vinfo_stat —— 我们不使用，按字节占位
    soi_so: u64,
    soi_pcb: u64,
    soi_type: i32,
    soi_protocol: i32,
    soi_family: i32,
    soi_options: i16,
    soi_linger: i16,
    soi_state: i16,
    soi_qlen: i16,
    soi_incqlen: i16,
    soi_qlimit: i16,
    soi_timeo: i16,
    soi_error: u16,
    soi_oobmark: u32,
    soi_rcv: [u8; 56], // sockbuf_info —— 占位
    soi_snd: [u8; 56], // sockbuf_info —— 占位
    soi_kind: i32,
    rfu_1: u32,
    soi_proto: ProSockInfoPri,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SocketFdInfo {
    pfi: [u8; 152], // proc_fileinfo —— 占位
    psi: SocketInfo,
}

unsafe extern "C" {
    fn proc_listpids(type_: u32, typeinfo: u32, buffer: *mut c_void, buffersize: c_int) -> c_int;
    fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        arg: u64,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
    fn proc_pidfdinfo(
        pid: c_int,
        fd: c_int,
        flavor: c_int,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
    fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffersize: u32) -> c_int;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct MacosFinder;

impl MacosFinder {
    pub fn new() -> Self {
        Self
    }
}

impl ProcessFinder for MacosFinder {
    fn find(&self, proto: NetworkProto, src_ip: IpAddr, src_port: u16) -> Option<ProcessInfo> {
        let pid = match unsafe { find_pid(proto, src_ip, src_port) } {
            Some(p) => p,
            None => return None,
        };
        let path = unsafe { read_pidpath(pid).unwrap_or_default() };
        let name = Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Some(ProcessInfo { name, path, uid: 0 })
    }
}

unsafe fn find_pid(proto: NetworkProto, src_ip: IpAddr, src_port: u16) -> Option<i32> {
    // 1) 列出全部 PID
    let needed_bytes = proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0);
    if needed_bytes <= 0 {
        return None;
    }
    let count = needed_bytes as usize / size_of::<i32>();
    let mut pids = vec![0i32; count];
    let got = proc_listpids(PROC_ALL_PIDS, 0, pids.as_mut_ptr().cast(), needed_bytes);
    if got <= 0 {
        return None;
    }
    let n = got as usize / size_of::<i32>();
    pids.truncate(n);

    let want_v4 = matches!(src_ip, IpAddr::V4(_));
    let port_be = (src_port as u32).to_be();

    for &pid in &pids {
        if pid <= 0 {
            continue;
        }
        // 2) 列出 PID 的 fd
        let fdsize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0);
        if fdsize <= 0 {
            continue;
        }
        let fd_count = fdsize as usize / size_of::<ProcFdInfo>();
        let mut fds = vec![
            ProcFdInfo {
                proc_fd: 0,
                proc_fdtype: 0
            };
            fd_count
        ];
        let got_fd = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds.as_mut_ptr().cast(), fdsize);
        if got_fd <= 0 {
            continue;
        }
        let real_count = got_fd as usize / size_of::<ProcFdInfo>();
        for fd in fds.iter().take(real_count) {
            if fd.proc_fdtype != PROX_FDTYPE_SOCKET {
                continue;
            }
            let mut info: SocketFdInfo = zeroed();
            let r = proc_pidfdinfo(
                pid,
                fd.proc_fd,
                PROC_PIDFDSOCKETINFO,
                (&mut info) as *mut SocketFdInfo as *mut c_void,
                size_of::<SocketFdInfo>() as c_int,
            );
            if r <= 0 {
                continue;
            }
            let socket = &info.psi;
            // proto 过滤
            let proto_match = match proto {
                NetworkProto::Tcp => socket.soi_kind == SOCKINFO_TCP,
                NetworkProto::Udp => {
                    socket.soi_kind == SOCKINFO_IN && socket.soi_protocol == 17 // IPPROTO_UDP
                }
            };
            if !proto_match {
                continue;
            }
            let ini = if socket.soi_kind == SOCKINFO_TCP {
                &socket.soi_proto.pri_tcp.tcpsi_ini
            } else {
                &socket.soi_proto.pri_in
            };
            // lport 比对（高 16 bit 是 BE port）
            if (ini.insi_lport as u32) & 0xffff != port_be & 0xffff {
                continue;
            }
            // 地址族过滤
            let is_v4 = (ini.insi_vflag & INI_IPV4) != 0;
            let is_v6 = (ini.insi_vflag & INI_IPV6) != 0;
            match src_ip {
                IpAddr::V4(target) => {
                    let raw_addr = if is_v4 {
                        let a = ini.insi_laddr.insi_v4.i46a_addr4;
                        Some(Ipv4Addr::from(u32::from_be(a)))
                    } else if is_v6 {
                        // dual-stack 上可能 v6 socket 收 v4 流量，地址会是 ::
                        let bytes = ini.insi_laddr.insi_v6;
                        if bytes == [0u8; 16] {
                            None // 视为 wildcard
                        } else if bytes[..10] == [0u8; 10] && bytes[10] == 0xff && bytes[11] == 0xff
                        {
                            Some(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]))
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    };
                    match raw_addr {
                        Some(a) if a == target || a == Ipv4Addr::UNSPECIFIED => {
                            return Some(pid);
                        }
                        None => return Some(pid), // wildcard ::
                        _ => continue,
                    }
                }
                IpAddr::V6(target) => {
                    if !is_v6 {
                        continue;
                    }
                    let bytes = ini.insi_laddr.insi_v6;
                    let a = Ipv6Addr::from(bytes);
                    if a == target || a == Ipv6Addr::UNSPECIFIED {
                        return Some(pid);
                    }
                }
            }
        }
        let _ = want_v4;
    }
    None
}

unsafe fn read_pidpath(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE];
    let r = proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32);
    if r <= 0 {
        return None;
    }
    buf.truncate(r as usize);
    let path_len = buf.iter().position(|&byte| byte == 0).unwrap_or(buf.len());
    buf.truncate(path_len);
    buf.push(0);
    let cstr = CStr::from_bytes_with_nul(&buf).ok()?;
    Some(cstr.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_port_returns_none() {
        let finder = MacosFinder::new();
        assert!(
            finder
                .find(NetworkProto::Tcp, "127.0.0.1".parse().unwrap(), 64999)
                .is_none()
        );
    }

    #[test]
    fn tcp_listener_self_lookup() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let finder = MacosFinder::new();
        let info = finder
            .find(NetworkProto::Tcp, "127.0.0.1".parse().unwrap(), port)
            .expect("self lookup must hit");
        assert!(!info.path.is_empty());
        assert!(!info.name.is_empty());
    }
}
