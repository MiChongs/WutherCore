//! 路由表管理 —— 跨平台抽象 + 真实平台调用。
//!
//! 添加与撤销路由必须配对，否则会污染系统路由表。所有由 capture 写入的路由
//! 由 [`RouteTable`] 集中持有，进程退出/Stop 时统一回滚。
//!
//! ## 平台后端
//!
//! | 平台    | add 命令                                              | del 命令                                |
//! |---------|-------------------------------------------------------|-----------------------------------------|
//! | Linux   | `ip route add <dest> dev <iface> [via <gw>] metric N` | `ip route del <dest> ...`               |
//! | macOS   | `route -n add -net <dest> -interface <iface>`         | `route -n delete -net <dest>`           |
//! | Windows | `route ADD <dest> MASK <mask> <gw> METRIC N IF <idx>` | `route DELETE <dest>`                   |
//!
//! 添加失败会返回给调用方，且不会写入回滚账本；调用方可自行决定是否降级。
//! 撤销已成功添加的路由时尽力回滚（best-effort）。

use std::{net::IpAddr, process::Command, sync::Arc};

use ipnet::IpNet;
use parking_lot::Mutex;
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct ManagedRoute {
    pub dest: IpNet,
    pub gateway: Option<IpAddr>,
    pub interface: String,
    pub metric: u32,
    /// Linux/Android policy routing table. `None` means main table / platform default.
    pub table: Option<u32>,
}

/// 平台无关后端。tests 可注入 fake backend；prod 用 [`SystemBackend`]。
pub trait RouteBackend: Send + Sync + std::fmt::Debug {
    fn add(&self, r: &ManagedRoute) -> Result<(), String>;
    fn del(&self, r: &ManagedRoute) -> Result<(), String>;
}

#[derive(Debug)]
pub struct RouteTable {
    inner: Mutex<Vec<ManagedRoute>>,
    backend: Arc<dyn RouteBackend>,
}

impl Default for RouteTable {
    fn default() -> Self {
        Self::with_backend(Arc::new(SystemBackend))
    }
}

impl RouteTable {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn with_backend(backend: Arc<dyn RouteBackend>) -> Self {
        Self {
            inner: Mutex::new(Vec::new()),
            backend,
        }
    }

    /// 添加并真实写入。
    ///
    /// 只有后端确认成功后才写入回滚账本。失败的路由不能被记账，否则
    /// [`Self::revert_all`] 可能在退出时删除一条并非由本进程创建的系统路由。
    pub fn add(&self, r: ManagedRoute) -> Result<(), String> {
        self.backend.add(&r).map_err(|e| {
            warn!(target: "capture::route", error = %e, dest = %r.dest, iface = %r.interface, table = ?r.table, metric = r.metric, "route add failed");
            e
        })?;
        info!(target: "capture::route", dest = %r.dest, iface = %r.interface, gw = ?r.gateway, table = ?r.table, metric = r.metric, "route added");
        self.inner.lock().push(r);
        Ok(())
    }

    pub fn list(&self) -> Vec<ManagedRoute> {
        self.inner.lock().clone()
    }

    /// 退出时回滚所有由本管理器创建的路由（best-effort）。
    pub fn revert_all(&self) {
        let _ = self.revert_all_impl(false);
    }

    /// Revert the full ledger while returning every unexpected backend error.
    ///
    /// Ordinary best-effort platform cleanup can keep using
    /// [`Self::revert_all`]. Transactional callers use this variant so a
    /// failed `route`/`netsh` deletion is not reported as a clean shutdown.
    pub fn revert_all_checked(&self) -> Result<(), String> {
        self.revert_all_impl(true)
    }

    fn revert_all_impl(&self, retain_failed: bool) -> Result<(), String> {
        let mut g = self.inner.lock();
        let mut errors = Vec::new();
        let mut failed = Vec::new();
        let routes = std::mem::take(&mut *g);
        for r in routes.into_iter().rev() {
            match self.backend.del(&r) {
                Ok(()) => {
                    debug!(target: "capture::route", dest = %r.dest, iface = %r.interface, table = ?r.table, "route reverted");
                }
                Err(e) => {
                    if is_expected_route_delete_absence(&e) {
                        debug!(target: "capture::route", error = %e, dest = %r.dest, iface = %r.interface, table = ?r.table, "route already absent");
                    } else {
                        warn!(target: "capture::route", error = %e, dest = %r.dest, iface = %r.interface, table = ?r.table, "route revert failed");
                        errors.push(format!(
                            "{} via {} (table {:?}): {e}",
                            r.dest, r.interface, r.table
                        ));
                        if retain_failed {
                            failed.push(r);
                        }
                    }
                }
            }
        }
        // Deletion runs in reverse insertion order. Restore the ledger's
        // original order so every subsequent retry is reversed as well.
        failed.reverse();
        g.extend(failed);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }
}

/* ---------------- 系统后端 ---------------- */

#[derive(Debug)]
pub struct SystemBackend;

impl RouteBackend for SystemBackend {
    fn add(&self, r: &ManagedRoute) -> Result<(), String> {
        platform_add(r)
    }
    fn del(&self, r: &ManagedRoute) -> Result<(), String> {
        platform_del(r)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn platform_add(r: &ManagedRoute) -> Result<(), String> {
    let dest = r.dest.to_string();
    let metric = r.metric.to_string();
    let mut args: Vec<&str> = if r.dest.addr().is_ipv6() {
        vec![
            "-6",
            "route",
            "add",
            &dest,
            "dev",
            &r.interface,
            "metric",
            &metric,
        ]
    } else {
        vec![
            "route",
            "add",
            &dest,
            "dev",
            &r.interface,
            "metric",
            &metric,
        ]
    };
    let gw_str;
    if let Some(gw) = r.gateway {
        gw_str = gw.to_string();
        args.extend_from_slice(&["via", &gw_str]);
    }
    let table_str;
    if let Some(table) = r.table {
        table_str = table.to_string();
        args.extend_from_slice(&["table", &table_str]);
    }
    run_cmd("ip", &args)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn platform_del(r: &ManagedRoute) -> Result<(), String> {
    let dest = r.dest.to_string();
    let metric = r.metric.to_string();
    let mut args: Vec<&str> = if r.dest.addr().is_ipv6() {
        vec![
            "-6",
            "route",
            "del",
            &dest,
            "dev",
            &r.interface,
            "metric",
            &metric,
        ]
    } else {
        vec![
            "route",
            "del",
            &dest,
            "dev",
            &r.interface,
            "metric",
            &metric,
        ]
    };
    let table_str;
    if let Some(table) = r.table {
        table_str = table.to_string();
        args.extend_from_slice(&["table", &table_str]);
    }
    run_cmd("ip", &args)
}

#[cfg(target_os = "macos")]
fn platform_add(r: &ManagedRoute) -> Result<(), String> {
    let family = if r.dest.addr().is_ipv6() {
        "-inet6"
    } else {
        "-inet"
    };
    let dest = r.dest.to_string();
    let mut args: Vec<&str> = vec!["-n", "add", family, "-net", &dest];
    let gw_str;
    if let Some(gw) = r.gateway {
        gw_str = gw.to_string();
        args.extend_from_slice(&[&gw_str]);
    } else {
        args.extend_from_slice(&["-interface", &r.interface]);
    }
    run_cmd("route", &args)
}

#[cfg(target_os = "macos")]
fn platform_del(r: &ManagedRoute) -> Result<(), String> {
    let family = if r.dest.addr().is_ipv6() {
        "-inet6"
    } else {
        "-inet"
    };
    let dest = r.dest.to_string();
    let args: Vec<&str> = vec!["-n", "delete", family, "-net", &dest];
    run_cmd("route", &args)
}

#[cfg(target_os = "windows")]
fn platform_add(r: &ManagedRoute) -> Result<(), String> {
    // Windows 的 route 命令接受 IPv4 dotted mask；IPv6 用 netsh。
    if r.dest.addr().is_ipv6() {
        if r.gateway.is_some_and(|gateway| gateway.is_ipv4()) {
            return Err("IPv6 route cannot use an IPv4 next hop".into());
        }
        let args = windows_ipv6_route_args(r, true);
        let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
        run_cmd("netsh", &refs)
    } else {
        let interface_index = if_index_from_name(&r.interface)?;
        let args = windows_ipv4_route_args(r, interface_index, true);
        let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
        run_cmd("route", &refs)
    }
}

#[cfg(target_os = "windows")]
fn platform_del(r: &ManagedRoute) -> Result<(), String> {
    if r.dest.addr().is_ipv6() {
        if r.gateway.is_some_and(|gateway| gateway.is_ipv4()) {
            return Err("IPv6 route cannot use an IPv4 next hop".into());
        }
        let args = windows_ipv6_route_args(r, false);
        let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
        run_cmd("netsh", &refs)
    } else {
        let interface_index = if_index_from_name(&r.interface)?;
        let args = windows_ipv4_route_args(r, interface_index, false);
        let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
        run_cmd("route", &refs)
    }
}

#[cfg(target_os = "windows")]
fn windows_ipv4_route_args(route: &ManagedRoute, interface_index: u32, add: bool) -> Vec<String> {
    let mut args = vec![
        if add { "ADD" } else { "DELETE" }.into(),
        route.dest.network().to_string(),
        "MASK".into(),
        ipv4_mask(route.dest.prefix_len()),
        route
            .gateway
            .map(|gateway| gateway.to_string())
            .unwrap_or_else(|| "0.0.0.0".into()),
    ];
    if add {
        args.extend(["METRIC".into(), route.metric.to_string()]);
    }
    args.extend(["IF".into(), interface_index.to_string()]);
    args
}

#[cfg(target_os = "windows")]
fn windows_ipv6_route_args(route: &ManagedRoute, add: bool) -> Vec<String> {
    let mut args = vec![
        "interface".into(),
        "ipv6".into(),
        if add { "add" } else { "delete" }.into(),
        "route".into(),
        format!("prefix={}", route.dest),
        format!("interface={}", route.interface),
        format!(
            "nexthop={}",
            route
                .gateway
                .map(|gateway| gateway.to_string())
                .unwrap_or_else(|| "::".into())
        ),
    ];
    if add {
        args.push(format!("metric={}", route.metric));
    }
    // netsh defaults route mutations to PersistentStore. Capture routes must
    // never survive a crash or reboot.
    args.push("store=active".into());
    args
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "windows"
)))]
fn platform_add(_r: &ManagedRoute) -> Result<(), String> {
    Err("unsupported platform".into())
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "windows"
)))]
fn platform_del(_r: &ManagedRoute) -> Result<(), String> {
    Err("unsupported platform".into())
}

#[cfg(target_os = "windows")]
fn ipv4_mask(prefix: u8) -> String {
    let mask: u32 = if prefix == 0 {
        0
    } else {
        (!0u32) << (32 - prefix.min(32))
    };
    std::net::Ipv4Addr::from(mask).to_string()
}

#[cfg(target_os = "windows")]
fn if_index_from_name(name: &str) -> Result<u32, String> {
    // `netsh interface show interface` 的输出第 4 列是接口名；用 `netsh
    // interface ipv4 show interfaces` 拿索引（idx 在第 1 列）。
    let output = std::process::Command::new("netsh")
        .args(["interface", "ipv4", "show", "interfaces"])
        .output()
        .map_err(|error| format!("spawn netsh while resolving interface {name:?}: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        return Err(format!(
            "netsh interface lookup failed (status={:?}): {detail}",
            output.status.code()
        ));
    }
    let txt = String::from_utf8_lossy(&output.stdout);
    for line in txt.lines().skip(3) {
        // 行格式：Idx     Met         MTU          State                Name
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let if_name = parts[4..].join(" ");
        if if_name.eq_ignore_ascii_case(name) {
            return parts[0].parse::<u32>().map_err(|error| {
                format!(
                    "invalid interface index {:?} for {name:?}: {error}",
                    parts[0]
                )
            });
        }
    }
    Err(format!(
        "Windows interface {name:?} was not present in netsh interface list"
    ))
}

fn run_cmd(prog: &str, args: &[&str]) -> Result<(), String> {
    debug!(target: "capture::route", cmd = %prog, ?args, "exec");
    // 用 output() 捕获 stderr 不外泄到终端 —— 错误内容只走 tracing。
    let st = Command::new(prog)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("spawn {prog}: {e}"))?;
    if st.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&st.stderr);
        let stdout = String::from_utf8_lossy(&st.stdout);
        let detail = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        Err(format!(
            "{prog} failed (status={:?}): {detail}",
            st.status.code(),
        ))
    }
}

fn is_expected_route_delete_absence(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    if lower.starts_with("spawn ") {
        return false;
    }
    [
        "rtnetlink answers: no such process",
        "rtnetlink answers: no such file or directory",
        "no such process",
        "not in table",
        "element not found",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Debug, Default)]
    struct FakeBackend {
        added: AtomicUsize,
        deleted: AtomicUsize,
        fail_add: bool,
    }

    impl RouteBackend for FakeBackend {
        fn add(&self, _r: &ManagedRoute) -> Result<(), String> {
            self.added.fetch_add(1, Ordering::Relaxed);
            if self.fail_add {
                Err("add failed".into())
            } else {
                Ok(())
            }
        }
        fn del(&self, _r: &ManagedRoute) -> Result<(), String> {
            self.deleted.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn add_and_revert_uses_backend() {
        let backend = Arc::new(FakeBackend::default());
        let table = RouteTable::with_backend(backend.clone());
        table
            .add(ManagedRoute {
                dest: "0.0.0.0/0".parse().unwrap(),
                gateway: None,
                interface: "rpktun0".into(),
                metric: 1,
                table: Some(2024),
            })
            .unwrap();
        table
            .add(ManagedRoute {
                dest: "::/0".parse().unwrap(),
                gateway: None,
                interface: "rpktun0".into(),
                metric: 1,
                table: Some(2024),
            })
            .unwrap();
        assert_eq!(table.len(), 2);
        assert_eq!(backend.added.load(Ordering::Relaxed), 2);
        table.revert_all();
        assert_eq!(table.len(), 0);
        assert_eq!(backend.deleted.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn failed_add_is_returned_and_never_reverted() {
        let backend = Arc::new(FakeBackend {
            fail_add: true,
            ..Default::default()
        });
        let table = RouteTable::with_backend(backend.clone());
        let err = table
            .add(ManagedRoute {
                dest: "0.0.0.0/0".parse().unwrap(),
                gateway: None,
                interface: "rpktun0".into(),
                metric: 1,
                table: Some(2024),
            })
            .expect_err("backend failure must reach the caller");

        assert_eq!(err, "add failed");
        assert_eq!(backend.added.load(Ordering::Relaxed), 1);
        assert!(
            table.is_empty(),
            "failed route must not enter rollback ledger"
        );

        table.revert_all();
        assert_eq!(
            backend.deleted.load(Ordering::Relaxed),
            0,
            "rollback must not delete a route this process never created"
        );
    }

    #[test]
    fn managed_route_preserves_policy_table() {
        let r = ManagedRoute {
            dest: "0.0.0.0/1".parse().unwrap(),
            gateway: None,
            interface: "rpktun0".into(),
            metric: 0,
            table: Some(2024),
        };

        assert_eq!(r.table, Some(2024));
    }

    #[test]
    fn revert_failure_does_not_crash() {
        #[derive(Debug, Default)]
        struct FailBackend;
        impl RouteBackend for FailBackend {
            fn add(&self, _r: &ManagedRoute) -> Result<(), String> {
                Ok(())
            }
            fn del(&self, _r: &ManagedRoute) -> Result<(), String> {
                Err("boom".into())
            }
        }
        let table = RouteTable::with_backend(Arc::new(FailBackend));
        table
            .add(ManagedRoute {
                dest: "10.0.0.0/8".parse().unwrap(),
                gateway: None,
                interface: "x".into(),
                metric: 1,
                table: None,
            })
            .unwrap();
        table.revert_all(); // best-effort，不能 panic
        assert!(table.is_empty());
    }

    #[test]
    fn checked_revert_surfaces_backend_failure_and_retains_it_for_retry() {
        #[derive(Debug, Default)]
        struct FailBackend;
        impl RouteBackend for FailBackend {
            fn add(&self, _r: &ManagedRoute) -> Result<(), String> {
                Ok(())
            }
            fn del(&self, _r: &ManagedRoute) -> Result<(), String> {
                Err("injected delete failure".into())
            }
        }
        let table = RouteTable::with_backend(Arc::new(FailBackend));
        table
            .add(ManagedRoute {
                dest: "10.0.0.0/8".parse().unwrap(),
                gateway: None,
                interface: "test-tun".into(),
                metric: 1,
                table: None,
            })
            .unwrap();

        let error = table.revert_all_checked().unwrap_err();

        assert!(error.contains("injected delete failure"));
        assert!(error.contains("10.0.0.0/8 via test-tun"));
        assert_eq!(table.len(), 1, "failed deletion must remain retryable");
    }

    #[test]
    fn checked_revert_retries_in_reverse_insertion_order() {
        #[derive(Debug, Default)]
        struct RecordingFailBackend {
            deleted: Mutex<Vec<String>>,
        }
        impl RouteBackend for RecordingFailBackend {
            fn add(&self, _r: &ManagedRoute) -> Result<(), String> {
                Ok(())
            }
            fn del(&self, r: &ManagedRoute) -> Result<(), String> {
                self.deleted.lock().push(r.dest.to_string());
                Err("injected delete failure".into())
            }
        }

        let backend = Arc::new(RecordingFailBackend::default());
        let table = RouteTable::with_backend(backend.clone());
        for dest in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] {
            table
                .add(ManagedRoute {
                    dest: dest.parse().unwrap(),
                    gateway: None,
                    interface: "test-tun".into(),
                    metric: 1,
                    table: None,
                })
                .unwrap();
        }

        assert!(table.revert_all_checked().is_err());
        assert!(table.revert_all_checked().is_err());
        assert_eq!(
            *backend.deleted.lock(),
            [
                "192.168.0.0/16",
                "172.16.0.0/12",
                "10.0.0.0/8",
                "192.168.0.0/16",
                "172.16.0.0/12",
                "10.0.0.0/8",
            ]
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_ipv4_delete_targets_only_the_managed_interface() {
        let route = ManagedRoute {
            dest: "0.0.0.0/0".parse().unwrap(),
            gateway: None,
            interface: "WutherCoreTun".into(),
            metric: 0,
            table: None,
        };

        assert_eq!(
            windows_ipv4_route_args(&route, 42, false),
            [
                "DELETE", "0.0.0.0", "MASK", "0.0.0.0", "0.0.0.0", "IF", "42",
            ]
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_ipv6_routes_are_exact_and_active_only() {
        let route = ManagedRoute {
            dest: "::/0".parse().unwrap(),
            gateway: Some("fe80::1".parse().unwrap()),
            interface: "WutherCoreTun".into(),
            metric: 7,
            table: None,
        };

        assert_eq!(
            windows_ipv6_route_args(&route, true),
            [
                "interface",
                "ipv6",
                "add",
                "route",
                "prefix=::/0",
                "interface=WutherCoreTun",
                "nexthop=fe80::1",
                "metric=7",
                "store=active",
            ]
        );
        assert_eq!(
            windows_ipv6_route_args(&route, false),
            [
                "interface",
                "ipv6",
                "delete",
                "route",
                "prefix=::/0",
                "interface=WutherCoreTun",
                "nexthop=fe80::1",
                "store=active",
            ]
        );
    }

    #[test]
    fn linux_route_delete_no_such_process_is_expected_absence() {
        assert!(is_expected_route_delete_absence(
            "ip failed (status=Some(2)): RTNETLINK answers: No such process",
        ));
    }

    #[test]
    fn missing_route_command_is_not_expected_absence() {
        assert!(!is_expected_route_delete_absence(
            "spawn ip: No such file or directory",
        ));
    }
}
