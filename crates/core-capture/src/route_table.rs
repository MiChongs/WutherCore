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
//! | Windows | IP Helper `CreateIpForwardEntry2`                    | `DeleteIpForwardEntry2`                 |
//!
//! 添加失败会返回给调用方，且不会写入回滚账本；调用方可自行决定是否降级。
//! 撤销已成功添加的路由时尽力回滚（best-effort）。

use std::{net::IpAddr, sync::Arc};

#[cfg(target_os = "macos")]
use std::process::Command;

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
    /// Ensure an owned route still exists without adding another ledger item.
    fn ensure(&self, r: &ManagedRoute) -> Result<(), String> {
        self.add(r)
    }
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

    /// Re-assert routes already present in the ownership ledger.
    ///
    /// This is used after Windows network profile/interface changes, where
    /// the OS may discard routes while the Wintun adapter remains alive.
    pub fn reconcile_all(&self) -> Result<(), String> {
        let routes = self.inner.lock().clone();
        let errors = routes
            .iter()
            .filter_map(|route| self.backend.ensure(route).err())
            .collect::<Vec<_>>();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
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
    #[cfg(target_os = "windows")]
    fn ensure(&self, r: &ManagedRoute) -> Result<(), String> {
        windows_ensure_route(r)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn platform_add(r: &ManagedRoute) -> Result<(), String> {
    crate::linux_netlink::add_route(r)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn platform_del(r: &ManagedRoute) -> Result<(), String> {
    crate::linux_netlink::delete_route(r)
}

#[cfg(target_os = "windows")]
fn windows_ensure_route(r: &ManagedRoute) -> Result<(), String> {
    let route = windows_native_route(r)?;
    let mut manager = route_manager::RouteManager::new()
        .map_err(|error| format!("open Windows IP Helper route manager: {error}"))?;
    let exists = manager
        .list()
        .map_err(|error| format!("GetIpForwardTable2: {error}"))?
        .into_iter()
        .any(|current| {
            current.destination() == route.destination()
                && current.prefix() == route.prefix()
                && current.if_name() == route.if_name()
                && windows_gateway_matches(current.gateway(), route.gateway())
                && current.metric() == route.metric()
        });
    if exists {
        Ok(())
    } else {
        manager
            .add(&route)
            .map_err(|error| format!("recreate IP Helper route {}: {error}", r.dest))
    }
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
    let route = windows_native_route(r)?;
    let mut manager = route_manager::RouteManager::new()
        .map_err(|error| format!("open Windows IP Helper route manager: {error}"))?;
    manager
        .add(&route)
        .map_err(|error| format!("CreateIpForwardEntry2 for {}: {error}", r.dest))
}

#[cfg(target_os = "windows")]
fn windows_gateway_matches(current: Option<IpAddr>, expected: Option<IpAddr>) -> bool {
    current == expected
        || (expected.is_none()
            && current.is_some_and(|gateway| match gateway {
                IpAddr::V4(address) => address.is_unspecified(),
                IpAddr::V6(address) => address.is_unspecified(),
            }))
}

#[cfg(target_os = "windows")]
fn platform_del(r: &ManagedRoute) -> Result<(), String> {
    let route = windows_native_route(r)?;
    let mut manager = route_manager::RouteManager::new()
        .map_err(|error| format!("open Windows IP Helper route manager: {error}"))?;
    manager
        .delete(&route)
        .map_err(|error| format!("DeleteIpForwardEntry2 for {}: {error}", r.dest))
}

#[cfg(target_os = "windows")]
fn windows_native_route(r: &ManagedRoute) -> Result<route_manager::Route, String> {
    if r.table.is_some() {
        return Err("Windows routes do not support Linux policy table IDs".into());
    }
    if let Some(gateway) = r.gateway
        && gateway.is_ipv4() != r.dest.addr().is_ipv4()
    {
        return Err(format!(
            "route {} cannot use next hop {gateway} from another address family",
            r.dest
        ));
    }
    let mut route = route_manager::Route::new(r.dest.network(), r.dest.prefix_len())
        .with_if_name(r.interface.clone())
        .with_metric(r.metric);
    if let Some(gateway) = r.gateway {
        route = route.with_gateway(gateway);
    }
    Ok(route)
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

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
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
        "(os error 1168)",
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
        ensured: AtomicUsize,
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
        fn ensure(&self, _r: &ManagedRoute) -> Result<(), String> {
            self.ensured.fetch_add(1, Ordering::Relaxed);
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
    fn windows_native_route_preserves_interface_metric_and_prefix() {
        let route = ManagedRoute {
            dest: "128.0.0.0/1".parse().unwrap(),
            gateway: None,
            interface: "WutherCoreTun".into(),
            metric: 1,
            table: None,
        };
        let native = windows_native_route(&route).unwrap();

        assert_eq!(native.destination(), "128.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(native.prefix(), 1);
        assert_eq!(native.if_name().map(String::as_str), Some("WutherCoreTun"));
        assert_eq!(native.metric(), Some(1));
    }

    #[test]
    fn reconcile_reasserts_ledger_without_duplicating_it() {
        let backend = Arc::new(FakeBackend::default());
        let table = RouteTable::with_backend(backend.clone());
        table
            .add(ManagedRoute {
                dest: "0.0.0.0/1".parse().unwrap(),
                gateway: None,
                interface: "wuther0".into(),
                metric: 1,
                table: None,
            })
            .unwrap();
        table.reconcile_all().unwrap();
        assert_eq!(backend.ensured.load(Ordering::Relaxed), 1);
        assert_eq!(table.len(), 1);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_unspecified_next_hop_matches_on_link_route() {
        assert!(windows_gateway_matches(
            Some("0.0.0.0".parse().unwrap()),
            None
        ));
        assert!(windows_gateway_matches(Some("::".parse().unwrap()), None));
        assert!(!windows_gateway_matches(
            Some("192.0.2.1".parse().unwrap()),
            None
        ));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_native_route_preserves_ipv6_gateway() {
        let route = ManagedRoute {
            dest: "8000::/1".parse().unwrap(),
            gateway: Some("fe80::1".parse().unwrap()),
            interface: "WutherCoreTun".into(),
            metric: 7,
            table: None,
        };
        let native = windows_native_route(&route).unwrap();

        assert_eq!(native.destination(), "8000::".parse::<IpAddr>().unwrap());
        assert_eq!(native.prefix(), 1);
        assert_eq!(native.gateway(), Some("fe80::1".parse().unwrap()));
        assert_eq!(native.metric(), Some(7));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_native_route_rejects_policy_tables_and_mixed_families() {
        let mut route = ManagedRoute {
            dest: "0.0.0.0/1".parse().unwrap(),
            gateway: None,
            interface: "WutherCoreTun".into(),
            metric: 1,
            table: Some(2022),
        };
        assert!(windows_native_route(&route).is_err());

        route.table = None;
        route.gateway = Some("fe80::1".parse().unwrap());
        assert!(windows_native_route(&route).is_err());
    }

    #[test]
    fn linux_route_delete_no_such_process_is_expected_absence() {
        assert!(is_expected_route_delete_absence(
            "ip failed (status=Some(2)): RTNETLINK answers: No such process",
        ));
    }

    #[test]
    fn windows_ip_helper_element_not_found_is_expected_absence() {
        assert!(is_expected_route_delete_absence(
            "DeleteIpForwardEntry2 for 0.0.0.0/1: Element not found. (os error 1168)",
        ));
    }

    #[test]
    fn missing_route_command_is_not_expected_absence() {
        assert!(!is_expected_route_delete_absence(
            "spawn ip: No such file or directory",
        ));
    }
}
