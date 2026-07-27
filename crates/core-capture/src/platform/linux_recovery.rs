//! Crash-safe ownership for Linux/Android host-network capture state.
//!
//! Kernel routes and firewall rules outlive an abruptly killed process.  This
//! module keeps an advisory process lock plus a small, fsync'd recovery record.
//! A successor must remove the previous owner's reserved resources before it
//! is allowed to install new capture state.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
    process::{Command, Output, Stdio},
};

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::AsRawFd;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::engine::{CaptureError, CapturePlan};

const JOURNAL_VERSION: u32 = 1;
const MAX_PRIORITY_DELETES: usize = 64;
const NFT_TABLES: [&str; 2] = ["wuther_auto_redirect", "wuthercore_redirect"];
const IPTABLES_CHAINS: [(&str, &str, &str); 5] = [
    ("mangle", "OUTPUT", "WUTHERCORE_BYPASS"),
    ("mangle", "PREROUTING", "WUTHERCORE_REDIR"),
    ("nat", "PREROUTING", "WUTHERCORE_REDIR"),
    ("mangle", "PREROUTING", "WUTHERCORE_PREROUTING"),
    ("mangle", "OUTPUT", "WUTHERCORE_OUTPUT"),
];
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RecoveryMode {
    #[default]
    /// Version-1 journals did not record the engine kind and owned the union.
    Legacy,
    Tun,
    Tproxy,
    Redirect,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RecoveryRecord {
    version: u32,
    pid: u32,
    interface_name: String,
    table: u32,
    rule_priority: u32,
    auto_route: bool,
    auto_redirect: bool,
    strict_route: bool,
    bypass_tables: Vec<String>,
    #[serde(default)]
    mode: RecoveryMode,
}

impl RecoveryRecord {
    fn from_plan(plan: &CapturePlan, mode: RecoveryMode) -> Self {
        Self {
            version: JOURNAL_VERSION,
            pid: std::process::id(),
            interface_name: plan.interface_name.clone(),
            table: plan.iproute2_table_index,
            rule_priority: plan.iproute2_rule_index,
            auto_route: plan.auto_route,
            auto_redirect: plan.auto_redirect,
            strict_route: plan.strict_route,
            bypass_tables: if plan.auto_route || plan.auto_redirect {
                probe_bypass_tables()
            } else {
                Vec::new()
            },
            mode,
        }
    }

    fn priorities(&self) -> Vec<u32> {
        let mut priorities = Vec::new();
        if self.auto_route || self.auto_redirect {
            priorities.extend([
                self.rule_priority.saturating_sub(3).max(1),
                self.rule_priority.saturating_sub(2).max(1),
                self.rule_priority.saturating_sub(1).max(1),
                self.rule_priority,
            ]);
        }
        if self.strict_route {
            priorities.push(self.rule_priority.saturating_add(1));
        }
        priorities.sort_unstable();
        priorities.dedup();
        priorities
    }
}

#[derive(Debug)]
pub(crate) struct LinuxCaptureGuard {
    file: File,
    path: PathBuf,
    record: RecoveryRecord,
    clean: bool,
}

impl LinuxCaptureGuard {
    pub(crate) fn acquire(plan: &CapturePlan, mode: RecoveryMode) -> Result<Self, CaptureError> {
        let path = journal_path()?;
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|error| recovery_error(format!("open {}: {error}", path.display())))?;
        lock_exclusive(&file, &path)?;

        let previous = read_record(&mut file, &path)?;
        if let Some(previous) = previous {
            warn!(
                target: "capture::recovery",
                previous_pid = previous.pid,
                iface = %previous.interface_name,
                table = previous.table,
                rule_priority = previous.rule_priority,
                "unclean capture shutdown detected; recovering host network before startup"
            );
            recover(&previous)?;
            info!(
                target: "capture::recovery",
                previous_pid = previous.pid,
                "stale capture state recovered"
            );
        }

        let record = RecoveryRecord::from_plan(plan, mode);
        write_record(&mut file, &record, &path)?;
        Ok(Self {
            file,
            path,
            record,
            clean: false,
        })
    }

    pub(crate) fn mark_clean(mut self) -> Result<(), CaptureError> {
        // Ordinary engine cleanup contains legacy best-effort branches. Run
        // the same ownership-bounded sweep used after a crash before declaring
        // the durable journal clean.
        recover(&self.record)?;
        self.file
            .set_len(0)
            .and_then(|_| self.file.sync_all())
            .map_err(|error| recovery_error(format!("clear {}: {error}", self.path.display())))?;
        self.clean = true;
        Ok(())
    }
}

impl Drop for LinuxCaptureGuard {
    fn drop(&mut self) {
        if !self.clean {
            warn!(
                target: "capture::recovery",
                journal = %self.path.display(),
                "capture recovery record retained for the next process"
            );
        }
    }
}

fn journal_path() -> Result<PathBuf, CaptureError> {
    let base = std::env::var_os("WUTHER_CAPTURE_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("wuther-core"));
    std::fs::create_dir_all(&base)
        .map_err(|error| recovery_error(format!("create {}: {error}", base.display())))?;
    Ok(base.join("capture-recovery.lock"))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn lock_exclusive(file: &File, path: &PathBuf) -> Result<(), CaptureError> {
    nix::fcntl::flock(
        file.as_raw_fd(),
        nix::fcntl::FlockArg::LockExclusiveNonblock,
    )
    .map_err(|error| {
        recovery_error(format!(
            "another capture process owns {} ({error})",
            path.display()
        ))
    })
}

#[cfg(all(test, not(any(target_os = "linux", target_os = "android"))))]
fn lock_exclusive(_file: &File, _path: &PathBuf) -> Result<(), CaptureError> {
    Ok(())
}

fn read_record(file: &mut File, path: &PathBuf) -> Result<Option<RecoveryRecord>, CaptureError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| recovery_error(format!("seek {}: {error}", path.display())))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| recovery_error(format!("read {}: {error}", path.display())))?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    let record: RecoveryRecord = serde_json::from_slice(&bytes)
        .map_err(|error| recovery_error(format!("invalid {}: {error}", path.display())))?;
    if record.version != JOURNAL_VERSION {
        return Err(recovery_error(format!(
            "unsupported recovery journal version {} in {}",
            record.version,
            path.display()
        )));
    }
    Ok(Some(record))
}

fn write_record(
    file: &mut File,
    record: &RecoveryRecord,
    path: &PathBuf,
) -> Result<(), CaptureError> {
    let bytes = serde_json::to_vec(record)
        .map_err(|error| recovery_error(format!("encode {}: {error}", path.display())))?;
    file.set_len(0)
        .and_then(|_| file.seek(SeekFrom::Start(0)).map(|_| ()))
        .and_then(|_| file.write_all(&bytes))
        .and_then(|_| file.sync_all())
        .map_err(|error| recovery_error(format!("persist {}: {error}", path.display())))
}

fn recover(record: &RecoveryRecord) -> Result<(), CaptureError> {
    // Disable packet interception first, then remove policy rules and routes.
    for table in NFT_TABLES {
        delete_nft_table(table);
    }
    cleanup_iptables();

    if record.auto_route || record.auto_redirect || record.strict_route {
        ensure_ip_available()?;
        let custom_table = record.table.to_string();
        for family in ["-4", "-6"] {
            for priority in [
                record.rule_priority.saturating_sub(3).max(1),
                record.rule_priority,
            ] {
                delete_all_matching_rules(family, priority, Some(&custom_table), false)?;
            }
            for table in &record.bypass_tables {
                for priority in [
                    record.rule_priority.saturating_sub(2).max(1),
                    record.rule_priority.saturating_sub(1).max(1),
                ] {
                    delete_all_matching_rules(family, priority, Some(table), false)?;
                }
            }
            if record.strict_route {
                delete_all_matching_rules(
                    family,
                    record.rule_priority.saturating_add(1),
                    None,
                    true,
                )?;
            }
        }
        flush_table(record.table);
    }

    if matches!(record.mode, RecoveryMode::Legacy | RecoveryMode::Tproxy) {
        crate::linux_netlink::remove_tproxy_policy(
            true,
            crate::tproxy_rules::TPROXY_FWMARK,
            crate::tproxy_rules::TPROXY_ROUTE_TABLE,
        );
    }
    if matches!(record.mode, RecoveryMode::Legacy | RecoveryMode::Tun) {
        delete_tun(&record.interface_name);
    }
    Ok(())
}

fn ensure_ip_available() -> Result<(), CaptureError> {
    Command::new("ip")
        .arg("-Version")
        .stdin(Stdio::null())
        .output()
        .map(|_| ())
        .map_err(|error| recovery_error(format!("cannot run ip for stale-rule recovery: {error}")))
}

fn delete_all_matching_rules(
    family: &str,
    priority: u32,
    lookup: Option<&str>,
    blackhole: bool,
) -> Result<(), CaptureError> {
    let priority = priority.to_string();
    for _ in 0..MAX_PRIORITY_DELETES {
        let mut args = vec![family, "rule", "del", "priority", priority.as_str()];
        if let Some(table) = lookup {
            args.extend(["lookup", table]);
        }
        if blackhole {
            args.extend(["blackhole", "default"]);
        }
        let output = command_output("ip", &args)?;
        if output.status.success() && output.stdout.is_empty() && output.stderr.is_empty() {
            continue;
        }
        if is_absent(&output) {
            return Ok(());
        }
        return Err(command_error("ip", &output));
    }
    Err(recovery_error(format!(
        "too many stale {family} rules at priority {priority}"
    )))
}

fn probe_bypass_tables() -> Vec<String> {
    let mut tables = Vec::new();
    for (family, target) in [("-4", "1.1.1.1"), ("-6", "2606:4700:4700::1111")] {
        let Some(output) = command_output("ip", &[family, "route", "get", target])
            .ok()
            .filter(|output| output.status.success())
        else {
            continue;
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let words = stdout.split_whitespace().collect::<Vec<_>>();
        let table = words
            .windows(2)
            .find_map(|pair| (pair[0] == "table").then_some(pair[1]))
            .unwrap_or("main");
        if !tables.iter().any(|known| known == table) {
            tables.push(table.to_owned());
        }
    }
    if tables.is_empty() {
        tables.push("main".to_owned());
    }
    tables
}

fn flush_table(table: u32) {
    let table = table.to_string();
    for family in ["-4", "-6"] {
        let _ = command_output("ip", &[family, "route", "flush", "table", &table]);
    }
}

fn delete_exact_ip_rule(family: &str, mark: &str, table: &str) {
    // Some iproute2 environments (notably WSL) report a netlink permission
    // error on stderr while still returning exit status 0. Treat diagnostics
    // as failure and cap retries so crash recovery can never spin forever.
    for _ in 0..MAX_PRIORITY_DELETES {
        let Ok(output) = command_output(
            "ip",
            &["-f", family, "rule", "del", "fwmark", mark, "lookup", table],
        ) else {
            break;
        };
        if !output.status.success() || !output.stdout.is_empty() || !output.stderr.is_empty() {
            break;
        }
    }
}

fn flush_named_table(family: &str, table: &str) {
    let _ = command_output("ip", &["-f", family, "route", "flush", "table", table]);
}

fn delete_nft_table(table: &str) {
    let _ = command_output("nft", &["delete", "table", "inet", table]);
}

fn cleanup_iptables() {
    for program in ["iptables", "ip6tables"] {
        for (table, hook, chain) in IPTABLES_CHAINS {
            while command_output(program, &["-t", table, "-D", hook, "-j", chain])
                .is_ok_and(|output| output.status.success())
            {}
            let _ = command_output(program, &["-t", table, "-F", chain]);
            let _ = command_output(program, &["-t", table, "-X", chain]);
        }
        for chain in [
            "WUTHERCORE_DIVERT",
            "WUTHERCORE_PREROUTING",
            "WUTHERCORE_OUTPUT",
        ] {
            let _ = command_output(program, &["-t", "mangle", "-F", chain]);
            let _ = command_output(program, &["-t", "mangle", "-X", chain]);
        }
    }
}

fn delete_tun(interface: &str) {
    if interface.is_empty() || interface == "lo" {
        return;
    }
    let _ = command_output("ip", &["tuntap", "del", "dev", interface, "mode", "tun"]);
}

fn command_output(program: &str, args: &[&str]) -> Result<Output, CaptureError> {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| recovery_error(format!("spawn {program}: {error}")))
}

fn is_absent(output: &Output) -> bool {
    let text = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    )
    .to_ascii_lowercase();
    [
        "no such process",
        "no such file",
        "cannot find",
        "not found",
        "does not exist",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn command_error(program: &str, output: &Output) -> CaptureError {
    let detail = if output.stderr.is_empty() {
        String::from_utf8_lossy(&output.stdout)
    } else {
        String::from_utf8_lossy(&output.stderr)
    };
    recovery_error(format!(
        "{program} failed (status={:?}): {}",
        output.status.code(),
        detail.trim()
    ))
}

fn recovery_error(message: impl Into<String>) -> CaptureError {
    CaptureError::Route(format!("capture crash recovery: {}", message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_priorities_cover_all_reserved_auto_route_layers() {
        let record = RecoveryRecord {
            version: JOURNAL_VERSION,
            pid: 1,
            interface_name: "wuther0".into(),
            table: 2022,
            rule_priority: 9000,
            auto_route: true,
            auto_redirect: false,
            strict_route: true,
            bypass_tables: vec!["main".into()],
            mode: RecoveryMode::Tun,
        };
        assert_eq!(record.priorities(), [8997, 8998, 8999, 9000, 9001]);
    }

    #[test]
    fn journal_round_trip_is_stable() {
        let record = RecoveryRecord {
            version: JOURNAL_VERSION,
            pid: 42,
            interface_name: "wuther0".into(),
            table: 2022,
            rule_priority: 9000,
            auto_route: true,
            auto_redirect: true,
            strict_route: false,
            bypass_tables: vec!["main".into(), "97".into()],
            mode: RecoveryMode::Tproxy,
        };
        let bytes = serde_json::to_vec(&record).unwrap();
        assert_eq!(
            serde_json::from_slice::<RecoveryRecord>(&bytes).unwrap(),
            record
        );
    }

    #[test]
    fn version_one_journal_without_mode_uses_legacy_union_cleanup() {
        let json = r#"{
            "version":1,"pid":42,"interface_name":"wuther0",
            "table":2022,"rule_priority":9000,"auto_route":false,
            "auto_redirect":false,"strict_route":false,"bypass_tables":[]
        }"#;
        let record: RecoveryRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.mode, RecoveryMode::Legacy);
    }
}
