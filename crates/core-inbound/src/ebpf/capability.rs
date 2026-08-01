//! Linux capability preparation for the Aya eBPF data plane.
//!
//! `uid == 0` is deliberately not treated as sufficient. Android root
//! managers, containers, and systemd services commonly restrict the effective
//! or bounding sets even when the process uid is zero.

use std::{collections::HashSet, fs};

use caps::{CapSet, Capability, CapsHashSet};
use core_config::model::EbpfCapabilityOptions;
use nix::{
    sys::resource::{RLIM_INFINITY, Resource, getrlimit, setrlimit},
    unistd::geteuid,
};
use tracing::{debug, info, warn};

use super::EbpfInboundError;

const CAP_BPF_INDEX: u8 = 39;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfBpfAuthority {
    CapBpf,
    CapSysAdmin,
}

impl EbpfBpfAuthority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CapBpf => "CAP_BPF",
            Self::CapSysAdmin => "CAP_SYS_ADMIN",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfMemlockStatus {
    pub soft: u64,
    pub hard: u64,
    pub unlimited: bool,
    pub adjustment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfCapabilityReport {
    pub uid: u32,
    pub cap_last_cap: u8,
    pub authority: EbpfBpfAuthority,
    pub effective: Vec<String>,
    pub permitted: Vec<String>,
    pub bounding: Vec<String>,
    pub promoted: Vec<String>,
    pub perfmon_effective: bool,
    pub memlock: EbpfMemlockStatus,
}

#[derive(Debug)]
struct CapabilitySnapshot {
    effective: CapsHashSet,
    permitted: CapsHashSet,
    bounding: CapsHashSet,
}

pub(super) fn prepare(
    policy: &EbpfCapabilityOptions,
) -> Result<EbpfCapabilityReport, EbpfInboundError> {
    let cap_last_cap = read_cap_last_cap();
    let mut snapshot = read_snapshot(true)?;
    let mut promoted = Vec::new();

    activate_required(
        Capability::CAP_NET_ADMIN,
        policy.auto_raise,
        &mut snapshot,
        &mut promoted,
    )?;
    let authority = select_bpf_authority(cap_last_cap, policy, &mut snapshot, &mut promoted)?;
    let memlock = prepare_memlock();
    let report = build_report(cap_last_cap, authority, snapshot, promoted, memlock);

    info!(
        target: "inbound::ebpf",
        uid = report.uid,
        cap_last_cap = report.cap_last_cap,
        bpf_authority = report.authority.as_str(),
        effective = ?report.effective,
        promoted = ?report.promoted,
        memlock_soft = report.memlock.soft,
        memlock_hard = report.memlock.hard,
        memlock_unlimited = report.memlock.unlimited,
        "eBPF capability preflight passed"
    );
    if !report.perfmon_effective {
        debug!(
            target: "inbound::ebpf",
            "CAP_PERFMON is absent and is not required by the configured network BPF program types"
        );
    }
    Ok(report)
}

/// Re-run the capability check on the current thread.
///
/// Linux credentials are per-thread. Tokio may run interface reconciliation
/// and cleanup on a worker other than the startup thread, so every privileged
/// maintenance entry point calls this function.
pub(super) fn ensure_current_thread(
    policy: &EbpfCapabilityOptions,
) -> Result<EbpfBpfAuthority, EbpfInboundError> {
    let cap_last_cap = read_cap_last_cap();
    let mut snapshot = read_snapshot(false)?;
    let mut promoted = Vec::new();
    activate_required(
        Capability::CAP_NET_ADMIN,
        policy.auto_raise,
        &mut snapshot,
        &mut promoted,
    )?;
    let authority = select_bpf_authority(cap_last_cap, policy, &mut snapshot, &mut promoted)?;
    if !promoted.is_empty() {
        debug!(
            target: "inbound::ebpf",
            ?promoted,
            "activated permitted eBPF capabilities on current runtime thread"
        );
    }
    Ok(authority)
}

/// Some Android vendor kernels expose CAP_BPF in `cap_last_cap` but retain the
/// older CAP_SYS_ADMIN check in their BPF syscall backport. Retry only after a
/// permission failure and only when the configured policy permits it.
pub(super) fn prepare_sys_admin_fallback(
    policy: &EbpfCapabilityOptions,
) -> Result<Option<EbpfCapabilityReport>, EbpfInboundError> {
    if !policy.allow_sys_admin_fallback {
        return Ok(None);
    }
    let cap_last_cap = read_cap_last_cap();
    let mut snapshot = read_snapshot(true)?;
    let mut promoted = Vec::new();
    activate_required(
        Capability::CAP_NET_ADMIN,
        policy.auto_raise,
        &mut snapshot,
        &mut promoted,
    )?;
    if !activate(
        Capability::CAP_SYS_ADMIN,
        policy.auto_raise,
        &mut snapshot,
        &mut promoted,
    )? {
        return Ok(None);
    }
    let report = build_report(
        cap_last_cap,
        EbpfBpfAuthority::CapSysAdmin,
        snapshot,
        promoted,
        prepare_memlock(),
    );
    Ok(Some(report))
}

fn build_report(
    cap_last_cap: u8,
    authority: EbpfBpfAuthority,
    snapshot: CapabilitySnapshot,
    promoted: Vec<String>,
    memlock: EbpfMemlockStatus,
) -> EbpfCapabilityReport {
    EbpfCapabilityReport {
        uid: geteuid().as_raw(),
        cap_last_cap,
        authority,
        effective: capability_names(&snapshot.effective),
        permitted: capability_names(&snapshot.permitted),
        bounding: capability_names(&snapshot.bounding),
        promoted,
        perfmon_effective: snapshot.effective.contains(&Capability::CAP_PERFMON),
        memlock,
    }
}

fn read_snapshot(include_bounding: bool) -> Result<CapabilitySnapshot, EbpfInboundError> {
    Ok(CapabilitySnapshot {
        effective: read_set(CapSet::Effective)?,
        permitted: read_set(CapSet::Permitted)?,
        bounding: if include_bounding {
            read_set(CapSet::Bounding)?
        } else {
            CapsHashSet::new()
        },
    })
}

fn read_set(set: CapSet) -> Result<CapsHashSet, EbpfInboundError> {
    caps::read(None, set).map_err(|error| {
        EbpfInboundError::Capability(format!("cannot read Linux {set:?} capability set: {error}"))
    })
}

fn activate_required(
    capability: Capability,
    auto_raise: bool,
    snapshot: &mut CapabilitySnapshot,
    promoted: &mut Vec<String>,
) -> Result<(), EbpfInboundError> {
    if activate(capability, auto_raise, snapshot, promoted)? {
        return Ok(());
    }
    Err(missing_capabilities(
        snapshot,
        &[capability_name(capability)],
        read_cap_last_cap(),
    ))
}

fn activate(
    capability: Capability,
    auto_raise: bool,
    snapshot: &mut CapabilitySnapshot,
    promoted: &mut Vec<String>,
) -> Result<bool, EbpfInboundError> {
    if snapshot.effective.contains(&capability) {
        return Ok(true);
    }
    if !auto_raise || !snapshot.permitted.contains(&capability) {
        return Ok(false);
    }
    caps::raise(None, CapSet::Effective, capability).map_err(|error| {
        EbpfInboundError::Capability(format!(
            "promote {} from permitted to effective set: {error}",
            capability_name(capability)
        ))
    })?;
    if !caps::has_cap(None, CapSet::Effective, capability).map_err(|error| {
        EbpfInboundError::Capability(format!(
            "verify effective {} after promotion: {error}",
            capability_name(capability)
        ))
    })? {
        return Err(EbpfInboundError::Capability(format!(
            "kernel accepted capability promotion but {} is still not effective",
            capability_name(capability)
        )));
    }
    snapshot.effective.insert(capability);
    promoted.push(capability_name(capability));
    Ok(true)
}

fn select_bpf_authority(
    cap_last_cap: u8,
    policy: &EbpfCapabilityOptions,
    snapshot: &mut CapabilitySnapshot,
    promoted: &mut Vec<String>,
) -> Result<EbpfBpfAuthority, EbpfInboundError> {
    let dedicated_supported = cap_last_cap >= CAP_BPF_INDEX;
    if dedicated_supported && activate(Capability::CAP_BPF, policy.auto_raise, snapshot, promoted)?
    {
        return Ok(EbpfBpfAuthority::CapBpf);
    }
    if policy.allow_sys_admin_fallback
        && activate(
            Capability::CAP_SYS_ADMIN,
            policy.auto_raise,
            snapshot,
            promoted,
        )?
    {
        return Ok(EbpfBpfAuthority::CapSysAdmin);
    }

    let alternatives = if dedicated_supported {
        if policy.allow_sys_admin_fallback {
            vec!["CAP_BPF or CAP_SYS_ADMIN".to_owned()]
        } else {
            vec!["CAP_BPF".to_owned()]
        }
    } else {
        vec!["CAP_SYS_ADMIN (kernel predates CAP_BPF)".to_owned()]
    };
    Err(missing_capabilities(snapshot, &alternatives, cap_last_cap))
}

fn missing_capabilities(
    snapshot: &CapabilitySnapshot,
    missing: &[String],
    cap_last_cap: u8,
) -> EbpfInboundError {
    let bounding_set = if snapshot.bounding.is_empty() {
        read_set(CapSet::Bounding).unwrap_or_default()
    } else {
        snapshot.bounding.clone()
    };
    let effective = capability_names(&snapshot.effective).join(",");
    let permitted = capability_names(&snapshot.permitted).join(",");
    let bounding = capability_names(&bounding_set).join(",");
    EbpfInboundError::Capability(format!(
        "missing effective {}; uid=0 alone is insufficient when Linux capabilities are restricted; \
         required profile is CAP_NET_ADMIN plus CAP_BPF on modern kernels, or CAP_NET_ADMIN plus \
         CAP_SYS_ADMIN for legacy/vendor compatibility; cap_last_cap={cap_last_cap}; \
         effective=[{effective}]; permitted=[{permitted}]; bounding=[{bounding}]. \
         Grant file/service capabilities before exec, for example \
         `setcap cap_net_admin,cap_bpf+ep <binary>` on a CAP_BPF kernel. \
         If the capability is absent from the bounding set or Android SELinux denies bpf, \
         the running process cannot restore it itself",
        missing.join(" + ")
    ))
}

fn capability_names(set: &HashSet<Capability>) -> Vec<String> {
    let mut names = set.iter().copied().map(capability_name).collect::<Vec<_>>();
    names.sort_unstable();
    names
}

fn capability_name(capability: Capability) -> String {
    format!("{capability:?}")
}

fn read_cap_last_cap() -> u8 {
    fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|value| value.trim().parse::<u8>().ok())
        .unwrap_or(CAP_BPF_INDEX)
}

fn prepare_memlock() -> EbpfMemlockStatus {
    let before = getrlimit(Resource::RLIMIT_MEMLOCK).ok();
    let mut adjustment = None;
    if let Err(error) = setrlimit(Resource::RLIMIT_MEMLOCK, RLIM_INFINITY, RLIM_INFINITY) {
        let fallback = getrlimit(Resource::RLIMIT_MEMLOCK).ok();
        if let Some((soft, hard)) = fallback
            && soft < hard
        {
            match setrlimit(Resource::RLIMIT_MEMLOCK, hard, hard) {
                Ok(()) => {
                    adjustment = Some(format!(
                        "RLIMIT_MEMLOCK infinity denied ({error}); raised soft limit to hard limit"
                    ));
                }
                Err(fallback_error) => {
                    adjustment = Some(format!(
                        "RLIMIT_MEMLOCK unchanged; infinity failed: {error}; soft-to-hard failed: {fallback_error}"
                    ));
                }
            }
        } else {
            adjustment = Some(format!("RLIMIT_MEMLOCK infinity denied: {error}"));
        }
    } else if before.is_some_and(|limits| limits != (RLIM_INFINITY, RLIM_INFINITY)) {
        adjustment = Some("raised RLIMIT_MEMLOCK to infinity".to_owned());
    }

    let (soft, hard) = getrlimit(Resource::RLIMIT_MEMLOCK).unwrap_or((0, 0));
    let status = EbpfMemlockStatus {
        soft: u64::from(soft),
        hard: u64::from(hard),
        unlimited: soft == RLIM_INFINITY,
        adjustment,
    };
    if !status.unlimited {
        warn!(
            target: "inbound::ebpf",
            soft = status.soft,
            hard = status.hard,
            adjustment = ?status.adjustment,
            "RLIMIT_MEMLOCK is finite; legacy kernels may require CAP_SYS_RESOURCE or a larger service limit"
        );
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(effective: &[Capability], permitted: &[Capability]) -> CapabilitySnapshot {
        CapabilitySnapshot {
            effective: effective.iter().copied().collect(),
            permitted: permitted.iter().copied().collect(),
            bounding: permitted.iter().copied().collect(),
        }
    }

    #[test]
    fn modern_kernel_prefers_cap_bpf() {
        let mut state = snapshot(
            &[Capability::CAP_NET_ADMIN, Capability::CAP_BPF],
            &[Capability::CAP_NET_ADMIN, Capability::CAP_BPF],
        );
        let authority = select_bpf_authority(
            40,
            &EbpfCapabilityOptions::default(),
            &mut state,
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(authority, EbpfBpfAuthority::CapBpf);
    }

    #[test]
    fn legacy_kernel_uses_sys_admin() {
        let mut state = snapshot(
            &[Capability::CAP_NET_ADMIN, Capability::CAP_SYS_ADMIN],
            &[Capability::CAP_NET_ADMIN, Capability::CAP_SYS_ADMIN],
        );
        let authority = select_bpf_authority(
            38,
            &EbpfCapabilityOptions::default(),
            &mut state,
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(authority, EbpfBpfAuthority::CapSysAdmin);
    }

    #[test]
    fn strict_policy_rejects_sys_admin_fallback() {
        let mut state = snapshot(
            &[Capability::CAP_NET_ADMIN, Capability::CAP_SYS_ADMIN],
            &[Capability::CAP_NET_ADMIN, Capability::CAP_SYS_ADMIN],
        );
        let policy = EbpfCapabilityOptions {
            allow_sys_admin_fallback: false,
            ..EbpfCapabilityOptions::default()
        };
        let error = select_bpf_authority(40, &policy, &mut state, &mut Vec::new()).unwrap_err();
        assert!(error.to_string().contains("CAP_BPF"));
    }

    #[test]
    fn error_explains_root_and_capability_sets() {
        let state = snapshot(&[Capability::CAP_NET_ADMIN], &[Capability::CAP_NET_ADMIN]);
        let error = missing_capabilities(&state, &["CAP_BPF".to_owned()], 40).to_string();
        assert!(error.contains("uid=0 alone is insufficient"));
        assert!(error.contains("effective=[CAP_NET_ADMIN]"));
        assert!(error.contains("bounding=[CAP_NET_ADMIN]"));
    }
}
