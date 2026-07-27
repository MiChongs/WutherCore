//! Linux capability checks shared by Linux and Android transparent capture.
//!
//! Checking the effective capability set is more accurate than checking UID 0:
//! a service may receive `CAP_NET_ADMIN` through systemd, a container runtime,
//! or file capabilities, while a namespaced root process may not have it.

use caps::{CapSet, Capability};

pub(crate) fn has_effective(capability: Capability) -> Result<bool, String> {
    caps::has_cap(None, CapSet::Effective, capability)
        .map_err(|error| format!("read effective Linux capabilities: {error}"))
}

pub(crate) fn require_net_admin(operation: &str) -> Result<(), String> {
    match has_effective(Capability::CAP_NET_ADMIN)? {
        true => Ok(()),
        false => Err(missing_net_admin_message(operation)),
    }
}

fn missing_net_admin_message(operation: &str) -> String {
    format!(
        "{operation} requires effective CAP_NET_ADMIN; grant it with systemd AmbientCapabilities/CapabilityBoundingSet, a container NET_ADMIN capability, or run an appropriately privileged daemon"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_capability_message_names_the_operation_and_capability() {
        let operation = "transparent capture";
        let error = missing_net_admin_message(operation);
        assert!(error.contains(operation));
        assert!(error.contains("CAP_NET_ADMIN"));
    }
}
