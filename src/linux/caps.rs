//! Linux capability dropping and `PR_SET_NO_NEW_PRIVS` enforcement.

use std::str::FromStr;

use caps::{CapSet, Capability, CapsHashSet};
use oci_spec::runtime::LinuxCapabilities;

use crate::error::{BoxletError, Result};

/// Enforces `PR_SET_NO_NEW_PRIVS` on the calling thread so `execve` cannot grant new privileges.
pub(crate) fn set_no_new_privs() -> Result<()> {
    // SAFETY: `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` is a well-defined Linux syscall with no pointers.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(BoxletError::Runtime {
            subsystem: "caps",
            message: format!("prctl(PR_SET_NO_NEW_PRIVS) failed: {err}"),
        });
    }
    Ok(())
}

/// Drops capabilities to the explicit `allowlist` (when provided) or the OCI spec capability set.
pub(crate) fn apply_capabilities(
    allowlist: Option<&[String]>,
    oci_caps: Option<&LinuxCapabilities>,
) -> Result<()> {
    let target_set = if let Some(names) = allowlist {
        parse_cap_names(names)?
    } else if let Some(spec_caps) = oci_caps {
        let names: Vec<String> = spec_caps
            .effective()
            .as_ref()
            .map(|set| set.iter().map(|c| format!("{c:?}")).collect())
            .unwrap_or_default();
        parse_cap_names(&names)?
    } else {
        CapsHashSet::new()
    };

    // Clear ambient set first, then drop bounding caps not in target_set.
    let _ = caps::clear(None, CapSet::Ambient);
    for cap in caps::all() {
        if !target_set.contains(&cap) && caps::has_cap(None, CapSet::Bounding, cap).unwrap_or(false)
        {
            caps::drop(None, CapSet::Bounding, cap).map_err(|err| BoxletError::Runtime {
                subsystem: "caps",
                message: format!("failed to drop bounding cap {cap}: {err}"),
            })?;
        }
    }

    // Linux capset(2) requires Effective <= Permitted at all times: narrow Effective
    // and Inheritable BEFORE narrowing Permitted.
    caps::set(None, CapSet::Effective, &target_set).map_err(|err| BoxletError::Runtime {
        subsystem: "caps",
        message: format!("failed to set effective caps: {err}"),
    })?;
    caps::set(None, CapSet::Inheritable, &target_set).map_err(|err| BoxletError::Runtime {
        subsystem: "caps",
        message: format!("failed to set inheritable caps: {err}"),
    })?;
    caps::set(None, CapSet::Permitted, &target_set).map_err(|err| BoxletError::Runtime {
        subsystem: "caps",
        message: format!("failed to set permitted caps: {err}"),
    })?;
    Ok(())
}

/// Parses Linux capability names (accepting both `CAP_CHOWN` and `CHOWN`).
pub(crate) fn parse_cap_names(names: &[String]) -> Result<CapsHashSet> {
    let mut set = CapsHashSet::new();
    for raw in names {
        let normalized = if raw.starts_with("CAP_") {
            raw.to_ascii_uppercase()
        } else {
            format!("CAP_{}", raw.to_ascii_uppercase())
        };
        let cap = Capability::from_str(&normalized).map_err(|err| BoxletError::InvalidPolicy {
            reason: format!("unknown Linux capability '{raw}': {err}"),
        })?;
        set.insert(cap);
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cap_names_accepts_valid_and_rejects_unknown() -> Result<()> {
        let caps = parse_cap_names(&["CAP_CHOWN".to_string(), "net_bind_service".to_string()])?;
        assert!(caps.contains(&Capability::CAP_CHOWN));
        assert!(caps.contains(&Capability::CAP_NET_BIND_SERVICE));

        let err = parse_cap_names(&["CAP_NOT_A_CAP".to_string()]).unwrap_err();
        assert!(matches!(err, BoxletError::InvalidPolicy { .. }));
        Ok(())
    }
}
