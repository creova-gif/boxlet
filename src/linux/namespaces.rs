//! Linux namespace unsharing, UTS hostname configuration, and loopback (`lo`) activation.

use std::fs;

use nix::sched::{unshare, CloneFlags};
use nix::unistd::sethostname;
use oci_spec::runtime::{LinuxNamespaceType, Spec};

use crate::error::{BoxletError, Result};
use crate::policy::NetworkMode;

/// Computes `CloneFlags` from an OCI spec verbatim (`create` mode) or with `NetworkMode` override (`run` mode).
pub(crate) fn build_unshare_flags(
    spec: &Spec,
    network_override: Option<NetworkMode>,
) -> CloneFlags {
    let mut flags = CloneFlags::empty();

    if let Some(namespaces) = spec.linux().as_ref().and_then(|l| l.namespaces().as_ref()) {
        for ns in namespaces {
            match ns.typ() {
                LinuxNamespaceType::Pid => flags |= CloneFlags::CLONE_NEWPID,
                LinuxNamespaceType::Mount => flags |= CloneFlags::CLONE_NEWNS,
                LinuxNamespaceType::Uts => flags |= CloneFlags::CLONE_NEWUTS,
                LinuxNamespaceType::Ipc => flags |= CloneFlags::CLONE_NEWIPC,
                LinuxNamespaceType::Network => flags |= CloneFlags::CLONE_NEWNET,
                LinuxNamespaceType::Cgroup => flags |= CloneFlags::CLONE_NEWCGROUP,
                LinuxNamespaceType::User => flags |= CloneFlags::CLONE_NEWUSER,
                _ => {}
            }
        }
    } else {
        flags |= CloneFlags::CLONE_NEWPID
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWIPC;
    }

    if let Some(net_mode) = network_override {
        match net_mode {
            NetworkMode::None => flags |= CloneFlags::CLONE_NEWNET,
            NetworkMode::Host => flags.remove(CloneFlags::CLONE_NEWNET),
        }
    }

    flags
}

/// Calls `unshare(2)` with the requested Linux namespace flags.
pub(crate) fn unshare_namespaces(flags: CloneFlags) -> Result<()> {
    if flags.is_empty() {
        return Ok(());
    }
    unshare(flags).map_err(|err| BoxletError::Runtime {
        subsystem: "namespaces",
        message: format!("unshare({flags:?}) failed: {err}"),
    })
}

/// Configures `/proc/self/setgroups`, `/proc/self/uid_map`, and `/proc/self/gid_map`
/// after `unshare(CLONE_NEWUSER)` so the unprivileged host caller maps cleanly to
/// container UID/GID `0:0`.
pub(crate) fn apply_user_namespace_mappings(
    spec: &Spec,
    flags: CloneFlags,
    host_euid: u32,
    host_egid: u32,
) -> Result<()> {
    if !flags.contains(CloneFlags::CLONE_NEWUSER) {
        return Ok(());
    }

    if let Err(err) = fs::write("/proc/self/setgroups", b"deny") {
        if err.kind() != std::io::ErrorKind::NotFound {
            return Err(BoxletError::Runtime {
                subsystem: "namespaces",
                message: format!("failed to write 'deny' to /proc/self/setgroups: {err}"),
            });
        }
    }

    let uid_map_body = match spec
        .linux()
        .as_ref()
        .and_then(|l| l.uid_mappings().as_ref())
    {
        Some(mappings) if !mappings.is_empty() => {
            let mut buf = String::new();
            for m in mappings {
                buf.push_str(&format!(
                    "{} {} {}\n",
                    m.container_id(),
                    m.host_id(),
                    m.size()
                ));
            }
            buf
        }
        _ => format!("0 {host_euid} 1\n"),
    };
    fs::write("/proc/self/uid_map", uid_map_body.as_bytes()).map_err(|err| {
        BoxletError::Runtime {
            subsystem: "namespaces",
            message: format!("failed to write /proc/self/uid_map: {err}"),
        }
    })?;

    let gid_map_body = match spec
        .linux()
        .as_ref()
        .and_then(|l| l.gid_mappings().as_ref())
    {
        Some(mappings) if !mappings.is_empty() => {
            let mut buf = String::new();
            for m in mappings {
                buf.push_str(&format!(
                    "{} {} {}\n",
                    m.container_id(),
                    m.host_id(),
                    m.size()
                ));
            }
            buf
        }
        _ => format!("0 {host_egid} 1\n"),
    };
    fs::write("/proc/self/gid_map", gid_map_body.as_bytes()).map_err(|err| {
        BoxletError::Runtime {
            subsystem: "namespaces",
            message: format!("failed to write /proc/self/gid_map: {err}"),
        }
    })?;

    Ok(())
}

/// Sets the container UTS hostname when configured in the OCI spec.
pub(crate) fn apply_hostname(spec: &Spec) -> Result<()> {
    if let Some(hostname) = spec.hostname() {
        if !hostname.is_empty() {
            sethostname(hostname).map_err(|err| BoxletError::Runtime {
                subsystem: "namespaces",
                message: format!("sethostname('{hostname}') failed: {err}"),
            })?;
        }
    }
    Ok(())
}

/// Brings up the loopback interface (`lo`) inside a newly created network namespace.
pub(crate) fn bring_up_loopback() -> Result<()> {
    // SAFETY: Standard Linux SIOCGIFFLAGS/SIOCSIFFLAGS ioctl sequence on an AF_INET DGRAM socket
    // with a zero-initialized `libc::ifreq` whose `ifr_name` is NUL-terminated `"lo\0"`.
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if sock < 0 {
            let err = std::io::Error::last_os_error();
            return Err(BoxletError::Runtime {
                subsystem: "namespaces",
                message: format!("socket(AF_INET) for loopback setup failed: {err}"),
            });
        }

        let mut ifr: libc::ifreq = std::mem::zeroed();
        ifr.ifr_name[0] = b'l' as libc::c_char;
        ifr.ifr_name[1] = b'o' as libc::c_char;

        let get_rc = libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifr);
        if get_rc != 0 {
            let err = std::io::Error::last_os_error();
            libc::close(sock);
            return Err(BoxletError::Runtime {
                subsystem: "namespaces",
                message: format!("ioctl(SIOCGIFFLAGS, lo) failed: {err}"),
            });
        }

        ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        let set_rc = libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &mut ifr);
        libc::close(sock);
        if set_rc != 0 {
            let err = std::io::Error::last_os_error();
            return Err(BoxletError::Runtime {
                subsystem: "namespaces",
                message: format!("ioctl(SIOCSIFFLAGS, lo) failed: {err}"),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_unshare_flags_honors_network_mode_override() {
        let spec = Spec::default();
        let none_flags = build_unshare_flags(&spec, Some(NetworkMode::None));
        assert!(none_flags.contains(CloneFlags::CLONE_NEWNET));
        assert!(none_flags.contains(CloneFlags::CLONE_NEWPID));

        let host_flags = build_unshare_flags(&spec, Some(NetworkMode::Host));
        assert!(!host_flags.contains(CloneFlags::CLONE_NEWNET));
        assert!(host_flags.contains(CloneFlags::CLONE_NEWPID));
    }

    #[test]
    fn build_unshare_flags_includes_user_namespace_when_configured() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|source| BoxletError::StateStore {
            path: std::path::PathBuf::from("tempdir"),
            source,
        })?;
        let bundle_dir = dir.path().join("bundle");
        let spec = crate::oci::BundleBuilder::new()
            .with_uid_gid_mapping(1000, 1000)
            .build(&bundle_dir)?;

        let flags = build_unshare_flags(&spec, None);
        assert!(flags.contains(CloneFlags::CLONE_NEWUSER));
        assert!(flags.contains(CloneFlags::CLONE_NEWPID));
        Ok(())
    }
}
