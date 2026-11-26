//! Host environment and kernel readiness diagnostics (`boxlet doctor`).

#[cfg(target_os = "linux")]
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Outcome status for an individual host readiness check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DoctorStatus {
    /// Check passed all requirements.
    Pass,
    /// Non-fatal warning or optional capability unavailable.
    Warn,
    /// Fatal requirement missing for Linux OCI container execution.
    Fail,
}

/// Result of a single host diagnostic probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorCheck {
    /// Machine-readable check identifier (e.g. `"host_os"`, `"kernel_version"`, `"root_privileges"`, `"cgroup_v2"`, `"seccomp_arch"`).
    pub name: String,
    /// Check outcome (`Pass`, `Warn`, `Fail`).
    pub status: DoctorStatus,
    /// Observed value or diagnostic message.
    pub detail: String,
    /// Actionable remediation advice when `status != DoctorStatus::Pass`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

/// Aggregated host diagnostic report returned by [`run_doctor`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    /// True when zero checks reported [`DoctorStatus::Fail`].
    pub overall_ready: bool,
    /// Host operating system (`std::env::consts::OS`).
    pub host_os: String,
    /// Host CPU architecture (`std::env::consts::ARCH`).
    pub host_arch: String,
    /// Individual diagnostic check results in deterministic order.
    pub checks: Vec<DoctorCheck>,
}

/// Parses a Linux kernel release string (such as `"5.15.0-101-generic"` or `"6.8.0-49-generic"`)
/// into its `(major, minor)` version tuple.
pub fn parse_kernel_major_minor(release: &str) -> Option<(u32, u32)> {
    let trimmed = release.trim();
    let mut parts = trimmed.split('.');
    let major_str = parts.next()?;
    let minor_raw = parts.next()?;
    let major = major_str.parse::<u32>().ok()?;
    let minor_digits: String = minor_raw
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if minor_digits.is_empty() {
        return None;
    }
    let minor = minor_digits.parse::<u32>().ok()?;
    Some((major, minor))
}

/// Runs deterministic host readiness checks for Boxlet's Linux OCI runtime and workspace tooling.
pub fn run_doctor(state_root: &Path, cgroup_parent: &Path) -> DoctorReport {
    let host_os = std::env::consts::OS.to_string();
    let host_arch = std::env::consts::ARCH.to_string();

    let checks = vec![
        check_host_os(state_root),
        check_kernel_version(),
        check_root_privileges(),
        check_cgroup_v2(cgroup_parent),
        check_seccomp_arch(),
    ];

    let overall_ready = checks.iter().all(|c| c.status != DoctorStatus::Fail);

    DoctorReport {
        overall_ready,
        host_os,
        host_arch,
        checks,
    }
}

fn check_host_os(state_root: &Path) -> DoctorCheck {
    let os = std::env::consts::OS;
    if cfg!(target_os = "linux") {
        DoctorCheck {
            name: "host_os".to_string(),
            status: DoctorStatus::Pass,
            detail: format!("os={os} state_root={}", state_root.display()),
            remediation: None,
        }
    } else {
        DoctorCheck {
            name: "host_os".to_string(),
            status: DoctorStatus::Fail,
            detail: format!(
                "os={os} (Linux required for OCI execution; state_root={})",
                state_root.display()
            ),
            remediation: Some("Run Linux OCI containers on a Linux 5.15+ host or VM".to_string()),
        }
    }
}

#[cfg(target_os = "linux")]
fn check_kernel_version() -> DoctorCheck {
    match fs::read_to_string("/proc/sys/kernel/osrelease") {
        Ok(raw) => {
            let release = raw.trim();
            match parse_kernel_major_minor(release) {
                Some((major, minor)) if major > 5 || (major == 5 && minor >= 15) => DoctorCheck {
                    name: "kernel_version".to_string(),
                    status: DoctorStatus::Pass,
                    detail: format!("kernel release {release} ({major}.{minor} >= 5.15)"),
                    remediation: None,
                },
                Some((major, minor)) => DoctorCheck {
                    name: "kernel_version".to_string(),
                    status: DoctorStatus::Fail,
                    detail: format!("kernel release {release} ({major}.{minor} < 5.15)"),
                    remediation: Some("Upgrade host Linux kernel to 5.15 or newer".to_string()),
                },
                None => DoctorCheck {
                    name: "kernel_version".to_string(),
                    status: DoctorStatus::Warn,
                    detail: format!("unrecognized kernel release format '{release}'"),
                    remediation: Some(
                        "Verify that the host runs Linux kernel 5.15 or newer".to_string(),
                    ),
                },
            }
        }
        Err(err) => DoctorCheck {
            name: "kernel_version".to_string(),
            status: DoctorStatus::Warn,
            detail: format!("failed to read /proc/sys/kernel/osrelease: {err}"),
            remediation: Some("Ensure /proc is mounted and readable".to_string()),
        },
    }
}

#[cfg(not(target_os = "linux"))]
fn check_kernel_version() -> DoctorCheck {
    DoctorCheck {
        name: "kernel_version".to_string(),
        status: DoctorStatus::Warn,
        detail: "Linux kernel version probe skipped on non-Linux host".to_string(),
        remediation: Some(
            "Run on a Linux 5.15+ host to probe /proc/sys/kernel/osrelease".to_string(),
        ),
    }
}

#[cfg(target_os = "linux")]
fn check_root_privileges() -> DoctorCheck {
    // SAFETY: `geteuid` is an async-signal-safe POSIX syscall with no preconditions.
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        DoctorCheck {
            name: "root_privileges".to_string(),
            status: DoctorStatus::Pass,
            detail: "effective UID is 0 (root)".to_string(),
            remediation: None,
        }
    } else {
        DoctorCheck {
            name: "root_privileges".to_string(),
            status: DoctorStatus::Fail,
            detail: format!(
                "effective UID is {euid} (root required for V1 namespaces and cgroups)"
            ),
            remediation: Some("Run boxlet with sudo/root privileges on Linux V1".to_string()),
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn check_root_privileges() -> DoctorCheck {
    DoctorCheck {
        name: "root_privileges".to_string(),
        status: DoctorStatus::Warn,
        detail: "Linux root privilege check skipped on non-Linux host".to_string(),
        remediation: Some("Run boxlet with sudo/root privileges on Linux V1".to_string()),
    }
}

#[cfg(target_os = "linux")]
fn check_cgroup_v2(cgroup_parent: &Path) -> DoctorCheck {
    let parent_controllers = cgroup_parent.join("cgroup.controllers");
    let probe_path = if parent_controllers.exists() {
        parent_controllers.as_path()
    } else {
        Path::new("/sys/fs/cgroup/cgroup.controllers")
    };
    match fs::read_to_string(probe_path) {
        Ok(raw) => {
            let available: Vec<&str> = raw.split_whitespace().collect();
            let required = ["memory", "cpu", "pids"];
            let missing: Vec<&str> = required
                .into_iter()
                .filter(|req| !available.contains(req))
                .collect();
            if missing.is_empty() {
                DoctorCheck {
                    name: "cgroup_v2".to_string(),
                    status: DoctorStatus::Pass,
                    detail: format!(
                        "cgroup v2 unified hierarchy active (controllers: {}; parent={})",
                        available.join(","),
                        cgroup_parent.display()
                    ),
                    remediation: None,
                }
            } else {
                DoctorCheck {
                    name: "cgroup_v2".to_string(),
                    status: DoctorStatus::Fail,
                    detail: format!(
                        "cgroup v2 present at '{}' but missing required controllers [{}] (parent={})",
                        probe_path.display(),
                        missing.join(", "),
                        cgroup_parent.display()
                    ),
                    remediation: Some(
                        "Enable memory, cpu, and pids controllers in /sys/fs/cgroup/cgroup.subtree_control"
                            .to_string(),
                    ),
                }
            }
        }
        Err(_) => DoctorCheck {
            name: "cgroup_v2".to_string(),
            status: DoctorStatus::Fail,
            detail: format!(
                "{} not found (parent={})",
                probe_path.display(),
                cgroup_parent.display()
            ),
            remediation: Some("Mount unified cgroup v2 hierarchy at /sys/fs/cgroup".to_string()),
        },
    }
}

#[cfg(not(target_os = "linux"))]
fn check_cgroup_v2(cgroup_parent: &Path) -> DoctorCheck {
    DoctorCheck {
        name: "cgroup_v2".to_string(),
        status: DoctorStatus::Warn,
        detail: format!(
            "cgroup v2 hierarchy check skipped on non-Linux host (configured parent={})",
            cgroup_parent.display()
        ),
        remediation: Some(
            "Mount unified cgroup v2 hierarchy at /sys/fs/cgroup on Linux".to_string(),
        ),
    }
}

fn check_seccomp_arch() -> DoctorCheck {
    let arch = std::env::consts::ARCH;
    if arch == "x86_64" || arch == "aarch64" {
        DoctorCheck {
            name: "seccomp_arch".to_string(),
            status: DoctorStatus::Pass,
            detail: format!("architecture '{arch}' supported by seccompiler BPF backend"),
            remediation: None,
        }
    } else {
        DoctorCheck {
            name: "seccomp_arch".to_string(),
            status: DoctorStatus::Fail,
            detail: format!("architecture '{arch}' is not supported by seccompiler"),
            remediation: Some("Run on an x86_64 or aarch64 host".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kernel_major_minor_handles_standard_and_distro_releases() {
        assert_eq!(
            parse_kernel_major_minor("5.15.0-101-generic"),
            Some((5, 15))
        );
        assert_eq!(parse_kernel_major_minor("6.8.0-49-generic\n"), Some((6, 8)));
        assert_eq!(parse_kernel_major_minor("6.12-rc4"), Some((6, 12)));
        assert_eq!(parse_kernel_major_minor("4.19.0"), Some((4, 19)));
        assert_eq!(parse_kernel_major_minor("invalid"), None);
        assert_eq!(parse_kernel_major_minor("5.x.0"), None);
    }

    #[test]
    fn run_doctor_produces_structured_checks_for_current_host() {
        let state_root = Path::new("/run/boxlet");
        let cgroup_parent = Path::new("/sys/fs/cgroup/boxlet.slice");
        let report = run_doctor(state_root, cgroup_parent);

        assert_eq!(report.host_os, std::env::consts::OS);
        assert_eq!(report.host_arch, std::env::consts::ARCH);
        assert_eq!(report.checks.len(), 5);

        let names: Vec<&str> = report.checks.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "host_os",
                "kernel_version",
                "root_privileges",
                "cgroup_v2",
                "seccomp_arch"
            ]
        );
        assert!(report.checks[0].detail.contains("/run/boxlet"));
        assert!(report.checks[3]
            .detail
            .contains("/sys/fs/cgroup/boxlet.slice"));

        let expected_ready = report.checks.iter().all(|c| c.status != DoctorStatus::Fail);
        assert_eq!(report.overall_ready, expected_ready);
    }
}
