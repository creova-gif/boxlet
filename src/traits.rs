//! Runtime backend and internal Linux strategy traits.

use std::path::Path;
#[cfg_attr(not(target_os = "linux"), allow(unused_imports))]
use std::path::PathBuf;

use oci_spec::runtime::Spec;

use crate::error::Result;
use crate::oci::state::ContainerState;
#[cfg_attr(not(target_os = "linux"), allow(unused_imports))]
use crate::policy::{ExecutionResult, ResolvedRunSpec, ResourceLimits};

/// Deep execution backend interface consumed by `Engine`.
///
/// Hides platform-specific lifecycle ordering (e.g. Linux cgroup v2 setup,
/// `pivot_root`, `boxlet __init` handshake, and 7-step teardown) so alternative
/// backends (such as `youki`, Firecracker, or `libkrun`) can plug in cleanly.
pub trait RuntimeBackend: Send + Sync {
    /// Creates a container from an OCI bundle using `spec` verbatim.
    fn create(&self, id: &str, bundle: &Path, spec: &Spec) -> Result<ContainerState>;

    /// Starts a previously created container (`Created -> Running`).
    fn start(&self, id: &str) -> Result<ContainerState>;

    /// Returns the current OCI state of a container.
    fn state(&self, id: &str) -> Result<ContainerState>;

    /// Sends an OS signal to a running container's init process.
    fn kill(&self, id: &str, signal: i32) -> Result<()>;

    /// Deletes a stopped container (or forcefully terminates and removes it when `force` is true).
    fn delete(&self, id: &str, force: bool) -> Result<()>;

    /// Lists all tracked containers in deterministic `id` order, refreshing liveness where supported.
    fn list(&self) -> Result<Vec<ContainerState>> {
        Ok(Vec::new())
    }

    /// Runs a container end-to-end with a merged [`ResolvedRunSpec`] and returns structured results.
    fn run(&self, id: &str, bundle: &Path, resolved: &ResolvedRunSpec) -> Result<ExecutionResult>;
}

/// Snapshot of cgroup v2 telemetry read prior to cgroup teardown.
#[allow(dead_code)] // Consumed by LinuxBackend in Milestone 2.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CgroupStats {
    pub memory_peak_bytes: Option<u64>,
    pub cpu_usage_usec: Option<u64>,
    pub oom_kill_count: u64,
}

/// Internal root filesystem strategy composed inside `LinuxBackend`.
///
/// V1 implements bind-mount + `pivot_root`; V2 plugs in overlayfs snapshotting and diffing.
#[allow(dead_code)] // Implemented by LinuxBackend in Milestone 2.
pub(crate) trait RootfsProvider: Send + Sync {
    fn prepare(&self, container_id: &str, rootfs_path: &Path) -> Result<PathBuf>;
    fn cleanup(&self, container_id: &str, prepared_path: &Path) -> Result<()>;
}

/// Internal cgroup v2 resource controller strategy composed inside `LinuxBackend`.
#[allow(dead_code)] // Implemented by LinuxBackend in Milestone 2.
pub(crate) trait ResourceController: Send + Sync {
    fn create_cgroup(&self, container_id: &str, limits: &ResourceLimits) -> Result<PathBuf>;
    fn attach_pid(&self, container_id: &str, pid: u32) -> Result<()>;
    fn kill_all(&self, container_id: &str) -> Result<()>;
    fn read_stats(&self, container_id: &str) -> Result<CgroupStats>;
    fn remove_cgroup(&self, container_id: &str) -> Result<()>;
}
