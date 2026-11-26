//! Hardware-virtualized microVM specification synthesis (AWS Firecracker and `libkrun`)
//! and pluggable [`RuntimeBackend`] implementation.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Instant;

use oci_spec::runtime::Spec;
use serde::{Deserialize, Serialize};

use crate::error::{BoxletError, Result};
use crate::oci::state::{ContainerState, ContainerStatus, StateStore};
use crate::oci::validate_container_id;
use crate::policy::{
    BoundedBuffer, CleanupStatus, ExecutionPolicy, ExecutionResult, PolicyViolations,
    ResolvedRunSpec, ResourceUsage,
};
use crate::traits::RuntimeBackend;

/// Minimum allowed guest RAM allocation in MiB for microVM sandboxes.
const MIN_MEM_SIZE_MIB: u64 = 16;

/// Minimum allowed guest vsock Context ID (CIDs 0, 1, and 2 are reserved by the hypervisor/host).
const MIN_VSOCK_CID: u32 = 3;

/// Bytes per MiB (`1024 * 1024`).
const BYTES_PER_MIB: u64 = 1024 * 1024;

/// Hardware virtualization VMM driver target for microVM sandboxes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VmmDriver {
    /// AWS Firecracker microVM (`firecracker` VMM config JSON).
    Firecracker,
    /// `libkrun` KVM/HVF microVM library configuration.
    Libkrun,
}

impl fmt::Display for VmmDriver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Firecracker => f.write_str("firecracker"),
            Self::Libkrun => f.write_str("libkrun"),
        }
    }
}

impl FromStr for VmmDriver {
    type Err = BoxletError;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "firecracker" => Ok(Self::Firecracker),
            "libkrun" => Ok(Self::Libkrun),
            other => Err(BoxletError::InvalidPolicy {
                reason: format!(
                    "unsupported VMM driver '{other}' (expected 'firecracker' or 'libkrun')"
                ),
            }),
        }
    }
}

/// Host-side configuration for launching or generating a hardware-virtualized microVM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroVmConfig {
    /// Selected VMM driver (`Firecracker` or `Libkrun`).
    pub driver: VmmDriver,
    /// Path to the uncompressed guest Linux kernel image (`vmlinux`), required for Firecracker.
    pub kernel_image_path: PathBuf,
    /// Optional initrd path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initrd_path: Option<PathBuf>,
    /// Kernel boot arguments.
    pub boot_args: String,
    /// Guest vCPU count (`>= 1`).
    pub vcpu_count: u8,
    /// Guest RAM size in MiB (`>= 16`).
    pub mem_size_mib: u64,
    /// Guest vsock Context ID (`>= 3`).
    pub vsock_cid: u32,
}

impl Default for MicroVmConfig {
    fn default() -> Self {
        Self {
            driver: VmmDriver::Firecracker,
            kernel_image_path: PathBuf::from("/var/lib/boxlet/vmlinux"),
            initrd_path: None,
            boot_args: "console=ttyS0 reboot=k panic=1 pci=off".to_string(),
            vcpu_count: 1,
            mem_size_mib: 128,
            vsock_cid: 3,
        }
    }
}

/// Complete Firecracker VMM configuration document (`/boot-source`, `/drives/rootfs`, `/machine-config`, `/vsock`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirecrackerVmSpec {
    /// Container or sandbox identifier.
    pub sandbox_id: String,
    /// Guest kernel image path (`boot-source.kernel_image_path`).
    pub kernel_image_path: PathBuf,
    /// Optional initrd path (`boot-source.initrd_path`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initrd_path: Option<PathBuf>,
    /// Kernel command line (`boot-source.boot_args`).
    pub boot_args: String,
    /// Root filesystem image or directory path (`drives[0].path_on_host`).
    pub rootfs_path: PathBuf,
    /// Whether the root drive is mounted read-only (`drives[0].is_read_only`).
    pub is_read_only: bool,
    /// Number of vCPUs (`machine-config.vcpu_count`).
    pub vcpu_count: u8,
    /// Memory size in MiB (`machine-config.mem_size_mib`).
    pub mem_size_mib: u64,
    /// Guest vsock CID (`vsock.guest_cid`).
    pub vsock_cid: u32,
    /// Guest workload entrypoint argv (`process.args`).
    pub guest_argv: Vec<String>,
    /// Guest environment variables (`process.env`).
    pub guest_env: Vec<String>,
    /// Guest working directory (`process.cwd`).
    pub guest_cwd: String,
}

/// Complete `libkrun` microVM context configuration (`krun_set_vm_config`, `krun_set_root`, `krun_set_exec`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LibkrunVmSpec {
    /// Container or sandbox identifier.
    pub sandbox_id: String,
    /// Host rootfs directory mapped into the microVM via virtio-fs (`krun_set_root`).
    pub rootfs_path: PathBuf,
    /// Whether the rootfs is read-only.
    pub readonly: bool,
    /// Number of vCPUs (`krun_set_vm_config`).
    pub num_vcpus: u8,
    /// RAM size in MiB (`krun_set_vm_config`).
    pub ram_mib: u64,
    /// Workload executable path (`krun_set_exec`).
    pub exec_path: String,
    /// Workload arguments (`krun_set_exec`).
    pub args: Vec<String>,
    /// Workload environment variables (`krun_set_exec`).
    pub env: Vec<String>,
    /// Workload working directory (`krun_set_workdir`).
    pub workdir: String,
}

impl MicroVmConfig {
    /// Validates host-side microVM parameters (`vcpu_count >= 1`, `mem_size_mib >= 16`,
    /// `vsock_cid >= 3`, and non-empty `kernel_image_path`).
    pub fn validate(&self) -> Result<()> {
        if self.vcpu_count < 1 {
            return Err(BoxletError::InvalidPolicy {
                reason: "microvm vcpu_count must be at least 1".to_string(),
            });
        }
        if self.mem_size_mib < MIN_MEM_SIZE_MIB {
            return Err(BoxletError::InvalidPolicy {
                reason: format!(
                    "microvm mem_size_mib must be at least {MIN_MEM_SIZE_MIB} (got {})",
                    self.mem_size_mib
                ),
            });
        }
        if self.vsock_cid < MIN_VSOCK_CID {
            return Err(BoxletError::InvalidPolicy {
                reason: format!(
                    "microvm vsock_cid must be at least {MIN_VSOCK_CID} (got {})",
                    self.vsock_cid
                ),
            });
        }
        if self.kernel_image_path.as_os_str().is_empty() {
            return Err(BoxletError::InvalidPolicy {
                reason: "microvm kernel_image_path must not be empty".to_string(),
            });
        }
        Ok(())
    }

    /// Synthesizes a validated [`FirecrackerVmSpec`] from an OCI bundle [`Spec`] and optional [`ExecutionPolicy`].
    pub fn build_firecracker_spec(
        &self,
        id: &str,
        bundle: &Path,
        spec: &Spec,
        policy: Option<&ExecutionPolicy>,
    ) -> Result<FirecrackerVmSpec> {
        validate_container_id(id)?;
        self.validate()?;
        if let Some(pol) = policy {
            pol.validate()?;
        }

        let (vcpu_count, mem_size_mib) = self.derive_resources(spec, policy);
        let (rootfs_path, is_read_only, guest_argv, guest_env, guest_cwd) =
            extract_oci_workload(bundle, spec)?;

        Ok(FirecrackerVmSpec {
            sandbox_id: id.to_string(),
            kernel_image_path: self.kernel_image_path.clone(),
            initrd_path: self.initrd_path.clone(),
            boot_args: self.boot_args.clone(),
            rootfs_path,
            is_read_only,
            vcpu_count,
            mem_size_mib,
            vsock_cid: self.vsock_cid,
            guest_argv,
            guest_env,
            guest_cwd,
        })
    }

    /// Synthesizes a validated [`LibkrunVmSpec`] from an OCI bundle [`Spec`] and optional [`ExecutionPolicy`].
    pub fn build_libkrun_spec(
        &self,
        id: &str,
        bundle: &Path,
        spec: &Spec,
        policy: Option<&ExecutionPolicy>,
    ) -> Result<LibkrunVmSpec> {
        validate_container_id(id)?;
        self.validate()?;
        if let Some(pol) = policy {
            pol.validate()?;
        }

        let (num_vcpus, ram_mib) = self.derive_resources(spec, policy);
        let (rootfs_path, readonly, guest_argv, env, workdir) = extract_oci_workload(bundle, spec)?;

        let exec_path = guest_argv
            .first()
            .cloned()
            .unwrap_or_else(|| "/bin/sh".to_string());
        let args = if guest_argv.len() > 1 {
            guest_argv[1..].to_vec()
        } else {
            Vec::new()
        };

        Ok(LibkrunVmSpec {
            sandbox_id: id.to_string(),
            rootfs_path,
            readonly,
            num_vcpus,
            ram_mib,
            exec_path,
            args,
            env,
            workdir,
        })
    }

    fn derive_resources(&self, spec: &Spec, policy: Option<&ExecutionPolicy>) -> (u8, u64) {
        let oci_resources = spec.linux().as_ref().and_then(|l| l.resources().as_ref());

        let vcpu_count = if let Some(cpus) = policy.and_then(|p| p.cpus) {
            cpus.ceil().clamp(1.0, f64::from(u8::MAX)) as u8
        } else if let Some(oci_cpu) = oci_resources.and_then(|r| r.cpu().as_ref()) {
            let period = oci_cpu.period().unwrap_or(100_000).max(1);
            if let Some(quota) = oci_cpu.quota().and_then(|q| u64::try_from(q).ok()) {
                let cpus = (quota as f64) / (period as f64);
                cpus.ceil().clamp(1.0, f64::from(u8::MAX)) as u8
            } else {
                self.vcpu_count
            }
        } else {
            self.vcpu_count
        };

        let mem_size_mib = if let Some(bytes) = policy.and_then(|p| p.memory_bytes) {
            (bytes / BYTES_PER_MIB).max(MIN_MEM_SIZE_MIB)
        } else if let Some(limit) = oci_resources
            .and_then(|r| r.memory().as_ref())
            .and_then(|m| m.limit())
            .and_then(|l| u64::try_from(l).ok())
        {
            (limit / BYTES_PER_MIB).max(MIN_MEM_SIZE_MIB)
        } else {
            self.mem_size_mib
        };

        (vcpu_count, mem_size_mib)
    }
}

type WorkloadParts = (PathBuf, bool, Vec<String>, Vec<String>, String);

fn extract_oci_workload(bundle: &Path, spec: &Spec) -> Result<WorkloadParts> {
    let configured_root = spec
        .root()
        .as_ref()
        .map(|r| r.path().clone())
        .unwrap_or_else(|| PathBuf::from("rootfs"));
    let rootfs_path = if configured_root.is_absolute() {
        configured_root
    } else {
        bundle.join(configured_root)
    };
    let is_read_only = spec
        .root()
        .as_ref()
        .and_then(|r| r.readonly())
        .unwrap_or(false);

    let guest_argv = match spec.process().as_ref().and_then(|p| p.args().clone()) {
        Some(args) if args.is_empty() => {
            return Err(BoxletError::InvalidPolicy {
                reason: "OCI process.args must not be empty for microVM execution".to_string(),
            });
        }
        Some(args) => args,
        None => vec!["/bin/sh".to_string()],
    };

    let guest_env = spec
        .process()
        .as_ref()
        .and_then(|p| p.env().clone())
        .unwrap_or_default();

    let guest_cwd = spec
        .process()
        .as_ref()
        .map(|p| p.cwd().to_string_lossy().into_owned())
        .filter(|cwd| !cwd.is_empty())
        .unwrap_or_else(|| "/".to_string());

    Ok((rootfs_path, is_read_only, guest_argv, guest_env, guest_cwd))
}

/// Pluggable [`RuntimeBackend`] adapter that materializes validated Firecracker or `libkrun`
/// microVM specifications under `<state_root>/<id>/microvm.json` and tracks OCI lifecycle state.
#[derive(Debug, Clone)]
pub struct MicroVmBackend {
    state_store: StateStore,
    vm_config: MicroVmConfig,
}

impl MicroVmBackend {
    /// Creates a new [`MicroVmBackend`] rooted at `state_root` with the given [`MicroVmConfig`].
    pub fn new(state_root: impl Into<PathBuf>, vm_config: MicroVmConfig) -> Self {
        Self {
            state_store: StateStore::new(state_root),
            vm_config,
        }
    }

    /// Returns a reference to the underlying [`MicroVmConfig`].
    pub fn vm_config(&self) -> &MicroVmConfig {
        &self.vm_config
    }

    /// Returns a reference to the underlying [`StateStore`].
    pub fn state_store(&self) -> &StateStore {
        &self.state_store
    }

    /// Returns the path to `<state_root>/<id>/microvm.json`.
    pub fn spec_path(&self, id: &str) -> Result<PathBuf> {
        Ok(self.state_store.container_dir(id)?.join("microvm.json"))
    }

    fn write_vm_spec_json(
        &self,
        id: &str,
        bundle: &Path,
        spec: &Spec,
        policy: Option<&ExecutionPolicy>,
    ) -> Result<Vec<u8>> {
        let json_bytes = match self.vm_config.driver {
            VmmDriver::Firecracker => {
                let fc_spec = self
                    .vm_config
                    .build_firecracker_spec(id, bundle, spec, policy)?;
                serde_json::to_vec_pretty(&fc_spec)?
            }
            VmmDriver::Libkrun => {
                let krun_spec = self
                    .vm_config
                    .build_libkrun_spec(id, bundle, spec, policy)?;
                serde_json::to_vec_pretty(&krun_spec)?
            }
        };

        let container_dir = self.state_store.container_dir(id)?;
        let spec_path = container_dir.join("microvm.json");
        let tmp_path = container_dir.join("microvm.json.tmp");

        let mut opts = OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut tmp_file = opts
            .open(&tmp_path)
            .map_err(|source| BoxletError::StateStore {
                path: tmp_path.clone(),
                source,
            })?;
        tmp_file
            .write_all(&json_bytes)
            .map_err(|source| BoxletError::StateStore {
                path: tmp_path.clone(),
                source,
            })?;
        tmp_file
            .sync_all()
            .map_err(|source| BoxletError::StateStore {
                path: tmp_path.clone(),
                source,
            })?;
        drop(tmp_file);

        fs::rename(&tmp_path, &spec_path).map_err(|source| BoxletError::StateStore {
            path: spec_path,
            source,
        })?;

        Ok(json_bytes)
    }
}

impl RuntimeBackend for MicroVmBackend {
    fn create(&self, id: &str, bundle: &Path, spec: &Spec) -> Result<ContainerState> {
        validate_container_id(id)?;
        self.vm_config.validate()?;

        let annotations: BTreeMap<String, String> = spec
            .annotations()
            .as_ref()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();
        self.state_store
            .init_creating(id, bundle.to_path_buf(), annotations)?;

        if let Err(err) = self.write_vm_spec_json(id, bundle, spec, None) {
            let _ = self.state_store.delete(id, true);
            return Err(err);
        }

        match self
            .state_store
            .transition(id, ContainerStatus::Created, Some(std::process::id()))
        {
            Ok(state) => Ok(state),
            Err(err) => {
                let _ = self.state_store.delete(id, true);
                Err(err)
            }
        }
    }

    fn start(&self, id: &str) -> Result<ContainerState> {
        validate_container_id(id)?;
        let spec_path = self.spec_path(id)?;
        if !spec_path.is_file() {
            return Err(BoxletError::ContainerNotFound { id: id.to_string() });
        }
        self.state_store
            .transition(id, ContainerStatus::Running, Some(std::process::id()))
    }

    fn state(&self, id: &str) -> Result<ContainerState> {
        validate_container_id(id)?;
        self.state_store.load(id)
    }

    fn kill(&self, id: &str, _signal: i32) -> Result<()> {
        validate_container_id(id)?;
        let _ = self
            .state_store
            .transition(id, ContainerStatus::Stopped, None)?;
        Ok(())
    }

    fn delete(&self, id: &str, force: bool) -> Result<()> {
        validate_container_id(id)?;
        self.state_store.delete(id, force)
    }

    fn list(&self) -> Result<Vec<ContainerState>> {
        self.state_store.list()
    }

    fn run(&self, id: &str, bundle: &Path, resolved: &ResolvedRunSpec) -> Result<ExecutionResult> {
        validate_container_id(id)?;
        self.vm_config.validate()?;
        let started = Instant::now();

        let derived_cpus = resolved.resources.cpu_quota_usec.map(|quota| {
            let period = resolved.resources.cpu_period_usec.max(1);
            (quota as f64) / (period as f64)
        });
        let derived_policy = ExecutionPolicy {
            memory_bytes: resolved.resources.memory_bytes,
            cpus: derived_cpus,
            pids_limit: resolved.resources.pids_limit,
            io_max: if resolved.resources.io_max.is_empty() {
                None
            } else {
                Some(resolved.resources.io_max.clone())
            },
            network: Some(resolved.network),
            no_new_privs: Some(resolved.no_new_privs),
            capabilities: resolved.capabilities.clone(),
            seccomp: Some(resolved.seccomp.clone()),
            timeout: resolved.timeout,
            max_output_bytes: Some(resolved.max_output_bytes),
            max_concurrency: None,
            nofile_limit: resolved.nofile_limit,
            bind_mounts: if resolved.bind_mounts.is_empty() {
                None
            } else {
                Some(resolved.bind_mounts.clone())
            },
        };

        self.create(id, bundle, &resolved.oci_spec)?;
        let spec_bytes =
            match self.write_vm_spec_json(id, bundle, &resolved.oci_spec, Some(&derived_policy)) {
                Ok(bytes) => bytes,
                Err(err) => {
                    let _ = self.state_store.delete(id, true);
                    return Err(err);
                }
            };

        if let Err(err) = self.start(id) {
            let _ = self.state_store.delete(id, true);
            return Err(err);
        }
        if let Err(err) = self.kill(id, 15) {
            let _ = self.state_store.delete(id, true);
            return Err(err);
        }

        let cleanup = match self.delete(id, true) {
            Ok(()) => CleanupStatus::Clean,
            Err(err) => CleanupStatus::Partial {
                warnings: vec![err.to_string()],
            },
        };

        let mut stdout_buf = BoundedBuffer::new(resolved.max_output_bytes);
        stdout_buf.push(&spec_bytes);
        let (stdout, stdout_truncated) = stdout_buf.into_parts();

        Ok(ExecutionResult {
            container_id: id.to_string(),
            exit_code: Some(0),
            stdout,
            stderr: Vec::new(),
            stdout_truncated,
            stderr_truncated: false,
            usage: ResourceUsage {
                duration: started.elapsed(),
                memory_peak_bytes: resolved.resources.memory_bytes,
                cpu_usage_usec: None,
                psi: None,
            },
            violations: PolicyViolations::default(),
            cleanup,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;
    use crate::oci::BundleBuilder;

    #[test]
    fn firecracker_and_libkrun_specs_derive_vcpus_and_memory_from_policy() -> Result<()> {
        assert_eq!("FIRECRACKER".parse::<VmmDriver>()?, VmmDriver::Firecracker);
        assert_eq!("libkrun".parse::<VmmDriver>()?, VmmDriver::Libkrun);
        assert!(matches!(
            "qemu".parse::<VmmDriver>(),
            Err(BoxletError::InvalidPolicy { .. })
        ));

        let tmp = tempfile::tempdir().map_err(|source| BoxletError::StateStore {
            path: PathBuf::from("tempdir"),
            source,
        })?;
        let bundle_dir = tmp.path().join("bundle");
        let spec = BundleBuilder::new()
            .with_args(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo microvm-ready".to_string(),
            ])
            .with_env(vec!["PATH=/bin:/usr/bin".to_string()])
            .with_cwd("/workspace")
            .with_readonly_rootfs(true)
            .build(&bundle_dir)?;

        let policy = ExecutionPolicy {
            cpus: Some(2.5),
            memory_bytes: Some(256 * 1024 * 1024),
            ..ExecutionPolicy::default()
        };

        let vm_cfg = MicroVmConfig::default();
        let fc_spec =
            vm_cfg.build_firecracker_spec("vm-fc-1", &bundle_dir, &spec, Some(&policy))?;
        assert_eq!(fc_spec.sandbox_id, "vm-fc-1");
        assert_eq!(fc_spec.vcpu_count, 3);
        assert_eq!(fc_spec.mem_size_mib, 256);
        assert_eq!(fc_spec.vsock_cid, 3);
        assert!(fc_spec.is_read_only);
        assert_eq!(fc_spec.rootfs_path, bundle_dir.join("rootfs"));
        assert_eq!(
            fc_spec.guest_argv,
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo microvm-ready".to_string()
            ]
        );
        assert_eq!(fc_spec.guest_cwd, "/workspace");

        let krun_cfg = MicroVmConfig {
            driver: VmmDriver::Libkrun,
            ..MicroVmConfig::default()
        };
        let krun_spec =
            krun_cfg.build_libkrun_spec("vm-krun-1", &bundle_dir, &spec, Some(&policy))?;
        assert_eq!(krun_spec.sandbox_id, "vm-krun-1");
        assert_eq!(krun_spec.num_vcpus, 3);
        assert_eq!(krun_spec.ram_mib, 256);
        assert!(krun_spec.readonly);
        assert_eq!(krun_spec.exec_path, "/bin/sh");
        assert_eq!(
            krun_spec.args,
            vec!["-c".to_string(), "echo microvm-ready".to_string()]
        );
        assert_eq!(krun_spec.workdir, "/workspace");

        // Verify validation rejects out-of-range parameters
        let bad_cfg = MicroVmConfig {
            vcpu_count: 0,
            ..MicroVmConfig::default()
        };
        assert!(matches!(
            bad_cfg.validate(),
            Err(BoxletError::InvalidPolicy { .. })
        ));

        Ok(())
    }

    #[test]
    fn microvm_backend_implements_full_runtime_backend_lifecycle() -> Result<()> {
        let tmp = tempfile::tempdir().map_err(|source| BoxletError::StateStore {
            path: PathBuf::from("tempdir"),
            source,
        })?;
        let state_root = tmp.path().join("state");
        let bundle_dir = tmp.path().join("bundle");
        let _spec = BundleBuilder::new()
            .with_shell_command("echo hello-microvm")
            .build(&bundle_dir)?;

        let backend = MicroVmBackend::new(&state_root, MicroVmConfig::default());
        let engine = Engine::new(backend.clone());

        let created = engine.create("vm-box-1", &bundle_dir)?;
        assert_eq!(created.status, ContainerStatus::Created);
        assert!(backend.spec_path("vm-box-1")?.is_file());

        let started = engine.start("vm-box-1")?;
        assert_eq!(started.status, ContainerStatus::Running);

        let queried = engine.state("vm-box-1")?;
        assert_eq!(queried.status, ContainerStatus::Running);

        let listed = engine.list()?;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, "vm-box-1");

        engine.kill("vm-box-1", 15)?;
        assert_eq!(engine.state("vm-box-1")?.status, ContainerStatus::Stopped);

        engine.delete("vm-box-1", false)?;
        assert!(engine.list()?.is_empty());

        // End-to-end Engine::run on MicroVmBackend
        let run_policy = ExecutionPolicy {
            cpus: Some(2.0),
            memory_bytes: Some(64 * 1024 * 1024),
            ..ExecutionPolicy::default()
        };
        let run_res = engine.run("vm-run-1", &bundle_dir, &run_policy)?;
        assert_eq!(run_res.exit_code, Some(0));
        assert_eq!(run_res.cleanup, CleanupStatus::Clean);
        let parsed_spec: FirecrackerVmSpec = serde_json::from_slice(&run_res.stdout)?;
        assert_eq!(parsed_spec.sandbox_id, "vm-run-1");
        assert_eq!(parsed_spec.vcpu_count, 2);
        assert_eq!(parsed_spec.mem_size_mib, 64);

        Ok(())
    }
}
