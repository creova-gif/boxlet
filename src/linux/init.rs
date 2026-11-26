//! Self-re-exec `boxlet __init` handshake and strict pre-`execve` container bootstrap.
//!
//! Per ADR-001 (R2):
//! 1. Intermediate `boxlet __init` sets `PR_SET_PDEATHSIG(SIGKILL)`, calls `unshare(...)`,
//!    and forks real container PID 1 (required because `unshare(CLONE_NEWPID)` only places
//!    the first child into the new PID namespace).
//! 2. Container PID 1 reports its host PID over the sync pipe, waits for cgroup attachment,
//!    pivots root, waits on the start FIFO (for OCI `create`/`start` separation), drops
//!    capabilities + `PR_SET_NO_NEW_PRIVS`, closes all non-stdio FDs, loads `seccompiler`
//!    BPF as the **very last step**, and calls `execve`.

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::path::{Path, PathBuf};

use nix::sched::CloneFlags;
use nix::unistd::{chdir, execvpe, fork, ForkResult};
use oci_spec::runtime::{PosixRlimitType, Spec};
use serde::{Deserialize, Serialize};

use crate::error::{BoxletError, Result};
use crate::linux::{caps, namespaces, rootfs, seccomp};
use crate::policy::{NetworkMode, SeccompPolicy};

#[cfg(target_env = "gnu")]
type RlimitResource = libc::__rlimit_resource_t;
#[cfg(not(target_env = "gnu"))]
type RlimitResource = libc::c_int;

/// Handshake config written by parent `LinuxBackend` to `<state_dir>/init.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct InitConfig {
    pub container_id: String,
    pub rootfs_path: PathBuf,
    pub spec: Spec,
    pub network_override: Option<NetworkMode>,
    pub no_new_privs: bool,
    pub capabilities_override: Option<Vec<String>>,
    pub seccomp_policy: Option<SeccompPolicy>,
    #[serde(default)]
    pub nofile_limit: Option<u64>,
    #[serde(default)]
    pub bind_mounts: Vec<crate::policy::BindMountSpec>,
    pub wait_for_start_fifo: Option<PathBuf>,
    pub pid_pipe_write_fd: RawFd,
    pub ack_pipe_read_fd: RawFd,
    pub ready_pipe_write_fd: RawFd,
}

/// Entry point executed by `boxlet __init <init_config_path>`.
pub fn run_init_process(config_path: &Path) -> Result<()> {
    let raw = fs::read_to_string(config_path).map_err(|err| BoxletError::Runtime {
        subsystem: "init",
        message: format!(
            "failed to read init config '{}': {err}",
            config_path.display()
        ),
    })?;
    let cfg: InitConfig = serde_json::from_str(&raw)?;

    // Ensure intermediate child dies immediately if parent crashes mid-handshake.
    set_pdeathsig_sigkill()?;

    // Pre-compile seccomp BPF BEFORE pivot_root so any fail-closed error aborts cleanly
    // before mutating mount namespaces or entering execve.
    let compiled_bpf = resolve_seccomp_bpf(&cfg)?;

    let host_euid = nix::unistd::geteuid().as_raw();
    let host_egid = nix::unistd::getegid().as_raw();
    let ns_flags = namespaces::build_unshare_flags(&cfg.spec, cfg.network_override);
    namespaces::unshare_namespaces(ns_flags)?;
    namespaces::apply_user_namespace_mappings(&cfg.spec, ns_flags, host_euid, host_egid)?;

    // SAFETY: `boxlet __init` is a freshly exec'd single-threaded process, so `fork()`
    // is safe here and places the child as PID 1 inside the new PID namespace.
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            // Report real container PID 1 (in host namespace) to the parent runtime.
            let mut pid_pipe = unsafe { File::from_raw_fd(cfg.pid_pipe_write_fd) };
            let pid_bytes = (child.as_raw() as u32).to_le_bytes();
            pid_pipe
                .write_all(&pid_bytes)
                .map_err(|err| BoxletError::Runtime {
                    subsystem: "init",
                    message: format!("failed to send PID 1 over sync pipe: {err}"),
                })?;
            drop(pid_pipe);
            // Intermediate process exits cleanly; container PID 1 is now owned by its namespace.
            std::process::exit(0);
        }
        Ok(ForkResult::Child) => container_pid1_main(cfg, ns_flags, compiled_bpf),
        Err(err) => Err(BoxletError::Runtime {
            subsystem: "init",
            message: format!("fork() for container PID 1 failed: {err}"),
        }),
    }
}

fn container_pid1_main(
    cfg: InitConfig,
    ns_flags: CloneFlags,
    compiled_bpf: Option<seccompiler::BpfProgram>,
) -> Result<()> {
    // 1. Wait for parent ack confirming PID 1 is attached to cgroup v2 and state.json is written.
    let mut ack_pipe = unsafe { File::from_raw_fd(cfg.ack_pipe_read_fd) };
    let mut ack = [0u8; 1];
    ack_pipe
        .read_exact(&mut ack)
        .map_err(|err| BoxletError::Runtime {
            subsystem: "init",
            message: format!("failed waiting for parent cgroup ack: {err}"),
        })?;
    drop(ack_pipe);

    // 2. Configure UTS hostname and isolated loopback if CLONE_NEWNET was enabled.
    namespaces::apply_hostname(&cfg.spec)?;
    if ns_flags.contains(CloneFlags::CLONE_NEWNET) {
        namespaces::bring_up_loopback()?;
    }

    // 3. Open start FIFO O_RDWR before pivot_root: never blocks on open() and blocks on read()
    // until `boxlet start` writes the trigger byte (preventing create/start deadlock).
    let start_fifo_file = match &cfg.wait_for_start_fifo {
        Some(fifo_path) => Some(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(fifo_path)
                .map_err(|err| BoxletError::Runtime {
                    subsystem: "init",
                    message: format!("failed to open start FIFO '{}': {err}", fifo_path.display()),
                })?,
        ),
        None => None,
    };

    // 4. Pivot root + mount /proc + minimal /dev + bind mounts + masked/readonly paths.
    rootfs::setup_and_pivot_root(&cfg.rootfs_path, &cfg.spec, &cfg.bind_mounts)?;

    // 5. Set working directory inside the pivoted rootfs.
    if let Some(process) = cfg.spec.process() {
        let cwd = process.cwd();
        if !cwd.as_os_str().is_empty() {
            chdir(cwd).map_err(|err| BoxletError::Runtime {
                subsystem: "init",
                message: format!("chdir('{}') inside container failed: {err}", cwd.display()),
            })?;
        }
    }

    // 6. Signal parent that container is READY (Created).
    let mut ready_pipe = unsafe { File::from_raw_fd(cfg.ready_pipe_write_fd) };
    ready_pipe
        .write_all(&[1u8])
        .map_err(|err| BoxletError::Runtime {
            subsystem: "init",
            message: format!("failed to send ready byte to parent: {err}"),
        })?;
    drop(ready_pipe);

    // 7. In `create` mode, block on start FIFO until `boxlet start` writes a trigger byte.
    if let Some(mut fifo) = start_fifo_file {
        let mut go = [0u8; 1];
        fifo.read_exact(&mut go)
            .map_err(|err| BoxletError::Runtime {
                subsystem: "init",
                message: format!("failed reading start FIFO trigger: {err}"),
            })?;
        drop(fifo);
    }

    // Enforce POSIX resource limits (RLIMIT_CORE = 0 default + OCI process.rlimits + nofile_limit).
    apply_rlimits(&cfg.spec, cfg.nofile_limit)?;

    // 8. Drop Linux capabilities and enforce PR_SET_NO_NEW_PRIVS.
    let oci_caps = cfg
        .spec
        .process()
        .as_ref()
        .and_then(|p| p.capabilities().as_ref());
    caps::apply_capabilities(cfg.capabilities_override.as_deref(), oci_caps)?;
    if cfg.no_new_privs {
        caps::set_no_new_privs()?;
    }

    // 9. Close all inherited non-stdio file descriptors before loading seccomp and execve.
    close_non_stdio_fds();

    // 10. Prepare execve arguments & environment.
    let (program, args, env) = extract_exec_params(&cfg.spec)?;

    // 11. Load compiled seccomp cBPF filter as the VERY LAST step before execve.
    if let Some(bpf) = &compiled_bpf {
        seccomp::apply_bpf_filter(bpf)?;
    }

    // 12. Replace PID 1 image with the container workload.
    match execvpe(&program, &args, &env) {
        Ok(infallible) => match infallible {},
        Err(err) => Err(BoxletError::Runtime {
            subsystem: "init",
            message: format!("execvpe({program:?}) failed: {err}"),
        }),
    }
}

fn resolve_seccomp_bpf(cfg: &InitConfig) -> Result<Option<seccompiler::BpfProgram>> {
    match &cfg.seccomp_policy {
        Some(SeccompPolicy::Disabled) => Ok(None),
        Some(SeccompPolicy::DefaultDeny) => {
            let profile = seccomp::default_deny_profile()?;
            Ok(Some(seccomp::compile_oci_seccomp(&profile)?))
        }
        Some(SeccompPolicy::Custom(profile)) => Ok(Some(seccomp::compile_oci_seccomp(profile)?)),
        None => match cfg.spec.linux().as_ref().and_then(|l| l.seccomp().as_ref()) {
            Some(oci_profile) => Ok(Some(seccomp::compile_oci_seccomp(oci_profile)?)),
            None => Ok(None),
        },
    }
}

fn extract_exec_params(spec: &Spec) -> Result<(CString, Vec<CString>, Vec<CString>)> {
    let process = spec
        .process()
        .as_ref()
        .ok_or_else(|| BoxletError::Runtime {
            subsystem: "init",
            message: "OCI spec missing required 'process' section".to_string(),
        })?;

    let raw_args = process
        .args()
        .as_ref()
        .ok_or_else(|| BoxletError::Runtime {
            subsystem: "init",
            message: "OCI spec missing required 'process.args'".to_string(),
        })?;

    if raw_args.is_empty() {
        return Err(BoxletError::Runtime {
            subsystem: "init",
            message: "OCI spec 'process.args' must not be empty".to_string(),
        });
    }

    let args: Vec<CString> = raw_args
        .iter()
        .map(|a| {
            CString::new(a.as_str()).map_err(|err| BoxletError::Runtime {
                subsystem: "init",
                message: format!("process arg contains interior NUL byte: {err}"),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let env: Vec<CString> = process
        .env()
        .as_ref()
        .map(|vars| {
            vars.iter()
                .map(|e| {
                    CString::new(e.as_str()).map_err(|err| BoxletError::Runtime {
                        subsystem: "init",
                        message: format!("process env contains interior NUL byte: {err}"),
                    })
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();

    let program = args[0].clone();
    Ok((program, args, env))
}

fn apply_rlimits(spec: &Spec, nofile_override: Option<u64>) -> Result<()> {
    // Default-disable core dumps (RLIMIT_CORE = 0) so untrusted sandbox crashes
    // never dump core files to disk unless explicitly enabled by process.rlimits.
    set_single_rlimit(libc::RLIMIT_CORE, 0, 0)?;

    if let Some(rlimits) = spec.process().as_ref().and_then(|p| p.rlimits().as_ref()) {
        for rlimit in rlimits {
            let res = match rlimit.typ() {
                PosixRlimitType::RlimitNofile => Some(libc::RLIMIT_NOFILE),
                PosixRlimitType::RlimitCore => Some(libc::RLIMIT_CORE),
                PosixRlimitType::RlimitNproc => Some(libc::RLIMIT_NPROC),
                PosixRlimitType::RlimitAs => Some(libc::RLIMIT_AS),
                PosixRlimitType::RlimitFsize => Some(libc::RLIMIT_FSIZE),
                PosixRlimitType::RlimitStack => Some(libc::RLIMIT_STACK),
                PosixRlimitType::RlimitCpu => Some(libc::RLIMIT_CPU),
                PosixRlimitType::RlimitMemlock => Some(libc::RLIMIT_MEMLOCK),
                _ => None,
            };
            if let Some(resource) = res {
                set_single_rlimit(resource, rlimit.soft(), rlimit.hard())?;
            }
        }
    }

    if let Some(nofile) = nofile_override {
        set_single_rlimit(libc::RLIMIT_NOFILE, nofile, nofile)?;
    }

    Ok(())
}

fn set_single_rlimit(resource: RlimitResource, soft: u64, hard: u64) -> Result<()> {
    let lim = libc::rlimit {
        rlim_cur: soft as libc::rlim_t,
        rlim_max: hard as libc::rlim_t,
    };
    // SAFETY: `setrlimit` is a standard POSIX syscall taking a valid `rlimit` struct pointer.
    let rc = unsafe { libc::setrlimit(resource, &lim) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(BoxletError::Runtime {
            subsystem: "init",
            message: format!(
                "setrlimit(resource={resource}, soft={soft}, hard={hard}) failed: {err}"
            ),
        });
    }
    Ok(())
}

fn set_pdeathsig_sigkill() -> Result<()> {
    // SAFETY: `prctl(PR_SET_PDEATHSIG, SIGKILL)` takes only integer constants.
    let rc = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(BoxletError::Runtime {
            subsystem: "init",
            message: format!("prctl(PR_SET_PDEATHSIG) failed: {err}"),
        });
    }
    Ok(())
}

fn close_non_stdio_fds() {
    // Best-effort sweep of /proc/self/fd to close any open FDs >= 3 before execve.
    if let Ok(entries) = fs::read_dir("/proc/self/fd") {
        let mut fds = Vec::new();
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(fd) = name.parse::<RawFd>() {
                    if fd >= 3 {
                        fds.push(fd);
                    }
                }
            }
        }
        for fd in fds {
            // SAFETY: Closing non-stdio descriptors owned by this freshly exec'd init process.
            unsafe {
                libc::close(fd);
            }
        }
    }
}
