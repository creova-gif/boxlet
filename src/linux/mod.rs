//! Linux 5.15+ `RuntimeBackend` implementation composing namespaces, `pivot_root`,
//! cgroup v2, capabilities, pure-Rust `seccompiler`, and self-re-exec `boxlet __init`.

pub(crate) mod caps;
pub(crate) mod cgroup_v2;
pub(crate) mod init;
pub(crate) mod namespaces;
pub(crate) mod rootfs;
pub(crate) mod seccomp;

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::signal::{kill as nix_kill, Signal};
use nix::sys::stat::Mode;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{mkfifo, pipe, Pid};
use oci_spec::runtime::Spec;

use crate::error::{BoxletError, Result};
use crate::linux::cgroup_v2::{CgroupV2Controller, DEFAULT_CGROUP_PARENT};
use crate::linux::init::InitConfig;
use crate::linux::rootfs::BindPivotRootfs;
use crate::oci::state::{ContainerState, ContainerStatus, StateStore, DEFAULT_STATE_ROOT};
use crate::policy::{
    BoundedBuffer, CleanupStatus, ExecutionResult, PolicyViolations, ResolvedRunSpec,
    ResourceLimits, ResourceUsage,
};
use crate::traits::{ResourceController, RootfsProvider, RuntimeBackend};

/// Maximum time to wait for `boxlet __init` to report PID 1 and reach `Created` state.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Linux 5.15+ OCI container backend implementing [`RuntimeBackend`].
#[derive(Debug, Clone)]
pub struct LinuxBackend {
    state_store: StateStore,
    cgroup: CgroupV2Controller,
    rootfs: BindPivotRootfs,
}

impl LinuxBackend {
    /// Creates a `LinuxBackend` with custom state root (`--root`) and cgroup parent (`--cgroup-parent`).
    pub fn new(state_root: impl Into<PathBuf>, cgroup_parent: impl Into<PathBuf>) -> Self {
        Self {
            state_store: StateStore::new(state_root),
            cgroup: CgroupV2Controller::new(cgroup_parent),
            rootfs: BindPivotRootfs,
        }
    }

    /// Creates a `LinuxBackend` using default `/run/boxlet` and `/sys/fs/cgroup/boxlet.slice`.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_STATE_ROOT, DEFAULT_CGROUP_PARENT)
    }
}

/// RAII guard that rolls back cgroup and state directory if `create` fails mid-handshake (ADR-001 R2).
struct CreateRollbackGuard<'a> {
    id: &'a str,
    state_store: &'a StateStore,
    cgroup: &'a CgroupV2Controller,
    armed: bool,
}

impl<'a> CreateRollbackGuard<'a> {
    fn new(id: &'a str, state_store: &'a StateStore, cgroup: &'a CgroupV2Controller) -> Self {
        Self {
            id,
            state_store,
            cgroup,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CreateRollbackGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.cgroup.kill_all(self.id);
            let _ = self.cgroup.remove_cgroup(self.id);
            let _ = self.state_store.delete(self.id, true);
        }
    }
}

impl RuntimeBackend for LinuxBackend {
    fn create(&self, id: &str, bundle: &Path, spec: &Spec) -> Result<ContainerState> {
        let limits = extract_oci_limits(spec);
        let state = self.spawn_container(
            id,
            bundle,
            spec,
            &limits,
            None,
            spec.process()
                .as_ref()
                .and_then(|p| p.no_new_privileges())
                .unwrap_or(false),
            None,
            None,
            true,
            Stdio::inherit(),
            Stdio::inherit(),
        )?;
        Ok(state.0)
    }

    fn start(&self, id: &str) -> Result<ContainerState> {
        let current = self.state_store.load(id)?;
        if current.status != ContainerStatus::Created {
            return Err(BoxletError::InvalidStateTransition {
                id: id.to_string(),
                from: current.status,
                to: ContainerStatus::Running,
            });
        }

        let fifo_path = self.state_store.container_dir(id)?.join("start.fifo");
        let mut fifo = OpenOptions::new()
            .write(true)
            .open(&fifo_path)
            .map_err(|err| BoxletError::Runtime {
                subsystem: "init",
                message: format!("failed to open start FIFO '{}': {err}", fifo_path.display()),
            })?;
        fifo.write_all(&[1u8]).map_err(|err| BoxletError::Runtime {
            subsystem: "init",
            message: format!("failed to signal start FIFO: {err}"),
        })?;

        self.state_store
            .transition(id, ContainerStatus::Running, None)
    }

    fn state(&self, id: &str) -> Result<ContainerState> {
        let mut st = self.state_store.load(id)?;
        if st.status == ContainerStatus::Running {
            if let Some(pid) = st.pid {
                let alive = nix_kill(Pid::from_raw(pid as i32), None).is_ok();
                if !alive {
                    st = self
                        .state_store
                        .transition(id, ContainerStatus::Stopped, None)?;
                }
            }
        }
        Ok(st)
    }

    fn kill(&self, id: &str, signal: i32) -> Result<()> {
        let st = self.state_store.load(id)?;
        let Some(pid) = st.pid else {
            return Err(BoxletError::Runtime {
                subsystem: "lifecycle",
                message: format!("container '{id}' has no active PID (status: {})", st.status),
            });
        };
        let sig = Signal::try_from(signal).map_err(|err| BoxletError::Runtime {
            subsystem: "lifecycle",
            message: format!("invalid signal number {signal}: {err}"),
        })?;
        nix_kill(Pid::from_raw(pid as i32), sig).map_err(|err| BoxletError::Runtime {
            subsystem: "lifecycle",
            message: format!("kill({pid}, {sig}) failed: {err}"),
        })
    }

    fn delete(&self, id: &str, force: bool) -> Result<()> {
        if force {
            let _ = self.cgroup.kill_all(id);
        }
        let _ = self.cgroup.remove_cgroup(id);
        self.state_store.delete(id, force)
    }

    fn run(&self, id: &str, bundle: &Path, resolved: &ResolvedRunSpec) -> Result<ExecutionResult> {
        let start_time = Instant::now();
        // Become a child subreaper so when intermediate `boxlet __init` exits after forking
        // container PID 1, the kernel reparents PID 1 to this process and `waitpid(pid1)` works.
        set_child_subreaper()?;

        let (stdout_read, stdout_write) = pipe().map_err(|err| BoxletError::Runtime {
            subsystem: "io",
            message: format!("pipe() for stdout failed: {err}"),
        })?;
        let (stderr_read, stderr_write) = pipe().map_err(|err| BoxletError::Runtime {
            subsystem: "io",
            message: format!("pipe() for stderr failed: {err}"),
        })?;

        let max_bytes = resolved.max_output_bytes;
        let stdout_handle = spawn_bounded_reader(stdout_read, max_bytes);
        let stderr_handle = spawn_bounded_reader(stderr_read, max_bytes);

        let (state, _child_guard) = match self.spawn_container(
            id,
            bundle,
            &resolved.oci_spec,
            &resolved.resources,
            Some(resolved.network),
            resolved.no_new_privs,
            resolved.capabilities.clone(),
            Some(resolved.seccomp.clone()),
            false,
            Stdio::from(stdout_write),
            Stdio::from(stderr_write),
        ) {
            Ok(pair) => pair,
            Err(err) => {
                let (init_stderr, _) = stderr_handle.join().unwrap_or_else(|_| (Vec::new(), false));
                let detail = String::from_utf8_lossy(&init_stderr).trim().to_string();
                if detail.is_empty() {
                    return Err(err);
                }
                return Err(BoxletError::Runtime {
                    subsystem: "init",
                    message: format!("{err}; init stderr: {detail}"),
                });
            }
        };

        let pid1 = state.pid.ok_or_else(|| BoxletError::Runtime {
            subsystem: "init",
            message: "spawned container missing PID 1".to_string(),
        })?;
        let _ = self
            .state_store
            .transition(id, ContainerStatus::Running, None);

        // 7-step deterministic teardown sequence (ADR-001 R3 / D4):
        // Step 1 & 2: Wait for PID 1 exit or timeout deadline -> cgroup.kill on timeout.
        let (wait_status, timed_out) =
            wait_with_timeout(Pid::from_raw(pid1 as i32), resolved.timeout, || {
                let _ = self.cgroup.kill_all(id);
            });

        // Step 3: Extract exit_code / termination_signal from reaped PID 1 status.
        let (exit_code, termination_signal) = match wait_status {
            Some(WaitStatus::Exited(_, code)) => (Some(code), None),
            Some(WaitStatus::Signaled(_, sig, _)) => (None, Some(sig as i32)),
            _ => (None, None),
        };

        // Step 4: Unconditional cgroup.kill to terminate any lingering grandchildren holding stdout/stderr FDs.
        let mut warnings = Vec::new();
        if let Err(err) = self.cgroup.kill_all(id) {
            warnings.push(format!("cgroup.kill warning: {err}"));
        }

        // Step 5: Join bounded stdout/stderr reader threads (EOF now guaranteed).
        let (stdout, stdout_truncated) =
            stdout_handle.join().unwrap_or_else(|_| (Vec::new(), false));
        let (stderr, stderr_truncated) =
            stderr_handle.join().unwrap_or_else(|_| (Vec::new(), false));

        // Step 6: Read cgroup v2 telemetry BEFORE removing the cgroup directory.
        let stats = self.cgroup.read_stats(id).unwrap_or_default();

        // Step 7: Remove leaf cgroup directory and container state directory.
        if let Err(err) = self.cgroup.remove_cgroup(id) {
            warnings.push(format!("cgroup remove warning: {err}"));
        }
        if let Err(err) = self.state_store.delete(id, true) {
            warnings.push(format!("state delete warning: {err}"));
        }

        let cleanup = if warnings.is_empty() {
            CleanupStatus::Clean
        } else {
            CleanupStatus::Partial { warnings }
        };

        Ok(ExecutionResult {
            container_id: id.to_string(),
            exit_code,
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
            usage: ResourceUsage {
                duration: start_time.elapsed(),
                memory_peak_bytes: stats.memory_peak_bytes,
                cpu_usage_usec: stats.cpu_usage_usec,
            },
            violations: PolicyViolations {
                timed_out,
                oom_killed: stats.oom_kill_count > 0,
                termination_signal,
            },
            cleanup,
        })
    }
}

impl LinuxBackend {
    #[allow(clippy::too_many_arguments)]
    fn spawn_container(
        &self,
        id: &str,
        bundle: &Path,
        spec: &Spec,
        limits: &ResourceLimits,
        network_override: Option<crate::policy::NetworkMode>,
        no_new_privs: bool,
        capabilities_override: Option<Vec<String>>,
        seccomp_policy: Option<crate::policy::SeccompPolicy>,
        wait_for_start: bool,
        stdout_cfg: Stdio,
        stderr_cfg: Stdio,
    ) -> Result<(ContainerState, ())> {
        let annotations: BTreeMap<String, String> = spec
            .annotations()
            .as_ref()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();

        self.state_store
            .init_creating(id, bundle.to_path_buf(), annotations)?;
        let mut rollback = CreateRollbackGuard::new(id, &self.state_store, &self.cgroup);

        let raw_rootfs = spec
            .root()
            .as_ref()
            .map(|r| bundle.join(r.path()))
            .unwrap_or_else(|| bundle.join("rootfs"));
        let prepared_rootfs = self.rootfs.prepare(id, &raw_rootfs)?;

        self.cgroup.create_cgroup(id, limits)?;

        let state_dir = self.state_store.container_dir(id)?;
        let start_fifo_path = if wait_for_start {
            let p = state_dir.join("start.fifo");
            mkfifo(&p, Mode::S_IRUSR | Mode::S_IWUSR).map_err(|err| BoxletError::Runtime {
                subsystem: "init",
                message: format!("mkfifo('{}') failed: {err}", p.display()),
            })?;
            Some(p)
        } else {
            None
        };

        let (pid_r, pid_w) = pipe().map_err(|err| BoxletError::Runtime {
            subsystem: "init",
            message: format!("pipe(pid) failed: {err}"),
        })?;
        let (ack_r, ack_w) = pipe().map_err(|err| BoxletError::Runtime {
            subsystem: "init",
            message: format!("pipe(ack) failed: {err}"),
        })?;
        let (ready_r, ready_w) = pipe().map_err(|err| BoxletError::Runtime {
            subsystem: "init",
            message: format!("pipe(ready) failed: {err}"),
        })?;

        // Clear FD_CLOEXEC only on the three child ends so `boxlet __init` inherits them.
        clear_cloexec(&pid_w)?;
        clear_cloexec(&ack_r)?;
        clear_cloexec(&ready_w)?;

        let init_cfg = InitConfig {
            container_id: id.to_string(),
            rootfs_path: prepared_rootfs,
            spec: spec.clone(),
            network_override,
            no_new_privs,
            capabilities_override,
            seccomp_policy,
            wait_for_start_fifo: start_fifo_path,
            pid_pipe_write_fd: pid_w.as_raw_fd(),
            ack_pipe_read_fd: ack_r.as_raw_fd(),
            ready_pipe_write_fd: ready_w.as_raw_fd(),
        };

        let init_cfg_path = state_dir.join("init.json");
        fs::write(&init_cfg_path, serde_json::to_vec_pretty(&init_cfg)?).map_err(|err| {
            BoxletError::Runtime {
                subsystem: "init",
                message: format!("failed to write init.json: {err}"),
            }
        })?;

        let current_exe = std::env::current_exe().map_err(|err| BoxletError::Runtime {
            subsystem: "init",
            message: format!("failed to resolve current_exe for self-re-exec: {err}"),
        })?;

        let mut child = Command::new(current_exe)
            .arg("__init")
            .arg(&init_cfg_path)
            .stdin(Stdio::null())
            .stdout(stdout_cfg)
            .stderr(stderr_cfg)
            .spawn()
            .map_err(|err| BoxletError::Runtime {
                subsystem: "init",
                message: format!("failed to spawn boxlet __init: {err}"),
            })?;

        // Close child pipe ends in parent so EOF is observed if child crashes.
        drop(pid_w);
        drop(ack_r);
        drop(ready_w);

        // Read real container PID 1 with bounded handshake timeout.
        let pid_bytes = read_exact_with_timeout(&pid_r, 4, HANDSHAKE_TIMEOUT)?;
        let pid1 = u32::from_le_bytes([pid_bytes[0], pid_bytes[1], pid_bytes[2], pid_bytes[3]]);

        // Reap intermediate helper process.
        let _ = child.wait();

        // Attach container PID 1 to cgroup v2 and transition state to Created.
        self.cgroup.attach_pid(id, pid1)?;
        let created_state =
            self.state_store
                .transition(id, ContainerStatus::Created, Some(pid1))?;

        // Send ack byte to PID 1 so it proceeds to pivot_root & ready signal.
        let mut ack_file = unsafe { File::from_raw_fd(ack_w.as_raw_fd()) };
        std::mem::forget(ack_w);
        ack_file
            .write_all(&[1u8])
            .map_err(|err| BoxletError::Runtime {
                subsystem: "init",
                message: format!("failed to send cgroup ack to PID 1: {err}"),
            })?;
        drop(ack_file);

        // Wait for PID 1 READY signal with bounded handshake timeout.
        let _ = read_exact_with_timeout(&ready_r, 1, HANDSHAKE_TIMEOUT)?;

        rollback.disarm();
        Ok((created_state, ()))
    }
}

fn set_child_subreaper() -> Result<()> {
    // SAFETY: `prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)` takes only integer arguments.
    let rc = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(BoxletError::Runtime {
            subsystem: "init",
            message: format!("prctl(PR_SET_CHILD_SUBREAPER) failed: {err}"),
        });
    }
    Ok(())
}

fn clear_cloexec(fd: &OwnedFd) -> Result<()> {
    fcntl(fd.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::empty())).map_err(|err| {
        BoxletError::Runtime {
            subsystem: "init",
            message: format!("failed to clear FD_CLOEXEC: {err}"),
        }
    })?;
    Ok(())
}

fn read_exact_with_timeout(fd: &OwnedFd, len: usize, timeout: Duration) -> Result<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let mut out = vec![0u8; len];
    let mut read_so_far = 0;

    while read_so_far < len {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(BoxletError::Runtime {
                subsystem: "init",
                message: format!(
                    "timed out after {timeout:?} waiting for container init handshake"
                ),
            });
        }
        let timeout_ms = u16::try_from(remaining.as_millis()).unwrap_or(u16::MAX);
        let mut fds = [PollFd::new(fd.as_fd_borrowed(), PollFlags::POLLIN)];
        let ready =
            poll(&mut fds, PollTimeout::from(timeout_ms)).map_err(|err| BoxletError::Runtime {
                subsystem: "init",
                message: format!("poll() during init handshake failed: {err}"),
            })?;
        if ready == 0 {
            continue;
        }
        // SAFETY: Valid owned file descriptor reading into valid buffer slice.
        let n = unsafe {
            libc::read(
                fd.as_raw_fd(),
                out[read_so_far..].as_mut_ptr().cast(),
                len - read_so_far,
            )
        };
        if n <= 0 {
            return Err(BoxletError::Runtime {
                subsystem: "init",
                message: "container init process closed handshake pipe unexpectedly".to_string(),
            });
        }
        read_so_far += n as usize;
    }

    Ok(out)
}

trait BorrowFdExt {
    fn as_fd_borrowed(&self) -> std::os::fd::BorrowedFd<'_>;
}

impl BorrowFdExt for OwnedFd {
    fn as_fd_borrowed(&self) -> std::os::fd::BorrowedFd<'_> {
        std::os::fd::AsFd::as_fd(self)
    }
}

fn spawn_bounded_reader(fd: OwnedFd, max_bytes: usize) -> thread::JoinHandle<(Vec<u8>, bool)> {
    thread::spawn(move || {
        let mut file = File::from(fd);
        let mut buf = BoundedBuffer::new(max_bytes);
        let mut chunk = [0u8; 4096];
        loop {
            match file.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.push(&chunk[..n]),
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        buf.into_parts()
    })
}

fn wait_with_timeout<F>(
    pid: Pid,
    timeout: Option<Duration>,
    on_timeout: F,
) -> (Option<WaitStatus>, bool)
where
    F: FnOnce(),
{
    let start = Instant::now();
    let mut timed_out = false;
    let mut on_timeout = Some(on_timeout);

    loop {
        match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => {
                if let Some(limit) = timeout {
                    if !timed_out && start.elapsed() >= limit {
                        timed_out = true;
                        if let Some(cb) = on_timeout.take() {
                            cb();
                        }
                    }
                }
                thread::sleep(Duration::from_millis(5));
            }
            Ok(status) => return (Some(status), timed_out),
            Err(_) => return (None, timed_out),
        }
    }
}

fn extract_oci_limits(spec: &Spec) -> ResourceLimits {
    let oci_res = spec.linux().as_ref().and_then(|l| l.resources().as_ref());
    let memory_bytes = oci_res
        .and_then(|r| r.memory().as_ref())
        .and_then(|m| m.limit())
        .and_then(|v| u64::try_from(v).ok());
    let cpu_period_usec = oci_res
        .and_then(|r| r.cpu().as_ref())
        .and_then(|c| c.period())
        .unwrap_or(crate::policy::DEFAULT_CPU_PERIOD_USEC);
    let cpu_quota_usec = oci_res
        .and_then(|r| r.cpu().as_ref())
        .and_then(|c| c.quota())
        .and_then(|q| u64::try_from(q).ok());
    let pids_limit = oci_res.and_then(|r| r.pids().as_ref()).map(|p| p.limit());

    ResourceLimits {
        memory_bytes,
        cpu_quota_usec,
        cpu_period_usec,
        pids_limit,
    }
}
