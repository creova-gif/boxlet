//! Pure-Rust OCI seccomp translator using `syscalls` + Firecracker's `seccompiler`.
//!
//! Zero C `libseccomp` dependencies. Fails closed (`BoxletError::UnsupportedSeccompRule`)
//! on any unknown syscall name, unsupported OCI operator, or unsupported flag.

use std::collections::BTreeMap;
use std::str::FromStr;

use oci_spec::runtime::{
    LinuxSeccomp, LinuxSeccompAction, LinuxSeccompBuilder, LinuxSeccompOperator,
    LinuxSyscallBuilder,
};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};
use syscalls::Sysno;

use crate::error::{BoxletError, Result};

/// Compiles an OCI [`LinuxSeccomp`] profile into a Linux cBPF [`BpfProgram`] for the host arch.
pub(crate) fn compile_oci_seccomp(profile: &LinuxSeccomp) -> Result<BpfProgram> {
    if let Some(flags) = profile.flags() {
        if !flags.is_empty() {
            return Err(BoxletError::UnsupportedSeccompRule {
                reason: format!("OCI seccomp flags are not supported in V1: {flags:?}"),
            });
        }
    }

    if profile.listener_path().is_some() || profile.listener_metadata().is_some() {
        return Err(BoxletError::UnsupportedSeccompRule {
            reason: "seccomp user notification listeners are not supported in V1".to_string(),
        });
    }

    let arch = current_target_arch()?;
    let default_action = map_action(profile.default_action(), profile.default_errno_ret())?;

    let mut rules_by_action: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    let mut match_action: Option<SeccompAction> = None;

    if let Some(syscalls) = profile.syscalls() {
        for entry in syscalls {
            let entry_action = map_action(entry.action(), entry.errno_ret())?;
            if entry_action == default_action {
                continue;
            }
            match &match_action {
                None => match_action = Some(entry_action),
                Some(existing) if existing == &entry_action => {}
                Some(existing) => {
                    return Err(BoxletError::UnsupportedSeccompRule {
                        reason: format!(
                            "mixed non-default seccomp actions ({existing:?} vs {entry_action:?}) are not supported in V1 single-filter mode"
                        ),
                    });
                }
            }

            let mut conditions = Vec::new();
            if let Some(args) = entry.args() {
                for arg in args {
                    let arg_index = u8::try_from(arg.index()).map_err(|_| {
                        BoxletError::UnsupportedSeccompRule {
                            reason: format!("seccomp arg index {} exceeds u8", arg.index()),
                        }
                    })?;
                    let op = map_operator(arg.op(), arg.value_two())?;
                    let cond =
                        SeccompCondition::new(arg_index, SeccompCmpArgLen::Qword, op, arg.value())
                            .map_err(|err| BoxletError::UnsupportedSeccompRule {
                                reason: format!("invalid seccomp condition: {err}"),
                            })?;
                    conditions.push(cond);
                }
            }

            if conditions.is_empty() {
                // In seccompiler, an empty Vec<SeccompRule> matches the syscall unconditionally.
                for name in entry.names() {
                    let sysno = resolve_syscall_number(name)?;
                    rules_by_action.entry(sysno).or_default();
                }
            } else {
                let rule = SeccompRule::new(conditions).map_err(|err| {
                    BoxletError::UnsupportedSeccompRule {
                        reason: format!("invalid seccomp rule: {err}"),
                    }
                })?;

                for name in entry.names() {
                    let sysno = resolve_syscall_number(name)?;
                    rules_by_action.entry(sysno).or_default().push(rule.clone());
                }
            }
        }
    }

    let effective_match_action = match_action.unwrap_or(SeccompAction::Allow);
    let filter = SeccompFilter::new(
        rules_by_action,
        default_action,
        effective_match_action,
        arch,
    )
    .map_err(|err| BoxletError::UnsupportedSeccompRule {
        reason: format!("failed to construct seccomp filter: {err}"),
    })?;

    BpfProgram::try_from(filter).map_err(|err| BoxletError::UnsupportedSeccompRule {
        reason: format!("failed to compile seccomp BPF program: {err}"),
    })
}

/// Loads a compiled cBPF filter into the current thread.
///
/// Per ADR-001, this MUST be called as the very last step before `execve`.
pub(crate) fn apply_bpf_filter(program: &BpfProgram) -> Result<()> {
    seccompiler::apply_filter(program).map_err(|err| BoxletError::Runtime {
        subsystem: "seccomp",
        message: format!("failed to load seccomp BPF filter: {err}"),
    })
}

/// Returns Boxlet's V1 default-deny OCI seccomp profile (`SCMP_ACT_ERRNO(EPERM)` default)
/// allowing standard POSIX/container syscalls while blocking `ptrace`, `mount`, `bpf`,
/// `kexec_load`, `unshare`, `setns`, `reboot`, module loading, and `io_uring_setup`.
pub(crate) fn default_deny_profile() -> Result<LinuxSeccomp> {
    // Allowlist of standard syscalls present on Linux x86_64/aarch64; filter to syscalls
    // that exist on the current architecture so aarch64/x86_64 both compile cleanly.
    let candidate_syscalls = [
        "accept",
        "accept4",
        "access",
        "arch_prctl",
        "bind",
        "brk",
        "capget",
        "capset",
        "chdir",
        "chmod",
        "chown",
        "clock_getres",
        "clock_gettime",
        "clock_nanosleep",
        "clone",
        "clone3",
        "close",
        "close_range",
        "connect",
        "dup",
        "dup2",
        "dup3",
        "epoll_create",
        "epoll_create1",
        "epoll_ctl",
        "epoll_pwait",
        "epoll_wait",
        "eventfd",
        "eventfd2",
        "execve",
        "execveat",
        "exit",
        "exit_group",
        "faccessat",
        "faccessat2",
        "fadvise64",
        "fallocate",
        "fchdir",
        "fchmod",
        "fchmodat",
        "fchown",
        "fchownat",
        "fcntl",
        "fdatasync",
        "fgetxattr",
        "flistxattr",
        "flock",
        "fork",
        "fstat",
        "fstatfs",
        "fsync",
        "ftruncate",
        "futex",
        "getcwd",
        "getdents",
        "getdents64",
        "getegid",
        "geteuid",
        "getgid",
        "getgroups",
        "getpeername",
        "getpgid",
        "getpgrp",
        "getpid",
        "getppid",
        "getpriority",
        "getrandom",
        "getresgid",
        "getresuid",
        "getrlimit",
        "getrusage",
        "getsid",
        "getsockname",
        "getsockopt",
        "gettid",
        "gettimeofday",
        "getuid",
        "ioctl",
        "kill",
        "link",
        "linkat",
        "listen",
        "lseek",
        "lstat",
        "madvise",
        "mkdir",
        "mkdirat",
        "mmap",
        "mprotect",
        "mremap",
        "munmap",
        "nanosleep",
        "newfstatat",
        "open",
        "openat",
        "openat2",
        "pause",
        "pipe",
        "pipe2",
        "poll",
        "ppoll",
        "prctl",
        "pread64",
        "prlimit64",
        "pselect6",
        "pwrite64",
        "read",
        "readlink",
        "readlinkat",
        "readv",
        "recvfrom",
        "recvmmsg",
        "recvmsg",
        "rename",
        "renameat",
        "renameat2",
        "restart_syscall",
        "rmdir",
        "rseq",
        "rt_sigaction",
        "rt_sigpending",
        "rt_sigprocmask",
        "rt_sigqueueinfo",
        "rt_sigreturn",
        "rt_sigsuspend",
        "rt_sigtimedwait",
        "sched_getaffinity",
        "sched_yield",
        "select",
        "sendfile",
        "sendmmsg",
        "sendmsg",
        "sendto",
        "set_robust_list",
        "set_tid_address",
        "setgid",
        "setgroups",
        "setpgid",
        "setresgid",
        "setresuid",
        "setsid",
        "setsockopt",
        "setuid",
        "shutdown",
        "sigaltstack",
        "socket",
        "socketpair",
        "stat",
        "statfs",
        "statx",
        "symlink",
        "symlinkat",
        "sysinfo",
        "tgkill",
        "time",
        "tkill",
        "truncate",
        "umask",
        "uname",
        "unlink",
        "unlinkat",
        "utimensat",
        "vfork",
        "wait4",
        "waitid",
        "write",
        "writev",
    ];

    let arch_names: Vec<String> = candidate_syscalls
        .iter()
        .filter(|name| Sysno::from_str(name).is_ok())
        .map(|name| (*name).to_string())
        .collect();

    let allow_rule = LinuxSyscallBuilder::default()
        .names(arch_names)
        .action(LinuxSeccompAction::ScmpActAllow)
        .build()
        .map_err(|err| BoxletError::UnsupportedSeccompRule {
            reason: format!("failed to build default allow rule: {err}"),
        })?;

    LinuxSeccompBuilder::default()
        .default_action(LinuxSeccompAction::ScmpActErrno)
        .default_errno_ret(libc::EPERM as u32)
        .syscalls(vec![allow_rule])
        .build()
        .map_err(|err| BoxletError::UnsupportedSeccompRule {
            reason: format!("failed to build default seccomp profile: {err}"),
        })
}

fn current_target_arch() -> Result<TargetArch> {
    #[cfg(target_arch = "x86_64")]
    {
        Ok(TargetArch::x86_64)
    }
    #[cfg(target_arch = "aarch64")]
    {
        Ok(TargetArch::aarch64)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Err(BoxletError::UnsupportedSeccompRule {
            reason: "seccomp BPF compilation only supports x86_64 and aarch64 in V1".to_string(),
        })
    }
}

fn resolve_syscall_number(name: &str) -> Result<i64> {
    let sysno = Sysno::from_str(name).map_err(|_| BoxletError::UnsupportedSeccompRule {
        reason: format!("unknown syscall '{name}' for current target architecture"),
    })?;
    Ok(sysno.id() as i64)
}

fn map_action(action: LinuxSeccompAction, errno_ret: Option<u32>) -> Result<SeccompAction> {
    match action {
        LinuxSeccompAction::ScmpActKill | LinuxSeccompAction::ScmpActKillThread => {
            Ok(SeccompAction::KillThread)
        }
        LinuxSeccompAction::ScmpActKillProcess => Ok(SeccompAction::KillProcess),
        LinuxSeccompAction::ScmpActTrap => Ok(SeccompAction::Trap),
        LinuxSeccompAction::ScmpActErrno => {
            let code = errno_ret.unwrap_or(libc::EPERM as u32);
            Ok(SeccompAction::Errno(code))
        }
        LinuxSeccompAction::ScmpActTrace => Ok(SeccompAction::Trace(errno_ret.unwrap_or(0))),
        LinuxSeccompAction::ScmpActLog => Ok(SeccompAction::Log),
        LinuxSeccompAction::ScmpActAllow => Ok(SeccompAction::Allow),
        other => Err(BoxletError::UnsupportedSeccompRule {
            reason: format!("unsupported OCI seccomp action: {other:?}"),
        }),
    }
}

fn map_operator(op: LinuxSeccompOperator, value_two: Option<u64>) -> Result<SeccompCmpOp> {
    match op {
        LinuxSeccompOperator::ScmpCmpNe => Ok(SeccompCmpOp::Ne),
        LinuxSeccompOperator::ScmpCmpLt => Ok(SeccompCmpOp::Lt),
        LinuxSeccompOperator::ScmpCmpLe => Ok(SeccompCmpOp::Le),
        LinuxSeccompOperator::ScmpCmpEq => Ok(SeccompCmpOp::Eq),
        LinuxSeccompOperator::ScmpCmpGe => Ok(SeccompCmpOp::Ge),
        LinuxSeccompOperator::ScmpCmpGt => Ok(SeccompCmpOp::Gt),
        LinuxSeccompOperator::ScmpCmpMaskedEq => {
            let mask = value_two.ok_or_else(|| BoxletError::UnsupportedSeccompRule {
                reason: "SCMP_CMP_MASKED_EQ requires valueTwo mask".to_string(),
            })?;
            Ok(SeccompCmpOp::MaskedEq(mask))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oci_spec::runtime::LinuxSeccompArgBuilder;

    #[test]
    fn default_deny_profile_compiles_to_nonempty_bpf() -> Result<()> {
        let profile = default_deny_profile()?;
        let bpf = compile_oci_seccomp(&profile)?;
        assert!(!bpf.is_empty());
        Ok(())
    }

    #[test]
    fn unknown_syscall_fails_closed() -> Result<()> {
        let bad_rule = LinuxSyscallBuilder::default()
            .names(vec!["not_a_real_syscall_xyz".to_string()])
            .action(LinuxSeccompAction::ScmpActAllow)
            .build()
            .map_err(|e| BoxletError::UnsupportedSeccompRule {
                reason: e.to_string(),
            })?;
        let profile = LinuxSeccompBuilder::default()
            .default_action(LinuxSeccompAction::ScmpActErrno)
            .syscalls(vec![bad_rule])
            .build()
            .map_err(|e| BoxletError::UnsupportedSeccompRule {
                reason: e.to_string(),
            })?;

        let err = compile_oci_seccomp(&profile).unwrap_err();
        assert!(matches!(err, BoxletError::UnsupportedSeccompRule { .. }));
        Ok(())
    }

    #[test]
    fn arg_comparison_operators_compile_to_bpf() -> Result<()> {
        let arg = LinuxSeccompArgBuilder::default()
            .index(0usize)
            .value(1u64)
            .op(LinuxSeccompOperator::ScmpCmpEq)
            .build()
            .map_err(|e| BoxletError::UnsupportedSeccompRule {
                reason: e.to_string(),
            })?;
        let rule = LinuxSyscallBuilder::default()
            .names(vec!["write".to_string()])
            .action(LinuxSeccompAction::ScmpActAllow)
            .args(vec![arg])
            .build()
            .map_err(|e| BoxletError::UnsupportedSeccompRule {
                reason: e.to_string(),
            })?;
        let profile = LinuxSeccompBuilder::default()
            .default_action(LinuxSeccompAction::ScmpActKillProcess)
            .syscalls(vec![rule])
            .build()
            .map_err(|e| BoxletError::UnsupportedSeccompRule {
                reason: e.to_string(),
            })?;

        let bpf = compile_oci_seccomp(&profile)?;
        assert!(!bpf.is_empty());
        Ok(())
    }
}
