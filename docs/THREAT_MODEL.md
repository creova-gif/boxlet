# Boxlet V1 Threat Model

**Scope:** Single-host, root-required, Linux 5.15+ OCI container runtime and embeddable Rust execution library (`boxlet` v0.1.x / V1).
**Architecture Reference:** [docs/adr/001-v1-architecture-and-seams.md](adr/001-v1-architecture-and-seams.md)

> **Security Posture Warning (V1):** Boxlet V1 isolates workloads using Linux kernel primitives (namespaces, `pivot_root`, cgroup v2, capabilities, `PR_SET_NO_NEW_PRIVS`, and seccomp cBPF). All containers **share the host Linux kernel**. V1 is designed for dedicated Linux test/development hosts and controlled engineering verification, **not** for executing arbitrary hostile multi-tenant workloads in production. Production hostile multi-tenant isolation requires a hardware-virtualized `RuntimeBackend` (e.g. Firecracker or `libkrun`), which is planned for a future milestone.

---

## 1. Trust Boundaries

```text
  Trusted Host (Linux 5.15+, root)
  +-------------------------------------------------------------------+
  |  Caller (CLI user or host Rust application)                       |
  |     |                                                             |
  |     v                                                             |
  |  Boxlet Engine + LinuxBackend (root)                              |
  |     - State Store: /run/boxlet/<id>/state.json (flock-guarded)    |
  |     - Cgroup v2:   /sys/fs/cgroup/boxlet.slice/<id>               |
  |     - Bounded stdout/stderr readers (default 1 MiB/stream)        |
  +===================================================================+
        ||  TRUST BOUNDARY:                                      ||
        ||  - PID / Mount / UTS / IPC / Net (none) namespaces    ||
        ||  - pivot_root + masked/readonly /proc & /sys paths    ||
        ||  - Dropped capabilities + PR_SET_NO_NEW_PRIVS         ||
        ||  - O_CLOEXEC / closed parent FDs                      ||
        ||  - Pure-Rust seccomp cBPF filter (loaded last)        ||
        ||  - Cgroup v2 memory.max / cpu.max / pids.max          ||
  +===================================================================+
  |  Untrusted Workload (Container PID 1 + child processes)           |
  |     - Runs inside isolated rootfs bundle                          |
  |     - Cannot escalate privileges or exceed cgroup budgets         |
  +-------------------------------------------------------------------+
```

---

## 2. Assets to Protect

1. **Host filesystem & secrets:** Files outside the container's OCI bundle rootfs, including host `/etc`, `/root`, credentials, and `/run/boxlet` state directories of other containers.
2. **Host process table & IPC:** Host daemons, sibling containers, and the parent `boxlet` process.
3. **Host compute availability:** Host RAM, CPU time, PID table, and open file descriptors.
4. **Host `boxlet` process stability:** Protection against host OOM or indefinite hangs triggered by misbehaving container output or backgrounded child processes.
5. **Policy integrity:** Guarantee that an unsupported security rule (seccomp syscall/operator or network mode) never silently downgrades to a weaker configuration.

---

## 3. Threats & V1 Mitigations

| Threat | Attack Vector | V1 Mitigation | Verification |
|---|---|---|---|
| **Filesystem escape** | Accessing host paths or `..` traversal out of bundle rootfs | Dedicated mount namespace (`CLONE_NEWNS`) with `MS_PRIVATE` propagation, `pivot_root` + unmount old root, masked/readonly sensitive `/proc` and `/sys` paths | `oci-runtime-tools` rootfs/mount tests |
| **Privilege escalation** | Setuid binaries, retaining `CAP_SYS_ADMIN` / `CAP_NET_RAW`, loading kernel modules | Drop Linux capabilities to an explicit allowlist via `caps`; enforce `PR_SET_NO_NEW_PRIVS` before `execve` | Container `/proc/self/status` assertion (`NoNewPrivs: 1`, `CapEff`/`CapBnd` check) |
| **Dangerous syscalls** | Calling `ptrace`, `mount`, `bpf`, `kexec_load`, `unshare`, etc. | Pure-Rust `syscalls` + `seccompiler` cBPF filter loaded as the final step before `execve`; fail closed (`BoxletError::UnsupportedSeccompRule`) on unknown syscalls or unsupported operators | Linux regression tests verifying in-guest `EPERM` (`SCMP_ACT_ERRNO`) and `SIGSYS` (`SCMP_ACT_KILL_PROCESS`) |
| **Silent policy downgrade** | Passing an unknown network mode or unsupported seccomp rule expecting enforcement | Fail-closed validation before spawning (`BoxletError::UnsupportedNetworkMode`, `BoxletError::UnsupportedSeccompRule`) | Deterministic unit tests |
| **Host memory / CPU / PID exhaustion (DoS)** | Allocation bomb, CPU spin loop, or fork bomb inside container | Unified cgroup v2 (`memory.max`, `cpu.max`, `pids.max`) under `/sys/fs/cgroup/boxlet.slice/<id>`; `oom_killed` read from `memory.events` before teardown | Linux OOM test (`--memory 128m` -> `oom_killed = true`) |
| **Host OOM via log flood** | Container writes gigabytes to stdout/stderr to exhaust host `boxlet` RAM | Bounded stdout/stderr capture buffers (`max_output_bytes`, default 1 MiB/stream) with `stdout_truncated` / `stderr_truncated` flags | Linux stdout flood regression test |
| **Teardown hang via background grandchild** | Container forks a child holding stdout/stderr open after PID 1 exits | Deterministic 7-step teardown writes `1` to `cgroup.kill` unconditionally after `waitpid` before joining pipe readers | Linux grandchild-pipe regression test |
| **Host FD leak into container** | Sync pipe, start FIFO, or state lock FD left open across `execve` | Mark all internal parent/init FDs `O_CLOEXEC` and explicitly close non-stdio FDs prior to loading seccomp and calling `execve` | Inspection of `/proc/self/fd` inside container in integration test |
| **Orphaned cgroups / state on crash** | `boxlet create` fails or parent dies mid-handshake | `PR_SET_PDEATHSIG(SIGKILL)` on init child, bounded sync pipe timeout, and RAII rollback removing `<cgroup-parent>/<id>` and `<root>/<id>` | Failure-injection test asserting zero leftover cgroups/state dirs |
| **Concurrent state corruption** | Parallel `boxlet start` / `kill` / `delete` on same container ID | Per-container `flock` + atomic write-and-rename of `<root>/<id>/state.json` | Concurrent lifecycle state unit/integration test |
| **Unauthorized network egress** | Workload connects to host LAN, cloud metadata (`169.254.169.254`), or internet | `boxlet run` defaults to `--network none` (`CLONE_NEWNET` with loopback `lo` only, no external routes or interfaces) | Linux network-isolation integration test |

---

## 4. Residual Risks & Explicit Non-Goals (V1)

1. **Shared host kernel exploits (residual risk):** A Linux kernel vulnerability triggered by an allowed syscall can break out of namespaces and seccomp. V1 accepts this boundary for single-host dev/test environments; hostile multi-tenant isolation is deferred to a future microVM `RuntimeBackend` (Firecracker / `libkrun`).
2. **Root execution requirement (non-goal in V1):** V1 requires `root` on a dedicated Linux 5.15+ host/VM. Rootless user-namespace containers are explicitly excluded from V1 to avoid premature complexity and false security claims.
3. **Host-mode networking (`--network host`):** When a caller explicitly opts into `--network host`, the container shares the host network namespace and can reach local services and cloud metadata endpoints. Callers must only enable `host` networking for trusted workloads.
4. **Disk / inode quotas:** V1 does not enforce filesystem size quotas or overlayfs upperdir caps; deferred to V2 `RootfsProvider` work.
5. **Supply-chain / secrets scanning:** CI enforces `cargo audit` on Rust dependencies and prohibits committing `.env` files, API keys, or credentials (`AGENTS.md`).
