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

## 4. Enterprise V6 Hardening Invariants (Audit Hash Chaining & Rootless User Namespaces)

1. **Tamper-Evident Audit Hash Chaining (`src/audit.rs`):**
   - Every [`AuditRecord`] written by [`JsonlAuditLogger`] acquires an exclusive advisory file lock (`File::lock()`), reads the tail record, assigns a monotonically increasing sequence number (`seq`), records the predecessor's digest (`prev_hash_fnv1a64`), and computes its own deterministic 64-bit FNV-1a digest (`record_hash_fnv1a64`) over `(seq, prev_hash_fnv1a64, timestamp_unix_ms, canonical_event_json)`.
   - `JsonlAuditLogger::summarize()` (`boxlet audit --file <PATH> [--json|--prometheus]`) recomputes the hash chain from `seq = 1` (`prev_hash_fnv1a64 = 0`) through the final entry and sets `hash_chain_valid = false` if any record is modified, deleted, reordered, or spliced.
2. **Rootless User Namespace Isolation (`CLONE_NEWUSER`, `uid_map`, `gid_map`, `setgroups`):**
   - Bundles scaffolded with `boxlet init-bundle --rootless` (`BundleBuilder::with_rootless(true)`) include the `user` namespace (`CLONE_NEWUSER`) and map container UID/GID `0` to the unprivileged calling host UID/GID (`uidMappings` / `gidMappings`).
   - Before writing `/proc/self/gid_map`, the container init process unconditionally writes `"deny"` to `/proc/self/setgroups` to prevent `setgroups(2)` privilege-escalation attacks (CVE-2014-8989), then writes `uid_map` and `gid_map` before `pivot_root` and `execve`.

---

## 5. V7 Storage & Block I/O Isolation Invariants (`io.max` & OCI Image Layout Whiteouts)

1. **Fail-Closed Cgroup v2 `io.max` Block I/O Throttling (`src/policy.rs`, `src/linux/cgroup.rs`):**
   - `IoMaxRule::parse()` validates major:minor device numbers (`major > 0`) and requires at least one positive bandwidth (`rbps`, `wbps`) or IOPS (`riops`, `wiops`) limit, rejecting zero limits (`rbps=0`), unknown keys, or empty rule strings with `BoxletError::InvalidPolicy` before any container process is spawned.
   - On Linux, `CgroupV2::apply_limits()` enables `+io` in parent `cgroup.subtree_control` and writes each formatted `IoMaxRule::to_cgroup_line()` (`<MAJ>:<MIN> rbps=... wbps=... riops=... wiops=...`) to the container's `io.max` control file to prevent noisy-neighbor disk bandwidth or IOPS exhaustion ([ADR-010](adr/010-cgroup-io-max-and-oci-image-layout.md)).
2. **Fail-Closed Multi-Layer OCI Image Layout Unpacking & Whiteout Sanitization (`src/image.rs`):**
   - `unpack_oci_image_layout()` verifies `oci-layout` (`imageLayoutVersion == "1.0.0"`), validates every layer blob's 16-hex-character `fnv1a64` digest against its actual content hash before extraction, and rejects any `.wh.<target>` whiteout marker containing `/`, `..`, or empty target names so malicious layers cannot delete files outside their parent directory.

---

## 6. V8 Resource Exhaustion & Core-Dump Leak Prevention (`setrlimit(2)` & PSI Telemetry)

1. **Unconditional Core-Dump Suppression (`RLIMIT_CORE = 0`):**
   - Prior to dropping capabilities and invoking `execve`, the container init stage unconditionally sets `RLIMIT_CORE` (`soft = 0, hard = 0`) via `setrlimit(2)` unless explicitly overridden by a trusted OCI `process.rlimits` entry. This prevents crashing container workloads from writing memory dumps containing sensitive secrets or tokens to the container rootfs or host core-pattern handlers ([ADR-011](adr/011-psi-telemetry-rlimits-and-benchmark-suite.md)).
2. **File-Descriptor Exhaustion Defense (`RLIMIT_NOFILE` / `--nofile <N>`):**
   - `ExecutionPolicy::nofile_limit` (`boxlet run --nofile <N>` / `boxlet branch-run --nofile <N>`) and OCI `process.rlimits` (`RLIMIT_NOFILE`) cap the maximum number of open file descriptors per process inside the sandbox via `setrlimit(2)`, preventing an untrusted workload from exhausting the host kernel file table. Setting `--nofile 0` or `soft > hard` fails closed with `BoxletError::InvalidPolicy` before spawning.
3. **Cgroup v2 Pressure Stall Information (`*.pressure` PSI) Contention Telemetry:**
   - Before cgroup directory deletion, `CgroupV2::read_usage()` harvests `cpu.pressure`, `memory.pressure`, and `io.pressure` (`PsiMetrics`) and aggregates stall microseconds into tamper-evident audit summaries and Prometheus metrics (`boxlet_psi_*_microseconds_total`), enabling early detection of noisy-neighbor resource contention or DoS thrashing.

---

## 7. Residual Risks & Explicit Non-Goals (V1)

1. **Shared host kernel exploits (residual risk):** A Linux kernel vulnerability triggered by an allowed syscall can break out of namespaces and seccomp. V1 accepts this boundary for single-host dev/test environments; hostile multi-tenant isolation is deferred to a future microVM `RuntimeBackend` (Firecracker / `libkrun`).
2. **Root execution requirement (non-goal in V1):** V1 requires `root` on a dedicated Linux 5.15+ host/VM. Rootless user-namespace containers are explicitly excluded from V1 to avoid premature complexity and false security claims.
3. **Host-mode networking (`--network host`):** When a caller explicitly opts into `--network host`, the container shares the host network namespace and can reach local services and cloud metadata endpoints. Callers must only enable `host` networking for trusted workloads.
4. **Disk / inode quotas:** V1 does not enforce filesystem size quotas or overlayfs upperdir caps; deferred to V2 `RootfsProvider` work.
5. **Supply-chain / secrets scanning:** CI enforces `cargo audit` on Rust dependencies and prohibits committing `.env` files, API keys, or credentials (`AGENTS.md`).
