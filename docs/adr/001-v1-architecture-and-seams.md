# ADR-001: Boxlet V1 Architecture, Runtime Seams, and Linux Isolation Contracts

- **Status:** Accepted
- **Owner:** Justin Mafie
- **Date:** 2026-11-24
- **Design Doc:** [docs/designs/boxlet-v1-oci-runtime.md](../designs/boxlet-v1-oci-runtime.md)

## Context

Boxlet aims to become an embeddable, programmable, policy-controlled execution engine in Rust for autonomous AI software engineers and developer infrastructure, with future milestones adding copy-on-write filesystem snapshotting, checkpointing, 3-way sandbox branching, and stronger isolation backends (such as Firecracker or `libkrun`).

For V1, we need the smallest real, secure, measurable Linux OCI container runtime and shared Rust crate that:
1. Implements the OCI runtime lifecycle (`create`, `start`, `state`, `kill`, `delete`) plus a `boxlet run` developer wrapper on top of a single Rust `Engine`.
2. Builds cleanly on a fresh Linux 5.15+ machine with `cargo` alone (zero C library header prerequisites) and produces static musl release binaries.
3. Enforces Linux namespaces, `pivot_root`, dropped capabilities, `PR_SET_NO_NEW_PRIVS`, cgroup v2 resource limits (`memory`, `cpu`, `pids`), and an explicit fail-closed seccomp BPF profile.
4. Preserves clean architectural seams so V2 overlayfs snapshotting and V3 microVM/`youki` backends can plug in without rewriting callers.

## Decision

### 1. Single-Crate Modular Layout (`~18` Files)
Boxlet V1 ships as a single Rust crate (`boxlet` library + `boxlet` CLI binary) organized by subsystem so each `unsafe` Linux kernel boundary stays small, readable, and independently auditable:
- Portable public surface: `src/policy.rs`, `src/result.rs` (or combined with `policy.rs`), `src/traits.rs`, `src/error.rs`, `src/engine.rs`, `src/oci/{mod.rs, state.rs}`.
- Linux-only internals (`#[cfg(target_os = "linux")]`, `pub(crate)`): `src/linux/{mod.rs, namespaces.rs, rootfs.rs, cgroup_v2.rs, caps.rs, seccomp.rs, init.rs}`.
- Thin CLI binary: `src/main.rs` (`clap` exposing `--root`, `--cgroup-parent`, `create`, `start`, `state`, `kill`, `delete`, `run`, and hidden internal `__init`).

All production paths prohibit `.unwrap()` and `.expect()` (`AGENTS.md`), routing errors through a single typed `BoxletError` enum (`thiserror`).

### 2. One Deep `RuntimeBackend` Trait on `Engine`
`Engine` interacts with a single deep `RuntimeBackend` trait (`create`, `start`, `state`, `kill`, `delete`, `run`), rather than orchestrating separate peer traits for rootfs, cgroups, and namespaces.
- `LinuxBackend` owns Linux-specific setup and teardown ordering internally, composing `RootfsProvider` (V1: bind-mount + `pivot_root`; V2: overlayfs snapshots/diffs) and `CgroupV2` as internal pluggable strategies.
- Future backends (`youki` or Firecracker/`libkrun` microVMs) implement `RuntimeBackend` cleanly without faking host-side `pivot_root` or container-process cgroup directories.

### 3. Precedence & Merge Semantics (`create` vs `run`)
- **`boxlet create` / `Engine::create`:** Consumes the OCI bundle's `config.json` verbatim with zero opinionated defaults injected, preserving strict `oci-runtime-tools` compatibility.
- **`boxlet run` / `Engine::run(bundle, policy)`:** Loads `config.json` and overlays every explicitly specified `ExecutionPolicy` field (`memory`, `cpus`, `pids`, `network`, `capabilities`, `seccomp`, `timeout`, `max_output_bytes`). Any field omitted from both receives Boxlet's safe V1 default (`network = none`, `no_new_privs = true`, default-deny seccomp allowlist, `max_output_bytes = 1 MiB` per stream).
- **Network modes:** V1 supports `none` (isolated `CLONE_NEWNET` with loopback `lo` only) and `host` (shared host netns). Bridged, `veth`, and CNI networking are excluded; any unsupported mode fails closed with `BoxletError::UnsupportedNetworkMode`.

### 4. Self-Re-Exec `boxlet __init` Handshake & Pre-`execve` Ordering
To avoid Rust multi-threaded `fork()` async-signal-safety hazards while implementing OCI `create`/`start` separation:
1. Parent creates the container state dir (`<root>/<id>`, default `/run/boxlet/<id>`, guarded by per-container `flock`) and cgroup v2 leaf (`<cgroup-parent>/<id>`, default `/sys/fs/cgroup/boxlet.slice/<id>`), spawns `boxlet __init` with a sync pipe (`O_CLOEXEC`) and start FIFO path, and attaches an RAII rollback guard.
2. Intermediate `boxlet __init` calls `unshare(CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | [CLONE_NEWNET])`, sets `PR_SET_PDEATHSIG(SIGKILL)`, and forks the real **container PID 1** (since `unshare(CLONE_NEWPID)` only places the first child into the new PID namespace).
3. Container PID 1 reports its host-namespace PID back to the parent over the sync pipe, waits for the parent to place it into the cgroup and write atomic `state.json` (`Creating -> Created`), then executes the strict pre-`execve` sequence:
   - Mount `/proc`, minimal `/dev` nodes, masked/readonly paths, and `pivot_root` into the rootfs.
   - Wait on the start FIFO until `boxlet start` signals readiness (`Created -> Running`).
   - Drop Linux capabilities via `caps` and set `PR_SET_NO_NEW_PRIVS`.
   - Close all inherited non-stdio file descriptors (sync pipe/FIFO marked `O_CLOEXEC`).
   - Load compiled `seccompiler::BpfProgram` as the **very last step before `execve`**.
   - Call `execve` for the workload entrypoint.
4. Any handshake error, EOF, or bounded handshake timeout triggers RAII rollback removing both the cgroup directory and `<root>/<id>` state directory.

### 5. Deterministic 7-Step `boxlet run` Teardown Sequence
To prevent hung runs from backgrounded grandchildren holding stdout/stderr open and to guarantee accurate OOM/CPU stats:
1. Wait for container PID 1 exit or `ExecutionPolicy::timeout` deadline.
2. If timeout fired: set `timed_out = true` and write `1` to `cgroup.kill`.
3. Reap PID 1 via `waitpid` and record `exit_code` / `termination_signal` (e.g. `SIGSYS`).
4. Write `1` to `cgroup.kill` unconditionally to terminate any lingering grandchildren holding stdout/stderr FDs open.
5. Join bounded stdout/stderr reader threads (capped at `max_output_bytes`, setting `stdout_truncated` / `stderr_truncated`).
6. Read cgroup v2 `memory.events` (`oom_kill`), `memory.peak`, and `cpu.stat` **before** removing the cgroup.
7. Remove the leaf cgroup directory (`rmdir`) and clean up the container state directory, recording `cleanup_status`.

### 6. Pure-Rust Seccomp Pipeline & Supported OCI Operator Subset
Boxlet V1 avoids C `libseccomp-dev` FFI by combining two pure-Rust crates:
- **`syscalls`:** Resolves OCI `linux.seccomp` syscall string names to architecture-specific numeric syscall IDs for `x86_64` and `aarch64`.
- **`seccompiler` (AWS Firecracker):** Compiles numeric syscall rules into Linux cBPF bytecode (`BpfProgram`).

**Locked V1 OCI seccomp contract (resolving Design Doc Open Question #1):**
- **Supported argument comparison operators:** `SCMP_CMP_EQ`, `SCMP_CMP_NE`, `SCMP_CMP_LT`, `SCMP_CMP_LE`, `SCMP_CMP_GT`, `SCMP_CMP_GE`, and `SCMP_CMP_MASKED_EQ` (mapping 1-to-1 to `seccompiler::SeccompCmpOp` and covering the standard `oci-runtime-tools` validation suite).
- **Supported OCI actions:** `SCMP_ACT_KILL`, `SCMP_ACT_KILL_PROCESS`, `SCMP_ACT_KILL_THREAD`, `SCMP_ACT_TRAP`, `SCMP_ACT_ERRNO` (with custom errno value), `SCMP_ACT_TRACE`, `SCMP_ACT_LOG`, and `SCMP_ACT_ALLOW`.
- **Fail-closed rule:** Any unknown syscall name for the target architecture, unsupported OCI seccomp flag (e.g. `SECCOMP_FILTER_FLAG_NEW_LISTENER` / notify FD), unsupported action, or unsupported argument operator returns `Err(BoxletError::UnsupportedSeccompRule)` and aborts container creation before `execve`.

### 7. Linux 5.15+ Unified Cgroup v2 Baseline
V1 requires Linux 5.15+ with unified cgroup v2 (guaranteed `cgroup.kill` support, introduced in Linux 5.14) and root privileges on a dedicated Linux host/VM. Container cgroups live under a dedicated parent slice (default `/sys/fs/cgroup/boxlet.slice`, overridable via `--cgroup-parent`) with `+memory +cpu +pids` enabled in `cgroup.subtree_control` outside the host runner's active process cgroup to satisfy cgroup v2's no-internal-processes rule.

## Alternatives Considered

1. **Single crate with C `libseccomp` FFI (Approach A):** Smaller seccomp glue code, but requires `libseccomp-dev` headers on every Linux build host and complicates static musl release binaries. Rejected in favor of pure-Rust `syscalls` + `seccompiler`.
2. **Four-crate Cargo workspace in V1 (Approach B):** Enforces compile-time separation between portable SDK types and Linux syscalls immediately, but adds Cargo workspace plumbing before the first container boots. Deferred to V2 when a second backend crate is added.
3. **Three peer traits (`RootfsProvider`, `ResourceController`, `IsolationBackend`) on `Engine`:** Leaked Linux setup/teardown sequencing into `Engine` and broke future Firecracker/`libkrun` compatibility. Replaced by a single deep `RuntimeBackend` trait (Eng Review R1 / D2).
4. **Linux 5.4-5.14 PID-drain fallback loop:** Added racy `cgroup.procs` polling complexity for older kernels not used by modern Ubuntu/Debian CI runners. Rejected in favor of Linux 5.15+ `cgroup.kill`.

## Consequences & Failure Modes

- **Positive:** Fresh Linux 5.15+ machines build Boxlet with `cargo` alone; static `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` releases are clean; `Engine` is decoupled from Linux-only primitives; unsafe code is confined to `pub(crate)` modules in `src/linux/`.
- **Trade-off:** V1 does not run containers natively on macOS (macOS development uses Linux Docker/VM or CI for kernel tests, while portable policy/OCI unit tests run anywhere).
- **Failure modes & mitigations:**
  - *Mid-handshake crash in `boxlet create`:* `PR_SET_PDEATHSIG(SIGKILL)` + bounded sync pipe timeout + RAII rollback guarantees zero leaked cgroups or state dirs.
  - *OOM kill during `boxlet run`:* 7-step teardown reads `memory.events` (`oom_kill`) before `rmdir`, surfacing `oom_killed = true` reliably.
  - *Background grandchild holding stdout open:* Unconditional `cgroup.kill` after `waitpid` forces immediate pipe EOF.
  - *`SCMP_ACT_ERRNO` observability limit:* Kernel `EPERM` denials are observed in-guest by the workload (not out-of-band by the parent runtime); `SCMP_ACT_KILL_PROCESS` surfaces `termination_signal = Some(SIGSYS)` in `ExecutionResult`.
  - *Shared-kernel boundary:* Linux containers share the host kernel; documented explicitly in [docs/THREAT_MODEL.md](../THREAT_MODEL.md) until a microVM `RuntimeBackend` is added.
