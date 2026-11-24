# Boxlet: Minimal OCI-Compatible Container Runtime & Programmable Execution Engine

- **Spec Doc:** [Boxlet: Minimal OCI-Compatible Container Runtime](https://docs.google.com/document/d/1XDaWCxQUGEH9LMqC95nJ4WZy_ut_YOQJ5_yChSJrlvA/edit?usp=drivesdk&ouid=110227624285917376281)
- **Architecture Decision Record:** [docs/adr/001-v1-architecture-and-seams.md](docs/adr/001-v1-architecture-and-seams.md)
- **Threat Model:** [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- **Design Doc:** [docs/designs/boxlet-v1-oci-runtime.md](docs/designs/boxlet-v1-oci-runtime.md)
- **Engineering Standards:** [AGENTS.md](AGENTS.md)

---

## Overview

**Boxlet** is an AI-native, minimal Linux OCI-compatible container runtime and embeddable Rust execution engine designed for autonomous software engineering agents and developer infrastructure.

While general-purpose runtimes (`runc`, `youki`) optimize for full container ecosystem surface area, Boxlet is built around **policy-first programmable execution**:
- **Single Shared Core:** Both the OCI CLI (`create`, `start`, `state`, `kill`, `delete`, `run`) and downstream Rust applications drive the exact same `Engine`, `ExecutionPolicy`, and `ExecutionResult` primitives.
- **Zero-C-Dependency Static Builds:** Compiles OCI `linux.seccomp` profiles directly to Linux cBPF bytecode using pure-Rust [`syscalls`](https://crates.io/crates/syscalls) + AWS Firecracker's [`seccompiler`](https://crates.io/crates/seccompiler) — no `libseccomp-dev` C headers required, enabling clean static `musl` binaries on `x86_64` and `aarch64`.
- **Structured Observability & Bounded Output:** Every `boxlet run` returns a machine-readable `ExecutionResult` containing bounded `stdout`/`stderr` buffers (preventing host OOM on log floods), truncation flags, peak memory, CPU usage (`cpu.stat`), violation telemetry (`oom_killed`, `timed_out`, `termination_signal`), and deterministic cleanup verification.
- **Deterministic 7-Step Teardown:** While the `boxlet run` host process is alive, it unconditionally terminates lingering background grandchildren via Linux 5.15+ `cgroup.kill` after `waitpid` so stdout/stderr pipes never hang and zero orphaned processes or cgroups survive teardown.

---

## Architecture

```text
+-------------------------------------------------------------------------+
|                    Callers: CLI (`boxlet`) / Rust SDK                   |
|          (`create`, `start`, `state`, `kill`, `delete`, `run`)          |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                             `boxlet::Engine`                            |
|   - Policy merge semantics (`create` verbatim vs `run` safe overlay)    |
|   - Structured `ExecutionPolicy` & `ExecutionResult` contracts          |
+------------------------------------+------------------------------------+
                                     |
                                     v  `RuntimeBackend` trait seam
+-------------------------------------------------------------------------+
|                         `LinuxBackend` (Linux 5.15+)                    |
|                                                                         |
|  +-----------------------+  +--------------------+  +----------------+  |
|  |   OCI State Store     |  |     Cgroup v2      |  | RootfsProvider |  |
|  | `/run/boxlet/<id>`    |  | `boxlet.slice/<id>`|  | V1: bind-mount |  |
|  | `flock` + atomic JSON |  | `memory.max`       |  | + `pivot_root` |  |
|  +-----------------------+  | `cpu.max`          |  | `/proc`, `/dev`|  |
|                             | `pids.max`         |  | V2: overlayfs  |  |
|                             | `cgroup.kill`      |  | snapshot/diff  |  |
|                             +--------------------+  +----------------+  |
|                                     |                                   |
|                                     v  Self-re-exec (`boxlet __init`)   |
|  +-------------------------------------------------------------------+  |
|  |               Container Init Handshake & Pre-`execve`             |  |
|  |  1. `unshare(CLONE_NEWPID | NEWNS | NEWUTS | NEWIPC | [NEWNET])`  |  |
|  |  2. `PR_SET_PDEATHSIG(SIGKILL)` + fork real Container PID 1       |  |
|  |  3. Sync pipe PID report -> Cgroup placement -> `pivot_root`      |  |
|  |  4. Drop Linux capabilities (`caps`) + `PR_SET_NO_NEW_PRIVS`      |  |
|  |  5. Close inherited FDs (`O_CLOEXEC`)                             |  |
|  |  6. Load pure-Rust `seccompiler` cBPF filter (fail-closed, last)  |  |
|  |  7. `execve` workload entrypoint                                  |  |
|  +-------------------------------------------------------------------+  |
+-------------------------------------------------------------------------+
```

---

## Quickstart & V1 Demo

### Prerequisites

- **OS:** Linux 5.15+ with unified **cgroup v2** mounted at `/sys/fs/cgroup` and `root` privileges (required in V1 for cgroup slice provisioning, `pivot_root`, and namespaces).
- **Toolchain:** Rust 1.80+ (`cargo build --release`). No C library headers required.

### Build

```bash
cargo build --release
```

For a completely static Linux `musl` binary:

```bash
rustup target add x86_64-unknown-linux-musl
RUSTFLAGS="-C target-feature=+crt-static" \
  cargo build --release --target x86_64-unknown-linux-musl
```

### High-Level Policy Execution (`boxlet run`)

`boxlet run` overlays explicit resource and isolation limits onto an OCI bundle and emits structured execution telemetry:

```bash
sudo ./target/release/boxlet run \
  --memory 128m \
  --cpus 0.5 \
  --pids 64 \
  --network none \
  --timeout 30 \
  --json \
  ./bundle
```

### Standard OCI Runtime Lifecycle (`create` / `start` / `state` / `kill` / `delete`)

`boxlet create` consumes the bundle's `config.json` verbatim with zero opinionated defaults injected, preserving strict OCI runtime compliance:

```bash
sudo ./target/release/boxlet create --bundle ./bundle demo-1
sudo ./target/release/boxlet state demo-1
sudo ./target/release/boxlet start demo-1
sudo ./target/release/boxlet kill demo-1 SIGTERM
sudo ./target/release/boxlet delete --force demo-1
```

### Run the End-to-End V1 Demo Script

On a Linux 5.15+ host with `busybox` (`busybox-static`) and `python3` installed, run the self-contained verification demo covering normal execution, `memory.max` OOM-kill telemetry (`oom_killed: true`), fail-closed seccomp/capability enforcement, and zero-leak cleanup:

```bash
sudo ./scripts/demo-v1.sh ./target/release/boxlet
```

---

## Embeddable Rust SDK

External Rust applications drive the exact same `Engine` as the CLI. See [`examples/embed_run.rs`](examples/embed_run.rs) for a complete runnable binary.

> **Important (`__init` forwarding):** Because `LinuxBackend` uses a self-re-exec stage (`<current_exe> __init <config.json>`) to enter namespaces cleanly without multi-threaded post-`fork()` undefined behavior, binaries embedding `LinuxBackend` must forward the `__init` argument at the start of `main()` before initializing async runtimes or thread pools.

```rust
use std::path::PathBuf;
use std::time::Duration;
use boxlet::policy::{ExecutionPolicy, NetworkMode};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Forward the internal self-re-exec container init stage on Linux:
    #[cfg(target_os = "linux")]
    if args.get(1).map(String::as_str) == Some("__init") {
        if let Some(cfg_path) = args.get(2) {
            if let Err(err) = boxlet::run_internal_init(std::path::Path::new(cfg_path)) {
                eprintln!("boxlet __init failed: {err}");
                std::process::exit(1);
            }
            return;
        }
    }

    let policy = ExecutionPolicy {
        memory_bytes: Some(128 * 1024 * 1024),
        cpus: Some(0.5),
        pids_limit: Some(64),
        network: Some(NetworkMode::None),
        timeout: Some(Duration::from_secs(30)),
        ..ExecutionPolicy::default()
    };

    #[cfg(target_os = "linux")]
    {
        let backend = boxlet::LinuxBackend::with_defaults();
        let engine = boxlet::Engine::new(backend);
        let result = engine
            .run("sandbox-1", &PathBuf::from("./bundle"), &policy)
            .expect("container execution failed");

        println!(
            "exit={:?} oom={} timed_out={} peak_mem={:?} cleanup={:?}",
            result.exit_code,
            result.violations.oom_killed,
            result.violations.timed_out,
            result.usage.memory_peak_bytes,
            result.cleanup,
        );
    }
}
```

---

## Security Posture & Threat Model

Boxlet V1 enforces defense-in-depth Linux kernel isolation:
1. **Namespaces:** Dedicated PID (`CLONE_NEWPID` with double-fork PID 1), Mount (`CLONE_NEWNS` with `MS_PRIVATE`), UTS, IPC, and Network (`CLONE_NEWNET` loopback-only by default for `boxlet run`).
2. **Filesystem Isolation:** `pivot_root` into the bundle rootfs, unmounting the old root, mounting isolated `/proc` and minimal `/dev`, and masking sensitive `/proc` and `/sys` paths.
3. **Privilege Reduction:** Drops Linux capabilities (`Effective`, `Permitted`, `Inheritable`, `Bounding`, `Ambient`) to an explicit allowlist via `caps` and sets `PR_SET_NO_NEW_PRIVS` (enabled by default in `boxlet run`; `boxlet create` honors `process.noNewPrivileges` in `config.json`).
4. **Fail-Closed Pure-Rust Seccomp BPF:** When `linux.seccomp` is configured in `config.json`, translates OCI seccomp rules via `syscalls` + `seccompiler` and loads the cBPF program as the final step before `execve`. Any unknown syscall name, unsupported operator, or unsupported flag aborts container creation with `BoxletError::UnsupportedSeccompRule`.
5. **Unified Cgroup v2 Budgets:** Enforces `memory.max`, `cpu.max`, and `pids.max` under `/sys/fs/cgroup/boxlet.slice/<id>` and guarantees teardown via `cgroup.kill`.

> **Shared-Kernel Boundary Warning:** Like `runc` and `youki`, Boxlet V1 containers share the host Linux kernel and require `root` on a dedicated Linux 5.15+ host or VM. Boxlet V1 is **not** designed for executing arbitrary hostile multi-tenant workloads in production without an outer hardware virtualization boundary. Future milestones plug microVM backends (such as Firecracker or `libkrun`) into the `RuntimeBackend` trait seam.

For the full trust-boundary diagram, threat matrix, and residual risk analysis, see:
- **[Threat Model (`docs/THREAT_MODEL.md`)](docs/THREAT_MODEL.md)**
- **[ADR-001: V1 Architecture, Runtime Seams, and Linux Isolation Contracts (`docs/adr/001-v1-architecture-and-seams.md`)](docs/adr/001-v1-architecture-and-seams.md)**
