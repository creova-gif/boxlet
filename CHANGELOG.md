# Changelog

All notable changes to **Boxlet** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-26

### Added

#### V1 — OCI Runtime & Programmable Policy Engine (Milestones 0–3)
- **OCI v1.0.2 State Machine (`src/oci.rs`, `src/engine.rs`):** File-locked (`flock`) atomic `state.json` persistence supporting `create`, `start`, `state`, `kill`, and `delete` ([ADR-001](docs/adr/001-v1-architecture-and-seams.md)).
- **Programmable Execution Policy (`src/policy.rs`):** `ExecutionPolicy`, `NetworkMode`, `ExecutionResult`, `ResourceUsage`, `PolicyViolations`, `CleanupReport`, and bounded stdout/stderr ring/head capture (`BoundedBuffer`).
- **Linux 5.15+ Isolation Backend (`src/linux/`):** Self-re-exec container init (`boxlet __init`), `CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET` namespaces, `pivot_root`, `/proc` & `/dev` provisioning, capability dropping via `caps`, `PR_SET_NO_NEW_PRIVS`, pure-Rust `seccompiler` cBPF syscall filtering, and unified cgroup v2 (`memory.max`, `cpu.max`, `pids.max`, `cgroup.kill`) with 7-step deterministic teardown.

#### V2 — Deterministic Snapshots, Diffs, Parallel Branching & Rollback (Milestones 4–5)
- **Workspace Snapshots & Diffs (`src/snapshot.rs`):** 64-bit FNV-1a content & symlink digests (`TreeManifest`), `WorkspaceSnapshot`, single-pass `O(N)` `FsDiff` (`added`, `modified`, `deleted`), and `OverlayRootfsProvider` ([ADR-002](docs/adr/002-filesystem-snapshots-and-diffing.md)).
- **Parallel Multi-Agent Branch Execution (`boxlet branch-run`):** Concurrent isolated candidate branch evaluation via `Engine::run_branches` ([ADR-003](docs/adr/003-parallel-branch-execution.md)).
- **Candidate Winner Promotion & Rollback (`--promote-winner`, `boxlet restore`):** Automatic first-clean-winner promotion (`Engine::run_branches_with_promotion`, `BranchBatchReport`) and 4-stage deterministic workspace rollback (`WorkspaceSnapshot::restore`) ([ADR-004](docs/adr/004-branch-promotion-and-rollback.md)).

#### V3 — Structured Audit Trail, Bundle Scaffolding & Container Inventory (Milestones 6–7)
- **Append-Only JSONL Audit Trail (`src/audit.rs`, `--audit-log`):** `flock`-synchronized `0600` JSONL audit logger (`JsonlAuditLogger`, `AuditEvent`) and chronological telemetry aggregation (`boxlet audit --file`, `AuditSummary`) ([ADR-005](docs/adr/005-audit-trail-and-bundle-scaffolding.md), [ADR-006](docs/adr/006-container-inventory-prune-and-audit-analytics.md)).
- **Zero-Config OCI Bundle Scaffolding (`boxlet init-bundle`, `BundleBuilder`):** BusyBox rootfs & `config.json` generator with automatic applet symlink provisioning.
- **Container Inventory & Garbage Collection (`boxlet list`, `boxlet prune`):** Live PID-refreshed container inventory (`Engine::list`) and stopped/active container garbage collection (`Engine::prune`, `PruneReport`).

#### V4 — Host Readiness Diagnostics & Declarative Evaluation Rubrics (Milestone 8)
- **Host Readiness Diagnostics (`src/doctor.rs`, `boxlet doctor`):** Structured kernel version, root privilege, unified cgroup v2 controller (`memory`, `cpu`, `pids`), seccomp architecture, and state directory readiness checks (`DoctorReport`) ([ADR-007](docs/adr/007-doctor-diagnostics-and-declarative-eval-rubrics.md)).
- **Declarative Multi-Agent Evaluation Rubrics (`src/eval.rs`, `boxlet eval --spec`):** `EvalSpec` and `EvalRubric` guardrails (`require_exit_zero`, `required_stdout_contains`, `forbidden_stderr_contains`, `required_added_paths`, `forbidden_modified_paths`, `max_changed_files`) with deterministic candidate scoring and winner promotion (`EvalReport`).

#### V5 — MicroVM Hardware-Virtualization Backend & Portable OCI Rootfs Tar Archives (Milestones 9–10)
- **Portable OCI Rootfs Tar Importer/Exporter (`src/image.rs`, `boxlet image-export`, `boxlet image-import`):** Deterministic USTAR tar archive export (`export_rootfs_tar`, sorted paths, `mtime=0`, `uid=0`, `gid=0`, 64-bit FNV-1a digest) and fail-closed tar extraction (`import_rootfs_tar`, `RootfsArchiveReport`) rejecting path traversal and device special files ([ADR-008](docs/adr/008-microvm-backend-and-oci-image-archives.md)).
- **MicroVM Hardware-Virtualization Backend (`src/microvm.rs`, `boxlet microvm-config`):** `VmmDriver` (`Firecracker`, `Libkrun`), `MicroVmConfig`, `FirecrackerVmSpec`, `LibkrunVmSpec`, and `MicroVmBackend` implementing `RuntimeBackend` for hardware-isolated multi-tenant execution.

#### V6 — Enterprise Hardening, Tamper-Evident Audit Ledger, Prometheus Metrics, Bounded Concurrency & Rootless Support (Milestones 11–12)
- **Tamper-Evident Hash-Chained Audit Ledger (`src/audit.rs`, `boxlet audit --file`):** Lock-serialized (`File::lock()`) monotonic sequence numbers (`seq`), 64-bit FNV-1a cryptographic hash chaining (`prev_hash_fnv1a64`, `record_hash_fnv1a64`), and `hash_chain_valid` verification in `AuditSummary` ([ADR-009](docs/adr/009-enterprise-audit-hash-chaining-worker-pool-and-rootless.md)).
- **Prometheus / OpenMetrics Telemetry Export (`boxlet audit --file ... --prometheus`, `AuditSummary::to_prometheus_text`):** Zero-dependency Prometheus text-exposition format metric exporter (`boxlet_audit_records_total`, `boxlet_runs_completed_total`, `boxlet_audit_hash_chain_valid`, `boxlet_audit_chronological_valid`, etc.).
- **Bounded Worker-Pool Concurrency (`--max-concurrency <N>`, `ExecutionPolicy::max_concurrency`):** Configurable worker-pool throttling for parallel multi-agent branch fan-out in `boxlet branch-run` (`Engine::run_branches`) and `boxlet eval` (`EvalSpec`).
- **Rootless User Namespace Scaffolding & Mapping (`boxlet init-bundle --rootless`, `BundleBuilder::with_rootless`, `CLONE_NEWUSER`):** Unprivileged container support via `CLONE_NEWUSER`, `/proc/self/setgroups` `"deny"` enforcement, and host-to-container UID/GID mapping (`uid_map`, `gid_map`, `uidMappings`, `gidMappings`).

#### V7 — Cgroup v2 Block I/O Bandwidth/IOPS Throttling & Multi-Layer OCI Image Layout (Milestones 13–14)
- **Cgroup v2 Block I/O Bandwidth & IOPS Throttling (`--io-max`, `IoMaxRule`, `ExecutionPolicy::io_max`):** Fail-closed parsing, validation, and unified cgroup v2 `io.max` rule formatting (`<MAJ>:<MIN> rbps=... wbps=... riops=... wiops=...`) across `ExecutionPolicy`, `LinuxResources::block_io_max`, `CgroupV2::apply_limits`, and `boxlet doctor` (`+io` controller readiness) ([ADR-010](docs/adr/010-cgroup-io-max-and-oci-image-layout.md)).
- **Multi-Layer OCI Image Layout v1.0 Packing & Unpacking with Whiteouts (`src/image.rs`, `boxlet image-pack`, `boxlet image-unpack`):** Deterministic content-addressable OCI Image Layout v1.0 generator (`oci-layout`, `index.json`, `blobs/fnv1a64/<digest>`, `OciImageLayoutReport`, `OciLayerDescriptor`) and multi-layer unpacker supporting `.wh.<name>` explicit whiteouts and `.wh..wh..opq` opaque directory markers with fail-closed path-traversal protection.

#### V8 — Cgroup v2 PSI Telemetry, POSIX `setrlimit(2)` Resource Enforcement & Deterministic Benchmark Suite (Milestones 15–16)
- **Cgroup v2 Pressure Stall Information (`*.pressure` PSI) Telemetry (`PsiMetrics`, `ResourceUsage::psi`, `boxlet audit --prometheus`):** Harvests `cpu.pressure`, `memory.pressure`, and `io.pressure` (`some` / `full` `total=` stall microseconds) into `PsiMetrics` prior to cgroup teardown and exports `boxlet_psi_*_microseconds_total` counters in `AuditSummary::to_prometheus_text` ([ADR-011](docs/adr/011-psi-telemetry-rlimits-and-benchmark-suite.md)).
- **POSIX `setrlimit(2)` Resource Enforcement (`--nofile <N>`, `ExecutionPolicy::nofile_limit`, `PosixRlimit`):** Enforces `RLIMIT_CORE = 0` unconditionally before `execve` to prevent sensitive workload memory core-dump leaks and applies configurable `RLIMIT_NOFILE` open file-descriptor caps (`--nofile <N>` / `process.rlimits`) with fail-closed validation (`nofile == 0` rejected).
- **Deterministic Latency & Throughput Benchmark Suite (`src/bench.rs`, `boxlet bench`, `Engine::run_benchmark`):** Built-in benchmark harness (`BenchmarkConfig`, `BenchmarkReport`, `LatencySummary`) measuring `sandbox_run`, `workspace_snapshot_diff`, and `parallel_branch_batch` latency percentiles (`min_us`, `p50_us`, `p95_us`, `p99_us`, `max_us`, `mean_us`) and throughput (`runs_per_sec`, `branches_per_sec`) with JSON (`--json`) and Markdown table (`--markdown`) reports.

#### V9 — Declarative Host Bind Mounts & Seccomp Profile Management (Milestones 17–18)
- **Declarative Host Bind Mounts (`--mount <SRC>:<DST>[:ro|rw]`, `BindMountSpec`, `ExecutionPolicy::bind_mounts`, `OciMount`):** Fail-closed parsing, path-traversal and reserved-destination (`/`, `/proc`, `/sys`, `/dev`) rejection, read-only default (`ro`), and in-namespace recursive bind-mount provisioning prior to `pivot_root` with `MS_BIND | MS_REC` followed by `MS_REMOUNT | MS_BIND | MS_NOSUID | MS_NODEV` (plus `MS_RDONLY` when read-only) ([ADR-012](docs/adr/012-bind-mounts-and-seccomp-profile-management.md)).
- **Seccomp Profile Export & Custom Profile Enforcement (`boxlet seccomp-export`, `--seccomp-profile <PATH>`, `build_default_seccomp_profile`, `load_seccomp_profile`):** Cross-platform OCI `LinuxSeccomp` baseline profile generator (`build_default_seccomp_profile`, `boxlet seccomp-export [--out <PATH>]`) and fail-closed custom seccomp JSON profile loader (`load_seccomp_profile`, `ExecutionPolicy::seccomp_profile_path`) integrated with `boxlet run` and `boxlet branch-run`.

#### V10 — Ephemeral Size-Bounded `tmpfs` Scratch Mounts & Per-Run Process Overrides (Milestones 19–20)
- **Ephemeral Size-Bounded `tmpfs` Scratch Mounts (`--tmpfs <DST>[:size=<BYTES>,mode=<OCTAL>,noexec|exec]`, `TmpfsMountSpec`, `ExecutionPolicy::tmpfs_mounts`):** Fail-closed parsing, reserved-destination and path-traversal rejection, default `size=64m,mode=1777,noexec`, and in-namespace `tmpfs` mount provisioning prior to `pivot_root` with `MS_NOSUID | MS_NODEV` (plus `MS_NOEXEC` when `noexec=true`) enabling safe in-memory scratch directories inside read-only rootfs bundles ([ADR-013](docs/adr/013-ephemeral-tmpfs-mounts-and-process-overrides.md)).
- **Per-Run Process Overrides (`--cmd <SHELL_CMD>`, `-e` / `--env <KEY=VALUE>`, `--cwd <DIR>`, `ExecutionPolicy::args_override`, `env_overrides`, `cwd_override`):** Per-invocation entrypoint command, key-deduplicated environment variable, and working directory overrides across `boxlet run` and `boxlet branch-run`, allowing immutable base bundles to be reused without mutating `config.json`.
