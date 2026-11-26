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
