# ADR-005: Structured JSONL Audit Trail and Deterministic OCI Bundle Scaffolding

- **Status:** Accepted
- **Owner:** Justin Mafie
- **Date:** 2026-11-25

## Context

Autonomous AI coding agents and security-sensitive sandbox orchestrators require two operational capabilities beyond raw container execution:

1. **Tamper-evident, machine-readable audit telemetry:** When an agent orchestrator creates containers, runs untrusted commands under resource/seccomp policies, or evaluates `N` parallel workspace branches with automatic winner promotion, security and compliance pipelines need a chronological, append-only record of every lifecycle transition, policy violation (`timed_out`, `oom_killed`, `termination_signal`), peak memory/CPU usage, and promoted branch diff count. Relying strictly on transient stdout leaves no durable forensic trail if the caller process terminates or rotates logs.
2. **Zero-shell-script OCI bundle scaffolding:** Constructing a valid OCI Runtime Specification bundle (`config.json` + `rootfs/{bin,proc,dev,tmp,etc}` + BusyBox applet symlinks) previously required ad-hoc shell scripts (`jq`, `mkdir -p`, `ln -s`). A first-class Rust `BundleBuilder` API and `boxlet init <bundle_dir>` CLI command eliminate manual boilerplate while guaranteeing OCI 1.0.2 specification compliance.

## Decision

### 1. Append-Only JSON Lines Audit Logger (`src/audit.rs`)

- **Schema (`AuditRecord` & `AuditEvent`):**
  - Every audit line is serialized as a single JSON object (`AuditRecord`) containing `timestamp_unix_ms: u64` and a flattened, internally tagged `AuditEvent` (`#[serde(tag = "event", rename_all = "snake_case")]`).
  - Covered events span the full Boxlet surface:
    - `container_created` (`container_id`, `bundle`)
    - `container_started` (`container_id`, `pid`)
    - `container_killed` (`container_id`, `signal`)
    - `container_deleted` (`container_id`, `force`)
    - `container_run_completed` (`container_id`, `exit_code`, `duration_ms`, `memory_peak_bytes`, `cpu_usage_usec`, `violations`, `cleanup`)
    - `branch_batch_completed` (`branch_count`, `succeeded_count`, `promoted_branch_id`, `promoted_changes`)
- **Storage & Permissions (`JsonlAuditLogger`):**
  - `JsonlAuditLogger::record` creates parent directories if needed, opens the target `.jsonl` file in `append(true).create(true)` mode with `0o600` owner-only permissions on Unix (and explicitly tightens existing files to `0o600`), and writes the serialized JSON line + `\n` in a single `write_all` call.
  - `Engine::with_audit_log` attaches an optional `JsonlAuditLogger` to `Engine` (and CLI `--audit-log <PATH>` wires it automatically) so both library and CLI consumers share identical audit instrumentation.

### 2. Deterministic OCI Bundle Builder (`src/oci/mod.rs`)

- `BundleBuilder` provides a fluent builder (`with_args`, `with_shell_command`, `with_env`, `with_cwd`, `with_hostname`, `with_readonly_rootfs`, `with_busybox`) that validates non-empty `args` and `cwd`, scaffolds `<bundle_dir>/rootfs/{bin,proc,dev,tmp,etc}` and `<bundle_dir>/rootfs/etc/hostname`, optionally copies a static `busybox` binary into `rootfs/bin/busybox` (`0o755`) with standard applet symlinks (`/bin/busybox`), and writes a compliant OCI `1.0.2` `config.json` with `Pid`, `Mount`, `Uts`, `Ipc`, and `Network` namespaces and `no_new_privileges = true`.

## Alternatives Considered

1. **SQLite database for audit logging:**
   - *Rejected:* Adds native C/SQLite dependencies, complicates streaming ingestion by log ship agents (`fluent-bit`, `vector`, `jq`), and increases lock contention compared to atomic single-line `.jsonl` appends.
2. **External shell scripts for bundle creation (`scripts/mkbundle.sh`):**
   - *Rejected:* Cannot be invoked programmatically from Rust SDK callers or integration tests without spawning external shell processes, and duplicates OCI `config.json` generation logic.

## Consequences & Failure Modes

- **Positive:**
  - Every `boxlet` lifecycle operation, single-container run, and parallel multi-branch evaluation can emit structured `.jsonl` audit events protected with `0600` permissions.
  - Users and automated tests can scaffold complete, runnable OCI bundles in one command (`boxlet init`) or one builder call (`BundleBuilder::new().build(...)`).
- **Failure modes & mitigations:**
  - *Audit log permission drift on pre-existing files:* `JsonlAuditLogger::record` explicitly enforces `0o600` via both `OpenOptionsExt::mode(0o600)` at creation time and `fs::set_permissions` on existing files.
  - *Re-running `BundleBuilder::build` on an existing directory:* Existing applet symlinks or files in `rootfs/bin/<applet>` are removed before creating symlinks so bundle initialization is idempotent.
