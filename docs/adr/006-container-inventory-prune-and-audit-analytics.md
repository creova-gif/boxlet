# ADR-006: Container Inventory, Prune Garbage Collection, and Audit Analytics
- **Status:** Accepted
- **Owner:** Justin Mafie
- **Date:** 2026-11-26

## Context
Autonomous coding agents and CI harnesses executing many short-lived OCI containers and multi-branch speculative workloads accumulate stopped container state directories under `<root>/<id>` and append-only JSON Lines (`.jsonl`) audit records. Operators and agent supervisors need:
1. Deterministic container inventory inspection (`boxlet list`) over `<root>` without racing concurrent container lifecycle transitions or tripping over stray files.
2. Safe bulk garbage collection (`boxlet prune`) of `Stopped` containers (or all containers when `--force` is specified) that reclaims cgroups and state directories.
3. Single-pass telemetry and integrity verification (`boxlet audit --file`) over `.jsonl` audit logs to summarize pass/fail counts, OOM/timeout violations, promoted speculative branches, peak memory consumption, and chronological monotonicity.

## Decision
1. **Lexicographically Sorted State Store Inventory (`StateStore::list_ids` and `StateStore::list`):**
   - `StateStore::list_ids` returns an empty vector if `<root>` does not exist, otherwise scans `<root>` entries, filtering strictly to real directories (`entry.file_type()?.is_dir()`) that contain a regular `state.json` file and whose directory name passes `validate_container_id`. Valid IDs are sorted lexicographically.
   - `StateStore::list` iterates over `list_ids()` and loads each container state under `flock` via `StateStore::load`, gracefully skipping entries that return `BoxletError::ContainerNotFound` due to concurrent deletion races.
2. **Prune Audit Telemetry (`AuditEvent::ContainersPruned`):**
   - Extend `AuditEvent` with `ContainersPruned { removed_count, skipped_active_count, force }` so bulk cleanup operations are recorded in the same `0600` `.jsonl` audit stream as individual container lifecycle events.
3. **Structured Audit Analytics (`JsonlAuditLogger::summarize` and `AuditSummary`):**
   - Fold all parsed `AuditRecord` lines from `JsonlAuditLogger::read_all()` into `AuditSummary`, tracking total records, completed/succeeded/failed runs, timeout and OOM kill counts, completed branch batches, total evaluated branches, promoted winners, cumulative execution duration, maximum peak memory bytes, and `chronological_valid` (verifying `timestamp_unix_ms` is non-decreasing across the log).

## Alternatives Considered
- **Maintaining a separate central index file (`index.json`) in `<root>`:** Rejected because a central index introduces lock contention across unrelated containers and risks divergence from per-container `<root>/<id>/state.json` directories after crashes. Scanning `<root>` directories and locking each container's `.lock` on load is lock-free across independent containers and self-healing.
- **External `jq` scripts for audit log verification:** Rejected because first-class typed aggregation in Rust (`JsonlAuditLogger::summarize`) guarantees schema alignment with `AuditEvent` and enables programmatic preflight/postflight assertions in both CLI (`boxlet audit --file`) and library consumers.

## Consequences & Failure Modes
- **Concurrent Deletion Resilience:** If another process deletes a container between `list_ids()` and `load(&id)`, `StateStore::list` ignores `ContainerNotFound` and returns the remaining containers in sorted order without failing the scan.
- **Symlink & Stray File Safety:** Non-directory entries, symlinks (`file_type()?.is_dir()` is false for symlinks), partially removed directories without `state.json`, and invalid container IDs are ignored during inventory scans.
- **Clock Skew Detection:** Any out-of-order timestamp (`rec.timestamp_unix_ms < prev_ts`) marks `AuditSummary::chronological_valid = false`, surfacing log tampering or clock regressions immediately.
