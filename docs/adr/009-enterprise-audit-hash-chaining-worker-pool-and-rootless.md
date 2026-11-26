# ADR-009: Enterprise Audit Hash-Chaining, Bounded Worker Pool, and Rootless User Namespaces
- **Status:** Accepted
- **Owner:** Justin Mafie

## Context
As Boxlet scales into enterprise multi-agent evaluation pipelines and zero-trust CI environments, three operational requirements emerge:
1. **Tamper-Evident Auditability & Prometheus Observability:** Chronological timestamps alone (`timestamp_unix_ms`) cannot detect in-place edits, deleted log entries, or truncated headers in `.jsonl` audit logs, nor can external monitoring stacks scrape JSON summaries directly without an OpenMetrics/Prometheus text exposition format. Furthermore, concurrent `boxlet` processes writing to a shared `.jsonl` audit log require OS-level file locking to maintain a linear sequence.
2. **Bounded Multi-Branch Concurrency:** Unbounded `std::thread::scope` fan-out across tens of candidate agent branches in `Engine::run_branches` and `Engine::run_eval` risks exhausting host PIDs, cgroup v2 subtrees, or RAM when evaluating large candidate batches.
3. **Rootless Execution (`CLONE_NEWUSER`):** Running sandboxes in unprivileged CI runners or non-root developer workstations requires Linux user namespace isolation (`CLONE_NEWUSER`) with `/proc/<pid>/uid_map`, `/proc/<pid>/gid_map`, and `/proc/<pid>/setgroups` (`"deny"`) synchronization before container initialization proceeds.

## Decision
1. **Tamper-Evident 64-bit FNV-1a Hash-Chained JSONL Audit Ledger & Prometheus Exposition (`src/audit.rs`):**
   - Extend `AuditRecord` with backward-compatible (`#[serde(default)]`) fields: `seq: u64` (1-based monotonic index), `prev_hash_fnv1a64: u64` (`0` for the genesis record, or the preceding record's hash), and `record_hash_fnv1a64: u64`.
   - Compute `record_hash_fnv1a64` deterministically via 64-bit FNV-1a (`FNV1A_64_OFFSET_BASIS = 0xcbf2_9ce4_8422_2325`, `FNV1A_64_PRIME = 0x0100_0000_01b3`) over little-endian bytes of `(seq, prev_hash_fnv1a64, timestamp_unix_ms)` followed by the canonical JSON serialization of `AuditEvent`.
   - Protect `JsonlAuditLogger::record` with `std::fs::File::lock()` (stabilized in Rust 1.89) on a `read(true).create(true).append(true)` descriptor (`0600` permissions, `O_NOFOLLOW` on Linux) so concurrent writers serialize sequence assignment and hash chaining atomically.
   - Extend `AuditSummary` with `hash_chain_valid: bool`, `head_hash_fnv1a64: u64`, `JsonlAuditLogger::verify_integrity()`, and `AuditSummary::to_prometheus_metrics()` emitting standard `# HELP` / `# TYPE` Prometheus counters and gauges.
2. **Bounded Worker-Pool Concurrency (`ExecutionPolicy::max_concurrency`):**
   - Add `max_concurrency: Option<usize>` to `ExecutionPolicy` (validated to be `>= 1` when set) and `--max-concurrency` CLI flags on `branch-run` and `eval`.
   - Partition parallel branch execution in `Engine::run_branches` (and consequently `Engine::run_eval`) using an atomic work-stealing cursor (`AtomicUsize`) across `min(branches.len(), max_concurrency)` scoped worker threads while preserving deterministic output ordering by branch index.
3. **Rootless User Namespace Orchestration (`CLONE_NEWUSER`):**
   - Add `BundleBuilder::with_rootless(host_uid, host_gid)` to emit the `user` namespace entry alongside `uidMappings` (`containerID: 0, hostID: host_uid, size: 1`) and `gidMappings` (`containerID: 0, hostID: host_gid, size: 1`) in OCI `config.json`.
   - Synchronize parent/child namespace setup over an additional host-to-init pipe: when `CLONE_NEWUSER` is enabled, the parent writes `/proc/<pid>/setgroups` (`"deny"`), `/proc/<pid>/uid_map`, and `/proc/<pid>/gid_map` before signaling the child to assume container root (`setgid(0)` / `setuid(0)`) and pivot root.

## Alternatives Considered
- **External Cryptographic Hash Crates (`sha2` / `blake3`) vs. Dependency-Free 64-bit FNV-1a:**
  - *Rejected for V6 core dependency budget:* Keeping deterministic 64-bit FNV-1a in-tree avoids expanding the dependency graph while providing fast, deterministic tamper evidence against accidental corruption, line deletion, or unhashed edits.
- **Unbounded Thread Spawning with Semaphore vs. Scoped Worker Pool with `AtomicUsize` Cursor:**
  - *Rejected:* Spawning `N` OS threads upfront only to block them on a semaphore wastes thread stack memory; spawning at most `max_concurrency` worker threads pulling from an `AtomicUsize` index bounds both OS thread count and active sandbox count.

## Consequences & Failure Modes
- **Audit Lock Contention:** Under extreme concurrent write rates to a single `.jsonl` file, `File::lock()` serializes writers and scans existing lines to compute `(next_seq, prev_hash)`. Log rotation or per-batch audit files should be used for high-volume long-running daemons.
- **Rootless Kernel Restrictions:** Some enterprise Linux distributions restrict unprivileged user namespaces via `kernel.unprivileged_userns_clone=0` or AppArmor; in those environments `clone(CLONE_NEWUSER)` fails closed with an actionable `BoxletError::Runtime` error.
