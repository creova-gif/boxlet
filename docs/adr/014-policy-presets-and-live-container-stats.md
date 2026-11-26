# ADR-014: Policy Presets and Live Container Telemetry (`boxlet stats`)
- **Status:** Accepted
- **Owner:** Justin Mafie

## Context
As AI agent evaluation harnesses and multi-tenant execution pipelines adopt Boxlet at scale, two operational needs emerged:

1. **Standardized Security & Resource Profiles (`PolicyPreset` & `--policy-file`):**
   Requiring every `boxlet run` or `boxlet branch-run` invocation to pass a dozen individual resource and isolation flags (`--memory`, `--cpus`, `--pids`, `--nofile`, `--tmpfs`, `--timeout`, `--network`) creates configuration drift across agent workflows. Operators need opinionated, auditable baseline profiles (`strict`, `balanced`, `build`), a portable way to export those profiles as JSON (`boxlet policy-export`), and deterministic layering so a base preset or JSON policy file can be combined with fine-grained CLI overrides (`ExecutionPolicy::with_overrides`).
2. **Live & Post-Run Container Telemetry Inspection (`ContainerStats` & `boxlet stats`):**
   While `boxlet run` returns an `ExecutionResult` upon completion, long-running containers managed via the OCI lifecycle (`boxlet create` / `boxlet start`) or external orchestrators need on-demand visibility into live cgroup v2 resource consumption (`memory.peak`, `cpu.stat` `usage_usec`, `memory.events` `oom_kill`, and `*.pressure` PSI stall metrics) alongside current OCI liveness (`ContainerStatus` and `pid`).

## Decision
1. **Built-In `PolicyPreset` Profiles and Layered Policy Overrides:**
   - Introduce `PolicyPreset` (`Strict`, `Balanced`, `Build`) in `src/policy.rs` with `FromStr` parsing and `ExecutionPolicy::from_preset(PolicyPreset)`:
     - `strict`: Tight sandbox defaults (`memory_bytes = 64 MiB`, `cpus = 0.5`, `pids_limit = 32`, `nofile_limit = 256`, `network = None`, `no_new_privs = true`, `capabilities = Some(vec![])`, `seccomp = DefaultDeny`, `timeout = 15s`, `max_output_bytes = 256 KiB`, `tmpfs_mounts = ["/tmp:size=16m,mode=1777,noexec"]`).
     - `balanced`: General agent evaluation defaults (`memory_bytes = 256 MiB`, `cpus = 1.0`, `pids_limit = 128`, `nofile_limit = 1024`, `network = None`, `no_new_privs = true`, `capabilities = Some(vec![])`, `seccomp = DefaultDeny`, `timeout = 60s`, `max_output_bytes = 1 MiB`, `tmpfs_mounts = ["/tmp:size=64m,mode=1777,noexec"]`).
     - `build`: Compilation and test-suite defaults (`memory_bytes = 1 GiB`, `cpus = 2.0`, `pids_limit = 512`, `nofile_limit = 4096`, `network = None`, `no_new_privs = true`, `capabilities = Some(vec![])`, `seccomp = DefaultDeny`, `timeout = 300s`, `max_output_bytes = 4 MiB`, `tmpfs_mounts = ["/tmp:size=256m,mode=1777,exec"]`).
   - Add `ExecutionPolicy::load_from_file(&Path)` to load and validate a JSON-serialized `ExecutionPolicy` from disk.
   - Add `ExecutionPolicy::with_overrides(&ExecutionPolicy)` so any `Some(...)` field in the override policy replaces the corresponding base field while `None` fields preserve the base preset or file value.
   - Expose `boxlet policy-export [--preset strict|balanced|build] [--out <FILE>]` and mutually exclusive `--preset <NAME>` / `--policy-file <PATH>` flags on `boxlet run` and `boxlet branch-run`.

2. **Live & Post-Run Container Telemetry (`ContainerStats`, `Engine::stats`, `boxlet stats`):**
   - Introduce `ContainerStats` in `src/policy.rs` capturing `id`, `status: ContainerStatus`, `pid: Option<u32>`, `memory_peak_bytes: Option<u64>`, `cpu_usage_usec: Option<u64>`, `oom_kill_count: u64`, and `psi: Option<PsiMetrics>`.
   - Extend `RuntimeBackend` with `fn stats(&self, id: &str) -> Result<ContainerStats>` (with a portable default delegating to `self.state(id)` and a `LinuxBackend` implementation that refreshes liveness and reads the container's cgroup v2 leaf via `CgroupManager::read_stats` when present, gracefully falling back to `None`/`0` telemetry if the cgroup has already been torn down).
   - Expose `Engine::stats(&self, id: &str) -> Result<ContainerStats>` (enforcing `validate_container_id(id)` up front) and `boxlet stats [--json] <ID>`.

## Alternatives Considered
- **Separate CLI Subcommands per Preset (`boxlet run-strict`, `boxlet run-build`):**
  Rejected because it duplicates CLI flag surfaces and does not compose with exported JSON policy files (`--policy-file`).
- **Failing `boxlet stats` When a Stopped Container's Cgroup Leaf Is Removed:**
  Rejected because operators frequently inspect a container after termination; returning the persisted OCI `ContainerStatus::Stopped` state with `None` cgroup counters provides a consistent, non-fragile query contract while returning live cgroup v2 metrics whenever the cgroup leaf exists.

## Consequences & Failure Modes
- **Positive:**
  - Single-flag hardened sandboxes (`boxlet run --preset strict <bundle>`) with deterministic CLI override layering.
  - Auditable, version-controlled policy files via `boxlet policy-export --preset strict --out policy.json` and `boxlet run --policy-file policy.json`.
  - Real-time cgroup v2 memory, CPU, OOM, and PSI telemetry inspection via `Engine::stats` and `boxlet stats --json <id>`.
- **Failure Modes & Mitigations:**
  - *Conflicting base policy sources:* `--preset` and `--policy-file` are marked `conflicts_with` in `clap` so ambiguous double-bases are rejected at CLI parse time.
  - *Invalid overrides or tampered JSON policy files:* Both `ExecutionPolicy::load_from_file` and the post-override merged policy invoke `ExecutionPolicy::validate()` before execution, failing closed with `BoxletError::InvalidPolicy`.
  - *Path traversal via container ID in `stats`:* `Engine::stats` validates `id` via `validate_container_id(id)` before touching the state store or cgroup hierarchy.
