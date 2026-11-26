# ADR-011: Cgroup v2 PSI Telemetry, POSIX Resource Limits (`setrlimit`), and Deterministic Benchmark Suite
- **Status:** Accepted
- **Owner:** Justin Mafie

## Context
As AI agents and multi-branch evaluation pipelines execute untrusted workloads inside Boxlet sandboxes at higher density, operators and programmatic SDK callers require:
1. **Granular Resource Contention Visibility:** Peak memory (`memory.peak`) and total CPU time (`cpu.stat`) show cumulative consumption, but do not reveal whether a workload stalled waiting on throttled CPU (`cpu.max`), memory reclaim/thrashing (`memory.pressure`), or block I/O (`io.max`). Linux cgroup v2 exposes Pressure Stall Information (`cpu.pressure`, `memory.pressure`, `io.pressure`) with microsecond stall counters (`some`/`full` `total=`).
2. **Process-Level Descriptor and Core-Dump Hardening:** In addition to cgroup-wide `pids.max` and `memory.max`, individual sandboxed processes can exhaust host file-descriptor tables unless `RLIMIT_NOFILE` is bounded, or leak sensitive memory contents to the container filesystem via core dumps unless `RLIMIT_CORE` is zeroed prior to `execve(2)`.
3. **Built-In Reproducible Latency & Throughput Benchmarking:** Evaluating cold-start container execution, deterministic `TreeManifest` snapshot/diff cycles, and concurrent multi-branch fan-out requires a first-class, zero-external-dependency benchmark suite (`boxlet bench` and `Engine::run_benchmark`) producing percentile distributions (`min`, `p50`, `p95`, `p99`, `max`, `mean`) in both JSON and GitHub-Flavored Markdown tables.

## Decision
1. **Cgroup v2 Pressure Stall Information (`PsiMetrics`) Telemetry:**
   - Before tearing down the container's leaf cgroup in `CgroupController`, Boxlet reads `cpu.pressure`, `memory.pressure`, and `io.pressure` on a best-effort basis and parses the `some` and `full` `total=` microsecond stall counters into `PsiMetrics`.
   - `ResourceUsage` and `AuditEvent::ContainerRunCompleted` include `psi: Option<PsiMetrics>`.
   - `JsonlAuditLogger::summarize` accumulates `total_psi_cpu_some_usec`, `total_psi_memory_some_usec`, and `total_psi_io_some_usec` into `AuditSummary`, and `AuditSummary::to_prometheus_metrics` exports `boxlet_psi_cpu_some_microseconds_total`, `boxlet_psi_memory_some_microseconds_total`, and `boxlet_psi_io_some_microseconds_total`.
2. **POSIX `setrlimit(2)` Hardening (`RLIMIT_NOFILE` and `RLIMIT_CORE`):**
   - `ExecutionPolicy` and `ResolvedRunSpec` add `nofile_limit: Option<u64>` (exposed on the CLI via `--nofile` on `boxlet run` and `boxlet branch-run`, validated `> 0`, and falling back to any `RLIMIT_NOFILE` entry in OCI `process.rlimits`).
   - Inside `run_init_process` (`src/linux/init.rs`), before dropping capabilities and installing the seccomp filter, Boxlet unconditionally sets `RLIMIT_CORE = (0, 0)` to disable core dumps and applies `RLIMIT_NOFILE = (limit, limit)` when configured.
3. **Deterministic Benchmark Harness (`src/bench.rs` & `boxlet bench`):**
   - `Engine::run_benchmark(&self, bundle: &Path, config: &BenchmarkConfig) -> Result<BenchmarkReport>` executes configurable warmup runs followed by timed iterations of single-container execution (`sandbox_run`), `TreeManifest` capture + diff (`snapshot_diff`), and parallel multi-branch execution (`parallel_branch_batch`).
   - `LatencySummary::from_samples` computes deterministic `min_us`, `p50_us`, `p95_us`, `p99_us`, `max_us`, and `mean_us` latency statistics without external statistical dependencies, and `BenchmarkReport::to_markdown_table` renders a ready-to-publish Markdown report.

## Alternatives Considered
- **External Benchmarking Scripts (`hyperfine` / shell wrappers):** Rejected as the sole benchmarking mechanism because shell wrappers only measure outer CLI process spawn overhead and cannot decompose single-container execution, in-process `TreeManifest` snapshot/diff, and bounded parallel branch fan-out with per-run cgroup `memory.peak` aggregation.
- **Polling PSI files from a background thread during execution:** Rejected because cgroup v2 `*.pressure` `total=` counters are monotonically increasing cumulative microsecond counters over the lifetime of the leaf cgroup; a single read immediately after child termination and before `rmdir` captures the exact total stall duration with zero runtime polling overhead.

## Consequences & Failure Modes
- **Kernel PSI Support Variance:** Hosts booted with `psi=0` or older kernels without `CONFIG_PSI=y` may not expose `*.pressure` files in leaf cgroups. Boxlet treats missing PSI files as non-fatal and sets `ResourceUsage::psi = None` when all stall counters are absent.
- **Strict `RLIMIT_NOFILE` Enforcement:** Setting `--nofile` too low (e.g., `< 8`) can cause dynamic linkers or shells inside the container to fail with `EMFILE` upon startup; this is expected POSIX behavior under explicit operator policy.
