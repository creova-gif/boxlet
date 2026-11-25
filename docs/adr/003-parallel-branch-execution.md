# ADR-003: Parallel Multi-Branch Sandbox Execution & CLI Surface

- **Status:** Accepted
- **Owner:** Justin Mafie
- **Date:** 2026-11-25

## Context

Multi-agent software engineering workflows frequently need to fan out `N` isolated candidate executions from a single base OCI bundle concurrently, override per-branch command arguments, environment variables, or working directories, and collect both structured execution telemetry (`ExecutionResult`: exit code, bounded stdout/stderr, cgroup v2 resource usage, policy violations, cleanup status) and a deterministic filesystem diff (`FsDiff`: `added`, `modified`, `deleted` relative paths) for each branch without mutating the base bundle.

While ADR-002 introduced `TreeManifest`, `FsDiff`, and `WorkspaceSnapshot` in `src/snapshot.rs`, callers still had to manually orchestrate temporary snapshot directories, clone and patch OCI `config.json` files per branch, spawn threads, and correlate post-run `TreeManifest` diffs with `Engine::run` outputs. Furthermore, the `boxlet` CLI lacked first-class subcommands for creating workspace snapshots, diffing directory trees on any host platform, and running multi-branch sandboxes in parallel.

## Decision

### 1. SDK Types: `BranchSpec` and `BranchExecutionResult` (`src/engine.rs`)

We extend `boxlet::engine` (and re-export at the crate root) with two serializable types:

- **`BranchSpec`**:
  - `id: String` — unique branch/container identifier validated via `validate_container_id`.
  - `args: Option<Vec<String>>` — optional `process.args` override for the branch workload.
  - `env: Option<Vec<String>>` — optional `KEY=VALUE` environment overrides merged into `process.env` (replacing matching `KEY=` entries and appending new keys).
  - `cwd: Option<String>` — optional `process.cwd` override inside the container.
  - Ergonomic builder helpers: `BranchSpec::new(id)`, `.with_args(...)`, `.with_env(...)`, and `.with_cwd(...)`.
- **`BranchExecutionResult`**:
  - `branch_id: String` — identifier matching `BranchSpec::id`.
  - `execution: ExecutionResult` — full container execution result from `RuntimeBackend::run`.
  - `fs_diff: FsDiff` — deterministic filesystem diff of the branch's rootfs relative to the base bundle rootfs snapshot.

### 2. Parallel Orchestration: `Engine::run_branches` (`src/engine.rs`)

We add `Engine::run_branches(&self, bundle: &Path, branches: &[BranchSpec], policy: &ExecutionPolicy) -> Result<Vec<BranchExecutionResult>>`:

1. **Upfront Validation:**
   - Validates `policy.validate()?`.
   - Validates every `branch.id` via `validate_container_id` and rejects duplicate branch IDs within the batch with `BoxletError::ContainerAlreadyExists`.
2. **Base Bundle Loading & Workspace Snapshotting:**
   - Loads `<bundle>/config.json` via `load_bundle_spec(bundle)`.
   - Creates an isolated temporary workspace directory under `std::env::temp_dir()` guarded by an RAII cleanup struct (`TempWorkspaceGuard`) that removes the temporary tree on scope exit (whether returning `Ok` or `Err`).
   - Resolves `<bundle>/<root.path>` (defaulting to `<bundle>/rootfs`) and checkpoints it once via `WorkspaceSnapshot::create("base", &source_rootfs, &snapshot_base)`.
3. **Per-Branch OCI Bundle Materialization:**
   - For each `BranchSpec`, creates `<work>/bundles/<branch_id>/rootfs` via `snapshot.branch("rootfs", &branch_bundle_dir)` and writes `<work>/bundles/<branch_id>/config.json` with `root.path = "rootfs"` and the branch's `args`, `env`, and `cwd` overrides applied.
4. **Scoped Parallel Execution & Post-Run Diffing:**
   - Uses `std::thread::scope` (leveraging `B: RuntimeBackend + Send + Sync`) to execute `self.backend.run(&branch.id, &branch_bundle_dir, &resolved)` concurrently across all branches.
   - Immediately after each branch finishes, captures `TreeManifest::capture(&branch_rootfs)` and computes `snapshot.manifest.diff(&after_manifest)`.
   - Joins all scoped worker threads in input slice order, removes the temporary workspace via `TempWorkspaceGuard`, and returns `Vec<BranchExecutionResult>` in the exact order of `branches` without mutating the caller's original bundle.

### 3. CLI Subcommands (`src/main.rs`)

We expose three new subcommands on the `boxlet` CLI:

- **`boxlet snapshot`** (`--rootfs <PATH> --out <SNAPSHOT_BASE> [--json] <ID>`, also accepting optional `create`):
  - Portable across macOS and Linux. Creates a `WorkspaceSnapshot` and prints either structured JSON (`--json`) or a concise human-readable summary.
- **`boxlet diff`** (`<BEFORE> <AFTER> [--json]` or `--before <DIR> --after <DIR> [--json]`):
  - Portable across macOS and Linux. Captures `TreeManifest` for both directories, computes `FsDiff`, and prints either pretty JSON (`--json`) or `+` (added), `~` (modified), and `-` (deleted) lines.
- **`boxlet branch-run`** (`--cmd <SHELL_CMD>...` repeatable + `--memory`, `--cpus`, `--pids`, `--network`, `--timeout`, `--max-output-bytes`, `--json`, `<BUNDLE>`):
  - Converts each `--cmd` into a `BranchSpec` (`branch-1`, `branch-2`, ...) with `args: Some(vec!["/bin/sh".into(), "-c".into(), cmd])`, executes `engine.run_branches(&bundle, &specs, &policy)`, and prints either the full `Vec<BranchExecutionResult>` as JSON (`--json`) or a per-branch execution + filesystem diff summary. Returns a non-zero `ExitCode` if any branch exits non-zero or experiences a policy violation.

## Alternatives Considered

1. **Sequential branch execution in `Engine::run_branches`:**
   - *Rejected:* Serializing `N` agent candidate runs multiplies latency by `N`. Because each branch receives an isolated rootfs directory, container ID, state directory, and cgroup v2 leaf, `std::thread::scope` safely runs all branches concurrently with zero shared mutable state.
2. **Mutating the base bundle's `config.json` in place:**
   - *Rejected:* Concurrent branches require distinct `process.args`, `process.env`, `process.cwd`, and `root.path` settings. Materializing lightweight per-branch bundle directories inside an RAII-guarded temporary workspace guarantees the caller's base bundle is never modified.
3. **Gating `boxlet snapshot` and `boxlet diff` behind `#[cfg(target_os = "linux")]`:**
   - *Rejected:* `WorkspaceSnapshot` and `TreeManifest` are pure Rust and host-OS-agnostic. Allowing `boxlet snapshot` and `boxlet diff` on macOS as well as Linux lets developers and CI pipelines test workspace snapshotting and diff inspection on any Unix host.

## Consequences & Failure Modes

- **Positive:**
  - Single-call parallel fan-out (`Engine::run_branches` / `boxlet branch-run`) returning both container telemetry and exact filesystem diffs in deterministic input order.
  - Zero mutation of the source OCI bundle and automatic RAII cleanup of temporary branch rootfs directories.
- **Failure modes & mitigations:**
  - *Duplicate or unsafe branch IDs:* Validated before any filesystem copy or container creation begins; duplicates fail fast with `BoxletError::ContainerAlreadyExists` and path-traversal IDs fail with `BoxletError::InvalidContainerId`.
  - *Temporary workspace leaks on error:* `TempWorkspaceGuard` removes the temporary directory in its `Drop` implementation even if a branch fails or returns an early error.
