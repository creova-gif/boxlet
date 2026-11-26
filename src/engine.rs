//! Shared execution engine used by both the `boxlet` CLI and downstream Rust SDK callers.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use oci_spec::runtime::Spec;
use serde::{Deserialize, Serialize};

use crate::audit::{AuditEvent, JsonlAuditLogger};
use crate::error::{BoxletError, Result};
use crate::eval::{
    evaluate_candidate, select_winning_verdict, CandidateVerdict, EvalReport, EvalSpec,
};
use crate::oci::state::{ContainerState, ContainerStatus};
use crate::oci::{load_bundle_spec, validate_container_id};
use crate::policy::{merge_policy_with_spec, ExecutionPolicy, ExecutionResult, ResolvedRunSpec};
use crate::snapshot::{FsDiff, TreeManifest, WorkspaceSnapshot};
use crate::traits::RuntimeBackend;

/// Monotonic counter used to disambiguate concurrent temporary branch workspaces.
static WORKSPACE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Summary of containers removed or skipped during [`Engine::prune`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PruneReport {
    /// Container IDs that were deleted.
    pub removed_containers: Vec<String>,
    /// Active container IDs (`Creating`, `Created`, `Running`) that were skipped when `force == false`.
    pub skipped_active_containers: Vec<String>,
}

/// Per-branch workload overrides for [`Engine::run_branches`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchSpec {
    /// Unique identifier for this branch (validated via `validate_container_id`).
    pub id: String,
    /// Optional command argv override (`process.args`).
    pub args: Option<Vec<String>>,
    /// Optional environment entries (`KEY=VALUE`) appended to or overriding `process.env`.
    pub env: Option<Vec<String>>,
    /// Optional working directory override (`process.cwd`).
    pub cwd: Option<String>,
}

impl BranchSpec {
    /// Constructs a new [`BranchSpec`] with the given branch `id` and no process overrides.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            args: None,
            env: None,
            cwd: None,
        }
    }

    /// Overrides the container command arguments (`process.args`) for this branch.
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = Some(args);
        self
    }

    /// Overrides or appends environment variables (`KEY=VALUE`) in `process.env` for this branch.
    pub fn with_env(mut self, env: Vec<String>) -> Self {
        self.env = Some(env);
        self
    }

    /// Overrides the working directory (`process.cwd`) inside the container for this branch.
    pub fn with_cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }
}

/// Combined execution telemetry and filesystem diff for a single sandbox branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchExecutionResult {
    /// Branch identifier matching [`BranchSpec::id`].
    pub branch_id: String,
    /// Container execution telemetry (`stdout`, `stderr`, `exit_code`, `usage`, `violations`, `cleanup`).
    pub execution: ExecutionResult,
    /// Deterministic filesystem diff relative to the base bundle rootfs snapshot.
    pub fs_diff: FsDiff,
}

/// Aggregated outcome of a parallel multi-branch evaluation and optional winner promotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchBatchReport {
    /// Per-branch execution results and filesystem diffs in the exact input order.
    pub branches: Vec<BranchExecutionResult>,
    /// Identifier of the winning branch promoted back to the source bundle rootfs, if any.
    pub promoted_branch_id: Option<String>,
    /// Filesystem diff applied to the source bundle rootfs when a winner was promoted.
    pub promoted_diff: Option<FsDiff>,
}

/// RAII guard that removes the temporary workspace directory created by [`Engine::run_branches`].
struct TempWorkspaceGuard {
    path: PathBuf,
}

impl TempWorkspaceGuard {
    fn create(bundle: &Path) -> Result<Self> {
        let preferred_base = bundle
            .parent()
            .filter(|p| !p.as_os_str().is_empty() && p.exists())
            .map(Path::to_path_buf);
        let fallback_base = std::env::temp_dir();

        if let Some(ref base) = preferred_base {
            if let Ok(guard) = Self::create_in_base(base) {
                return Ok(guard);
            }
        }
        Self::create_in_base(&fallback_base)
    }

    fn create_in_base(base: &Path) -> Result<Self> {
        let pid = std::process::id();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);

        for _ in 0..256 {
            let seq = WORKSPACE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let candidate = base.join(format!(".boxlet-branches-{pid}-{nanos}-{seq}"));
            match create_private_dir(&candidate) {
                Ok(()) => return Ok(Self { path: candidate }),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(source) => {
                    return Err(BoxletError::StateStore {
                        path: candidate,
                        source,
                    });
                }
            }
        }

        Err(BoxletError::Runtime {
            subsystem: "engine",
            message: "failed to allocate unique temporary workspace directory for branches"
                .to_string(),
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    fs::create_dir(path)
}

impl Drop for TempWorkspaceGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Pre-materialized per-branch bundle and resolved run configuration.
struct PreparedBranch {
    branch_id: String,
    bundle_dir: PathBuf,
    rootfs_dir: PathBuf,
    resolved: ResolvedRunSpec,
}

/// Shared Boxlet execution engine parameterized over a single deep [`RuntimeBackend`].
#[derive(Debug, Clone)]
pub struct Engine<B: RuntimeBackend> {
    backend: B,
    audit_logger: Option<JsonlAuditLogger>,
}

impl<B: RuntimeBackend> Engine<B> {
    /// Constructs a new [`Engine`] backed by `backend`.
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            audit_logger: None,
        }
    }

    /// Attaches an append-only [`JsonlAuditLogger`] to this [`Engine`].
    pub fn with_audit_logger(mut self, logger: JsonlAuditLogger) -> Self {
        self.audit_logger = Some(logger);
        self
    }

    /// Attaches an optional append-only [`JsonlAuditLogger`] to this [`Engine`].
    pub fn with_optional_audit_logger(mut self, logger: Option<JsonlAuditLogger>) -> Self {
        self.audit_logger = logger;
        self
    }

    fn preflight_audit(&self) -> Result<()> {
        if let Some(ref logger) = self.audit_logger {
            logger.preflight()?;
        }
        Ok(())
    }

    /// Creates a container from `<bundle>/config.json` **verbatim** (no `boxlet run` defaults injected).
    pub fn create(&self, id: &str, bundle: &Path) -> Result<ContainerState> {
        validate_container_id(id)?;
        self.preflight_audit()?;
        let spec = load_bundle_spec(bundle)?;
        let state = self.backend.create(id, bundle, &spec)?;
        if let Some(ref logger) = self.audit_logger {
            logger.record(AuditEvent::ContainerCreated {
                container_id: id.to_string(),
                bundle: bundle.to_path_buf(),
            })?;
        }
        Ok(state)
    }

    /// Starts a previously created container (`Created -> Running`).
    pub fn start(&self, id: &str) -> Result<ContainerState> {
        validate_container_id(id)?;
        self.preflight_audit()?;
        let state = self.backend.start(id)?;
        if let Some(ref logger) = self.audit_logger {
            logger.record(AuditEvent::ContainerStarted {
                container_id: id.to_string(),
                pid: state.pid,
            })?;
        }
        Ok(state)
    }

    /// Queries the current OCI state of container `id`.
    pub fn state(&self, id: &str) -> Result<ContainerState> {
        validate_container_id(id)?;
        self.backend.state(id)
    }

    /// Sends OS signal `signal` to container `id`.
    pub fn kill(&self, id: &str, signal: i32) -> Result<()> {
        validate_container_id(id)?;
        self.preflight_audit()?;
        self.backend.kill(id, signal)?;
        if let Some(ref logger) = self.audit_logger {
            logger.record(AuditEvent::ContainerKilled {
                container_id: id.to_string(),
                signal,
            })?;
        }
        Ok(())
    }

    /// Deletes container `id` (requires `Stopped` unless `force` is true).
    pub fn delete(&self, id: &str, force: bool) -> Result<()> {
        validate_container_id(id)?;
        self.preflight_audit()?;
        self.backend.delete(id, force)?;
        if let Some(ref logger) = self.audit_logger {
            logger.record(AuditEvent::ContainerDeleted {
                container_id: id.to_string(),
                force,
            })?;
        }
        Ok(())
    }

    /// Lists all tracked containers in deterministic `id` order.
    pub fn list(&self) -> Result<Vec<ContainerState>> {
        self.backend.list()
    }

    /// Removes stopped containers (or all containers when `force` is `true`) and returns a [`PruneReport`].
    pub fn prune(&self, force: bool) -> Result<PruneReport> {
        self.preflight_audit()?;
        let states = self.backend.list()?;
        let mut removed_containers = Vec::new();
        let mut skipped_active_containers = Vec::new();

        let mut delete_err: Option<BoxletError> = None;
        for st in states {
            if force || st.status == ContainerStatus::Stopped {
                match self.backend.delete(&st.id, force) {
                    Ok(()) => removed_containers.push(st.id),
                    Err(err) => {
                        delete_err = Some(err);
                        break;
                    }
                }
            } else {
                skipped_active_containers.push(st.id);
            }
        }

        if let Some(ref logger) = self.audit_logger {
            if !removed_containers.is_empty() || delete_err.is_none() {
                let _ = logger.record(AuditEvent::ContainersPruned {
                    removed_count: removed_containers.len(),
                    skipped_active_count: skipped_active_containers.len(),
                    force,
                });
            }
        }

        if let Some(err) = delete_err {
            return Err(err);
        }

        Ok(PruneReport {
            removed_containers,
            skipped_active_containers,
        })
    }

    /// Runs a container end-to-end by overlaying `policy` onto `<bundle>/config.json`
    /// (applying Boxlet's safe V1 defaults for fields omitted from both).
    pub fn run(
        &self,
        id: &str,
        bundle: &Path,
        policy: &ExecutionPolicy,
    ) -> Result<ExecutionResult> {
        validate_container_id(id)?;
        self.preflight_audit()?;
        let base_spec = load_bundle_spec(bundle)?;
        let resolved = merge_policy_with_spec(&base_spec, policy)?;
        let result = self.backend.run(id, bundle, &resolved)?;
        if let Some(ref logger) = self.audit_logger {
            logger.record(AuditEvent::ContainerRunCompleted {
                container_id: result.container_id.clone(),
                exit_code: result.exit_code,
                duration_ms: u64::try_from(result.usage.duration.as_millis()).unwrap_or(u64::MAX),
                memory_peak_bytes: result.usage.memory_peak_bytes,
                cpu_usage_usec: result.usage.cpu_usage_usec,
                psi: result.usage.psi.clone(),
                violations: result.violations.clone(),
                cleanup: result.cleanup.clone(),
            })?;
        }
        Ok(result)
    }

    /// Executes a deterministic benchmark suite measuring single-sandbox cold-start latency,
    /// `TreeManifest` snapshot/diff latency, and parallel multi-branch batch latency.
    pub fn run_benchmark(
        &self,
        bundle: &Path,
        config: &crate::bench::BenchmarkConfig,
    ) -> Result<crate::bench::BenchmarkReport> {
        config.validate()?;
        let base_spec = load_bundle_spec(bundle)?;
        let configured_rootfs = base_spec
            .root()
            .as_ref()
            .map(|r| r.path().clone())
            .unwrap_or_else(|| PathBuf::from("rootfs"));
        let source_rootfs = if configured_rootfs.is_absolute() {
            configured_rootfs
        } else {
            bundle.join(configured_rootfs)
        };

        for idx in 0..config.warmup {
            let warmup_id = format!("bench-warmup-{}", idx + 1);
            let _ = self.run(&warmup_id, bundle, &config.policy)?;
        }

        let mut run_samples_us = Vec::with_capacity(config.iterations);
        let mut peak_memory_bytes: Option<u64> = None;
        for idx in 0..config.iterations {
            let run_id = format!("bench-run-{}", idx + 1);
            let start = std::time::Instant::now();
            let res = self.run(&run_id, bundle, &config.policy)?;
            let elapsed_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
            run_samples_us.push(elapsed_us);
            if let Some(mem) = res.usage.memory_peak_bytes {
                peak_memory_bytes = Some(peak_memory_bytes.map_or(mem, |cur| cur.max(mem)));
            }
        }

        let mut snap_samples_us = Vec::with_capacity(config.iterations);
        for _ in 0..config.iterations {
            let start = std::time::Instant::now();
            let manifest = TreeManifest::capture(&source_rootfs)?;
            let _diff = manifest.diff(&manifest);
            let elapsed_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
            snap_samples_us.push(elapsed_us);
        }

        let branch_specs: Vec<BranchSpec> = (0..config.branches_per_iter)
            .map(|b| BranchSpec::new(format!("bench-branch-{}", b + 1)))
            .collect();
        let mut branch_samples_us = Vec::with_capacity(config.iterations);
        for _ in 0..config.iterations {
            let start = std::time::Instant::now();
            let _ = self.run_branches(bundle, &branch_specs, &config.policy)?;
            let elapsed_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
            branch_samples_us.push(elapsed_us);
        }

        let total_run_us: u128 = run_samples_us.iter().map(|&v| u128::from(v)).sum();
        let throughput_runs_per_sec = if total_run_us > 0 {
            (config.iterations as f64) / ((total_run_us as f64) / 1_000_000.0)
        } else {
            0.0
        };

        Ok(crate::bench::BenchmarkReport {
            iterations: config.iterations,
            warmup: config.warmup,
            branches_per_iter: config.branches_per_iter,
            run_latency_us: crate::bench::LatencySummary::from_samples(&run_samples_us),
            branch_batch_latency_us: crate::bench::LatencySummary::from_samples(&branch_samples_us),
            snapshot_diff_latency_us: crate::bench::LatencySummary::from_samples(&snap_samples_us),
            throughput_runs_per_sec,
            peak_memory_bytes,
        })
    }

    /// Snapshots `<bundle>` once, fans out `branches` concurrently in isolated workspace
    /// root filesystems, and returns per-branch execution telemetry plus deterministic
    /// [`FsDiff`]s in the exact input order without mutating `<bundle>`.
    pub fn run_branches(
        &self,
        bundle: &Path,
        branches: &[BranchSpec],
        policy: &ExecutionPolicy,
    ) -> Result<Vec<BranchExecutionResult>> {
        self.run_branches_with_promotion(bundle, branches, policy, false)
            .map(|r| r.branches)
    }

    /// Snapshots `<bundle>` once, fans out `branches` concurrently in isolated workspace
    /// root filesystems, and optionally promotes the first passing branch (`exit_code == Some(0)`
    /// with no timeout or OOM violations) back onto the source bundle rootfs.
    pub fn run_branches_with_promotion(
        &self,
        bundle: &Path,
        branches: &[BranchSpec],
        policy: &ExecutionPolicy,
        promote_winner: bool,
    ) -> Result<BranchBatchReport> {
        policy.validate()?;
        self.preflight_audit()?;

        let mut seen_ids = BTreeSet::new();
        for branch in branches {
            validate_container_id(&branch.id)?;
            if !seen_ids.insert(branch.id.as_str()) {
                return Err(BoxletError::ContainerAlreadyExists {
                    id: branch.id.clone(),
                });
            }
        }

        let base_spec = load_bundle_spec(bundle)?;
        if branches.is_empty() {
            return Ok(BranchBatchReport {
                branches: Vec::new(),
                promoted_branch_id: None,
                promoted_diff: None,
            });
        }

        let configured_rootfs = base_spec
            .root()
            .as_ref()
            .map(|r| r.path().clone())
            .unwrap_or_else(|| PathBuf::from("rootfs"));
        let source_rootfs = if configured_rootfs.is_absolute() {
            configured_rootfs
        } else {
            bundle.join(configured_rootfs)
        };

        let workspace = TempWorkspaceGuard::create(bundle)?;
        let snapshot_base = workspace.path().join("snapshots");
        let bundles_base = workspace.path().join("bundles");

        let snapshot = WorkspaceSnapshot::create("base", &source_rootfs, &snapshot_base)?;

        let mut prepared = Vec::with_capacity(branches.len());
        for branch in branches {
            let branch_bundle_dir = bundles_base.join(&branch.id);
            let branch_rootfs_dir = snapshot.branch("rootfs", &branch_bundle_dir)?;
            let branch_spec = apply_branch_overrides(&base_spec, branch);
            let config_path = branch_bundle_dir.join("config.json");
            branch_spec
                .save(&config_path)
                .map_err(|source| BoxletError::OciSpec {
                    path: config_path,
                    source,
                })?;
            let resolved = merge_policy_with_spec(&branch_spec, policy)?;
            prepared.push(PreparedBranch {
                branch_id: branch.id.clone(),
                bundle_dir: branch_bundle_dir,
                rootfs_dir: branch_rootfs_dir,
                resolved,
            });
        }

        let results = execute_prepared_branches_bounded(
            &self.backend,
            &snapshot.manifest,
            &prepared,
            policy.max_concurrency,
        )?;

        let succeeded_count = results
            .iter()
            .filter(|res| {
                res.execution.exit_code == Some(0)
                    && !res.execution.violations.timed_out
                    && !res.execution.violations.oom_killed
            })
            .count();

        let mut promoted_branch_id = None;
        let mut promoted_diff = None;
        if promote_winner {
            if let Some((winner_res, winner_prepared)) =
                results.iter().zip(prepared.iter()).find(|(res, _)| {
                    res.execution.exit_code == Some(0)
                        && !res.execution.violations.timed_out
                        && !res.execution.violations.oom_killed
                })
            {
                let applied_diff =
                    match snapshot.promote_branch(&winner_prepared.rootfs_dir, &source_rootfs) {
                        Ok(diff) => diff,
                        Err(err) => {
                            if !is_pre_sync_divergence_error(&err) {
                                let _ = snapshot.restore(&source_rootfs);
                            }
                            return Err(err);
                        }
                    };
                promoted_branch_id = Some(winner_res.branch_id.clone());
                promoted_diff = Some(applied_diff);
            }
        }

        if let Some(ref logger) = self.audit_logger {
            logger.record(AuditEvent::BranchBatchCompleted {
                branch_count: results.len(),
                succeeded_count,
                promoted_branch_id: promoted_branch_id.clone(),
                promoted_changes: promoted_diff.as_ref().map(FsDiff::total_changes),
            })?;
        }

        Ok(BranchBatchReport {
            branches: results,
            promoted_branch_id,
            promoted_diff,
        })
    }

    /// Evaluates multiple parallel candidate branches against a declarative [`EvalSpec`]
    /// rubric, scores each candidate, selects the highest-scoring passing candidate,
    /// and optionally promotes the winning candidate's rootfs diff back onto `<bundle>`.
    pub fn run_eval(&self, bundle: &Path, spec: &EvalSpec) -> Result<EvalReport> {
        spec.policy.validate()?;
        self.preflight_audit()?;

        let mut seen_ids = BTreeSet::new();
        for candidate in &spec.candidates {
            validate_container_id(&candidate.id)?;
            if !seen_ids.insert(candidate.id.as_str()) {
                return Err(BoxletError::ContainerAlreadyExists {
                    id: candidate.id.clone(),
                });
            }
        }

        let base_spec = load_bundle_spec(bundle)?;
        if spec.candidates.is_empty() {
            return Ok(EvalReport {
                verdicts: Vec::new(),
                winning_branch_id: None,
                promoted: false,
                promoted_diff: None,
            });
        }

        let configured_rootfs = base_spec
            .root()
            .as_ref()
            .map(|r| r.path().clone())
            .unwrap_or_else(|| PathBuf::from("rootfs"));
        let source_rootfs = if configured_rootfs.is_absolute() {
            configured_rootfs
        } else {
            bundle.join(configured_rootfs)
        };

        let workspace = TempWorkspaceGuard::create(bundle)?;
        let snapshot_base = workspace.path().join("snapshots");
        let bundles_base = workspace.path().join("bundles");

        let snapshot = WorkspaceSnapshot::create("base", &source_rootfs, &snapshot_base)?;

        let mut prepared = Vec::with_capacity(spec.candidates.len());
        for candidate in &spec.candidates {
            let branch_bundle_dir = bundles_base.join(&candidate.id);
            let branch_rootfs_dir = snapshot.branch("rootfs", &branch_bundle_dir)?;
            let branch_spec = apply_branch_overrides(&base_spec, candidate);
            let config_path = branch_bundle_dir.join("config.json");
            branch_spec
                .save(&config_path)
                .map_err(|source| BoxletError::OciSpec {
                    path: config_path,
                    source,
                })?;
            let resolved = merge_policy_with_spec(&branch_spec, &spec.policy)?;
            prepared.push(PreparedBranch {
                branch_id: candidate.id.clone(),
                bundle_dir: branch_bundle_dir,
                rootfs_dir: branch_rootfs_dir,
                resolved,
            });
        }

        let results = execute_prepared_branches_bounded(
            &self.backend,
            &snapshot.manifest,
            &prepared,
            spec.policy.max_concurrency,
        )?;

        let verdicts: Vec<CandidateVerdict> = results
            .into_iter()
            .map(|branch_res| evaluate_candidate(&spec.rubric, branch_res))
            .collect();

        let winning_branch_id = select_winning_verdict(&verdicts).map(|v| v.branch_id.clone());

        let mut promoted = false;
        let mut promoted_diff = None;
        if spec.promote_winner {
            if let Some(ref win_id) = winning_branch_id {
                if let Some(winner_prepared) = prepared.iter().find(|p| &p.branch_id == win_id) {
                    let applied_diff = match snapshot
                        .promote_branch(&winner_prepared.rootfs_dir, &source_rootfs)
                    {
                        Ok(diff) => diff,
                        Err(err) => {
                            if !is_pre_sync_divergence_error(&err) {
                                let _ = snapshot.restore(&source_rootfs);
                            }
                            return Err(err);
                        }
                    };
                    promoted = true;
                    promoted_diff = Some(applied_diff);
                }
            }
        }

        if let Some(ref logger) = self.audit_logger {
            let succeeded_count = verdicts.iter().filter(|v| v.passed_rubric).count();
            logger.record(AuditEvent::BranchBatchCompleted {
                branch_count: verdicts.len(),
                succeeded_count,
                promoted_branch_id: if promoted {
                    winning_branch_id.clone()
                } else {
                    None
                },
                promoted_changes: promoted_diff.as_ref().map(FsDiff::total_changes),
            })?;
        }

        Ok(EvalReport {
            verdicts,
            winning_branch_id,
            promoted,
            promoted_diff,
        })
    }
}

fn execute_prepared_branches_bounded<B: RuntimeBackend>(
    backend: &B,
    base_manifest: &TreeManifest,
    prepared: &[PreparedBranch],
    max_concurrency: Option<usize>,
) -> Result<Vec<BranchExecutionResult>> {
    if let Some(0) = max_concurrency {
        return Err(BoxletError::InvalidPolicy {
            reason: "max_concurrency must be at least 1".to_string(),
        });
    }
    if prepared.is_empty() {
        return Ok(Vec::new());
    }

    let worker_count = max_concurrency
        .unwrap_or(prepared.len())
        .clamp(1, prepared.len());
    let next_idx = AtomicUsize::new(0);

    thread::scope(|scope| -> Result<Vec<BranchExecutionResult>> {
        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let next_idx_ref = &next_idx;
            handles.push(
                scope.spawn(move || -> Vec<(usize, Result<BranchExecutionResult>)> {
                    let mut local_out = Vec::new();
                    loop {
                        let idx = next_idx_ref.fetch_add(1, Ordering::Relaxed);
                        let Some(item) = prepared.get(idx) else {
                            break;
                        };
                        let res = (|| -> Result<BranchExecutionResult> {
                            let execution =
                                backend.run(&item.branch_id, &item.bundle_dir, &item.resolved)?;
                            let after_manifest = TreeManifest::capture(&item.rootfs_dir)?;
                            let fs_diff = base_manifest.diff(&after_manifest);
                            Ok(BranchExecutionResult {
                                branch_id: item.branch_id.clone(),
                                execution,
                                fs_diff,
                            })
                        })();
                        local_out.push((idx, res));
                    }
                    local_out
                }),
            );
        }

        let mut indexed = Vec::with_capacity(prepared.len());
        let mut first_err: Option<BoxletError> = None;
        for handle in handles {
            match handle.join() {
                Ok(worker_items) => {
                    for (idx, item_res) in worker_items {
                        match item_res {
                            Ok(branch_res) => indexed.push((idx, branch_res)),
                            Err(err) => {
                                if first_err.is_none() {
                                    first_err = Some(err);
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    if first_err.is_none() {
                        first_err = Some(BoxletError::Runtime {
                            subsystem: "engine",
                            message: "branch execution worker thread panicked".to_string(),
                        });
                    }
                }
            }
        }
        if let Some(err) = first_err {
            return Err(err);
        }
        indexed.sort_by_key(|(idx, _)| *idx);
        Ok(indexed.into_iter().map(|(_, res)| res).collect())
    })
}

fn is_pre_sync_divergence_error(err: &BoxletError) -> bool {
    matches!(
        err,
        BoxletError::StateStore { source, .. }
            if source.kind() == std::io::ErrorKind::InvalidData
    )
}

fn apply_branch_overrides(base_spec: &Spec, branch: &BranchSpec) -> Spec {
    let mut spec = base_spec.clone();

    let mut root = spec.root().clone().unwrap_or_default();
    root.set_path(PathBuf::from("rootfs"));
    root.set_readonly(Some(false));
    spec.set_root(Some(root));

    if branch.args.is_some() || branch.env.is_some() || branch.cwd.is_some() {
        let mut process = spec.process().clone().unwrap_or_default();
        if let Some(args) = &branch.args {
            process.set_args(Some(args.clone()));
        }
        if let Some(env_overrides) = &branch.env {
            let mut merged_env = process.env().clone().unwrap_or_default();
            for entry in env_overrides {
                if let Some((key, _)) = entry.split_once('=') {
                    let prefix = format!("{key}=");
                    if let Some(existing) = merged_env.iter_mut().find(|e| e.starts_with(&prefix)) {
                        *existing = entry.clone();
                        continue;
                    }
                }
                merged_env.push(entry.clone());
            }
            process.set_env(Some(merged_env));
        }
        if let Some(cwd) = &branch.cwd {
            process.set_cwd(PathBuf::from(cwd));
        }
        spec.set_process(Some(process));
    }

    spec
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::time::Duration;

    use oci_spec::runtime::Spec;

    use super::*;
    use crate::error::BoxletError;
    use crate::eval::EvalRubric;
    use crate::oci::state::ContainerStatus;
    use crate::oci::OCI_RUNTIME_VERSION;
    use crate::policy::{
        CleanupStatus, NetworkMode, PolicyViolations, ResolvedRunSpec, ResourceUsage,
        SeccompPolicy, DEFAULT_MAX_OUTPUT_BYTES,
    };

    #[derive(Default)]
    struct MockBackend {
        last_created_spec: Mutex<Option<Spec>>,
        last_run_spec: Mutex<Option<ResolvedRunSpec>>,
        containers: Mutex<BTreeMap<String, ContainerState>>,
        active_runs: AtomicUsize,
        peak_active_runs: AtomicUsize,
        simulated_delay: Option<Duration>,
    }

    impl MockBackend {
        fn insert_container(&self, id: &str, status: ContainerStatus, pid: Option<u32>) {
            if let Ok(mut guard) = self.containers.lock() {
                guard.insert(
                    id.to_string(),
                    ContainerState {
                        oci_version: OCI_RUNTIME_VERSION.to_string(),
                        id: id.to_string(),
                        status,
                        pid,
                        bundle: PathBuf::from("/bundle"),
                        annotations: BTreeMap::new(),
                    },
                );
            }
        }
    }

    impl RuntimeBackend for MockBackend {
        fn create(&self, id: &str, bundle: &Path, spec: &Spec) -> Result<ContainerState> {
            if let Ok(mut guard) = self.last_created_spec.lock() {
                *guard = Some(spec.clone());
            }
            let st = ContainerState {
                oci_version: OCI_RUNTIME_VERSION.to_string(),
                id: id.to_string(),
                status: ContainerStatus::Created,
                pid: Some(1001),
                bundle: bundle.to_path_buf(),
                annotations: BTreeMap::new(),
            };
            if let Ok(mut guard) = self.containers.lock() {
                guard.insert(id.to_string(), st.clone());
            }
            Ok(st)
        }

        fn start(&self, id: &str) -> Result<ContainerState> {
            let st = ContainerState {
                oci_version: OCI_RUNTIME_VERSION.to_string(),
                id: id.to_string(),
                status: ContainerStatus::Running,
                pid: Some(1001),
                bundle: PathBuf::from("/bundle"),
                annotations: BTreeMap::new(),
            };
            if let Ok(mut guard) = self.containers.lock() {
                guard.insert(id.to_string(), st.clone());
            }
            Ok(st)
        }

        fn state(&self, id: &str) -> Result<ContainerState> {
            if let Ok(guard) = self.containers.lock() {
                if let Some(st) = guard.get(id) {
                    return Ok(st.clone());
                }
            }
            Ok(ContainerState {
                oci_version: OCI_RUNTIME_VERSION.to_string(),
                id: id.to_string(),
                status: ContainerStatus::Stopped,
                pid: None,
                bundle: PathBuf::from("/bundle"),
                annotations: BTreeMap::new(),
            })
        }

        fn kill(&self, _id: &str, _signal: i32) -> Result<()> {
            Ok(())
        }

        fn delete(&self, id: &str, force: bool) -> Result<()> {
            if let Ok(mut guard) = self.containers.lock() {
                if let Some(existing) = guard.get(id) {
                    if !force && existing.status != ContainerStatus::Stopped {
                        return Err(BoxletError::ContainerNotStopped {
                            id: id.to_string(),
                            status: existing.status,
                        });
                    }
                    guard.remove(id);
                }
            }
            Ok(())
        }

        fn list(&self) -> Result<Vec<ContainerState>> {
            let guard = self.containers.lock().map_err(|_| BoxletError::Runtime {
                subsystem: "test",
                message: "MockBackend mutex poisoned".to_string(),
            })?;
            Ok(guard.values().cloned().collect())
        }

        fn run(
            &self,
            id: &str,
            bundle: &Path,
            resolved: &ResolvedRunSpec,
        ) -> Result<ExecutionResult> {
            let current_active = self.active_runs.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak_active_runs
                .fetch_max(current_active, Ordering::SeqCst);
            if let Some(delay) = self.simulated_delay {
                thread::sleep(delay);
            }

            if let Ok(mut guard) = self.last_run_spec.lock() {
                *guard = Some(resolved.clone());
            }

            let rootfs = bundle.join("rootfs");
            let args = resolved
                .oci_spec
                .process()
                .as_ref()
                .and_then(|p| p.args().clone())
                .unwrap_or_default();

            let mut exit_code = 0;
            if let Some(action) = args.first().map(String::as_str) {
                match action {
                    "branch-a-action" => {
                        let new_file = rootfs.join("src/candidate_a.rs");
                        fs::write(&new_file, b"pub fn a() {}\n").map_err(|source| {
                            BoxletError::StateStore {
                                path: new_file,
                                source,
                            }
                        })?;
                        let main_rs = rootfs.join("src/main.rs");
                        fs::write(&main_rs, b"fn main() { /* a */ }\n").map_err(|source| {
                            BoxletError::StateStore {
                                path: main_rs,
                                source,
                            }
                        })?;
                    }
                    "branch-b-action" => {
                        let readme = rootfs.join("README.md");
                        fs::remove_file(&readme).map_err(|source| BoxletError::StateStore {
                            path: readme,
                            source,
                        })?;
                    }
                    "branch-c-action" => {
                        let notes = rootfs.join("notes.txt");
                        fs::write(&notes, b"candidate c\n").map_err(|source| {
                            BoxletError::StateStore {
                                path: notes,
                                source,
                            }
                        })?;
                    }
                    "branch-fail-action" => {
                        let failed = rootfs.join("failed.txt");
                        fs::write(&failed, b"broken attempt\n").map_err(|source| {
                            BoxletError::StateStore {
                                path: failed,
                                source,
                            }
                        })?;
                        exit_code = 1;
                    }
                    "branch-win-action" => {
                        let winner = rootfs.join("winner.txt");
                        fs::write(&winner, b"winning patch\n").map_err(|source| {
                            BoxletError::StateStore {
                                path: winner,
                                source,
                            }
                        })?;
                        exit_code = 0;
                    }
                    "eval-cand-1-action" => {
                        let winner = rootfs.join("winner.txt");
                        fs::write(&winner, b"cand-1 patch\n").map_err(|source| {
                            BoxletError::StateStore {
                                path: winner,
                                source,
                            }
                        })?;
                        let protected = rootfs.join("etc/protected.conf");
                        fs::write(&protected, b"tampered=true\n").map_err(|source| {
                            BoxletError::StateStore {
                                path: protected,
                                source,
                            }
                        })?;
                        exit_code = 0;
                    }
                    _ => {}
                }
            }

            self.active_runs.fetch_sub(1, Ordering::SeqCst);

            Ok(ExecutionResult {
                container_id: id.to_string(),
                exit_code: Some(exit_code),
                stdout: format!("ran {id}\n").into_bytes(),
                stderr: Vec::new(),
                stdout_truncated: false,
                stderr_truncated: false,
                usage: ResourceUsage {
                    duration: Duration::from_millis(12),
                    memory_peak_bytes: Some(4096),
                    cpu_usage_usec: Some(500),
                    psi: None,
                },
                violations: PolicyViolations::default(),
                cleanup: CleanupStatus::Clean,
            })
        }
    }

    fn make_bundle() -> Result<tempfile::TempDir> {
        let dir = tempfile::tempdir().map_err(|source| BoxletError::StateStore {
            path: PathBuf::from("tempdir"),
            source,
        })?;
        let rootfs = dir.path().join("rootfs");
        fs::create_dir_all(rootfs.join("src")).map_err(|source| BoxletError::StateStore {
            path: rootfs.join("src"),
            source,
        })?;
        fs::write(rootfs.join("src/main.rs"), b"fn main() {}\n").map_err(|source| {
            BoxletError::StateStore {
                path: rootfs.join("src/main.rs"),
                source,
            }
        })?;
        fs::write(rootfs.join("README.md"), b"# Base\n").map_err(|source| {
            BoxletError::StateStore {
                path: rootfs.join("README.md"),
                source,
            }
        })?;

        let spec = Spec::default();
        spec.save(dir.path().join("config.json"))
            .map_err(|source| BoxletError::OciSpec {
                path: dir.path().join("config.json"),
                source,
            })?;
        Ok(dir)
    }

    #[test]
    fn engine_create_passes_oci_spec_verbatim() -> Result<()> {
        let bundle = make_bundle()?;
        let backend = MockBackend::default();
        let engine = Engine::new(backend);

        let st = engine.create("oci-1", bundle.path())?;
        assert_eq!(st.status, ContainerStatus::Created);
        assert_eq!(st.pid, Some(1001));
        Ok(())
    }

    #[test]
    fn engine_run_merges_policy_and_safe_defaults() -> Result<()> {
        let bundle = make_bundle()?;
        let engine = Engine::new(MockBackend::default());
        let policy = ExecutionPolicy {
            memory_bytes: Some(64 * 1024 * 1024),
            cpus: Some(0.5),
            ..ExecutionPolicy::default()
        };

        let result = engine.run("run-1", bundle.path(), &policy)?;
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.cleanup, CleanupStatus::Clean);

        let captured = engine
            .backend
            .last_run_spec
            .lock()
            .ok()
            .and_then(|g| g.clone());
        let Some(resolved) = captured else {
            return Err(BoxletError::Runtime {
                subsystem: "test",
                message: "expected MockBackend::run to capture ResolvedRunSpec".to_string(),
            });
        };
        assert_eq!(resolved.network, NetworkMode::None);
        assert!(resolved.no_new_privs);
        assert_eq!(resolved.seccomp, SeccompPolicy::DefaultDeny);
        assert_eq!(resolved.max_output_bytes, DEFAULT_MAX_OUTPUT_BYTES);
        assert_eq!(resolved.resources.memory_bytes, Some(64 * 1024 * 1024));
        assert_eq!(resolved.resources.cpu_quota_usec, Some(50_000));
        Ok(())
    }

    #[test]
    fn engine_rejects_invalid_container_id_before_backend() -> Result<()> {
        let bundle = make_bundle()?;
        let engine = Engine::new(MockBackend::default());
        let err = engine.create("../bad", bundle.path()).unwrap_err();
        assert!(matches!(err, BoxletError::InvalidContainerId { .. }));
        Ok(())
    }

    #[test]
    fn engine_run_branches_executes_parallel_specs_and_captures_diffs() -> Result<()> {
        let bundle = make_bundle()?;
        let before_base = TreeManifest::capture(&bundle.path().join("rootfs"))?;

        let engine = Engine::new(MockBackend::default());
        let branches = vec![
            BranchSpec::new("branch-a")
                .with_args(vec!["branch-a-action".to_string()])
                .with_env(vec!["CANDIDATE=a".to_string()])
                .with_cwd("/"),
            BranchSpec::new("branch-b").with_args(vec!["branch-b-action".to_string()]),
            BranchSpec::new("branch-c").with_args(vec!["branch-c-action".to_string()]),
        ];
        let policy = ExecutionPolicy {
            memory_bytes: Some(64 * 1024 * 1024),
            ..ExecutionPolicy::default()
        };

        let results = engine.run_branches(bundle.path(), &branches, &policy)?;
        assert_eq!(results.len(), 3);

        assert_eq!(results[0].branch_id, "branch-a");
        assert_eq!(results[0].execution.exit_code, Some(0));
        assert_eq!(
            results[0].fs_diff.added,
            vec![PathBuf::from("src/candidate_a.rs")]
        );
        assert_eq!(
            results[0].fs_diff.modified,
            vec![PathBuf::from("src/main.rs")]
        );
        assert!(results[0].fs_diff.deleted.is_empty());

        assert_eq!(results[1].branch_id, "branch-b");
        assert!(results[1].fs_diff.added.is_empty());
        assert!(results[1].fs_diff.modified.is_empty());
        assert_eq!(results[1].fs_diff.deleted, vec![PathBuf::from("README.md")]);

        assert_eq!(results[2].branch_id, "branch-c");
        assert_eq!(results[2].fs_diff.added, vec![PathBuf::from("notes.txt")]);
        assert!(results[2].fs_diff.modified.is_empty());
        assert!(results[2].fs_diff.deleted.is_empty());

        // Original bundle rootfs must remain untouched
        let after_base = TreeManifest::capture(&bundle.path().join("rootfs"))?;
        assert_eq!(before_base, after_base);
        Ok(())
    }

    #[test]
    fn engine_run_branches_rejects_duplicate_or_invalid_branch_ids() -> Result<()> {
        let bundle = make_bundle()?;
        let engine = Engine::new(MockBackend::default());
        let policy = ExecutionPolicy::default();

        let dup_specs = vec![BranchSpec::new("dup-1"), BranchSpec::new("dup-1")];
        let dup_err = engine
            .run_branches(bundle.path(), &dup_specs, &policy)
            .unwrap_err();
        assert!(matches!(
            dup_err,
            BoxletError::ContainerAlreadyExists { id } if id == "dup-1"
        ));

        let bad_specs = vec![BranchSpec::new("../escape")];
        let bad_err = engine
            .run_branches(bundle.path(), &bad_specs, &policy)
            .unwrap_err();
        assert!(matches!(bad_err, BoxletError::InvalidContainerId { .. }));
        Ok(())
    }

    #[test]
    fn engine_run_branches_with_promotion_promotes_first_passing_branch() -> Result<()> {
        let bundle = make_bundle()?;
        let engine = Engine::new(MockBackend::default());
        let specs = vec![
            BranchSpec::new("branch-1").with_args(vec!["branch-fail-action".to_string()]),
            BranchSpec::new("branch-2").with_args(vec!["branch-win-action".to_string()]),
        ];
        let policy = ExecutionPolicy::default();

        let report = engine.run_branches_with_promotion(bundle.path(), &specs, &policy, true)?;
        assert_eq!(report.branches.len(), 2);
        assert_eq!(report.branches[0].execution.exit_code, Some(1));
        assert_eq!(report.branches[1].execution.exit_code, Some(0));
        assert_eq!(report.promoted_branch_id, Some("branch-2".to_string()));
        assert!(bundle.path().join("rootfs/winner.txt").exists());
        assert!(!bundle.path().join("rootfs/failed.txt").exists());
        assert_eq!(
            report.promoted_diff.as_ref().map(|d| d.added.clone()),
            Some(vec![PathBuf::from("winner.txt")])
        );
        Ok(())
    }

    #[test]
    fn engine_with_audit_logger_records_run_and_branch_events() -> Result<()> {
        let bundle = make_bundle()?;
        let log_dir = tempfile::tempdir().map_err(|source| BoxletError::StateStore {
            path: PathBuf::from("tempdir"),
            source,
        })?;
        let logger = JsonlAuditLogger::new(log_dir.path().join("audit.jsonl"));
        let engine = Engine::new(MockBackend::default()).with_audit_logger(logger.clone());
        let policy = ExecutionPolicy::default();

        let run_res = engine.run("audit-run-1", bundle.path(), &policy)?;
        assert_eq!(run_res.exit_code, Some(0));

        let specs = vec![
            BranchSpec::new("branch-1").with_args(vec!["branch-fail-action".to_string()]),
            BranchSpec::new("branch-2").with_args(vec!["branch-win-action".to_string()]),
        ];
        let report = engine.run_branches_with_promotion(bundle.path(), &specs, &policy, true)?;
        assert_eq!(report.promoted_branch_id, Some("branch-2".to_string()));

        let records = logger.read_all()?;
        assert_eq!(records.len(), 2);
        assert!(matches!(
            &records[0].event,
            AuditEvent::ContainerRunCompleted {
                container_id,
                exit_code: Some(0),
                ..
            } if container_id == "audit-run-1"
        ));
        assert!(matches!(
            &records[1].event,
            AuditEvent::BranchBatchCompleted {
                branch_count: 2,
                succeeded_count: 1,
                promoted_branch_id: Some(winner),
                promoted_changes: Some(1),
            } if winner == "branch-2"
        ));
        Ok(())
    }

    #[test]
    fn engine_list_and_prune_remove_stopped_and_respect_force_flag() -> Result<()> {
        let log_dir = tempfile::tempdir().map_err(|source| BoxletError::StateStore {
            path: PathBuf::from("tempdir"),
            source,
        })?;
        let logger = JsonlAuditLogger::new(log_dir.path().join("audit.jsonl"));
        let backend = MockBackend::default();
        backend.insert_container("box-active", ContainerStatus::Running, Some(2002));
        backend.insert_container("box-created", ContainerStatus::Created, Some(2001));
        backend.insert_container("box-stopped-1", ContainerStatus::Stopped, None);
        backend.insert_container("box-stopped-2", ContainerStatus::Stopped, None);

        let engine = Engine::new(backend).with_audit_logger(logger.clone());

        let initial = engine.list()?;
        let initial_ids: Vec<&str> = initial.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(
            initial_ids,
            vec![
                "box-active",
                "box-created",
                "box-stopped-1",
                "box-stopped-2"
            ]
        );

        let prune_soft = engine.prune(false)?;
        assert_eq!(
            prune_soft.removed_containers,
            vec!["box-stopped-1".to_string(), "box-stopped-2".to_string()]
        );
        assert_eq!(
            prune_soft.skipped_active_containers,
            vec!["box-active".to_string(), "box-created".to_string()]
        );

        let after_soft = engine.list()?;
        let after_soft_ids: Vec<&str> = after_soft.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(after_soft_ids, vec!["box-active", "box-created"]);

        let prune_force = engine.prune(true)?;
        assert_eq!(
            prune_force.removed_containers,
            vec!["box-active".to_string(), "box-created".to_string()]
        );
        assert!(prune_force.skipped_active_containers.is_empty());
        assert!(engine.list()?.is_empty());

        let records = logger.read_all()?;
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].event,
            AuditEvent::ContainersPruned {
                removed_count: 2,
                skipped_active_count: 2,
                force: false,
            }
        );
        assert_eq!(
            records[1].event,
            AuditEvent::ContainersPruned {
                removed_count: 2,
                skipped_active_count: 0,
                force: true,
            }
        );
        Ok(())
    }

    #[test]
    fn engine_run_eval_enforces_rubric_guardrails_and_promotes_winning_candidate() -> Result<()> {
        let bundle = make_bundle()?;
        let etc_dir = bundle.path().join("rootfs/etc");
        fs::create_dir_all(&etc_dir).map_err(|source| BoxletError::StateStore {
            path: etc_dir.clone(),
            source,
        })?;
        let protected_path = etc_dir.join("protected.conf");
        fs::write(&protected_path, b"immutable=1\n").map_err(|source| BoxletError::StateStore {
            path: protected_path.clone(),
            source,
        })?;

        let log_dir = tempfile::tempdir().map_err(|source| BoxletError::StateStore {
            path: PathBuf::from("tempdir"),
            source,
        })?;
        let logger = JsonlAuditLogger::new(log_dir.path().join("audit.jsonl"));
        let engine = Engine::new(MockBackend::default()).with_audit_logger(logger.clone());

        let eval_spec = EvalSpec {
            policy: ExecutionPolicy::default(),
            rubric: EvalRubric {
                require_exit_zero: true,
                required_stdout_contains: Vec::new(),
                forbidden_stderr_contains: Vec::new(),
                required_added_paths: vec![PathBuf::from("winner.txt")],
                forbidden_modified_paths: vec![PathBuf::from("etc/protected.conf")],
                max_changed_files: Some(2),
            },
            candidates: vec![
                BranchSpec::new("cand-1").with_args(vec!["eval-cand-1-action".to_string()]),
                BranchSpec::new("cand-2").with_args(vec!["branch-fail-action".to_string()]),
                BranchSpec::new("cand-3").with_args(vec!["branch-win-action".to_string()]),
            ],
            promote_winner: true,
        };

        let report = engine.run_eval(bundle.path(), &eval_spec)?;
        assert_eq!(report.verdicts.len(), 3);
        assert!(!report.verdicts[0].passed_rubric);
        assert!(!report.verdicts[1].passed_rubric);
        assert!(report.verdicts[2].passed_rubric);
        assert_eq!(report.winning_branch_id, Some("cand-3".to_string()));
        assert!(report.promoted);

        assert!(bundle.path().join("rootfs/winner.txt").exists());
        let protected_after =
            fs::read(&protected_path).map_err(|source| BoxletError::StateStore {
                path: protected_path,
                source,
            })?;
        assert_eq!(protected_after, b"immutable=1\n");

        let records = logger.read_all()?;
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].event,
            AuditEvent::BranchBatchCompleted {
                branch_count: 3,
                succeeded_count: 1,
                promoted_branch_id: Some("cand-3".to_string()),
                promoted_changes: Some(1),
            }
        );
        Ok(())
    }

    #[test]
    fn engine_run_branches_respects_max_concurrency_limit() -> Result<()> {
        let bundle = make_bundle()?;
        let backend = MockBackend {
            simulated_delay: Some(Duration::from_millis(10)),
            ..MockBackend::default()
        };
        let engine = Engine::new(backend);

        let branches: Vec<BranchSpec> = (0..6)
            .map(|idx| BranchSpec::new(format!("branch-{idx}")))
            .collect();
        let policy = ExecutionPolicy {
            max_concurrency: Some(2),
            ..ExecutionPolicy::default()
        };

        let results = engine.run_branches(bundle.path(), &branches, &policy)?;
        assert_eq!(results.len(), 6);
        for (idx, res) in results.iter().enumerate() {
            assert_eq!(res.branch_id, format!("branch-{idx}"));
            assert_eq!(res.execution.exit_code, Some(0));
        }

        let peak = engine.backend.peak_active_runs.load(Ordering::SeqCst);
        assert!(
            (1..=2).contains(&peak),
            "expected peak_active_runs in 1..=2, got {peak}"
        );
        assert_eq!(engine.backend.active_runs.load(Ordering::SeqCst), 0);

        let zero_policy = ExecutionPolicy {
            max_concurrency: Some(0),
            ..ExecutionPolicy::default()
        };
        let err = engine
            .run_branches(bundle.path(), &branches, &zero_policy)
            .unwrap_err();
        assert!(matches!(err, BoxletError::InvalidPolicy { .. }));
        Ok(())
    }

    #[test]
    fn engine_run_benchmark_computes_latency_percentiles_and_markdown_table() -> Result<()> {
        let bundle = make_bundle()?;
        let engine = Engine::new(MockBackend::default());
        let cfg = crate::bench::BenchmarkConfig {
            iterations: 3,
            warmup: 1,
            branches_per_iter: 2,
            policy: ExecutionPolicy::default(),
        };

        let report = engine.run_benchmark(bundle.path(), &cfg)?;
        assert_eq!(report.iterations, 3);
        assert_eq!(report.warmup, 1);
        assert_eq!(report.branches_per_iter, 2);
        assert_eq!(report.run_latency_us.samples, 3);
        assert_eq!(report.snapshot_diff_latency_us.samples, 3);
        assert_eq!(report.branch_batch_latency_us.samples, 3);
        assert_eq!(report.peak_memory_bytes, Some(4096));

        let md = report.to_markdown_table();
        assert!(md.contains("sandbox_run"));
        assert!(md.contains("snapshot_diff"));
        assert!(md.contains("parallel_branch_batch"));
        Ok(())
    }
}
