//! Shared execution engine used by both the `boxlet` CLI and downstream Rust SDK callers.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use oci_spec::runtime::Spec;
use serde::{Deserialize, Serialize};

use crate::error::{BoxletError, Result};
use crate::oci::state::ContainerState;
use crate::oci::{load_bundle_spec, validate_container_id};
use crate::policy::{merge_policy_with_spec, ExecutionPolicy, ExecutionResult, ResolvedRunSpec};
use crate::snapshot::{FsDiff, TreeManifest, WorkspaceSnapshot};
use crate::traits::RuntimeBackend;

/// Monotonic counter used to disambiguate concurrent temporary branch workspaces.
static WORKSPACE_COUNTER: AtomicU64 = AtomicU64::new(0);

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
}

impl<B: RuntimeBackend> Engine<B> {
    /// Constructs a new [`Engine`] backed by `backend`.
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Creates a container from `<bundle>/config.json` **verbatim** (no `boxlet run` defaults injected).
    pub fn create(&self, id: &str, bundle: &Path) -> Result<ContainerState> {
        validate_container_id(id)?;
        let spec = load_bundle_spec(bundle)?;
        self.backend.create(id, bundle, &spec)
    }

    /// Starts a previously created container (`Created -> Running`).
    pub fn start(&self, id: &str) -> Result<ContainerState> {
        validate_container_id(id)?;
        self.backend.start(id)
    }

    /// Queries the current OCI state of container `id`.
    pub fn state(&self, id: &str) -> Result<ContainerState> {
        validate_container_id(id)?;
        self.backend.state(id)
    }

    /// Sends OS signal `signal` to container `id`.
    pub fn kill(&self, id: &str, signal: i32) -> Result<()> {
        validate_container_id(id)?;
        self.backend.kill(id, signal)
    }

    /// Deletes container `id` (requires `Stopped` unless `force` is true).
    pub fn delete(&self, id: &str, force: bool) -> Result<()> {
        validate_container_id(id)?;
        self.backend.delete(id, force)
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
        let base_spec = load_bundle_spec(bundle)?;
        let resolved = merge_policy_with_spec(&base_spec, policy)?;
        self.backend.run(id, bundle, &resolved)
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

        let results = thread::scope(|scope| -> Result<Vec<BranchExecutionResult>> {
            let mut handles = Vec::with_capacity(prepared.len());
            for item in &prepared {
                let backend = &self.backend;
                let base_manifest = &snapshot.manifest;
                handles.push(scope.spawn(move || -> Result<BranchExecutionResult> {
                    let execution =
                        backend.run(&item.branch_id, &item.bundle_dir, &item.resolved)?;
                    let after_manifest = TreeManifest::capture(&item.rootfs_dir)?;
                    let fs_diff = base_manifest.diff(&after_manifest);
                    Ok(BranchExecutionResult {
                        branch_id: item.branch_id.clone(),
                        execution,
                        fs_diff,
                    })
                }));
            }

            let mut out = Vec::with_capacity(handles.len());
            let mut first_err: Option<BoxletError> = None;
            for handle in handles {
                match handle.join() {
                    Ok(Ok(branch_res)) => out.push(branch_res),
                    Ok(Err(err)) => {
                        if first_err.is_none() {
                            first_err = Some(err);
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
            Ok(out)
        })?;

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
                            let _ = snapshot.restore(&source_rootfs);
                            return Err(err);
                        }
                    };
                promoted_branch_id = Some(winner_res.branch_id.clone());
                promoted_diff = Some(applied_diff);
            }
        }

        Ok(BranchBatchReport {
            branches: results,
            promoted_branch_id,
            promoted_diff,
        })
    }
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
    }

    impl RuntimeBackend for MockBackend {
        fn create(&self, id: &str, bundle: &Path, spec: &Spec) -> Result<ContainerState> {
            if let Ok(mut guard) = self.last_created_spec.lock() {
                *guard = Some(spec.clone());
            }
            Ok(ContainerState {
                oci_version: OCI_RUNTIME_VERSION.to_string(),
                id: id.to_string(),
                status: ContainerStatus::Created,
                pid: Some(1001),
                bundle: bundle.to_path_buf(),
                annotations: BTreeMap::new(),
            })
        }

        fn start(&self, id: &str) -> Result<ContainerState> {
            Ok(ContainerState {
                oci_version: OCI_RUNTIME_VERSION.to_string(),
                id: id.to_string(),
                status: ContainerStatus::Running,
                pid: Some(1001),
                bundle: PathBuf::from("/bundle"),
                annotations: BTreeMap::new(),
            })
        }

        fn state(&self, id: &str) -> Result<ContainerState> {
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

        fn delete(&self, _id: &str, _force: bool) -> Result<()> {
            Ok(())
        }

        fn run(
            &self,
            id: &str,
            bundle: &Path,
            resolved: &ResolvedRunSpec,
        ) -> Result<ExecutionResult> {
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
                    _ => {}
                }
            }

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
}
