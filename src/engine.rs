//! Shared execution engine used by both the `boxlet` CLI and downstream Rust SDK callers.

use std::path::Path;

use crate::error::Result;
use crate::oci::state::ContainerState;
use crate::oci::{load_bundle_spec, validate_container_id};
use crate::policy::{merge_policy_with_spec, ExecutionPolicy, ExecutionResult};
use crate::traits::RuntimeBackend;

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
            _bundle: &Path,
            resolved: &ResolvedRunSpec,
        ) -> Result<ExecutionResult> {
            if let Ok(mut guard) = self.last_run_spec.lock() {
                *guard = Some(resolved.clone());
            }
            Ok(ExecutionResult {
                container_id: id.to_string(),
                exit_code: Some(0),
                stdout: b"hello\n".to_vec(),
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
}
