//! OCI container lifecycle state machine and `flock`-guarded atomic state store.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{BoxletError, Result};
use crate::oci::{validate_container_id, OCI_RUNTIME_VERSION};

/// Default root directory for container state persistence (`--root`).
pub const DEFAULT_STATE_ROOT: &str = "/run/boxlet";

/// OCI container lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerStatus {
    /// Container is being created (`boxlet create` in progress).
    Creating,
    /// Container namespaces/rootfs are prepared; waiting on `boxlet start`.
    Created,
    /// Container workload process is running.
    Running,
    /// Container workload has exited or been killed.
    Stopped,
}

impl ContainerStatus {
    /// Returns `true` if transitioning from `self` to `next` is valid under the OCI lifecycle.
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Creating, Self::Created | Self::Stopped)
                | (Self::Created, Self::Running | Self::Stopped)
                | (Self::Running, Self::Stopped)
        )
    }
}

impl fmt::Display for ContainerStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Creating => "creating",
            Self::Created => "created",
            Self::Running => "running",
            Self::Stopped => "stopped",
        };
        f.write_str(label)
    }
}

/// OCI-compliant runtime state persisted at `<root>/<id>/state.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerState {
    /// OCI runtime specification version.
    #[serde(rename = "ociVersion")]
    pub oci_version: String,
    /// Unique container identifier.
    pub id: String,
    /// Current lifecycle status.
    pub status: ContainerStatus,
    /// Host-namespace PID of container PID 1 (present in `Created` and `Running`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Absolute path to the OCI bundle directory.
    pub bundle: PathBuf,
    /// Optional OCI annotations.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

/// Manages per-container state files under `<root>/<id>/state.json` using
/// exclusive file locks and atomic write-and-rename updates.
#[derive(Debug, Clone)]
pub struct StateStore {
    root: PathBuf,
}

impl StateStore {
    /// Creates a new state store rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Returns the root directory of this state store.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns `<root>/<id>`.
    pub fn container_dir(&self, id: &str) -> Result<PathBuf> {
        validate_container_id(id)?;
        Ok(self.root.join(id))
    }

    /// Creates `<root>/<id>` and writes the initial `Creating` state atomically.
    pub fn init_creating(
        &self,
        id: &str,
        bundle: PathBuf,
        annotations: BTreeMap<String, String>,
    ) -> Result<ContainerState> {
        let dir = self.container_dir(id)?;
        fs::create_dir_all(&self.root).map_err(|source| BoxletError::StateStore {
            path: self.root.clone(),
            source,
        })?;

        match fs::create_dir(&dir) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(BoxletError::ContainerAlreadyExists { id: id.to_string() });
            }
            Err(source) => {
                return Err(BoxletError::StateStore { path: dir, source });
            }
        }

        let _lock = self.acquire_lock(&dir)?;
        let state = ContainerState {
            oci_version: OCI_RUNTIME_VERSION.to_string(),
            id: id.to_string(),
            status: ContainerStatus::Creating,
            pid: None,
            bundle,
            annotations,
        };
        write_state_atomic(&dir, &state)?;
        Ok(state)
    }

    /// Loads the current state of container `id`.
    pub fn load(&self, id: &str) -> Result<ContainerState> {
        let dir = self.container_dir(id)?;
        if !dir.exists() {
            return Err(BoxletError::ContainerNotFound { id: id.to_string() });
        }
        let _lock = self.acquire_lock(&dir)?;
        read_state(&dir, id)
    }

    /// Transitions container `id` to `next_status` (optionally updating `pid`) atomically.
    pub fn transition(
        &self,
        id: &str,
        next_status: ContainerStatus,
        pid: Option<u32>,
    ) -> Result<ContainerState> {
        let dir = self.container_dir(id)?;
        if !dir.exists() {
            return Err(BoxletError::ContainerNotFound { id: id.to_string() });
        }
        let _lock = self.acquire_lock(&dir)?;
        let mut current = read_state(&dir, id)?;

        if !current.status.can_transition_to(next_status) {
            return Err(BoxletError::InvalidStateTransition {
                id: id.to_string(),
                from: current.status,
                to: next_status,
            });
        }

        current.status = next_status;
        if let Some(p) = pid {
            current.pid = Some(p);
        }
        if next_status == ContainerStatus::Stopped {
            current.pid = None;
        }

        write_state_atomic(&dir, &current)?;
        Ok(current)
    }

    /// Removes container `id`'s state directory. Fails unless status is `Stopped` or `force` is true.
    pub fn delete(&self, id: &str, force: bool) -> Result<()> {
        let dir = self.container_dir(id)?;
        if !dir.exists() {
            return Err(BoxletError::ContainerNotFound { id: id.to_string() });
        }

        let lock = self.acquire_lock(&dir)?;
        let current = read_state(&dir, id)?;
        if !force && current.status != ContainerStatus::Stopped {
            return Err(BoxletError::ContainerNotStopped {
                id: id.to_string(),
                status: current.status,
            });
        }
        drop(lock);

        fs::remove_dir_all(&dir).map_err(|source| BoxletError::StateStore { path: dir, source })
    }

    fn acquire_lock(&self, dir: &Path) -> Result<File> {
        let lock_path = dir.join(".lock");
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|source| BoxletError::StateStore {
                path: lock_path.clone(),
                source,
            })?;
        file.lock().map_err(|source| BoxletError::StateStore {
            path: lock_path,
            source,
        })?;
        Ok(file)
    }
}

fn read_state(dir: &Path, id: &str) -> Result<ContainerState> {
    let state_path = dir.join("state.json");
    let raw = fs::read_to_string(&state_path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            BoxletError::ContainerNotFound { id: id.to_string() }
        } else {
            BoxletError::StateStore {
                path: state_path.clone(),
                source,
            }
        }
    })?;
    Ok(serde_json::from_str(&raw)?)
}

fn write_state_atomic(dir: &Path, state: &ContainerState) -> Result<()> {
    let state_path = dir.join("state.json");
    let tmp_path = dir.join("state.json.tmp");
    let bytes = serde_json::to_vec_pretty(state)?;

    let mut tmp = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&tmp_path)
        .map_err(|source| BoxletError::StateStore {
            path: tmp_path.clone(),
            source,
        })?;
    tmp.write_all(&bytes)
        .map_err(|source| BoxletError::StateStore {
            path: tmp_path.clone(),
            source,
        })?;
    tmp.sync_all().map_err(|source| BoxletError::StateStore {
        path: tmp_path.clone(),
        source,
    })?;
    drop(tmp);

    fs::rename(&tmp_path, &state_path).map_err(|source| BoxletError::StateStore {
        path: state_path,
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> Result<(tempfile::TempDir, StateStore)> {
        let dir = tempfile::tempdir().map_err(|source| BoxletError::StateStore {
            path: PathBuf::from("tempdir"),
            source,
        })?;
        let store = StateStore::new(dir.path().join("state-root"));
        Ok((dir, store))
    }

    #[test]
    fn valid_oci_lifecycle_transitions_persist_and_delete() -> Result<()> {
        let (_tmp, store) = test_store()?;
        let s0 = store.init_creating("box-1", PathBuf::from("/bundle"), BTreeMap::new())?;
        assert_eq!(s0.status, ContainerStatus::Creating);
        assert_eq!(s0.pid, None);

        let s1 = store.transition("box-1", ContainerStatus::Created, Some(4242))?;
        assert_eq!(s1.status, ContainerStatus::Created);
        assert_eq!(s1.pid, Some(4242));

        let s2 = store.transition("box-1", ContainerStatus::Running, None)?;
        assert_eq!(s2.status, ContainerStatus::Running);
        assert_eq!(s2.pid, Some(4242));

        // Cannot delete running container without force
        assert!(matches!(
            store.delete("box-1", false),
            Err(BoxletError::ContainerNotStopped { .. })
        ));

        let s3 = store.transition("box-1", ContainerStatus::Stopped, None)?;
        assert_eq!(s3.status, ContainerStatus::Stopped);
        assert_eq!(s3.pid, None);

        let reloaded = store.load("box-1")?;
        assert_eq!(reloaded, s3);

        store.delete("box-1", false)?;
        assert!(matches!(
            store.load("box-1"),
            Err(BoxletError::ContainerNotFound { .. })
        ));
        Ok(())
    }

    #[test]
    fn invalid_transitions_and_duplicate_ids_are_rejected() -> Result<()> {
        let (_tmp, store) = test_store()?;
        store.init_creating("box-2", PathBuf::from("/bundle"), BTreeMap::new())?;

        // Duplicate create rejected
        assert!(matches!(
            store.init_creating("box-2", PathBuf::from("/bundle"), BTreeMap::new()),
            Err(BoxletError::ContainerAlreadyExists { .. })
        ));

        // Creating -> Running directly is invalid (must pass through Created)
        assert!(matches!(
            store.transition("box-2", ContainerStatus::Running, None),
            Err(BoxletError::InvalidStateTransition {
                from: ContainerStatus::Creating,
                to: ContainerStatus::Running,
                ..
            })
        ));

        // Force delete works even in Creating state
        store.delete("box-2", true)?;
        Ok(())
    }
}
