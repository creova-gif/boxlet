//! Deterministic filesystem tree manifests, diffs, and copy-on-write workspace snapshots.
//!
//! Provides the portable V2 foundation described in `docs/adr/002-filesystem-snapshots-and-diffing.md`:
//! capturing a base rootfs into a [`WorkspaceSnapshot`], branching it into `N` isolated sandbox
//! root directories, and computing exact [`FsDiff`]s (`added`, `modified`, `deleted`) after
//! parallel agent runs complete.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{BoxletError, Result};
use crate::oci::validate_container_id;

/// Internal pivot directory skipped during rootfs manifest capture and snapshot copies.
const OLD_ROOT_DIR_NAME: &str = ".boxlet_old_root";

/// 64-bit FNV-1a offset basis.
const FNV1A_64_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;

/// 64-bit FNV-1a prime.
const FNV1A_64_PRIME: u64 = 0x0100_0000_01b3;

/// Classification of a filesystem entry inside a [`TreeManifest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
}

/// Deterministic metadata recorded for a single relative path in a [`TreeManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryMetadata {
    /// Kind of filesystem entry (`File`, `Directory`, or `Symlink`).
    pub kind: EntryKind,
    /// Logical byte size (`0` for directories, byte length for regular files and symlinks).
    pub size: u64,
    /// Lower 12 POSIX permission bits (`mode & 0o7777`).
    pub mode: u32,
    /// 64-bit FNV-1a digest of file contents for regular files or link target path for symlinks (`None` for directories).
    pub fnv1a64: Option<u64>,
}

/// Alias for [`EntryMetadata`] referenced in architecture documentation.
pub type FileEntryMetadata = EntryMetadata;

/// Deterministic, ordered snapshot of every entry inside a root filesystem directory.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeManifest {
    /// Map from root-relative path to [`EntryMetadata`], ordered lexicographically.
    pub entries: BTreeMap<PathBuf, EntryMetadata>,
}

/// Structured filesystem diff between two [`TreeManifest`] snapshots.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsDiff {
    /// Relative paths present in the target manifest that did not exist in the base manifest.
    pub added: Vec<PathBuf>,
    /// Relative paths present in both manifests whose [`EntryMetadata`] changed.
    pub modified: Vec<PathBuf>,
    /// Relative paths present in the base manifest that were removed from the target manifest.
    pub deleted: Vec<PathBuf>,
}

impl FsDiff {
    /// Returns `true` if no entries were added, modified, or deleted.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.modified.is_empty() && self.deleted.is_empty()
    }

    /// Returns the total number of added, modified, and deleted paths.
    pub fn total_changes(&self) -> usize {
        self.added.len() + self.modified.len() + self.deleted.len()
    }
}

impl TreeManifest {
    /// Recursively walks `root` deterministically and captures a [`TreeManifest`].
    ///
    /// Symbolic links are inspected via `symlink_metadata` without following targets outside
    /// `root`, regular files are hashed with 64-bit FNV-1a, and `.boxlet_old_root` is skipped.
    pub fn capture(root: &Path) -> Result<Self> {
        if !root.exists() {
            return Err(BoxletError::StateStore {
                path: root.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "snapshot root directory does not exist",
                ),
            });
        }

        let mut entries = BTreeMap::new();
        capture_dir_recursive(root, root, &mut entries)?;
        Ok(Self { entries })
    }

    /// Computes the deterministic [`FsDiff`] from `self` (before) to `after`.
    pub fn diff(&self, after: &TreeManifest) -> FsDiff {
        let mut added = Vec::new();
        let mut modified = Vec::new();
        let mut deleted = Vec::new();

        for (path, before_meta) in &self.entries {
            match after.entries.get(path) {
                None => deleted.push(path.clone()),
                Some(after_meta) if after_meta != before_meta => modified.push(path.clone()),
                Some(_) => {}
            }
        }

        for path in after.entries.keys() {
            if !self.entries.contains_key(path) {
                added.push(path.clone());
            }
        }

        FsDiff {
            added,
            modified,
            deleted,
        }
    }
}

/// Immutable checkpoint of a workspace rootfs that can spawn isolated writable branches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceSnapshot {
    /// Validated unique identifier for this snapshot.
    pub id: String,
    /// Directory holding the checkpointed base rootfs contents.
    pub snapshot_dir: PathBuf,
    /// Deterministic manifest captured when the snapshot was created.
    pub manifest: TreeManifest,
}

impl WorkspaceSnapshot {
    /// Creates a new [`WorkspaceSnapshot`] by copying `source_rootfs` into `<snapshot_base>/<id>`
    /// and capturing its initial [`TreeManifest`].
    pub fn create(
        id: impl Into<String>,
        source_rootfs: &Path,
        snapshot_base: &Path,
    ) -> Result<Self> {
        let id = id.into();
        validate_container_id(&id)?;

        if !source_rootfs.exists() {
            return Err(BoxletError::StateStore {
                path: source_rootfs.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "source rootfs directory does not exist",
                ),
            });
        }

        let snapshot_dir = snapshot_base.join(&id);
        ensure_not_nested(source_rootfs, &snapshot_dir)?;

        fs::create_dir_all(snapshot_base).map_err(|source| BoxletError::StateStore {
            path: snapshot_base.to_path_buf(),
            source,
        })?;

        match fs::create_dir(&snapshot_dir) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(BoxletError::ContainerAlreadyExists { id });
            }
            Err(source) => {
                return Err(BoxletError::StateStore {
                    path: snapshot_dir,
                    source,
                });
            }
        }

        let manifest = match copy_tree_recursive(source_rootfs, &snapshot_dir, true)
            .and_then(|()| TreeManifest::capture(&snapshot_dir))
        {
            Ok(manifest) => manifest,
            Err(err) => {
                let _ = fs::remove_dir_all(&snapshot_dir);
                return Err(err);
            }
        };

        Ok(Self {
            id,
            snapshot_dir,
            manifest,
        })
    }

    /// Creates an isolated writable branch of this snapshot at `<branch_dest>/<branch_id>`
    /// and returns the resulting branch rootfs path.
    pub fn branch(&self, branch_id: &str, branch_dest: &Path) -> Result<PathBuf> {
        validate_container_id(branch_id)?;

        let branch_path = branch_dest.join(branch_id);
        ensure_not_nested(&self.snapshot_dir, &branch_path)?;

        fs::create_dir_all(branch_dest).map_err(|source| BoxletError::StateStore {
            path: branch_dest.to_path_buf(),
            source,
        })?;

        match fs::create_dir(&branch_path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(BoxletError::ContainerAlreadyExists {
                    id: branch_id.to_string(),
                });
            }
            Err(source) => {
                return Err(BoxletError::StateStore {
                    path: branch_path,
                    source,
                });
            }
        }

        if let Err(err) = copy_tree_recursive(&self.snapshot_dir, &branch_path, true) {
            let _ = fs::remove_dir_all(&branch_path);
            return Err(err);
        }
        Ok(branch_path)
    }
}

fn resolve_existing_prefix(path: &Path) -> Result<PathBuf> {
    let mut current = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| BoxletError::StateStore {
                path: path.to_path_buf(),
                source,
            })?
            .join(path)
    };
    let mut tail = Vec::new();
    while !current.exists() {
        if let Some(name) = current.file_name() {
            tail.push(name.to_os_string());
        }
        if !current.pop() {
            break;
        }
    }
    let mut resolved = fs::canonicalize(&current).map_err(|source| BoxletError::StateStore {
        path: current,
        source,
    })?;
    for part in tail.into_iter().rev() {
        resolved.push(part);
    }
    Ok(resolved)
}

fn ensure_not_nested(src_root: &Path, dst_root: &Path) -> Result<()> {
    let canon_src = fs::canonicalize(src_root).map_err(|source| BoxletError::StateStore {
        path: src_root.to_path_buf(),
        source,
    })?;
    let resolved_dst = resolve_existing_prefix(dst_root)?;
    if resolved_dst.starts_with(&canon_src) {
        return Err(BoxletError::StateStore {
            path: dst_root.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "destination directory cannot be inside source rootfs directory",
            ),
        });
    }
    Ok(())
}

fn capture_dir_recursive(
    root: &Path,
    current: &Path,
    entries: &mut BTreeMap<PathBuf, EntryMetadata>,
) -> Result<()> {
    let read_dir = fs::read_dir(current).map_err(|source| BoxletError::StateStore {
        path: current.to_path_buf(),
        source,
    })?;

    let mut dir_entries = Vec::new();
    for item in read_dir {
        let entry = item.map_err(|source| BoxletError::StateStore {
            path: current.to_path_buf(),
            source,
        })?;
        dir_entries.push(entry);
    }
    dir_entries.sort_by_key(|e| e.file_name());

    for entry in dir_entries {
        let path = entry.path();
        let rel_path = match path.strip_prefix(root) {
            Ok(rel) => rel.to_path_buf(),
            Err(_) => continue,
        };

        if rel_path.as_os_str() == OLD_ROOT_DIR_NAME {
            continue;
        }

        let meta = fs::symlink_metadata(&path).map_err(|source| BoxletError::StateStore {
            path: path.clone(),
            source,
        })?;
        let file_type = meta.file_type();
        let mode = extract_mode(&meta);

        if file_type.is_dir() {
            entries.insert(
                rel_path,
                EntryMetadata {
                    kind: EntryKind::Directory,
                    size: 0,
                    mode,
                    fnv1a64: None,
                },
            );
            capture_dir_recursive(root, &path, entries)?;
        } else if file_type.is_symlink() {
            let target = fs::read_link(&path).map_err(|source| BoxletError::StateStore {
                path: path.clone(),
                source,
            })?;
            let target_bytes = target.as_os_str().as_encoded_bytes();
            entries.insert(
                rel_path,
                EntryMetadata {
                    kind: EntryKind::Symlink,
                    size: target_bytes.len() as u64,
                    mode,
                    fnv1a64: Some(hash_bytes_fnv1a64(target_bytes)),
                },
            );
        } else if file_type.is_file() {
            let hash = hash_file_fnv1a64(&path)?;
            entries.insert(
                rel_path,
                EntryMetadata {
                    kind: EntryKind::File,
                    size: meta.len(),
                    mode,
                    fnv1a64: Some(hash),
                },
            );
        }
    }

    Ok(())
}

fn copy_tree_recursive(src_dir: &Path, dst_dir: &Path, is_root: bool) -> Result<()> {
    let read_dir = fs::read_dir(src_dir).map_err(|source| BoxletError::StateStore {
        path: src_dir.to_path_buf(),
        source,
    })?;

    let mut dir_entries = Vec::new();
    for item in read_dir {
        let entry = item.map_err(|source| BoxletError::StateStore {
            path: src_dir.to_path_buf(),
            source,
        })?;
        dir_entries.push(entry);
    }
    dir_entries.sort_by_key(|e| e.file_name());

    for entry in dir_entries {
        let file_name = entry.file_name();
        if is_root && file_name == OLD_ROOT_DIR_NAME {
            continue;
        }

        let src_path = entry.path();
        let dst_path = dst_dir.join(&file_name);
        let meta = fs::symlink_metadata(&src_path).map_err(|source| BoxletError::StateStore {
            path: src_path.clone(),
            source,
        })?;
        let file_type = meta.file_type();

        if file_type.is_dir() {
            fs::create_dir_all(&dst_path).map_err(|source| BoxletError::StateStore {
                path: dst_path.clone(),
                source,
            })?;
            copy_tree_recursive(&src_path, &dst_path, false)?;
            fs::set_permissions(&dst_path, meta.permissions()).map_err(|source| {
                BoxletError::StateStore {
                    path: dst_path.clone(),
                    source,
                }
            })?;
        } else if file_type.is_symlink() {
            let target = fs::read_link(&src_path).map_err(|source| BoxletError::StateStore {
                path: src_path.clone(),
                source,
            })?;
            create_symlink(&target, &dst_path)?;
        } else if file_type.is_file() {
            fs::copy(&src_path, &dst_path).map_err(|source| BoxletError::StateStore {
                path: dst_path.clone(),
                source,
            })?;
            fs::set_permissions(&dst_path, meta.permissions()).map_err(|source| {
                BoxletError::StateStore {
                    path: dst_path,
                    source,
                }
            })?;
        }
    }

    Ok(())
}

#[cfg(unix)]
fn extract_mode(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    meta.mode() & 0o7777
}

#[cfg(not(unix))]
fn extract_mode(meta: &fs::Metadata) -> u32 {
    if meta.permissions().readonly() {
        0o444
    } else {
        0o644
    }
}

#[cfg(unix)]
fn create_symlink(target: &Path, link_path: &Path) -> Result<()> {
    std::os::unix::fs::symlink(target, link_path).map_err(|source| BoxletError::StateStore {
        path: link_path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn create_symlink(_target: &Path, link_path: &Path) -> Result<()> {
    Err(BoxletError::StateStore {
        path: link_path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "symlinks require a Unix host filesystem",
        ),
    })
}

fn hash_bytes_fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = FNV1A_64_OFFSET_BASIS;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV1A_64_PRIME);
    }
    hash
}

fn hash_file_fnv1a64(path: &Path) -> Result<u64> {
    let mut file = File::open(path).map_err(|source| BoxletError::StateStore {
        path: path.to_path_buf(),
        source,
    })?;
    let mut hash = FNV1A_64_OFFSET_BASIS;
    let mut buf = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|source| BoxletError::StateStore {
                path: path.to_path_buf(),
                source,
            })?;
        if n == 0 {
            break;
        }
        for &byte in &buf[..n] {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(FNV1A_64_PRIME);
        }
    }
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tempdir() -> Result<tempfile::TempDir> {
        tempfile::tempdir().map_err(|source| BoxletError::StateStore {
            path: PathBuf::from("tempdir"),
            source,
        })
    }

    fn write_file(path: &Path, contents: &[u8]) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| BoxletError::StateStore {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        fs::write(path, contents).map_err(|source| BoxletError::StateStore {
            path: path.to_path_buf(),
            source,
        })
    }

    #[test]
    fn three_way_workspace_branching_computes_exact_diffs_without_mutating_base() -> Result<()> {
        let tmp = make_tempdir()?;
        let source_rootfs = tmp.path().join("source-rootfs");
        let snapshot_base = tmp.path().join("snapshots");
        let branches_base = tmp.path().join("branches");

        // Populate base rootfs (+ internal .boxlet_old_root which must be ignored)
        write_file(&source_rootfs.join("etc/config.toml"), b"port = 8080\n")?;
        write_file(&source_rootfs.join("src/main.rs"), b"fn main() {}\n")?;
        write_file(&source_rootfs.join("README.md"), b"# Base Workspace\n")?;
        write_file(
            &source_rootfs.join(".boxlet_old_root/leaked.txt"),
            b"ignore me",
        )?;

        let snapshot = WorkspaceSnapshot::create("base-v1", &source_rootfs, &snapshot_base)?;
        assert!(!snapshot
            .manifest
            .entries
            .contains_key(Path::new(".boxlet_old_root")));

        // Branch into 3 independent sandboxes
        let branch_a = snapshot.branch("branch-a", &branches_base)?;
        let branch_b = snapshot.branch("branch-b", &branches_base)?;
        let branch_c = snapshot.branch("branch-c", &branches_base)?;

        // branch-a: adds a new module and modifies src/main.rs
        write_file(&branch_a.join("src/agent_a.rs"), b"pub fn solve() {}\n")?;
        write_file(
            &branch_a.join("src/main.rs"),
            b"mod agent_a;\nfn main() { agent_a::solve(); }\n",
        )?;

        // branch-b: modifies etc/config.toml and deletes README.md
        write_file(&branch_b.join("etc/config.toml"), b"port = 9090\n")?;
        fs::remove_file(branch_b.join("README.md")).map_err(|source| BoxletError::StateStore {
            path: branch_b.join("README.md"),
            source,
        })?;

        // branch-c: adds a test file, modifies README.md, and deletes src/main.rs
        write_file(&branch_c.join("tests/smoke.rs"), b"#[test] fn ok() {}\n")?;
        write_file(&branch_c.join("README.md"), b"# Candidate C\n")?;
        fs::remove_file(branch_c.join("src/main.rs")).map_err(|source| {
            BoxletError::StateStore {
                path: branch_c.join("src/main.rs"),
                source,
            }
        })?;

        // Compute diffs for each branch against the base snapshot
        let diff_a = snapshot.manifest.diff(&TreeManifest::capture(&branch_a)?);
        assert!(!diff_a.is_empty());
        assert_eq!(diff_a.total_changes(), 2);
        assert_eq!(diff_a.added, vec![PathBuf::from("src/agent_a.rs")]);
        assert_eq!(diff_a.modified, vec![PathBuf::from("src/main.rs")]);
        assert!(diff_a.deleted.is_empty());

        let diff_b = snapshot.manifest.diff(&TreeManifest::capture(&branch_b)?);
        assert!(!diff_b.is_empty());
        assert_eq!(diff_b.total_changes(), 2);
        assert!(diff_b.added.is_empty());
        assert_eq!(diff_b.modified, vec![PathBuf::from("etc/config.toml")]);
        assert_eq!(diff_b.deleted, vec![PathBuf::from("README.md")]);

        let diff_c = snapshot.manifest.diff(&TreeManifest::capture(&branch_c)?);
        assert!(!diff_c.is_empty());
        assert_eq!(diff_c.total_changes(), 4);
        assert_eq!(
            diff_c.added,
            vec![PathBuf::from("tests"), PathBuf::from("tests/smoke.rs")]
        );
        assert_eq!(diff_c.modified, vec![PathBuf::from("README.md")]);
        assert_eq!(diff_c.deleted, vec![PathBuf::from("src/main.rs")]);

        // Verify the original snapshot directory is completely untouched
        let current_snapshot_manifest = TreeManifest::capture(&snapshot.snapshot_dir)?;
        let snapshot_self_diff = snapshot.manifest.diff(&current_snapshot_manifest);
        assert!(snapshot_self_diff.is_empty());
        assert_eq!(snapshot_self_diff.total_changes(), 0);
        assert_eq!(current_snapshot_manifest, snapshot.manifest);

        Ok(())
    }

    #[test]
    fn duplicate_snapshot_or_branch_id_and_invalid_ids_are_rejected() -> Result<()> {
        let tmp = make_tempdir()?;
        let source_rootfs = tmp.path().join("rootfs");
        let snapshot_base = tmp.path().join("snapshots");
        write_file(&source_rootfs.join("hello.txt"), b"world")?;

        assert!(matches!(
            WorkspaceSnapshot::create("../escape", &source_rootfs, &snapshot_base),
            Err(BoxletError::InvalidContainerId { .. })
        ));

        let snap = WorkspaceSnapshot::create("snap-1", &source_rootfs, &snapshot_base)?;
        assert!(matches!(
            WorkspaceSnapshot::create("snap-1", &source_rootfs, &snapshot_base),
            Err(BoxletError::ContainerAlreadyExists { .. })
        ));

        let branches_base = tmp.path().join("branches");
        let _b1 = snap.branch("branch-1", &branches_base)?;
        assert!(matches!(
            snap.branch("branch-1", &branches_base),
            Err(BoxletError::ContainerAlreadyExists { .. })
        ));

        Ok(())
    }

    #[test]
    fn nested_destinations_are_rejected_and_nested_pivot_dir_is_preserved() -> Result<()> {
        let tmp = make_tempdir()?;
        let source_rootfs = tmp.path().join("rootfs");
        write_file(&source_rootfs.join("app/main.rs"), b"fn main() {}")?;
        write_file(
            &source_rootfs.join("nested/.boxlet_old_root/keep.txt"),
            b"keep",
        )?;

        // Destination inside source_rootfs must be rejected before creating directories
        let nested_snap_base = source_rootfs.join("snapshots");
        assert!(WorkspaceSnapshot::create("nested-1", &source_rootfs, &nested_snap_base).is_err());
        assert!(!nested_snap_base.exists());

        let snapshot_base = tmp.path().join("snapshots");
        let snap = WorkspaceSnapshot::create("snap-ok", &source_rootfs, &snapshot_base)?;
        assert!(snap
            .manifest
            .entries
            .contains_key(Path::new("nested/.boxlet_old_root/keep.txt")));

        // Branch destination inside snapshot_dir must also be rejected
        let nested_branch_dest = snap.snapshot_dir.join("branches");
        assert!(snap.branch("branch-nested", &nested_branch_dest).is_err());
        assert!(!nested_branch_dest.exists());

        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn same_length_symlink_retarget_and_readonly_dir_copy_work() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let tmp = make_tempdir()?;
        let source_rootfs = tmp.path().join("rootfs");
        let snapshot_base = tmp.path().join("snapshots");
        let branches_base = tmp.path().join("branches");

        write_file(&source_rootfs.join("ro_dir/file.txt"), b"readonly child")?;
        let ro_dir = source_rootfs.join("ro_dir");
        fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o555)).map_err(|source| {
            BoxletError::StateStore {
                path: ro_dir.clone(),
                source,
            }
        })?;
        create_symlink(Path::new("target-a"), &source_rootfs.join("current_link"))?;

        let snap = WorkspaceSnapshot::create("snap-sym", &source_rootfs, &snapshot_base)?;
        let branch = snap.branch("branch-sym", &branches_base)?;

        // Replace symlink with a same-length target ("target-a" -> "target-b")
        let branch_link = branch.join("current_link");
        fs::remove_file(&branch_link).map_err(|source| BoxletError::StateStore {
            path: branch_link.clone(),
            source,
        })?;
        create_symlink(Path::new("target-b"), &branch_link)?;

        let diff = snap.manifest.diff(&TreeManifest::capture(&branch)?);
        assert_eq!(diff.modified, vec![PathBuf::from("current_link")]);

        // Restore write permissions on temp dirs before TempDir drop cleanup
        fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o755)).map_err(|source| {
            BoxletError::StateStore {
                path: ro_dir,
                source,
            }
        })?;
        fs::set_permissions(
            snap.snapshot_dir.join("ro_dir"),
            fs::Permissions::from_mode(0o755),
        )
        .map_err(|source| BoxletError::StateStore {
            path: snap.snapshot_dir.join("ro_dir"),
            source,
        })?;
        fs::set_permissions(branch.join("ro_dir"), fs::Permissions::from_mode(0o755)).map_err(
            |source| BoxletError::StateStore {
                path: branch.join("ro_dir"),
                source,
            },
        )?;

        Ok(())
    }
}
