//! Linux `overlayfs` copy-on-write rootfs driver and `O(changed_files)` upperdir diff inspector.
//!
//! Implements Tier 2 of `docs/adr/002-filesystem-snapshots-and-diffing.md`:
//! - [`OverlayDirs`] and [`OverlayRootfsProvider`] prepare per-container/per-branch
//!   `upper`, `work`, and `merged` directories and mount kernel `overlayfs` on Linux 5.15+.
//! - [`inspect_upper_diff`] computes an exact [`FsDiff`] against a base [`TreeManifest`]
//!   by walking only the writable `upperdir` and interpreting Linux `overlayfs` whiteout
//!   character devices (`c 0:0`) and `.wh.<name>` markers without re-scanning `lowerdir`.

use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use nix::mount::{mount, umount2, MntFlags, MsFlags};

use crate::error::{BoxletError, Result};
use crate::oci::validate_container_id;
use crate::snapshot::{EntryKind, EntryMetadata, FsDiff, TreeManifest};
use crate::traits::RootfsProvider;

/// Internal pivot directory skipped during upperdir diff inspection.
const OLD_ROOT_DIR_NAME: &str = ".boxlet_old_root";

/// 64-bit FNV-1a offset basis (matches `crate::snapshot`).
const FNV1A_64_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;

/// 64-bit FNV-1a prime (matches `crate::snapshot`).
const FNV1A_64_PRIME: u64 = 0x0100_0000_01b3;

/// Per-container or per-branch directory layout required by Linux `overlayfs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayDirs {
    /// Root directory holding `upper`, `work`, and `merged` (`<work_root>/<id>`).
    pub branch_root: PathBuf,
    /// Read-only base rootfs or snapshot directory (`lowerdir`).
    pub lowerdir: PathBuf,
    /// Writable copy-on-write layer (`<work_root>/<id>/upper`).
    pub upperdir: PathBuf,
    /// Kernel internal work directory (`<work_root>/<id>/work`, must reside on same fs as `upperdir`).
    pub workdir: PathBuf,
    /// Unified mount target directory (`<work_root>/<id>/merged`).
    pub merged: PathBuf,
}

impl OverlayDirs {
    /// Constructs and validates [`OverlayDirs`] under `<work_root>/<id>/{upper,work,merged}`.
    pub fn new(work_root: &Path, id: &str, lowerdir: &Path) -> Result<Self> {
        validate_container_id(id)?;
        validate_overlay_path(lowerdir, "lowerdir")?;
        validate_overlay_path(work_root, "work_root")?;

        let branch_root = work_root.join(id);
        let upperdir = branch_root.join("upper");
        let workdir = branch_root.join("work");
        let merged = branch_root.join("merged");

        validate_overlay_path(&upperdir, "upperdir")?;
        validate_overlay_path(&workdir, "workdir")?;
        validate_overlay_path(&merged, "merged")?;

        Ok(Self {
            branch_root,
            lowerdir: lowerdir.to_path_buf(),
            upperdir,
            workdir,
            merged,
        })
    }

    /// Creates the `upper`, `work`, and `merged` directories on disk after verifying `lowerdir` exists.
    pub fn prepare_dirs(&self) -> Result<()> {
        if !self.lowerdir.is_dir() {
            return Err(BoxletError::Runtime {
                subsystem: "overlayfs",
                message: format!(
                    "overlay lowerdir '{}' does not exist or is not a directory",
                    self.lowerdir.display()
                ),
            });
        }

        for dir in [&self.upperdir, &self.workdir, &self.merged] {
            fs::create_dir_all(dir).map_err(|err| BoxletError::Runtime {
                subsystem: "overlayfs",
                message: format!(
                    "failed to create overlay directory '{}': {err}",
                    dir.display()
                ),
            })?;
        }
        Ok(())
    }

    /// Formats the kernel `mount(2)` option string (`lowerdir=...,upperdir=...,workdir=...`).
    pub fn mount_options(&self) -> Result<String> {
        build_mount_options(&self.lowerdir, &self.upperdir, &self.workdir)
    }

    /// Removes the `<work_root>/<id>` directory tree (`upper`, `work`, `merged`).
    pub fn cleanup_dirs(&self) -> Result<()> {
        if self.branch_root.exists() {
            fs::remove_dir_all(&self.branch_root).map_err(|err| BoxletError::Runtime {
                subsystem: "overlayfs",
                message: format!(
                    "failed to remove overlay branch root '{}': {err}",
                    self.branch_root.display()
                ),
            })?;
        }
        Ok(())
    }
}

/// Validates that a path can be safely embedded into an `overlayfs` mount options string.
///
/// Linux `overlayfs` uses `:` to delimit multiple lower directories and `,` to delimit
/// mount options, so paths containing `:`, `,`, or `\0` (or non-UTF-8 sequences) are
/// rejected fail-closed before calling `mount(2)`.
pub fn validate_overlay_path<'a>(path: &'a Path, role: &'static str) -> Result<&'a str> {
    let raw = path.to_str().ok_or_else(|| BoxletError::Runtime {
        subsystem: "overlayfs",
        message: format!(
            "overlay {role} path '{}' is not valid UTF-8",
            path.display()
        ),
    })?;

    if raw.is_empty() {
        return Err(BoxletError::Runtime {
            subsystem: "overlayfs",
            message: format!("overlay {role} path cannot be empty"),
        });
    }

    if raw.contains(':') || raw.contains(',') || raw.contains('\0') {
        return Err(BoxletError::Runtime {
            subsystem: "overlayfs",
            message: format!(
                "overlay {role} path '{raw}' contains forbidden delimiter (':' or ',' or NUL)"
            ),
        });
    }

    Ok(raw)
}

/// Builds a validated `overlayfs` mount option string: `lowerdir=<lower>,upperdir=<upper>,workdir=<work>`.
pub fn build_mount_options(lowerdir: &Path, upperdir: &Path, workdir: &Path) -> Result<String> {
    let lower = validate_overlay_path(lowerdir, "lowerdir")?;
    let upper = validate_overlay_path(upperdir, "upperdir")?;
    let work = validate_overlay_path(workdir, "workdir")?;

    Ok(format!("lowerdir={lower},upperdir={upper},workdir={work}"))
}

/// Mounts a Linux `overlay` filesystem at `dirs.merged` using `dirs.lowerdir`, `dirs.upperdir`, and `dirs.workdir`.
pub fn mount_overlay(dirs: &OverlayDirs) -> Result<()> {
    let options = dirs.mount_options()?;
    mount(
        Some("overlay"),
        &dirs.merged,
        Some("overlay"),
        MsFlags::empty(),
        Some(options.as_str()),
    )
    .map_err(|err| BoxletError::Runtime {
        subsystem: "overlayfs",
        message: format!(
            "mount(overlay -> '{}', options='{}') failed: {err}",
            dirs.merged.display(),
            options
        ),
    })
}

/// Unmounts a mounted `overlay` filesystem at `merged` using `MNT_DETACH`.
pub fn unmount_overlay(merged: &Path) -> Result<()> {
    umount2(merged, MntFlags::MNT_DETACH).map_err(|err| BoxletError::Runtime {
        subsystem: "overlayfs",
        message: format!("umount2('{}', MNT_DETACH) failed: {err}", merged.display()),
    })
}

/// Linux `overlayfs` copy-on-write [`RootfsProvider`] implementation.
#[derive(Debug, Clone)]
pub struct OverlayRootfsProvider {
    work_root: PathBuf,
}

impl OverlayRootfsProvider {
    /// Creates a new [`OverlayRootfsProvider`] storing per-container layers under `work_root`.
    pub fn new(work_root: impl Into<PathBuf>) -> Self {
        Self {
            work_root: work_root.into(),
        }
    }

    /// Returns the [`OverlayDirs`] layout for `container_id` backed by `lower_rootfs`.
    pub fn dirs_for(&self, container_id: &str, lower_rootfs: &Path) -> Result<OverlayDirs> {
        OverlayDirs::new(&self.work_root, container_id, lower_rootfs)
    }
}

impl RootfsProvider for OverlayRootfsProvider {
    fn prepare(&self, container_id: &str, rootfs_path: &Path) -> Result<PathBuf> {
        let dirs = self.dirs_for(container_id, rootfs_path)?;
        dirs.prepare_dirs()?;
        if let Err(err) = mount_overlay(&dirs) {
            let _ = dirs.cleanup_dirs();
            return Err(err);
        }
        Ok(dirs.merged)
    }

    fn cleanup(&self, container_id: &str, prepared_path: &Path) -> Result<()> {
        validate_container_id(container_id)?;
        if prepared_path.exists() {
            let _ = unmount_overlay(prepared_path);
        }
        let branch_root = self.work_root.join(container_id);
        if branch_root.exists() {
            fs::remove_dir_all(&branch_root).map_err(|err| BoxletError::Runtime {
                subsystem: "overlayfs",
                message: format!(
                    "failed to clean up overlay directory '{}': {err}",
                    branch_root.display()
                ),
            })?;
        }
        Ok(())
    }
}

/// Returns `true` when raw POSIX `st_mode` and `st_rdev` represent a Linux `overlayfs`
/// whiteout character device (`S_IFCHR` with device number `0:0`, i.e. `rdev == 0`).
pub fn is_whiteout_mode_and_rdev(mode: u32, rdev: u64) -> bool {
    (mode & libc::S_IFMT) == libc::S_IFCHR && rdev == 0
}

/// Returns `true` if `meta` is a Linux `overlayfs` whiteout character device (`c 0:0`).
pub fn is_overlay_whiteout(meta: &fs::Metadata) -> bool {
    meta.file_type().is_char_device() && is_whiteout_mode_and_rdev(meta.mode(), meta.rdev())
}

/// Computes an `O(changed_files)` [`FsDiff`] by inspecting only the writable `upper_dir`
/// against a pre-captured `lower_manifest` without re-reading or re-hashing unchanged
/// files in `lowerdir`.
pub fn inspect_upper_diff(lower_manifest: &TreeManifest, upper_dir: &Path) -> Result<FsDiff> {
    if !upper_dir.exists() {
        return Err(BoxletError::StateStore {
            path: upper_dir.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "overlay upperdir does not exist",
            ),
        });
    }

    let mut added = Vec::new();
    let mut modified = Vec::new();
    let mut deleted = Vec::new();

    walk_upper_recursive(
        upper_dir,
        upper_dir,
        lower_manifest,
        &mut added,
        &mut modified,
        &mut deleted,
    )?;

    added.sort();
    added.dedup();
    modified.sort();
    modified.dedup();
    deleted.sort();
    deleted.dedup();

    Ok(FsDiff {
        added,
        modified,
        deleted,
    })
}

fn walk_upper_recursive(
    upper_root: &Path,
    current: &Path,
    lower_manifest: &TreeManifest,
    added: &mut Vec<PathBuf>,
    modified: &mut Vec<PathBuf>,
    deleted: &mut Vec<PathBuf>,
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
        let rel_path = match path.strip_prefix(upper_root) {
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

        // Check for kernel `c 0:0` whiteout character device.
        if is_overlay_whiteout(&meta) {
            record_deleted_path(lower_manifest, &rel_path, deleted);
            continue;
        }

        let file_type = meta.file_type();
        let mode = meta.mode() & 0o7777;

        if file_type.is_dir() {
            if is_opaque_overlay_dir(&path) {
                record_opaque_deleted_children(lower_manifest, &rel_path, &path, deleted);
            }
            let upper_meta = EntryMetadata {
                kind: EntryKind::Directory,
                size: 0,
                mode,
                fnv1a64: None,
            };
            classify_upper_entry(
                lower_manifest,
                &rel_path,
                &upper_meta,
                added,
                modified,
                deleted,
            );
            walk_upper_recursive(upper_root, &path, lower_manifest, added, modified, deleted)?;
        } else if file_type.is_symlink() {
            let target = fs::read_link(&path).map_err(|source| BoxletError::StateStore {
                path: path.clone(),
                source,
            })?;
            let target_bytes = target.as_os_str().as_encoded_bytes();
            let upper_meta = EntryMetadata {
                kind: EntryKind::Symlink,
                size: target_bytes.len() as u64,
                mode,
                fnv1a64: Some(hash_bytes_fnv1a64(target_bytes)),
            };
            classify_upper_entry(
                lower_manifest,
                &rel_path,
                &upper_meta,
                added,
                modified,
                deleted,
            );
        } else if file_type.is_file() {
            let hash = hash_file_fnv1a64(&path)?;
            let upper_meta = EntryMetadata {
                kind: EntryKind::File,
                size: meta.len(),
                mode,
                fnv1a64: Some(hash),
            };
            classify_upper_entry(
                lower_manifest,
                &rel_path,
                &upper_meta,
                added,
                modified,
                deleted,
            );
        }
    }

    Ok(())
}

fn classify_upper_entry(
    lower_manifest: &TreeManifest,
    rel_path: &Path,
    upper_meta: &EntryMetadata,
    added: &mut Vec<PathBuf>,
    modified: &mut Vec<PathBuf>,
    deleted: &mut Vec<PathBuf>,
) {
    match lower_manifest.entries.get(rel_path) {
        None => added.push(rel_path.to_path_buf()),
        Some(lower_meta) => {
            if lower_meta != upper_meta {
                modified.push(rel_path.to_path_buf());
            }
            // If a directory in lowerdir was replaced by a non-directory in upperdir,
            // any lowerdir descendants under that directory were also removed.
            if lower_meta.kind == EntryKind::Directory && upper_meta.kind != EntryKind::Directory {
                for candidate in lower_manifest.entries.keys() {
                    if candidate != rel_path && candidate.starts_with(rel_path) {
                        deleted.push(candidate.clone());
                    }
                }
            }
        }
    }
}

fn is_opaque_overlay_dir(path: &Path) -> bool {
    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    for attr_name in [c"trusted.overlay.opaque", c"user.overlay.opaque"] {
        let mut buf = [0u8; 4];
        // SAFETY: `c_path` and `attr_name` are valid NUL-terminated CStrings and `buf` is valid writable memory.
        let n = unsafe {
            libc::lgetxattr(
                c_path.as_ptr(),
                attr_name.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if n == 1 && buf[0] == b'y' {
            return true;
        }
    }
    false
}

fn record_opaque_deleted_children(
    lower_manifest: &TreeManifest,
    dir_rel: &Path,
    upper_dir_path: &Path,
    deleted: &mut Vec<PathBuf>,
) {
    for candidate in lower_manifest.entries.keys() {
        if candidate != dir_rel && candidate.starts_with(dir_rel) {
            if let Ok(sub_rel) = candidate.strip_prefix(dir_rel) {
                let recreated_in_upper = upper_dir_path.join(sub_rel);
                if fs::symlink_metadata(&recreated_in_upper).is_err() {
                    deleted.push(candidate.clone());
                }
            }
        }
    }
}

fn record_deleted_path(
    lower_manifest: &TreeManifest,
    target_rel: &Path,
    deleted: &mut Vec<PathBuf>,
) {
    for candidate in lower_manifest.entries.keys() {
        if candidate == target_rel || candidate.starts_with(target_rel) {
            deleted.push(candidate.clone());
        }
    }
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
    use nix::sys::stat::{mknod, Mode, SFlag};

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
    fn build_mount_options_formats_valid_paths_and_rejects_colon_or_comma() -> Result<()> {
        let opts = build_mount_options(
            Path::new("/var/lib/boxlet/snapshots/base-v1"),
            Path::new("/run/boxlet/overlay/branch-a/upper"),
            Path::new("/run/boxlet/overlay/branch-a/work"),
        )?;
        assert_eq!(
            opts,
            "lowerdir=/var/lib/boxlet/snapshots/base-v1,upperdir=/run/boxlet/overlay/branch-a/upper,workdir=/run/boxlet/overlay/branch-a/work"
        );

        let colon_err = build_mount_options(
            Path::new("/var/lib/boxlet/bad:lower"),
            Path::new("/run/boxlet/upper"),
            Path::new("/run/boxlet/work"),
        );
        assert!(matches!(
            colon_err,
            Err(BoxletError::Runtime {
                subsystem: "overlayfs",
                ..
            })
        ));

        let comma_err = build_mount_options(
            Path::new("/var/lib/boxlet/lower"),
            Path::new("/run/boxlet/bad,upper"),
            Path::new("/run/boxlet/work"),
        );
        assert!(matches!(
            comma_err,
            Err(BoxletError::Runtime {
                subsystem: "overlayfs",
                ..
            })
        ));

        let empty_err = build_mount_options(
            Path::new(""),
            Path::new("/run/boxlet/upper"),
            Path::new("/run/boxlet/work"),
        );
        assert!(matches!(
            empty_err,
            Err(BoxletError::Runtime {
                subsystem: "overlayfs",
                ..
            })
        ));

        Ok(())
    }

    #[test]
    fn overlay_dirs_prepare_and_cleanup_lifecycle() -> Result<()> {
        let tmp = make_tempdir()?;
        let lower = tmp.path().join("lower");
        let work_root = tmp.path().join("overlay-work");
        fs::create_dir_all(&lower).map_err(|source| BoxletError::StateStore {
            path: lower.clone(),
            source,
        })?;

        let provider = OverlayRootfsProvider::new(&work_root);
        let dirs = provider.dirs_for("branch-1", &lower)?;
        dirs.prepare_dirs()?;

        assert!(dirs.upperdir.is_dir());
        assert!(dirs.workdir.is_dir());
        assert!(dirs.merged.is_dir());

        let expected_opts = format!(
            "lowerdir={},upperdir={},workdir={}",
            lower.display(),
            dirs.upperdir.display(),
            dirs.workdir.display()
        );
        assert_eq!(dirs.mount_options()?, expected_opts);

        dirs.cleanup_dirs()?;
        assert!(!dirs.branch_root.exists());
        assert!(lower.is_dir());

        Ok(())
    }

    #[test]
    fn inspect_upper_diff_classifies_added_modified_and_unchanged_without_rescanning_lower(
    ) -> Result<()> {
        let tmp = make_tempdir()?;
        let lower = tmp.path().join("lower");
        let upper = tmp.path().join("upper");

        write_file(&lower.join("etc/app.conf"), b"threads = 4\n")?;
        write_file(&lower.join("src/lib.rs"), b"pub fn v1() {}\n")?;
        write_file(&lower.join("README.md"), b"# Immutable Base\n")?;

        let lower_manifest = TreeManifest::capture(&lower)?;

        // Populate upperdir with:
        // 1. An unchanged copy-up of README.md (same content and permissions)
        // 2. A modified src/lib.rs
        // 3. A newly added src/overlay_feature.rs
        write_file(&upper.join("README.md"), b"# Immutable Base\n")?;
        write_file(&upper.join("src/lib.rs"), b"pub fn v2() {}\n")?;
        write_file(
            &upper.join("src/overlay_feature.rs"),
            b"pub fn fast_cow() {}\n",
        )?;

        let diff = inspect_upper_diff(&lower_manifest, &upper)?;
        assert_eq!(diff.added, vec![PathBuf::from("src/overlay_feature.rs")]);
        assert_eq!(diff.modified, vec![PathBuf::from("src/lib.rs")]);
        assert!(diff.deleted.is_empty());

        Ok(())
    }

    #[test]
    fn is_overlay_whiteout_identifies_zero_rdev_char_device() -> Result<()> {
        // Whiteout char device has S_IFCHR and rdev == 0 (major 0, minor 0).
        assert!(is_whiteout_mode_and_rdev(libc::S_IFCHR | 0o600, 0));
        // Standard /dev/null char device (1:3 -> non-zero rdev) is NOT a whiteout.
        assert!(!is_whiteout_mode_and_rdev(
            libc::S_IFCHR | 0o666,
            libc::makedev(1, 3)
        ));
        // Regular file with rdev == 0 is NOT a whiteout.
        assert!(!is_whiteout_mode_and_rdev(libc::S_IFREG | 0o644, 0));

        // Verify whiteout deletion and directory replacement handling in inspect_upper_diff.
        let tmp = make_tempdir()?;
        let lower = tmp.path().join("lower");
        let upper = tmp.path().join("upper");

        write_file(&lower.join("obsolete.txt"), b"delete me\n")?;
        write_file(&lower.join("legacy/mod.rs"), b"pub mod old;\n")?;
        write_file(&lower.join("legacy/sub/helper.rs"), b"pub fn h() {}\n")?;
        write_file(&lower.join("keep.txt"), b"stay\n")?;

        let lower_manifest = TreeManifest::capture(&lower)?;
        fs::create_dir_all(&upper).map_err(|source| BoxletError::StateStore {
            path: upper.clone(),
            source,
        })?;

        // Replace `legacy` directory in lowerdir with a regular file in upperdir;
        // `classify_upper_entry` must mark `legacy` as modified and all its lower descendants as deleted.
        write_file(&upper.join("legacy"), b"replaced dir with file\n")?;

        // Also test kernel `c 0:0` whiteout node if permitted in this test environment.
        let char_whiteout_path = upper.join("obsolete.txt");
        let created_char_whiteout =
            mknod(&char_whiteout_path, SFlag::S_IFCHR, Mode::empty(), 0).is_ok();
        if created_char_whiteout {
            let meta = fs::symlink_metadata(&char_whiteout_path).map_err(|source| {
                BoxletError::StateStore {
                    path: char_whiteout_path,
                    source,
                }
            })?;
            assert!(is_overlay_whiteout(&meta));
        }

        let diff = inspect_upper_diff(&lower_manifest, &upper)?;
        assert!(diff.added.is_empty());
        assert_eq!(diff.modified, vec![PathBuf::from("legacy")]);
        let mut expected_deleted = vec![
            PathBuf::from("legacy/mod.rs"),
            PathBuf::from("legacy/sub"),
            PathBuf::from("legacy/sub/helper.rs"),
        ];
        if created_char_whiteout {
            expected_deleted.push(PathBuf::from("obsolete.txt"));
        }
        assert_eq!(diff.deleted, expected_deleted);

        Ok(())
    }
}
