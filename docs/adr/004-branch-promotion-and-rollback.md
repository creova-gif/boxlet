# ADR-004: Branch Winner Promotion and Deterministic Workspace Rollback

- **Status:** Accepted
- **Owner:** Justin Mafie
- **Date:** 2026-11-25

## Context

After `Engine::run_branches` executes `N` candidate branches in parallel from an immutable checkpoint, an autonomous software engineering loop evaluates each candidate's `ExecutionResult` (exit code, test output, resource telemetry, policy violations) and `FsDiff` (`added`, `modified`, `deleted` paths). To close the autonomous execution loop without manual file copying or shell scripting, callers require two complementary host-side primitives:

1. **Winner Promotion (`promote_branch` / `sync_rootfs_delta`):** Apply a winning candidate branch's filesystem changes (`added`, `modified`, `deleted`) back onto the target workspace rootfs so downstream steps observe the exact post-branch state.
2. **Deterministic Rollback (`restore` / `restore_from_dir`):** Roll a mutated target workspace rootfs back to an immutable checkpoint (`WorkspaceSnapshot` or snapshot directory) by computing and applying the exact reverse delta (`FsDiff`), removing untracked files, symlinks, and directories created after the checkpoint and restoring modified or deleted files, directories, and symlinks to their exact checkpointed contents and POSIX modes.

## Decision

### 1. Snapshot Loading, Branch Promotion, and Deterministic Rollback (`src/snapshot.rs`)

We extend `WorkspaceSnapshot` and `boxlet::snapshot` with four methods and a standalone synchronization primitive:

- **`WorkspaceSnapshot::load(id: impl Into<String>, snapshot_dir: &Path) -> Result<Self>`**:
  - Validates `id` via `validate_container_id`, captures `TreeManifest::capture(snapshot_dir)`, and reconstructs a `WorkspaceSnapshot` from an existing on-disk checkpoint directory.
- **`WorkspaceSnapshot::promote_branch(&self, branch_rootfs: &Path, target_rootfs: &Path) -> Result<FsDiff>`**:
  - Ensures `branch_rootfs`, `target_rootfs`, and `self.snapshot_dir` exist and that none of the three directories is identical to or nested inside another (`ensure_not_nested` / `ensure_disjoint_dirs`).
  - Captures `branch_manifest = TreeManifest::capture(branch_rootfs)?` and computes the winning branch's delta relative to the base checkpoint (`self.manifest.diff(&branch_manifest)`).
  - Synchronizes `target_rootfs` to match `branch_rootfs` via `sync_tree_to_source(branch_rootfs, &branch_manifest, target_rootfs)?` so `TreeManifest::capture(target_rootfs)` is identical to `branch_manifest`, and returns the promoted `FsDiff`.
- **`WorkspaceSnapshot::restore(&self, target_rootfs: &Path) -> Result<FsDiff>`**:
  - Ensures `self.snapshot_dir` and `target_rootfs` are disjoint and synchronizes `target_rootfs` back to `self.snapshot_dir` (`&self.manifest`), returning the reverse `FsDiff` applied from the pre-restore `target_rootfs` state to `self.manifest`.
- **`WorkspaceSnapshot::restore_from_dir(snapshot_dir: &Path, target_rootfs: &Path) -> Result<FsDiff>`** and **`sync_rootfs_delta(source_rootfs: &Path, target_rootfs: &Path) -> Result<FsDiff>`**:
  - Captures the source/snapshot `TreeManifest` and synchronizes `target_rootfs` to match `source_rootfs`, returning the `FsDiff` applied from `target_rootfs` (before) to `source_rootfs` (after).

### 2. Tree Synchronization Algorithm & Read-Only Directory Handling

`sync_tree_to_source(source_rootfs, source_manifest, target_rootfs)` transitions `target_rootfs` to match `source_manifest` deterministically:

1. **Pre-Sync Directory Writability Pass:**
   - Captures `target_manifest = TreeManifest::capture(target_rootfs)?` and computes `applied_diff = target_manifest.diff(source_manifest)`.
   - Temporarily grants write permission (`0o755`) on all existing directories in `target_manifest` so child files, symlinks, and subdirectories inside read-only (`0o555`) directories can be added, overwritten, or deleted without `EACCES` / `EPERM`.
2. **Reverse-Depth Deletion & Kind-Transition Cleanup:**
   - Identifies every path in `target_manifest` that was either deleted in `source_manifest` or changed `EntryKind` (e.g., file-to-directory or directory-to-file).
   - Removes those paths in reverse order (deepest children before parent directories) while preserving any top-level `.boxlet_old_root` pivot directory.
3. **Forward-Order Addition & Modification Pass:**
   - Iterates `source_manifest.entries` in lexicographical order (parent directories before children), creating missing directories, replacing modified symlinks verbatim via `read_link`, and unlinking-then-copying added or modified regular files (so read-only `0o444` target files are cleanly replaced) along with their POSIX permission modes.
4. **Reverse-Order Directory Permission Restoration:**
   - Restores the exact `EntryMetadata::mode` (including `0o555` read-only directories) from `source_manifest` on all directories in reverse depth order after all child mutations are complete.

## Alternatives Considered

1. **Blindly deleting `target_rootfs` with `fs::remove_dir_all` and re-copying the entire tree:**
   - *Rejected:* Unlinking the root directory itself breaks open file descriptors, bind-mount points, or parent directory permissions, fails when `target_rootfs` contains read-only (`0o555`) subdirectories, and copies unchanged files unnecessarily when only a small delta changed.
2. **Shelling out to `rsync --delete`:**
   - *Rejected:* Adds an external binary dependency that may not exist on minimal hosts and cannot return Boxlet's structured `FsDiff` type directly.

## Consequences & Failure Modes

- **Positive:**
  - Completes the checkpoint -> parallel branch fan-out -> winner promotion -> deterministic rollback lifecycle in pure Rust across macOS and Linux.
  - Preserves unchanged files in `target_rootfs` without unnecessary writes while guaranteeing `TreeManifest::capture(target_rootfs) == TreeManifest::capture(source_rootfs)` after promotion or rollback.
- **Failure modes & mitigations:**
  - *Read-only (`0o555`) directories or (`0o444`) files blocking rollback/promotion:* Handled explicitly by loosening existing directory permissions prior to child mutations, unlinking destination files before copying, and restoring exact directory modes in reverse depth order.
  - *Nested source/target directories causing recursive self-corruption:* Rejected upfront via canonicalized prefix checks (`ensure_not_nested`) before any filesystem mutation occurs.
