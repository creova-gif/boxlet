# ADR-002: Filesystem Snapshots, N-Way Workspace Branching, and Deterministic Diffing

- **Status:** Accepted
- **Owner:** Justin Mafie
- **Date:** 2026-11-24

## Context

Autonomous AI software engineering workflows frequently need to explore multiple candidate patches, tool invocations, or dependency upgrades in parallel from an identical starting workspace. Standard OCI runtimes (`runc`, `youki`) treat a container rootfs as a single mutable directory for a single container lifecycle, leaving callers to manually copy gigabytes of rootfs state or parse unstructured shell output to discover what files a sandboxed agent created, modified, or deleted.

To establish Boxlet's agent-native foundation for V2 while keeping V1 portable across development hosts (macOS and Linux), we need:
1. A deterministic, serializable filesystem diff representation (`FsDiff`: `added`, `modified`, `deleted` relative paths) and directory tree manifest (`TreeManifest`) that can inspect any rootfs before and after sandbox execution.
2. A workspace snapshot and N-way branching abstraction (`WorkspaceSnapshot`) that checkpoints a base rootfs once, spawns `N` isolated writable branches (`branch-a`, `branch-b`, `branch-c`) for parallel sandboxes, and computes exact per-branch diffs without mutating the base checkpoint.
3. A clear two-tier architecture connecting portable user-space tree manifests with Linux kernel `overlayfs` (`lowerdir` + per-branch `upperdir`/`workdir`) so large root filesystems branch in `O(1)` time and diff in `O(changed_files)` time on Linux 5.15+.

## Decision

### 1. Two-Tier Snapshot & Diff Architecture

Boxlet separates the **logical snapshot/diff data model** (`src/snapshot.rs`) from the **underlying storage driver** (`RootfsProvider` in `src/traits.rs`):

- **Tier 1: Portable Deterministic Tree Manifest & Diff Engine (`src/snapshot.rs`):**
  - `TreeManifest` walks a root directory deterministically using a sorted `BTreeMap<PathBuf, EntryMetadata>`, skipping internal runtime pivot mount points (`.boxlet_old_root`).
  - Each `EntryMetadata` records `kind` (`EntryKind::File`, `Directory`, `Symlink`), byte `size`, POSIX permission `mode` (`0o7777` mask), and a 64-bit FNV-1a digest (`fnv1a64: Option<u64>`) over file contents for regular files and over the symlink target path for symlinks (`None` for directories).
  - `TreeManifest::diff(&self, after: &TreeManifest) -> FsDiff` performs an ordered single-pass comparison over both `BTreeMap` keys, classifying every relative path into `added`, `modified` (when `EntryMetadata` differs in kind, size, mode, or content hash), or `deleted`.
  - `WorkspaceSnapshot::create` captures an immutable copy and `TreeManifest` of a source rootfs, while `WorkspaceSnapshot::branch` materializes isolated writable branch directories (`<branch_dest>/<branch_id>`) so `N` parallel sandboxes can execute concurrently and compare their resulting `FsDiff`s against the base snapshot manifest.

- **Tier 2: Linux `overlayfs` Copy-on-Write Driver (`RootfsProvider` V2):**
  - On Linux 5.15+, `OverlayRootfsProvider` mounts each sandbox branch as an `overlay` filesystem with `lowerdir=<snapshot_dir>,upperdir=<branch_dir>/upper,workdir=<branch_dir>/work`.
  - Branch creation is `O(1)` (`mkdir` of `upper` and `work` plus `mount(2)` inside the container mount namespace), sharing the read-only `lowerdir` page cache across all parallel agent sandboxes.
  - Post-run diffing inspects `<branch_dir>/upper` directly in `O(changed_files)` time: regular files/directories in `upper` map to `added` or `modified` (depending on presence in `lowerdir`), while Linux `overlayfs` whiteout character devices (`c 0:0`) and `trusted.overlay.opaque` xattrs map to `deleted` entries.

### 2. Identifier Safety and Failure Semantics
- Snapshot IDs and branch IDs reuse `crate::oci::validate_container_id` to prevent path traversal (`..`, `/`, `\`, NUL bytes) when constructing snapshot or branch directories.
- All filesystem operations route errors through `BoxletError::StateStore` with the offending `PathBuf` attached, adhering strictly to Boxlet's zero-`.unwrap()` / zero-`.expect()` production invariant.

## Alternatives Considered

1. **Shelling out to `rsync`, `diff -rq`, or `git status` inside the sandbox:**
   - *Rejected:* Requires external binaries inside minimal container rootfses, fails when the guest workload corrupts `/usr/bin` or `.git`, and does not provide structured Rust types (`FsDiff`) on the host side.
2. **Linux-only `overlayfs` with no portable `TreeManifest` layer:**
   - *Rejected:* Prevents deterministic unit testing of N-way branching and diff classification on macOS developer machines or unprivileged filesystems where kernel `overlayfs` mounts are unavailable.
3. **Cryptographic SHA-256 for every file in `TreeManifest`:**
   - *Rejected for default change detection:* Snapshot diffing compares a trusted host-side base directory against post-run sandbox state to detect file mutations, not adversarial collision attacks. Streaming 64-bit FNV-1a (`fnv1a64`) paired with file size and mode requires zero external dependencies and runs with minimal allocation overhead.

## Consequences & Failure Modes

- **Positive:**
  - Multi-agent evaluation loops can checkpoint a workspace once, fan out `N` parallel candidate runs, inspect `FsDiff::added` / `modified` / `deleted` in structured JSON, and discard failed branches cleanly.
  - Works identically across macOS and Linux in portable copy mode (`WorkspaceSnapshot`), while providing a direct seam for `O(1)` Linux `overlayfs` mounts via `RootfsProvider`.
- **Failure modes & mitigations:**
  - *Symlink escape during snapshot copy:* `TreeManifest::capture` and recursive tree copying use `symlink_metadata` (`lstat`) rather than following symlinks (`stat`), recreating symlinks verbatim via `read_link` instead of traversing outside the rootfs boundary.
  - *Residual `.boxlet_old_root` directory from `pivot_root`:* Explicitly filtered out at the top of `TreeManifest::capture` and tree copy routines so host pivot artifacts never pollute workspace snapshots or diffs.
