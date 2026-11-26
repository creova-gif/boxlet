# ADR-008: Hardware-Virtualized MicroVM Backend and Pure-Rust OCI Rootfs Tar Archives

- **Status:** Accepted
- **Owner:** Justin Mafie
- **Date:** 2026-11-26

## Context

While Linux namespaces, `pivot_root`, `cgroup v2`, capabilities dropping, and Seccomp-BPF provide strong process-level isolation on a shared host kernel, multi-tenant cloud deployments and high-risk untrusted code execution require hardware virtualization boundaries (KVM on Linux or Hypervisor.framework via `libkrun`) where each sandbox runs inside its own dedicated guest kernel. Additionally, moving prepared root filesystems or winning evaluation branches across machines requires a deterministic, portable archive format that does not depend on external `tar` binaries or C archive libraries.

We need:
1. A hardware-virtualized microVM backend (`MicroVmBackend` in `src/microvm.rs`) implementing `RuntimeBackend` that translates OCI `Spec` bundles and Boxlet `ExecutionPolicy` resource bounds (`cpus`, `memory_bytes`) into validated **AWS Firecracker** (`FirecrackerVmSpec`) and **`libkrun`** (`LibkrunVmSpec`) VMM configurations while preserving full OCI container state lifecycle semantics (`create`, `start`, `state`, `kill`, `delete`, `list`, `run`).
2. A zero-C-dependency, deterministic POSIX USTAR `.tar` rootfs archive exporter and importer (`export_rootfs_tar` and `import_rootfs_tar` in `src/image.rs`) integrated with `TreeManifest` for reproducible rootfs packaging and fail-closed extraction.

## Decision

### 1. Pluggable MicroVM Specification Synthesis and `MicroVmBackend` (`src/microvm.rs`)

- **`VmmDriver` and `MicroVmConfig`:**
  - `VmmDriver` selects between `VmmDriver::Firecracker` (`firecracker` VMM JSON configuration covering `/boot-source`, `/drives/rootfs`, `/machine-config`, and `/vsock`) and `VmmDriver::Libkrun` (`libkrun` context parameters covering `krun_set_vm_config`, `krun_set_root`, `krun_set_exec`, and `krun_set_workdir`).
  - `MicroVmConfig::validate()` enforces fail-closed bounds prior to spec synthesis or container creation: `vcpu_count >= 1`, `mem_size_mib >= 16`, `vsock_cid >= 3`, and a non-empty `kernel_image_path`.
- **Policy-to-Hardware Resource Mapping:**
  - `MicroVmConfig::build_firecracker_spec` and `MicroVmConfig::build_libkrun_spec` derive guest vCPUs from `ExecutionPolicy::cpus` (rounding up via `.ceil()` to at least `1` vCPU when set, otherwise inheriting `MicroVmConfig::vcpu_count`) and guest RAM from `ExecutionPolicy::memory_bytes` (converting bytes to MiB and clamping to `>= 16 MiB` when set, otherwise inheriting `MicroVmConfig::mem_size_mib`).
  - Root filesystem path, read-only mount flag (`root.readonly`), workload argv (`process.args`), environment variables (`process.env`), and working directory (`process.cwd`) are extracted directly from the OCI `Spec`.
- **`MicroVmBackend` (`RuntimeBackend` Implementation):**
  - Materializes `<state_root>/<id>/microvm.json` atomically alongside `<state_root>/<id>/state.json` (managed via `StateStore`), allowing `Engine<MicroVmBackend>` to execute full OCI lifecycle operations, N-way branching (`run_branches`), and declarative rubric evaluation (`run_eval`) identically across Linux and macOS hosts.

### 2. Deterministic POSIX USTAR Rootfs Archive Export & Fail-Closed Import (`src/image.rs`)

- **Deterministic Export (`export_rootfs_tar`):**
  - Captures a `TreeManifest` of the source rootfs so entries are emitted in canonical lexicographical path order and internal pivot directories (`.boxlet_old_root`) are automatically excluded.
  - Emits standard 512-byte POSIX.1-1988 USTAR headers (`magic = "ustar\0"`, `version = "00"`) with zeroed `uid`, `gid`, and `mtime` (`00000000000\0`) so identical root filesystem trees produce bit-for-bit identical `.tar` streams and identical 64-bit FNV-1a digests (`archive_fnv1a64`).
  - Rejects relative paths or symlink targets exceeding the 100-byte USTAR field limit with `BoxletError::StateStore` (`ErrorKind::InvalidInput`) rather than silently truncating paths.
- **Fail-Closed Import (`import_rootfs_tar`):**
  - Verifies every 512-byte USTAR header checksum and magic signature before touching the target filesystem.
  - Rejects empty entry names, absolute paths (`/`), path traversal components (`..` / `Component::ParentDir`), and intermediate symlink ancestor traversal with `BoxletError::StateStore` (`ErrorKind::InvalidInput`, `"tar entry contains unsafe path traversal"`).
  - Applies directory permissions in reverse depth order after all child files and symlinks are extracted so read-only (`0555`) directories round-trip cleanly and `TreeManifest::capture(&original) == TreeManifest::capture(&imported)` holds identically.

## Alternatives Considered

1. **Shelling out to host `/usr/bin/tar`:**
   - *Rejected:* Host `tar` implementations differ between BSD `tar` (macOS) and GNU `tar` (Linux) in header extensions, uid/gid preservation, and xattr handling, breaking deterministic archive digests and adding external binary dependencies.
2. **Coupling Firecracker/libkrun configuration directly into `LinuxBackend`:**
   - *Rejected:* Violates the `RuntimeBackend` seam established in ADR-001 and prevents synthesizing and testing microVM configurations on macOS hosts using Hypervisor.framework (`libkrun`).

## Consequences & Failure Modes

- **Positive:**
  - `Engine<MicroVmBackend>` supports the full Boxlet SDK surface (`create`, `start`, `state`, `kill`, `delete`, `list`, `run`, `prune`, `run_branches`, `run_eval`) with zero platform-specific conditional compilation.
  - Rootfs snapshots and winning evaluation branches can be exported to and imported from portable `.tar` archives with cryptographic-style FNV-1a integrity verification and exact `TreeManifest` equivalence.
- **Failure modes & mitigations:**
  - *Malicious `.tar` path or symlink traversal:* `import_rootfs_tar` validates every path component and verifies that no ancestor directory inside `target_rootfs` is a symbolic link before writing files or creating subdirectories.
  - *Read-only directory extraction ordering:* Directories are created with owner write permissions during extraction and locked down to their recorded USTAR `mode` in deepest-first order at the end of `import_rootfs_tar`.
