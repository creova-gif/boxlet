# ADR-012: Declarative Bind Mounts and Portable OCI Seccomp Profile Management
- **Status:** Accepted
- **Owner:** Justin Mafie

## Context
Sandboxed workloads (such as AI agent evaluation loops, compiler toolchains, and read-only dataset runners) frequently need controlled access to specific host directories or files without copying multi-gigabyte datasets into every container rootfs or exposing the entire host filesystem. At the same time, security-sensitive deployments require visibility into Boxlet's default-deny `seccomp-bpf` syscall filter as well as the ability to supply audited, workload-specific OCI `LinuxSeccomp` JSON profiles from the CLI and Rust SDK.

Prior to V9:
- `ExecutionPolicy` did not expose declarative host-to-container bind mounts on `boxlet run` or `boxlet branch-run`, and `microvm-config` had no mechanism to translate policy bind mounts into hypervisor rootfs/virtio-fs drive specifications.
- Boxlet's baseline default-deny seccomp profile was constructed inside the Linux seccomp module without a portable public helper or CLI export command (`boxlet seccomp-export`) for offline auditing and customization on any host OS.

## Decision
1. **Declarative Bind Mounts (`BindMountSpec` & `--mount`):**
   - Introduce `BindMountSpec { source: PathBuf, destination: PathBuf, read_only: bool }` in `boxlet::policy` with `FromStr` parsing for `<src>:<dst>[:ro|rw]`, defaulting to read-only (`read_only = true`) when the mode suffix is omitted.
   - Reject relative paths and `..` path traversal components (`Component::ParentDir`) in both `source` and `destination` at parse and validation time.
   - Expose repeatable `--mount <src>:<dst>[:ro|rw]` flags on `boxlet run` and `boxlet branch-run`, populating `ExecutionPolicy::bind_mounts`.
   - Harden container init mount setup (`src/linux/mounts.rs`): before `pivot_root`, resolve the target path inside the new rootfs after canonicalizing intermediate symlinks so a symlink inside the container rootfs cannot redirect a bind mount onto an arbitrary host path, auto-create the mount target (directory or file matching the host source metadata), perform `MS_BIND | MS_REC`, and when `read_only` is set, immediately remount with `MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV`.
   - Extend `MicroVmConfig::build_firecracker_spec` and `MicroVmConfig::build_libkrun_spec` to accept policy `BindMountSpec` slices and project them into deterministic secondary Firecracker block drives (`/dev/vdb`, `/dev/vdc`, ...) and `libkrun` `virtio_fs_mounts`.

2. **Portable OCI Seccomp Profile Export & Custom Profile Loading:**
   - Extract `build_default_seccomp_profile() -> Result<oci_spec::runtime::LinuxSeccomp>` and `load_seccomp_profile(path: &Path) -> Result<oci_spec::runtime::LinuxSeccomp>` into `boxlet::policy` (and re-export them from the crate root) so they compile and run portably on both Linux and macOS.
   - Validate loaded seccomp profiles to reject empty syscall rules when the default action is `ScmpAction::ScmpActErrno` (which would otherwise block every syscall including `exit_group`).
   - Add `boxlet seccomp-export [--out <PATH>]` to serialize Boxlet's default-deny OCI `LinuxSeccomp` profile as pretty-printed JSON to stdout or a file.
   - Add `--seccomp-profile <PATH>` to `boxlet run` and `boxlet branch-run` to load a custom OCI `LinuxSeccomp` JSON profile into `ExecutionPolicy::seccomp` (`SeccompPolicy::Custom`).

## Alternatives Considered
- **Relying solely on manual edits to bundle `config.json` mounts and `linux.seccomp`:** Requires mutating the shared base bundle before every run or branch batch, preventing per-invocation policy overrides on immutable bundles.
- **Defaulting bind mounts to read-write (`rw`):** Violates least-privilege defaults for sandboxed agent workloads where host toolchains and datasets should be immutable unless explicitly opted into `:rw`.
- **Keeping seccomp profile generation Linux-only:** Prevents macOS and CI control-plane tooling from inspecting, exporting, or validating OCI seccomp profiles without a Linux VM.

## Consequences & Failure Modes
- **Least-privilege host sharing:** Host directories mounted via `--mount /host/data:/data` are read-only, `nosuid`, and `nodev` by default, preventing container processes from mutating host files or escalating privileges via setuid binaries or device nodes.
- **Symlink escape prevention:** Target path resolution verifies that the canonicalized mount destination remains strictly inside the container rootfs prior to `pivot_root`.
- **Auditable seccomp baseline:** Security engineers can run `boxlet seccomp-export --out seccomp.json`, inspect or tailor the exact OCI `LinuxSeccomp` allowlist, and pass `--seccomp-profile seccomp.json` to `boxlet run` or `boxlet branch-run`.
