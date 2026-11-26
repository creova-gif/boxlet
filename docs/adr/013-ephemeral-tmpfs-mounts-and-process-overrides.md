# ADR-013: Ephemeral Size-Bounded Tmpfs Mounts and Per-Run Process Overrides
- **Status:** Accepted
- **Owner:** Justin Mafie

## Context
Autonomous AI agents and untrusted tool-use workloads frequently execute inside read-only root filesystems (`root.readonly = true`, scaffolded via `boxlet init-bundle --readonly`) to prevent persistent tampering with system binaries or libraries. However, compilers, interpreters, and standard Unix tools still require bounded scratch directories (such as `/tmp`, `/run`, or `/var/tmp`) that vanish when the container exits and cannot exhaust host memory.

In addition, orchestrators reusing a single immutable OCI bundle across many `boxlet run` or `boxlet branch-run` invocations need to override the container command (`--cmd`), inject or override environment variables (`-e` / `--env`), and change the working directory (`--cwd`) per execution without mutating the on-disk bundle's `config.json`.

## Decision
1. **Ephemeral Size-Bounded `tmpfs` Mounts (`TmpfsMountSpec`, `--tmpfs`):**
   - Introduce `TmpfsMountSpec` in `boxlet::policy` (`destination: PathBuf`, `size_bytes: u64`, `mode: u32`, `noexec: bool`) with human-readable CLI syntax `<dst>[:size=64m,mode=1777,noexec|exec]` exposed via `--tmpfs` on `boxlet run` and `boxlet branch-run`.
   - Enforce strict validation: `destination` must be an absolute path inside the container without `..` traversal components, `size_bytes` must be strictly positive (`> 0`, defaulting to `64 MiB`), and `mode` must be `<= 0o7777` (defaulting to `0o1777`).
   - Synthesize OCI `Mount` entries with `typ = "tmpfs"`, `source = "tmpfs"`, and options `["nosuid", "nodev", "noexec"|"exec", "size=<bytes>", "mode=<octal>"]`.
   - In `src/linux/mounts.rs`, mount `tmpfs` targets inside the container mount namespace before `pivot_root` (creating mountpoint directories while the rootfs is still writable before applying `MS_RDONLY` remount) using `MsFlags::MS_NOSUID | MsFlags::MS_NODEV` (and `MsFlags::MS_NOEXEC` by default unless `exec` is explicitly requested) and passing `size=<bytes>,mode=<octal>` in the kernel `mount(2)` `data` parameter.

2. **Per-Run Process Overrides (`args_override`, `env_overrides`, `cwd_override`):**
   - Extend `ExecutionPolicy` with `args_override: Option<Vec<String>>` (`--cmd <CMD>` -> `["/bin/sh", "-c", "<CMD>"]`), `env_overrides: Option<Vec<String>>` (`-e` / `--env KEY=VALUE`), and `cwd_override: Option<String>` (`--cwd <PATH>`).
   - Validate in `ExecutionPolicy::validate()` that `args_override` is non-empty when present, every `env_overrides` entry is `KEY=VALUE` with a non-empty key containing no NUL bytes, and `cwd_override` is an absolute path without `..` components.
   - Apply process overrides in-memory inside `LinuxBackend::merge_policy_with_spec` (and propagate to `MicroVmConfig` for Firecracker and `libkrun` specs) by overlaying `args`, upserting `KEY=VALUE` entries in `process.env` by key name, and updating `process.cwd`, leaving the bundle's on-disk `config.json` untouched.

## Alternatives Considered
- **Mutating `bundle/config.json` on disk before each run:** Rejected because concurrent executions (`branch-run`, `eval`, or multi-agent workers sharing a base bundle) would race on `config.json` and violate bundle immutability.
- **Unbounded `tmpfs` mounts without `size=` or `MS_NOEXEC` defaults:** Rejected because an untrusted workload inside the container could exhaust host RAM via `/tmp` writes or execute dropped payloads from scratch space by default.
- **Requiring host-backed `--mount` directories for `/tmp`:** Rejected because host bind mounts persist artifacts on the host filesystem unless manually cleaned up and do not enforce kernel-level in-memory byte caps.

## Consequences & Failure Modes
- **Read-Only Rootfs Compatibility:** Because `prepare_rootfs` creates mountpoints and mounts `tmpfs` before remounting `/` read-only (`MS_BIND | MS_REMOUNT | MS_RDONLY`), read-only containers can still mount writable, size-bounded `/tmp` or `/run` scratch directories as long as the top-level mountpoint exists or can be created prior to the read-only remount.
- **Memory Accounting:** Kernel `tmpfs` pages are charged to the container's cgroup v2 `memory.max` controller in addition to the per-mount `size=<bytes>` ceiling, ensuring defense in depth against memory exhaustion.
- **Validation Failures:** Malformed `--tmpfs` options, relative destinations, empty `--cmd` overrides, or `-e` entries missing `=` fail fast with `BoxletError::InvalidPolicy` before any namespace or cgroup state is created.
