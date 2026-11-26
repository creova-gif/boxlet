# CLI surface & embedding example

CLI surface verifies that the `boxlet` binary and the `examples/embed_run.rs` library embedding example compile cleanly, expose the documented OCI (`create`, `start`, `state`, `kill`, `delete`), V1 `run`, and V2 (`snapshot`, `diff`, `restore`, `branch-run`) subcommands, execute cross-platform V2 snapshot, diff, and restore commands end-to-end, and fail closed on unsupported network modes.

## Sub-features

- `cli-build` compiles `boxlet` (`src/main.rs`) and `examples/embed_run.rs` with zero errors.
- `cli-help` confirms `boxlet --help`, `boxlet run --help`, `boxlet create --help`, `boxlet snapshot --help`, `boxlet diff --help`, `boxlet restore --help`, and `boxlet branch-run --help` render the expected flags (`--root`, `--cgroup-parent`, `--memory`, `--cpus`, `--network`, `--json`, `--bundle`, `--rootfs`, `--out`, `--snapshot`, `--target`, `--promote-winner`, `--cmd`).
- `cli-v2-snapshot-diff-restore` executes `boxlet snapshot --rootfs <dir> --out <snaps> --json snap-1`, `boxlet diff --json <snaps>/snap-1 <after>`, and `boxlet restore --snapshot <snaps>/snap-1 --target <after> --json` against a temporary workspace tree and verifies the structured JSON output records the snapshot ID, added and modified relative paths, and an empty post-restore diff (`"added":[]`, `"modified":[]`, `"deleted":[]`).
- `cli-fail-closed` confirms `boxlet run --network bridge /nonexistent` exits non-zero and prints `unsupported network mode` rather than silently falling back to host networking.

## How to get to it (user POV)

- Build and invoke `boxlet --help`, `boxlet create --help`, `boxlet run --help`, `boxlet snapshot --help`, `boxlet diff --help`, `boxlet restore --help`, `boxlet branch-run --help`, or `boxlet run --memory 128m --cpus 0.5 --network none ./bundle`.
- Build `cargo build --example embed_run` to verify external Rust SDK integration.

## Driving it with control-boxlet

Preconditions:

- `control-boxlet launch --run <RUN_ID>` succeeded with `READY=true` (`docker` backend on macOS, `native` on Linux).
- `control-boxlet doctor --run <RUN_ID>` reported `doctor: OK`.

- **Build and exercise CLI surface.** Execute `.agents/skills/verify-boxlet/scripts/control-boxlet drive cli-surface --run <RUN_ID>`. Exit code is `0`, stdout includes the `--help` output for `boxlet`, `boxlet run`, `boxlet create`, `boxlet snapshot`, `boxlet diff`, `boxlet restore`, and `boxlet branch-run`, verifies live `snapshot`, `diff --json`, and `restore --json` execution on a scratch directory, and ends with `cli-verified: help subcommands + v2 snapshot/diff/restore + fail-closed network error`.
- **Inspect proof artifacts.** Read `/tmp/boxlet-verify-evidence/<RUN_ID>/cli-surface/stdout.txt`, `exit_code.txt`, and `meta.json`. `exit_code.txt` contains `0` and `stdout.txt` confirms help output, V2 snapshot/diff/restore JSON verification, and fail-closed network error handling.

## Gotchas

- Live privileged container execution (`sudo boxlet run ...` with `pivot_root`, `unshare`, and `/sys/fs/cgroup/boxlet.slice`) requires a privileged Linux 5.15+ host with unified cgroup v2 controller delegation. Inside unprivileged Docker containers on macOS, live container boot is `verified-unreachable` and is instead verified by the `linux-integration` job in `.github/workflows/ci.yml` on `ubuntu-latest`.
- The internal `boxlet __init` subcommand is intentionally hidden from `--help` output.
