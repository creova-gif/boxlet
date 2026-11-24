# CLI surface & embedding example

CLI surface verifies that the `boxlet` binary and the `examples/embed_run.rs` library embedding example compile cleanly on Linux, expose the documented OCI (`create`, `start`, `state`, `kill`, `delete`) and `run` subcommands, and fail closed on unsupported V1 network modes.

## Sub-features

- `cli-build` compiles `boxlet` (`src/main.rs`) and `examples/embed_run.rs` with zero errors.
- `cli-help` confirms `boxlet --help`, `boxlet run --help`, and `boxlet create --help` render the expected flags (`--root`, `--cgroup-parent`, `--memory`, `--cpus`, `--network`, `--json`, `--bundle`).
- `cli-fail-closed` confirms `boxlet run --network bridge /nonexistent` exits non-zero and prints `unsupported network mode` rather than silently falling back to host networking.

## How to get to it (user POV)

- Build and invoke `boxlet --help`, `boxlet create --help`, `boxlet run --help`, or `boxlet run --memory 128m --cpus 0.5 --network none ./bundle` from a Linux shell.
- Build `cargo build --example embed_run` to verify external Rust SDK integration.

## Driving it with control-boxlet

Preconditions:

- `control-boxlet launch --run <RUN_ID>` succeeded with `READY=true` on Linux (`docker` backend on macOS, `native` on Linux).
- `control-boxlet doctor --run <RUN_ID>` reported `doctor: OK`.

- **Build and exercise CLI surface.** Execute `.agents/skills/verify-boxlet/scripts/control-boxlet drive cli-surface --run <RUN_ID>`. Exit code is `0`, stdout includes the `--help` output for `boxlet`, `boxlet run`, and `boxlet create`, and ends with `cli-verified: help subcommands + fail-closed network error`.
- **Inspect proof artifacts.** Read `/tmp/boxlet-verify-evidence/<RUN_ID>/cli-surface/stdout.txt`, `exit_code.txt`, and `meta.json`. `exit_code.txt` contains `0` and `stdout.txt` confirms help output and fail-closed network error handling.

## Gotchas

- Live privileged container execution (`sudo boxlet run ...` with `pivot_root`, `unshare`, and `/sys/fs/cgroup/boxlet.slice`) requires a privileged Linux 5.15+ host with unified cgroup v2 controller delegation. Inside unprivileged Docker containers on macOS, live container boot is `verified-unreachable` and is instead verified by the `linux-integration` job in `.github/workflows/ci.yml` on `ubuntu-latest`.
- The internal `boxlet __init` subcommand is intentionally hidden from `--help` output.
