# CI quality gates

CI quality gates verify that Boxlet conforms to the repository's formatting, static analysis, and unit test contract defined in `.github/workflows/ci.yml` and `AGENTS.md`.

## Sub-features

- `gate-fmt` enforces `rustfmt` compliance via `cargo fmt --check`.
- `gate-clippy` enforces zero Clippy warnings across all targets (lib, bin, examples, tests) via `cargo clippy --all-targets -- -D warnings`.
- `gate-test` executes the full Cargo unit test suite across both the library crate and `boxlet` CLI binary via `cargo test`.

## How to get to it (user POV)

- Run `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` on Linux (plus `cargo audit` in CI), or push a commit/PR to trigger `.github/workflows/ci.yml`.

## Driving it with control-boxlet

Preconditions:

- `control-boxlet launch --run <RUN_ID>` succeeded with `READY=true` on Linux (`native` on Linux or `docker` on macOS).
- `control-boxlet doctor --run <RUN_ID>` reported `doctor: OK`.

- **Run all three gates.** Execute `.agents/skills/verify-boxlet/scripts/control-boxlet drive quality-gates --run <RUN_ID>`. Exit code is `0`, `cargo fmt --check` produces no diff, `cargo clippy --all-targets -- -D warnings` reports zero warnings, and `cargo test` passes all lib and CLI bin tests (`test result: ok`).
- **Inspect proof artifacts.** Read `/tmp/boxlet-verify-evidence/<RUN_ID>/quality-gates/stdout.txt`, `stderr.txt`, and `exit_code.txt`. `exit_code.txt` contains `0` and `stdout.txt` includes passing test summaries for both `src/lib.rs` and `src/main.rs`.

## Gotchas

- `cargo fmt --check` exits non-zero on any unformatted Rust file without modifying the workspace; fix formatting in the repo before re-running.
- On macOS hosts with a local Rust toolchain, forcing `BOXLET_VERIFY_BACKEND=native` skips `src/linux/*` and can fail `clippy --all-targets` on Linux-only imports in `src/main.rs`. Always use the default `docker` Linux backend on macOS to match `.github/workflows/ci.yml` (`ubuntu-latest`).
- `cargo audit` and the privileged `linux-integration` job run in GitHub Actions CI (`.github/workflows/ci.yml`) and are not executed by the local `quality-gates` drive.
