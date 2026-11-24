# CI quality gates

CI quality gates verify that Boxlet conforms to the repository's formatting, static analysis, and unit test contract defined in `.github/workflows/ci.yml` and `AGENTS.md`.

## Sub-features

- `gate-fmt` enforces `rustfmt` compliance via `cargo fmt --check`.
- `gate-clippy` enforces zero Clippy warnings via `cargo clippy -- -D warnings`.
- `gate-test` executes the Cargo unit and doc test suite via `cargo test`.

## How to get to it (user POV)

- Run `cargo fmt --check && cargo clippy -- -D warnings && cargo test` locally or push a commit/PR to trigger `.github/workflows/ci.yml`.

## Driving it with control-boxlet

Preconditions:

- `control-boxlet launch --run <RUN_ID>` succeeded with `READY=true`.
- `control-boxlet doctor --run <RUN_ID>` reported `doctor: OK`.

- **Run all three gates.** Execute `.agents/skills/verify-boxlet/scripts/control-boxlet drive quality-gates --run <RUN_ID>`. Exit code is `0`, `cargo fmt --check` produces no diff, Clippy reports no warnings, and `cargo test` reports `test result: ok` with `tests::smoke_test ... ok`.
- **Inspect proof artifacts.** Read `/tmp/boxlet-verify-evidence/<RUN_ID>/quality-gates/stdout.txt`, `stderr.txt`, and `exit_code.txt`. `exit_code.txt` contains `0` and `stdout.txt` includes the passing `cargo test` summary.

## Gotchas

- `cargo fmt --check` exits non-zero on any unformatted Rust file without modifying the workspace; fix formatting in the repo before re-running.
- Running `cargo clippy` without `-- -D warnings` hides warnings that fail CI; always run through `control-boxlet drive quality-gates`.
- Under the `docker` backend, `CARGO_TARGET_DIR` is redirected to `/scratch/target` so no `target/` directory is created inside the workspace.
