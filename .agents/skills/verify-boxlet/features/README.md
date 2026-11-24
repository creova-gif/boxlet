# Boxlet verification map

This directory is the maintained source for verifying the user-facing behavior of Boxlet. Read this index before driving the crate, then follow the matching feature file as the literal recipe.

## Baseline preconditions

- Start from the repository root containing `Cargo.toml` (`name = "boxlet"`).
- Pick a unique `RUN_ID` per verification session (e.g. `verify-1`) so concurrent runs never share `CARGO_TARGET_DIR` or scratch crates.
- Run `.agents/skills/verify-boxlet/scripts/control-boxlet launch --run <RUN_ID>` and require `READY=true`.
- Run `.agents/skills/verify-boxlet/scripts/control-boxlet doctor --run <RUN_ID>` and require `doctor: OK`.
- Never mutate tracked workspace files during verification (`control-boxlet launch` copies the crate into `/tmp/boxlet-verify-<RUN_ID>/workspace`).

## Driving conventions

- Start every recipe from a launched and doctor-verified `RUN_ID`.
- Treat every command as literal; keep feature names and flags unchanged.
- Run all feature journeys through `.agents/skills/verify-boxlet/scripts/control-boxlet drive <feature> --run <RUN_ID>`.
- Always run `control-boxlet cleanup --run <RUN_ID>` after driving (including after failures). Cleanup removes `/tmp/boxlet-verify-<RUN_ID>` and preserves `/tmp/boxlet-verify-evidence/<RUN_ID>/`.

## Proof and skip reporting

- Every feature drive writes `command.txt`, `stdout.txt`, `stderr.txt`, `exit_code.txt`, and `meta.json` under `/tmp/boxlet-verify-evidence/<RUN_ID>/<feature>/`.
- Record the `RUN_ID`, backend (`native` or `docker`), and feature ID alongside any proof summary.
- If a feature cannot run due to an unmet precondition (e.g. missing local `cargo` and stopped Docker daemon), report the exact failing command and unmet precondition; never weaken assertions to make a journey pass.
- Do not report a feature as verified through a different feature's output.

## Feature entry contract

Each feature file starts with an H1 title and one paragraph describing the user-visible behavior. It then uses exactly four H2 sections in this order:

1. `Sub-features` lists short IDs with one line for each behavior.
2. `How to get to it (user POV)` lists every caller entry point.
3. `Driving it with control-boxlet` starts with `Preconditions:` and pairs each action with an exact command and observable result.
4. `Gotchas` lists traps that can waste or invalidate a verification run.

## Features

- [Healthcheck API](./healthcheck-api.md) proves an external Rust consumer crate can depend on `boxlet`, compile against its public API, and receive `"ok"` from `boxlet::healthcheck()`.
- [CI quality gates](./quality-gates.md) proves formatting, strict Clippy lints (`-D warnings`), and the Cargo test suite pass cleanly.
- [Public API documentation](./api-docs.md) proves `cargo doc --no-deps` builds with `-D warnings` and documents the exported `healthcheck` symbol.
