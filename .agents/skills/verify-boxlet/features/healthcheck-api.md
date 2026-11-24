# Healthcheck API

Healthcheck API lets an external Rust consumer depend on the `boxlet` crate, call `boxlet::healthcheck()`, and receive the static `"ok"` readiness string.

## Sub-features

- `healthcheck-linkage` compiles a standalone consumer binary crate against `boxlet` via path dependency.
- `healthcheck-return` calls `boxlet::healthcheck()` at runtime and verifies exact stdout `ok` with exit code `0`.

## How to get to it (user POV)

- Add `boxlet = { path = "<path-to-boxlet>" }` to a Rust consumer's `Cargo.toml` and call `boxlet::healthcheck()` from `main()`.

## Driving it with control-boxlet

Preconditions:

- `control-boxlet launch --run <RUN_ID>` succeeded with `READY=true`.
- `control-boxlet doctor --run <RUN_ID>` reported `doctor: OK`.

- **Build and run external consumer.** Generate a disposable consumer crate in the run scratch dir, compile it against `boxlet`, and execute it. Run `.agents/skills/verify-boxlet/scripts/control-boxlet drive healthcheck --run <RUN_ID>`. Exit code is `0` and stdout prints `ok`.
- **Inspect proof artifacts.** Read `/tmp/boxlet-verify-evidence/<RUN_ID>/healthcheck/stdout.txt`, `exit_code.txt`, and `meta.json`. `stdout.txt` contains `ok`, `exit_code.txt` contains `0`, and `meta.json` records `feature: "healthcheck"` and `exit_code: 0`.

## Gotchas

- Passing `cargo test` inside `boxlet` alone does not prove public visibility (`pub fn`); the external consumer crate catches accidental `pub(crate)` or private symbol regressions.
- Because `control-boxlet launch` snapshots the crate into `/tmp/boxlet-verify-<RUN_ID>/workspace`, re-run `launch` with a fresh `RUN_ID` after editing `src/` or `Cargo.toml`.
- Do not delete `/tmp/boxlet-verify-evidence/<RUN_ID>/` when cleaning up the consumer crate.
