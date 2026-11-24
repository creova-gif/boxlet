---
name: verify-boxlet
description: "Verify the Boxlet Rust crate (library API, CI quality gates, and public API docs) in an isolated native or Linux Docker environment with reproducible proof artifacts. Use when proving Boxlet behavior, checking changes before shipping, or validating the public crate surface."
---

# Verify Boxlet

Boxlet is a minimal OCI-compatible container runtime implemented in Rust. At the current repository revision (`boxlet` v0.1.0), the checked-in surface is a Rust library crate (`Cargo.toml`, `src/lib.rs`) exposing `boxlet::healthcheck() -> &'static str`, gated by CI (`cargo fmt --check && cargo clippy -- -D warnings && cargo test`). No CLI binary (`src/main.rs`) exists yet; when CLI or OCI runtime commands are added, update this skill and `features/` via `/maintain-verification-skill`.

All commands below use the bundled helper script at `.agents/skills/verify-boxlet/scripts/control-boxlet`.

## Launch

Boxlet is a short-lived Rust library/build target (no long-running server). Launch initializes a per-run isolated scratch directory (`/tmp/boxlet-verify-<RUN_ID>`), selects the execution backend, and compiles the crate into an isolated `CARGO_TARGET_DIR` so concurrent runs never contend on `target/` or mutate the workspace.

```bash
HARNESS=".agents/skills/verify-boxlet/scripts/control-boxlet"
"$HARNESS" launch --run verify-1
```

- **Backend selection:** Uses `native` if `cargo` and `rustc` are on `PATH`; otherwise uses `docker` (`boxlet-verify-rust:1-slim`, built automatically from `rust:1-slim` with `rustfmt` and `clippy` added). Both backends operate on a per-run snapshot of the crate in `/tmp/boxlet-verify-<RUN_ID>/workspace` so `Cargo.lock` and `target/` never mutate the repository. Override with `BOXLET_VERIFY_BACKEND=native|docker`.
- **Readiness signal:** Exit code `0` and stdout ending with `READY=true`, plus `/tmp/boxlet-verify-<RUN_ID>/run.env` created.
- **Isolation:** Two runs with different `--run <RUN_ID>` values use distinct `/tmp/boxlet-verify-<RUN_ID>` scratch dirs, distinct `CARGO_TARGET_DIR` paths, and distinct `/tmp/boxlet-verify-evidence/<RUN_ID>` proof directories. Never reuse a `RUN_ID` across concurrent sessions.

## Doctor

Run this read-only check before driving features or whenever a build/run looks off:

```bash
"$HARNESS" doctor --run verify-1
```

Doctor verifies:
1. `Cargo.toml` at the repo root defines `name = "boxlet"`.
2. The selected backend (`native` or `docker`) is healthy and prints `rustc`, `cargo`, `rustfmt`, and `clippy` versions.
3. The run manifest `/tmp/boxlet-verify-<RUN_ID>/run.env` exists and points to a valid scratch directory.
4. Outputs `doctor: OK` and exits `0`.

## Drive

Read [`features/README.md`](features/README.md) first, then follow the recipe for the feature you are proving:

- **External caller `healthcheck` API** ([`features/healthcheck-api.md`](features/healthcheck-api.md)):
  ```bash
  "$HARNESS" drive healthcheck --run verify-1
  ```
- **CI & `AGENTS.md` quality gates** ([`features/quality-gates.md`](features/quality-gates.md)):
  ```bash
  "$HARNESS" drive quality-gates --run verify-1
  ```
- **Public API rustdoc contract** ([`features/api-docs.md`](features/api-docs.md)):
  ```bash
  "$HARNESS" drive api-docs --run verify-1
  ```

## Evidence

Every `control-boxlet drive <feature> --run <RUN_ID>` call writes proof artifacts to `/tmp/boxlet-verify-evidence/<RUN_ID>/<feature>/` (or `--evidence <dir>`):

- `command.txt` — exact command executed
- `stdout.txt` — captured standard output
- `stderr.txt` — captured standard error
- `exit_code.txt` — process exit code
- `meta.json` — `run_id`, `feature`, `backend`, `exit_code`, UTC timestamp, and `evidence_dir`

**Proof standards:**
- Exercise the real caller path: `healthcheck` compiles and runs a separate external Cargo binary crate that depends on `boxlet` by path rather than relying solely on internal `#[cfg(test)]` unit tests.
- Capture both the action (`command.txt`) and the resulting state (`stdout.txt`, `stderr.txt`, `exit_code.txt`, `meta.json`).
- Verify side effects alongside stdout (e.g., `api-docs` asserts the generated `doc/boxlet/index.html` exists on disk and exports `healthcheck`).
- Never report a skipped feature or backend as verified through another path. If `docker` is used on macOS because local `cargo` is absent, note that `native` macOS execution was not exercised.

## Cleanup

Tear down the run's scratch directory and any containers created for that run:

```bash
"$HARNESS" cleanup --run verify-1
```

- Removes only `/tmp/boxlet-verify-<RUN_ID>` and Docker containers matching `--filter label=boxlet-verify-run=<RUN_ID>`. Never kills processes by name.
- **Preserves evidence:** `/tmp/boxlet-verify-evidence/<RUN_ID>/` survives cleanup untouched.

## Helpers

- [`.agents/skills/verify-boxlet/scripts/control-boxlet`](scripts/control-boxlet) — executable Bash harness implementing `launch`, `doctor`, `drive`, and `cleanup`. Run `control-boxlet --help` for all flags and environment overrides.
