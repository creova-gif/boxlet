---
name: verify-boxlet
description: "Verify the Boxlet Rust crate and OCI runtime CLI (library API, CLI surface, CI quality gates, and public API docs) in an isolated Linux Docker or native Linux environment with reproducible proof artifacts. Use when proving Boxlet behavior, checking changes before shipping, or validating the public crate and CLI surface."
---

# Verify Boxlet

Boxlet is a minimal Linux 5.15+ OCI-compatible container runtime and embeddable Rust execution core (`boxlet` v0.1.0). Its user-facing surfaces are:
- **Rust library crate** (`src/lib.rs`, `src/engine.rs`, `src/policy.rs`, `src/traits.rs`, `src/oci/`, `src/error.rs`, plus `LinuxBackend` on Linux and `examples/embed_run.rs`).
- **OCI + developer CLI binary** (`src/main.rs`: `boxlet create|start|state|kill|delete|run`, global `--root` and `--cgroup-parent`).
- **CI quality & Linux integration gates** (`.github/workflows/ci.yml`: `rustfmt`, `clippy --all-targets -D warnings`, `cargo test`, `cargo doc --no-deps`, `cargo audit`, and privileged `ubuntu-latest` container execution).

All commands below use the bundled helper script at `.agents/skills/verify-boxlet/scripts/control-boxlet`.

## Launch

Boxlet is a short-lived Rust CLI and library (no long-running server). Launch initializes a per-run isolated scratch directory (`/tmp/boxlet-verify-<RUN_ID>`), snapshots the crate into `/tmp/boxlet-verify-<RUN_ID>/workspace`, selects the execution backend, and pre-builds into an isolated `CARGO_TARGET_DIR`.

```bash
HARNESS=".agents/skills/verify-boxlet/scripts/control-boxlet"
"$HARNESS" launch --run verify-1
```

- **Backend selection:** Uses `native` on Linux hosts when `cargo` and `rustc` are on `PATH`; defaults to `docker` (`boxlet-verify-rust:1-slim`, built automatically from `rust:1-slim` with `rustfmt` and `clippy`) on macOS/non-Linux hosts so Linux-only modules (`src/linux/*`) are always compiled and tested. Override with `BOXLET_VERIFY_BACKEND=native|docker`.
- **Readiness signal:** Exit code `0` and stdout ending with `READY=true`, plus `/tmp/boxlet-verify-<RUN_ID>/run.env` created.
- **Isolation:** Each `--run <RUN_ID>` uses distinct `/tmp/boxlet-verify-<RUN_ID>` scratch and `/tmp/boxlet-verify-evidence/<RUN_ID>` proof directories. Never reuse a `RUN_ID` across concurrent sessions.

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
- **CLI surface & embedding example** ([`features/cli-surface.md`](features/cli-surface.md)):
  ```bash
  "$HARNESS" drive cli-surface --run verify-1
  ```

## Evidence

Every `control-boxlet drive <feature> --run <RUN_ID>` call writes proof artifacts to `/tmp/boxlet-verify-evidence/<RUN_ID>/<feature>/` (or `--evidence <dir>`):

- `command.txt` — exact command executed
- `stdout.txt` — captured standard output
- `stderr.txt` — captured standard error
- `exit_code.txt` — process exit code
- `meta.json` — `run_id`, `feature`, `backend`, `exit_code`, UTC timestamp, and `evidence_dir`

**Proof standards:**
- Exercise real caller paths: `healthcheck` compiles and executes an external Cargo consumer crate; `cli-surface` builds and executes the real `boxlet` binary and `examples/embed_run.rs`.
- Capture both the action (`command.txt`) and resulting state (`stdout.txt`, `stderr.txt`, `exit_code.txt`, `meta.json`).
- Verify side effects alongside stdout (e.g., `api-docs` verifies `target/doc/boxlet/index.html` exists and exports `healthcheck`, `Engine`, `engine`, `policy`, `oci`, `traits`, and `error`).
- Never claim privileged Linux container execution (`pivot_root` + cgroup v2 `boxlet.slice`) as locally verified unless run on a privileged Linux 5.15+ host or GitHub Actions `linux-integration`.

## Cleanup

Tear down the run's scratch directory and any containers created for that run:

```bash
"$HARNESS" cleanup --run verify-1
```

- Removes only `/tmp/boxlet-verify-<RUN_ID>` and Docker containers matching `--filter label=boxlet-verify-run=<RUN_ID>`. Never kills processes by name.
- **Preserves evidence:** `/tmp/boxlet-verify-evidence/<RUN_ID>/` survives cleanup untouched.

## Helpers

- [`.agents/skills/verify-boxlet/scripts/control-boxlet`](scripts/control-boxlet) — executable Bash harness implementing `launch`, `doctor`, `drive`, and `cleanup`. Run `control-boxlet --help` for all flags and environment overrides.
