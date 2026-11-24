# Public API documentation

Public API documentation verifies that Boxlet's exported crate symbols build cleanly under `rustdoc` with warnings treated as errors and appear in the generated crate index.

## Sub-features

- `doc-build` compiles crate docs with `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`.
- `doc-symbol-index` confirms `doc/boxlet/index.html` is generated and lists `healthcheck`.

## How to get to it (user POV)

- Run `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` and open `target/doc/boxlet/index.html`.

## Driving it with control-boxlet

Preconditions:

- `control-boxlet launch --run <RUN_ID>` succeeded with `READY=true`.
- `control-boxlet doctor --run <RUN_ID>` reported `doctor: OK`.

- **Build and verify docs.** Execute `.agents/skills/verify-boxlet/scripts/control-boxlet drive api-docs --run <RUN_ID>`. Exit code is `0` and stdout prints `doc-verified: boxlet::healthcheck present in index.html`.
- **Inspect proof artifacts.** Read `/tmp/boxlet-verify-evidence/<RUN_ID>/api-docs/stdout.txt`, `exit_code.txt`, and `meta.json`. `exit_code.txt` contains `0` and `stdout.txt` confirms the generated HTML artifact exists and references `healthcheck`.

## Gotchas

- `cargo doc` without `RUSTDOCFLAGS="-D warnings"` silently passes broken intra-doc links and missing-doc lints.
- Generated HTML lives in `/tmp/boxlet-verify-<RUN_ID>/target/doc/` and is removed on `cleanup`; the captured proof in `/tmp/boxlet-verify-evidence/<RUN_ID>/api-docs/` persists after cleanup.
