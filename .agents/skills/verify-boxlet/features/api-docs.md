# Public API documentation

Public API documentation verifies that Boxlet's exported crate modules, types, and functions build cleanly under `rustdoc` with warnings treated as errors and appear in the generated crate index.

## Sub-features

- `doc-build` compiles crate docs with `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`.
- `doc-symbol-index` confirms `target/doc/boxlet/index.html` is generated and lists `healthcheck`, `Engine`, `engine`, `policy`, `oci`, `snapshot`, `audit`, `doctor`, `eval`, `image`, `microvm`, `bench`, `traits`, `error`, `BundleBuilder`, `AuditEvent`, `JsonlAuditLogger`, `PruneReport`, `AuditSummary`, `DoctorReport`, `EvalSpec`, `EvalRubric`, `EvalReport`, `RootfsArchiveReport`, `OciImageLayoutReport`, `OciLayerDescriptor`, `IoMaxRule`, `PsiMetrics`, `BindMountSpec`, `build_default_seccomp_profile`, `load_seccomp_profile`, `BenchmarkConfig`, `BenchmarkReport`, `LatencySummary`, `MicroVmConfig`, and `MicroVmBackend`, and confirms the V2 branching contracts `BranchSpec`, `BranchExecutionResult`, and `BranchBatchReport` appear in the generated `rustdoc` HTML (`target/doc/boxlet/engine/index.html` or `target/doc/boxlet/index.html`).

## How to get to it (user POV)

- Run `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` and open `target/doc/boxlet/index.html`.

## Driving it with control-boxlet

Preconditions:

- `control-boxlet launch --run <RUN_ID>` succeeded with `READY=true`.
- `control-boxlet doctor --run <RUN_ID>` reported `doctor: OK`.

- **Build and verify docs.** Execute `.agents/skills/verify-boxlet/scripts/control-boxlet drive api-docs --run <RUN_ID>`. Exit code is `0` and stdout prints `doc-verified: healthcheck, Engine, engine, policy, oci, snapshot, audit, doctor, eval, image, microvm, bench, traits, error, BundleBuilder, AuditEvent, JsonlAuditLogger, PruneReport, AuditSummary, DoctorReport, EvalSpec, EvalRubric, EvalReport, RootfsArchiveReport, OciImageLayoutReport, OciLayerDescriptor, IoMaxRule, PsiMetrics, BindMountSpec, build_default_seccomp_profile, load_seccomp_profile, BenchmarkConfig, BenchmarkReport, LatencySummary, MicroVmConfig, MicroVmBackend, BranchSpec, BranchExecutionResult, BranchBatchReport present in rustdoc output`.
- **Inspect proof artifacts.** Read `/tmp/boxlet-verify-evidence/<RUN_ID>/api-docs/stdout.txt`, `exit_code.txt`, and `meta.json`. `exit_code.txt` contains `0` and `stdout.txt` confirms the generated HTML index exists and documents all exported V1, V2, V3, V4, V5, V6 (ADR-009: tamper-evident hash-chained `AuditRecord` / `AuditSummary::to_prometheus_text`, `ExecutionPolicy::max_concurrency`, and `BundleBuilder::with_rootless`), V7 (ADR-010: `IoMaxRule`, `ExecutionPolicy::io_max`, `OciImageLayoutReport`, `OciLayerDescriptor`, `pack_oci_image_layout`, and `unpack_oci_image_layout`), V8 (ADR-011: `PsiMetrics`, `ExecutionPolicy::nofile_limit`, `BenchmarkConfig`, `BenchmarkReport`, `LatencySummary`, and `Engine::run_benchmark`), and V9 (ADR-012: `BindMountSpec`, `ExecutionPolicy::bind_mounts`, `ExecutionPolicy::seccomp_profile_path`, `build_default_seccomp_profile`, and `load_seccomp_profile`) public modules and symbols.

## Gotchas

- `cargo doc` without `RUSTDOCFLAGS="-D warnings"` silently passes broken intra-doc links and missing-doc lints.
- Linux-only exports (`LinuxBackend`, `run_internal_init`) are only included when built on Linux (`docker` backend or native Linux host).
- Generated HTML lives in `/tmp/boxlet-verify-<RUN_ID>/target/doc/` and is removed on `cleanup`; the captured proof in `/tmp/boxlet-verify-evidence/<RUN_ID>/api-docs/` persists after cleanup.
