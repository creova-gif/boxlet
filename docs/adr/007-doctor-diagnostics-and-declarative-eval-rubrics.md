# ADR-007: Host Readiness Diagnostics (`boxlet doctor`) and Declarative Multi-Agent Evaluation Rubrics (`boxlet eval`)
- **Status:** Accepted
- **Owner:** Justin Mafie
- **Date:** 2026-11-26

## Context

As Boxlet is deployed across heterogeneous developer machines, CI runners, and Linux production hosts to execute parallel AI coding-agent branches, operators and agent harnesses face two recurring operational challenges:

1. **Opaque Host Environment Failures (`boxlet doctor`):**
   - Executing OCI containers in Boxlet V1 relies on specific Linux kernel capabilities: a Linux 5.15+ kernel, root privileges (`euid == 0`), a unified cgroup v2 hierarchy mounted at `/sys/fs/cgroup` with `memory`, `cpu`, and `pids` controllers enabled, and a `seccompiler`-supported CPU architecture (`x86_64` or `aarch64`).
   - Previously, misconfigured hosts only surfaced errors mid-run when container creation or cgroup setup failed. Operators and automated CI pipelines need a fast, non-destructive preflight probe (`boxlet doctor [--json]`) that checks every host prerequisite in deterministic order and provides actionable remediation guidance.

2. **Ad-Hoc Candidate Selection and Reward Hacking in Parallel Branch Runs (`boxlet eval`):**
   - `Engine::run_branches_with_promotion` (ADR-005) promotes the first branch that exits with code `0` and zero resource/timeout violations.
   - However, in multi-agent code generation and repair benchmarks, an agent candidate might exit `0` while deleting or modifying protected test harnesses (`tests/`, `.github/`), failing to emit required verification markers on `stdout`, emitting fatal diagnostics on `stderr`, or touching an excessive number of files.
   - Furthermore, when multiple candidates satisfy all correctness and guardrail constraints, callers want deterministic ranking that favors minimal, surgical diffs (`total_changes()`) and faster execution over bloated patches, without writing custom host-side shell scripts around `boxlet branch-run`.

## Decision

### 1. Structured Host Preflight Diagnostics (`src/doctor.rs` & `boxlet doctor`)

We introduce `boxlet::doctor::{run_doctor, parse_kernel_major_minor, DoctorCheck, DoctorReport, DoctorStatus}` and the `boxlet doctor [--json]` CLI subcommand:

- **`DoctorStatus` (`Pass`, `Warn`, `Fail`):** Classifies each diagnostic probe outcome.
- **`DoctorCheck`:** Records `name`, `status`, observed `detail`, and optional `remediation` advice when `status != DoctorStatus::Pass`.
- **`DoctorReport`:** Aggregates `overall_ready` (`true` when zero checks report `DoctorStatus::Fail`), `host_os`, `host_arch`, and the ordered `Vec<DoctorCheck>`.
- **Five Deterministic Probes in `run_doctor(state_root, cgroup_parent)`:**
  1. `host_os`: Verifies `cfg!(target_os = "linux")` and reports the configured `state_root`.
  2. `kernel_version`: Reads `/proc/sys/kernel/osrelease` on Linux and verifies kernel version `>= 5.15` via `parse_kernel_major_minor` (`Warn` on non-Linux hosts or unreadable `/proc`).
  3. `root_privileges`: Checks `libc::geteuid() == 0` on Linux (`Warn` on non-Linux hosts).
  4. `cgroup_v2`: Inspects `/sys/fs/cgroup/cgroup.controllers` on Linux to confirm unified cgroup v2 mount presence and `memory`, `cpu`, and `pids` controller availability alongside `cgroup_parent` (`Warn` if optional controllers are missing or on non-Linux hosts; `Fail` if `/sys/fs/cgroup/cgroup.controllers` is absent on Linux).
  5. `seccomp_arch`: Verifies `std::env::consts::ARCH` is `x86_64` or `aarch64`.

### 2. Declarative Multi-Agent Evaluation Rubrics (`src/eval.rs`, `Engine::run_eval`, & `boxlet eval`)

We introduce `boxlet::eval::{evaluate_candidate, select_winning_verdict, CandidateVerdict, EvalReport, EvalRubric, EvalSpec}`, `Engine::run_eval`, and the `boxlet eval --spec <SPEC.json> [--promote-winner] [--json] <BUNDLE>` CLI subcommand:

- **`EvalRubric` Guardrails:**
  - `require_exit_zero` (defaults to `true`): Requires `exit_code == Some(0)`, `!timed_out`, and `!oom_killed`.
  - `required_stdout_contains`: Substrings that must appear in UTF-8 `stdout`.
  - `forbidden_stderr_contains`: Substrings that must not appear in UTF-8 `stderr`.
  - `required_added_paths`: Relative paths that must appear in `fs_diff.added`.
  - `forbidden_modified_paths`: Protected relative file or directory paths that must not be modified (`fs_diff.modified`) or deleted (`fs_diff.deleted`), matching both exact paths and directory prefixes (`path.starts_with(forbidden)`).
  - `max_changed_files`: Optional upper bound on `fs_diff.total_changes()`.
- **Deterministic Scoring (`evaluate_candidate`) and Ranking (`select_winning_verdict`):**
  - Candidates with zero rubric violations receive `passed_rubric = true` and a deterministic score:
    `10_000 - (fs_diff.total_changes() as i64 * 10) - (usage.duration.as_millis().min(5_000) as i64)`
    This rewards smaller, surgical diffs first and faster execution second.
  - Candidates with one or more violations receive `passed_rubric = false` and `score = -(violations.len() as i64 * 1000)`.
  - `select_winning_verdict` selects the passing candidate with the highest `score`, breaking ties deterministically by earliest position in `EvalSpec::candidates`.
- **Atomic Winner Promotion & Audit Telemetry (`Engine::run_eval`):**
  - When `spec.promote_winner` is `true` and a winning candidate exists, `Engine::run_eval` promotes the winner's rootfs onto the source bundle via `WorkspaceSnapshot::promote_branch` (with automatic snapshot rollback on I/O failure) and records a `BranchBatchCompleted` event in the `.jsonl` audit log.

## Alternatives Considered

1. **Relying solely on exit code `0` in `boxlet branch-run --promote-winner`:**
   - *Rejected:* Exit code `0` alone cannot prevent an untrusted coding agent from tampering with protected test files inside the writable branch rootfs or selecting a 50-file diff when a 1-file diff also passes tests.
2. **Embedding an external scripting engine (Lua/Python) for rubric evaluation:**
   - *Rejected:* Adds heavy dependencies, non-deterministic execution time, and security surface area, whereas a declarative JSON `EvalSpec` covers exit status, output assertions, protected path guardrails, diff size bounds, and deterministic scoring in pure Rust.

## Consequences & Failure Modes

- **Positive:**
  - `boxlet doctor` gives instant, machine-readable (`--json`) host readiness diagnostics across both Linux production hosts and macOS development environments.
  - `boxlet eval` prevents test-tampering reward hacks via `forbidden_modified_paths` and deterministically promotes the cleanest, fastest passing branch.
- **Failure modes & mitigations:**
  - *Directory-level protected path bypass:* If a rubric protects `tests/harness` and a candidate modifies `tests/harness/judge.rs`, exact path matching alone would miss it; `evaluate_candidate` checks `p == forbidden || p.starts_with(forbidden)` across both `modified` and `deleted` paths.
  - *No candidate satisfies the rubric:* `winning_branch_id` is `None`, `promoted` is `false`, the source bundle rootfs remains untouched, and `boxlet eval` exits with `ExitCode::FAILURE` while still emitting the full `EvalReport` so callers can inspect `rubric_violations`.
