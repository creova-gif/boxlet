# Contributing to Boxlet

Thank you for contributing to **Boxlet**! This guide covers our architecture seams, engineering standards, verification workflows, and pull request process.

---

## 1. Architecture Seams

Boxlet is structured around a single shared execution core (`boxlet::Engine`) that powers both the `boxlet` CLI (`src/main.rs`) and external Rust SDK consumers:

- **`src/engine.rs` (`Engine`):** Orchestrates policy merging, container lifecycles, parallel branch execution, winner promotion, garbage collection, and audit logging.
- **`src/traits.rs` (`RuntimeBackend` & `RootfsProvider`):** Backend abstraction seams enabling pluggable execution drivers (`LinuxBackend`, `MicroVmBackend`, and cross-platform mock backends).
- **`src/linux/` (`LinuxBackend`):** Linux 5.15+ namespaces (`CLONE_NEW*`), `pivot_root`, unified cgroup v2 (`memory.max`, `cpu.max`, `pids.max`, `cgroup.kill`), capability dropping (`caps`), and pure-Rust `seccompiler` cBPF filters.
- **`src/snapshot.rs` (`WorkspaceSnapshot`, `TreeManifest`, `FsDiff`):** Deterministic 64-bit FNV-1a workspace snapshots, single-pass `O(N)` filesystem diffs, branching, and 4-stage atomic rollback.
- **`src/audit.rs`, `src/doctor.rs`, `src/eval.rs`:** Structured `0600` JSONL audit logging and analytics, host kernel readiness diagnostics, and declarative multi-agent rubric evaluation.
- **`src/image.rs` & `src/microvm.rs`:** Deterministic portable OCI rootfs tar archive export/import and hardware-virtualized MicroVM (`Firecracker` / `libkrun`) specification synthesis.

---

## 2. Engineering Standards (`AGENTS.md`)

All contributions must adhere strictly to [`AGENTS.md`](AGENTS.md):

1. **Architecture Decision Records (ADRs):** Every non-trivial design choice or new module must be documented in `docs/adr/` using [`docs/adr/000-template.md`](docs/adr/000-template.md).
2. **Zero `.unwrap()` or `.expect()` in Production Paths:** Production code in `src/` must propagate typed errors via `crate::error::Result<T>` and `BoxletError`. `.unwrap()` and `.expect()` are permitted **only** inside `#[cfg(test)]` modules.
3. **Formatting & Static Analysis:**
   - `cargo fmt --check` must pass with zero diffs.
   - `cargo clippy --all-targets -- -D warnings` must pass with zero warnings.
   - `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` must compile cleanly.
4. **Fail-Closed Isolation:** Unsupported network modes, unknown capabilities, unknown seccomp syscalls, or path traversal attempts in archives must fail closed with explicit `BoxletError` variants.
5. **Deterministic Unit Tests:** Every feature or bugfix must include deterministic unit tests in `src/`.

---

## 3. Running the Verification Harness (`control-boxlet`)

Boxlet ships a self-contained verification harness at `.agents/skills/verify-boxlet/scripts/control-boxlet` that works on both **macOS** (via Docker) and **Linux** (natively):

```bash
# 1. Launch an isolated verification workspace
.agents/skills/verify-boxlet/scripts/control-boxlet launch --run dev-check

# 2. Check toolchain and backend health
.agents/skills/verify-boxlet/scripts/control-boxlet doctor --run dev-check

# 3. Run all 4 verification gates
.agents/skills/verify-boxlet/scripts/control-boxlet drive healthcheck --run dev-check
.agents/skills/verify-boxlet/scripts/control-boxlet drive quality-gates --run dev-check
.agents/skills/verify-boxlet/scripts/control-boxlet drive api-docs --run dev-check
.agents/skills/verify-boxlet/scripts/control-boxlet drive cli-surface --run dev-check

# 4. Clean up scratch artifacts (preserves evidence in /tmp/boxlet-verify-evidence/dev-check)
.agents/skills/verify-boxlet/scripts/control-boxlet cleanup --run dev-check
```

---

## 4. Running the 18-Check Linux End-to-End Suite (`scripts/demo-v1.sh`)

On a Linux 5.15+ host with unified cgroup v2, `busybox`, and `python3`:

```bash
cargo build
sudo ./scripts/demo-v1.sh ./target/debug/boxlet
```

All 18 checks must pass with zero leaked cgroups under `/sys/fs/cgroup/boxlet.slice` or leftover state directories.

---

## 5. Pull Request Checklist

Before opening a pull request, ensure every item in [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md) is satisfied.
