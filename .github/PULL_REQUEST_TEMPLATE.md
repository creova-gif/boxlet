## Summary

<!-- Briefly describe the problem and the solution implemented in this PR. -->

## Related ADR / Issue

- ADR: `docs/adr/...` (if introducing a non-trivial architectural decision)
- Closes #

## Engineering Standards & Verification Checklist

- [ ] **No production `.unwrap()` / `.expect()`:** All non-test code in `src/` propagates typed `BoxletError` via `Result<T>`.
- [ ] **Formatting & Lints:** `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` pass with zero warnings.
- [ ] **Rustdoc:** `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` builds cleanly.
- [ ] **Deterministic Unit Tests:** `cargo test` passes with deterministic coverage for new or modified paths.
- [ ] **Verification Harness:** `.agents/skills/verify-boxlet/scripts/control-boxlet drive <feature> --run <id>` passes for `healthcheck`, `quality-gates`, `api-docs`, and `cli-surface`.
- [ ] **Linux End-to-End Suite (if modifying runtime/CLI):** `sudo ./scripts/demo-v1.sh ./target/debug/boxlet` passes all 18 checks with zero leaked cgroups or state directories.
