//! Boxlet: Minimal Linux OCI-compatible container runtime and programmable execution core.

pub mod engine;
pub mod error;
#[cfg(target_os = "linux")]
pub(crate) mod linux;
pub mod oci;
pub mod policy;
pub mod snapshot;
pub mod traits;

pub use engine::{BranchBatchReport, BranchExecutionResult, BranchSpec, Engine};
#[cfg(target_os = "linux")]
pub use linux::LinuxBackend;

/// Executes the internal self-re-exec container init stage (`boxlet __init <config>`).
#[cfg(target_os = "linux")]
pub fn run_internal_init(config_path: &std::path::Path) -> error::Result<()> {
    linux::init::run_init_process(config_path)
}

/// Basic library readiness probe.
pub fn healthcheck() -> &'static str {
    "ok"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_test() {
        assert_eq!(healthcheck(), "ok");
    }
}
