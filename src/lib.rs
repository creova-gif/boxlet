//! Boxlet: Minimal Linux OCI-compatible container runtime and programmable execution core.

pub mod audit;
pub mod doctor;
pub mod engine;
pub mod error;
pub mod eval;
pub mod image;
#[cfg(target_os = "linux")]
pub(crate) mod linux;
pub mod microvm;
pub mod oci;
pub mod policy;
pub mod snapshot;
pub mod traits;

pub use audit::{AuditEvent, AuditRecord, AuditSummary, JsonlAuditLogger};
pub use doctor::{run_doctor, DoctorCheck, DoctorReport, DoctorStatus};
pub use engine::{BranchBatchReport, BranchExecutionResult, BranchSpec, Engine, PruneReport};
pub use eval::{CandidateVerdict, EvalReport, EvalRubric, EvalSpec};
pub use image::{export_rootfs_tar, import_rootfs_tar, RootfsArchiveReport};
#[cfg(target_os = "linux")]
pub use linux::overlay::{inspect_upper_diff, OverlayDirs, OverlayRootfsProvider};
#[cfg(target_os = "linux")]
pub use linux::LinuxBackend;
pub use microvm::{FirecrackerVmSpec, LibkrunVmSpec, MicroVmBackend, MicroVmConfig, VmmDriver};
pub use oci::BundleBuilder;

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
