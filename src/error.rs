//! Typed error definitions for Boxlet.

use std::path::PathBuf;

use thiserror::Error;

use crate::oci::state::ContainerStatus;

/// Result alias using [`BoxletError`].
pub type Result<T> = std::result::Result<T, BoxletError>;

/// All error conditions returned by Boxlet's public API and internal subsystems.
#[derive(Debug, Error)]
pub enum BoxletError {
    /// Container identifier is empty or contains unsafe path characters.
    #[error("invalid container id '{id}': {reason}")]
    InvalidContainerId {
        /// The rejected container identifier.
        id: String,
        /// Why the identifier was rejected.
        reason: String,
    },

    /// Attempted to create a container whose ID already exists in the state store.
    #[error("container '{id}' already exists")]
    ContainerAlreadyExists {
        /// The conflicting container identifier.
        id: String,
    },

    /// Requested container ID was not found in the state store.
    #[error("container '{id}' not found")]
    ContainerNotFound {
        /// The missing container identifier.
        id: String,
    },

    /// Requested OCI lifecycle transition is not allowed from the current state.
    #[error("invalid state transition for container '{id}': {from} -> {to}")]
    InvalidStateTransition {
        /// Container identifier.
        id: String,
        /// Current lifecycle status.
        from: ContainerStatus,
        /// Attempted target lifecycle status.
        to: ContainerStatus,
    },

    /// Attempted to delete a non-stopped container without `force`.
    #[error("cannot delete container '{id}' in status '{status}' without force")]
    ContainerNotStopped {
        /// Container identifier.
        id: String,
        /// Current lifecycle status.
        status: ContainerStatus,
    },

    /// Failed to load or validate an OCI `config.json` bundle specification.
    #[error("failed to load OCI spec at '{path}': {source}")]
    OciSpec {
        /// Path to the OCI `config.json` file.
        path: PathBuf,
        /// Underlying `oci-spec` error.
        #[source]
        source: oci_spec::OciSpecError,
    },

    /// Requested network mode is not supported in V1 (only `none` and `host`).
    #[error("unsupported network mode '{mode}' (V1 supports only 'none' and 'host')")]
    UnsupportedNetworkMode {
        /// The unsupported network mode string.
        mode: String,
    },

    /// Seccomp rule, syscall name, action, or operator is unsupported (fail-closed).
    #[error("unsupported seccomp rule: {reason}")]
    UnsupportedSeccompRule {
        /// Description of the unsupported seccomp construct.
        reason: String,
    },

    /// Execution policy contains invalid bounds (e.g. zero memory or non-finite CPUs).
    #[error("invalid execution policy: {reason}")]
    InvalidPolicy {
        /// Description of the invalid policy field.
        reason: String,
    },

    /// Filesystem or lock error in the container state store.
    #[error("state store I/O error at '{path}': {source}")]
    StateStore {
        /// Path involved in the I/O failure.
        path: PathBuf,
        /// Underlying OS I/O error.
        #[source]
        source: std::io::Error,
    },

    /// JSON serialization or deserialization error.
    #[error("JSON serialization error: {source}")]
    Serialization {
        /// Underlying `serde_json` error.
        #[from]
        source: serde_json::Error,
    },

    /// Linux runtime subsystem failure.
    #[error("runtime subsystem '{subsystem}' failed: {message}")]
    Runtime {
        /// Subsystem name (e.g. `cgroup_v2`, `rootfs`, `init`).
        subsystem: &'static str,
        /// Actionable error message.
        message: String,
    },

    /// Operation requires Linux kernel support unavailable on the current host OS.
    #[error("feature '{feature}' is only supported on Linux 5.15+")]
    UnsupportedPlatform {
        /// Feature name.
        feature: &'static str,
    },
}
