//! OCI Runtime Specification bundle loading and container lifecycle state store.

pub mod state;

use std::path::Path;

use oci_spec::runtime::Spec;

use crate::error::{BoxletError, Result};

/// Default OCI runtime specification version reported in `state.json`.
pub const OCI_RUNTIME_VERSION: &str = "1.0.2";

/// Loads and validates `<bundle>/config.json` via `oci-spec`.
pub fn load_bundle_spec(bundle: &Path) -> Result<Spec> {
    let config_path = bundle.join("config.json");
    Spec::load(&config_path).map_err(|source| BoxletError::OciSpec {
        path: config_path,
        source,
    })
}

/// Validates that a container ID is non-empty and safe for filesystem paths.
pub fn validate_container_id(id: &str) -> Result<()> {
    if id.is_empty() {
        return Err(BoxletError::InvalidContainerId {
            id: id.to_string(),
            reason: "container id must not be empty".to_string(),
        });
    }
    if id == "." || id == ".." || id.contains("..") {
        return Err(BoxletError::InvalidContainerId {
            id: id.to_string(),
            reason: "container id must not contain path traversal segments".to_string(),
        });
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(BoxletError::InvalidContainerId {
            id: id.to_string(),
            reason: "container id may only contain ASCII alphanumeric, '-', '_', or '.'"
                .to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_container_id_accepts_safe_ids_and_rejects_traversal() {
        assert!(validate_container_id("agent-01_test.v1").is_ok());
        assert!(validate_container_id("").is_err());
        assert!(validate_container_id("..").is_err());
        assert!(validate_container_id("../escape").is_err());
        assert!(validate_container_id("a/b").is_err());
    }

    #[test]
    fn load_bundle_spec_parses_valid_config_json() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|source| BoxletError::StateStore {
            path: std::path::PathBuf::from("tempdir"),
            source,
        })?;
        let spec = Spec::default();
        spec.save(dir.path().join("config.json"))
            .map_err(|source| BoxletError::OciSpec {
                path: dir.path().join("config.json"),
                source,
            })?;

        let loaded = load_bundle_spec(dir.path())?;
        assert_eq!(loaded.version(), spec.version());
        Ok(())
    }
}
