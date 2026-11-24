//! Boxlet: Minimal Linux OCI-compatible container runtime and programmable execution core.

pub mod error;
pub mod oci;
pub mod policy;
pub mod traits;

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
