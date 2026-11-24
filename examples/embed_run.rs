//! Example demonstrating embedding `boxlet::Engine` in an external Rust application.

use std::path::PathBuf;
use std::time::Duration;

use boxlet::policy::{ExecutionPolicy, NetworkMode};

fn main() {
    let bundle = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./bundle"));

    let policy = ExecutionPolicy {
        memory_bytes: Some(128 * 1024 * 1024),
        cpus: Some(0.5),
        pids_limit: Some(64),
        network: Some(NetworkMode::None),
        timeout: Some(Duration::from_secs(30)),
        ..ExecutionPolicy::default()
    };

    #[cfg(target_os = "linux")]
    {
        let backend = boxlet::LinuxBackend::with_defaults();
        let engine = boxlet::Engine::new(backend);
        match engine.run("embed-demo-1", &bundle, &policy) {
            Ok(res) => {
                println!(
                    "container={} exit={:?} oom={} timed_out={} duration={:?} cleanup={:?}",
                    res.container_id,
                    res.exit_code,
                    res.violations.oom_killed,
                    res.violations.timed_out,
                    res.usage.duration,
                    res.cleanup,
                );
            }
            Err(err) => {
                eprintln!("execution failed: {err}");
                std::process::exit(1);
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (bundle, policy);
        eprintln!("boxlet container execution requires Linux 5.15+");
    }
}
