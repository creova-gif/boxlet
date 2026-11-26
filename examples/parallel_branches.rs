//! Example demonstrating parallel N-way sandbox branching, filesystem diffing, and winner promotion
//! via `Engine::run_branches` and `Engine::run_branches_with_promotion`.

use std::path::PathBuf;
use std::time::Duration;

#[cfg(target_os = "linux")]
use boxlet::engine::BranchBatchReport;
use boxlet::engine::BranchSpec;
use boxlet::policy::{ExecutionPolicy, NetworkMode};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Hosts using the default LinuxBackend must forward self-re-exec `__init <config>`.
    #[cfg(target_os = "linux")]
    if args.get(1).map(String::as_str) == Some("__init") {
        if let Some(cfg_path) = args.get(2) {
            if let Err(err) = boxlet::run_internal_init(std::path::Path::new(cfg_path)) {
                eprintln!("boxlet __init failed: {err}");
                std::process::exit(1);
            }
            return;
        }
    }

    let bundle = args
        .iter()
        .skip(1)
        .find(|arg| !arg.starts_with("--"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./bundle"));
    let promote_winner = args.iter().any(|arg| arg == "--promote-winner");

    let branches = vec![
        BranchSpec::new("candidate-a")
            .with_args(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo 'patch A' > /candidate_a.txt".to_string(),
            ])
            .with_env(vec!["AGENT_BRANCH=candidate-a".to_string()])
            .with_cwd("/"),
        BranchSpec::new("candidate-b")
            .with_args(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo 'patch B' > /candidate_b.txt".to_string(),
            ])
            .with_env(vec!["AGENT_BRANCH=candidate-b".to_string()])
            .with_cwd("/"),
    ];

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
        match engine.run_branches_with_promotion(&bundle, &branches, &policy, promote_winner) {
            Ok(BranchBatchReport {
                branches: results,
                promoted_branch_id,
                promoted_diff,
            }) => {
                for res in results {
                    println!(
                        "branch={} exit={:?} duration={:?} added={:?} modified={:?} deleted={:?}",
                        res.branch_id,
                        res.execution.exit_code,
                        res.execution.usage.duration,
                        res.fs_diff.added,
                        res.fs_diff.modified,
                        res.fs_diff.deleted,
                    );
                }
                if let Some(winner) = promoted_branch_id {
                    println!(
                        "promoted winner={} applied_diff={:?}",
                        winner, promoted_diff
                    );
                }
            }
            Err(err) => {
                eprintln!("parallel branch execution failed: {err}");
                std::process::exit(1);
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        println!(
            "Configured {} parallel branches against bundle '{}' (promote_winner={}, policy memory={:?}, network={:?}):",
            branches.len(),
            bundle.display(),
            promote_winner,
            policy.memory_bytes,
            policy.network,
        );
        for spec in &branches {
            println!(
                "  - branch_id={} args={:?} env={:?} cwd={:?}",
                spec.id, spec.args, spec.env, spec.cwd
            );
        }
        eprintln!("note: Linux container execution requires Linux 5.15+");
    }
}
