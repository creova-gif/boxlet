//! Thin `clap` CLI driving the shared `boxlet::Engine` and workspace snapshot/diff tools.

#[cfg(target_os = "linux")]
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
#[cfg(target_os = "linux")]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};

#[cfg(target_os = "linux")]
use boxlet::engine::BranchSpec;
use boxlet::error::{BoxletError, Result};
use boxlet::oci::state::DEFAULT_STATE_ROOT;
#[cfg(target_os = "linux")]
use boxlet::policy::{ExecutionPolicy, NetworkMode};
use boxlet::snapshot::{TreeManifest, WorkspaceSnapshot};

const DEFAULT_CGROUP_PARENT: &str = "/sys/fs/cgroup/boxlet.slice";

#[derive(Debug, Parser)]
#[command(
    name = "boxlet",
    version,
    about = "Minimal Linux OCI-compatible container runtime and programmable execution sandbox"
)]
struct Cli {
    /// Root directory for container state persistence.
    #[arg(long, global = true, default_value = DEFAULT_STATE_ROOT)]
    root: PathBuf,

    /// Dedicated cgroup v2 parent slice for container leaf cgroups.
    #[arg(long, global = true, default_value = DEFAULT_CGROUP_PARENT)]
    cgroup_parent: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Create a container from an OCI bundle (`config.json` honored verbatim).
    Create {
        /// Path to the OCI bundle directory containing `config.json`.
        #[arg(short = 'b', long, default_value = ".")]
        bundle: PathBuf,
        /// Unique container identifier.
        id: String,
    },
    /// Start a previously created container (`Created -> Running`).
    Start {
        /// Container identifier.
        id: String,
    },
    /// Print the OCI state JSON of a container.
    State {
        /// Container identifier.
        id: String,
    },
    /// Send a signal to a running container.
    Kill {
        /// Container identifier.
        id: String,
        /// Signal name or number (e.g. SIGTERM, SIGKILL, 9, 15).
        #[arg(default_value = "SIGTERM")]
        signal: String,
    },
    /// Delete a stopped container (or force-kill and remove it).
    Delete {
        /// Force-kill via cgroup.kill before removing state.
        #[arg(short = 'f', long)]
        force: bool,
        /// Container identifier.
        id: String,
    },
    /// Run a container end-to-end with explicit policy limits and structured observability.
    Run {
        /// Optional container ID (auto-generated if omitted).
        #[arg(long)]
        id: Option<String>,
        /// Hard cgroup v2 memory limit (e.g. 128m, 1g, 65536).
        #[arg(long)]
        memory: Option<String>,
        /// CPU limit in cores (e.g. 0.5, 2.0).
        #[arg(long)]
        cpus: Option<f64>,
        /// Maximum number of processes/threads (`pids.max`).
        #[arg(long)]
        pids: Option<i64>,
        /// Network isolation mode (`none` or `host`).
        #[arg(long)]
        network: Option<String>,
        /// Maximum execution timeout in seconds.
        #[arg(long)]
        timeout: Option<u64>,
        /// Maximum bytes captured per stream (`stdout` and `stderr`).
        #[arg(long)]
        max_output_bytes: Option<usize>,
        /// Emit the full structured `ExecutionResult` as JSON to stdout.
        #[arg(long)]
        json: bool,
        /// Path to the OCI bundle directory containing `config.json`.
        bundle: PathBuf,
    },
    /// Create an immutable workspace snapshot and capture its deterministic `TreeManifest`.
    Snapshot {
        /// Path to the source rootfs directory to checkpoint.
        #[arg(long)]
        rootfs: PathBuf,
        /// Base output directory where `<out>/<id>` will be created.
        #[arg(long)]
        out: PathBuf,
        /// Emit the full `WorkspaceSnapshot` metadata and manifest as JSON to stdout.
        #[arg(long)]
        json: bool,
        /// Unique snapshot identifier (or `create` followed by `<ID>`).
        id: String,
        /// Optional snapshot identifier when invoked as `boxlet snapshot create ... <ID>`.
        #[arg(hide = true)]
        trailing_id: Option<String>,
    },
    /// Compute the deterministic filesystem diff (`added`, `modified`, `deleted`) between two directories.
    Diff {
        /// Emit the structured `FsDiff` as JSON to stdout.
        #[arg(long)]
        json: bool,
        /// Base ("before") rootfs directory (flag form of `<BEFORE>`).
        #[arg(long = "before", value_name = "DIR", conflicts_with = "before")]
        before_flag: Option<PathBuf>,
        /// Target ("after") rootfs directory (flag form of `<AFTER>`).
        #[arg(long = "after", value_name = "DIR", conflicts_with = "after")]
        after_flag: Option<PathBuf>,
        /// Base ("before") rootfs directory.
        #[arg(value_name = "BEFORE", required_unless_present = "before_flag")]
        before: Option<PathBuf>,
        /// Target ("after") rootfs directory.
        #[arg(value_name = "AFTER", required_unless_present = "after_flag")]
        after: Option<PathBuf>,
    },
    /// Restore a target rootfs directory to match a previously captured snapshot directory.
    Restore {
        /// Path to the snapshot directory (`<out>/<id>`).
        #[arg(long)]
        snapshot: PathBuf,
        /// Path to the target rootfs directory to restore.
        #[arg(long)]
        target: PathBuf,
        /// Emit the applied `FsDiff` as JSON to stdout.
        #[arg(long)]
        json: bool,
    },
    /// Fan out N isolated sandbox branches in parallel from a base OCI bundle and collect diffs.
    BranchRun {
        /// Shell command (`sh -c <CMD>`) to execute in each parallel branch (repeatable).
        #[arg(long = "cmd", required = true)]
        cmds: Vec<String>,
        /// Hard cgroup v2 memory limit per branch (e.g. 128m, 1g, 65536).
        #[arg(long)]
        memory: Option<String>,
        /// CPU limit in cores per branch (e.g. 0.5, 2.0).
        #[arg(long)]
        cpus: Option<f64>,
        /// Maximum number of processes/threads (`pids.max`) per branch.
        #[arg(long)]
        pids: Option<i64>,
        /// Network isolation mode (`none` or `host`).
        #[arg(long)]
        network: Option<String>,
        /// Maximum execution timeout in seconds per branch.
        #[arg(long)]
        timeout: Option<u64>,
        /// Maximum bytes captured per stream (`stdout` and `stderr`) per branch.
        #[arg(long)]
        max_output_bytes: Option<usize>,
        /// Promote the first passing branch (`exit_code == 0`, no violations) back onto the bundle rootfs.
        #[arg(long)]
        promote_winner: bool,
        /// Emit the full `Vec<BranchExecutionResult>` (or `BranchBatchReport` with `--promote-winner`) as JSON to stdout.
        #[arg(long)]
        json: bool,
        /// Path to the base OCI bundle directory containing `config.json`.
        bundle: PathBuf,
    },
    /// Hidden internal self-re-exec container init stage.
    #[command(name = "__init", hide = true)]
    InternalInit {
        /// Path to the serialized `init.json` handshake config.
        config: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("boxlet error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Commands::Snapshot {
            rootfs,
            out,
            json,
            id,
            trailing_id,
        } => {
            let effective_id = match (id.as_str(), trailing_id) {
                ("create", Some(real_id)) => real_id,
                (_, None) => id,
                (other, Some(extra)) => {
                    return Err(BoxletError::InvalidPolicy {
                        reason: format!(
                            "unexpected extra argument '{extra}' for snapshot '{other}'"
                        ),
                    });
                }
            };
            let snapshot = WorkspaceSnapshot::create(&effective_id, &rootfs, &out)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&snapshot)?);
            } else {
                println!(
                    "snapshot={} path={} entries={}",
                    snapshot.id,
                    snapshot.snapshot_dir.display(),
                    snapshot.manifest.entries.len()
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::Diff {
            json,
            before_flag,
            after_flag,
            before,
            after,
        } => {
            let before_dir = before_flag
                .or(before)
                .ok_or_else(|| BoxletError::InvalidPolicy {
                    reason: "missing 'before' directory for diff".to_string(),
                })?;
            let after_dir = after_flag
                .or(after)
                .ok_or_else(|| BoxletError::InvalidPolicy {
                    reason: "missing 'after' directory for diff".to_string(),
                })?;
            let before_manifest = TreeManifest::capture(&before_dir)?;
            let after_manifest = TreeManifest::capture(&after_dir)?;
            let diff = before_manifest.diff(&after_manifest);
            if json {
                println!("{}", serde_json::to_string_pretty(&diff)?);
            } else {
                for path in &diff.added {
                    println!("+ {}", path.display());
                }
                for path in &diff.modified {
                    println!("~ {}", path.display());
                }
                for path in &diff.deleted {
                    println!("- {}", path.display());
                }
                if diff.is_empty() {
                    println!("(no filesystem changes)");
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::Restore {
            snapshot,
            target,
            json,
        } => {
            let diff = WorkspaceSnapshot::restore_from_dir(&snapshot, &target)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&diff)?);
            } else {
                println!(
                    "restored target={} changes={}",
                    target.display(),
                    diff.total_changes()
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        other => dispatch_platform(cli.root, cli.cgroup_parent, other),
    }
}

#[cfg(target_os = "linux")]
fn dispatch_platform(root: PathBuf, cgroup_parent: PathBuf, command: Commands) -> Result<ExitCode> {
    if let Commands::InternalInit { config } = command {
        boxlet::run_internal_init(&config)?;
        return Ok(ExitCode::SUCCESS);
    }

    let backend = boxlet::LinuxBackend::new(root, cgroup_parent);
    let engine = boxlet::Engine::new(backend);

    match command {
        Commands::Create { bundle, id } => {
            engine.create(&id, &bundle)?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Start { id } => {
            engine.start(&id)?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::State { id } => {
            let state = engine.state(&id)?;
            let json = serde_json::to_string_pretty(&state)?;
            println!("{json}");
            Ok(ExitCode::SUCCESS)
        }
        Commands::Kill { id, signal } => {
            let sig = parse_signal(&signal)?;
            engine.kill(&id, sig)?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Delete { force, id } => {
            engine.delete(&id, force)?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Run {
            id,
            memory,
            cpus,
            pids,
            network,
            timeout,
            max_output_bytes,
            json,
            bundle,
        } => {
            let container_id = id.unwrap_or_else(generate_container_id);
            let policy = build_execution_policy(
                memory.as_deref(),
                cpus,
                pids,
                network.as_deref(),
                timeout,
                max_output_bytes,
            )?;

            let result = engine.run(&container_id, &bundle, &policy)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                let _ = std::io::stdout().write_all(&result.stdout);
                let _ = std::io::stderr().write_all(&result.stderr);
            }

            if let Some(code) = result.exit_code {
                Ok(ExitCode::from(u8::try_from(code).unwrap_or(1)))
            } else if let Some(sig) = result.violations.termination_signal {
                let exit_val = u8::try_from(128 + sig).unwrap_or(137);
                Ok(ExitCode::from(exit_val))
            } else {
                Ok(ExitCode::FAILURE)
            }
        }
        Commands::BranchRun {
            cmds,
            memory,
            cpus,
            pids,
            network,
            timeout,
            max_output_bytes,
            promote_winner,
            json,
            bundle,
        } => {
            let policy = build_execution_policy(
                memory.as_deref(),
                cpus,
                pids,
                network.as_deref(),
                timeout,
                max_output_bytes,
            )?;
            let prefix = generate_container_id();
            let specs: Vec<BranchSpec> = cmds
                .into_iter()
                .enumerate()
                .map(|(idx, cmd)| {
                    BranchSpec::new(format!("{prefix}-branch-{}", idx + 1)).with_args(vec![
                        "/bin/sh".to_string(),
                        "-c".to_string(),
                        cmd,
                    ])
                })
                .collect();

            if promote_winner {
                let report = engine.run_branches_with_promotion(&bundle, &specs, &policy, true)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    for item in &report.branches {
                        println!(
                            "branch={} exit={:?} added={} modified={} deleted={}",
                            item.branch_id,
                            item.execution.exit_code,
                            item.fs_diff.added.len(),
                            item.fs_diff.modified.len(),
                            item.fs_diff.deleted.len(),
                        );
                    }
                    println!("promoted_branch_id={:?}", report.promoted_branch_id);
                }
                if report.promoted_branch_id.is_some() {
                    Ok(ExitCode::SUCCESS)
                } else {
                    Ok(ExitCode::FAILURE)
                }
            } else {
                let results = engine.run_branches(&bundle, &specs, &policy)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&results)?);
                } else {
                    for item in &results {
                        println!(
                            "branch={} exit={:?} added={} modified={} deleted={}",
                            item.branch_id,
                            item.execution.exit_code,
                            item.fs_diff.added.len(),
                            item.fs_diff.modified.len(),
                            item.fs_diff.deleted.len(),
                        );
                    }
                }

                let all_ok = results.iter().all(|r| {
                    r.execution.exit_code == Some(0)
                        && !r.execution.violations.timed_out
                        && !r.execution.violations.oom_killed
                });
                if all_ok {
                    Ok(ExitCode::SUCCESS)
                } else {
                    Ok(ExitCode::FAILURE)
                }
            }
        }
        Commands::Snapshot { .. }
        | Commands::Diff { .. }
        | Commands::Restore { .. }
        | Commands::InternalInit { .. } => Ok(ExitCode::SUCCESS),
    }
}

#[cfg(not(target_os = "linux"))]
fn dispatch_platform(
    _root: PathBuf,
    _cgroup_parent: PathBuf,
    _command: Commands,
) -> Result<ExitCode> {
    Err(BoxletError::UnsupportedPlatform {
        feature: "Linux OCI container execution",
    })
}

#[cfg(target_os = "linux")]
fn build_execution_policy(
    memory: Option<&str>,
    cpus: Option<f64>,
    pids: Option<i64>,
    network: Option<&str>,
    timeout: Option<u64>,
    max_output_bytes: Option<usize>,
) -> Result<ExecutionPolicy> {
    let memory_bytes = memory.map(parse_byte_size).transpose()?;
    let network_mode = network.map(|m| m.parse::<NetworkMode>()).transpose()?;
    Ok(ExecutionPolicy {
        memory_bytes,
        cpus,
        pids_limit: pids,
        network: network_mode,
        timeout: timeout.map(Duration::from_secs),
        max_output_bytes,
        ..ExecutionPolicy::default()
    })
}

/// Parses human-readable byte sizes (`128m`, `1g`, `512k`, or raw bytes).
#[cfg(any(target_os = "linux", test))]
fn parse_byte_size(input: &str) -> Result<u64> {
    let trimmed = input.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return Err(BoxletError::InvalidPolicy {
            reason: "memory size must not be empty".to_string(),
        });
    }

    let (num_part, multiplier) = if let Some(v) = trimmed.strip_suffix("gb") {
        (v, 1024u64 * 1024 * 1024)
    } else if let Some(v) = trimmed.strip_suffix('g') {
        (v, 1024u64 * 1024 * 1024)
    } else if let Some(v) = trimmed.strip_suffix("mb") {
        (v, 1024u64 * 1024)
    } else if let Some(v) = trimmed.strip_suffix('m') {
        (v, 1024u64 * 1024)
    } else if let Some(v) = trimmed.strip_suffix("kb") {
        (v, 1024u64)
    } else if let Some(v) = trimmed.strip_suffix('k') {
        (v, 1024u64)
    } else if let Some(v) = trimmed.strip_suffix('b') {
        (v, 1u64)
    } else {
        (trimmed.as_str(), 1u64)
    };

    let base = num_part
        .trim()
        .parse::<u64>()
        .map_err(|_| BoxletError::InvalidPolicy {
            reason: format!("invalid memory size '{input}'"),
        })?;

    base.checked_mul(multiplier)
        .ok_or_else(|| BoxletError::InvalidPolicy {
            reason: format!("memory size '{input}' overflows u64"),
        })
}

/// Parses signal names (`SIGKILL`, `TERM`, `INT`) or positive integers.
#[cfg(any(target_os = "linux", test))]
fn parse_signal(input: &str) -> Result<i32> {
    let norm = input.trim().to_ascii_uppercase();
    if let Ok(num) = norm.parse::<i32>() {
        if num > 0 {
            return Ok(num);
        }
    }
    let stripped = norm.strip_prefix("SIG").unwrap_or(&norm);
    match stripped {
        "HUP" => Ok(1),
        "INT" => Ok(2),
        "QUIT" => Ok(3),
        "KILL" => Ok(9),
        "USR1" => Ok(10),
        "USR2" => Ok(12),
        "TERM" => Ok(15),
        _ => Err(BoxletError::InvalidPolicy {
            reason: format!("unsupported signal '{input}'"),
        }),
    }
}

#[cfg(target_os = "linux")]
fn generate_container_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("boxlet-{}-{nanos}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_byte_size_handles_units_and_rejects_invalid() -> Result<()> {
        assert_eq!(parse_byte_size("128m")?, 128 * 1024 * 1024);
        assert_eq!(parse_byte_size("1G")?, 1024 * 1024 * 1024);
        assert_eq!(parse_byte_size("512kb")?, 512 * 1024);
        assert_eq!(parse_byte_size("4096")?, 4096);
        assert!(parse_byte_size("abc").is_err());
        assert!(parse_byte_size("").is_err());
        Ok(())
    }

    #[test]
    fn parse_signal_handles_names_and_numbers() -> Result<()> {
        assert_eq!(parse_signal("SIGTERM")?, 15);
        assert_eq!(parse_signal("kill")?, 9);
        assert_eq!(parse_signal("9")?, 9);
        assert!(parse_signal("NOTASIG").is_err());
        Ok(())
    }

    #[test]
    fn cli_snapshot_and_diff_parse_and_execute_portably() -> Result<()> {
        let tmp = tempfile::tempdir().map_err(|source| BoxletError::StateStore {
            path: PathBuf::from("tempdir"),
            source,
        })?;
        let rootfs_a = tmp.path().join("rootfs-a");
        let rootfs_b = tmp.path().join("rootfs-b");
        let out_dir = tmp.path().join("snapshots");

        std::fs::create_dir_all(&rootfs_a).map_err(|source| BoxletError::StateStore {
            path: rootfs_a.clone(),
            source,
        })?;
        std::fs::write(rootfs_a.join("file.txt"), b"v1\n").map_err(|source| {
            BoxletError::StateStore {
                path: rootfs_a.join("file.txt"),
                source,
            }
        })?;

        std::fs::create_dir_all(&rootfs_b).map_err(|source| BoxletError::StateStore {
            path: rootfs_b.clone(),
            source,
        })?;
        std::fs::write(rootfs_b.join("file.txt"), b"v2\n").map_err(|source| {
            BoxletError::StateStore {
                path: rootfs_b.join("file.txt"),
                source,
            }
        })?;
        std::fs::write(rootfs_b.join("added.txt"), b"new\n").map_err(|source| {
            BoxletError::StateStore {
                path: rootfs_b.join("added.txt"),
                source,
            }
        })?;

        let snap_cli = Cli::try_parse_from([
            "boxlet",
            "snapshot",
            "--rootfs",
            rootfs_a.to_str().unwrap_or_default(),
            "--out",
            out_dir.to_str().unwrap_or_default(),
            "--json",
            "snap-cli-1",
        ])
        .map_err(|err| BoxletError::InvalidPolicy {
            reason: err.to_string(),
        })?;
        assert_eq!(dispatch(snap_cli)?, ExitCode::SUCCESS);

        let diff_cli = Cli::try_parse_from([
            "boxlet",
            "diff",
            "--before",
            rootfs_a.to_str().unwrap_or_default(),
            "--after",
            rootfs_b.to_str().unwrap_or_default(),
            "--json",
        ])
        .map_err(|err| BoxletError::InvalidPolicy {
            reason: err.to_string(),
        })?;
        assert_eq!(dispatch(diff_cli)?, ExitCode::SUCCESS);

        let snap_dir = out_dir.join("snap-cli-1");
        let restore_cli = Cli::try_parse_from([
            "boxlet",
            "restore",
            "--snapshot",
            snap_dir.to_str().unwrap_or_default(),
            "--target",
            rootfs_b.to_str().unwrap_or_default(),
            "--json",
        ])
        .map_err(|err| BoxletError::InvalidPolicy {
            reason: err.to_string(),
        })?;
        assert_eq!(dispatch(restore_cli)?, ExitCode::SUCCESS);
        assert!(!rootfs_b.join("added.txt").exists());
        let restored_bytes =
            std::fs::read(rootfs_b.join("file.txt")).map_err(|source| BoxletError::StateStore {
                path: rootfs_b.join("file.txt"),
                source,
            })?;
        assert_eq!(restored_bytes, b"v1\n");
        Ok(())
    }
}
