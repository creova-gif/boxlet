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
use boxlet::{run_doctor, BundleBuilder, DoctorStatus, JsonlAuditLogger};

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

    /// Optional path to an append-only JSON Lines (`.jsonl`) audit log file.
    #[arg(long, global = true)]
    audit_log: Option<PathBuf>,

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
    /// List all tracked containers in the state root.
    List {
        /// Emit the container states as a JSON array to stdout.
        #[arg(long)]
        json: bool,
    },
    /// Remove stopped containers (or force-remove all containers when `--force` is set).
    Prune {
        /// Force-kill and remove active (`Creating`, `Created`, `Running`) containers as well.
        #[arg(short = 'f', long)]
        force: bool,
        /// Emit the `PruneReport` as JSON to stdout.
        #[arg(long)]
        json: bool,
    },
    /// Inspect and summarize an append-only JSON Lines (`.jsonl`) audit log file.
    Audit {
        /// Path to the `.jsonl` audit log file to inspect.
        #[arg(long)]
        file: PathBuf,
        /// Emit the `AuditSummary` as JSON to stdout.
        #[arg(long)]
        json: bool,
        /// Emit the summary in Prometheus / OpenMetrics text exposition format.
        #[arg(long, conflicts_with = "json")]
        prometheus: bool,
    },
    /// Run host preflight diagnostics for Linux namespaces, cgroup v2, and state directories.
    Doctor {
        /// Emit the `DoctorReport` as JSON to stdout.
        #[arg(long)]
        json: bool,
    },
    /// Evaluate parallel sandbox candidates against a declarative JSON rubric (`EvalSpec`).
    Eval {
        /// Path to the JSON `EvalSpec` file.
        #[arg(long)]
        spec: PathBuf,
        /// Override maximum number of candidate branches to execute concurrently.
        #[arg(long)]
        max_concurrency: Option<usize>,
        /// Override `promote_winner = true` to promote the winning candidate back to the bundle rootfs.
        #[arg(long)]
        promote_winner: bool,
        /// Emit the full `EvalReport` as JSON to stdout.
        #[arg(long)]
        json: bool,
        /// Path to the base OCI bundle directory containing `config.json`.
        bundle: PathBuf,
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
        /// Maximum number of branches to execute concurrently.
        #[arg(long)]
        max_concurrency: Option<usize>,
        /// Promote the first passing branch (`exit_code == 0`, no violations) back onto the bundle rootfs.
        #[arg(long)]
        promote_winner: bool,
        /// Emit the full `Vec<BranchExecutionResult>` (or `BranchBatchReport` with `--promote-winner`) as JSON to stdout.
        #[arg(long)]
        json: bool,
        /// Path to the base OCI bundle directory containing `config.json`.
        bundle: PathBuf,
    },
    /// Scaffold a minimal OCI bundle directory (`config.json` + `rootfs` hierarchy).
    InitBundle {
        /// Shell command (`sh -c <CMD>`) to configure as the container entrypoint.
        #[arg(long, default_value = "echo boxlet-ok")]
        cmd: String,
        /// Optional path to a static `busybox` binary to populate `/bin/busybox` and standard applets.
        #[arg(long)]
        busybox: Option<PathBuf>,
        /// Container UTS hostname.
        #[arg(long, default_value = "boxlet-sandbox")]
        hostname: String,
        /// Working directory inside the container rootfs.
        #[arg(long, default_value = "/")]
        cwd: String,
        /// Mark the root filesystem read-only in `config.json`.
        #[arg(long)]
        readonly: bool,
        /// Configure rootless user namespace (`CLONE_NEWUSER`) mapping container root (0:0) to the current host UID/GID.
        #[arg(long)]
        rootless: bool,
        /// Emit a JSON summary of the generated bundle to stdout.
        #[arg(long)]
        json: bool,
        /// Target directory where `<bundle>/config.json` and `<bundle>/rootfs` will be created.
        bundle: PathBuf,
    },
    /// Export a rootfs directory into a deterministic POSIX USTAR `.tar` archive.
    ImageExport {
        /// Source rootfs directory to archive.
        #[arg(long)]
        rootfs: PathBuf,
        /// Output `.tar` archive file path.
        #[arg(long)]
        out: PathBuf,
        /// Emit the `RootfsArchiveReport` as JSON to stdout.
        #[arg(long)]
        json: bool,
    },
    /// Import a POSIX USTAR `.tar` archive into a target rootfs directory with path-traversal protection.
    ImageImport {
        /// Input `.tar` archive file path.
        #[arg(long)]
        archive: PathBuf,
        /// Target rootfs directory to populate.
        #[arg(long)]
        out: PathBuf,
        /// Emit the `RootfsArchiveReport` as JSON to stdout.
        #[arg(long)]
        json: bool,
    },
    /// Generate a validated Firecracker or `libkrun` microVM configuration from an OCI bundle.
    MicrovmConfig {
        /// VMM driver target (`firecracker` or `libkrun`).
        #[arg(long, default_value = "firecracker")]
        driver: String,
        /// Sandbox identifier.
        #[arg(long, default_value = "microvm-1")]
        id: String,
        /// Guest kernel image path (`vmlinux`) for Firecracker.
        #[arg(long, default_value = "/var/lib/boxlet/vmlinux")]
        kernel: PathBuf,
        /// Optional guest initrd path.
        #[arg(long)]
        initrd: Option<PathBuf>,
        /// Guest memory size in MiB (or overridden via `--memory`).
        #[arg(long, default_value_t = 128)]
        mem_mib: u64,
        /// Guest vCPU count.
        #[arg(long, default_value_t = 1)]
        vcpus: u8,
        /// Optional output file path for the generated JSON config (prints to stdout if omitted).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Path to the OCI bundle directory containing `config.json`.
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
        Commands::InitBundle {
            cmd,
            busybox,
            hostname,
            cwd,
            readonly,
            rootless,
            json,
            bundle,
        } => {
            let mut builder = BundleBuilder::new()
                .with_shell_command(cmd)
                .with_hostname(hostname)
                .with_cwd(cwd)
                .with_readonly_rootfs(readonly)
                .with_rootless(rootless);
            if let Some(bb) = busybox {
                builder = builder.with_busybox(bb);
            }
            let spec = builder.build(&bundle)?;
            if json {
                let summary = serde_json::json!({
                    "bundle": bundle,
                    "config": bundle.join("config.json"),
                    "rootfs": bundle.join("rootfs"),
                    "oci_version": spec.version(),
                });
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!(
                    "initialized bundle={} config={} rootfs={}",
                    bundle.display(),
                    bundle.join("config.json").display(),
                    bundle.join("rootfs").display()
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::Audit {
            file,
            json,
            prometheus,
        } => {
            let summary = JsonlAuditLogger::new(&file).summarize()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else if prometheus {
                println!("{}", summary.to_prometheus_metrics());
            } else {
                println!(
                    "records={} runs={} batches={} chronological_valid={} hash_chain_valid={}",
                    summary.total_records,
                    summary.runs_completed,
                    summary.branch_batches_completed,
                    summary.chronological_valid,
                    summary.hash_chain_valid
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::Doctor { json } => {
            let report = run_doctor(&cli.root, &cli.cgroup_parent);
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                for check in &report.checks {
                    let status_label = match check.status {
                        DoctorStatus::Pass => "pass",
                        DoctorStatus::Warn => "warn",
                        DoctorStatus::Fail => "fail",
                    };
                    println!("[{status_label}] {}: {}", check.name, check.detail);
                }
            }
            if report.overall_ready {
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::FAILURE)
            }
        }
        Commands::ImageExport { rootfs, out, json } => {
            let report = boxlet::export_rootfs_tar(&rootfs, &out)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "exported rootfs={} archive={} entries={} bytes={} fnv1a64={:#018x}",
                    report.rootfs_path.display(),
                    report.archive_path.display(),
                    report.entry_count,
                    report.total_file_bytes,
                    report.archive_fnv1a64
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::ImageImport { archive, out, json } => {
            let report = boxlet::import_rootfs_tar(&archive, &out)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "imported archive={} rootfs={} entries={} bytes={} fnv1a64={:#018x}",
                    report.archive_path.display(),
                    report.rootfs_path.display(),
                    report.entry_count,
                    report.total_file_bytes,
                    report.archive_fnv1a64
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::MicrovmConfig {
            driver,
            id,
            kernel,
            initrd,
            mem_mib,
            vcpus,
            out,
            bundle,
        } => {
            let vmm_driver: boxlet::VmmDriver = driver.parse()?;
            let spec = boxlet::oci::load_bundle_spec(&bundle)?;
            let vm_cfg = boxlet::MicroVmConfig {
                driver: vmm_driver,
                kernel_image_path: kernel,
                initrd_path: initrd,
                vcpu_count: vcpus,
                mem_size_mib: mem_mib,
                ..boxlet::MicroVmConfig::default()
            };
            let rendered = match vmm_driver {
                boxlet::VmmDriver::Firecracker => {
                    let fc_spec = vm_cfg.build_firecracker_spec(&id, &bundle, &spec, None)?;
                    serde_json::to_string_pretty(&fc_spec)?
                }
                boxlet::VmmDriver::Libkrun => {
                    let lk_spec = vm_cfg.build_libkrun_spec(&id, &bundle, &spec, None)?;
                    serde_json::to_string_pretty(&lk_spec)?
                }
            };
            if let Some(out_path) = out {
                if let Some(parent) = out_path.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent).map_err(|source| {
                            BoxletError::StateStore {
                                path: parent.to_path_buf(),
                                source,
                            }
                        })?;
                    }
                }
                std::fs::write(&out_path, format!("{rendered}\n")).map_err(|source| {
                    BoxletError::StateStore {
                        path: out_path,
                        source,
                    }
                })?;
            } else {
                println!("{rendered}");
            }
            Ok(ExitCode::SUCCESS)
        }
        other => dispatch_platform(
            cli.root,
            cli.cgroup_parent,
            cli.audit_log.map(JsonlAuditLogger::new),
            other,
        ),
    }
}

#[cfg(target_os = "linux")]
fn dispatch_platform(
    root: PathBuf,
    cgroup_parent: PathBuf,
    audit_logger: Option<JsonlAuditLogger>,
    command: Commands,
) -> Result<ExitCode> {
    if let Commands::InternalInit { config } = command {
        boxlet::run_internal_init(&config)?;
        return Ok(ExitCode::SUCCESS);
    }

    let backend = boxlet::LinuxBackend::new(root, cgroup_parent);
    let engine = boxlet::Engine::new(backend).with_optional_audit_logger(audit_logger);

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
        Commands::List { json } => {
            let states = engine.list()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&states)?);
            } else if states.is_empty() {
                println!("(no containers)");
            } else {
                for st in &states {
                    println!(
                        "id={} status={} pid={:?} bundle={}",
                        st.id,
                        st.status,
                        st.pid,
                        st.bundle.display()
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::Prune { force, json } => {
            let report = engine.prune(force)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "pruned removed={} skipped={}",
                    report.removed_containers.len(),
                    report.skipped_active_containers.len()
                );
            }
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
            max_concurrency,
            promote_winner,
            json,
            bundle,
        } => {
            let mut policy = build_execution_policy(
                memory.as_deref(),
                cpus,
                pids,
                network.as_deref(),
                timeout,
                max_output_bytes,
            )?;
            policy.max_concurrency = max_concurrency;
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
        Commands::Eval {
            spec,
            max_concurrency,
            promote_winner,
            json,
            bundle,
        } => {
            let mut eval_spec = boxlet::EvalSpec::load(&spec)?;
            if let Some(mc) = max_concurrency {
                eval_spec.policy.max_concurrency = Some(mc);
            }
            if promote_winner {
                eval_spec.promote_winner = true;
            }
            let report = engine.run_eval(&bundle, &eval_spec)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                for verdict in &report.verdicts {
                    println!(
                        "candidate={} passed={} score={} violations={}",
                        verdict.branch_id,
                        verdict.passed_rubric,
                        verdict.score,
                        verdict.rubric_violations.len()
                    );
                }
                println!(
                    "winning_branch_id={:?} promoted={}",
                    report.winning_branch_id, report.promoted
                );
            }
            if report.winning_branch_id.is_some() {
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::FAILURE)
            }
        }
        Commands::Snapshot { .. }
        | Commands::Diff { .. }
        | Commands::Restore { .. }
        | Commands::InitBundle { .. }
        | Commands::ImageExport { .. }
        | Commands::ImageImport { .. }
        | Commands::MicrovmConfig { .. }
        | Commands::Audit { .. }
        | Commands::Doctor { .. }
        | Commands::InternalInit { .. } => Ok(ExitCode::SUCCESS),
    }
}

#[cfg(not(target_os = "linux"))]
fn dispatch_platform(
    _root: PathBuf,
    _cgroup_parent: PathBuf,
    _audit_logger: Option<JsonlAuditLogger>,
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

    #[test]
    fn cli_init_bundle_parses_and_executes_portably() -> Result<()> {
        let tmp = tempfile::tempdir().map_err(|source| BoxletError::StateStore {
            path: PathBuf::from("tempdir"),
            source,
        })?;
        let bundle_dir = tmp.path().join("demo-bundle");

        let init_cli = Cli::try_parse_from([
            "boxlet",
            "init-bundle",
            "--cmd",
            "echo hi",
            "--rootless",
            "--json",
            bundle_dir.to_str().unwrap_or_default(),
        ])
        .map_err(|err| BoxletError::InvalidPolicy {
            reason: err.to_string(),
        })?;

        assert_eq!(dispatch(init_cli)?, ExitCode::SUCCESS);
        assert!(bundle_dir.join("config.json").exists());
        assert!(bundle_dir.join("rootfs").is_dir());
        let loaded_spec = boxlet::oci::load_bundle_spec(&bundle_dir)?;
        assert!(loaded_spec
            .linux()
            .as_ref()
            .and_then(|l| l.uid_mappings().as_ref())
            .is_some());
        Ok(())
    }

    #[test]
    fn cli_audit_parses_and_executes_portably() -> Result<()> {
        let tmp = tempfile::tempdir().map_err(|source| BoxletError::StateStore {
            path: PathBuf::from("tempdir"),
            source,
        })?;
        let audit_path = tmp.path().join("audit.jsonl");
        let logger = JsonlAuditLogger::new(&audit_path);

        logger.record(boxlet::AuditEvent::ContainerCreated {
            container_id: "box-audit-1".to_string(),
            bundle: PathBuf::from("/tmp/bundle"),
        })?;
        logger.record(boxlet::AuditEvent::BranchBatchCompleted {
            branch_count: 2,
            succeeded_count: 1,
            promoted_branch_id: Some("branch-1".to_string()),
            promoted_changes: Some(3),
        })?;

        let audit_cli = Cli::try_parse_from([
            "boxlet",
            "audit",
            "--file",
            audit_path.to_str().unwrap_or_default(),
            "--json",
        ])
        .map_err(|err| BoxletError::InvalidPolicy {
            reason: err.to_string(),
        })?;

        assert_eq!(dispatch(audit_cli)?, ExitCode::SUCCESS);

        let prom_cli = Cli::try_parse_from([
            "boxlet",
            "audit",
            "--file",
            audit_path.to_str().unwrap_or_default(),
            "--prometheus",
        ])
        .map_err(|err| BoxletError::InvalidPolicy {
            reason: err.to_string(),
        })?;
        assert_eq!(dispatch(prom_cli)?, ExitCode::SUCCESS);

        let summary = logger.summarize()?;
        assert_eq!(summary.total_records, 2);
        assert_eq!(summary.branch_batches_completed, 1);
        assert_eq!(summary.promoted_winners, vec!["branch-1".to_string()]);
        assert!(summary.chronological_valid);
        Ok(())
    }

    #[test]
    fn cli_doctor_json_parses_and_executes_portably() -> Result<()> {
        let tmp = tempfile::tempdir().map_err(|source| BoxletError::StateStore {
            path: PathBuf::from("tempdir"),
            source,
        })?;
        let state_root = tmp.path().join("state");
        let cgroup_parent = tmp.path().join("cgroup");

        let doctor_cli = Cli::try_parse_from([
            "boxlet",
            "--root",
            state_root.to_str().unwrap_or_default(),
            "--cgroup-parent",
            cgroup_parent.to_str().unwrap_or_default(),
            "doctor",
            "--json",
        ])
        .map_err(|err| BoxletError::InvalidPolicy {
            reason: err.to_string(),
        })?;

        let expected_report = run_doctor(&state_root, &cgroup_parent);
        let expected_code = if expected_report.overall_ready {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };

        assert_eq!(dispatch(doctor_cli)?, expected_code);
        assert!(!expected_report.checks.is_empty());
        Ok(())
    }

    #[test]
    fn cli_image_export_import_and_microvm_config_execute_portably() -> Result<()> {
        let tmp = tempfile::tempdir().map_err(|source| BoxletError::StateStore {
            path: PathBuf::from("tempdir"),
            source,
        })?;
        let bundle_dir = tmp.path().join("vm-bundle");
        BundleBuilder::new()
            .with_shell_command("echo vm-ready")
            .build(&bundle_dir)?;

        let rootfs_src = bundle_dir.join("rootfs");
        std::fs::write(rootfs_src.join("etc/agent.conf"), b"mode=microvm\n").map_err(|source| {
            BoxletError::StateStore {
                path: rootfs_src.join("etc/agent.conf"),
                source,
            }
        })?;

        let tar_path = tmp.path().join("rootfs.tar");
        let export_cli = Cli::try_parse_from([
            "boxlet",
            "image-export",
            "--rootfs",
            rootfs_src.to_str().unwrap_or_default(),
            "--out",
            tar_path.to_str().unwrap_or_default(),
            "--json",
        ])
        .map_err(|err| BoxletError::InvalidPolicy {
            reason: err.to_string(),
        })?;
        assert_eq!(dispatch(export_cli)?, ExitCode::SUCCESS);
        assert!(tar_path.is_file());

        let imported_rootfs = tmp.path().join("imported-rootfs");
        let import_cli = Cli::try_parse_from([
            "boxlet",
            "image-import",
            "--archive",
            tar_path.to_str().unwrap_or_default(),
            "--out",
            imported_rootfs.to_str().unwrap_or_default(),
            "--json",
        ])
        .map_err(|err| BoxletError::InvalidPolicy {
            reason: err.to_string(),
        })?;
        assert_eq!(dispatch(import_cli)?, ExitCode::SUCCESS);
        let imported_conf = std::fs::read_to_string(imported_rootfs.join("etc/agent.conf"))
            .map_err(|source| BoxletError::StateStore {
                path: imported_rootfs.join("etc/agent.conf"),
                source,
            })?;
        assert_eq!(imported_conf, "mode=microvm\n");

        let fc_out = tmp.path().join("firecracker.json");
        let fc_cli = Cli::try_parse_from([
            "boxlet",
            "microvm-config",
            "--driver",
            "firecracker",
            "--id",
            "vm-test-1",
            "--mem-mib",
            "256",
            "--vcpus",
            "2",
            "--out",
            fc_out.to_str().unwrap_or_default(),
            bundle_dir.to_str().unwrap_or_default(),
        ])
        .map_err(|err| BoxletError::InvalidPolicy {
            reason: err.to_string(),
        })?;
        assert_eq!(dispatch(fc_cli)?, ExitCode::SUCCESS);
        assert!(fc_out.is_file());

        let lk_out = tmp.path().join("libkrun.json");
        let lk_cli = Cli::try_parse_from([
            "boxlet",
            "microvm-config",
            "--driver",
            "libkrun",
            "--id",
            "vm-test-2",
            "--out",
            lk_out.to_str().unwrap_or_default(),
            bundle_dir.to_str().unwrap_or_default(),
        ])
        .map_err(|err| BoxletError::InvalidPolicy {
            reason: err.to_string(),
        })?;
        assert_eq!(dispatch(lk_cli)?, ExitCode::SUCCESS);
        assert!(lk_out.is_file());

        Ok(())
    }
}
