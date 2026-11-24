//! Thin `clap` CLI driving the shared `boxlet::Engine`.

#[cfg(target_os = "linux")]
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
#[cfg(target_os = "linux")]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};

use boxlet::error::{BoxletError, Result};
use boxlet::oci::state::DEFAULT_STATE_ROOT;
#[cfg(target_os = "linux")]
use boxlet::policy::{ExecutionPolicy, NetworkMode};

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

#[cfg(target_os = "linux")]
fn dispatch(cli: Cli) -> Result<ExitCode> {
    if let Commands::InternalInit { config } = cli.command {
        boxlet::run_internal_init(&config)?;
        return Ok(ExitCode::SUCCESS);
    }

    let backend = boxlet::LinuxBackend::new(cli.root, cli.cgroup_parent);
    let engine = boxlet::Engine::new(backend);

    match cli.command {
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
            let memory_bytes = memory.as_deref().map(parse_byte_size).transpose()?;
            let network_mode = network
                .as_deref()
                .map(|m| m.parse::<NetworkMode>())
                .transpose()?;
            let policy = ExecutionPolicy {
                memory_bytes,
                cpus,
                pids_limit: pids,
                network: network_mode,
                timeout: timeout.map(Duration::from_secs),
                max_output_bytes,
                ..ExecutionPolicy::default()
            };

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
        Commands::InternalInit { .. } => Ok(ExitCode::SUCCESS),
    }
}

#[cfg(not(target_os = "linux"))]
fn dispatch(_cli: Cli) -> Result<ExitCode> {
    Err(BoxletError::UnsupportedPlatform {
        feature: "Linux OCI container execution",
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
}
