//! Structured, append-only JSON Lines (`.jsonl`) audit trail for sandbox lifecycle and execution telemetry.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{BoxletError, Result};
use crate::policy::{CleanupStatus, PolicyViolations};

/// Structured lifecycle or execution event recorded to the Boxlet audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    /// A container was created (`boxlet create`).
    ContainerCreated {
        /// Container identifier.
        container_id: String,
        /// Bundle directory path.
        bundle: PathBuf,
    },
    /// A created container was started (`boxlet start`).
    ContainerStarted {
        /// Container identifier.
        container_id: String,
        /// Container init PID on the host, if known.
        pid: Option<u32>,
    },
    /// A signal was delivered to a container (`boxlet kill`).
    ContainerKilled {
        /// Container identifier.
        container_id: String,
        /// OS signal number delivered.
        signal: i32,
    },
    /// A container was deleted (`boxlet delete`).
    ContainerDeleted {
        /// Container identifier.
        container_id: String,
        /// Whether `--force` was set.
        force: bool,
    },
    /// A single policy-driven execution completed (`boxlet run`).
    ContainerRunCompleted {
        /// Container identifier.
        container_id: String,
        /// Exit code if exited normally.
        exit_code: Option<i32>,
        /// Execution wall-clock duration in milliseconds.
        duration_ms: u64,
        /// Peak memory usage in bytes (`memory.peak`).
        memory_peak_bytes: Option<u64>,
        /// Total CPU usage in microseconds (`cpu.stat`).
        cpu_usage_usec: Option<u64>,
        /// Policy violation flags.
        violations: PolicyViolations,
        /// Cleanup outcome.
        cleanup: CleanupStatus,
    },
    /// A parallel multi-branch evaluation batch completed (`boxlet branch-run`).
    BranchBatchCompleted {
        /// Total number of candidate branches evaluated.
        branch_count: usize,
        /// Number of branches that exited with code `0` and no violations.
        succeeded_count: usize,
        /// Promoted winning branch ID, if `--promote-winner` succeeded.
        promoted_branch_id: Option<String>,
        /// Total filesystem changes (`added + modified + deleted`) in the promoted diff, if any.
        promoted_changes: Option<usize>,
    },
}

/// Timestamped envelope written as a single JSON Line in an audit log file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Unix epoch timestamp in milliseconds when the event was recorded.
    pub timestamp_unix_ms: u64,
    /// Flattened structured audit event payload.
    #[serde(flatten)]
    pub event: AuditEvent,
}

impl AuditRecord {
    /// Creates a new [`AuditRecord`] stamped with the current Unix epoch timestamp in milliseconds.
    pub fn new(event: AuditEvent) -> Self {
        let timestamp_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        Self {
            timestamp_unix_ms,
            event,
        }
    }
}

/// Append-only JSON Lines (`.jsonl`) audit logger with `0600` owner-only file permissions.
#[derive(Debug, Clone)]
pub struct JsonlAuditLogger {
    path: PathBuf,
}

impl JsonlAuditLogger {
    /// Creates a new [`JsonlAuditLogger`] writing to `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Returns the filesystem path of the `.jsonl` audit log file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Verifies that the audit log file can be safely opened for append without following symlinks.
    pub fn preflight(&self) -> Result<()> {
        let _file = self.open_log_file()?;
        Ok(())
    }

    /// Appends `event` as a single timestamped JSON Line to the audit log and returns the written [`AuditRecord`].
    pub fn record(&self, event: AuditEvent) -> Result<AuditRecord> {
        let mut file = self.open_log_file()?;

        let rec = AuditRecord::new(event);
        let mut line = serde_json::to_string(&rec)?;
        line.push('\n');

        file.write_all(line.as_bytes())
            .map_err(|source| BoxletError::StateStore {
                path: self.path.clone(),
                source,
            })?;

        Ok(rec)
    }

    fn open_log_file(&self) -> Result<File> {
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|source| BoxletError::StateStore {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        if let Ok(meta) = fs::symlink_metadata(&self.path) {
            if meta.file_type().is_symlink() {
                return Err(BoxletError::StateStore {
                    path: self.path.clone(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "audit log path must not be a symbolic link",
                    ),
                });
            }
        }

        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }

        let file = options
            .open(&self.path)
            .map_err(|source| BoxletError::StateStore {
                path: self.path.clone(),
                source,
            })?;

        #[cfg(unix)]
        {
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|source| BoxletError::StateStore {
                    path: self.path.clone(),
                    source,
                })?;
        }

        Ok(file)
    }

    /// Reads and parses all [`AuditRecord`] entries from the `.jsonl` audit log file in chronological order.
    pub fn read_all(&self) -> Result<Vec<AuditRecord>> {
        let file = File::open(&self.path).map_err(|source| BoxletError::StateStore {
            path: self.path.clone(),
            source,
        })?;
        let reader = BufReader::new(file);
        let mut records = Vec::new();
        for line_res in reader.lines() {
            let line = line_res.map_err(|source| BoxletError::StateStore {
                path: self.path.clone(),
                source,
            })?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let record: AuditRecord = serde_json::from_str(trimmed)?;
            records.push(record);
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonl_audit_logger_appends_records_and_enforces_0600_permissions() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|source| BoxletError::StateStore {
            path: PathBuf::from("tempdir"),
            source,
        })?;
        let log_path = dir.path().join("logs").join("audit.jsonl");
        let logger = JsonlAuditLogger::new(&log_path);

        let e1 = AuditEvent::ContainerCreated {
            container_id: "box-1".to_string(),
            bundle: PathBuf::from("/tmp/bundle"),
        };
        let e2 = AuditEvent::ContainerRunCompleted {
            container_id: "box-1".to_string(),
            exit_code: Some(0),
            duration_ms: 42,
            memory_peak_bytes: Some(1024 * 1024),
            cpu_usage_usec: Some(15_000),
            violations: PolicyViolations::default(),
            cleanup: CleanupStatus::Clean,
        };
        let e3 = AuditEvent::BranchBatchCompleted {
            branch_count: 3,
            succeeded_count: 2,
            promoted_branch_id: Some("candidate-b".to_string()),
            promoted_changes: Some(4),
        };

        let r1 = logger.record(e1.clone())?;
        let r2 = logger.record(e2.clone())?;
        let r3 = logger.record(e3.clone())?;

        assert!(r1.timestamp_unix_ms > 0);
        assert_eq!(r1.event, e1);
        assert_eq!(r2.event, e2);
        assert_eq!(r3.event, e3);

        let all = logger.read_all()?;
        assert_eq!(all.len(), 3);
        assert_eq!(all[0], r1);
        assert_eq!(all[1], r2);
        assert_eq!(all[2], r3);

        #[cfg(unix)]
        {
            let meta = fs::metadata(&log_path).map_err(|source| BoxletError::StateStore {
                path: log_path.clone(),
                source,
            })?;
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }

        Ok(())
    }
}
