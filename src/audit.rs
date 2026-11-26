//! Structured, append-only JSON Lines (`.jsonl`) audit trail for sandbox lifecycle and execution telemetry.

use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{BoxletError, Result};
use crate::policy::{CleanupStatus, PolicyViolations};

/// 64-bit FNV-1a offset basis constant.
pub const FNV1A_64_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;

/// 64-bit FNV-1a prime multiplier constant.
pub const FNV1A_64_PRIME: u64 = 0x0100_0000_01b3;

fn fnv1a_64_update(mut hash: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(FNV1A_64_PRIME);
    }
    hash
}

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
    /// Stopped (or forced) containers were garbage-collected (`boxlet prune`).
    ContainersPruned {
        /// Number of containers removed.
        removed_count: usize,
        /// Number of active (`Creating`, `Created`, `Running`) containers skipped.
        skipped_active_count: usize,
        /// Whether `--force` was set.
        force: bool,
    },
}

/// Aggregated telemetry and integrity summary computed across a `.jsonl` audit log.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditSummary {
    /// Total number of valid [`AuditRecord`] lines parsed.
    pub total_records: usize,
    /// Total `container_run_completed` events.
    pub runs_completed: usize,
    /// Number of `container_run_completed` events with `exit_code == Some(0)` and no violations.
    pub runs_succeeded: usize,
    /// Number of `container_run_completed` events that exited non-zero or had violations.
    pub runs_failed: usize,
    /// Number of runs where `violations.timed_out` was true.
    pub timed_out_count: usize,
    /// Number of runs where `violations.oom_killed` was true.
    pub oom_killed_count: usize,
    /// Total `branch_batch_completed` events.
    pub branch_batches_completed: usize,
    /// Total candidate branches evaluated across all `branch_batch_completed` events.
    pub total_branches_evaluated: usize,
    /// Winning branch IDs promoted across `branch_batch_completed` events.
    pub promoted_winners: Vec<String>,
    /// Sum of `duration_ms` across all `container_run_completed` events.
    pub total_duration_ms: u64,
    /// Maximum `memory_peak_bytes` observed across all `container_run_completed` events.
    pub max_memory_peak_bytes: Option<u64>,
    /// True when all `timestamp_unix_ms` values are non-decreasing in file order.
    pub chronological_valid: bool,
    /// True when every record's sequence number, previous hash link, and FNV-1a payload hash are valid.
    pub hash_chain_valid: bool,
    /// The `record_hash_fnv1a64` of the final record in the audit log (`0` if empty).
    pub head_hash_fnv1a64: u64,
}

impl AuditSummary {
    /// Formats this audit summary in standard Prometheus / OpenMetrics text exposition format.
    pub fn to_prometheus_metrics(&self) -> String {
        let mut out = String::with_capacity(1536);

        let _ = writeln!(
            out,
            "# HELP boxlet_audit_records_total Total number of valid audit records in the ledger.\n\
             # TYPE boxlet_audit_records_total counter\n\
             boxlet_audit_records_total {}",
            self.total_records
        );
        let _ = writeln!(
            out,
            "# HELP boxlet_runs_completed_total Total number of sandbox container runs completed.\n\
             # TYPE boxlet_runs_completed_total counter\n\
             boxlet_runs_completed_total {}",
            self.runs_completed
        );
        let _ = writeln!(
            out,
            "# HELP boxlet_runs_succeeded_total Total number of sandbox container runs that exited cleanly with code 0.\n\
             # TYPE boxlet_runs_succeeded_total counter\n\
             boxlet_runs_succeeded_total {}",
            self.runs_succeeded
        );
        let _ = writeln!(
            out,
            "# HELP boxlet_runs_failed_total Total number of sandbox container runs that failed or violated policy.\n\
             # TYPE boxlet_runs_failed_total counter\n\
             boxlet_runs_failed_total {}",
            self.runs_failed
        );
        let _ = writeln!(
            out,
            "# HELP boxlet_runs_timed_out_total Total number of sandbox container runs terminated due to timeout.\n\
             # TYPE boxlet_runs_timed_out_total counter\n\
             boxlet_runs_timed_out_total {}",
            self.timed_out_count
        );
        let _ = writeln!(
            out,
            "# HELP boxlet_runs_oom_killed_total Total number of sandbox container runs killed by cgroup v2 OOM.\n\
             # TYPE boxlet_runs_oom_killed_total counter\n\
             boxlet_runs_oom_killed_total {}",
            self.oom_killed_count
        );
        let _ = writeln!(
            out,
            "# HELP boxlet_branch_batches_completed_total Total number of parallel multi-branch evaluation batches completed.\n\
             # TYPE boxlet_branch_batches_completed_total counter\n\
             boxlet_branch_batches_completed_total {}",
            self.branch_batches_completed
        );
        let _ = writeln!(
            out,
            "# HELP boxlet_branches_evaluated_total Total number of candidate branches evaluated across all batches.\n\
             # TYPE boxlet_branches_evaluated_total counter\n\
             boxlet_branches_evaluated_total {}",
            self.total_branches_evaluated
        );
        let _ = writeln!(
            out,
            "# HELP boxlet_run_duration_milliseconds_total Cumulative execution duration in milliseconds across all runs.\n\
             # TYPE boxlet_run_duration_milliseconds_total counter\n\
             boxlet_run_duration_milliseconds_total {}",
            self.total_duration_ms
        );
        let _ = writeln!(
            out,
            "# HELP boxlet_memory_peak_bytes_max Maximum cgroup v2 memory peak in bytes observed across all runs.\n\
             # TYPE boxlet_memory_peak_bytes_max gauge\n\
             boxlet_memory_peak_bytes_max {}",
            self.max_memory_peak_bytes.unwrap_or(0)
        );
        let _ = writeln!(
            out,
            "# HELP boxlet_audit_chronological_valid Whether all audit record timestamps are monotonically non-decreasing (1 = valid, 0 = invalid).\n\
             # TYPE boxlet_audit_chronological_valid gauge\n\
             boxlet_audit_chronological_valid {}",
            u8::from(self.chronological_valid)
        );
        let _ = writeln!(
            out,
            "# HELP boxlet_audit_hash_chain_valid Whether the FNV-1a 64-bit tamper-evident hash chain is intact (1 = valid, 0 = invalid).\n\
             # TYPE boxlet_audit_hash_chain_valid gauge\n\
             boxlet_audit_hash_chain_valid {}",
            u8::from(self.hash_chain_valid)
        );

        out
    }
}

/// Timestamped, hash-chained envelope written as a single JSON Line in an audit log file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// 1-based monotonic sequence number in the audit ledger.
    #[serde(default)]
    pub seq: u64,
    /// 64-bit FNV-1a hash of the immediately preceding record (`0` for the genesis record).
    #[serde(default)]
    pub prev_hash_fnv1a64: u64,
    /// Deterministic 64-bit FNV-1a digest over `(seq, prev_hash_fnv1a64, timestamp_unix_ms, event)`.
    #[serde(default)]
    pub record_hash_fnv1a64: u64,
    /// Unix epoch timestamp in milliseconds when the event was recorded.
    pub timestamp_unix_ms: u64,
    /// Flattened structured audit event payload.
    #[serde(flatten)]
    pub event: AuditEvent,
}

impl AuditRecord {
    /// Computes the deterministic 64-bit FNV-1a digest over sequence number, previous hash, timestamp, and canonical event JSON.
    pub fn compute_hash(
        seq: u64,
        prev_hash_fnv1a64: u64,
        timestamp_unix_ms: u64,
        event: &AuditEvent,
    ) -> Result<u64> {
        let event_bytes = serde_json::to_vec(event)?;
        let mut hash = FNV1A_64_OFFSET_BASIS;
        hash = fnv1a_64_update(hash, &seq.to_le_bytes());
        hash = fnv1a_64_update(hash, &prev_hash_fnv1a64.to_le_bytes());
        hash = fnv1a_64_update(hash, &timestamp_unix_ms.to_le_bytes());
        hash = fnv1a_64_update(hash, &event_bytes);
        Ok(hash)
    }

    /// Creates a new hash-chained [`AuditRecord`] at `seq` linked to `prev_hash_fnv1a64`.
    pub fn new_chained(seq: u64, prev_hash_fnv1a64: u64, event: AuditEvent) -> Result<Self> {
        let timestamp_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        let record_hash_fnv1a64 =
            Self::compute_hash(seq, prev_hash_fnv1a64, timestamp_unix_ms, &event)?;
        Ok(Self {
            seq,
            prev_hash_fnv1a64,
            record_hash_fnv1a64,
            timestamp_unix_ms,
            event,
        })
    }

    /// Creates a standalone genesis [`AuditRecord`] (`seq = 1`, `prev_hash_fnv1a64 = 0`) stamped with the current Unix epoch timestamp.
    pub fn new(event: AuditEvent) -> Self {
        let timestamp_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        let record_hash_fnv1a64 = Self::compute_hash(1, 0, timestamp_unix_ms, &event).unwrap_or(0);
        Self {
            seq: 1,
            prev_hash_fnv1a64: 0,
            record_hash_fnv1a64,
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

    /// Appends `event` as a hash-chained, timestamped JSON Line to the audit log under an exclusive file lock.
    pub fn record(&self, event: AuditEvent) -> Result<AuditRecord> {
        let mut file = self.open_log_file()?;
        file.lock().map_err(|source| BoxletError::StateStore {
            path: self.path.clone(),
            source,
        })?;

        file.seek(SeekFrom::Start(0))
            .map_err(|source| BoxletError::StateStore {
                path: self.path.clone(),
                source,
            })?;

        let mut count: u64 = 0;
        let mut last_record: Option<AuditRecord> = None;
        {
            let reader = BufReader::new(&file);
            for line_res in reader.lines() {
                let line = line_res.map_err(|source| BoxletError::StateStore {
                    path: self.path.clone(),
                    source,
                })?;
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let rec: AuditRecord = serde_json::from_str(trimmed)?;
                count = count.saturating_add(1);
                last_record = Some(rec);
            }
        }

        let (next_seq, prev_hash) = match last_record {
            Some(last) => {
                let seq = if last.seq == 0 {
                    count.saturating_add(1)
                } else {
                    last.seq.saturating_add(1)
                };
                (seq, last.record_hash_fnv1a64)
            }
            None => (1, 0),
        };

        let rec = AuditRecord::new_chained(next_seq, prev_hash, event)?;
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
        options.read(true).create(true).append(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        #[cfg(target_os = "linux")]
        {
            options.custom_flags(libc::O_NOFOLLOW);
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

    /// Verifies both chronological monotonicity and FNV-1a 64-bit hash-chain integrity across the audit ledger.
    pub fn verify_integrity(&self) -> Result<bool> {
        let summary = self.summarize()?;
        Ok(summary.chronological_valid && summary.hash_chain_valid)
    }

    /// Aggregates all records in the `.jsonl` audit log into an [`AuditSummary`] and verifies chronological and hash-chain integrity.
    pub fn summarize(&self) -> Result<AuditSummary> {
        let records = self.read_all()?;
        let mut summary = AuditSummary {
            chronological_valid: true,
            hash_chain_valid: true,
            ..AuditSummary::default()
        };
        let mut prev_ts: Option<u64> = None;
        let mut expected_prev_hash: u64 = 0;

        for (idx, rec) in records.into_iter().enumerate() {
            summary.total_records += 1;
            if let Some(prev) = prev_ts {
                if rec.timestamp_unix_ms < prev {
                    summary.chronological_valid = false;
                }
            }
            prev_ts = Some(rec.timestamp_unix_ms);

            let expected_seq = (idx as u64).saturating_add(1);
            let computed_hash = AuditRecord::compute_hash(
                rec.seq,
                rec.prev_hash_fnv1a64,
                rec.timestamp_unix_ms,
                &rec.event,
            )?;
            if rec.seq != expected_seq
                || rec.prev_hash_fnv1a64 != expected_prev_hash
                || rec.record_hash_fnv1a64 != computed_hash
            {
                summary.hash_chain_valid = false;
            }
            expected_prev_hash = rec.record_hash_fnv1a64;
            summary.head_hash_fnv1a64 = rec.record_hash_fnv1a64;

            match rec.event {
                AuditEvent::ContainerRunCompleted {
                    exit_code,
                    duration_ms,
                    memory_peak_bytes,
                    violations,
                    ..
                } => {
                    summary.runs_completed += 1;
                    let has_violation = violations.timed_out
                        || violations.oom_killed
                        || violations.termination_signal.is_some();
                    if exit_code == Some(0) && !has_violation {
                        summary.runs_succeeded += 1;
                    } else {
                        summary.runs_failed += 1;
                    }
                    if violations.timed_out {
                        summary.timed_out_count += 1;
                    }
                    if violations.oom_killed {
                        summary.oom_killed_count += 1;
                    }
                    summary.total_duration_ms =
                        summary.total_duration_ms.saturating_add(duration_ms);
                    if let Some(peak) = memory_peak_bytes {
                        summary.max_memory_peak_bytes = Some(
                            summary
                                .max_memory_peak_bytes
                                .map_or(peak, |cur| cur.max(peak)),
                        );
                    }
                }
                AuditEvent::BranchBatchCompleted {
                    branch_count,
                    promoted_branch_id,
                    ..
                } => {
                    summary.branch_batches_completed += 1;
                    summary.total_branches_evaluated = summary
                        .total_branches_evaluated
                        .saturating_add(branch_count);
                    if let Some(winner) = promoted_branch_id {
                        summary.promoted_winners.push(winner);
                    }
                }
                AuditEvent::ContainerCreated { .. }
                | AuditEvent::ContainerStarted { .. }
                | AuditEvent::ContainerKilled { .. }
                | AuditEvent::ContainerDeleted { .. }
                | AuditEvent::ContainersPruned { .. } => {}
            }
        }

        Ok(summary)
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
        assert_eq!(r1.seq, 1);
        assert_eq!(r1.prev_hash_fnv1a64, 0);
        assert_ne!(r1.record_hash_fnv1a64, 0);
        assert_eq!(r2.seq, 2);
        assert_eq!(r2.prev_hash_fnv1a64, r1.record_hash_fnv1a64);
        assert_eq!(r3.seq, 3);
        assert_eq!(r3.prev_hash_fnv1a64, r2.record_hash_fnv1a64);
        assert_eq!(r1.event, e1);
        assert_eq!(r2.event, e2);
        assert_eq!(r3.event, e3);

        let all = logger.read_all()?;
        assert_eq!(all.len(), 3);
        assert_eq!(all[0], r1);
        assert_eq!(all[1], r2);
        assert_eq!(all[2], r3);
        assert!(logger.verify_integrity()?);

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

    #[test]
    fn audit_logger_summarize_computes_metrics_and_verifies_chronological_order() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|source| BoxletError::StateStore {
            path: PathBuf::from("tempdir"),
            source,
        })?;
        let log_path = dir.path().join("audit.jsonl");
        let logger = JsonlAuditLogger::new(&log_path);

        logger.record(AuditEvent::ContainerRunCompleted {
            container_id: "run-ok".to_string(),
            exit_code: Some(0),
            duration_ms: 30,
            memory_peak_bytes: Some(2_000_000),
            cpu_usage_usec: Some(10_000),
            violations: PolicyViolations::default(),
            cleanup: CleanupStatus::Clean,
        })?;

        logger.record(AuditEvent::ContainerRunCompleted {
            container_id: "run-oom-timeout".to_string(),
            exit_code: None,
            duration_ms: 120,
            memory_peak_bytes: Some(8_000_000),
            cpu_usage_usec: Some(50_000),
            violations: PolicyViolations {
                timed_out: true,
                oom_killed: true,
                termination_signal: Some(9),
            },
            cleanup: CleanupStatus::Clean,
        })?;

        logger.record(AuditEvent::BranchBatchCompleted {
            branch_count: 3,
            succeeded_count: 2,
            promoted_branch_id: Some("candidate-a".to_string()),
            promoted_changes: Some(2),
        })?;

        let last_rec = logger.record(AuditEvent::ContainersPruned {
            removed_count: 2,
            skipped_active_count: 1,
            force: false,
        })?;

        let summary = logger.summarize()?;
        assert_eq!(summary.total_records, 4);
        assert_eq!(summary.runs_completed, 2);
        assert_eq!(summary.runs_succeeded, 1);
        assert_eq!(summary.runs_failed, 1);
        assert_eq!(summary.timed_out_count, 1);
        assert_eq!(summary.oom_killed_count, 1);
        assert_eq!(summary.branch_batches_completed, 1);
        assert_eq!(summary.total_branches_evaluated, 3);
        assert_eq!(summary.promoted_winners, vec!["candidate-a".to_string()]);
        assert_eq!(summary.total_duration_ms, 150);
        assert_eq!(summary.max_memory_peak_bytes, Some(8_000_000));
        assert!(summary.chronological_valid);
        assert!(summary.hash_chain_valid);
        assert_eq!(summary.head_hash_fnv1a64, last_rec.record_hash_fnv1a64);
        assert!(logger.verify_integrity()?);

        let prom = summary.to_prometheus_metrics();
        assert!(prom.contains("boxlet_audit_records_total 4"));
        assert!(prom.contains("boxlet_runs_completed_total 2"));
        assert!(prom.contains("boxlet_runs_succeeded_total 1"));
        assert!(prom.contains("boxlet_runs_failed_total 1"));
        assert!(prom.contains("boxlet_runs_timed_out_total 1"));
        assert!(prom.contains("boxlet_runs_oom_killed_total 1"));
        assert!(prom.contains("boxlet_branch_batches_completed_total 1"));
        assert!(prom.contains("boxlet_branches_evaluated_total 3"));
        assert!(prom.contains("boxlet_run_duration_milliseconds_total 150"));
        assert!(prom.contains("boxlet_memory_peak_bytes_max 8000000"));
        assert!(prom.contains("boxlet_audit_chronological_valid 1"));
        assert!(prom.contains("boxlet_audit_hash_chain_valid 1"));

        Ok(())
    }

    #[test]
    fn audit_logger_detects_payload_tampering_and_line_deletion() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|source| BoxletError::StateStore {
            path: PathBuf::from("tempdir"),
            source,
        })?;
        let log_path = dir.path().join("audit.jsonl");
        let logger = JsonlAuditLogger::new(&log_path);

        logger.record(AuditEvent::ContainerCreated {
            container_id: "box-alpha".to_string(),
            bundle: PathBuf::from("/tmp/bundle-a"),
        })?;
        logger.record(AuditEvent::ContainerStarted {
            container_id: "box-alpha".to_string(),
            pid: Some(1234),
        })?;
        logger.record(AuditEvent::ContainerDeleted {
            container_id: "box-alpha".to_string(),
            force: false,
        })?;

        assert!(logger.verify_integrity()?);

        let original_contents =
            fs::read_to_string(&log_path).map_err(|source| BoxletError::StateStore {
                path: log_path.clone(),
                source,
            })?;

        // 1. Tamper with payload field in the second line.
        let tampered_payload = original_contents.replace("1234", "9999");
        fs::write(&log_path, &tampered_payload).map_err(|source| BoxletError::StateStore {
            path: log_path.clone(),
            source,
        })?;
        assert!(!logger.summarize()?.hash_chain_valid);
        assert!(!logger.verify_integrity()?);

        // 2. Delete the first line to break sequence and prev_hash linkage.
        let remaining_lines: Vec<&str> = original_contents.lines().skip(1).collect();
        fs::write(&log_path, format!("{}\n", remaining_lines.join("\n"))).map_err(|source| {
            BoxletError::StateStore {
                path: log_path.clone(),
                source,
            }
        })?;
        assert!(!logger.summarize()?.hash_chain_valid);
        assert!(!logger.verify_integrity()?);

        Ok(())
    }
}
