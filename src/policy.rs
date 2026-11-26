//! Execution policies, structured results, bounded output capture, and OCI merge logic.

use std::str::FromStr;
use std::time::Duration;

use oci_spec::runtime::{LinuxSeccomp, Spec};
use serde::{Deserialize, Serialize};

use crate::error::{BoxletError, Result};

/// Default per-stream stdout/stderr capture limit (1 MiB) to prevent host OOM.
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// Default cgroup v2 CPU period in microseconds (100 ms).
pub const DEFAULT_CPU_PERIOD_USEC: u64 = 100_000;

/// Supported V1 network isolation modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    /// Isolated Linux network namespace (`CLONE_NEWNET`) with loopback (`lo`) only.
    None,
    /// Shared host network namespace (no `CLONE_NEWNET`).
    Host,
}

impl FromStr for NetworkMode {
    type Err = BoxletError;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "host" => Ok(Self::Host),
            other => Err(BoxletError::UnsupportedNetworkMode {
                mode: other.to_string(),
            }),
        }
    }
}

/// Seccomp enforcement mode for `boxlet run`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum SeccompPolicy {
    /// Boxlet's default-deny V1 syscall allowlist.
    DefaultDeny,
    /// Explicit OCI seccomp profile.
    Custom(Box<LinuxSeccomp>),
    /// Explicitly disable seccomp filtering (not recommended for untrusted workloads).
    Disabled,
}

/// Per-device cgroup v2 `io.max` bandwidth (bytes/sec) and IOPS throttle rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoMaxRule {
    /// Block device major number (e.g. `8` for SCSI/SATA, `259` for NVMe).
    pub major: u32,
    /// Block device minor number (e.g. `0`).
    pub minor: u32,
    /// Maximum read bytes per second (`rbps`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rbps: Option<u64>,
    /// Maximum write bytes per second (`wbps`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wbps: Option<u64>,
    /// Maximum read I/O operations per second (`riops`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub riops: Option<u64>,
    /// Maximum write I/O operations per second (`wiops`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wiops: Option<u64>,
}

impl IoMaxRule {
    /// Validates that at least one limit is set and all set limits are strictly positive.
    pub fn validate(&self) -> Result<()> {
        if self.rbps.is_none()
            && self.wbps.is_none()
            && self.riops.is_none()
            && self.wiops.is_none()
        {
            return Err(BoxletError::InvalidPolicy {
                reason: "io.max rule must specify at least one of rbps, wbps, riops, or wiops"
                    .to_string(),
            });
        }
        if matches!(self.rbps, Some(0))
            || matches!(self.wbps, Some(0))
            || matches!(self.riops, Some(0))
            || matches!(self.wiops, Some(0))
        {
            return Err(BoxletError::InvalidPolicy {
                reason: "io.max limits must be greater than 0".to_string(),
            });
        }
        Ok(())
    }

    /// Formats this rule as a single cgroup v2 `io.max` line (without trailing newline).
    pub fn to_cgroup_line(&self) -> String {
        let fmt_opt = |opt: Option<u64>| match opt {
            Some(v) => v.to_string(),
            None => "max".to_string(),
        };
        format!(
            "{}:{} rbps={} wbps={} riops={} wiops={}",
            self.major,
            self.minor,
            fmt_opt(self.rbps),
            fmt_opt(self.wbps),
            fmt_opt(self.riops),
            fmt_opt(self.wiops),
        )
    }
}

impl FromStr for IoMaxRule {
    type Err = BoxletError;

    fn from_str(s: &str) -> Result<Self> {
        let mut tokens = s
            .split(|c: char| c.is_whitespace() || c == ',')
            .filter(|t| !t.is_empty());

        let dev_token = tokens.next().ok_or_else(|| BoxletError::InvalidPolicy {
            reason: "io.max rule must start with '<major>:<minor>'".to_string(),
        })?;
        let (maj_str, min_str) =
            dev_token
                .split_once(':')
                .ok_or_else(|| BoxletError::InvalidPolicy {
                    reason: format!(
                        "invalid io.max device '{dev_token}' (expected '<major>:<minor>')"
                    ),
                })?;
        let major = maj_str
            .parse::<u32>()
            .map_err(|_| BoxletError::InvalidPolicy {
                reason: format!("invalid io.max major number '{maj_str}'"),
            })?;
        let minor = min_str
            .parse::<u32>()
            .map_err(|_| BoxletError::InvalidPolicy {
                reason: format!("invalid io.max minor number '{min_str}'"),
            })?;

        let mut rule = Self {
            major,
            minor,
            rbps: None,
            wbps: None,
            riops: None,
            wiops: None,
        };

        for token in tokens {
            let (key, val_str) =
                token
                    .split_once('=')
                    .ok_or_else(|| BoxletError::InvalidPolicy {
                        reason: format!(
                            "invalid io.max parameter '{token}' (expected 'key=value')"
                        ),
                    })?;
            let parsed_val = if val_str.eq_ignore_ascii_case("max") {
                None
            } else {
                let n = val_str
                    .parse::<u64>()
                    .map_err(|_| BoxletError::InvalidPolicy {
                        reason: format!("invalid io.max limit value '{val_str}' for '{key}'"),
                    })?;
                Some(n)
            };

            match key {
                "rbps" => rule.rbps = parsed_val,
                "wbps" => rule.wbps = parsed_val,
                "riops" => rule.riops = parsed_val,
                "wiops" => rule.wiops = parsed_val,
                other => {
                    return Err(BoxletError::InvalidPolicy {
                        reason: format!(
                            "unknown io.max key '{other}' (expected rbps, wbps, riops, or wiops)"
                        ),
                    });
                }
            }
        }

        rule.validate()?;
        Ok(rule)
    }
}

/// First-class execution policy overlaid onto an OCI bundle by `boxlet run`.
///
/// Fields set to `None` defer to the bundle's `config.json`, falling back to
/// Boxlet's safe V1 defaults when omitted from both.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ExecutionPolicy {
    /// Hard cgroup v2 `memory.max` limit in bytes.
    pub memory_bytes: Option<u64>,
    /// CPU quota expressed in cores (e.g. `0.5` = 50,000 us per 100,000 us period).
    pub cpus: Option<f64>,
    /// Maximum number of processes/threads (`pids.max`).
    pub pids_limit: Option<i64>,
    /// Per-device cgroup v2 `io.max` block I/O bandwidth and IOPS limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub io_max: Option<Vec<IoMaxRule>>,
    /// Network isolation mode (`none` or `host`).
    pub network: Option<NetworkMode>,
    /// Whether to enforce `PR_SET_NO_NEW_PRIVS`.
    pub no_new_privs: Option<bool>,
    /// Explicit capability allowlist (empty vector drops all capabilities).
    pub capabilities: Option<Vec<String>>,
    /// Seccomp enforcement policy.
    pub seccomp: Option<SeccompPolicy>,
    /// Maximum wall-clock execution time before `cgroup.kill`.
    pub timeout: Option<Duration>,
    /// Maximum bytes captured per stream (`stdout` and `stderr` independently).
    pub max_output_bytes: Option<usize>,
    /// Maximum number of concurrent sandbox branches or eval candidates executed in parallel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrency: Option<usize>,
}

impl ExecutionPolicy {
    /// Validates all explicitly set bounds in the policy.
    pub fn validate(&self) -> Result<()> {
        if let Some(0) = self.memory_bytes {
            return Err(BoxletError::InvalidPolicy {
                reason: "memory_bytes must be greater than 0".to_string(),
            });
        }
        if let Some(cpus) = self.cpus {
            if !cpus.is_finite() || cpus <= 0.0 {
                return Err(BoxletError::InvalidPolicy {
                    reason: format!("cpus must be finite and > 0.0 (got {cpus})"),
                });
            }
        }
        if let Some(pids) = self.pids_limit {
            if pids <= 0 {
                return Err(BoxletError::InvalidPolicy {
                    reason: format!("pids_limit must be > 0 (got {pids})"),
                });
            }
        }
        if let Some(ref rules) = self.io_max {
            if rules.is_empty() {
                return Err(BoxletError::InvalidPolicy {
                    reason: "io_max must not be an empty list".to_string(),
                });
            }
            for rule in rules {
                rule.validate()?;
            }
        }
        if let Some(0) = self.max_concurrency {
            return Err(BoxletError::InvalidPolicy {
                reason: "max_concurrency must be at least 1".to_string(),
            });
        }
        Ok(())
    }
}

/// Concrete cgroup v2 resource limits derived from OCI spec + `ExecutionPolicy`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// `memory.max` in bytes.
    pub memory_bytes: Option<u64>,
    /// `cpu.max` quota in microseconds (paired with `cpu_period_usec`).
    pub cpu_quota_usec: Option<u64>,
    /// `cpu.max` period in microseconds.
    pub cpu_period_usec: u64,
    /// `pids.max` process limit.
    pub pids_limit: Option<i64>,
    /// Per-device cgroup v2 `io.max` throttle rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub io_max: Vec<IoMaxRule>,
}

/// Fully resolved specification produced by merging an OCI `config.json` with an [`ExecutionPolicy`].
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedRunSpec {
    /// Base OCI runtime specification loaded from `config.json`.
    pub oci_spec: Spec,
    /// Effective cgroup v2 resource limits.
    pub resources: ResourceLimits,
    /// Effective V1 network mode (`none` by default).
    pub network: NetworkMode,
    /// Effective `PR_SET_NO_NEW_PRIVS` flag (`true` by default).
    pub no_new_privs: bool,
    /// Effective capability allowlist override (`None` means use OCI spec capabilities).
    pub capabilities: Option<Vec<String>>,
    /// Effective seccomp policy (`DefaultDeny` if omitted from both policy and OCI spec).
    pub seccomp: SeccompPolicy,
    /// Optional wall-clock timeout.
    pub timeout: Option<Duration>,
    /// Maximum bytes captured per stream (`stdout` and `stderr`).
    pub max_output_bytes: usize,
}

/// Merges an OCI `Spec` with an [`ExecutionPolicy`] using Boxlet V1 precedence rules:
///
/// 1. Explicit fields in `policy` always override `config.json`.
/// 2. Fields omitted from `policy` inherit from `config.json` when present.
/// 3. Fields omitted from both receive Boxlet's safe V1 defaults (`network = none`,
///    `no_new_privs = true`, `seccomp = DefaultDeny`, `max_output_bytes = 1 MiB`).
///
/// Note: `boxlet create` never calls this function; it consumes `config.json` verbatim.
pub fn merge_policy_with_spec(base: &Spec, policy: &ExecutionPolicy) -> Result<ResolvedRunSpec> {
    policy.validate()?;

    let oci_resources = base.linux().as_ref().and_then(|l| l.resources().as_ref());

    let memory_bytes = match policy.memory_bytes {
        Some(m) => Some(m),
        None => oci_resources
            .and_then(|r| r.memory().as_ref())
            .and_then(|m| m.limit())
            .and_then(|limit| u64::try_from(limit).ok()),
    };

    let (cpu_quota_usec, cpu_period_usec) = match policy.cpus {
        Some(cpus) => {
            let quota = (cpus * (DEFAULT_CPU_PERIOD_USEC as f64)).round() as u64;
            (Some(quota.max(1)), DEFAULT_CPU_PERIOD_USEC)
        }
        None => {
            let oci_cpu = oci_resources.and_then(|r| r.cpu().as_ref());
            let period = oci_cpu
                .and_then(|c| c.period())
                .unwrap_or(DEFAULT_CPU_PERIOD_USEC);
            let quota = oci_cpu
                .and_then(|c| c.quota())
                .and_then(|q| u64::try_from(q).ok());
            (quota, period)
        }
    };

    let pids_limit = match policy.pids_limit {
        Some(p) => Some(p),
        None => oci_resources
            .and_then(|r| r.pids().as_ref())
            .map(|p| p.limit()),
    };

    let network = policy.network.unwrap_or(NetworkMode::None);

    let no_new_privs = policy
        .no_new_privs
        .or_else(|| base.process().as_ref().and_then(|p| p.no_new_privileges()))
        .unwrap_or(true);

    let seccomp = match &policy.seccomp {
        Some(explicit) => explicit.clone(),
        None => match base.linux().as_ref().and_then(|l| l.seccomp().as_ref()) {
            Some(oci_seccomp) => SeccompPolicy::Custom(Box::new(oci_seccomp.clone())),
            None => SeccompPolicy::DefaultDeny,
        },
    };

    let max_output_bytes = policy.max_output_bytes.unwrap_or(DEFAULT_MAX_OUTPUT_BYTES);
    let io_max = policy.io_max.clone().unwrap_or_default();

    Ok(ResolvedRunSpec {
        oci_spec: base.clone(),
        resources: ResourceLimits {
            memory_bytes,
            cpu_quota_usec,
            cpu_period_usec,
            pids_limit,
            io_max,
        },
        network,
        no_new_privs,
        capabilities: policy.capabilities.clone(),
        seccomp,
        timeout: policy.timeout,
        max_output_bytes,
    })
}

/// Resource usage metrics collected during container execution.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// Wall-clock duration of container execution.
    pub duration: Duration,
    /// Peak cgroup v2 memory usage in bytes (`memory.peak`), when available.
    pub memory_peak_bytes: Option<u64>,
    /// Total cgroup v2 CPU time in microseconds (`cpu.stat` `usage_usec`), when available.
    pub cpu_usage_usec: Option<u64>,
}

/// Observable policy-violation signals captured by the runtime.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyViolations {
    /// True when the workload exceeded `ExecutionPolicy::timeout`.
    pub timed_out: bool,
    /// True when cgroup v2 `memory.events` reported `oom_kill > 0` before teardown.
    pub oom_killed: bool,
    /// Signal number that terminated PID 1 (e.g. `SIGSYS` for `SCMP_ACT_KILL_PROCESS`).
    pub termination_signal: Option<i32>,
}

/// Outcome of container teardown (cgroup removal and state directory cleanup).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum CleanupStatus {
    /// All processes, cgroups, and state directories were removed cleanly.
    Clean,
    /// Cleanup encountered one or more non-fatal warnings.
    Partial {
        /// Human-readable warnings collected during teardown.
        warnings: Vec<String>,
    },
}

/// Structured, machine-readable outcome returned by `Engine::run` and `boxlet run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Container identifier.
    pub container_id: String,
    /// Normal exit status code if PID 1 exited without a fatal signal.
    pub exit_code: Option<i32>,
    /// Captured stdout bytes (bounded by `max_output_bytes`).
    pub stdout: Vec<u8>,
    /// Captured stderr bytes (bounded by `max_output_bytes`).
    pub stderr: Vec<u8>,
    /// True when stdout exceeded `max_output_bytes` and trailing bytes were discarded.
    pub stdout_truncated: bool,
    /// True when stderr exceeded `max_output_bytes` and trailing bytes were discarded.
    pub stderr_truncated: bool,
    /// Resource consumption metrics.
    pub usage: ResourceUsage,
    /// Observable policy violations.
    pub violations: PolicyViolations,
    /// Teardown status.
    pub cleanup: CleanupStatus,
}

/// Bounded in-memory byte buffer that discards overflow without allocating past `max_bytes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedBuffer {
    max_bytes: usize,
    data: Vec<u8>,
    truncated: bool,
}

impl BoundedBuffer {
    /// Creates a new bounded buffer with the given byte capacity limit.
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            data: Vec::new(),
            truncated: false,
        }
    }

    /// Appends bytes up to `max_bytes`, setting `truncated` if any input bytes are discarded.
    pub fn push(&mut self, chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }
        let remaining = self.max_bytes.saturating_sub(self.data.len());
        if remaining == 0 {
            self.truncated = true;
            return;
        }
        if chunk.len() <= remaining {
            self.data.extend_from_slice(chunk);
        } else {
            self.data.extend_from_slice(&chunk[..remaining]);
            self.truncated = true;
        }
    }

    /// Returns whether any bytes were discarded due to the cap.
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Consumes the buffer and returns `(bytes, truncated)`.
    pub fn into_parts(self) -> (Vec<u8>, bool) {
        (self.data, self.truncated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_mode_parses_supported_and_rejects_unsupported() {
        assert_eq!("none".parse::<NetworkMode>().ok(), Some(NetworkMode::None));
        assert_eq!("HOST".parse::<NetworkMode>().ok(), Some(NetworkMode::Host));

        let err = "bridge".parse::<NetworkMode>().unwrap_err();
        assert!(matches!(
            err,
            BoxletError::UnsupportedNetworkMode { mode } if mode == "bridge"
        ));
    }

    #[test]
    fn policy_validation_rejects_invalid_bounds() {
        let zero_mem = ExecutionPolicy {
            memory_bytes: Some(0),
            ..ExecutionPolicy::default()
        };
        assert!(matches!(
            zero_mem.validate(),
            Err(BoxletError::InvalidPolicy { .. })
        ));

        let bad_cpu = ExecutionPolicy {
            cpus: Some(f64::NAN),
            ..ExecutionPolicy::default()
        };
        assert!(matches!(
            bad_cpu.validate(),
            Err(BoxletError::InvalidPolicy { .. })
        ));

        let zero_pids = ExecutionPolicy {
            pids_limit: Some(0),
            ..ExecutionPolicy::default()
        };
        assert!(matches!(
            zero_pids.validate(),
            Err(BoxletError::InvalidPolicy { .. })
        ));

        let zero_concurrency = ExecutionPolicy {
            max_concurrency: Some(0),
            ..ExecutionPolicy::default()
        };
        assert!(matches!(
            zero_concurrency.validate(),
            Err(BoxletError::InvalidPolicy { .. })
        ));

        let empty_io_max = ExecutionPolicy {
            io_max: Some(Vec::new()),
            ..ExecutionPolicy::default()
        };
        assert!(matches!(
            empty_io_max.validate(),
            Err(BoxletError::InvalidPolicy { .. })
        ));
    }

    #[test]
    fn io_max_rule_parses_formats_and_rejects_invalid_rules() -> Result<()> {
        let parsed: IoMaxRule = "8:0 rbps=10485760 wbps=max riops=1000".parse()?;
        assert_eq!(
            parsed,
            IoMaxRule {
                major: 8,
                minor: 0,
                rbps: Some(10_485_760),
                wbps: None,
                riops: Some(1000),
                wiops: None,
            }
        );
        assert_eq!(
            parsed.to_cgroup_line(),
            "8:0 rbps=10485760 wbps=max riops=1000 wiops=max"
        );

        let comma_parsed: IoMaxRule = "259:1,wbps=5242880,wiops=500".parse()?;
        assert_eq!(
            comma_parsed.to_cgroup_line(),
            "259:1 rbps=max wbps=5242880 riops=max wiops=500"
        );

        assert!("8:0".parse::<IoMaxRule>().is_err());
        assert!("8:0 rbps=max wbps=max".parse::<IoMaxRule>().is_err());
        assert!("8:0 rbps=0".parse::<IoMaxRule>().is_err());
        assert!("8:0 unknown=100".parse::<IoMaxRule>().is_err());
        assert!("invalid rbps=100".parse::<IoMaxRule>().is_err());
        Ok(())
    }

    #[test]
    fn merge_applies_safe_v1_defaults_when_omitted_from_both() -> Result<()> {
        let spec = Spec::default();
        let policy = ExecutionPolicy::default();

        let resolved = merge_policy_with_spec(&spec, &policy)?;
        assert_eq!(resolved.network, NetworkMode::None);
        assert!(resolved.no_new_privs);
        assert_eq!(resolved.seccomp, SeccompPolicy::DefaultDeny);
        assert_eq!(resolved.max_output_bytes, DEFAULT_MAX_OUTPUT_BYTES);
        assert_eq!(resolved.resources.cpu_period_usec, DEFAULT_CPU_PERIOD_USEC);
        assert!(resolved.resources.io_max.is_empty());
        Ok(())
    }

    #[test]
    fn merge_policy_overrides_oci_spec_values() -> Result<()> {
        let spec = Spec::default();
        let io_rule: IoMaxRule = "8:0 rbps=10485760 wbps=5242880".parse()?;
        let policy = ExecutionPolicy {
            memory_bytes: Some(128 * 1024 * 1024),
            cpus: Some(0.5),
            pids_limit: Some(64),
            io_max: Some(vec![io_rule.clone()]),
            network: Some(NetworkMode::Host),
            no_new_privs: Some(true),
            capabilities: Some(Vec::new()),
            seccomp: Some(SeccompPolicy::Disabled),
            timeout: Some(Duration::from_secs(30)),
            max_output_bytes: Some(4096),
            max_concurrency: Some(4),
        };

        let resolved = merge_policy_with_spec(&spec, &policy)?;
        assert_eq!(resolved.resources.memory_bytes, Some(128 * 1024 * 1024));
        assert_eq!(resolved.resources.cpu_quota_usec, Some(50_000));
        assert_eq!(resolved.resources.pids_limit, Some(64));
        assert_eq!(resolved.resources.io_max, vec![io_rule]);
        assert_eq!(resolved.network, NetworkMode::Host);
        assert_eq!(resolved.seccomp, SeccompPolicy::Disabled);
        assert_eq!(resolved.timeout, Some(Duration::from_secs(30)));
        assert_eq!(resolved.max_output_bytes, 4096);
        Ok(())
    }

    #[test]
    fn bounded_buffer_caps_bytes_and_marks_truncated() {
        let mut buf = BoundedBuffer::new(5);
        buf.push(b"abc");
        assert!(!buf.is_truncated());
        buf.push(b"defgh");
        assert!(buf.is_truncated());
        buf.push(b"ignored");

        let (data, truncated) = buf.into_parts();
        assert_eq!(data, b"abcde");
        assert!(truncated);
    }

    #[test]
    fn bounded_buffer_zero_cap_discards_nonempty_input() {
        let mut buf = BoundedBuffer::new(0);
        buf.push(b"");
        assert!(!buf.is_truncated());
        buf.push(b"x");
        assert!(buf.is_truncated());
        let (data, truncated) = buf.into_parts();
        assert!(data.is_empty());
        assert!(truncated);
    }
}
