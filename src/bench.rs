//! Deterministic sandbox execution, snapshot/diff, and parallel branch benchmark suite.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::error::{BoxletError, Result};
use crate::policy::ExecutionPolicy;

/// Configuration for [`crate::Engine::run_benchmark`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkConfig {
    /// Number of measured iterations per benchmark phase (`>= 1`).
    pub iterations: usize,
    /// Number of unmeasured warmup runs executed before timing begins.
    pub warmup: usize,
    /// Number of concurrent candidate branches executed per iteration in the parallel branch phase (`>= 1`).
    pub branches_per_iter: usize,
    /// Execution policy applied to each measured and warmup run.
    pub policy: ExecutionPolicy,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            iterations: 5,
            warmup: 1,
            branches_per_iter: 2,
            policy: ExecutionPolicy::default(),
        }
    }
}

impl BenchmarkConfig {
    /// Validates that `iterations >= 1`, `branches_per_iter >= 1`, and `policy` is valid.
    pub fn validate(&self) -> Result<()> {
        if self.iterations == 0 {
            return Err(BoxletError::InvalidPolicy {
                reason: "benchmark iterations must be at least 1".to_string(),
            });
        }
        if self.branches_per_iter == 0 {
            return Err(BoxletError::InvalidPolicy {
                reason: "benchmark branches_per_iter must be at least 1".to_string(),
            });
        }
        self.policy.validate()
    }
}

/// Percentile and mean latency distribution summary in microseconds (`us`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencySummary {
    /// Total number of latency samples recorded.
    pub samples: usize,
    /// Minimum observed latency in microseconds.
    pub min_us: u64,
    /// Median (50th percentile) latency in microseconds.
    pub p50_us: u64,
    /// 95th percentile latency in microseconds.
    pub p95_us: u64,
    /// 99th percentile latency in microseconds.
    pub p99_us: u64,
    /// Maximum observed latency in microseconds.
    pub max_us: u64,
    /// Arithmetic mean latency in microseconds.
    pub mean_us: u64,
}

impl LatencySummary {
    /// Computes deterministic latency percentiles (`min`, `p50`, `p95`, `p99`, `max`, `mean`)
    /// from a slice of raw latency samples in microseconds.
    pub fn from_samples(raw_samples_us: &[u64]) -> Self {
        if raw_samples_us.is_empty() {
            return Self::default();
        }
        let mut sorted = raw_samples_us.to_vec();
        sorted.sort_unstable();
        let n = sorted.len();

        let percentile = |pct: usize| -> u64 {
            let idx = ((n.saturating_sub(1)) * pct) / 100;
            sorted[idx]
        };

        let sum: u128 = sorted.iter().map(|&v| u128::from(v)).sum();
        let mean_us = u64::try_from(sum / (n as u128)).unwrap_or(u64::MAX);

        Self {
            samples: n,
            min_us: sorted[0],
            p50_us: percentile(50),
            p95_us: percentile(95),
            p99_us: percentile(99),
            max_us: sorted[n - 1],
            mean_us,
        }
    }
}

/// Structured benchmark report produced by [`crate::Engine::run_benchmark`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkReport {
    /// Number of measured iterations executed per phase.
    pub iterations: usize,
    /// Number of warmup iterations executed before measurement.
    pub warmup: usize,
    /// Number of concurrent branches executed per iteration in the parallel branch phase.
    pub branches_per_iter: usize,
    /// Cold-start single container execution (`Engine::run`) latency distribution.
    pub run_latency_us: LatencySummary,
    /// Parallel multi-branch execution (`Engine::run_branches`) batch latency distribution.
    pub branch_batch_latency_us: LatencySummary,
    /// Workspace `TreeManifest::capture` + `diff` cycle latency distribution.
    pub snapshot_diff_latency_us: LatencySummary,
    /// Aggregate single-container throughput in runs per second.
    pub throughput_runs_per_sec: f64,
    /// Maximum cgroup v2 `memory.peak` bytes observed across measured runs, if reported.
    pub peak_memory_bytes: Option<u64>,
}

impl BenchmarkReport {
    /// Renders this benchmark report as a GitHub-Flavored Markdown table.
    pub fn to_markdown_table(&self) -> String {
        let mut out = String::with_capacity(512);
        let _ = writeln!(
            out,
            "| Phase | Samples | Min (us) | p50 (us) | p95 (us) | p99 (us) | Max (us) | Mean (us) |"
        );
        let _ = writeln!(
            out,
            "| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
        );
        for (name, summary) in [
            ("sandbox_run", &self.run_latency_us),
            ("snapshot_diff", &self.snapshot_diff_latency_us),
            ("parallel_branch_batch", &self.branch_batch_latency_us),
        ] {
            let _ = writeln!(
                out,
                "| `{name}` | {} | {} | {} | {} | {} | {} | {} |",
                summary.samples,
                summary.min_us,
                summary.p50_us,
                summary.p95_us,
                summary.p99_us,
                summary.max_us,
                summary.mean_us
            );
        }
        let peak_mem_display = match self.peak_memory_bytes {
            Some(bytes) => format!("{bytes} B"),
            None => "n/a".to_string(),
        };
        let _ = writeln!(
            out,
            "\n- **Throughput:** {:.2} runs/sec | **Warmup:** {} | **Branches/Iter:** {} | **Peak Memory:** {}",
            self.throughput_runs_per_sec,
            self.warmup,
            self.branches_per_iter,
            peak_mem_display
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_summary_computes_percentiles_and_handles_empty_input() {
        let empty = LatencySummary::from_samples(&[]);
        assert_eq!(empty, LatencySummary::default());

        let samples = vec![500, 100, 300, 200, 400];
        let summary = LatencySummary::from_samples(&samples);
        assert_eq!(summary.samples, 5);
        assert_eq!(summary.min_us, 100);
        assert_eq!(summary.p50_us, 300);
        assert_eq!(summary.p95_us, 400);
        assert_eq!(summary.p99_us, 400);
        assert_eq!(summary.max_us, 500);
        assert_eq!(summary.mean_us, 300);
    }

    #[test]
    fn benchmark_config_validates_iterations_branches_and_policy() {
        let valid = BenchmarkConfig::default();
        assert!(valid.validate().is_ok());

        let zero_iters = BenchmarkConfig {
            iterations: 0,
            ..BenchmarkConfig::default()
        };
        assert!(matches!(
            zero_iters.validate(),
            Err(BoxletError::InvalidPolicy { .. })
        ));

        let zero_branches = BenchmarkConfig {
            branches_per_iter: 0,
            ..BenchmarkConfig::default()
        };
        assert!(matches!(
            zero_branches.validate(),
            Err(BoxletError::InvalidPolicy { .. })
        ));
    }

    #[test]
    fn benchmark_report_renders_markdown_table() {
        let report = BenchmarkReport {
            iterations: 3,
            warmup: 1,
            branches_per_iter: 2,
            run_latency_us: LatencySummary::from_samples(&[100, 200, 300]),
            snapshot_diff_latency_us: LatencySummary::from_samples(&[50, 60, 70]),
            branch_batch_latency_us: LatencySummary::from_samples(&[250, 300, 350]),
            throughput_runs_per_sec: 5000.0,
            peak_memory_bytes: Some(4096),
        };
        let md = report.to_markdown_table();
        assert!(md.contains("| Phase | Samples | Min (us) | p50 (us) | p95 (us) | p99 (us) | Max (us) | Mean (us) |"));
        assert!(md.contains("| `sandbox_run` | 3 | 100 | 200 | 200 | 200 | 300 | 200 |"));
        assert!(md.contains("| `snapshot_diff` | 3 | 50 | 60 | 60 | 60 | 70 | 60 |"));
        assert!(md.contains("| `parallel_branch_batch` | 3 | 250 | 300 | 300 | 300 | 350 | 300 |"));
        assert!(md.contains("5000.00 runs/sec"));
        assert!(md.contains("4096 B"));
    }
}
