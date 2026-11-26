//! Declarative multi-agent evaluation specifications, guardrails, and rubric scoring (`boxlet eval`).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::engine::{BranchExecutionResult, BranchSpec};
use crate::error::{BoxletError, Result};
use crate::policy::ExecutionPolicy;
use crate::snapshot::FsDiff;

const fn default_true() -> bool {
    true
}

/// Declarative acceptance and ranking rubric applied to each candidate branch in [`EvalSpec`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalRubric {
    /// Require the candidate container to exit with code `0` and zero policy violations (`timed_out`, `oom_killed`).
    #[serde(default = "default_true")]
    pub require_exit_zero: bool,
    /// Substrings that MUST appear in the candidate's UTF-8 `stdout`.
    #[serde(default)]
    pub required_stdout_contains: Vec<String>,
    /// Substrings that MUST NOT appear in the candidate's UTF-8 `stderr`.
    #[serde(default)]
    pub forbidden_stderr_contains: Vec<String>,
    /// Relative paths that MUST be present in `fs_diff.added`.
    #[serde(default)]
    pub required_added_paths: Vec<PathBuf>,
    /// Relative paths that MUST NOT be modified or deleted (`fs_diff.modified` or `fs_diff.deleted`), e.g. protected test/CI files.
    #[serde(default)]
    pub forbidden_modified_paths: Vec<PathBuf>,
    /// Optional upper bound on total filesystem changes (`added + modified + deleted`).
    #[serde(default)]
    pub max_changed_files: Option<usize>,
}

impl Default for EvalRubric {
    fn default() -> Self {
        Self {
            require_exit_zero: true,
            required_stdout_contains: Vec::new(),
            forbidden_stderr_contains: Vec::new(),
            required_added_paths: Vec::new(),
            forbidden_modified_paths: Vec::new(),
            max_changed_files: None,
        }
    }
}

/// Declarative specification for evaluating multiple candidate branches against an [`EvalRubric`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvalSpec {
    /// Execution policy applied to every candidate branch.
    #[serde(default)]
    pub policy: ExecutionPolicy,
    /// Acceptance and scoring rubric.
    #[serde(default)]
    pub rubric: EvalRubric,
    /// Candidate branch specifications to execute in parallel.
    pub candidates: Vec<BranchSpec>,
    /// Whether to automatically promote the highest-ranked passing candidate onto the bundle rootfs.
    #[serde(default)]
    pub promote_winner: bool,
}

impl EvalSpec {
    /// Loads and deserializes a JSON [`EvalSpec`] from `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path).map_err(|source| BoxletError::StateStore {
            path: path.to_path_buf(),
            source,
        })?;
        let spec: Self = serde_json::from_str(&raw)?;
        Ok(spec)
    }
}

/// Rubric evaluation verdict and score for a single candidate branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateVerdict {
    /// Candidate branch identifier.
    pub branch_id: String,
    /// True when the candidate satisfied every constraint in [`EvalRubric`].
    pub passed_rubric: bool,
    /// Deterministic rubric score (higher is better; passing candidates score `>= 1000` minus change/duration penalties).
    pub score: i64,
    /// Human-readable rubric violation reasons (empty when `passed_rubric` is `true`).
    pub rubric_violations: Vec<String>,
    /// Underlying branch execution telemetry and filesystem diff.
    pub branch_result: BranchExecutionResult,
}

/// Complete evaluation report returned by `Engine::run_eval` and `boxlet eval`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalReport {
    /// Per-candidate verdicts in the input candidate order.
    pub verdicts: Vec<CandidateVerdict>,
    /// Identifier of the highest-ranked candidate that passed the rubric, if any.
    pub winning_branch_id: Option<String>,
    /// True if the winning branch's filesystem changes were promoted onto the bundle rootfs.
    pub promoted: bool,
    /// Filesystem diff applied to the bundle rootfs when `promoted` is `true`.
    pub promoted_diff: Option<FsDiff>,
}

/// Evaluates a single candidate's [`BranchExecutionResult`] against `rubric` and computes a deterministic [`CandidateVerdict`].
pub fn evaluate_candidate(
    rubric: &EvalRubric,
    branch_result: BranchExecutionResult,
) -> CandidateVerdict {
    let mut violations = Vec::new();

    if rubric.require_exit_zero {
        if branch_result.execution.exit_code != Some(0) {
            violations.push(format!(
                "expected exit_code Some(0), got {:?}",
                branch_result.execution.exit_code
            ));
        }
        if branch_result.execution.violations.timed_out {
            violations.push("candidate execution timed out".to_string());
        }
        if branch_result.execution.violations.oom_killed {
            violations.push("candidate execution was OOM-killed".to_string());
        }
    }

    let stdout_str = String::from_utf8_lossy(&branch_result.execution.stdout);
    for expected in &rubric.required_stdout_contains {
        if !stdout_str.contains(expected) {
            violations.push(format!("stdout missing required substring '{expected}'"));
        }
    }

    let stderr_str = String::from_utf8_lossy(&branch_result.execution.stderr);
    for forbidden in &rubric.forbidden_stderr_contains {
        if stderr_str.contains(forbidden) {
            violations.push(format!("stderr contains forbidden substring '{forbidden}'"));
        }
    }

    for required_path in &rubric.required_added_paths {
        if !branch_result
            .fs_diff
            .added
            .iter()
            .any(|added| added == required_path)
        {
            violations.push(format!(
                "required added path '{}' missing from fs_diff.added",
                required_path.display()
            ));
        }
    }

    for forbidden_path in &rubric.forbidden_modified_paths {
        let touched = branch_result
            .fs_diff
            .modified
            .iter()
            .chain(branch_result.fs_diff.deleted.iter())
            .find(|p| *p == forbidden_path || p.starts_with(forbidden_path));
        if let Some(offending) = touched {
            violations.push(format!(
                "protected path '{}' was modified or deleted (matched rule '{}')",
                offending.display(),
                forbidden_path.display()
            ));
        }
    }

    let total_changes = branch_result.fs_diff.total_changes();
    if let Some(max_files) = rubric.max_changed_files {
        if total_changes > max_files {
            violations.push(format!(
                "total changed files ({total_changes}) exceeded max_changed_files ({max_files})"
            ));
        }
    }

    let passed_rubric = violations.is_empty();
    let score = if passed_rubric {
        let change_penalty = i64::try_from(total_changes).unwrap_or(i64::MAX / 20) * 10;
        let duration_ms_capped = branch_result
            .execution
            .usage
            .duration
            .as_millis()
            .min(5_000);
        let duration_penalty = i64::try_from(duration_ms_capped).unwrap_or(5_000);
        10_000 - change_penalty - duration_penalty
    } else {
        -(i64::try_from(violations.len()).unwrap_or(1_000) * 1000)
    };

    CandidateVerdict {
        branch_id: branch_result.branch_id.clone(),
        passed_rubric,
        score,
        rubric_violations: violations,
        branch_result,
    }
}

/// Selects the highest-scoring [`CandidateVerdict`] that passed the rubric, breaking ties by earliest candidate order.
pub fn select_winning_verdict(verdicts: &[CandidateVerdict]) -> Option<&CandidateVerdict> {
    let mut best: Option<&CandidateVerdict> = None;
    for verdict in verdicts.iter().filter(|v| v.passed_rubric) {
        if best.is_none_or(|current| verdict.score > current.score) {
            best = Some(verdict);
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::policy::{CleanupStatus, ExecutionResult, PolicyViolations, ResourceUsage};

    fn make_branch_result(
        branch_id: &str,
        exit_code: Option<i32>,
        stdout: &[u8],
        stderr: &[u8],
        duration_ms: u64,
        fs_diff: FsDiff,
    ) -> BranchExecutionResult {
        BranchExecutionResult {
            branch_id: branch_id.to_string(),
            execution: ExecutionResult {
                container_id: branch_id.to_string(),
                exit_code,
                stdout: stdout.to_vec(),
                stderr: stderr.to_vec(),
                stdout_truncated: false,
                stderr_truncated: false,
                usage: ResourceUsage {
                    duration: Duration::from_millis(duration_ms),
                    memory_peak_bytes: Some(4096),
                    cpu_usage_usec: Some(200),
                },
                violations: PolicyViolations::default(),
                cleanup: CleanupStatus::Clean,
            },
            fs_diff,
        }
    }

    #[test]
    fn evaluate_candidate_enforces_stdout_added_and_forbidden_path_guardrails() {
        let rubric = EvalRubric {
            require_exit_zero: true,
            required_stdout_contains: vec!["ALL TESTS PASSED".to_string()],
            forbidden_stderr_contains: vec!["PANIC".to_string()],
            required_added_paths: vec![PathBuf::from("src/fix.rs")],
            forbidden_modified_paths: vec![PathBuf::from("tests/harness")],
            max_changed_files: Some(2),
        };

        let passing_res = make_branch_result(
            "cand-pass",
            Some(0),
            b"running suite... ALL TESTS PASSED\n",
            b"",
            25,
            FsDiff {
                added: vec![PathBuf::from("src/fix.rs")],
                modified: vec![PathBuf::from("src/lib.rs")],
                deleted: Vec::new(),
            },
        );
        let pass_verdict = evaluate_candidate(&rubric, passing_res);
        assert!(pass_verdict.passed_rubric);
        assert!(pass_verdict.rubric_violations.is_empty());
        assert_eq!(pass_verdict.score, 10_000 - 20 - 25);

        let failing_res = make_branch_result(
            "cand-tamper",
            Some(0),
            b"missing expected token\n",
            b"PANIC in worker\n",
            10,
            FsDiff {
                added: Vec::new(),
                modified: vec![PathBuf::from("tests/harness/judge.rs")],
                deleted: Vec::new(),
            },
        );
        let fail_verdict = evaluate_candidate(&rubric, failing_res);
        assert!(!fail_verdict.passed_rubric);
        assert_eq!(fail_verdict.rubric_violations.len(), 4);
        assert_eq!(fail_verdict.score, -4000);
    }

    #[test]
    fn select_winning_verdict_ranks_passing_candidates_by_score_and_tiebreaks_in_order() {
        let rubric = EvalRubric::default();

        // Candidate 1: 3 changed files, 50ms -> score = 10_000 - 30 - 50 = 9920
        let v1 = evaluate_candidate(
            &rubric,
            make_branch_result(
                "cand-1",
                Some(0),
                b"ok",
                b"",
                50,
                FsDiff {
                    added: vec![
                        PathBuf::from("a.rs"),
                        PathBuf::from("b.rs"),
                        PathBuf::from("c.rs"),
                    ],
                    modified: Vec::new(),
                    deleted: Vec::new(),
                },
            ),
        );

        // Candidate 2: 1 changed file, 10ms -> score = 10_000 - 10 - 10 = 9980
        let v2 = evaluate_candidate(
            &rubric,
            make_branch_result(
                "cand-2",
                Some(0),
                b"ok",
                b"",
                10,
                FsDiff {
                    added: vec![PathBuf::from("minimal.rs")],
                    modified: Vec::new(),
                    deleted: Vec::new(),
                },
            ),
        );

        // Candidate 3: tied with Candidate 2 (1 changed file, 10ms -> score = 9980)
        let v3 = evaluate_candidate(
            &rubric,
            make_branch_result(
                "cand-3",
                Some(0),
                b"ok",
                b"",
                10,
                FsDiff {
                    added: vec![PathBuf::from("other.rs")],
                    modified: Vec::new(),
                    deleted: Vec::new(),
                },
            ),
        );

        let verdicts = vec![v1, v2, v3];
        let winner = select_winning_verdict(&verdicts);
        assert_eq!(winner.map(|w| w.branch_id.as_str()), Some("cand-2"));
    }
}
