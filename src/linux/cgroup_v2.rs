//! Linux 5.15+ unified cgroup v2 resource controller.

use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use crate::error::{BoxletError, Result};
use crate::policy::ResourceLimits;
use crate::traits::{CgroupStats, ResourceController};

/// Default parent cgroup slice (`--cgroup-parent`) outside the runner's active process cgroup.
pub const DEFAULT_CGROUP_PARENT: &str = "/sys/fs/cgroup/boxlet.slice";

/// Unified cgroup v2 controller managing leaf directories `<parent>/<container_id>`.
#[derive(Debug, Clone)]
pub(crate) struct CgroupV2Controller {
    parent: PathBuf,
}

impl CgroupV2Controller {
    /// Creates a cgroup v2 controller rooted under `parent`.
    pub(crate) fn new(parent: impl Into<PathBuf>) -> Self {
        Self {
            parent: parent.into(),
        }
    }

    /// Returns the path of the container's leaf cgroup directory.
    pub(crate) fn leaf_path(&self, container_id: &str) -> PathBuf {
        self.parent.join(container_id)
    }

    /// Ensures the parent slice exists and enables `+memory +cpu +pids` in `cgroup.subtree_control`.
    fn ensure_parent_slice(&self) -> Result<()> {
        fs::create_dir_all(&self.parent).map_err(|err| BoxletError::Runtime {
            subsystem: "cgroup_v2",
            message: format!(
                "failed to create cgroup parent '{}': {err}",
                self.parent.display()
            ),
        })?;

        let subtree_control = self.parent.join("cgroup.subtree_control");
        if subtree_control.exists() {
            fs::write(&subtree_control, "+memory +cpu +pids\n").map_err(|err| {
                BoxletError::Runtime {
                    subsystem: "cgroup_v2",
                    message: format!(
                        "failed to enable +memory +cpu +pids in '{}': {err}",
                        subtree_control.display()
                    ),
                }
            })?;
        }
        Ok(())
    }
}

impl ResourceController for CgroupV2Controller {
    fn create_cgroup(&self, container_id: &str, limits: &ResourceLimits) -> Result<PathBuf> {
        self.ensure_parent_slice()?;
        let leaf = self.leaf_path(container_id);
        fs::create_dir_all(&leaf).map_err(|err| BoxletError::Runtime {
            subsystem: "cgroup_v2",
            message: format!("failed to create leaf cgroup '{}': {err}", leaf.display()),
        })?;

        if let Some(mem_bytes) = limits.memory_bytes {
            write_cgroup_file(&leaf.join("memory.max"), &format!("{mem_bytes}\n"))?;
        }

        if limits.cpu_quota_usec.is_some() {
            let cpu_max = format_cpu_max(limits.cpu_quota_usec, limits.cpu_period_usec);
            write_cgroup_file(&leaf.join("cpu.max"), &format!("{cpu_max}\n"))?;
        }

        if let Some(pids) = limits.pids_limit {
            write_cgroup_file(&leaf.join("pids.max"), &format!("{pids}\n"))?;
        }

        Ok(leaf)
    }

    fn attach_pid(&self, container_id: &str, pid: u32) -> Result<()> {
        let procs = self.leaf_path(container_id).join("cgroup.procs");
        write_cgroup_file(&procs, &format!("{pid}\n"))
    }

    fn kill_all(&self, container_id: &str) -> Result<()> {
        let kill_file = self.leaf_path(container_id).join("cgroup.kill");
        if !kill_file.exists() {
            return Ok(());
        }
        write_cgroup_file(&kill_file, "1\n")
    }

    fn read_stats(&self, container_id: &str) -> Result<CgroupStats> {
        let leaf = self.leaf_path(container_id);
        let memory_peak_bytes = fs::read_to_string(leaf.join("memory.peak"))
            .ok()
            .and_then(|s| parse_u64_value(&s));

        let cpu_usage_usec = fs::read_to_string(leaf.join("cpu.stat"))
            .ok()
            .and_then(|s| parse_cpu_stat_usage_usec(&s));

        let oom_kill_count = fs::read_to_string(leaf.join("memory.events"))
            .ok()
            .map(|s| parse_memory_events_oom_kill(&s))
            .unwrap_or(0);

        Ok(CgroupStats {
            memory_peak_bytes,
            cpu_usage_usec,
            oom_kill_count,
        })
    }

    fn remove_cgroup(&self, container_id: &str) -> Result<()> {
        let leaf = self.leaf_path(container_id);
        if !leaf.exists() {
            return Ok(());
        }

        // Kernel may briefly return EBUSY right after cgroup.kill while reaping dying tasks.
        let mut last_err = None;
        for _ in 0..20 {
            match fs::remove_dir(&leaf) {
                Ok(()) => return Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(err) => {
                    last_err = Some(err);
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }

        let err_msg = last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown error".to_string());
        Err(BoxletError::Runtime {
            subsystem: "cgroup_v2",
            message: format!("failed to remove cgroup '{}': {err_msg}", leaf.display()),
        })
    }
}

fn write_cgroup_file(path: &Path, content: &str) -> Result<()> {
    fs::write(path, content).map_err(|err| BoxletError::Runtime {
        subsystem: "cgroup_v2",
        message: format!("failed to write '{}': {err}", path.display()),
    })
}

/// Formats the cgroup v2 `cpu.max` value (`"<quota> <period>"` or `"max <period>"`).
pub(crate) fn format_cpu_max(quota_usec: Option<u64>, period_usec: u64) -> String {
    match quota_usec {
        Some(quota) => format!("{quota} {period_usec}"),
        None => format!("max {period_usec}"),
    }
}

/// Parses `oom_kill <N>` from cgroup v2 `memory.events`.
pub(crate) fn parse_memory_events_oom_kill(content: &str) -> u64 {
    content
        .lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            let key = parts.next()?;
            let val = parts.next()?;
            if key == "oom_kill" {
                val.parse::<u64>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

/// Parses `usage_usec <N>` from cgroup v2 `cpu.stat`.
pub(crate) fn parse_cpu_stat_usage_usec(content: &str) -> Option<u64> {
    content.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let key = parts.next()?;
        let val = parts.next()?;
        if key == "usage_usec" {
            val.parse::<u64>().ok()
        } else {
            None
        }
    })
}

/// Parses a single trimmed `u64` value (such as `memory.peak`).
pub(crate) fn parse_u64_value(content: &str) -> Option<u64> {
    content.trim().parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cgroup_v2_stats_files_correctly() {
        let mem_events = "low 0\nhigh 0\nmax 4\noom 1\noom_kill 2\noom_group_kill 0\n";
        assert_eq!(parse_memory_events_oom_kill(mem_events), 2);
        assert_eq!(parse_memory_events_oom_kill("low 0\n"), 0);

        let cpu_stat = "usage_usec 14820\nuser_usec 9100\nsystem_usec 5720\n";
        assert_eq!(parse_cpu_stat_usage_usec(cpu_stat), Some(14_820));
        assert_eq!(parse_cpu_stat_usage_usec("nr_periods 10\n"), None);

        assert_eq!(parse_u64_value("67108864\n"), Some(67_108_864));
        assert_eq!(parse_u64_value("max\n"), None);

        assert_eq!(format_cpu_max(Some(50_000), 100_000), "50000 100000");
        assert_eq!(format_cpu_max(None, 100_000), "max 100000");
    }

    #[test]
    fn mock_cgroup_dir_writes_limits_reads_stats_and_removes_cleanly() -> Result<()> {
        let tmp = tempfile::tempdir().map_err(|source| BoxletError::StateStore {
            path: PathBuf::from("tempdir"),
            source,
        })?;
        let ctrl = CgroupV2Controller::new(tmp.path().join("boxlet.slice"));
        let limits = ResourceLimits {
            memory_bytes: Some(134_217_728),
            cpu_quota_usec: Some(50_000),
            cpu_period_usec: 100_000,
            pids_limit: Some(64),
        };

        let leaf = ctrl.create_cgroup("test-cg", &limits)?;
        assert_eq!(
            fs::read_to_string(leaf.join("memory.max")).ok().as_deref(),
            Some("134217728\n")
        );
        assert_eq!(
            fs::read_to_string(leaf.join("cpu.max")).ok().as_deref(),
            Some("50000 100000\n")
        );
        assert_eq!(
            fs::read_to_string(leaf.join("pids.max")).ok().as_deref(),
            Some("64\n")
        );

        fs::write(leaf.join("memory.peak"), "1048576\n").ok();
        fs::write(leaf.join("cpu.stat"), "usage_usec 4200\n").ok();
        fs::write(leaf.join("memory.events"), "oom_kill 1\n").ok();

        let stats = ctrl.read_stats("test-cg")?;
        assert_eq!(stats.memory_peak_bytes, Some(1_048_576));
        assert_eq!(stats.cpu_usage_usec, Some(4_200));
        assert_eq!(stats.oom_kill_count, 1);

        // Clean up mock files so remove_dir succeeds (real cgroupfs deletes virtual files on rmdir)
        for f in [
            "memory.max",
            "cpu.max",
            "pids.max",
            "memory.peak",
            "cpu.stat",
            "memory.events",
        ] {
            let _ = fs::remove_file(leaf.join(f));
        }
        ctrl.remove_cgroup("test-cg")?;
        assert!(!leaf.exists());
        Ok(())
    }
}
