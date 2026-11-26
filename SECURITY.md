# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `0.1.x` | :white_check_mark: Supported |
| `< 0.1.0` | :x: Unsupported |

---

## Shared-Kernel vs. Hardware-Virtualized MicroVM Isolation Boundary

Boxlet provides two distinct isolation tiers depending on workload trust:

1. **`LinuxBackend` (Shared-Kernel Linux Container Isolation):**
   - Uses Linux 5.15+ namespaces (`CLONE_NEWPID`, `CLONE_NEWNS`, `CLONE_NEWUTS`, `CLONE_NEWIPC`, `CLONE_NEWNET`), `pivot_root`, dropped Linux capabilities (`caps`), `PR_SET_NO_NEW_PRIVS`, pure-Rust `seccompiler` cBPF syscall filtering, and unified cgroup v2 (`memory.max`, `cpu.max`, `pids.max`, `cgroup.kill`).
   - **Boundary Warning:** Like `runc` and `youki`, `LinuxBackend` containers share the host Linux kernel. For untrusted or hostile multi-tenant workloads, run `LinuxBackend` inside a dedicated outer VM or use `MicroVmBackend`.
2. **`MicroVmBackend` (`Firecracker` / `libkrun` Hardware Virtualization):**
   - Synthesizes deterministic KVM microVM specifications (`boxlet microvm-config --driver firecracker|libkrun`, `FirecrackerVmSpec`, `LibkrunVmSpec`) with a dedicated guest kernel, memory ballooning disabled, and non-root execution posture (`no_new_privileges: true`) to provide a hardware virtualization boundary against host kernel privilege escalation.

For the full trust-boundary diagram, threat matrix, and fail-closed controls (including tar archive path-traversal rejection and cBPF seccomp compilation), see **[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)**.

---

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for suspected security vulnerabilities (such as container breakouts, symlink/path traversal bypasses in `image` or `snapshot`, seccomp filter bypasses, or cgroup escape vectors).

Instead, report vulnerabilities privately via:
1. **GitHub Private Vulnerability Reporting:** Use the ["Report a vulnerability"](https://github.com/creova-gif/boxlet/security/advisories/new) tab on the repository.
2. **What to Include:**
   - Host OS, Linux kernel version (`uname -r`), and CPU architecture (`x86_64` / `aarch64`).
   - Minimal OCI `config.json`, `EvalSpec`, or tar archive reproducing the issue.
   - Expected fail-closed behavior vs. observed behavior.

We acknowledge vulnerability reports within **48 hours** and aim to publish a fix and coordinated security advisory within **14 days**.
