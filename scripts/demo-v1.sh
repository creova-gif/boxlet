#!/usr/bin/env bash
# Boxlet V1 End-to-End Verification & Demo Suite
# Runs on any privileged Linux 5.15+ host with unified cgroup v2 and busybox-static.
set -euo pipefail

BOXLET_BIN="${1:-./target/debug/boxlet}"
CGROUP_PARENT="${BOXLET_CGROUP_PARENT:-/sys/fs/cgroup/boxlet.slice}"

if [[ ! -x "$BOXLET_BIN" ]]; then
  echo "error: boxlet binary not found or not executable at '$BOXLET_BIN'" >&2
  exit 1
fi

BUSYBOX_SRC=""
for candidate in /bin/busybox /usr/bin/busybox; do
  if [[ -x "$candidate" ]]; then
    BUSYBOX_SRC="$candidate"
    break
  fi
done
if [[ -z "$BUSYBOX_SRC" ]]; then
  echo "error: busybox binary not found in /bin/busybox or /usr/bin/busybox" >&2
  exit 1
fi

WORK_DIR="$(mktemp -d /tmp/boxlet-demo.XXXXXX)"
BUNDLE_DIR="$WORK_DIR/bundle"
STATE_ROOT="$WORK_DIR/state"

cleanup() {
  for id in ci-check-1 ci-check-2 ci-check-3 ci-check-4 ci-check-5 ci-check-6 ci-oci-lifecycle-1; do
    if [[ -d "$CGROUP_PARENT/$id" ]]; then
      echo 1 | sudo tee "$CGROUP_PARENT/$id/cgroup.kill" >/dev/null 2>&1 || true
      sudo rmdir "$CGROUP_PARENT/$id" >/dev/null 2>&1 || true
    fi
  done
  sudo rm -rf "$WORK_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> [Setup] Provisioning BusyBox OCI bundle at $BUNDLE_DIR and cgroup slice at $CGROUP_PARENT"
mkdir -p "$BUNDLE_DIR/rootfs/bin" "$BUNDLE_DIR/rootfs/proc" "$BUNDLE_DIR/rootfs/dev" "$BUNDLE_DIR/rootfs/tmp"
cp "$BUSYBOX_SRC" "$BUNDLE_DIR/rootfs/bin/busybox"
for cmd in sh echo sleep true false cat dd head grep mount chroot wc; do
  ln -sf /bin/busybox "$BUNDLE_DIR/rootfs/bin/$cmd"
done

sudo mkdir -p "$CGROUP_PARENT" "$STATE_ROOT"
echo "+memory +cpu +pids" | sudo tee /sys/fs/cgroup/cgroup.subtree_control >/dev/null || true
echo "+memory +cpu +pids" | sudo tee "$CGROUP_PARENT/cgroup.subtree_control" >/dev/null || true

write_bundle_config() {
  local shell_cmd="$1"
  cat > "$BUNDLE_DIR/config.json" <<EOF
{
  "ociVersion": "1.0.2",
  "process": {
    "terminal": false,
    "user": { "uid": 0, "gid": 0 },
    "args": ["/bin/sh", "-c", $(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$shell_cmd")],
    "env": ["PATH=/bin"],
    "cwd": "/"
  },
  "root": { "path": "rootfs", "readonly": false },
  "hostname": "boxlet-ci",
  "linux": {
    "namespaces": [
      { "type": "pid" },
      { "type": "mount" },
      { "type": "uts" },
      { "type": "ipc" },
      { "type": "network" }
    ]
  }
}
EOF
}

assert_zero_leaks() {
  local id="$1"
  if [[ -d "$CGROUP_PARENT/$id" ]]; then
    echo "FAIL: leftover cgroup directory $CGROUP_PARENT/$id" >&2
    exit 1
  fi
  if [[ -d "$STATE_ROOT/$id" ]]; then
    echo "FAIL: leftover state directory $STATE_ROOT/$id" >&2
    exit 1
  fi
}

# ------------------------------------------------------------------------------
# Check 1: Smoke + NoNewPrivs: 1 + dropped capabilities
# ------------------------------------------------------------------------------
echo "==> [Check 1] Smoke + NoNewPrivs: 1 + CapEff: 0000000000000000"
write_bundle_config "echo boxlet-ci-ok && grep -E '^(NoNewPrivs|CapEff):' /proc/self/status"
OUT_JSON="$WORK_DIR/check1.json"
RC=0
sudo "$BOXLET_BIN" run \
  --root "$STATE_ROOT" \
  --cgroup-parent "$CGROUP_PARENT" \
  --id ci-check-1 \
  --memory 128m \
  --cpus 0.5 \
  --network none \
  --json \
  "$BUNDLE_DIR" > "$OUT_JSON" || RC=$?

test "$RC" -eq 0
python3 - "$OUT_JSON" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
stdout = bytes(data["stdout"]).decode("utf-8", errors="replace")
assert data["exit_code"] == 0, f"expected exit_code 0, got {data['exit_code']}"
assert "boxlet-ci-ok" in stdout, f"missing boxlet-ci-ok in stdout: {stdout!r}"
assert "NoNewPrivs:\t1" in stdout, f"missing NoNewPrivs:\\t1 in stdout: {stdout!r}"
assert "CapEff:\t0000000000000000" in stdout, f"missing CapEff:\\t0000000000000000 in stdout: {stdout!r}"
assert data["cleanup"]["status"] == "clean", f"expected clean status, got {data['cleanup']}"
print("    stdout:", stdout.strip().replace("\n", " | "))
PY
assert_zero_leaks "ci-check-1"

# ------------------------------------------------------------------------------
# Check 2: Prohibited operation / seccomp + capability denial
# ------------------------------------------------------------------------------
echo "==> [Check 2] Prohibited syscall / capability denial (mount -t tmpfs none /tmp)"
write_bundle_config "mount -t tmpfs none /tmp"
OUT_JSON="$WORK_DIR/check2.json"
RC=0
sudo "$BOXLET_BIN" run \
  --root "$STATE_ROOT" \
  --cgroup-parent "$CGROUP_PARENT" \
  --id ci-check-2 \
  --memory 128m \
  --network none \
  --json \
  "$BUNDLE_DIR" > "$OUT_JSON" || RC=$?

test "$RC" -ne 0
python3 - "$OUT_JSON" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
stderr = bytes(data["stderr"]).decode("utf-8", errors="replace")
assert data["exit_code"] != 0, f"expected non-zero exit_code, got {data['exit_code']}"
assert "Operation not permitted" in stderr or "permission denied" in stderr.lower(), (
    f"expected Operation not permitted in stderr, got: {stderr!r}"
)
assert data["cleanup"]["status"] == "clean", f"expected clean status, got {data['cleanup']}"
print("    denied as expected:", stderr.strip())
PY
assert_zero_leaks "ci-check-2"

# ------------------------------------------------------------------------------
# Check 3: Bounded stdout truncation cap
# ------------------------------------------------------------------------------
echo "==> [Check 3] Bounded stdout truncation cap (--max-output-bytes 1024)"
write_bundle_config "dd if=/dev/zero bs=1024 count=4 2>/dev/null"
OUT_JSON="$WORK_DIR/check3.json"
RC=0
sudo "$BOXLET_BIN" run \
  --root "$STATE_ROOT" \
  --cgroup-parent "$CGROUP_PARENT" \
  --id ci-check-3 \
  --max-output-bytes 1024 \
  --json \
  "$BUNDLE_DIR" > "$OUT_JSON" || RC=$?

test "$RC" -eq 0
python3 - "$OUT_JSON" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
assert data["stdout_truncated"] is True, f"expected stdout_truncated=True, got {data['stdout_truncated']}"
assert len(data["stdout"]) == 1024, f"expected len(stdout)==1024, got {len(data['stdout'])}"
assert data["cleanup"]["status"] == "clean", f"expected clean status, got {data['cleanup']}"
print(f"    stdout_truncated={data['stdout_truncated']}, len(stdout)={len(data['stdout'])}")
PY
assert_zero_leaks "ci-check-3"

# ------------------------------------------------------------------------------
# Check 4: Grandchild pipe-hang immunity (7-step teardown)
# ------------------------------------------------------------------------------
echo "==> [Check 4] Grandchild pipe-hang immunity ((sleep 30 &) && echo grandchild-test-ok)"
write_bundle_config "(sleep 30 &) && echo grandchild-test-ok"
OUT_JSON="$WORK_DIR/check4.json"
START_TS=$(date +%s)
RC=0
sudo "$BOXLET_BIN" run \
  --root "$STATE_ROOT" \
  --cgroup-parent "$CGROUP_PARENT" \
  --id ci-check-4 \
  --json \
  "$BUNDLE_DIR" > "$OUT_JSON" || RC=$?
ELAPSED=$(( $(date +%s) - START_TS ))

test "$RC" -eq 0
test "$ELAPSED" -lt 5
python3 - "$OUT_JSON" "$ELAPSED" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
stdout = bytes(data["stdout"]).decode("utf-8", errors="replace")
assert data["exit_code"] == 0, f"expected exit_code 0, got {data['exit_code']}"
assert "grandchild-test-ok" in stdout, f"missing grandchild-test-ok in {stdout!r}"
assert data["cleanup"]["status"] == "clean", f"expected clean status, got {data['cleanup']}"
print(f"    completed in {sys.argv[2]}s (<5s) with cleanup=clean")
PY
assert_zero_leaks "ci-check-4"

# ------------------------------------------------------------------------------
# Check 5: Timeout enforcement
# ------------------------------------------------------------------------------
echo "==> [Check 5] Timeout enforcement (sleep 10 with --timeout 1)"
write_bundle_config "sleep 10"
OUT_JSON="$WORK_DIR/check5.json"
RC=0
sudo "$BOXLET_BIN" run \
  --root "$STATE_ROOT" \
  --cgroup-parent "$CGROUP_PARENT" \
  --id ci-check-5 \
  --timeout 1 \
  --json \
  "$BUNDLE_DIR" > "$OUT_JSON" || RC=$?

test "$RC" -ne 0
python3 - "$OUT_JSON" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
assert data["violations"]["timed_out"] is True, f"expected timed_out=True, got {data['violations']}"
assert data["cleanup"]["status"] == "clean", f"expected clean status, got {data['cleanup']}"
print(f"    timed_out={data['violations']['timed_out']}, termination_signal={data['violations']['termination_signal']}")
PY
assert_zero_leaks "ci-check-5"

# ------------------------------------------------------------------------------
# Check 6: Memory limit OOM enforcement
# ------------------------------------------------------------------------------
echo "==> [Check 6] Memory limit OOM enforcement (--memory 4m)"
write_bundle_config 'x="0123456789abcdef0123456789abcdef"; while true; do x="$x$x"; done'
OUT_JSON="$WORK_DIR/check6.json"
RC=0
sudo "$BOXLET_BIN" run \
  --root "$STATE_ROOT" \
  --cgroup-parent "$CGROUP_PARENT" \
  --id ci-check-6 \
  --memory 4m \
  --timeout 10 \
  --json \
  "$BUNDLE_DIR" > "$OUT_JSON" || RC=$?

test "$RC" -ne 0
python3 - "$OUT_JSON" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
oom = data["violations"]["oom_killed"]
exit_code = data["exit_code"]
sig = data["violations"]["termination_signal"]
peak = data["usage"].get("memory_peak_bytes")
assert oom is True or sig == 9 or exit_code == 137, (
    f"expected OOM kill or SIGKILL (9/137), got violations={data['violations']}, exit_code={exit_code}"
)
assert peak is None or peak > 0, f"expected memory_peak_bytes > 0 when available, got {peak}"
assert data["cleanup"]["status"] == "clean", f"expected clean status, got {data['cleanup']}"
print(f"    oom_killed={oom}, exit_code={exit_code}, signal={sig}, memory_peak_bytes={peak}")
PY
assert_zero_leaks "ci-check-6"

# ------------------------------------------------------------------------------
# Check 7: OCI lifecycle (create -> state -> start -> state -> kill -> delete)
# ------------------------------------------------------------------------------
echo "==> [Check 7] OCI lifecycle (create -> state -> start -> state -> kill -> delete)"
write_bundle_config "sleep 30"
OCI_ID="ci-oci-lifecycle-1"

sudo "$BOXLET_BIN" create \
  --root "$STATE_ROOT" \
  --cgroup-parent "$CGROUP_PARENT" \
  --bundle "$BUNDLE_DIR" \
  "$OCI_ID"

STATE_CREATED=$(sudo "$BOXLET_BIN" state --root "$STATE_ROOT" --cgroup-parent "$CGROUP_PARENT" "$OCI_ID")
echo "$STATE_CREATED" | grep -q '"status": "created"'

sudo "$BOXLET_BIN" start --root "$STATE_ROOT" --cgroup-parent "$CGROUP_PARENT" "$OCI_ID"

STATE_RUNNING=$(sudo "$BOXLET_BIN" state --root "$STATE_ROOT" --cgroup-parent "$CGROUP_PARENT" "$OCI_ID")
echo "$STATE_RUNNING" | grep -q '"status": "running"'

sudo "$BOXLET_BIN" kill --root "$STATE_ROOT" --cgroup-parent "$CGROUP_PARENT" "$OCI_ID" SIGKILL
sleep 0.2

STATE_STOPPED=$(sudo "$BOXLET_BIN" state --root "$STATE_ROOT" --cgroup-parent "$CGROUP_PARENT" "$OCI_ID")
echo "$STATE_STOPPED" | grep -q '"status": "stopped"'

sudo "$BOXLET_BIN" delete --root "$STATE_ROOT" --cgroup-parent "$CGROUP_PARENT" --force "$OCI_ID"
assert_zero_leaks "$OCI_ID"

# ------------------------------------------------------------------------------
# Check 8: V2 Snapshot & Deterministic Filesystem Diff (boxlet snapshot + boxlet diff --json)
# ------------------------------------------------------------------------------
echo "==> [Check 8] V2 Snapshot & Deterministic Filesystem Diff (boxlet snapshot + boxlet diff --json)"
"$BOXLET_BIN" snapshot \
  --rootfs "$BUNDLE_DIR/rootfs" \
  --out "$WORK_DIR/snapshots" \
  --json \
  snap-ci-1 > "$WORK_DIR/check8-snap.json"

cp -a "$BUNDLE_DIR/rootfs" "$WORK_DIR/rootfs-after"
echo "agent-artifact" > "$WORK_DIR/rootfs-after/tmp/agent_created.txt"
ln -sf /bin/sh "$WORK_DIR/rootfs-after/bin/wc"

"$BOXLET_BIN" diff \
  --json \
  "$WORK_DIR/snapshots/snap-ci-1" \
  "$WORK_DIR/rootfs-after" > "$WORK_DIR/check8-diff.json"

python3 - "$WORK_DIR/check8-snap.json" "$WORK_DIR/check8-diff.json" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    snap = json.load(f)
with open(sys.argv[2]) as f:
    diff = json.load(f)
assert snap.get("id") == "snap-ci-1", f"expected snap id 'snap-ci-1', got {snap.get('id')!r}"
assert "tmp/agent_created.txt" in diff.get("added", []), f"expected tmp/agent_created.txt in added, got {diff}"
assert "bin/wc" in diff.get("modified", []), f"expected bin/wc in modified, got {diff}"
print(f"    snapshot id={snap['id']}, diff added={diff['added']}, modified={diff['modified']}")
PY

# ------------------------------------------------------------------------------
# Check 9: V2 Multi-Agent Parallel Branch Execution (boxlet branch-run --json)
# ------------------------------------------------------------------------------
echo "==> [Check 9] V2 Multi-Agent Parallel Branch Execution (boxlet branch-run --json)"
sudo "$BOXLET_BIN" branch-run \
  --root "$STATE_ROOT" \
  --cgroup-parent "$CGROUP_PARENT" \
  --memory 128m \
  --network none \
  --cmd "echo candidate-a > /tmp/candidate_a.txt && echo branch-a-ok" \
  --cmd "echo candidate-b > /tmp/candidate_b.txt && rm -f /bin/wc && echo branch-b-ok" \
  --json \
  "$BUNDLE_DIR" > "$WORK_DIR/check9-branches.json"

python3 - "$WORK_DIR/check9-branches.json" <<'PY'
import json, sys

with open(sys.argv[1]) as f:
    data = json.load(f)

assert isinstance(data, list) and len(data) == 2, f"expected 2 branch results, got {len(data) if isinstance(data, list) else type(data)}"

def get_exit_code(branch):
    if "exit_code" in branch:
        return branch["exit_code"]
    for key in ("execution", "result"):
        if isinstance(branch.get(key), dict) and "exit_code" in branch[key]:
            return branch[key]["exit_code"]
    return None

b0, b1 = data[0], data[1]
assert get_exit_code(b0) == 0, f"expected branch 0 exit_code 0, got {b0}"
assert "tmp/candidate_a.txt" in b0["fs_diff"]["added"], f"expected tmp/candidate_a.txt in branch 0 added: {b0['fs_diff']}"
assert "tmp/candidate_b.txt" not in b0["fs_diff"]["added"], f"unexpected tmp/candidate_b.txt in branch 0 added: {b0['fs_diff']}"

assert get_exit_code(b1) == 0, f"expected branch 1 exit_code 0, got {b1}"
assert "tmp/candidate_b.txt" in b1["fs_diff"]["added"], f"expected tmp/candidate_b.txt in branch 1 added: {b1['fs_diff']}"
assert "bin/wc" in b1["fs_diff"]["deleted"], f"expected bin/wc in branch 1 deleted: {b1['fs_diff']}"
print(
    f"    branch[0] added={b0['fs_diff']['added']}, "
    f"branch[1] added={b1['fs_diff']['added']} deleted={b1['fs_diff']['deleted']}"
)
PY

test -e "$BUNDLE_DIR/rootfs/bin/wc"
test ! -e "$BUNDLE_DIR/rootfs/tmp/candidate_a.txt"

echo "==> All 9 Boxlet V1 & V2 end-to-end checks passed with zero leaked cgroups or state directories!"
