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
  for id in ci-check-1 ci-check-2 ci-check-3 ci-check-4 ci-check-5 ci-check-6 ci-oci-lifecycle-1 ci-check-11 ci-check-12 ci-list-1 ci-list-2 eval-cand-tamper eval-cand-fail eval-cand-clean; do
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

# ------------------------------------------------------------------------------
# Check 10: V2 Candidate Evaluation, Winner Promotion & Snapshot Rollback
# ------------------------------------------------------------------------------
echo "==> [Check 10] V2 Candidate Evaluation, Winner Promotion & Snapshot Rollback (boxlet branch-run --promote-winner + boxlet restore)"
sudo "$BOXLET_BIN" branch-run \
  --root "$STATE_ROOT" \
  --cgroup-parent "$CGROUP_PARENT" \
  --memory 128m \
  --network none \
  --promote-winner \
  --cmd "echo broken-patch > /tmp/failed_attempt.txt && exit 1" \
  --cmd "echo verified-fix > /tmp/winning_patch.txt && echo winner-ok" \
  --json \
  "$BUNDLE_DIR" > "$WORK_DIR/check10-promote.json"

python3 - "$WORK_DIR/check10-promote.json" <<'PY'
import json, sys

with open(sys.argv[1]) as f:
    data = json.load(f)

promoted_id = data.get("promoted_branch_id")
assert isinstance(promoted_id, str) and promoted_id.endswith("-branch-2"), (
    f"expected promoted_branch_id ending with '-branch-2', got {promoted_id!r}"
)
promoted_diff = data.get("promoted_diff", {})
assert "tmp/winning_patch.txt" in promoted_diff.get("added", []), (
    f"expected tmp/winning_patch.txt in promoted_diff.added, got {promoted_diff}"
)
branches = data.get("branches", [])
assert len(branches) == 2, f"expected 2 branches, got {len(branches)}"
assert branches[0]["execution"]["exit_code"] == 1, (
    f"expected branch 0 exit_code 1, got {branches[0]['execution']['exit_code']}"
)
assert branches[1]["execution"]["exit_code"] == 0, (
    f"expected branch 1 exit_code 0, got {branches[1]['execution']['exit_code']}"
)
print(f"    promoted_branch_id={promoted_id}, promoted_diff.added={promoted_diff['added']}")
PY

test -f "$BUNDLE_DIR/rootfs/tmp/winning_patch.txt"
test ! -e "$BUNDLE_DIR/rootfs/tmp/failed_attempt.txt"

sudo "$BOXLET_BIN" restore \
  --snapshot "$WORK_DIR/snapshots/snap-ci-1" \
  --target "$BUNDLE_DIR/rootfs" \
  --json > "$WORK_DIR/check10-restore.json"

test ! -e "$BUNDLE_DIR/rootfs/tmp/winning_patch.txt"

"$BOXLET_BIN" diff \
  --json \
  "$WORK_DIR/snapshots/snap-ci-1" \
  "$BUNDLE_DIR/rootfs" > "$WORK_DIR/check10-post-restore-diff.json"

python3 - "$WORK_DIR/check10-restore.json" "$WORK_DIR/check10-post-restore-diff.json" <<'PY'
import json, sys

with open(sys.argv[1]) as f:
    restore_diff = json.load(f)
with open(sys.argv[2]) as f:
    post_diff = json.load(f)

assert post_diff.get("added") == [], f"expected empty added after restore, got {post_diff}"
assert post_diff.get("modified") == [], f"expected empty modified after restore, got {post_diff}"
assert post_diff.get("deleted") == [], f"expected empty deleted after restore, got {post_diff}"
print(f"    restored cleanly (reverted={restore_diff}, post_restore_diff={post_diff})")
PY

# ------------------------------------------------------------------------------
# Check 11: Zero-Config OCI Bundle Scaffolding (boxlet init-bundle + boxlet run)
# ------------------------------------------------------------------------------
echo "==> [Check 11] Zero-Config OCI Bundle Scaffolding (boxlet init-bundle + boxlet run)"
"$BOXLET_BIN" init-bundle \
  --cmd "echo init-bundle-ok && uname -s" \
  --busybox "$BUSYBOX_SRC" \
  --hostname "boxlet-scaffold" \
  --json \
  "$WORK_DIR/scaffolded-bundle" > "$WORK_DIR/check11-init.json"

sudo "$BOXLET_BIN" run \
  --root "$STATE_ROOT" \
  --cgroup-parent "$CGROUP_PARENT" \
  --id ci-check-11 \
  --memory 64m \
  --network none \
  --json \
  "$WORK_DIR/scaffolded-bundle" > "$WORK_DIR/check11-run.json"

python3 - "$WORK_DIR/check11-init.json" "$WORK_DIR/check11-run.json" <<'PY'
import json, sys

with open(sys.argv[1]) as f:
    init_meta = json.load(f)
with open(sys.argv[2]) as f:
    run_data = json.load(f)

stdout = bytes(run_data["stdout"]).decode("utf-8", errors="replace")
assert run_data["exit_code"] == 0, f"expected exit_code 0, got {run_data['exit_code']}"
assert "init-bundle-ok" in stdout, f"missing init-bundle-ok in stdout: {stdout!r}"
assert run_data["cleanup"]["status"] == "clean", f"expected clean status, got {run_data['cleanup']}"
print(f"    scaffolded bundle={init_meta.get('bundle_dir', 'ok')}, stdout={stdout.strip().replace(chr(10), ' | ')}")
PY
assert_zero_leaks "ci-check-11"

# ------------------------------------------------------------------------------
# Check 12: Structured JSONL Audit Trail (--audit-log)
# ------------------------------------------------------------------------------
echo "==> [Check 12] Structured JSONL Audit Trail (--audit-log)"
sudo "$BOXLET_BIN" --audit-log "$WORK_DIR/audit.jsonl" run \
  --root "$STATE_ROOT" \
  --cgroup-parent "$CGROUP_PARENT" \
  --id ci-check-12 \
  --memory 64m \
  --network none \
  --json \
  "$WORK_DIR/scaffolded-bundle" > "$WORK_DIR/check12-run.json"

sudo "$BOXLET_BIN" --audit-log "$WORK_DIR/audit.jsonl" branch-run \
  --root "$STATE_ROOT" \
  --cgroup-parent "$CGROUP_PARENT" \
  --memory 64m \
  --network none \
  --cmd "echo audit-branch-1" \
  --json \
  "$WORK_DIR/scaffolded-bundle" > "$WORK_DIR/check12-branch.json"

sudo python3 - "$WORK_DIR/audit.jsonl" <<'PY'
import json, os, sys

path = sys.argv[1]
assert os.path.exists(path), f"expected audit log at {path}"
mode = os.stat(path).st_mode & 0o777
assert mode == 0o600, f"expected 0o600 permissions on audit log, got {oct(mode)}"

with open(path) as f:
    lines = [json.loads(line) for line in f if line.strip()]

assert len(lines) == 2, f"expected 2 JSONL audit records, got {len(lines)}: {lines}"
assert lines[0].get("event") == "container_run_completed", f"unexpected event[0]: {lines[0]}"
assert lines[0].get("container_id") == "ci-check-12", f"unexpected container_id[0]: {lines[0]}"
assert lines[1].get("event") == "branch_batch_completed", f"unexpected event[1]: {lines[1]}"
assert lines[1].get("branch_count") == 1, f"unexpected branch_count[1]: {lines[1]}"
print(f"    audit.jsonl verified: mode={oct(mode)}, events={[r['event'] for r in lines]}")
PY
assert_zero_leaks "ci-check-12"

# ------------------------------------------------------------------------------
# Check 13: Container Inventory & Garbage Collection (boxlet list + boxlet prune)
# ------------------------------------------------------------------------------
echo "==> [Check 13] Container Inventory & Garbage Collection (boxlet list + boxlet prune)"
write_bundle_config "sleep 30"
sudo "$BOXLET_BIN" create --root "$STATE_ROOT" --cgroup-parent "$CGROUP_PARENT" --bundle "$BUNDLE_DIR" ci-list-1
sudo "$BOXLET_BIN" create --root "$STATE_ROOT" --cgroup-parent "$CGROUP_PARENT" --bundle "$BUNDLE_DIR" ci-list-2

sudo "$BOXLET_BIN" list --root "$STATE_ROOT" --cgroup-parent "$CGROUP_PARENT" --json > "$WORK_DIR/check13-list.json"
python3 - "$WORK_DIR/check13-list.json" <<'PY'
import json, sys

with open(sys.argv[1]) as f:
    data = json.load(f)

assert [c["id"] for c in data] == ["ci-list-1", "ci-list-2"], f"unexpected container ids: {data}"
assert all(c["status"] == "created" for c in data), f"expected status=='created' for all: {data}"
print(f"    list verified: {[ (c['id'], c['status']) for c in data ]}")
PY

sudo "$BOXLET_BIN" start --root "$STATE_ROOT" --cgroup-parent "$CGROUP_PARENT" ci-list-1
sudo "$BOXLET_BIN" kill --root "$STATE_ROOT" --cgroup-parent "$CGROUP_PARENT" ci-list-1 SIGKILL
for _ in {1..20}; do
  if sudo "$BOXLET_BIN" state --root "$STATE_ROOT" --cgroup-parent "$CGROUP_PARENT" ci-list-1 | grep -q '"status": "stopped"'; then
    break
  fi
  sleep 0.1
done

sudo "$BOXLET_BIN" --audit-log "$WORK_DIR/audit.jsonl" prune --root "$STATE_ROOT" --cgroup-parent "$CGROUP_PARENT" --json > "$WORK_DIR/check13-prune1.json"
python3 - "$WORK_DIR/check13-prune1.json" <<'PY'
import json, sys

with open(sys.argv[1]) as f:
    data = json.load(f)

assert data["removed_containers"] == ["ci-list-1"], f"expected removed_containers==['ci-list-1'], got {data}"
assert data["skipped_active_containers"] == ["ci-list-2"], f"expected skipped_active_containers==['ci-list-2'], got {data}"
print(f"    prune (stopped only) verified: removed={data['removed_containers']}, skipped={data['skipped_active_containers']}")
PY

sudo "$BOXLET_BIN" --audit-log "$WORK_DIR/audit.jsonl" prune --root "$STATE_ROOT" --cgroup-parent "$CGROUP_PARENT" --force --json > "$WORK_DIR/check13-prune2.json"
python3 - "$WORK_DIR/check13-prune2.json" <<'PY'
import json, sys

with open(sys.argv[1]) as f:
    data = json.load(f)

assert data["removed_containers"] == ["ci-list-2"], f"expected removed_containers==['ci-list-2'], got {data}"
print(f"    prune (--force) verified: removed={data['removed_containers']}")
PY
assert_zero_leaks "ci-list-1"
assert_zero_leaks "ci-list-2"

# ------------------------------------------------------------------------------
# Check 14: Audit Log Telemetry Summary & Integrity Verification (boxlet audit --file)
# ------------------------------------------------------------------------------
echo "==> [Check 14] Audit Log Telemetry Summary & Integrity Verification (boxlet audit --file)"
sudo "$BOXLET_BIN" audit --file "$WORK_DIR/audit.jsonl" --json > "$WORK_DIR/check14-audit.json"
python3 - "$WORK_DIR/check14-audit.json" <<'PY'
import json, sys

with open(sys.argv[1]) as f:
    data = json.load(f)

assert data["total_records"] == 4, f"expected total_records==4, got {data}"
assert data["runs_completed"] == 1 and data["runs_succeeded"] == 1, f"expected runs_completed==1 and runs_succeeded==1, got {data}"
assert data["branch_batches_completed"] == 1 and data["total_branches_evaluated"] == 1, (
    f"expected branch_batches_completed==1 and total_branches_evaluated==1, got {data}"
)
assert data["chronological_valid"] is True, f"expected chronological_valid is True, got {data}"
print(
    f"    audit summary verified: total_records={data['total_records']}, "
    f"runs_completed={data['runs_completed']}, branch_batches={data['branch_batches_completed']}, "
    f"chronological_valid={data['chronological_valid']}"
)
PY

# ------------------------------------------------------------------------------
# Check 15: Host Environment & Kernel Readiness Diagnostics (boxlet doctor --json)
# ------------------------------------------------------------------------------
echo "==> [Check 15] Host Environment & Kernel Readiness Diagnostics (boxlet doctor --json)"
sudo "$BOXLET_BIN" doctor --root "$STATE_ROOT" --cgroup-parent "$CGROUP_PARENT" --json > "$WORK_DIR/check15-doctor.json"
python3 - "$WORK_DIR/check15-doctor.json" <<'PY'
import json, sys

with open(sys.argv[1]) as f:
    data = json.load(f)

assert data["overall_ready"] is True, f"expected overall_ready is True, got {data}"
assert data["host_os"] == "linux", f"expected host_os=='linux', got {data}"
expected_checks = ["host_os", "kernel_version", "root_privileges", "cgroup_v2", "seccomp_arch"]
by_name = {c["name"]: c for c in data.get("checks", [])}
for name in expected_checks:
    assert name in by_name, f"missing doctor check {name!r} in {data}"
    assert by_name[name]["status"] == "pass", f"expected check {name!r} status=='pass', got {by_name[name]}"
print(
    f"    doctor verified: overall_ready={data['overall_ready']}, "
    f"host_os={data['host_os']}, checks={[c['name'] + ':' + c['status'] for c in data['checks']]}"
)
PY

# ------------------------------------------------------------------------------
# Check 16: Declarative Multi-Agent Rubric Evaluation & Guardrails (boxlet eval --spec ... --promote-winner --json)
# ------------------------------------------------------------------------------
echo "==> [Check 16] Declarative Multi-Agent Rubric Evaluation & Guardrails (boxlet eval --spec ... --promote-winner --json)"
cat > "$WORK_DIR/eval-spec.json" <<'EOF'
{
  "policy": {
    "memory_bytes": 67108864,
    "network": "none"
  },
  "rubric": {
    "require_exit_zero": true,
    "required_stdout_contains": ["EVAL_PASS"],
    "required_added_paths": ["tmp/eval_solution.txt"],
    "forbidden_modified_paths": ["etc/hostname"]
  },
  "candidates": [
    {
      "id": "eval-cand-tamper",
      "args": ["/bin/sh", "-c", "echo tampered > /etc/hostname && echo solution > /tmp/eval_solution.txt && echo EVAL_PASS"]
    },
    {
      "id": "eval-cand-fail",
      "args": ["/bin/sh", "-c", "echo solution > /tmp/eval_solution.txt && exit 1"]
    },
    {
      "id": "eval-cand-clean",
      "args": ["/bin/sh", "-c", "echo clean-solution > /tmp/eval_solution.txt && echo EVAL_PASS"]
    }
  ],
  "promote_winner": true
}
EOF

sudo "$BOXLET_BIN" eval \
  --root "$STATE_ROOT" \
  --cgroup-parent "$CGROUP_PARENT" \
  --spec "$WORK_DIR/eval-spec.json" \
  --promote-winner \
  --json \
  "$WORK_DIR/scaffolded-bundle" > "$WORK_DIR/check16-eval.json"

python3 - "$WORK_DIR/check16-eval.json" <<'PY'
import json, sys

with open(sys.argv[1]) as f:
    data = json.load(f)

verdicts = data.get("verdicts", [])
assert len(verdicts) == 3, f"expected 3 candidate verdicts, got {len(verdicts)}: {data}"
assert verdicts[0]["passed_rubric"] is False, f"expected verdicts[0] (tamper) passed_rubric is False, got {verdicts[0]}"
assert verdicts[1]["passed_rubric"] is False, f"expected verdicts[1] (fail) passed_rubric is False, got {verdicts[1]}"
assert verdicts[2]["passed_rubric"] is True, f"expected verdicts[2] (clean) passed_rubric is True, got {verdicts[2]}"
assert data.get("winning_branch_id") == "eval-cand-clean", f"expected winning_branch_id=='eval-cand-clean', got {data}"
assert data.get("promoted") is True, f"expected promoted is True, got {data}"
print(
    f"    eval verified: winning_branch_id={data['winning_branch_id']}, promoted={data['promoted']}, "
    f"scores={[(v['branch_id'], v['passed_rubric'], v['score']) for v in verdicts]}"
)
PY

test -f "$WORK_DIR/scaffolded-bundle/rootfs/tmp/eval_solution.txt"
grep -q "boxlet-scaffold" "$WORK_DIR/scaffolded-bundle/rootfs/etc/hostname"
assert_zero_leaks "eval-cand-tamper"
assert_zero_leaks "eval-cand-fail"
assert_zero_leaks "eval-cand-clean"

echo "==> All 16 Boxlet V1–V4 end-to-end checks passed with zero leaked cgroups or state directories!"
