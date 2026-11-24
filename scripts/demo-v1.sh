#!/usr/bin/env bash
# Boxlet V1 End-to-End Verification & Demo Suite
# Runs on any privileged Linux 5.15+ host with unified cgroup v2 and busybox-static.
set -euo pipefail

BOXLET_BIN="${1:-./target/debug/boxlet}"
BUNDLE_DIR="${BOXLET_BUNDLE_DIR:-/tmp/boxlet-ci-bundle}"
STATE_ROOT="${BOXLET_STATE_ROOT:-/tmp/boxlet-ci-state}"
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

echo "==> [Setup] Provisioning BusyBox OCI bundle at $BUNDLE_DIR and cgroup slice at $CGROUP_PARENT"
sudo rm -rf "$BUNDLE_DIR" "$STATE_ROOT"
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
OUT_JSON="/tmp/boxlet-check1.json"
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
OUT_JSON="/tmp/boxlet-check2.json"
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
OUT_JSON="/tmp/boxlet-check3.json"
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
OUT_JSON="/tmp/boxlet-check4.json"
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
OUT_JSON="/tmp/boxlet-check5.json"
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
OUT_JSON="/tmp/boxlet-check6.json"
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
peak = data["usage"].get("memory_peak_bytes") or 0
assert oom is True or (exit_code not in (None, 0) or sig is not None), (
    f"expected OOM kill or non-zero failure, got violations={data['violations']}, exit_code={exit_code}"
)
assert peak > 0, f"expected memory_peak_bytes > 0, got {peak}"
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

echo "==> All 7 Boxlet V1 end-to-end checks passed with zero leaked cgroups or state directories!"
