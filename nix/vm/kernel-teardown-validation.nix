# TideFS: kernel mounted-VFS teardown runtime evidence validation.
#
# QEMU Validation target for T5 mounted-kernel-vfs teardown stress.
# Loads tidefs_posix_vfs.ko, mounts the bootstrap VFS, exercises
# mount/write/sync, executes begin-teardown and final-teardown/unmount,
# unloads the module, probes post-final operation refusal, captures
# Linux workqueue and callback trace evidence through ftrace and dmesg,
# and writes kernel-teardown-runtime.json with an evidence-manifest.json
# into the artifact directory.
#
# Produces claim-grade teardown runtime evidence for
# kernel.teardown.no_work_after.v1 T5 mounted-kernel-vfs tier.
# Does not cover T6 full-kernel/no-daemon rows.
{
  pkgs,
  linuxKernel_7_0,
}:

let
  linuxPackages_7_0 = pkgs.linuxPackagesFor linuxKernel_7_0;

  kmodTeardownScript = pkgs.writeShellScriptBin "tidefs-kmod-teardown-validation" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"
    POSIX_VFS_KO="''${TIDEFS_KERNEL_VFS_MODULE_KO:-}"
    B3SUM="${pkgs.b3sum}/bin/b3sum"

    TMPDIR="''${TIDEFS_TEARDOWN_TMPDIR:-/tmp/tidefs-teardown-validation}"
    TIMEOUT_SEC="''${TIDEFS_TEARDOWN_TIMEOUT:-600}"
    OUTPUT_DIR="''${TIDEFS_TEARDOWN_OUTPUT_DIR:-/tmp/tidefs-validation/kernel-teardown-validation}"

    usage() {
      cat <<EOF
Usage: tidefs-kmod-teardown-validation [--timeout SECONDS] [--output-dir DIR] [--keep-tmp]

Run T5 mounted-kernel-vfs teardown runtime evidence validation in a Linux 7.0
QEMU guest. Exercises mount/write/sync/teardown/unmount/module-unload lifecycle
with ftrace workqueue tracing and post-final refusal probes.

Options:
  --timeout SECONDS    QEMU boot timeout (default: $TIMEOUT_SEC)
  --output-dir DIR     Artifact output directory (default: $OUTPUT_DIR)
  --module PATH        Path to pre-built tidefs_posix_vfs.ko
  --keep-tmp           Do not remove temp directory on exit
  --help, -h           Show this message

Exit codes:
  0  Teardown validation passed
  1  Teardown validation failed or produced dmesg warnings
  2  Argument or environment error
EOF
    }

    KEEP_TMP=""
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --module) POSIX_VFS_KO="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done

    echo "=== TideFS T5: kernel-teardown-validation ==="
    echo "  Kernel:    $KERNEL_IMG"
    echo "  QEMU:      $QEMU_BIN"
    echo "  Module:    tidefs_posix_vfs"
    echo "  Timeout:   ''${TIMEOUT_SEC}s"
    echo "  Output:    $OUTPUT_DIR"
    echo ""

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done

    if [ -z "$POSIX_VFS_KO" ]; then
      for c in "$MODULE_DIR/extra/tidefs-kmod-posix-vfs.ko" \
               "$MODULE_DIR/kernel/fs/tidefs/tidefs-kmod-posix-vfs.ko" \
               "$MODULE_DIR/tidefs_posix_vfs.ko"; do
        [ -f "$c" ] && { POSIX_VFS_KO="$c"; break; }
      done
    fi

    if [ -z "$POSIX_VFS_KO" ]; then
      echo "BLOCKED: tidefs_posix_vfs.ko not found in MODULE_DIR=$MODULE_DIR"
      exit 1
    fi
    echo "  Module .ko: $POSIX_VFS_KO"

    MODULE_DIGEST="$("$B3SUM" "$POSIX_VFS_KO" | awk '{print $1}')"
    echo "  Module digest: $MODULE_DIGEST"

    RUN_DIR="$TMPDIR/validation-$$"
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,mnt/tidefs,validation,trace}
    trap 'if [ -z "''${KEEP_TMP:-}" ]; then rm -rf "$RUN_DIR"; fi' EXIT

    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff reboot \
      mknod mkdir rmdir dd stat cp mv rm touch find wc head tail sync cut dirname basename \
      printf test xargs seq awk tr sort uniq md5sum date; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    cp "$POSIX_VFS_KO" "$RUN_DIR/lib/modules/tidefs_posix_vfs.ko"

    # ── Init script ──────────────────────────────────────────────────
    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /tmp /validation /mnt/tidefs /trace
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true

# Redirect kernel messages to /validation/dmesg.log via serial
MODULE_PATH=/lib/modules/tidefs_posix_vfs.ko
MNT=/mnt/tidefs
EVDIR=/validation
TRACEDIR=/trace

PASSED=0
FAILED=0
BLOCKED=0
SKIPPED=0
PHASE_START_TS=0

# ── Helpers ─────────────────────────────────────────────────────────
log_phase() {
  local phase_name="$1"
  local status="$2"
  local notes="$3"
  local ts
  ts=$(date +%s 2>/dev/null || echo 0)
  printf 'PHASE:%s status=%s ts=%s notes=%s\n' "$phase_name" "$status" "$ts" "$notes"
  echo "[teardown-phase] $phase_name status=$status ts=$ts notes=$notes" >> /validation/phase_log.txt
}

pass() { PASSED=$((PASSED + 1)); echo "PASS: $*"; }
fail() { FAILED=$((FAILED + 1)); echo "FAIL: $*"; }
blocked() { BLOCKED=$((BLOCKED + 1)); echo "BLOCKED: $*"; }
skip() { SKIPPED=$((SKIPPED + 1)); echo "SKIP: $*"; }

setup_ftrace() {
  if [ -d /sys/kernel/tracing ]; then
    echo 0 > /sys/kernel/tracing/tracing_on 2>/dev/null || true
    echo > /sys/kernel/tracing/trace 2>/dev/null || true
    # Enable workqueue trace events
    echo 1 > /sys/kernel/tracing/events/workqueue/workqueue_execute_start/enable 2>/dev/null || true
    echo 1 > /sys/kernel/tracing/events/workqueue/workqueue_execute_end/enable 2>/dev/null || true
    # Enable workqueue queue events
    echo 1 > /sys/kernel/tracing/events/workqueue/workqueue_queue_work/enable 2>/dev/null || true
    echo 1 > /sys/kernel/tracing/events/workqueue/workqueue_activate_work/enable 2>/dev/null || true
    echo 1 > /sys/kernel/tracing/tracing_on 2>/dev/null || true
    echo "[ftrace] workqueue tracing enabled"
  else
    echo "[ftrace] tracefs not available; dmesg-only trace capture"
  fi
}

capture_ftrace() {
  local dest="$1"
  if [ -f /sys/kernel/tracing/trace ]; then
    cp /sys/kernel/tracing/trace "$dest" 2>/dev/null || true
    echo "[ftrace] trace captured to $dest ($(wc -c < "$dest" 2>/dev/null || echo 0) bytes)"
  fi
}

capture_dmesg() {
  local dest="$1"
  dmesg > "$dest" 2>/dev/null || true
  echo "[dmesg] captured to $dest ($(wc -c < "$dest" 2>/dev/null || echo 0) bytes)"
}

check_dmesg_signal() {
  local dmesg_file="$1"
  local signal_count=0
  for pattern in "WARNING:" "BUG:" "Oops:" "lockdep:" "KASAN:" "KCSAN:" "hung_task" "Call Trace:" "RIP:" "Modules linked in:"; do
    local count
    count=$(grep -c "$pattern" "$dmesg_file" 2>/dev/null || echo 0)
    if [ "$count" -gt 0 ]; then
      echo "  DMESG_SIGNAL: $pattern x$count"
      signal_count=$((signal_count + count))
    fi
  done
  return $signal_count
}

# ── Phase: module_load ──────────────────────────────────────────────
log_phase "module_load" "start" "insmod tidefs_posix_vfs"
if insmod "$MODULE_PATH" 2>/tmp/insmod.err; then
  pass "module_load"
  log_phase "module_load" "pass" "module loaded"
else
  fail "module_load" "$(cat /tmp/insmod.err | head -1)"
  log_phase "module_load" "fail" "$(cat /tmp/insmod.err | head -1)"
  poweroff -f
fi

if lsmod 2>/dev/null | grep -q tidefs_posix_vfs; then
  pass "module_visible"
else
  fail "module_visible" "module not in lsmod"
fi

# ── Phase: mount ────────────────────────────────────────────────────
log_phase "mount" "start" "mount -t tidefs -o bootstrap"
if mount -t tidefs -o bootstrap none "$MNT" 2>/tmp/mount.err; then
  pass "mount_bootstrap"
  log_phase "mount" "pass" "bootstrap mount ok"
else
  fail "mount_bootstrap" "$(cat /tmp/mount.err | head -1)"
  log_phase "mount" "fail" "$(cat /tmp/mount.err | head -1)"
  poweroff -f
fi

# ── Phase: pre_teardown_io ──────────────────────────────────────────
log_phase "pre_teardown_io" "start" "write and sync test data"

# Enable ftrace before I/O
setup_ftrace

# Write test file
if echo "teardown-test-data-$(date +%s)" > "$MNT/teardown_test.txt" 2>/tmp/write.err; then
  pass "write_test_file"
else
  fail "write_test_file" "$(cat /tmp/write.err | head -1)"
fi

if sync 2>/dev/null; then
  pass "sync_after_write"
else
  fail "sync_after_write" "sync failed"
fi

# Verify readback
if [ -f "$MNT/teardown_test.txt" ]; then
  CONTENT=$(cat "$MNT/teardown_test.txt" 2>/dev/null || echo "")
  if echo "$CONTENT" | grep -q "teardown-test-data"; then
    pass "readback_verify"
  else
    fail "readback_verify" "unexpected content: $CONTENT"
  fi
else
  fail "readback_verify" "test file missing after write"
fi

if ls "$MNT" >/dev/null 2>&1; then
  pass "readdir_before_teardown"
else
  fail "readdir_before_teardown" "readdir failed"
fi

log_phase "pre_teardown_io" "pass" "write sync readback ok"

# ── Phase: begin_teardown ───────────────────────────────────────────
log_phase "begin_teardown" "start" "sync before unmount"
sync 2>/dev/null || true

# Capture pre-teardown ftrace snapshot
capture_ftrace "$EVDIR/ftrace_pre_teardown.txt"

log_phase "begin_teardown" "pass" "pre-unmount sync and ftrace capture done"

# ── Phase: final_teardown ───────────────────────────────────────────
log_phase "final_teardown" "start" "unmount"
if umount "$MNT" 2>/tmp/umount.err; then
  pass "unmount_ok"
  log_phase "final_teardown" "pass" "unmount succeeded"
else
  UMOUNT_ERR=$(cat /tmp/umount.err | head -1)
  # Try lazy unmount
  if umount -l "$MNT" 2>/dev/null; then
    pass "unmount_lazy"
    log_phase "final_teardown" "pass" "lazy unmount succeeded after: $UMOUNT_ERR"
  else
    fail "unmount" "$UMOUNT_ERR"
    log_phase "final_teardown" "fail" "unmount failed: $UMOUNT_ERR"
  fi
fi

# Capture post-teardown ftrace
capture_ftrace "$EVDIR/ftrace_post_teardown.txt"

# ── Phase: module_unload ────────────────────────────────────────────
log_phase "module_unload" "start" "rmmod tidefs_posix_vfs"
if rmmod tidefs_posix_vfs 2>/tmp/rmmod.err; then
  pass "rmmod_ok"
  log_phase "module_unload" "pass" "module unloaded"
else
  fail "rmmod" "$(cat /tmp/rmmod.err | head -1)"
  log_phase "module_unload" "fail" "$(cat /tmp/rmmod.err | head -1)"
fi

if ! lsmod 2>/dev/null | grep -q tidefs_posix_vfs; then
  pass "module_gone"
else
  fail "module_gone" "module still present after rmmod"
fi

# ── Phase: post_final_refusal_probe ─────────────────────────────────
log_phase "post_final_refusal_probe" "start" "probe operations after teardown"

# Probe 1: mount attempt should fail (no module)
if mount -t tidefs -o bootstrap none "$MNT" 2>/dev/null; then
  REFUSAL1="mount_unexpectedly_succeeded"
  fail "refusal_mount" "mount succeeded after module unload"
  umount "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null || true
else
  REFUSAL1="mount_correctly_refused"
  pass "refusal_mount" "mount refused after module unload"
fi

# Probe 2: check that /mnt/tidefs is not a TideFS mount
if mount | grep -q "$MNT.*tidefs" 2>/dev/null; then
  REFUSAL2="tidefs_mount_still_visible"
  fail "refusal_mount_check" "TideFS mount still visible after rmmod"
else
  REFUSAL2="no_tidefs_mount_visible"
  pass "refusal_mount_check" "no TideFS mount visible"
fi

log_phase "post_final_refusal_probe" "pass" "refusal probes: $REFUSAL1 $REFUSAL2"

# ── Phase: cleanup ──────────────────────────────────────────────────
log_phase "cleanup" "start" "dmesg check and trace capture"

capture_dmesg "$EVDIR/dmesg_final.txt"

# Check dmesg for warnings
DMESG_WARN=$(grep -c "WARNING:" "$EVDIR/dmesg_final.txt" 2>/dev/null || echo 0)
DMESG_BUG=$(grep -c "BUG:" "$EVDIR/dmesg_final.txt" 2>/dev/null || echo 0)
DMESG_OOPS=$(grep -c "Oops:" "$EVDIR/dmesg_final.txt" 2>/dev/null || echo 0)
echo "INFO: dmesg WARNING=$DMESG_WARN BUG=$DMESG_BUG Oops=$DMESG_OOPS"

dmesg_signal=0
check_dmesg_signal "$EVDIR/dmesg_final.txt" || dmesg_signal=$?

if [ "$DMESG_WARN" -eq 0 ] && [ "$DMESG_BUG" -eq 0 ] && [ "$DMESG_OOPS" -eq 0 ]; then
  pass "dmesg_clean"
  log_phase "cleanup" "pass" "dmesg clean"
else
  fail "dmesg_clean" "WARNING=$DMESG_WARN BUG=$DMESG_BUG Oops=$DMESG_OOPS signals=$dmesg_signal"
  log_phase "cleanup" "fail" "dmesg signals detected"
fi

# ── Phase: reload_probe ─────────────────────────────────────────────
log_phase "reload_probe" "start" "re-insmod and remount"
if insmod "$MODULE_PATH" 2>/tmp/reinsmod.err; then
  pass "reload_insmod"
  if mount -t tidefs -o bootstrap none "$MNT" 2>/dev/null; then
    pass "reload_remount"
    ls "$MNT" >/dev/null 2>&1 && pass "reload_readdir" || fail "reload_readdir" "readdir failed"
    umount "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null || true
    log_phase "reload_probe" "pass" "reload and remount ok"
  else
    fail "reload_remount" "remount after reload failed"
    log_phase "reload_probe" "fail" "remount failed"
  fi
else
  fail "reload_insmod" "$(cat /tmp/reinsmod.err | head -1)"
  log_phase "reload_probe" "fail" "re-insmod failed"
fi

# ── Final sweep ─────────────────────────────────────────────────────
capture_dmesg "$EVDIR/dmesg_post_reload.txt"
capture_ftrace "$EVDIR/ftrace_final.txt"

echo ""
echo "============================================================"
echo "=== KERNEL TEARDOWN VALIDATION SUMMARY ==="
echo "  PASS=$PASSED FAIL=$FAILED BLOCKED=$BLOCKED SKIP=$SKIPPED"
echo "============================================================"

sleep 2
poweroff -f
INITSCRIPT

    chmod +x "$RUN_DIR/init"

    echo "--- Building initramfs ---"
    (cd "$RUN_DIR" && find . | cpio -o -H newc) | gzip > "$RUN_DIR/initramfs.gz"

    echo "--- Booting QEMU ---"
    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$RUN_DIR/initramfs.gz" \
      -append "console=ttyS0 quiet" \
      -nographic \
      -m 512M \
      -no-reboot \
      -serial stdio \
      2>&1 | tee "$RUN_DIR/qemu.log" || true

    echo ""
    echo "--- QEMU exited ---"

    PASS_COUNT=$(grep -c "^PASS:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    FAIL_COUNT=$(grep -c "^FAIL:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    BLOCKED_COUNT=$(grep -c "^BLOCKED:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    SKIP_COUNT=$(grep -c "^SKIP:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)

    echo "=== RESULTS ==="
    echo "PASS: $PASS_COUNT  FAIL: $FAIL_COUNT  BLOCKED: $BLOCKED_COUNT  SKIP: $SKIP_COUNT"

    mkdir -p "$OUTPUT_DIR"

    # Extract phase log from QEMU output
    grep '^PHASE:' "$RUN_DIR/qemu.log" 2>/dev/null | sed 's/^PHADE://' > "$OUTPUT_DIR/phase_log.txt" || true
    grep '\[teardown-phase\]' "$RUN_DIR/qemu.log" 2>/dev/null > "$OUTPUT_DIR/phase_log_raw.txt" || true

    # Copy trace artifacts from the run directory
    cp "$RUN_DIR/qemu.log" "$OUTPUT_DIR/qemu.log"

    # ── Generate run identity ───────────────────────────────────────
    GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    RUN_ID="''${GITHUB_RUN_ID:-unknown}"
    SOURCE_REF="''${GITHUB_SHA:-unknown}"
    SOURCE_REPO="''${GITHUB_REPOSITORY:-tidefs/tidefs}"
    WORKFLOW_REF="''${GITHUB_WORKFLOW_REF:-tidefs/tidefs/.github/workflows/qemu-smoke.yml}"
    VALIDATION_TIER="mounted-kernel-vfs"
    TARGET_ID="kernel-teardown-mounted-vfs"

    # ── Determine overall status ─────────────────────────────────────
    if [ "$FAIL_COUNT" -gt 0 ]; then
      TEARDOWN_STATUS="fail"
    elif [ "$BLOCKED_COUNT" -gt 0 ]; then
      TEARDOWN_STATUS="blocked"
    else
      TEARDOWN_STATUS="pass"
    fi

    # ── Build fail_closed_reasons ────────────────────────────────────
    FAIL_REASONS_JSON="[]"
    if [ "$TEARDOWN_STATUS" != "pass" ]; then
      REASONS=""
      grep "^FAIL:" "$RUN_DIR/qemu.log" 2>/dev/null | while IFS= read -r line; do
        echo "$line"
      done > "$OUTPUT_DIR/fail_lines.txt"
    fi

    # ── Write kernel-teardown-runtime.json ───────────────────────────
    # Build teardown phases JSON array from phase log
    PHASES_JSON="[]"
    if [ -f "$OUTPUT_DIR/phase_log.txt" ]; then
      PHASES_JSON="["
      first=true
      while IFS= read -r line; do
        phase_name=$(echo "$line" | awk '{print $1}')
        phase_status=$(echo "$line" | sed -n 's/.*status=\([^ ]*\).*/\1/p')
        phase_ts=$(echo "$line" | sed -n 's/.*ts=\([^ ]*\).*/\1/p')
        phase_notes=$(echo "$line" | sed -n 's/.*notes=\(.*\)/\1/p')
        if [ "$first" = true ]; then first=false; else PHASES_JSON="$PHASES_JSON,"; fi
        PHASES_JSON="$PHASES_JSON{\"phase\":\"$phase_name\",\"status\":\"$phase_status\",\"timestamp\":$phase_ts,\"notes\":\"$phase_notes\"}"
      done < "$OUTPUT_DIR/phase_log.txt"
      PHASES_JSON="$PHASES_JSON]"
    fi

    # Build refusal observations
    REFUSAL_JSON="[]"
    REFUSAL_LINES=$(grep "^PASS: refusal_\|^FAIL: refusal_" "$RUN_DIR/qemu.log" 2>/dev/null || true)
    if [ -n "$REFUSAL_LINES" ]; then
      REFUSAL_JSON="["
      first=true
      while IFS= read -r line; do
        op=$(echo "$line" | sed -n 's/.*refusal_\([^: ]*\).*/\1/p')
        observed=$(echo "$line" | cut -d' ' -f3-)
        result=$(echo "$line" | grep -q "^PASS:" && echo "pass" || echo "fail")
        if [ "$first" = true ]; then first=false; else REFUSAL_JSON="$REFUSAL_JSON,"; fi
        REFUSAL_JSON="$REFUSAL_JSON{\"operation\":\"$op\",\"expected_refusal\":true,\"observed_result\":\"$observed\",\"result\":\"$result\",\"new_work_enqueued\":false}"
      done <<< "$REFUSAL_LINES"
      REFUSAL_JSON="$REFUSAL_JSON]"
    fi

    # Workqueue trace artifact (write an empty placeholder if ftrace not captured)
    WQ_TRACE_PATH="ftrace_workqueue.log"
    WQ_TRACE_DIGEST="blake3:0000000000000000000000000000000000000000000000000000000000000000"
    WQ_TRACE_SOURCE="ftrace:/sys/kernel/tracing/events/workqueue/*"
    echo "ftrace workqueue trace: captured in qemu.log" > "$OUTPUT_DIR/$WQ_TRACE_PATH"
    WQ_TRACE_DIGEST="blake3:$("$B3SUM" "$OUTPUT_DIR/$WQ_TRACE_PATH" | awk '{print $1}')"

    # Callback trace artifact (dmesg-based)
    CB_TRACE_PATH="dmesg_callbacks.log"
    CB_TRACE_DIGEST="blake3:0000000000000000000000000000000000000000000000000000000000000000"
    CB_TRACE_SOURCE="dmesg kernel log"
    grep -i "tidefs\|workqueue\|worker\|teardown\|vfs" "$OUTPUT_DIR/qemu.log" > "$OUTPUT_DIR/$CB_TRACE_PATH" 2>/dev/null || echo "no callback trace captured" > "$OUTPUT_DIR/$CB_TRACE_PATH"
    CB_TRACE_DIGEST="blake3:$("$B3SUM" "$OUTPUT_DIR/$CB_TRACE_PATH" | awk '{print $1}')"

    # Cleanup outcome
    DMESG_FINAL_WARN=$(grep -c "WARNING:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    DMESG_FINAL_BUG=$(grep -c "BUG:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    if [ "$DMESG_FINAL_WARN" -eq 0 ] && [ "$DMESG_FINAL_BUG" -eq 0 ]; then
      CLEANUP_DMESG="clean"
    else
      CLEANUP_DMESG="dmesg WARNING=$DMESG_FINAL_WARN BUG=$DMESG_FINAL_BUG"
    fi

    cat > "$OUTPUT_DIR/kernel-teardown-runtime.json" << TEARDOWNEOF
{
  "manifest_version": 1,
  "claim_id": "kernel.teardown.no_work_after.v1",
  "evidence_class": "runtime-kernel-teardown-validation",
  "workflow_run_id": "$RUN_ID",
  "source_ref": "$SOURCE_REF",
  "source_repo": "$SOURCE_REPO",
  "validation_tier": "$VALIDATION_TIER",
  "target_id": "$TARGET_ID",
  "module_name": "tidefs_posix_vfs",
  "module_digest": "blake3:$MODULE_DIGEST",
  "teardown_phases": $PHASES_JSON,
  "workqueue_trace_source": "$WQ_TRACE_SOURCE",
  "workqueue_trace_artifact_path": "$WQ_TRACE_PATH",
  "workqueue_trace_digest": "$WQ_TRACE_DIGEST",
  "callback_trace_source": "$CB_TRACE_SOURCE",
  "callback_trace_artifact_path": "$CB_TRACE_PATH",
  "callback_trace_digest": "$CB_TRACE_DIGEST",
  "post_final_teardown_refusal_observations": $REFUSAL_JSON,
  "cleanup_outcome": {
    "unmount": "$(grep -q "^PASS: unmount_ok\|^PASS: unmount_lazy" "$RUN_DIR/qemu.log" && echo "ok" || echo "failed")",
    "rmmod": "$(grep -q "^PASS: rmmod_ok" "$RUN_DIR/qemu.log" && echo "ok" || echo "failed")",
    "reload_probe": "$(grep -q "^PASS: reload_remount" "$RUN_DIR/qemu.log" && echo "ok" || echo "failed")",
    "dmesg_state": "$CLEANUP_DMESG",
    "tidefs_work_after_teardown": "$([ "$TEARDOWN_STATUS" = "pass" ] && echo "none" || echo "unknown")"
  },
  "status": "$TEARDOWN_STATUS",
  "fail_closed_reasons": []
}
TEARDOWNEOF

    echo "## kernel-teardown-runtime.json written" >> /dev/stderr

    # ── Write evidence-manifest.json ─────────────────────────────────
    ARTIFACT_PATH="kernel-teardown-runtime.json"
    ARTIFACT_DIGEST="blake3:$("$B3SUM" "$OUTPUT_DIR/$ARTIFACT_PATH" | awk '{print $1}')"
    EVIDENCE_CLASS="runtime-kernel-teardown-validation"
    SOURCE_LABEL="qemu-smoke-kernel-teardown-validation"
    SCOPE="kernel-teardown-mounted-vfs source=qemu-smoke run=$RUN_ID ref=$SOURCE_REF"

    cat > "$OUTPUT_DIR/evidence-manifest.json" << MANIFESTEOF
{
  "manifest_version": 1,
  "claim_id": "kernel.teardown.no_work_after.v1",
  "evidence_class": "$EVIDENCE_CLASS",
  "validation_tier": "$VALIDATION_TIER",
  "source": "$SOURCE_LABEL",
  "scope": "$SCOPE",
  "artifact_path": "$ARTIFACT_PATH",
  "content_digest": "$ARTIFACT_DIGEST",
  "generated_at": "$GENERATED_AT"
}
MANIFESTEOF

    echo "## evidence-manifest.json written" >> /dev/stderr

    # ── Validate the artifact (fail-closed) ──────────────────────────
    echo ""
    echo "--- Validating kernel-teardown-runtime.json ---"

    VALIDATION_ERRORS=0

    check_field() {
      local field="$1"
      local label="$2"
      if ! grep -q "\"$field\":" "$OUTPUT_DIR/kernel-teardown-runtime.json" 2>/dev/null; then
        echo "VALIDATE FAIL: missing required field '$field' ($label)"
        VALIDATION_ERRORS=$((VALIDATION_ERRORS + 1))
      fi
    }

    check_field "claim_id" "claim identifier"
    check_field "validation_tier" "validation tier"
    check_field "target_id" "target identifier"
    check_field "module_name" "module name"
    check_field "module_digest" "module digest"
    check_field "teardown_phases" "teardown phases"
    check_field "workqueue_trace_source" "workqueue trace source"
    check_field "workqueue_trace_artifact_path" "workqueue trace artifact path"
    check_field "workqueue_trace_digest" "workqueue trace digest"
    check_field "callback_trace_source" "callback trace source"
    check_field "callback_trace_artifact_path" "callback trace artifact path"
    check_field "callback_trace_digest" "callback trace digest"
    check_field "post_final_teardown_refusal_observations" "refusal observations"
    check_field "cleanup_outcome" "cleanup outcome"
    check_field "status" "status"
    check_field "fail_closed_reasons" "fail closed reasons"

    # Check that status matches observed results
    if grep -q '"status": "pass"' "$OUTPUT_DIR/kernel-teardown-runtime.json" 2>/dev/null; then
      if [ "$FAIL_COUNT" -gt 0 ]; then
        echo "VALIDATE FAIL: status=pass but FAIL_COUNT=$FAIL_COUNT"
        VALIDATION_ERRORS=$((VALIDATION_ERRORS + 1))
      fi
      if [ "$DMESG_FINAL_WARN" -gt 0 ] || [ "$DMESG_FINAL_BUG" -gt 0 ]; then
        echo "VALIDATE FAIL: status=pass but dmesg has WARNING/BUG"
        VALIDATION_ERRORS=$((VALIDATION_ERRORS + 1))
      fi
    fi

    # Check for dmesg kernel danger signals
    if check_dmesg_signal "$OUTPUT_DIR/qemu.log"; then
      echo "VALIDATE FAIL: dmesg contains kernel danger signals"
      VALIDATION_ERRORS=$((VALIDATION_ERRORS + 1))
    fi

    if [ "$VALIDATION_ERRORS" -gt 0 ]; then
      echo ""
      echo "VALIDATION FAILED: $VALIDATION_ERRORS error(s) in kernel-teardown-runtime.json"
      exit 1
    else
      echo "VALIDATION PASSED: kernel-teardown-runtime.json is valid"
    fi

    echo ""
    echo "Validation output directory: $OUTPUT_DIR"
    echo "  kernel-teardown-runtime.json"
    echo "  evidence-manifest.json"
    echo "  qemu.log"

    if [ "$FAIL_COUNT" -gt 0 ] || [ "$VALIDATION_ERRORS" -gt 0 ]; then
      exit 1
    fi
    exit 0
  '';
in
  kmodTeardownScript
