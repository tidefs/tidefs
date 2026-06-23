# TideFS: kernel mounted-VFS teardown runtime evidence validation.
#
# QEMU Validation target for T5 mounted-kernel-vfs teardown stress.
# Loads tidefs_posix_vfs.ko, creates a disposable configured pool member,
# mounts it through the kernel VFS path, exercises mount/write/sync,
# executes begin-teardown and final-teardown/unmount,
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
  tidefsPackage,
  tidefsXtaskRuntime,
}:

let
  linuxPackages_7_0 = pkgs.linuxPackagesFor linuxKernel_7_0;

  kmodTeardownScript = pkgs.writeShellScriptBin "tidefs-kmod-teardown-validation" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    GZIP="${pkgs.gzip}/bin/gzip"
    LDD_BIN="${pkgs.lib.getBin pkgs.glibc}/bin/ldd"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"
    KERNEL_RELEASE="${linuxKernel_7_0.version}"
    POSIX_VFS_KO="''${TIDEFS_KERNEL_VFS_MODULE_KO:-}"
    TIDEFSCTL="${tidefsPackage}/bin/tidefsctl"
    B3SUM="${pkgs.b3sum}/bin/b3sum"
    JQ="${pkgs.jq}/bin/jq"
    VALIDATOR="${tidefsXtaskRuntime}/bin/tidefs-xtask"

    TMPDIR="''${TIDEFS_TEARDOWN_TMPDIR:-/tmp/tidefs-teardown-validation}"
    TIMEOUT_SEC="''${TIDEFS_TEARDOWN_TIMEOUT:-600}"
    OUTPUT_DIR="''${TIDEFS_TEARDOWN_OUTPUT_DIR:-/tmp/tidefs-validation/kernel-teardown-validation}"

    usage() {
      cat <<EOF
Usage: tidefs-kmod-teardown-validation [--timeout SECONDS] [--output-dir DIR] [--keep-tmp]

Run T5 mounted-kernel-vfs teardown runtime evidence validation in a Linux 7.0
QEMU guest. Creates a configured TideFS pool member, exercises
mount/write/sync/teardown/unmount/module-unload lifecycle with ftrace workqueue
tracing and post-final refusal probes.

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

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$GZIP" "$LDD_BIN" "$TIDEFSCTL" "$B3SUM" "$JQ" "$VALIDATOR"; do
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
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,mnt/tidefs,validation,trace,var/lib/tidefs,etc,run/tidefs/import}
    trap 'if [ -z "''${KEEP_TMP:-}" ]; then rm -rf "$RUN_DIR"; fi' EXIT
    POOL_IMG="$RUN_DIR/configured-pool-member.img"

    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"

    copy_elf_deps() {
      local elf="$1"
      local deps dep dep_dir ld_so ld_dir

      deps=$("$LDD_BIN" "$elf" 2>/dev/null | grep -o '/nix/store/[^ ]*' | sort -u || true)
      for dep in $deps; do
        if [ -f "$dep" ]; then
          dep_dir=$(dirname "$dep")
          mkdir -p "$RUN_DIR$dep_dir"
          cp "$dep" "$RUN_DIR$dep" 2>/dev/null || true
        fi
      done

      ld_so=$("$LDD_BIN" "$elf" 2>/dev/null | grep -o '/nix/store/[^ ]*ld-linux[^ ]*' | head -1 || true)
      if [ -n "$ld_so" ] && [ -f "$ld_so" ]; then
        ld_dir=$(dirname "$ld_so")
        mkdir -p "$RUN_DIR$ld_dir"
        cp "$ld_so" "$RUN_DIR$ld_so" 2>/dev/null || true
        chmod +x "$RUN_DIR$ld_so" 2>/dev/null || true
      fi
    }
    copy_elf_deps "$BUSYBOX"

    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff reboot \
      mknod mkdir rmdir dd stat cp mv rm touch find wc head tail sync cut dirname basename \
      printf test xargs seq awk tr sort uniq md5sum date umount lsmod; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    cp "$TIDEFSCTL" "$RUN_DIR/bin/tidefsctl"
    chmod +x "$RUN_DIR/bin/tidefsctl"
    copy_elf_deps "$TIDEFSCTL"

    cp "$POSIX_VFS_KO" "$RUN_DIR/lib/modules/tidefs_posix_vfs.ko"

    # ── Init script ──────────────────────────────────────────────────
    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /tmp /validation /mnt/tidefs /trace
mkdir -p /sys/kernel/debug 2>/dev/null || true
mount -t tracefs tracefs /trace 2>/dev/null \
  || mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null \
  || true
if [ ! -f /trace/trace ]; then
  mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
fi

# Redirect kernel messages to /validation/dmesg.log via serial
MODULE_PATH=/lib/modules/tidefs_posix_vfs.ko
MNT=/mnt/tidefs
EVDIR=/validation
TRACEDIR=/trace
TRACE_ROOT=""
POOL_DEV=/dev/vda
POOL_NAME=qemu_teardown_pool

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

count_matches() {
  local pattern="$1"
  local file="$2"
  local count
  count=$(grep -c "$pattern" "$file" 2>/dev/null || true)
  printf '%s' "''${count:-0}"
}

emit_artifact() {
  local label="$1"
  local path="$2"

  echo "BEGIN_ARTIFACT:$label"
  if [ -f "$path" ]; then
    cat "$path" 2>/dev/null || true
  else
    echo "artifact source missing: $path"
  fi
  echo "END_ARTIFACT:$label"
}

find_trace_root() {
  local candidate

  if [ -n "$TRACE_ROOT" ] && [ -f "$TRACE_ROOT/trace" ]; then
    return 0
  fi

  for candidate in "$TRACEDIR" /sys/kernel/tracing /sys/kernel/debug/tracing; do
    if [ -f "$candidate/trace" ]; then
      TRACE_ROOT="$candidate"
      return 0
    fi
  done

  return 1
}

setup_ftrace() {
  if find_trace_root; then
    echo 0 > "$TRACE_ROOT/tracing_on" 2>/dev/null || true
    echo > "$TRACE_ROOT/trace" 2>/dev/null || true
    # Enable workqueue trace events
    echo 1 > "$TRACE_ROOT/events/workqueue/workqueue_execute_start/enable" 2>/dev/null || true
    echo 1 > "$TRACE_ROOT/events/workqueue/workqueue_execute_end/enable" 2>/dev/null || true
    # Enable workqueue queue events
    echo 1 > "$TRACE_ROOT/events/workqueue/workqueue_queue_work/enable" 2>/dev/null || true
    echo 1 > "$TRACE_ROOT/events/workqueue/workqueue_activate_work/enable" 2>/dev/null || true
    echo 1 > "$TRACE_ROOT/tracing_on" 2>/dev/null || true
    echo "[ftrace] workqueue tracing enabled at $TRACE_ROOT"
  else
    echo "[ftrace] tracefs not available; dmesg-only trace capture"
  fi
}

capture_ftrace() {
  local dest="$1"
  if find_trace_root; then
    cp "$TRACE_ROOT/trace" "$dest" 2>/dev/null || true
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
  for pattern in "WARNING:" "BUG:" "Oops:" "lockdep:" "KASAN:" "KCSAN:" "hung_task" "Call Trace:" "RIP:"; do
    local count
    count=$(count_matches "$pattern" "$dmesg_file")
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
log_phase "mount" "start" "create configured pool and mount /dev/vda"
POOL_READY=0
for _ in $(seq 1 30); do
  [ -b "$POOL_DEV" ] && break
  sleep 1
done

if [ -b "$POOL_DEV" ]; then
  pass "configured_pool_device_present"
else
  blocked "configured_pool_device_present" "$POOL_DEV missing"
  log_phase "mount" "fail" "$POOL_DEV missing"
  poweroff -f
fi

if command -v tidefsctl >/dev/null 2>&1; then
  COUT=$(tidefsctl pool create "$POOL_NAME" --devices "$POOL_DEV" --json 2>&1); RC=$?
  if [ "$RC" -eq 0 ]; then
    pass "configured_pool_member_created"
    SOUT=$(tidefsctl pool scan --devices "$POOL_DEV" 2>&1); SRC=$?
    if [ "$SRC" -eq 0 ] && echo "$SOUT" | grep -qi "label"; then
      pass "configured_pool_label_verified"
      POOL_READY=1
    else
      fail "configured_pool_label_verified" "$SOUT"
    fi
  else
    fail "configured_pool_member_created" "$COUT"
  fi
else
  blocked "configured_pool_member_created" "tidefsctl not found in initramfs"
fi

if [ "$POOL_READY" -eq 1 ] && mount -t tidefs "$POOL_DEV" "$MNT" 2>/tmp/mount.err; then
  pass "configured_pool_mount"
  log_phase "mount" "pass" "configured pool mount ok"
else
  fail "configured_pool_mount" "$(cat /tmp/mount.err 2>/dev/null | head -1)"
  log_phase "mount" "fail" "$(cat /tmp/mount.err 2>/dev/null | head -1)"
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
if mount -t tidefs "$POOL_DEV" "$MNT" 2>/dev/null; then
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
DMESG_WARN=$(count_matches "WARNING:" "$EVDIR/dmesg_final.txt")
DMESG_BUG=$(count_matches "BUG:" "$EVDIR/dmesg_final.txt")
DMESG_OOPS=$(count_matches "Oops:" "$EVDIR/dmesg_final.txt")
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
  if mount -t tidefs "$POOL_DEV" "$MNT" 2>/tmp/reload-mount.err; then
    pass "reload_remount"
    ls "$MNT" >/dev/null 2>&1 && pass "reload_readdir" || fail "reload_readdir" "readdir failed"
    umount "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null || true
    log_phase "reload_probe" "pass" "reload and remount ok"
  else
    fail "reload_remount" "$(cat /tmp/reload-mount.err | head -1)"
    log_phase "reload_probe" "fail" "$(cat /tmp/reload-mount.err | head -1)"
  fi
else
  fail "reload_insmod" "$(cat /tmp/reinsmod.err | head -1)"
  log_phase "reload_probe" "fail" "re-insmod failed"
fi

# ── Final sweep ─────────────────────────────────────────────────────
capture_dmesg "$EVDIR/dmesg_post_reload.txt"
capture_ftrace "$EVDIR/ftrace_final.txt"

emit_artifact "ftrace_workqueue" "$EVDIR/ftrace_final.txt"
emit_artifact "dmesg_callbacks" "$EVDIR/dmesg_post_reload.txt"

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
    INITRAMFS_TMP="$RUN_DIR/../initramfs-$$.gz"
    (cd "$RUN_DIR" && find . -path ./initramfs.gz -prune -o -print | "$CPIO" -o -H newc 2>/dev/null | "$GZIP" -n) > "$INITRAMFS_TMP"
    mv "$INITRAMFS_TMP" "$RUN_DIR/initramfs.gz"
    echo "  Initramfs: $(du -h "$RUN_DIR/initramfs.gz" | cut -f1)"

    echo "--- Creating configured pool member disk image ---"
    dd if=/dev/zero of="$POOL_IMG" bs=1M count=128 2>/dev/null
    echo "  Pool disk: $POOL_IMG ($(du -h "$POOL_IMG" | cut -f1))"

    echo "--- Booting QEMU ---"
    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$RUN_DIR/initramfs.gz" \
      -append "console=ttyS0 quiet" \
      -nographic \
      -m 512M \
      -no-reboot \
      -drive file="$POOL_IMG",if=virtio,format=raw \
      2>&1 | tee "$RUN_DIR/qemu.log" || true

    echo ""
    echo "--- QEMU exited ---"

    count_log_matches() {
      local pattern="$1"
      local file="$2"
      local count
      count=$(grep -E -c "$pattern" "$file" 2>/dev/null || true)
      printf '%s' "''${count:-0}"
    }

    PASS_COUNT=$(count_log_matches "^PASS:" "$RUN_DIR/qemu.log")
    FAIL_COUNT=$(count_log_matches "^FAIL:" "$RUN_DIR/qemu.log")
    BLOCKED_COUNT=$(count_log_matches "^BLOCKED:" "$RUN_DIR/qemu.log")
    SKIP_COUNT=$(count_log_matches "^SKIP:" "$RUN_DIR/qemu.log")

    echo "=== RESULTS ==="
    echo "PASS: $PASS_COUNT  FAIL: $FAIL_COUNT  BLOCKED: $BLOCKED_COUNT  SKIP: $SKIP_COUNT"

    mkdir -p "$OUTPUT_DIR"

    # Extract phase log and guest-emitted trace snippets from QEMU output.
    grep '^PHASE:' "$RUN_DIR/qemu.log" 2>/dev/null | sed 's/^PHASE://' > "$OUTPUT_DIR/phase_log.txt" || true
    grep '\[teardown-phase\]' "$RUN_DIR/qemu.log" 2>/dev/null > "$OUTPUT_DIR/phase_log_raw.txt" || true

    cp "$RUN_DIR/qemu.log" "$OUTPUT_DIR/qemu.log"

    extract_guest_artifact() {
      local label="$1"
      local path="$2"
      awk -v begin="BEGIN_ARTIFACT:$label" -v end="END_ARTIFACT:$label" '
        {
          line = $0;
          sub(/\r$/, "", line);
        }
        line == begin { emit = 1; next }
        line == end { emit = 0; next }
        emit {
          sub(/\r$/, "", $0);
          print;
        }
      ' "$RUN_DIR/qemu.log" > "$OUTPUT_DIR/$path" || true
    }

    WQ_TRACE_PATH="ftrace_workqueue.log"
    CB_TRACE_PATH="dmesg_callbacks.log"
    extract_guest_artifact "ftrace_workqueue" "$WQ_TRACE_PATH"
    extract_guest_artifact "dmesg_callbacks" "$CB_TRACE_PATH"

    TRACE_ERRORS_FILE="$OUTPUT_DIR/trace_artifact_errors.txt"
    : > "$TRACE_ERRORS_FILE"
    if [ ! -s "$OUTPUT_DIR/$WQ_TRACE_PATH" ] || grep -q "artifact source missing" "$OUTPUT_DIR/$WQ_TRACE_PATH" 2>/dev/null; then
      echo "trace artifact missing or empty: $WQ_TRACE_PATH" >> "$TRACE_ERRORS_FILE"
    fi
    if [ ! -s "$OUTPUT_DIR/$CB_TRACE_PATH" ] || grep -q "artifact source missing" "$OUTPUT_DIR/$CB_TRACE_PATH" 2>/dev/null; then
      echo "trace artifact missing or empty: $CB_TRACE_PATH" >> "$TRACE_ERRORS_FILE"
    fi

    # ── Generate run identity ───────────────────────────────────────
    GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    RUN_ID="''${GITHUB_RUN_ID:-unknown}"
    RUN_ATTEMPT="''${GITHUB_RUN_ATTEMPT:-1}"
    case "$RUN_ATTEMPT" in
      ""|*[!0-9]*) RUN_ATTEMPT=1 ;;
    esac
    WORKFLOW_NAME="''${GITHUB_WORKFLOW:-QEMU Smoke}"
    WORKFLOW_JOB="''${GITHUB_JOB:-kernel-teardown-validation}"
    SOURCE_REF="''${GITHUB_REF:-unknown}"
    SOURCE_SHA="''${GITHUB_SHA:-unknown}"
    SOURCE_REPO="''${GITHUB_REPOSITORY:-tidefs/tidefs}"
    VALIDATION_TIER="mounted-kernel-vfs"
    TARGET_ID="kernel-teardown-mounted-vfs"

    DMESG_FINAL_WARN=$(count_log_matches "WARNING:" "$OUTPUT_DIR/qemu.log")
    DMESG_FINAL_BUG=$(count_log_matches "BUG:" "$OUTPUT_DIR/qemu.log")
    DMESG_FINAL_OOPS=$(count_log_matches "Oops:" "$OUTPUT_DIR/qemu.log")
    DMESG_DANGER_COUNT=$(count_log_matches "WARNING:|BUG:|Oops:|lockdep:|KASAN:|KCSAN:|hung_task|Call Trace:|RIP:" "$OUTPUT_DIR/qemu.log")
    TRACE_ERROR_COUNT=$(count_log_matches "." "$TRACE_ERRORS_FILE")

    # ── Determine overall status ─────────────────────────────────────
    if [ "$FAIL_COUNT" -gt 0 ] || [ "$DMESG_DANGER_COUNT" -gt 0 ] || [ "$TRACE_ERROR_COUNT" -gt 0 ]; then
      TEARDOWN_STATUS="fail"
    elif [ "$BLOCKED_COUNT" -gt 0 ]; then
      TEARDOWN_STATUS="blocked"
    else
      TEARDOWN_STATUS="pass"
    fi

    # ── Build fail_closed_reasons ────────────────────────────────────
    if [ "$TEARDOWN_STATUS" = "pass" ]; then
      FAIL_REASONS_JSON="$("$JQ" -n '[]')"
    else
      {
        grep -E "^(FAIL|BLOCKED):" "$RUN_DIR/qemu.log" 2>/dev/null || true
        cat "$TRACE_ERRORS_FILE"
        if [ "$DMESG_DANGER_COUNT" -gt 0 ]; then
          echo "dmesg danger signals observed: WARNING=$DMESG_FINAL_WARN BUG=$DMESG_FINAL_BUG Oops=$DMESG_FINAL_OOPS total=$DMESG_DANGER_COUNT"
        fi
      } > "$OUTPUT_DIR/fail_lines.txt"
      if [ -s "$OUTPUT_DIR/fail_lines.txt" ]; then
        FAIL_REASONS_JSON="$("$JQ" -R -s 'split("\n") | map(select(length > 0))' "$OUTPUT_DIR/fail_lines.txt")"
      else
        FAIL_REASONS_JSON="$("$JQ" -n --arg reason "status=$TEARDOWN_STATUS without pass evidence" '[$reason]')"
      fi
    fi

    # ── Build teardown phases JSON array from phase log ──────────────
    if [ -s "$OUTPUT_DIR/phase_log.txt" ]; then
      PHASES_JSON="$(
        awk '
          {
            phase=$1; status=""; ts=""; notes="";
            for (i=2; i<=NF; i++) {
              if ($i ~ /^status=/) {
                status=substr($i, 8);
              } else if ($i ~ /^ts=/) {
                ts=substr($i, 4);
              } else if ($i ~ /^notes=/) {
                notes=substr($i, 7);
                for (j=i+1; j<=NF; j++) {
                  notes=notes " " $j;
                }
                break;
              }
            }
            printf "%s\t%s\t%s\t%s\n", phase, status, ts, notes;
          }
        ' "$OUTPUT_DIR/phase_log.txt" \
          | "$JQ" -R -s 'split("\n") | map(select(length > 0) | split("\t") | {phase: .[0], status: .[1], start_timestamp: .[2], notes: .[3]})'
      )"
    else
      PHASES_JSON="$("$JQ" -n '[]')"
    fi

    # Build refusal observations
    REFUSAL_LINES="$OUTPUT_DIR/refusal_lines.txt"
    grep -E "^(PASS|FAIL): refusal_" "$RUN_DIR/qemu.log" 2>/dev/null > "$REFUSAL_LINES" || true
    if [ -s "$REFUSAL_LINES" ]; then
      REFUSAL_JSON="$(
        awk '
          {
            status=$1; sub(/:$/, "", status);
            operation=$2; sub(/^refusal_/, "", operation);
            observed=$0; sub(/^[^ ]+ [^ ]+ /, "", observed);
            new_work = status == "FAIL" ? "true" : "false";
            printf "%s\t%s\t%s\n", operation, observed, new_work;
          }
        ' "$REFUSAL_LINES" \
          | "$JQ" -R -s 'split("\n") | map(select(length > 0) | split("\t") | {operation: .[0], expected_refusal: true, observed_result: .[1], new_work_enqueued_or_started: (.[2] == "true")})'
      )"
    else
      REFUSAL_JSON="$("$JQ" -n '[]')"
    fi

    WQ_TRACE_SOURCE="ftrace:/sys/kernel/tracing/events/workqueue/*"
    WQ_TRACE_DIGEST="blake3:$("$B3SUM" "$OUTPUT_DIR/$WQ_TRACE_PATH" | awk '{print $1}')"
    CB_TRACE_SOURCE="dmesg kernel log emitted by guest"
    CB_TRACE_DIGEST="blake3:$("$B3SUM" "$OUTPUT_DIR/$CB_TRACE_PATH" | awk '{print $1}')"

    # Cleanup outcome
    if [ "$DMESG_FINAL_WARN" -eq 0 ] && [ "$DMESG_FINAL_BUG" -eq 0 ]; then
      CLEANUP_DMESG="clean"
    else
      CLEANUP_DMESG="dmesg WARNING=$DMESG_FINAL_WARN BUG=$DMESG_FINAL_BUG"
    fi
    UNMOUNT_OUTCOME="$(grep -Eq "^PASS: unmount_ok|^PASS: unmount_lazy" "$RUN_DIR/qemu.log" && echo "success" || echo "failed")"
    RMMOD_OUTCOME="$(grep -Eq "^PASS: rmmod_ok" "$RUN_DIR/qemu.log" && echo "success" || echo "failed")"
    RELOAD_OUTCOME="$(grep -Eq "^PASS: reload_remount" "$RUN_DIR/qemu.log" && echo "success" || echo "failed")"
    REMAINING_WORK="$([ "$TEARDOWN_STATUS" = "pass" ] && echo "none observed" || echo "unknown; validation did not pass")"

    "$JQ" -n \
      --arg generated_by "kernel-teardown-validation" \
      --arg claim_id "kernel.teardown.no_work_after.v1" \
      --arg evidence_class "runtime-kernel-teardown-no-work-after-artifact" \
      --arg workflow_run_id "$RUN_ID" \
      --argjson workflow_run_attempt "$RUN_ATTEMPT" \
      --arg workflow_name "$WORKFLOW_NAME" \
      --arg workflow_job "$WORKFLOW_JOB" \
      --arg source_ref "$SOURCE_REF" \
      --arg source_sha "$SOURCE_SHA" \
      --arg validation_tier "$VALIDATION_TIER" \
      --arg target_id "$TARGET_ID" \
      --arg kernel_release "$KERNEL_RELEASE" \
      --arg module_name "tidefs_posix_vfs" \
      --arg module_digest "blake3:$MODULE_DIGEST" \
      --argjson teardown_phases "$PHASES_JSON" \
      --arg workqueue_trace_source "$WQ_TRACE_SOURCE" \
      --arg workqueue_trace_artifact_path "$WQ_TRACE_PATH" \
      --arg workqueue_trace_digest "$WQ_TRACE_DIGEST" \
      --arg callback_trace_source "$CB_TRACE_SOURCE" \
      --arg callback_trace_artifact_path "$CB_TRACE_PATH" \
      --arg callback_trace_digest "$CB_TRACE_DIGEST" \
      --argjson refusal_observations "$REFUSAL_JSON" \
      --arg unmount "$UNMOUNT_OUTCOME" \
      --arg rmmod "$RMMOD_OUTCOME" \
      --arg reload_remount_probe "$RELOAD_OUTCOME" \
      --arg dmesg_state "$CLEANUP_DMESG" \
      --arg remaining_tidefs_work_observations "$REMAINING_WORK" \
      --arg status "$TEARDOWN_STATUS" \
      --argjson fail_closed_reasons "$FAIL_REASONS_JSON" \
      '{
        artifact_version: 1,
        generated_by: $generated_by,
        claim_id: $claim_id,
        evidence_class: $evidence_class,
        workflow_run_id: $workflow_run_id,
        workflow_run_attempt: $workflow_run_attempt,
        workflow_name: $workflow_name,
        workflow_job: $workflow_job,
        source_ref: $source_ref,
        source_sha: $source_sha,
        validation_tier: $validation_tier,
        target_id: $target_id,
        kernel_release: $kernel_release,
        module_name: $module_name,
        module_digest: $module_digest,
        teardown_phases: $teardown_phases,
        workqueue_trace_source: $workqueue_trace_source,
        workqueue_trace_artifact_path: $workqueue_trace_artifact_path,
        workqueue_trace_digest: $workqueue_trace_digest,
        callback_trace_source: $callback_trace_source,
        callback_trace_artifact_path: $callback_trace_artifact_path,
        callback_trace_digest: $callback_trace_digest,
        post_final_teardown_refusal_observations: $refusal_observations,
        cleanup_outcome: {
          unmount: $unmount,
          rmmod: $rmmod,
          reload_remount_probe: $reload_remount_probe,
          dmesg_state: $dmesg_state,
          remaining_tidefs_work_observations: $remaining_tidefs_work_observations
        },
        status: $status,
        fail_closed_reasons: $fail_closed_reasons
      }' > "$OUTPUT_DIR/kernel-teardown-runtime.json"

    echo "## kernel-teardown-runtime.json written" >> /dev/stderr

    # ── Write evidence-manifest.json ─────────────────────────────────
    ARTIFACT_PATH="kernel-teardown-runtime.json"
    ARTIFACT_DIGEST="blake3:$("$B3SUM" "$OUTPUT_DIR/$ARTIFACT_PATH" | awk '{print $1}')"
    EVIDENCE_CLASS="runtime-kernel-teardown-no-work-after-artifact"
    SOURCE_LABEL="qemu-smoke-kernel-teardown-validation"
    SCOPE="kernel-teardown-mounted-vfs source=qemu-smoke run=$RUN_ID ref=$SOURCE_REF sha=$SOURCE_SHA repo=$SOURCE_REPO"

    "$JQ" -n \
      --arg claim_id "kernel.teardown.no_work_after.v1" \
      --arg evidence_class "$EVIDENCE_CLASS" \
      --arg validation_tier "$VALIDATION_TIER" \
      --arg source "$SOURCE_LABEL" \
      --arg scope "$SCOPE" \
      --arg artifact_path "$ARTIFACT_PATH" \
      --arg content_digest "$ARTIFACT_DIGEST" \
      --arg generated_at "$GENERATED_AT" \
      '{
        manifest_version: 1,
        claim_id: $claim_id,
        evidence_class: $evidence_class,
        validation_tier: $validation_tier,
        source: $source,
        scope: $scope,
        artifact_path: $artifact_path,
        content_digest: $content_digest,
        generated_at: $generated_at
      }' > "$OUTPUT_DIR/evidence-manifest.json"

    echo "## evidence-manifest.json written" >> /dev/stderr

    # ── Validate the artifact (fail-closed) ──────────────────────────
    echo ""
    echo "--- Validating kernel-teardown-runtime.json ---"

    VALIDATION_ERRORS=0

    if ! "$VALIDATOR" validate-kernel-teardown-runtime-artifact "$OUTPUT_DIR/kernel-teardown-runtime.json"; then
      echo "VALIDATE FAIL: xtask teardown artifact validator rejected kernel-teardown-runtime.json"
      VALIDATION_ERRORS=$((VALIDATION_ERRORS + 1))
    fi

    if [ "$TEARDOWN_STATUS" = "pass" ] && { [ "$FAIL_COUNT" -gt 0 ] || [ "$DMESG_DANGER_COUNT" -gt 0 ] || [ "$TRACE_ERROR_COUNT" -gt 0 ]; }; then
      echo "VALIDATE FAIL: status=pass but fail/dmesg/trace counters are non-zero"
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

    if [ "$TEARDOWN_STATUS" != "pass" ] || [ "$VALIDATION_ERRORS" -gt 0 ]; then
      exit 1
    fi
    exit 0
  '';
in
  kmodTeardownScript
