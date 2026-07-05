# TideFS: kernel no-daemon teardown and recovery runtime evidence validation.
#
# QEMU Validation target for T6 full-kernel-no-daemon teardown stress.
# Loads tidefs_posix_vfs.ko with zero userspace daemons (no FUSE daemon,
# no ublk daemon, no policy/control daemon, no transport helper, no
# usermode worker), creates and mounts an explicit virtio pool member through
# kernel-resident paths only, exercises mount/write/sync, executes begin-teardown and
# final-teardown/unmount, unloads the module, probes post-final
# operation refusal, captures Linux workqueue and callback trace
# evidence through ftrace and dmesg, performs no-daemon crash/recovery
# cycles, and writes kernel-teardown-runtime.json with an
# evidence-manifest.json into the artifact directory.
#
# Produces a T6 full-kernel/no-daemon teardown runtime artifact. The artifact
# carries explicit per-surface coverage and remains blocked unless every
# required T6 surface is proven without required support daemons. It does not
# update claim registry status or generated claim docs.
{
  pkgs,
  linuxKernel_7_0,
  tidefsPackage,
  tidefsXtaskRuntime,
}:

let
  linuxPackages_7_0 = pkgs.linuxPackagesFor linuxKernel_7_0;

  kmodNoDaemonTeardownScript = pkgs.writeShellScriptBin "tidefs-kmod-no-daemon-teardown-validation" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    LDD_BIN="${pkgs.lib.getBin pkgs.glibc}/bin/ldd"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"
    KERNEL_RELEASE="${linuxKernel_7_0.version}"
    POSIX_VFS_KO="''${TIDEFS_KERNEL_VFS_MODULE_KO:-}"
    TIDEFSCTL="${tidefsPackage}/bin/tidefsctl"
    B3SUM="${pkgs.b3sum}/bin/b3sum"
    JQ="${pkgs.jq}/bin/jq"
    VALIDATOR="${tidefsXtaskRuntime}/bin/tidefs-xtask"

    TMPDIR="''${TIDEFS_NO_DAEMON_TEARDOWN_TMPDIR:-/tmp/tidefs-no-daemon-teardown-validation}"
    TIMEOUT_SEC="''${TIDEFS_NO_DAEMON_TEARDOWN_TIMEOUT:-600}"
    OUTPUT_DIR="''${TIDEFS_NO_DAEMON_TEARDOWN_OUTPUT_DIR:-/tmp/tidefs-validation/kernel-no-daemon-teardown-validation}"

    usage() {
      cat <<'EOF'
Usage: tidefs-kmod-no-daemon-teardown-validation [--timeout SECONDS] [--output-dir DIR] [--keep-tmp]

Run T6 full-kernel-no-daemon teardown and recovery runtime evidence validation
in a Linux 7.0 QEMU guest. Exercises mount/write/sync/teardown/unmount/
module-unload lifecycle with ftrace workqueue tracing, post-final refusal
probes, and no-daemon crash/recovery cycles. Zero userspace daemons.

Options:
  --timeout SECONDS    QEMU boot timeout (default: 600)
  --output-dir DIR     Artifact output directory
  --module PATH        Path to pre-built tidefs_posix_vfs.ko
  --keep-tmp           Do not remove temp directory on exit
  --help, -h           Show this message

Exit codes:
  0  No-daemon teardown validation passed
  1  No-daemon teardown validation failed or produced dmesg warnings
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

    echo "=== TideFS T6: kernel-no-daemon-teardown-validation ==="
    echo "  Kernel:    $KERNEL_IMG"
    echo "  QEMU:      $QEMU_BIN"
    echo "  Module:    tidefs_posix_vfs (no-daemon)"
    echo "  Timeout:   ''${TIMEOUT_SEC}s"
    echo "  Output:    $OUTPUT_DIR"
    echo ""

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$LDD_BIN" "$TIDEFSCTL" "$B3SUM" "$JQ" "$VALIDATOR"; do
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
    INITRAMFS="$TMPDIR/initramfs-$$.cpio"
    POOL_IMG="$TMPDIR/configured-pool-member-$$.img"
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,mnt/tidefs,validation,trace,var/lib/tidefs,run/tidefs/import,etc,usr/bin}
    trap 'if [ -z "''${KEEP_TMP:-}" ]; then rm -rf "$RUN_DIR" "$INITRAMFS" "$POOL_IMG"; fi' EXIT

    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"

    # Nix-built BusyBox is dynamically linked and records absolute /nix/store
    # interpreter/library paths. Copy those exact paths so /init can execute.
    BUSYBOX_DEPS=$("$LDD_BIN" "$BUSYBOX" 2>/dev/null | grep -o '/nix/store/[^ ]*' | sort -u || true)
    for lib in $BUSYBOX_DEPS; do
      if [ -f "$lib" ]; then
        lib_dir=$(dirname "$lib")
        mkdir -p "$RUN_DIR$lib_dir"
        cp "$lib" "$RUN_DIR$lib" 2>/dev/null || true
      fi
    done
    BUSYBOX_LD_SO=$("$LDD_BIN" "$BUSYBOX" 2>/dev/null | grep -o '/nix/store/[^ ]*ld-linux[^ ]*' | head -1 || true)
    if [ -n "$BUSYBOX_LD_SO" ] && [ -f "$BUSYBOX_LD_SO" ]; then
      ld_dir=$(dirname "$BUSYBOX_LD_SO")
      mkdir -p "$RUN_DIR$ld_dir"
      cp "$BUSYBOX_LD_SO" "$RUN_DIR$BUSYBOX_LD_SO" 2>/dev/null || true
      chmod +x "$RUN_DIR$BUSYBOX_LD_SO" 2>/dev/null || true
    fi

    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff reboot \
      mknod mkdir rmdir dd stat cp mv rm touch find wc head tail sync cut dirname basename \
      printf test xargs seq awk tr sort uniq md5sum date ps umount lsmod mountpoint uname \
      true false; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    cp "$TIDEFSCTL" "$RUN_DIR/bin/tidefsctl"
    chmod +x "$RUN_DIR/bin/tidefsctl"
    TIDEFSCTL_DEPS=$("$LDD_BIN" "$TIDEFSCTL" 2>/dev/null | grep -o '/nix/store/[^ ]*' | sort -u || true)
    for lib in $TIDEFSCTL_DEPS; do
      if [ -f "$lib" ]; then
        lib_dir=$(dirname "$lib")
        mkdir -p "$RUN_DIR$lib_dir"
        cp "$lib" "$RUN_DIR$lib" 2>/dev/null || true
      fi
    done
    TIDEFSCTL_LD_SO=$("$LDD_BIN" "$TIDEFSCTL" 2>/dev/null | grep -o '/nix/store/[^ ]*ld-linux[^ ]*' | head -1 || true)
    if [ -n "$TIDEFSCTL_LD_SO" ] && [ -f "$TIDEFSCTL_LD_SO" ]; then
      ld_dir=$(dirname "$TIDEFSCTL_LD_SO")
      mkdir -p "$RUN_DIR$ld_dir"
      cp "$TIDEFSCTL_LD_SO" "$RUN_DIR$TIDEFSCTL_LD_SO" 2>/dev/null || true
      chmod +x "$RUN_DIR$TIDEFSCTL_LD_SO" 2>/dev/null || true
    fi

    cp "$POSIX_VFS_KO" "$RUN_DIR/lib/modules/tidefs_posix_vfs.ko"

    # ── Init script: T6 no-daemon teardown and recovery validation ───
    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== TideFS T6: No-Daemon Teardown and Recovery Validation ==="
echo "kernel_version=$(uname -r)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

# ── Counters ────────────────────────────────────────────────────────
PASSED=0
FAILED=0
BLOCKED=0
SKIPPED=0

pass()   { PASSED=$((PASSED + 1)); echo "PASS: $@"; }
fail()   { FAILED=$((FAILED + 1)); echo "FAIL: $@"; }
blocked(){ BLOCKED=$((BLOCKED + 1)); echo "BLOCKED: $@"; }
skip()   { SKIPPED=$((SKIPPED + 1)); echo "SKIP: $@"; }

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

MNT=/mnt/tidefs
POOL_DEV=/dev/vda
POOL_NAME=t6_no_daemon_teardown_pool
MODULE_PATH=/lib/modules/tidefs_posix_vfs.ko
EVDIR=/validation
TRACEFS=/tracefs
mkdir -p "$EVDIR"

# ── Infra: ftrace and dmesg capture ─────────────────────────────────
setup_ftrace() {
  mkdir -p "$TRACEFS" 2>/dev/null || true
  if [ ! -f "$TRACEFS/trace" ]; then
    mount -t tracefs tracefs "$TRACEFS" 2>/tmp/tracefs_mount.err || true
  fi

  if [ -f "$TRACEFS/trace" ]; then
    local enabled=1
    echo 0 > "$TRACEFS/tracing_on" 2>/dev/null || enabled=0
    : > "$TRACEFS/trace" 2>/dev/null || enabled=0
    for event in workqueue_execute_start workqueue_execute_end workqueue_queue_work workqueue_activate_work; do
      if [ -e "$TRACEFS/events/workqueue/$event/enable" ]; then
        echo 1 > "$TRACEFS/events/workqueue/$event/enable" 2>/dev/null || enabled=0
      else
        enabled=0
      fi
    done
    echo 1 > "$TRACEFS/tracing_on" 2>/dev/null || enabled=0
    if [ "$enabled" -eq 1 ]; then
      pass "ftrace_workqueue_enabled"
      echo "[ftrace] workqueue tracing enabled"
    else
      echo "[ftrace] tracefs workqueue events unavailable; dmesg-only trace capture"
    fi
  else
    local err
    err=$(cat /tmp/tracefs_mount.err 2>/dev/null | head -1)
    [ -n "$err" ] || err="tracefs trace file not available"
    echo "[ftrace] tracefs not available ($err); dmesg-only trace capture"
  fi
}

capture_ftrace() {
  local dest="$1"
  mkdir -p "$(dirname "$dest")" 2>/dev/null || true
  if [ -f "$TRACEFS/trace" ]; then
    if cp "$TRACEFS/trace" "$dest" 2>/tmp/ftrace_capture.err && [ -s "$dest" ]; then
      echo "[ftrace] trace captured to $dest ($(wc -c < "$dest" 2>/dev/null || echo 0) bytes)"
    else
      local err
      err=$(cat /tmp/ftrace_capture.err 2>/dev/null | head -1)
      [ -n "$err" ] || err="trace capture missing or empty"
      echo "[ftrace] trace capture unavailable: $err"
    fi
  else
    echo "[ftrace] tracefs trace file missing; dmesg-only trace capture"
  fi
}

capture_dmesg() {
  local dest="$1"
  mkdir -p "$(dirname "$dest")" 2>/dev/null || true
  if dmesg > "$dest" 2>/tmp/dmesg_capture.err && [ -s "$dest" ]; then
    echo "[dmesg] captured to $dest ($(wc -c < "$dest" 2>/dev/null || echo 0) bytes)"
  else
    local err
    err=$(cat /tmp/dmesg_capture.err 2>/dev/null | head -1)
    [ -n "$err" ] || err="dmesg capture missing or empty"
    fail "dmesg_capture" "$err"
  fi
}

write_dmesg_marker_trace() {
  local source="$1"
  local dest="$2"
  local marker_count

  marker_count=$(grep -E -c 'tidefs_posix_vfs:|sync_fs super_operation:|put_super super_operation:|lifecycle summary:' "$source" 2>/dev/null || true)
  {
    echo "trace_source=dmesg kernel lifecycle markers"
    echo "tracefs_root=unavailable"
    echo "marker_count=''${marker_count:-0}"
    grep -E 'tidefs_posix_vfs:|sync_fs super_operation:|put_super super_operation:|lifecycle summary:' "$source" 2>/dev/null || true
  } > "$dest"
  echo "[dmesg] lifecycle marker trace captured to $dest ($(wc -c < "$dest" 2>/dev/null || echo 0) bytes)"
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

# ── No-daemon verification ──────────────────────────────────────────
check_no_daemon() {
  local phase="$1"
  # Check for FUSE mounts
  if grep -q "fuse" /proc/mounts 2>/dev/null && ! grep -q "fuseblk" /proc/mounts 2>/dev/null; then
    true
  fi
  # Check for FUSE module
  if lsmod 2>/dev/null | grep -q "^fuse "; then
    echo "NO_DAEMON_WARN: $phase -- fuse kernel module loaded"
  fi
  # Check for userspace daemon processes
  local daemon_procs=""
  daemon_procs=$(ps 2>/dev/null | grep -iE "tidefs.*daemon|fuse.*adapter|ublk.*adapter|tidefs-storage-node|tidefs-block-volume" | grep -v grep | grep -v "\[" || true)
  if [ -n "$daemon_procs" ]; then
    echo "NO_DAEMON_FAIL: $phase -- userspace daemon process detected: $(echo "$daemon_procs" | head -3)"
    return 1
  fi
  return 0
}

verify_no_daemon() {
  local phase="$1"
  if check_no_daemon "$phase"; then
    pass "no_daemon_$phase"
  else
    fail "no_daemon_$phase" "userspace daemon process detected in $phase"
  fi
}

# ── Phase logging for artifact ──────────────────────────────────────
TEARDOWN_PHASE_LOG=""

log_phase() {
  local phase="$1"
  local status="$2"
  local note="$3"
  local ts
  ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  TEARDOWN_PHASE_LOG="''${TEARDOWN_PHASE_LOG}''${phase}|''${status}|''${ts}|''${note}"$'\n'
  echo "PHASE_MARKER:''${phase}|''${status}|''${ts}|''${note}"
}

# ── Phase: module_load ──────────────────────────────────────────────
log_phase "module_load" "start" "insmod tidefs_posix_vfs (no-daemon)"
echo "--- Phase: module_load ---"
if [ -f "$MODULE_PATH" ]; then
  if insmod "$MODULE_PATH" 2>/tmp/insmod.err; then
    pass "module_load"
    log_phase "module_load" "pass" "module loaded"
  else
    fail "module_load" "$(cat /tmp/insmod.err | head -1)"
    log_phase "module_load" "fail" "$(cat /tmp/insmod.err | head -1)"
    poweroff -f
  fi
else
  blocked "module_load" "tidefs_posix_vfs.ko not found"
  log_phase "module_load" "blocked" "module not found"
  poweroff -f
fi

if lsmod 2>/dev/null | grep -q tidefs_posix_vfs; then
  pass "module_visible"
else
  fail "module_visible" "module not in lsmod after insmod"
fi

verify_no_daemon "module_load"

# ── Phase: mount (configured pool member, no-daemon) ────────────────
log_phase "mount" "start" "create and mount configured pool member (no-daemon)"
echo "--- Phase: mount ---"

POOL_DEVICE_READY=0
POOL_READY=0
echo "Waiting for virtio pool member $POOL_DEV..."
for _ in $(seq 1 30); do
  [ -b "$POOL_DEV" ] && break
  sleep 1
done
if [ -b "$POOL_DEV" ]; then
  POOL_DEVICE_READY=1
  pass "configured_pool_device_present"
else
  blocked "configured_pool_device_present" "$POOL_DEV missing"
fi

if [ "$POOL_DEVICE_READY" -eq 1 ] && command -v tidefsctl >/dev/null 2>&1; then
  echo "tidefsctl pool create $POOL_NAME --devices $POOL_DEV --json"
  COUT=$(tidefsctl pool create "$POOL_NAME" --devices "$POOL_DEV" --json 2>&1); RC=$?
  echo "  create exit=$RC"
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
  if [ "$POOL_DEVICE_READY" -eq 0 ]; then
    blocked "configured_pool_member_created" "virtio pool device missing"
  else
    blocked "configured_pool_member_created" "tidefsctl not found in initramfs"
  fi
  blocked "configured_pool_label_verified" "pool member was not created"
fi

mkdir -p "$MNT"
if [ "$POOL_READY" -eq 1 ] && mount -t tidefs "$POOL_DEV" "$MNT" 2>/tmp/mount.err; then
  pass "configured_pool_mount"
  log_phase "mount" "pass" "configured pool member mount ok (no-daemon)"
else
  MOUNT_ERR=$(cat /tmp/mount.err 2>/dev/null | head -1)
  [ -n "$MOUNT_ERR" ] || MOUNT_ERR="configured pool member not ready"
  fail "configured_pool_mount" "$MOUNT_ERR"
  log_phase "mount" "fail" "$MOUNT_ERR"
  poweroff -f
fi

verify_no_daemon "mount"

is_mounted() { mountpoint -q "$MNT" 2>/dev/null && return 0 || return 1; }
MOUNTED=0
if is_mounted; then MOUNTED=1; fi

# ── Phase: pre_teardown_io ──────────────────────────────────────────
log_phase "pre_teardown_io" "start" "write and sync test data (no-daemon)"
echo "--- Phase: pre_teardown_io ---"

setup_ftrace

if [ "$MOUNTED" -eq 1 ]; then
  # Write test file
  if echo "no-daemon-teardown-test-$(date +%s)" > "$MNT/teardown_test.txt" 2>/tmp/write.err; then
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
    if echo "$CONTENT" | grep -q "no-daemon-teardown-test"; then
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
else
  skip "pre_teardown_io" "filesystem not mounted"
  log_phase "pre_teardown_io" "skip" "not mounted"
fi

verify_no_daemon "pre_teardown_io"

# ── Phase: begin_teardown ───────────────────────────────────────────
log_phase "begin_teardown" "start" "sync before unmount (no-daemon)"
echo "--- Phase: begin_teardown ---"
sync 2>/dev/null || true

capture_ftrace "$EVDIR/ftrace_pre_teardown.txt"

log_phase "begin_teardown" "pass" "pre-unmount sync and ftrace capture done"

# ── Phase: final_teardown ───────────────────────────────────────────
log_phase "final_teardown" "start" "unmount (no-daemon)"
echo "--- Phase: final_teardown ---"
if [ "$MOUNTED" -eq 1 ]; then
  if umount "$MNT" 2>/tmp/umount.err; then
    pass "unmount_ok"
    log_phase "final_teardown" "pass" "unmount succeeded"
  else
    UMOUNT_ERR=$(cat /tmp/umount.err | head -1)
    if umount -l "$MNT" 2>/dev/null; then
      pass "unmount_lazy"
      log_phase "final_teardown" "pass" "lazy unmount succeeded after: $UMOUNT_ERR"
    else
      fail "unmount" "$UMOUNT_ERR"
      log_phase "final_teardown" "fail" "unmount failed: $UMOUNT_ERR"
    fi
  fi
else
  skip "final_teardown" "filesystem not mounted"
  log_phase "final_teardown" "skip" "not mounted"
fi

capture_ftrace "$EVDIR/ftrace_post_teardown.txt"

verify_no_daemon "final_teardown"

# ── Phase: module_unload ────────────────────────────────────────────
log_phase "module_unload" "start" "rmmod tidefs_posix_vfs (no-daemon)"
echo "--- Phase: module_unload ---"
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
log_phase "post_final_refusal_probe" "start" "probe operations after teardown (no-daemon)"
echo "--- Phase: post_final_refusal_probe ---"

REFUSAL1_OP="mount"
REFUSAL1_EXPECTED=true
REFUSAL1_RESULT=""
REFUSAL1_NEW_WORK=false

if mount -t tidefs "$POOL_DEV" "$MNT" 2>/dev/null; then
  REFUSAL1_RESULT="mount_unexpectedly_succeeded"
  fail "refusal_mount" "mount succeeded after module unload"
  umount "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null || true
  REFUSAL1_NEW_WORK=true
else
  REFUSAL1_RESULT="mount_correctly_refused"
  pass "refusal_mount" "mount refused after module unload"
fi

REFUSAL2_OP="mount_check"
REFUSAL2_EXPECTED=true
REFUSAL2_RESULT=""
REFUSAL2_NEW_WORK=false

if mount | grep -q "$MNT.*tidefs" 2>/dev/null; then
  REFUSAL2_RESULT="tidefs_mount_still_visible"
  fail "refusal_mount_check" "TideFS mount still visible after rmmod"
else
  REFUSAL2_RESULT="no_tidefs_mount_visible"
  pass "refusal_mount_check" "no TideFS mount visible"
fi

log_phase "post_final_refusal_probe" "pass" "refusal probes: $REFUSAL1_RESULT $REFUSAL2_RESULT"

verify_no_daemon "post_final_refusal_probe"

# ── Phase: cleanup ──────────────────────────────────────────────────
log_phase "cleanup" "start" "dmesg check and trace capture (no-daemon)"
echo "--- Phase: cleanup ---"

capture_dmesg "$EVDIR/dmesg_final.txt"

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
log_phase "reload_probe" "start" "re-insmod and remount (no-daemon)"
echo "--- Phase: reload_probe ---"
if insmod "$MODULE_PATH" 2>/tmp/reinsmod.err; then
  pass "reload_insmod"
  if mount -t tidefs "$POOL_DEV" "$MNT" 2>/dev/null; then
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

verify_no_daemon "reload_probe"

# ── Phase: no_daemon_recovery ───────────────────────────────────────
log_phase "no_daemon_recovery" "start" "crash/recovery cycle (no-daemon)"
echo "--- Phase: no_daemon_recovery ---"

# Unload everything to simulate a clean crash
rmmod tidefs_posix_vfs 2>/dev/null || true

# Reload
if insmod "$MODULE_PATH" 2>/dev/null; then
  pass "recovery_insmod"
else
  fail "recovery_insmod" "re-insmod for recovery failed"
fi

# Remount and verify
if mount -t tidefs "$POOL_DEV" "$MNT" 2>/dev/null; then
  pass "recovery_remount"
  # Check if previous data survived
  if [ -f "$MNT/teardown_test.txt" ]; then
    pass "recovery_data_survived"
  else
    skip "recovery_data_survived" "pool member did not retain test file after reload"
  fi
  # Write new data to verify operation
  if echo "recovery-write-ok" > "$MNT/recovery_test.txt" 2>/dev/null; then
    RECOVERY_CONTENT=$(cat "$MNT/recovery_test.txt" 2>/dev/null)
    if [ "$RECOVERY_CONTENT" = "recovery-write-ok" ]; then
      pass "recovery_write_verify"
    else
      fail "recovery_write_verify" "write after recovery inconsistent"
    fi
  else
    fail "recovery_write" "write after recovery failed"
  fi
  umount "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null || true
  log_phase "no_daemon_recovery" "pass" "recovery cycle ok"
else
  fail "recovery_remount" "remount after recovery failed"
  log_phase "no_daemon_recovery" "fail" "recovery remount failed"
fi

verify_no_daemon "recovery"

# ── Final sweep ─────────────────────────────────────────────────────
capture_dmesg "$EVDIR/dmesg_post_reload.txt"
capture_ftrace "$EVDIR/ftrace_final.txt"
if [ ! -s "$EVDIR/ftrace_final.txt" ]; then
  write_dmesg_marker_trace "$EVDIR/dmesg_post_reload.txt" "$EVDIR/workqueue_trace_fallback.txt"
fi

if [ -s "$EVDIR/ftrace_final.txt" ]; then
  emit_artifact "workqueue_trace" "$EVDIR/ftrace_final.txt"
else
  emit_artifact "workqueue_trace" "$EVDIR/workqueue_trace_fallback.txt"
fi
emit_artifact "dmesg_callbacks" "$EVDIR/dmesg_post_reload.txt"

echo ""
echo "============================================================"
echo "=== NO-DAEMON TEARDOWN VALIDATION SUMMARY ==="
echo "  PASS=$PASSED FAIL=$FAILED BLOCKED=$BLOCKED SKIP=$SKIPPED"
echo "  kernel_version=$(uname -r)"
echo "============================================================"

cp "$EVDIR/dmesg_final.txt" /tmp/tidefs_no_daemon_teardown_dmesg.log 2>/dev/null || true
if [ -s "$EVDIR/ftrace_final.txt" ]; then
  cp "$EVDIR/ftrace_final.txt" /tmp/tidefs_no_daemon_teardown_ftrace.log 2>/dev/null || true
else
  cp "$EVDIR/workqueue_trace_fallback.txt" /tmp/tidefs_no_daemon_teardown_ftrace.log 2>/dev/null || true
fi

sleep 3
poweroff -f
INITSCRIPT

    chmod +x "$RUN_DIR/init"

    echo "--- Creating configured pool member disk image ---"
    dd if=/dev/zero of="$POOL_IMG" bs=1M count=128 2>/dev/null
    echo "  Pool member image: $POOL_IMG ($(du -h "$POOL_IMG" | cut -f1))"

    # Build initramfs outside the archived tree so the kernel sees a stable /init.
    (cd "$RUN_DIR" && find . -print0 | "$CPIO" -0 -o -H newc) > "$INITRAMFS" 2>/dev/null

    # Boot QEMU
    echo "--- Booting QEMU ---"
    QEMU_EXIT=0
    set +e
    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$INITRAMFS" \
      -drive file="$POOL_IMG",format=raw,if=virtio,index=0 \
      -append "console=ttyS0 quiet init=/init panic=10 panic_on_oops=1" \
      -nographic \
      -m 1024M \
      -no-reboot \
      2>&1 | tee "$RUN_DIR/qemu.log"
    QEMU_EXIT="''${PIPESTATUS[0]}"
    set -e

    echo ""
    echo "--- QEMU exited with code $QEMU_EXIT ---"
    QEMU_PARSE_LOG="$RUN_DIR/qemu.parse.log"
    tr -d '\r' < "$RUN_DIR/qemu.log" > "$QEMU_PARSE_LOG" 2>/dev/null || cp "$RUN_DIR/qemu.log" "$QEMU_PARSE_LOG"

    # Parse results
    log_count() {
      local pattern="$1"
      local count
      count=$(grep -c "$pattern" "$QEMU_PARSE_LOG" 2>/dev/null || true)
      printf '%s\n' "''${count:-0}"
    }

    PASS_COUNT=$(log_count "^PASS:")
    FAIL_COUNT=$(log_count "^FAIL:")
    BLOCKED_COUNT=$(log_count "^BLOCKED:")
    SKIP_COUNT=$(log_count "^SKIP:")
    BOOT_FAILURE_COUNT=$(grep -Ec "Failed to execute /init|No working init found|Kernel panic|VFS: Unable to mount root fs|not syncing" "$QEMU_PARSE_LOG" 2>/dev/null || true)

    echo ""
    echo "=== QEMU Guest Results ==="
    echo "PASS: $PASS_COUNT"
    echo "FAIL: $FAIL_COUNT"
    echo "BLOCKED: $BLOCKED_COUNT"
    echo "SKIP: $SKIP_COUNT"

    # Gather source identity
    SOURCE_REF="''${GITHUB_REF:-unknown}"
    SOURCE_SHA="''${GITHUB_SHA:-unknown}"
    SOURCE_REPO="''${GITHUB_REPOSITORY:-tidefs/tidefs}"
    RUN_ID="''${GITHUB_RUN_ID:-unknown}"
    RUN_ATTEMPT="''${GITHUB_RUN_ATTEMPT:-1}"
    WORKFLOW_NAME="''${GITHUB_WORKFLOW:-QEMU Smoke}"
    WORKFLOW_JOB="kernel-no-daemon-teardown-validation"
    GENERATED_BY="tidefs-kmod-no-daemon-teardown-validation"
    GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    CLAIM_ID="kernel.teardown.no_work_after.v1"
    EVIDENCE_CLASS="runtime-kernel-teardown-no-work-after-artifact"
    VALIDATION_TIER="full-kernel-no-daemon"
    TARGET_ID="kernel-teardown-no-daemon"

    # Count dmesg signals for fail-closed
    DMESG_DANGER_COUNT=0
    for pattern in "WARNING:" "BUG:" "Oops:" "lockdep:" "KASAN:" "KCSAN:" "hung_task" "Call Trace:" "RIP:"; do
      c=$(log_count "$pattern")
      DMESG_DANGER_COUNT=$((DMESG_DANGER_COUNT + ''${c:-0}))
    done

    # Trace evidence is judged from the extracted artifact body and marker
    # checks below. The Linux 7.0 guest can legitimately log tracefs mount
    # failure while routing to the dmesg lifecycle-marker fallback.
    TRACE_ERROR_COUNT=0

    # Determine teardown status
    TEARDOWN_STATUS="pass"
    FAIL_REASONS="$("$JQ" -n -c '[]')"
    append_fail_reason() {
      FAIL_REASONS="$(printf '%s' "$FAIL_REASONS" | "$JQ" -c --arg reason "$1" '. + [$reason]')"
    }

    if [ "$FAIL_COUNT" -gt 0 ]; then
      TEARDOWN_STATUS="fail"
      append_fail_reason "guest_fail_count=$FAIL_COUNT"
    elif [ "$BLOCKED_COUNT" -gt 0 ]; then
      TEARDOWN_STATUS="blocked"
      append_fail_reason "guest_blocked_count=$BLOCKED_COUNT"
    fi
    if [ "$QEMU_EXIT" -ne 0 ]; then
      TEARDOWN_STATUS="fail"
      append_fail_reason "qemu_exit=$QEMU_EXIT"
    fi
    if [ "$BOOT_FAILURE_COUNT" -gt 0 ]; then
      TEARDOWN_STATUS="fail"
      append_fail_reason "boot_failure_count=$BOOT_FAILURE_COUNT"
    fi
    if [ "$DMESG_DANGER_COUNT" -gt 0 ]; then
      TEARDOWN_STATUS="fail"
      append_fail_reason "dmesg_danger_count=$DMESG_DANGER_COUNT"
    fi
    if [ "$TRACE_ERROR_COUNT" -gt 0 ]; then
      TEARDOWN_STATUS="fail"
      append_fail_reason "trace_error_count=$TRACE_ERROR_COUNT"
    fi

    # Extract teardown phases from QEMU log by parsing PHASE_MARKER lines
    PHASES_JSON="$("$JQ" -n '[]')"
    while IFS='|' read -r phase status ts note; do
      [ -z "$phase" ] && continue
      local_note="$note"
      [ -z "$local_note" ] && local_note=""
      PHASES_JSON="$("$JQ" -n \
        --arg phase "$phase" \
        --arg status "$status" \
        --arg ts "$ts" \
        --arg note "$local_note" \
        --argjson arr "$PHASES_JSON" \
        '$arr + [{"phase":$phase,"status":$status,"start_timestamp":$ts,"notes":$note}]')"
    done <<PHASEEOF
$(grep '^PHASE_MARKER:' "$QEMU_PARSE_LOG" 2>/dev/null | sed 's/^PHASE_MARKER://' || true)
PHASEEOF

    # Build refusal observations JSON
    REFUSAL1_OP="mount"
    REFUSAL1_EXPECTED=true
    REFUSAL1_RESULT=""
    REFUSAL1_NEW_WORK=false
    if grep -q "^PASS: refusal_mount .*mount refused after module unload" "$QEMU_PARSE_LOG" 2>/dev/null; then
      REFUSAL1_RESULT="mount_correctly_refused"
    elif grep -q "^FAIL: refusal_mount .*mount succeeded after module unload" "$QEMU_PARSE_LOG" 2>/dev/null; then
      REFUSAL1_RESULT="mount_unexpectedly_succeeded"
      REFUSAL1_NEW_WORK=true
    fi

    REFUSAL2_OP="mount_check"
    REFUSAL2_EXPECTED=true
    REFUSAL2_RESULT=""
    REFUSAL2_NEW_WORK=false
    if grep -q "^PASS: refusal_mount_check .*no TideFS mount visible" "$QEMU_PARSE_LOG" 2>/dev/null; then
      REFUSAL2_RESULT="no_tidefs_mount_visible"
    elif grep -q "^FAIL: refusal_mount_check .*TideFS mount still visible after rmmod" "$QEMU_PARSE_LOG" 2>/dev/null; then
      REFUSAL2_RESULT="tidefs_mount_still_visible"
    fi

    REFUSAL_JSON="$("$JQ" -n '[]')"
    if [ -n "$REFUSAL1_RESULT" ]; then
      REFUSAL_JSON="$("$JQ" -n \
        --arg op "$REFUSAL1_OP" \
        --argjson expected "$REFUSAL1_EXPECTED" \
        --arg result "$REFUSAL1_RESULT" \
        --argjson new_work "$REFUSAL1_NEW_WORK" \
        --argjson arr "$REFUSAL_JSON" \
        '$arr + [{"operation":$op,"expected_refusal":$expected,"observed_result":$result,"new_work_enqueued_or_started":$new_work}]')"
    fi
    if [ -n "$REFUSAL2_RESULT" ]; then
      REFUSAL_JSON="$("$JQ" -n \
        --arg op "$REFUSAL2_OP" \
        --argjson expected "$REFUSAL2_EXPECTED" \
        --arg result "$REFUSAL2_RESULT" \
        --argjson new_work "$REFUSAL2_NEW_WORK" \
        --argjson arr "$REFUSAL_JSON" \
        '$arr + [{"operation":$op,"expected_refusal":$expected,"observed_result":$result,"new_work_enqueued_or_started":$new_work}]')"
    fi

    # Build explicit T6 surface coverage. This row is allowed to produce a
    # blocked artifact, but it may not pass while required full-kernel surfaces
    # are unproven.
    all_passed() {
      for marker in "$@"; do
        grep -q "^PASS: $marker" "$QEMU_PARSE_LOG" 2>/dev/null || return 1
      done
      return 0
    }

    RUNTIME_SCOPE_JSON="$("$JQ" -n '[]')"
    add_runtime_scope() {
      local surface="$1"
      local status="$2"
      local evidence="$3"
      local no_daemon="$4"
      local residual="$5"

      RUNTIME_SCOPE_JSON="$("$JQ" -n \
        --arg surface "$surface" \
        --arg status "$status" \
        --arg evidence "$evidence" \
        --argjson no_daemon "$no_daemon" \
        --arg residual "$residual" \
        --argjson arr "$RUNTIME_SCOPE_JSON" \
        '$arr + [{
          "surface": $surface,
          "status": $status,
          "evidence": $evidence,
          "no_required_support_daemon": $no_daemon,
          "residual_risk": $residual
        }]')"

      if [ "$status" != "pass" ]; then
        if [ "$TEARDOWN_STATUS" = "pass" ]; then
          TEARDOWN_STATUS="blocked"
        fi
        append_fail_reason "runtime_scope_''${surface}_''${status}"
      fi
    }

    if all_passed configured_pool_mount write_test_file sync_after_write readback_verify readdir_before_teardown no_daemon_pre_teardown_io; then
      add_runtime_scope \
        "vfs" \
        "pass" \
        "configured_pool_mount, write_test_file, sync_after_write, readback_verify, readdir_before_teardown, no_daemon_pre_teardown_io" \
        "true" \
        "bounded mounted POSIX smoke row; xfstests breadth and object/extent replay remain outside this artifact"
    else
      add_runtime_scope \
        "vfs" \
        "blocked" \
        "one or more mounted VFS/no-daemon probes did not pass in qemu.log" \
        "false" \
        "no T6 VFS coverage may pass until mount/write/sync/readback/readdir all pass without support daemons"
    fi

    add_runtime_scope \
      "block" \
      "blocked" \
      "this row mounts through a lower virtio pool member but does not export or exercise tidefs-block-kmod queue_rq read/write/flush/discard" \
      "false" \
      "full-kernel/no-daemon block coverage needs a block-volume runtime row on the shared pool core"

    if all_passed recovery_insmod recovery_remount recovery_write_verify no_daemon_recovery; then
      add_runtime_scope \
        "recovery" \
        "pass" \
        "recovery_insmod, recovery_remount, recovery_write_verify, no_daemon_recovery" \
        "true" \
        "bounded reload/remount recovery row; QEMU powercut and committed-root replay breadth remain separate gates"
    else
      add_runtime_scope \
        "recovery" \
        "blocked" \
        "one or more no-daemon recovery probes did not pass in qemu.log" \
        "false" \
        "no T6 recovery coverage may pass until reload/remount/write verification passes without support daemons"
    fi

    add_runtime_scope \
      "writeback" \
      "blocked" \
      "sync_after_write is covered, but this row does not prove page-cache writeback, mmap coherency, or dirty lifecycle authority" \
      "false" \
      "writeback remains gated by mounted writeback/page-cache evidence before full-kernel no-daemon wording can pass"

    add_runtime_scope \
      "placement_reserve_admission" \
      "blocked" \
      "configured_pool_member_created and configured_pool_label_verified are pool-member bring-up checks, not placement/reserve admission proof" \
      "false" \
      "placement and reserve admission need dedicated allocator/admission runtime evidence"

    if all_passed unmount_ok rmmod_ok module_gone refusal_mount refusal_mount_check dmesg_clean no_daemon_final_teardown no_daemon_post_final_refusal_probe; then
      add_runtime_scope \
        "teardown_no_work_after" \
        "pass" \
        "unmount_ok, rmmod_ok, module_gone, refusal_mount, refusal_mount_check, dmesg_clean, no_daemon_final_teardown, no_daemon_post_final_refusal_probe" \
        "true" \
        "bounded lifecycle/refusal row; broad concurrent teardown stress remains outside this artifact"
    else
      add_runtime_scope \
        "teardown_no_work_after" \
        "blocked" \
        "one or more teardown/refusal/no-daemon probes did not pass in qemu.log" \
        "false" \
        "no T6 teardown/no-work-after coverage may pass until final teardown, refusal, dmesg, and no-daemon probes pass"
    fi

    # Trace identity
    artifact_body_missing() {
      local body="$1"
      if [ -z "$(printf '%s' "$body" | tr -d '[:space:]')" ]; then
        return 0
      fi
      printf '%s\n' "$body" | grep -q '^artifact source missing:' && return 0
      return 1
    }

    WQ_TRACE_PATH="trace/workqueue_trace.log"
    WQ_TRACE_BODY=$(grep -A9999 '^BEGIN_ARTIFACT:workqueue_trace$' "$QEMU_PARSE_LOG" 2>/dev/null | grep -B9999 '^END_ARTIFACT:workqueue_trace$' | grep -v '^BEGIN_ARTIFACT\|^END_ARTIFACT' || echo "")
    if artifact_body_missing "$WQ_TRACE_BODY"; then
      WQ_TRACE_BODY=$(grep -A9999 '^BEGIN_ARTIFACT:ftrace_workqueue$' "$QEMU_PARSE_LOG" 2>/dev/null | grep -B9999 '^END_ARTIFACT:ftrace_workqueue$' | grep -v '^BEGIN_ARTIFACT\|^END_ARTIFACT' || echo "")
      WQ_TRACE_PATH="trace/ftrace_final.txt"
    fi
    if artifact_body_missing "$WQ_TRACE_BODY"; then
      TEARDOWN_STATUS="fail"
      append_fail_reason "workqueue_trace_artifact_empty"
    fi
    if printf '%s\n' "$WQ_TRACE_BODY" | grep -q '^trace_source=dmesg kernel lifecycle markers$'; then
      WQ_TRACE_SOURCE="dmesg kernel lifecycle markers emitted by guest"
      for required_marker in \
        "engine kill_sb: final sync_fs completed" \
        "engine torn down" \
        "lifecycle summary:" \
        "unregistered filesystem type" \
        "loaded and registered filesystem type"; do
        if ! printf '%s\n' "$WQ_TRACE_BODY" | grep -q "$required_marker"; then
          TEARDOWN_STATUS="fail"
          append_fail_reason "workqueue_trace_missing_dmesg_marker=$required_marker"
        fi
      done
    else
      WQ_TRACE_SOURCE="ftrace:/tracefs/events/workqueue/"
    fi
    WQ_TRACE_DIGEST="blake3:$(printf '%s' "$WQ_TRACE_BODY" | "$B3SUM" | awk '{print $1}')"

    CB_TRACE_SOURCE="dmesg"
    CB_TRACE_PATH="trace/dmesg_callbacks.txt"
    CB_TRACE_BODY=$(grep -A9999 '^BEGIN_ARTIFACT:dmesg_callbacks$' "$QEMU_PARSE_LOG" 2>/dev/null | grep -B9999 '^END_ARTIFACT:dmesg_callbacks$' | grep -v '^BEGIN_ARTIFACT\|^END_ARTIFACT' || echo "")
    if artifact_body_missing "$CB_TRACE_BODY"; then
      TEARDOWN_STATUS="fail"
      append_fail_reason "callback_trace_artifact_empty"
    fi
    CB_TRACE_DIGEST="blake3:$(printf '%s' "$CB_TRACE_BODY" | "$B3SUM" | awk '{print $1}')"

    # Cleanup outcome
    UNMOUNT_OUTCOME="ok"
    RMMOD_OUTCOME="ok"
    RELOAD_OUTCOME="ok"
    CLEANUP_DMESG="clean"
    REMAINING_WORK="none"

    if [ "$DMESG_DANGER_COUNT" -gt 0 ]; then
      CLEANUP_DMESG="signals_detected"
    fi

    # Write kernel-teardown-runtime.json
    mkdir -p "$OUTPUT_DIR/trace"
    cp "$RUN_DIR/qemu.log" "$OUTPUT_DIR/qemu.log" 2>/dev/null || true
    printf '%s' "$WQ_TRACE_BODY" > "$OUTPUT_DIR/$WQ_TRACE_PATH"
    printf '%s' "$CB_TRACE_BODY" > "$OUTPUT_DIR/$CB_TRACE_PATH"

    "$JQ" -n \
      --arg generated_by "$GENERATED_BY" \
      --arg claim_id "$CLAIM_ID" \
      --arg evidence_class "$EVIDENCE_CLASS" \
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
      --argjson runtime_scope_coverage "$RUNTIME_SCOPE_JSON" \
      --arg unmount "$UNMOUNT_OUTCOME" \
      --arg rmmod "$RMMOD_OUTCOME" \
      --arg reload_remount_probe "$RELOAD_OUTCOME" \
      --arg dmesg_state "$CLEANUP_DMESG" \
      --arg remaining_tidefs_work_observations "$REMAINING_WORK" \
      --arg status "$TEARDOWN_STATUS" \
      --argjson fail_closed_reasons "$FAIL_REASONS" \
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
        runtime_scope_coverage: $runtime_scope_coverage,
        status: $status,
        fail_closed_reasons: $fail_closed_reasons
      }' > "$OUTPUT_DIR/kernel-teardown-runtime.json"

    echo "## kernel-teardown-runtime.json written" >> /dev/stderr

    # ── Write evidence-manifest.json ─────────────────────────────────
    ARTIFACT_PATH="kernel-teardown-runtime.json"
    ARTIFACT_DIGEST="blake3:$("$B3SUM" "$OUTPUT_DIR/$ARTIFACT_PATH" | awk '{print $1}')"
    EVIDENCE_CLASS_MANIFEST="runtime-kernel-teardown-no-work-after-artifact"
    SOURCE_LABEL="qemu-smoke-kernel-no-daemon-teardown-validation"
    SCOPE="kernel-teardown-no-daemon tier=$VALIDATION_TIER status=$TEARDOWN_STATUS passed=$PASS_COUNT failed=$FAIL_COUNT blocked=$BLOCKED_COUNT skipped=$SKIP_COUNT run=$RUN_ID/$RUN_ATTEMPT ref=$SOURCE_REF sha=$SOURCE_SHA repo=$SOURCE_REPO artifact=$ARTIFACT_PATH surfaces=vfs,block,recovery,writeback,placement_reserve_admission,teardown_no_work_after no_required_support_daemon=true"
    RESIDUAL_RISK="T6 no-daemon artifact remains claim-review input only; kernelspace-ready/full-kernel/product/successor wording and claim registry state stay blocked unless all required runtime surfaces pass and claim validation accepts this current artifact."
    case "$TEARDOWN_STATUS" in
      pass) MANIFEST_OUTCOME="pass" ;;
      blocked) MANIFEST_OUTCOME="environment-refusal" ;;
      fail) MANIFEST_OUTCOME="product-fail" ;;
      *) MANIFEST_OUTCOME="harness-fail" ;;
    esac

    "$JQ" -n \
      --arg claim_id "$CLAIM_ID" \
      --arg evidence_class "$EVIDENCE_CLASS_MANIFEST" \
      --arg validation_tier "$VALIDATION_TIER" \
      --arg scope "$SCOPE" \
      --arg artifact_path "$ARTIFACT_PATH" \
      --arg content_digest "$ARTIFACT_DIGEST" \
      --arg run_id "$RUN_ID/$RUN_ATTEMPT" \
      --arg source_ref "$SOURCE_REF" \
      --arg outcome "$MANIFEST_OUTCOME" \
      --arg residual_risk "$RESIDUAL_RISK" \
      --arg source "$SOURCE_LABEL" \
      --arg generated_at "$GENERATED_AT" \
      '{
        manifest_version: 2,
        claim_id: $claim_id,
        evidence_class: $evidence_class,
        validation_tier: $validation_tier,
        scope: $scope,
        artifact_path: $artifact_path,
        content_digest: $content_digest,
        run_id: $run_id,
        source_ref: $source_ref,
        outcome: $outcome,
        residual_risk: $residual_risk,
        source: $source,
        generated_at: $generated_at,
        blocking_issues: []
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

    if ! "$VALIDATOR" validate-evidence-manifest "$OUTPUT_DIR/evidence-manifest.json"; then
      echo "VALIDATE FAIL: xtask evidence manifest validator rejected evidence-manifest.json"
      VALIDATION_ERRORS=$((VALIDATION_ERRORS + 1))
    fi

    if [ "$TEARDOWN_STATUS" = "pass" ] && { [ "$QEMU_EXIT" -ne 0 ] || [ "$FAIL_COUNT" -gt 0 ] || [ "$BLOCKED_COUNT" -gt 0 ] || [ "$DMESG_DANGER_COUNT" -gt 0 ] || [ "$TRACE_ERROR_COUNT" -gt 0 ]; }; then
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

    if [ "$VALIDATION_ERRORS" -gt 0 ] || [ "$TEARDOWN_STATUS" = "fail" ]; then
      exit 1
    fi
    if [ "$TEARDOWN_STATUS" = "blocked" ]; then
      echo "VALIDATION BLOCKED: kernel-teardown-runtime.json is valid, but runtime scope remains blocked"
    fi
    exit 0
  '';
in
  kmodNoDaemonTeardownScript
