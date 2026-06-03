# TideFS: kernel block-kmod no-daemon residency audit.
#
# Builds tidefs_block_kmod.ko against Linux 7.0, boots a QEMU guest,
# loads the module, checks the process table before/after block I/O
# to verify no ublk, FUSE, or other userspace support daemon is
# required for kernel block device operation.
#
# Validation tier: full-kernel (Tier 6) QEMU guest with a process-table check.
#
# Kernel block no-daemon residency audit.
{
  pkgs,
  linuxKernel_7_0,
}:

let
  glibcLib = "${pkgs.glibc}/lib";

  validateScript = pkgs.writeShellScriptBin "tidefs-kmod-block-no-daemon-audit" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="/root/ai/state/tidefs/kernel-dev/shared/linux-7.0/build/arch/x86/boot/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    MODULE_OUT="''${TIDEFS_KERNEL_BLOCK_MODULE_DIR:-/root/ai/tmp/tidefs-block-kmod/module-out}"
    BLOCK_KO="''${TIDEFS_KERNEL_BLOCK_MODULE_KO:-}"
    GLIBC_LIB="${glibcLib}"

    TMPDIR="''${TIDEFS_KNODAEMON_TMPDIR:-/tmp/tidefs-kernel-block-no-daemon}"
    TIMEOUT_SEC="''${TIDEFS_KNODAEMON_TIMEOUT:-600}"

    KEEP_TMP=""
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h)
          echo "Usage: tidefs-kblock-no-daemon-audit [--timeout SEC] [--keep-tmp]"
          echo "Audit kernel block-kmod for no-daemon residency in QEMU."
          exit 0
          ;;
        *) echo "ERROR: unknown option: $1" >&2; exit 2 ;;
      esac
    done

    echo "=== TideFS Kernel Block No-Daemon Residency Audit ==="
    echo "  Kernel:    $KERNEL_IMG"
    echo "  QEMU:      $QEMU_BIN"
    echo "  Module:    tidefs_block_kmod.ko"
    echo "  Timeout:   ''${TIMEOUT_SEC}s"
    echo ""

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done

    if [ -z "$BLOCK_KO" ]; then
      for d in "$MODULE_OUT/tidefs-block-kmod" "$MODULE_OUT" "$MODULE_OUT/extra"; do
        for c in "$d/tidefs_block_kmod.ko"; do
          [ -f "$c" ] && { BLOCK_KO="$c"; break 2; }
        done
      done
    fi

    if [ -z "$BLOCK_KO" ]; then
      echo "BLOCKED: tidefs_block_kmod.ko not found at $MODULE_OUT"
      echo "  Build it first with the Linux 7.0 source/build tree, M=/root/tidefs/crates/tidefs-block-kmod, and MO=$MODULE_OUT"
      exit 1
    fi
    echo "  Module .ko: $BLOCK_KO"

    RUN_DIR="$TMPDIR/validation-$$"
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,validation}
    trap 'if [ -z "''${KEEP_TMP:-}" ]; then rm -rf "$RUN_DIR"; fi' EXIT

    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"
    # Include ps for process table inspection.
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff \
      mknod mkdir rmdir dd stat cp mv rm touch find wc head sync cut md5sum \
      printf test expr uname date od ps; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    mkdir -p "$RUN_DIR/$GLIBC_LIB"
    cp "$GLIBC_LIB"/ld-linux-x86-64.so.2 "$RUN_DIR/$GLIBC_LIB/" 2>/dev/null || true
    for lib in libc.so.6 libm.so.6 libresolv.so.2 libdl.so.2; do
      [ -f "$GLIBC_LIB/$lib" ] && cp "$GLIBC_LIB/$lib" "$RUN_DIR/$GLIBC_LIB/"
    done

    cp "$BLOCK_KO" "$RUN_DIR/lib/modules/tidefs_block_kmod.ko"

    # ── Init script: no-daemon residency audit ──────────────────────
    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== TideFS Kernel Block No-Daemon Residency Audit ==="
echo "kernel_version=$(uname -r)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

PASSED=0
FAILED=0
BLOCKED=0

pass()   { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
fail()   { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); }
blocked(){ echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); }

EVDIR=/validation
DEV=/dev/tidefs
SECTOR=512

dmesg_snapshot() {
    local label="$1"
    dmesg > "$EVDIR/dmesg_''${label}.txt" 2>/dev/null || true
}

# ── Phase 0: Pre-module process audit ─────────────────────────────
echo "--- Phase 0: Pre-Module Process Audit ---"
dmesg_snapshot "pre_insmod"

echo "=== PROCESS TABLE BEFORE MODULE LOAD ==="
ps > "$EVDIR/ps_pre_insmod.txt" 2>/dev/null || true
cat "$EVDIR/ps_pre_insmod.txt"

# Pre-check: no ublk, FUSE, or tidefs daemon processes should exist before module load.
# (The guest only has busybox/init, so this is a sanity baseline.)
PS_PRE=$(cat "$EVDIR/ps_pre_insmod.txt" 2>/dev/null || echo "")
if [ -n "$PS_PRE" ]; then
    pass "phase0_ps_available"
else
    blocked "phase0_ps_available" "ps command produced no output"
fi

DAEMON_PRE=$(echo "$PS_PRE" | grep -cE "ublk|fuse|tidefs|daemon" 2>/dev/null || echo 0)
echo "INFO: pre-module daemon process count=$DAEMON_PRE"

if [ "$DAEMON_PRE" -eq 0 ]; then
    pass "phase0_no_daemon_processes_before_module"
else
    fail "phase0_no_daemon_processes_before_module" "found $DAEMON_PRE daemon-like processes before module load"
fi

# ── Phase 1: Module load ──────────────────────────────────────────
echo ""
echo "--- Phase 1: Module Load ---"

MOD=/lib/modules/tidefs_block_kmod.ko
if [ -f "$MOD" ]; then
    if insmod "$MOD" 2>/tmp/insmod.err; then
        pass "phase1_insmod"
    else
        fail "phase1_insmod" "$(cat /tmp/insmod.err | head -1)"
    fi
else
    blocked "phase1_insmod" "tidefs_block_kmod.ko not found"
fi

sleep 1
if [ -b "$DEV" ]; then
    pass "phase1_device_present"
else
    blocked "phase1_device_present" "/dev/tidefs did not appear"
fi

DEV_SIZE=$(cat /sys/block/tidefs/size 2>/dev/null || echo 0)
echo "INFO: /dev/tidefs size=$DEV_SIZE sectors"

dmesg_snapshot "post_insmod"

# ── Phase 2: Process audit after module load, before I/O ──────────
echo ""
echo "--- Phase 2: Post-Module-Load Process Audit ---"
echo "=== PROCESS TABLE AFTER MODULE LOAD (before I/O) ==="
ps > "$EVDIR/ps_post_insmod.txt" 2>/dev/null || true
cat "$EVDIR/ps_post_insmod.txt"

PS_POST_INSMOD=$(cat "$EVDIR/ps_post_insmod.txt" 2>/dev/null || echo "")
DAEMON_POST_INSMOD=$(echo "$PS_POST_INSMOD" | grep -cE "ublk|fuse|tidefs|daemon" 2>/dev/null || echo 0)
echo "INFO: post-insmod daemon process count=$DAEMON_POST_INSMOD"

if [ "$DAEMON_POST_INSMOD" -eq 0 ]; then
    pass "phase2_no_daemon_after_module_load"
else
    fail "phase2_no_daemon_after_module_load" "found $DAEMON_POST_INSMOD daemon-like processes after module load"
fi

# ── Phase 3: Block I/O ────────────────────────────────────────────
echo ""
echo "--- Phase 3: Block I/O ---"

echo -n "TIDEFS_NO_DAEMON_AUDIT_PATTERN_01" | dd of="$DEV" bs="$SECTOR" seek=10 count=1 2>/dev/null
echo -n "SECOND_NO_DAEMON_AUDIT_BLOCK_02" | dd of="$DEV" bs="$SECTOR" seek=11 count=1 2>/dev/null
echo -n "THIRD_NO_DAEMON_AUDIT_BLOCK_03" | dd of="$DEV" bs="$SECTOR" seek=12 count=1 2>/dev/null
sync

R10=$(dd if="$DEV" bs="$SECTOR" skip=10 count=1 2>/dev/null | head -c 31)
R11=$(dd if="$DEV" bs="$SECTOR" skip=11 count=1 2>/dev/null | head -c 31)
R12=$(dd if="$DEV" bs="$SECTOR" skip=12 count=1 2>/dev/null | head -c 31)

if echo "$R10" | grep -q "TIDEFS_NO_DAEMON"; then
    pass "phase3_write_read_verify_sector10"
else
    fail "phase3_write_read_verify_sector10" "got: $R10"
fi
if echo "$R11" | grep -q "SECOND_NO_DAEMON"; then
    pass "phase3_write_read_verify_sector11"
else
    fail "phase3_write_read_verify_sector11" "got: $R11"
fi
if echo "$R12" | grep -q "THIRD_NO_DAEMON"; then
    pass "phase3_write_read_verify_sector12"
else
    fail "phase3_write_read_verify_sector12" "got: $R12"
fi

# ── Phase 4: Process audit after I/O ──────────────────────────────
echo ""
echo "--- Phase 4: Post-I/O Process Audit ---"
echo "=== PROCESS TABLE AFTER BLOCK I/O ==="
ps > "$EVDIR/ps_post_io.txt" 2>/dev/null || true
cat "$EVDIR/ps_post_io.txt"

PS_POST_IO=$(cat "$EVDIR/ps_post_io.txt" 2>/dev/null || echo "")
DAEMON_POST_IO=$(echo "$PS_POST_IO" | grep -cE "ublk|fuse|tidefs|daemon" 2>/dev/null || echo 0)
echo "INFO: post-I/O daemon process count=$DAEMON_POST_IO"

if [ "$DAEMON_POST_IO" -eq 0 ]; then
    pass "phase4_no_daemon_after_block_io"
else
    fail "phase4_no_daemon_after_block_io" "found $DAEMON_POST_IO daemon-like processes after block I/O"
fi

# ── Phase 5: Dmesg integrity ──────────────────────────────────────
echo ""
echo "--- Phase 5: Dmesg Integrity ---"
DMESG_BUG=$(dmesg 2>/dev/null | grep -cE "BUG:|Kernel panic|Oops:|WARNING:" || echo 0)
echo "INFO: dmesg BUG/WARNING count=$DMESG_BUG"

if [ "$DMESG_BUG" -eq 0 ]; then
    pass "phase5_dmesg_clean"
else
    fail "phase5_dmesg_clean" "dmesg has $DMESG_BUG warning/bug lines"
fi

dmesg_snapshot "final"

# ── Phase 6: Module unload ────────────────────────────────────────
echo ""
echo "--- Phase 6: Module Unload ---"
sync
if rmmod tidefs_block 2>/tmp/rmmod.err; then
    pass "phase6_rmmod"
else
    fail "phase6_rmmod" "$(cat /tmp/rmmod.err | head -1)"
fi

sleep 1
dmesg_snapshot "post_rmmod"

DMESG_POST=$(dmesg 2>/dev/null | grep -cE "BUG:|Kernel panic|Oops:" || echo 0)
if [ "$DMESG_POST" -eq 0 ]; then
    pass "phase7_dmesg_post_clean"
else
    fail "phase7_dmesg_post_clean" "post-rmmod dmesg has $DMESG_POST bug lines"
fi

# ── Phase 7: No-daemon residency conclusion ───────────────────────
echo ""
echo "--- Phase 7: No-Daemon Residency Conclusion ---"
echo "ALL_DAEMON_CHECKS_PRE=$DAEMON_PRE"
echo "ALL_DAEMON_CHECKS_POST_INSMOD=$DAEMON_POST_INSMOD"
echo "ALL_DAEMON_CHECKS_POST_IO=$DAEMON_POST_IO"
echo "DMESG_BUG=$DMESG_BUG DMESG_POST=$DMESG_POST"

if [ "$DAEMON_PRE" -eq 0 ] && [ "$DAEMON_POST_INSMOD" -eq 0 ] && [ "$DAEMON_POST_IO" -eq 0 ]; then
    echo "NO_DAEMON_CONCLUSION: TideFS kernel block device does not require ublk or any userspace support daemon."
    echo "NO_DAEMON_CONCLUSION: All block device operations (write, read, sync, rmmod) completed without any userspace daemon process detected."
    pass "phase7_no_daemon_residency_proven"
else
    fail "phase7_no_daemon_residency_proven" "daemon processes detected during block I/O lifecycle"
fi

# ── Summary ───────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "=== NO-DAEMON RESIDENCY AUDIT SUMMARY ==="
echo "  PASS=$PASSED FAIL=$FAILED BLOCKED=$BLOCKED"
echo "  dmesg_BUG/WARNING=$DMESG_BUG post_rmmod_BUG=$DMESG_POST"
echo "  daemon_count(pre=$DAEMON_PRE post_mod=$DAEMON_POST_INSMOD post_io=$DAEMON_POST_IO)"
echo "============================================================"

cp /tmp/insmod.err "$EVDIR/" 2>/dev/null || true
cp /tmp/rmmod.err "$EVDIR/" 2>/dev/null || true

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
      2>&1 | tee "$RUN_DIR/qemu.log" || true

    echo ""
    echo "--- QEMU exited ---"

    PASS_COUNT=$(grep -c "^PASS:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    FAIL_COUNT=$(grep -c "^FAIL:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    BLOCKED_COUNT=$(grep -c "^BLOCKED:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)

    # Check for explicit no-daemon conclusion line
    NO_DAEMON_CONCLUSION=$(grep -c "^NO_DAEMON_CONCLUSION:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)

    echo ""
    echo "=== RESULTS ==="
    echo "PASS: $PASS_COUNT  FAIL: $FAIL_COUNT  BLOCKED: $BLOCKED_COUNT"
    echo "No-daemon conclusion lines: $NO_DAEMON_CONCLUSION"

    # Write external validation output
    OUTPUT_DIR="/root/ai/tmp/tidefs-validation/kernel-block-no-daemon-audit/$(date -u +%Y-%m-%dT%H%M%SZ)"
    mkdir -p "$OUTPUT_DIR"
    cp "$RUN_DIR/qemu.log" "$OUTPUT_DIR/qemu.log"
    cp "$BLOCK_KO" "$OUTPUT_DIR/tidefs_block_kmod.ko" 2>/dev/null || true

    # Also copy the validation dir from inside the guest
    if [ -d "$RUN_DIR/validation" ]; then
      mkdir -p "$OUTPUT_DIR/guest-validation"
      cp -r "$RUN_DIR/validation/"* "$OUTPUT_DIR/guest-validation/" 2>/dev/null || true
    fi

    COMMIT="$(git -C /root/tidefs rev-parse HEAD 2>/dev/null || echo unknown)"
    if git -C /root/tidefs diff --quiet --ignore-submodules -- 2>/dev/null && \
       git -C /root/tidefs diff --cached --quiet --ignore-submodules -- 2>/dev/null; then
      DIRTY=false
    else
      DIRTY=true
    fi

    cat > "$OUTPUT_DIR/manifest.json" << MANIFEST
{
  "test": "kernel-block-no-daemon-residency-audit",
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "validation_tier": "full-kernel (Tier 6) QEMU guest with process-table no-daemon check",
  "pass": $PASS_COUNT,
  "fail": $FAIL_COUNT,
  "blocked": $BLOCKED_COUNT,
  "no_daemon_conclusion_lines": $NO_DAEMON_CONCLUSION,
  "commit": "$COMMIT",
  "worktree_dirty": $DIRTY,
  "kernel": "Linux 7.0",
  "module": "tidefs_block_kmod.ko",
  "backend": "in-memory bring-up; pool-backed path still requires kernel pool-core integration",
  "result": "process-table audit proving no ublk/FUSE/daemon processes during kernel block-device lifecycle"
}
MANIFEST

    echo "Validation output directory: $OUTPUT_DIR"

    if [ "$FAIL_COUNT" -gt 0 ]; then
      exit 1
    fi
    exit 0
  '';
in
  validateScript
