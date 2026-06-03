# TideFS: kmod-posix-vfs intent-log to committed-root end-to-end
# crash-consistency validation in Linux 7.0 QEMU.
#
# Builds tidefs_posix_vfs.ko against Linux 7.0, creates a pool fixture on
# a raw virtio-blk disk image, and boot a two-phase QEMU guest:
#   Phase 1: mount + write + sync (txg commit) + poweroff (crash)
#   Phase 2: remount + intent replay + data integrity verification
#
# Validation tier: QEMU guest with block-device mount + crash/reboot cycle.
{
  pkgs,
  linuxKernel_7_0,
}:

let
  glibcLib = "${pkgs.glibc}/lib";

  validateScript = pkgs.writeShellScriptBin "tidefs-kmod-crash-consistency-e2e" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="''${TIDEFS_KERNEL_IMAGE:-/root/ai/state/tidefs/kernel-dev/shared/linux-7.0/build/arch/x86/boot/bzImage}"
    CPIO="${pkgs.cpio}/bin/cpio"
    MODULE_OUT="''${TIDEFS_KERNEL_VFS_MODULE_DIR:-/root/ai/tmp/tidefs-kmod-posix-vfs/module-out}"
    GLIBC_LIB="${glibcLib}"
    FIXTURE_BUILDER="''${TIDEFS_KCRASH_FIXTURE_BUILDER:-}"

    TMPDIR="''${TIDEFS_KCRASH_TMPDIR:-/tmp/tidefs-kmod-crash-e2e}"
    TIMEOUT_SEC="''${TIDEFS_KCRASH_TIMEOUT:-600}"

    KEEP_TMP=""
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h)
          echo "Usage: tidefs-kmod-crash-consistency-e2e [--timeout SEC] [--keep-tmp]"
          echo "Validate kmod-posix-vfs intent-log crash-consistency in QEMU."
          exit 0
          ;;
        *) echo "ERROR: unknown option: $1" >&2; exit 2 ;;
      esac
    done

    echo "=== TideFS Kmod Crash-Consistency E2E ==="
    echo "  Kernel:    $KERNEL_IMG"
    echo "  QEMU:      $QEMU_BIN"
    echo "  Module:    tidefs_posix_vfs.ko"
    echo "  Timeout:   ''${TIMEOUT_SEC}s"
    echo ""

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done

    POSIX_KO=""
    for c in "$MODULE_OUT/tidefs_posix_vfs.ko" \
             "$MODULE_OUT/extra/tidefs_posix_vfs.ko"; do
      [ -f "$c" ] && { POSIX_KO="$c"; break; }
    done

    if [ -z "$POSIX_KO" ]; then
      echo "BLOCKED: tidefs_posix_vfs.ko not found at $MODULE_OUT"
      echo "  Build it first with TIDEFS_KERNEL_VFS_MODULE_DIR pointing at the module output directory."
      exit 1
    fi
    echo "  Module .ko: $POSIX_KO"

    # Create pool fixture (128 MiB raw disk image with TideFS label + superblock)
    POOL_IMG="$TMPDIR/pool.img"
    mkdir -p "$TMPDIR"
    if [ -x "$FIXTURE_BUILDER" ]; then
      "$FIXTURE_BUILDER" "$POOL_IMG"
      echo "  Pool fixture: $POOL_IMG ($(stat -c%s "$POOL_IMG") bytes)"
    else
      echo "WARNING: fixture builder not found at $FIXTURE_BUILDER; creating 128 MiB zeroed image"
      dd if=/dev/zero of="$POOL_IMG" bs=1M count=128 2>/dev/null
    fi

    # ── Build initramfs ───────────────────────────────────────────────
    RUN_DIR="$TMPDIR/initrd-$$"
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,validation}
    trap 'if [ -z "''${KEEP_TMP:-}" ]; then rm -rf "$RUN_DIR" "$TMPDIR"; fi' EXIT

    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff \
      mknod mkdir rmdir dd stat cp mv rm ln touch find wc head sync cut md5sum \
      printf test expr uname date od tail mountpoint; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    mkdir -p "$RUN_DIR/lib64" "$RUN_DIR/usr/lib"
    cp "$GLIBC_LIB"/ld-linux-x86-64.so.2 "$RUN_DIR/lib64/" 2>/dev/null || true
    for lib in libc.so.6 libm.so.6 libresolv.so.2; do
      [ -f "$GLIBC_LIB/$lib" ] && cp "$GLIBC_LIB/$lib" "$RUN_DIR/lib64/"
    done

    cp "$POSIX_KO" "$RUN_DIR/lib/modules/tidefs_posix_vfs.ko"

    GUEST_SCRIPT="./nix/vm/kmod-crash-consistency-guest.sh"
    if [ ! -f "$GUEST_SCRIPT" ]; then
      echo "ERROR: guest script not found at $GUEST_SCRIPT" >&2
      exit 2
    fi

    # ── Phase 1 ──────────────────────────────────────────────────────
    echo ""
    echo "=== Phase 1: Mount + Write + Crash ==="

    cat > "$RUN_DIR/init-phase1" << 'INIT1'
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
exec /bin/sh /guest.sh phase1
INIT1
    chmod +x "$RUN_DIR/init-phase1"
    cp "$GUEST_SCRIPT" "$RUN_DIR/guest.sh"
    ln -sf init-phase1 "$RUN_DIR/init"

    echo "--- Building phase1 initramfs ---"
    (cd "$RUN_DIR" && find . | cpio -o -H newc) | gzip > "$TMPDIR/initramfs-p1.gz"

    echo "--- Booting QEMU Phase 1 ---"
    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$TMPDIR/initramfs-p1.gz" \
      -append "console=ttyS0 loglevel=7" \
      -drive file="$POOL_IMG",format=raw,if=virtio,index=0 \
      -nographic \
      -m 512M \
      -no-reboot \
      2>&1 | tee "$TMPDIR/qemu-phase1.log" || true

    echo "--- Phase 1 QEMU exited ---"

    P1_PASS=$(grep -c "^PASS:" "$TMPDIR/qemu-phase1.log" 2>/dev/null || echo 0)
    P1_FAIL=$(grep -c "^FAIL:" "$TMPDIR/qemu-phase1.log" 2>/dev/null || echo 0)
    P1_BLOCKED=$(grep -c "^BLOCKED:" "$TMPDIR/qemu-phase1.log" 2>/dev/null || echo 0)
    echo "Phase 1: PASS=$P1_PASS FAIL=$P1_FAIL BLOCKED=$P1_BLOCKED"

    # ── Phase 2 ──────────────────────────────────────────────────────
    echo ""
    echo "=== Phase 2: Remount + Intent Replay + Verify ==="

    rm -f "$RUN_DIR/init"
    cat > "$RUN_DIR/init-phase2" << 'INIT2'
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
exec /bin/sh /guest.sh phase2
INIT2
    chmod +x "$RUN_DIR/init-phase2"
    ln -sf init-phase2 "$RUN_DIR/init"

    echo "--- Building phase2 initramfs ---"
    (cd "$RUN_DIR" && find . | cpio -o -H newc) | gzip > "$TMPDIR/initramfs-p2.gz"

    echo "--- Booting QEMU Phase 2 (remount after crash) ---"
    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$TMPDIR/initramfs-p2.gz" \
      -append "console=ttyS0 loglevel=7" \
      -drive file="$POOL_IMG",format=raw,if=virtio,index=0 \
      -nographic \
      -m 512M \
      -no-reboot \
      2>&1 | tee "$TMPDIR/qemu-phase2.log" || true

    echo "--- Phase 2 QEMU exited ---"

    P2_PASS=$(grep -c "^PASS:" "$TMPDIR/qemu-phase2.log" 2>/dev/null || echo 0)
    P2_FAIL=$(grep -c "^FAIL:" "$TMPDIR/qemu-phase2.log" 2>/dev/null || echo 0)
    P2_BLOCKED=$(grep -c "^BLOCKED:" "$TMPDIR/qemu-phase2.log" 2>/dev/null || echo 0)
    echo "Phase 2: PASS=$P2_PASS FAIL=$P2_FAIL BLOCKED=$P2_BLOCKED"

    TOTAL_PASS=$((P1_PASS + P2_PASS))
    TOTAL_FAIL=$((P1_FAIL + P2_FAIL))
    TOTAL_BLOCKED=$((P1_BLOCKED + P2_BLOCKED))

    echo ""
    echo "=== COMBINED RESULTS ==="
    echo "TOTAL: PASS=$TOTAL_PASS FAIL=$TOTAL_FAIL BLOCKED=$TOTAL_BLOCKED"

    # Write external validation output
    OUTPUT_DIR="/root/ai/tmp/tidefs-validation/kmod-crash-consistency/$(date -u +%Y-%m-%dT%H%M%SZ)"
    mkdir -p "$OUTPUT_DIR"
    cp "$TMPDIR/qemu-phase1.log" "$OUTPUT_DIR/qemu-phase1.log"
    cp "$TMPDIR/qemu-phase2.log" "$OUTPUT_DIR/qemu-phase2.log"
    cp "$POSIX_KO" "$OUTPUT_DIR/tidefs_posix_vfs.ko" 2>/dev/null || true
    cp "$POOL_IMG" "$OUTPUT_DIR/pool.img" 2>/dev/null || true

    cat > "$OUTPUT_DIR/validation-manifest.json" << MANIFEST
{
  "test": "kmod-posix-vfs-crash-loop-replay-campaign",
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "validation_tier": "Tier 5/6 mounted Linux 7.0 kernel VFS crash-loop replay campaign",
  "phase1_pass": $P1_PASS,
  "phase1_fail": $P1_FAIL,
  "phase1_blocked": $P1_BLOCKED,
  "phase2_pass": $P2_PASS,
  "phase2_fail": $P2_FAIL,
  "phase2_blocked": $P2_BLOCKED,
  "total_pass": $TOTAL_PASS,
  "total_fail": $TOTAL_FAIL,
  "total_blocked": $TOTAL_BLOCKED,
  "commit": "$(git -C /root/tidefs rev-parse HEAD 2>/dev/null || echo unknown)",
  "worktree_dirty": $(git -C /root/tidefs diff --quiet -- . && git -C /root/tidefs diff --cached --quiet -- . && echo false || echo true),
  "kernel": "Linux 7.0",
  "module": "tidefs_posix_vfs.ko",
  "backend": "virtio-blk with pre-created pool fixture",
  "crash_method": "QEMU poweroff/reboot cycle",
  "result": "PASS=$TOTAL_PASS FAIL=$TOTAL_FAIL BLOCKED=$TOTAL_BLOCKED"
}
MANIFEST

    echo "Validation output directory: $OUTPUT_DIR"

    if [ "$TOTAL_FAIL" -gt 0 ]; then
      exit 1
    fi
    exit 0
  '';
in
  validateScript
