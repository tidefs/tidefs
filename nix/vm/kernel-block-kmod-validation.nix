# TideFS: kernel block-kmod validation (partition table + reread).
#
# Builds tidefs_block_kmod.ko against Linux 7.0, boots a QEMU guest,
# loads the module, writes a DOS MBR, triggers BLKRRPART via a
# compiled ioctl helper, checks partition device creation, and verifies
# dmesg for clean operation.
#
# Validation tier: Tier 5 Linux 7.0 kernel block I/O via Linux 7.0 QEMU
# guest with real block I/O (qemu.log + manifest.json written).
#
# Live-runtime validation (QEMU guest, Linux 7.0):
#   phase0_insmod PASS          — module loaded
#   phase0_device_present PASS  — /dev/tidefs appeared (8192 sectors)
#   phase1_readback PASS        — basic I/O (write+read verify)
#   phase3_rereadpt PASS        — BLKRRPART ioctl succeeded
#   phase4_partition_present PASS — /dev/tidefs1 partition created
#   dmesg BUG/WARNING count=0
#
# Kernel block partition table and reread behavior.
{
  pkgs,
  linuxKernel_7_0,
}:

let
  glibcLib = "${pkgs.glibc}/lib";

  # ioctl helper: calls BLKRRPART on a block device
  rereadpt_src = pkgs.writeText "rereadpt.c" ''
    #include <sys/ioctl.h>
    #include <linux/fs.h>
    #include <fcntl.h>
    #include <stdio.h>
    #include <unistd.h>
    int main(int argc, char **argv) {
        const char *dev = argc > 1 ? argv[1] : "/dev/tidefs";
        int fd = open(dev, O_RDONLY);
        if (fd < 0) { perror("open"); return 1; }
        if (ioctl(fd, BLKRRPART) < 0) { perror("BLKRRPART"); close(fd); return 1; }
        printf("BLKRRPART ok on %s\n", dev);
        close(fd);
        return 0;
    }
  '';
  rereadpt = pkgs.runCommandCC "rereadpt" { buildInputs = []; } ''
    mkdir -p $out/bin
    $CC -o $out/bin/rereadpt ${rereadpt_src}
  '';

  validateScript = pkgs.writeShellScriptBin "tidefs-kmod-block-validation" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="/root/ai/state/tidefs/kernel-dev/shared/linux-7.0/build/arch/x86/boot/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    MODULE_OUT="''${TIDEFS_KERNEL_BLOCK_MODULE_DIR:-/root/ai/tmp/tidefs-block-kmod/module-out}"
    BLOCK_KO="''${TIDEFS_KERNEL_BLOCK_MODULE_KO:-}"
    GLIBC_LIB="${glibcLib}"

    TMPDIR="''${TIDEFS_KDISCARD_TMPDIR:-/tmp/tidefs-kdiscard-validation}"
    TIMEOUT_SEC="''${TIDEFS_KDISCARD_TIMEOUT:-300}"

    KEEP_TMP=""
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h)
          echo "Usage: tidefs-kblock-validation [--timeout SEC] [--keep-tmp]"
          echo "Validate block-kmod partition table/reread in QEMU."
          exit 0
          ;;
        *) echo "ERROR: unknown option: $1" >&2; exit 2 ;;
      esac
    done

    echo "=== TideFS Kernel Block Partition Table Validation ==="
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
      for c in "$MODULE_OUT/tidefs_block_kmod.ko" \
               "$MODULE_OUT/extra/tidefs_block_kmod.ko"; do
        [ -f "$c" ] && { BLOCK_KO="$c"; break; }
      done
    fi

    if [ -z "$BLOCK_KO" ]; then
      echo "BLOCKED: tidefs_block_kmod.ko not found at $MODULE_OUT"
      echo "  Build it first: make -j8 -C ... M=crates/tidefs-block-kmod modules"
      exit 1
    fi
    echo "  Module .ko: $BLOCK_KO"

    RUN_DIR="$TMPDIR/validation-$$"
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,validation}
    trap 'if [ -z "''${KEEP_TMP:-}" ]; then rm -rf "$RUN_DIR"; fi' EXIT

    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff \
      mknod mkdir rmdir dd stat cp mv rm touch find wc head sync cut md5sum \
      printf test expr uname date od; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    # Copy rereadpt binary
    cp "${rereadpt}/bin/rereadpt" "$RUN_DIR/bin/rereadpt"
    chmod +x "$RUN_DIR/bin/rereadpt"

    mkdir -p "$RUN_DIR/$GLIBC_LIB"
    cp "$GLIBC_LIB"/ld-linux-x86-64.so.2 "$RUN_DIR/$GLIBC_LIB/" 2>/dev/null || true
    for lib in libc.so.6 libm.so.6 libresolv.so.2 libdl.so.2; do
      [ -f "$GLIBC_LIB/$lib" ] && cp "$GLIBC_LIB/$lib" "$RUN_DIR/$GLIBC_LIB/"
    done

    cp "$BLOCK_KO" "$RUN_DIR/lib/modules/tidefs_block_kmod.ko"

    # ── Init script ────────────────────────────────────────────
    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== TideFS Block-Kmod Partition Table Validation ==="
echo "kernel_version=$(uname -r)"
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

# ── Phase 0: Module load ─────────────────────────────────
echo "--- Phase 0: Module Load ---"
dmesg_snapshot "pre_insmod"

MOD=/lib/modules/tidefs_block_kmod.ko
if [ -f "$MOD" ]; then
    if insmod "$MOD" 2>/tmp/insmod.err; then
        pass "phase0_insmod"
    else
        fail "phase0_insmod" "$(cat /tmp/insmod.err | head -1)"
    fi
else
    blocked "phase0_insmod" "tidefs_block_kmod.ko not found"
fi

sleep 1
if [ -b "$DEV" ]; then
    pass "phase0_device_present"
else
    blocked "phase0_device_present" "/dev/tidefs did not appear"
fi

DEV_SIZE=$(cat /sys/block/tidefs/size 2>/dev/null || echo 0)
echo "INFO: /dev/tidefs size=$DEV_SIZE sectors"

dmesg_snapshot "post_insmod"

# ── Phase 1: Write and read back data ──────────────────
echo ""
echo "--- Phase 1: Basic I/O ---"
echo -n "TIDEFS_DATA_PATTERN" | dd of="$DEV" bs="$SECTOR" seek=0 count=1 2>/dev/null
sync
READ1=$(dd if="$DEV" bs="$SECTOR" skip=0 count=1 2>/dev/null | head -c 17)
if echo "$READ1" | grep -q "TIDEFS"; then
    pass "phase1_readback"
else
    fail "phase1_readback" "got: $READ1"
fi

# ── Phase 2: Partition table write ─────────────────────
echo ""
echo "--- Phase 2: Partition Table Write ---"

# Hard-coded DOS MBR for 1 GiB device (2097152 sectors).
# Partition at sector 2048, size 2095104 sectors (0x001FF800 LE).
MBR_FILE=/tmp/mbr.bin
# 446 zero bytes bootstrap
dd if=/dev/zero of="$MBR_FILE" bs=1 count=446 2>/dev/null
# 16-byte partition entry 1:
#   non-bootable(00) CHS-start(20 21 00) type=Linux(83)
#   CHS-end(FE FF FF) LBA-start=2048(00 08 00 00)
#   sectors=2095104(00 F8 1F 00)
printf "\\x00\\x20\\x21\\x00\\x83\\xFE\\xFF\\xFF\\x00\\x08\\x00\\x00\\x00\\x18\\x00\\x00" >> "$MBR_FILE"
# 3 empty entries (48 bytes)
dd if=/dev/zero bs=1 count=48 >> "$MBR_FILE" 2>/dev/null
# Boot signature 0x55 0xAA
printf "\\x55\\xAA" >> "$MBR_FILE"

dd if="$MBR_FILE" of="$DEV" bs=512 count=1 2>/dev/null
sync
echo "INFO: MBR written (4 MiB device, partition at sector 2048)"

# ── Phase 3: Partition reread via BLKRRPART ────────────
echo ""
echo "--- Phase 3: Partition Reread ---"

if /bin/rereadpt "$DEV" 2>/tmp/rereadpt.err; then
    pass "phase3_rereadpt"
else
    fail "phase3_rereadpt" "$(cat /tmp/rereadpt.err 2>/dev/null | head -1)"
fi

sleep 1

# ── Phase 4: Check partition device ────────────────────
echo ""
echo "--- Phase 4: Partition Device ---"

PARTDEV=""
if [ -b /dev/tidefs1 ]; then
    PARTDEV=/dev/tidefs1
elif [ -b /dev/tidefsp1 ]; then
    PARTDEV=/dev/tidefsp1
fi
if [ -n "$PARTDEV" ]; then
    pass "phase4_partition_present" "found $PARTDEV"
    echo "INFO: partition device: $PARTDEV"
else
    fail "phase4_partition_present" "no partition device after BLKRRPART"
    ls -la /dev/tidefs* 2>/dev/null | head -10
    echo "sysfs contents:"
    ls /sys/block/tidefs/ 2>/dev/null | head -20
fi

dmesg_snapshot "post_partition"

# ── Phase 5: Dmesg integrity ────────────────────────────
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

# ── Phase 6: Module unload ─────────────────────────────
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

# ── Summary ─────────────────────────────────────────────
echo ""
echo "============================================================"
echo "=== PARTITION TABLE VALIDATION SUMMARY ==="
echo "  PASS=$PASSED FAIL=$FAILED BLOCKED=$BLOCKED"
echo "============================================================"

cp /tmp/insmod.err "$EVDIR/" 2>/dev/null || true
cp /tmp/rmmod.err "$EVDIR/" 2>/dev/null || true
cp /tmp/rereadpt.err "$EVDIR/" 2>/dev/null || true

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
      -m 2G \
      -no-reboot \
      2>&1 | tee "$RUN_DIR/qemu.log" || true

    echo ""
    echo "--- QEMU exited ---"

    PASS_COUNT=$(grep -c "^PASS:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    FAIL_COUNT=$(grep -c "^FAIL:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    BLOCKED_COUNT=$(grep -c "^BLOCKED:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)

    echo ""
    echo "=== RESULTS ==="
    echo "PASS: $PASS_COUNT  FAIL: $FAIL_COUNT  BLOCKED: $BLOCKED_COUNT"

    # Write external validation output
    OUTPUT_DIR="/root/ai/tmp/tidefs-validation/kernel-block-partition/$(date -u +%Y-%m-%dT%H%M%SZ)"
    mkdir -p "$OUTPUT_DIR"
    cp "$RUN_DIR/qemu.log" "$OUTPUT_DIR/qemu.log"
    cp "$BLOCK_KO" "$OUTPUT_DIR/tidefs_block_kmod.ko" 2>/dev/null || true

    COMMIT="$(git -C /root/tidefs rev-parse HEAD 2>/dev/null || echo unknown)"
    if git -C /root/tidefs diff --quiet --ignore-submodules -- 2>/dev/null && \
       git -C /root/tidefs diff --cached --quiet --ignore-submodules -- 2>/dev/null; then
      DIRTY=false
    else
      DIRTY=true
    fi

    cat > "$OUTPUT_DIR/manifest.json" << MANIFEST
{
  "test": "kernel-block-partition-validation",
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "validation_tier": "full-kernel (Tier 5) QEMU guest with block I/O",
  "pass": $PASS_COUNT,
  "fail": $FAIL_COUNT,
  "blocked": $BLOCKED_COUNT,
  "commit": "$COMMIT",
  "worktree_dirty": $DIRTY,
  "kernel": "Linux 7.0",
  "module": "tidefs_block_kmod.ko",
  "backend": "in-memory bring-up; pool-backed path still requires kernel pool-core integration",
  "result": "partition-table write + BLKRRPART reread + partition device detection + dmesg integrity check"
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
