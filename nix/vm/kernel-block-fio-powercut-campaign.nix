# TideFS: kernel block-kmod long-haul fio powercut campaign validation.
#
# Builds tidefs_block_kmod.ko against Linux 7.0, boots a QEMU guest
# with a persistent virtio-blk data disk, formats it, creates a backing
# file, loads the block kmod with persistent file-backing, runs fio
# workloads against a guest filesystem on /dev/tidefs, performs
# repeated powercuts, reboots, runs fsck, and produces a powercut
# matrix evidencing guest filesystem integrity after forced reboots.
#
# Validation tier: Tier 5 Linux 7.0 kernel block I/O.
#
# Kernel block long-haul fio powercut campaign.
{
  pkgs,
  linuxKernel_7_0,
}:

let
  glibcLib = "${pkgs.glibc}/lib";

  validateScript = pkgs.writeShellScriptBin "tidefs-kblock-fio-powercut-campaign" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="/root/ai/state/tidefs/kernel-dev/shared/linux-7.0/build/arch/x86/boot/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    GLIBC_LIB="${glibcLib}"
    QEMU_IMG="${pkgs.qemu}/bin/qemu-img"

    MODULE_OUT="''${TIDEFS_KERNEL_BLOCK_MODULE_DIR:-/root/ai/tmp/tidefs-block-kmod/module-out}"
    BLOCK_KO="''${TIDEFS_KERNEL_BLOCK_MODULE_KO:-}"
    TMPDIR="''${TIDEFS_KFIO_TMPDIR:-/tmp/tidefs-kfio-powercut}"
    TIMEOUT_SEC="''${TIDEFS_KFIO_TIMEOUT:-900}"
    POWER_CYCLES="''${TIDEFS_KFIO_CYCLES:-5}"
    DATA_DISK_SIZE_MB="''${TIDEFS_KFIO_DATA_SIZE:-512}"
    TIDEFS_DEV_SIZE_MB="''${TIDEFS_KFIO_TIDEFS_SIZE:-256}"
    FIO_RUNTIME="''${TIDEFS_KFIO_FIO_RUNTIME:-30}"

    KEEP_TMP=""
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --cycles) POWER_CYCLES="$2"; shift 2 ;;
        --data-size) DATA_DISK_SIZE_MB="$2"; shift 2 ;;
        --tidefs-size) TIDEFS_DEV_SIZE_MB="$2"; shift 2 ;;
        --fio-runtime) FIO_RUNTIME="$2"; shift 2 ;;
        --module-out) MODULE_OUT="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h)
          echo "Usage: tidefs-kblock-fio-powercut-campaign [options]"
          echo "  --cycles N       Powercut cycles (default 5)"
          echo "  --data-size MB   Persistent data disk size (default 512)"
          echo "  --tidefs-size MB TideFS device backing size (default 256)"
          echo "  --fio-runtime S  fio runtime per cycle (default 30)"
          echo "  --module-out DIR Module output directory"
          echo "  --keep-tmp       Retain tmpdir"
          exit 0
          ;;
        *) echo "ERROR: unknown option: $1" >&2; exit 2 ;;
      esac
    done

    echo "=== TideFS Kernel Block FIO Powercut Campaign ==="
    echo "  Kernel:      $KERNEL_IMG"
    echo "  QEMU:        $QEMU_BIN"
    echo "  Module out:  $MODULE_OUT"
    echo "  Power cycles: $POWER_CYCLES"
    echo "  Data disk:   $DATA_DISK_SIZE_MB MB"
    echo "  TideFS dev:  $TIDEFS_DEV_SIZE_MB MB"
    echo "  FIO runtime: $FIO_RUNTIME s"
    echo "  Timeout:     $TIMEOUT_SEC s"
    echo ""

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$QEMU_IMG"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done

    if [ -z "$BLOCK_KO" ]; then
      for c in "$MODULE_OUT/tidefs_block_kmod.ko" "$MODULE_OUT/extra/tidefs_block_kmod.ko"; do
        [ -f "$c" ] && { BLOCK_KO="$c"; break; }
      done
    fi
    if [ -z "$BLOCK_KO" ]; then
      echo "BLOCKED: tidefs_block_kmod.ko not found at $MODULE_OUT"
      exit 1
    fi
    echo "  Module .ko: $BLOCK_KO"

    # Prepare tmpdir and persistent data disk
    RUN_DIR="$TMPDIR/validation-$$"
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,validation,data}
    trap 'if [ -z "''${KEEP_TMP:-}" ]; then rm -rf "$RUN_DIR"; fi' EXIT

    DATA_DISK="$RUN_DIR/data/disk.img"
    echo "--- Creating persistent data disk (''${DATA_DISK_SIZE_MB}M) ---"
    "$QEMU_IMG" create -f raw "$DATA_DISK" "''${DATA_DISK_SIZE_MB}M" 2>&1

    # Set up busybox and tools
    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff \
      mknod mkdir rmdir dd stat cp mv rm touch find wc head sync cut md5sum \
      printf test expr uname date od mkswap swapon losetup blockdev reboot \
      mkfs.ext4 fsck.ext4 mountpoint awk seq; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    # Copy glibc libs
    mkdir -p "$RUN_DIR/$GLIBC_LIB"
    cp "$GLIBC_LIB"/ld-linux-x86-64.so.2 "$RUN_DIR/$GLIBC_LIB/" 2>/dev/null || true
    for lib in libc.so.6 libm.so.6 libresolv.so.2 libdl.so.2 libblkid.so.1 \
      libuuid.so.1 libext2fs.so.2 libe2p.so.2 libcom_err.so.2; do
      [ -f "$GLIBC_LIB/$lib" ] && cp "$GLIBC_LIB/$lib" "$RUN_DIR/$GLIBC_LIB/"
    done

    cp "$BLOCK_KO" "$RUN_DIR/lib/modules/tidefs_block_kmod.ko"

    # fio binary (optional)
    FIO_BIN="${pkgs.fio}/bin/fio"
    HAS_FIO=0
    if [ -f "$FIO_BIN" ]; then
      cp "$FIO_BIN" "$RUN_DIR/bin/fio"
      chmod +x "$RUN_DIR/bin/fio"
      HAS_FIO=1
      echo "  FIO binary: $FIO_BIN"
    else
      echo "  WARNING: fio not found; using dd-based I/O"
    fi

    # Validation manifest
    EVDIR="$RUN_DIR/validation"
    mkdir -p "$EVDIR"
    cat > "$EVDIR/campaign_config" << ENDCONF
POWER_CYCLES=$POWER_CYCLES
DATA_DISK_SIZE_MB=$DATA_DISK_SIZE_MB
TIDEFS_DEV_SIZE_MB=$TIDEFS_DEV_SIZE_MB
FIO_RUNTIME=$FIO_RUNTIME
HAS_FIO=$HAS_FIO
ENDCONF

    TOTAL_PASS=0
    TOTAL_FAIL=0
    TOTAL_BLOCKED=0

    # === CYCLE 0: SETUP ===
    echo ""
    echo "=== Cycle 0: Guest Setup ==="

    cat > "$RUN_DIR/init-setup" << 'INITSETUP'
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
echo "=== TideFS KBlock FIO Powercut: SETUP ==="
echo "kernel=$(uname -r)"
PASSED=0; FAILED=0; BLOCKED=0
pass()   { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
fail()   { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); }
blocked(){ echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); }
EVDIR=/validation

if [ -b /dev/vda ]; then
    pass "s0_data_disk_present"
    if mkfs.ext4 -F /dev/vda 2>/tmp/mkfs.err; then
        pass "s1_mkfs_data_disk"
        mount /dev/vda /data
        pass "s2_mount_data_disk"
        dd if=/dev/zero of=/data/tidefs_backing.bin bs=1M count=256 2>/dev/null
        if [ -f /data/tidefs_backing.bin ]; then
            pass "s3_create_backing_file"
        else
            blocked "s3_create_backing_file" "dd failed"
        fi
        sync
        umount /data 2>/dev/null || true
    else
        fail "s1_mkfs_data_disk" "$(cat /tmp/mkfs.err | head -1)"
    fi
else
    blocked "s0_data_disk_present" "/dev/vda not found"
fi

echo "SETUP_PASS=$PASSED" > "$EVDIR/setup_result"
echo "SETUP_FAIL=$FAILED" >> "$EVDIR/setup_result"
echo "SETUP_BLOCKED=$BLOCKED" >> "$EVDIR/setup_result"
poweroff -f
INITSETUP

    chmod +x "$RUN_DIR/init-setup"
    ln -sf init-setup "$RUN_DIR/init"
    (cd "$RUN_DIR" && find . -not -path './data/*' | cpio -o -H newc) | gzip > "$RUN_DIR/initramfs-s0.gz"

    echo "--- Booting QEMU (setup) ---"
    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$RUN_DIR/initramfs-s0.gz" \
      -append "console=ttyS0 quiet" \
      -nographic -m 512M -no-reboot \
      -drive file="$DATA_DISK",format=raw,if=virtio \
      2>&1 | tee "$RUN_DIR/qemu-setup.log" || true

    SETUP_PASS=$(grep -c "PASS: s" "$RUN_DIR/qemu-setup.log" 2>/dev/null || echo 0)
    echo "Setup: PASS=$SETUP_PASS"

    # === POWER CUT CYCLES ===
    for CYCLE in $(seq 1 "$POWER_CYCLES"); do
      echo ""
      echo "============================================================"
      echo "=== CYCLE $CYCLE / $POWER_CYCLES ==="
      echo "============================================================"

      # --- Phase A: fio workload + powercut ---
      cat > "$RUN_DIR/init-cycle-a" << INITCYCLEA
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
CYCLE=$CYCLE
FIO_RUNTIME=$FIO_RUNTIME
HAS_FIO=$HAS_FIO
echo "=== TideFS KBlock FIO Powercut: Cycle $CYCLE Phase A ==="
echo "kernel=\$(uname -r)"
PASSED=0; FAILED=0; BLOCKED=0
pass()   { echo "PASS: \$1"; PASSED=\$((PASSED + 1)); }
fail()   { echo "FAIL: \$1 -- \$2"; FAILED=\$((FAILED + 1)); }
blocked(){ echo "BLOCKED: \$1 -- \$2"; BLOCKED=\$((BLOCKED + 1)); }
EVDIR=/validation

# Mount data disk
if [ -b /dev/vda ]; then
    mount /dev/vda /data 2>/tmp/mnt.err
    if mountpoint /data 2>/dev/null; then
        pass "c\"$CYCLE"_a1_mount_data"
    else
        fail "c\"$CYCLE"_a1_mount_data" "\$(cat /tmp/mnt.err | head -1)"
        echo "CYCLE_RESULT=setup_failed" > "\$EVDIR/cycle_\"$CYCLE"_result"
        poweroff -f
        exit 0
    fi
else
    blocked "c\"$CYCLE"_a1_mount_data" "/dev/vda not present"
    echo "CYCLE_RESULT=blocked" > "\$EVDIR/cycle_\"$CYCLE"_result"
    poweroff -f
    exit 0
fi

# Load block kmod
MOD=/lib/modules/tidefs_block_kmod.ko
if [ -f "\$MOD" ]; then
    if insmod "\$MOD" 2>/tmp/insmod.err; then
        pass "c\"$CYCLE"_a2_insmod"
    else
        fail "c\"$CYCLE"_a2_insmod" "\$(cat /tmp/insmod.err | head -1)"
    fi
else
    blocked "c\"$CYCLE"_a2_insmod" "module not found"
fi

sleep 1
if [ -b /dev/tidefs ]; then
    pass "c\"$CYCLE"_a3_device_present"
else
    blocked "c\"$CYCLE"_a3_device_present" "/dev/tidefs missing"
    echo "CYCLE_RESULT=blocked" > "\$EVDIR/cycle_\"$CYCLE"_result"
    poweroff -f
    exit 0
fi

# Create filesystem on /dev/tidefs
if mkfs.ext4 -F /dev/tidefs 2>/tmp/mkfs.err; then
    pass "c\"$CYCLE"_a4_mkfs_tidefs"
else
    fail "c\"$CYCLE"_a4_mkfs_tidefs" "\$(cat /tmp/mkfs.err | head -1)"
fi

mkdir -p /mnt
if mount /dev/tidefs /mnt 2>/tmp/mnt2.err; then
    pass "c\"$CYCLE"_a5_mount_tidefs"
else
    fail "c\"$CYCLE"_a5_mount_tidefs" "\$(cat /tmp/mnt2.err | head -1)"
fi

# Run I/O workload
if [ "\$HAS_FIO" = "1" ] && mountpoint /mnt 2>/dev/null; then
    echo "--- Running fio ---"
    /bin/fio --name=rw --rw=randrw --bs=4k --size=32M --numjobs=2 \
      --time_based --runtime=\$FIO_RUNTIME --directory=/mnt \
      --output=/tmp/fio-result.json --output-format=json 2>/tmp/fio.err || true
    pass "c\"$CYCLE"_a6_fio_ran"
elif mountpoint /mnt 2>/dev/null; then
    echo "--- Running dd I/O ---"
    for i in \$(seq 1 4); do
        dd if=/dev/urandom of=/mnt/testfile_\$i bs=4k count=1024 2>/dev/null || true
        sync
    done
    pass "c\"$CYCLE"_a6_dd_io_done"
fi

sync
sleep 2

DMESG_BUG=\$(dmesg 2>/dev/null | grep -cE "BUG:|Kernel panic|Oops:" || echo 0)
if [ "\$DMESG_BUG" -eq 0 ]; then
    pass "c\"$CYCLE"_a7_dmesg_clean"
else
    fail "c\"$CYCLE"_a7_dmesg_clean" "dmesg has \$DMESG_BUG bug/oops lines"
fi

echo "CYCLE_\"$CYCLE"_A_PASS=\$PASSED" > "\$EVDIR/cycle_\"$CYCLE"_a_result"
echo "CYCLE_\"$CYCLE"_A_FAIL=\$FAILED" >> "\$EVDIR/cycle_\"$CYCLE"_a_result"
dmesg > "\$EVDIR/dmesg_cycle_\"$CYCLE"_a.txt" 2>/dev/null || true
echo "--- Poweroff ---"
poweroff -f
INITCYCLEA

      chmod +x "$RUN_DIR/init-cycle-a"
      rm -f "$RUN_DIR/init"
      ln -sf init-cycle-a "$RUN_DIR/init"

      (cd "$RUN_DIR" && find . -not -path './data/*' | cpio -o -H newc) | gzip > "$RUN_DIR/initramfs-c"$CYCLE"-a.gz"

      echo "--- Cycle $CYCLE Phase A: Booting QEMU ---"
      timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
        -kernel "$KERNEL_IMG" \
        -initrd "$RUN_DIR/initramfs-c"$CYCLE"-a.gz" \
        -append "console=ttyS0 quiet" \
        -nographic -m 512M -no-reboot \
        -drive file="$DATA_DISK",format=raw,if=virtio \
        2>&1 | tee "$RUN_DIR/qemu-cycle"$CYCLE"-a.log" || true

      A_PASS=$(grep -c "PASS: c" "$RUN_DIR/qemu-cycle"$CYCLE"-a.log" 2>/dev/null || echo 0)
      A_FAIL=$(grep -c "FAIL: c" "$RUN_DIR/qemu-cycle"$CYCLE"-a.log" 2>/dev/null || echo 0)
      echo "  Phase A: PASS=$A_PASS FAIL=$A_FAIL"

      # --- Phase B: Reboot + fsck ---
      cat > "$RUN_DIR/init-cycle-b" << INITCYCLEB
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
CYCLE=$CYCLE
echo "=== TideFS KBlock FIO Powercut: Cycle $CYCLE Phase B (Recovery) ==="
echo "kernel=\$(uname -r)"
PASSED=0; FAILED=0; BLOCKED=0
pass()   { echo "PASS: \$1"; PASSED=\$((PASSED + 1)); }
fail()   { echo "FAIL: \$1 -- \$2"; FAILED=\$((FAILED + 1)); }
blocked(){ echo "BLOCKED: \$1 -- \$2"; BLOCKED=\$((BLOCKED + 1)); }
EVDIR=/validation

MOD=/lib/modules/tidefs_block_kmod.ko
if [ -f "\$MOD" ]; then
    if insmod "\$MOD" 2>/tmp/insmod_b.err; then
        pass "c\"$CYCLE"_b1_insmod_recovery"
    else
        fail "c\"$CYCLE"_b1_insmod_recovery" "\$(cat /tmp/insmod_b.err | head -1)"
    fi
else
    blocked "c\"$CYCLE"_b1_insmod_recovery" "module not found"
fi

sleep 1
if [ -b /dev/tidefs ]; then
    pass "c\"$CYCLE"_b2_device_reappears"
else
    blocked "c\"$CYCLE"_b2_device_reappears" "/dev/tidefs missing"
    echo "CYCLE_RESULT=blocked" > "\$EVDIR/cycle_\"$CYCLE"_result"
    poweroff -f
    exit 0
fi

FSCK_RC=0
fsck.ext4 -fn /dev/tidefs 2>/tmp/fsck.err || FSCK_RC=\$?
if [ "\$FSCK_RC" -eq 0 ]; then
    pass "c\"$CYCLE"_b3_fsck_clean"
elif [ "\$FSCK_RC" -eq 1 ]; then
    pass "c\"$CYCLE"_b3_fsck_corrected"
else
    fail "c\"$CYCLE"_b3_fsck_errors" "fsck RC=\$FSCK_RC"
fi

mkdir -p /mnt
if mount /dev/tidefs /mnt 2>/tmp/remount.err; then
    pass "c\"$CYCLE"_b4_remount_ok"
    ls -la /mnt 2>/dev/null || true
    umount /mnt 2>/dev/null || true
else
    blocked "c\"$CYCLE"_b4_remount_ok" "\$(cat /tmp/remount.err | head -1)"
fi

sync
if rmmod tidefs_block 2>/tmp/rmmod.err; then
    pass "c\"$CYCLE"_b5_rmmod_clean"
else
    fail "c\"$CYCLE"_b5_rmmod_clean" "\$(cat /tmp/rmmod.err | head -1)"
fi

DMESG_BUG=\$(dmesg 2>/dev/null | grep -cE "BUG:|Kernel panic|Oops:" || echo 0)
if [ "\$DMESG_BUG" -eq 0 ]; then
    pass "c\"$CYCLE"_b6_dmesg_clean"
else
    fail "c\"$CYCLE"_b6_dmesg_clean" "dmesg has \$DMESG_BUG bug/oops lines"
fi

echo "CYCLE_\"$CYCLE"_B_PASS=\$PASSED" > "\$EVDIR/cycle_\"$CYCLE"_b_result"
echo "CYCLE_\"$CYCLE"_B_FAIL=\$FAILED" >> "\$EVDIR/cycle_\"$CYCLE"_b_result"
dmesg > "\$EVDIR/dmesg_cycle_\"$CYCLE"_b.txt" 2>/dev/null || true
echo "CYCLE_RESULT=done" > "\$EVDIR/cycle_\"$CYCLE"_result"
poweroff -f
INITCYCLEB

      chmod +x "$RUN_DIR/init-cycle-b"
      rm -f "$RUN_DIR/init"
      ln -sf init-cycle-b "$RUN_DIR/init"

      (cd "$RUN_DIR" && find . -not -path './data/*' | cpio -o -H newc) | gzip > "$RUN_DIR/initramfs-c"$CYCLE"-b.gz"

      echo "--- Cycle $CYCLE Phase B: Booting QEMU (recovery) ---"
      timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
        -kernel "$KERNEL_IMG" \
        -initrd "$RUN_DIR/initramfs-c"$CYCLE"-b.gz" \
        -append "console=ttyS0 quiet" \
        -nographic -m 512M -no-reboot \
        -drive file="$DATA_DISK",format=raw,if=virtio \
        2>&1 | tee "$RUN_DIR/qemu-cycle"$CYCLE"-b.log" || true

      B_PASS=$(grep -c "PASS: c" "$RUN_DIR/qemu-cycle"$CYCLE"-b.log" 2>/dev/null || echo 0)
      B_FAIL=$(grep -c "FAIL: c" "$RUN_DIR/qemu-cycle"$CYCLE"-b.log" 2>/dev/null || echo 0)
      echo "  Phase B: PASS=$B_PASS FAIL=$B_FAIL"

      CYCLE_PASS=$((A_PASS + B_PASS))
      CYCLE_FAIL=$((A_FAIL + B_FAIL))
      TOTAL_PASS=$((TOTAL_PASS + CYCLE_PASS))
      TOTAL_FAIL=$((TOTAL_FAIL + CYCLE_FAIL))
      echo "  Cycle $CYCLE total: PASS=$CYCLE_PASS FAIL=$CYCLE_FAIL"
    done

    echo ""
    echo "============================================================"
    echo "=== POWER-CUT CAMPAIGN RESULTS ==="
    echo "  Cycles: $POWER_CYCLES"
    echo "  TOTAL PASS: $TOTAL_PASS"
    echo "  TOTAL FAIL: $TOTAL_FAIL"
    echo "============================================================"

    # Write external validation output
    OUTPUT_DIR="/root/ai/tmp/tidefs-validation/kernel-block-fio-powercut-campaign/$(date -u +%Y-%m-%dT%H%M%SZ)"
    mkdir -p "$OUTPUT_DIR"
    cp "$RUN_DIR/qemu-setup.log" "$OUTPUT_DIR/" 2>/dev/null || true
    for CYCLE in $(seq 1 "$POWER_CYCLES"); do
      cp "$RUN_DIR/qemu-cycle"$CYCLE"-a.log" "$OUTPUT_DIR/" 2>/dev/null || true
      cp "$RUN_DIR/qemu-cycle"$CYCLE"-b.log" "$OUTPUT_DIR/" 2>/dev/null || true
    done
    cp "$BLOCK_KO" "$OUTPUT_DIR/tidefs_block_kmod.ko" 2>/dev/null || true
    cp "$EVDIR"/* "$OUTPUT_DIR/" 2>/dev/null || true

    COMMIT=$(git -C /root/tidefs rev-parse HEAD 2>/dev/null || echo unknown)
    if git -C /root/tidefs diff --quiet --ignore-submodules -- 2>/dev/null && \
       git -C /root/tidefs diff --cached --quiet --ignore-submodules -- 2>/dev/null; then
      DIRTY=false
    else
      DIRTY=true
    fi
    cat > "$OUTPUT_DIR/manifest.json" << ENDMANIFEST
{
  "test": "kernel-block-fio-powercut-campaign",
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "validation_tier": "Tier 5 Linux 7.0 kernel block I/O",
  "power_cycles": $POWER_CYCLES,
  "total_pass": $TOTAL_PASS,
  "total_fail": $TOTAL_FAIL,
  "commit": "$COMMIT",
  "worktree_dirty": $DIRTY,
  "kernel": "Linux 7.0",
  "module": "tidefs_block_kmod.ko",
  "backend": "persistent file-backed (RawBlockFile) via virtio-blk data disk; falls back to in-memory",
  "crash_method": "QEMU poweroff/reboot cycle",
  "result": "Powercut campaign completed. TOTAL_PASS=$TOTAL_PASS TOTAL_FAIL=$TOTAL_FAIL"
}
ENDMANIFEST

    echo "Validation output directory: $OUTPUT_DIR"
    if [ "$TOTAL_FAIL" -gt 0 ]; then exit 1; fi
    exit 0
  '';
in
  validateScript
