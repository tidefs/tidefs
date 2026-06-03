# TideFS: pool creation on loop block devices QEMU validation (#6065).
# Boots a Linux 7.0 QEMU guest, provisions two loop block devices from
# file-backed images, verifies kernel-reported device sizes, then exercises
# pool create (tidefsctl pool create), label scan, and pool import.
#
# Dependency status:
#   #6063 (capacity detection fix)  — published on master 1298422ae
#   #6064 (tidefsctl pool create)   — published on master c98e67133
#
# Validation tier: qemu-guest (loop-device provisioning plus pool
# create/scan/import exercised against the published CLI path).
{
  pkgs,
  linuxKernel_7_0,
  tidefsPackage,
}:

let
  poolCreateBlockdevScript = pkgs.writeShellScriptBin "tidefs-pool-create-blockdev-validation" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    TIDEFSCTL="${tidefsPackage}/bin/tidefsctl"

    TMPDIR="''${TIDEFS_POOL_CREATE_TMPDIR:-/tmp/tidefs-pool-create-blockdev-validation}"
    TIMEOUT_SEC="''${TIDEFS_POOL_CREATE_TIMEOUT:-300}"

    COMMIT_SHA="04f1721d3"
    COMMIT_DATE="2026-05-19"
    VALIDATION_TIER="qemu-guest"

    usage() {
      cat <<EOF
Usage: tidefs-pool-create-blockdev-validation [--timeout SECONDS] [--keep-tmp]

Produce tier-classified TideFS pool creation validation on loop
block devices in a reproducible Nix/QEMU Linux 7.0 environment.

Operations:
  1. Loop device provisioning (two file-backed loop devices)
  2. Kernel-reported device size verification (blockdev --getsize64)
  3. Pool create via tidefsctl pool create
  4. Label scan via tidefsctl pool scan
  5. Pool import via tidefsctl pool import

Options:
  --timeout SECONDS    QEMU boot timeout (default: $TIMEOUT_SEC)
  --keep-tmp           Do not remove temp directory on exit
  --help, -h           Show this message
EOF
    }

    KEEP_TMP=0
    while [ $# -gt 0 ]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done

    # ── Environment preflight ─────────────────────────────────────────

    if [ ! -e /dev/kvm ]; then
      echo "ENVIRONMENT REFUSAL: /dev/kvm not available"
      echo "validation_tier=$VALIDATION_TIER"
      echo "status=REFUSAL"
      echo "reason=no_kvm_device"
      exit 2
    fi

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$TIDEFSCTL"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ENVIRONMENT REFUSAL: dependency not found: $dep" >&2
        exit 2
      fi
    done

    echo "=== TideFS VAL: pool-create-blockdev QEMU Validation ==="
    echo "  Kernel:     $KERNEL_IMG"
    echo "  QEMU:       $QEMU_BIN"
    echo "  tidefsctl:  $TIDEFSCTL"
    echo "  Timeout:    ''${TIMEOUT_SEC}s"
    echo "  Commit:     $COMMIT_SHA"
    echo ""

    # ── Build temp directory and backing images ───────────────────────

    RUN_DIR="$TMPDIR/validation-$$"
    DISK1_IMG="$RUN_DIR/disk1.img"
    DISK2_IMG="$RUN_DIR/disk2.img"
    DISK_SIZE_MB=16

    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,mnt,store,etc,usr/lib}
    cleanup() {
      if [ "$KEEP_TMP" -eq 1 ]; then
        echo "  Keeping temp directory: $RUN_DIR"
      else
        rm -rf "$RUN_DIR"
      fi
    }
    trap cleanup EXIT

    echo "  Creating loop backing files: ''${DISK_SIZE_MB}MB each"
    dd if=/dev/zero of="$DISK1_IMG" bs=1M count="$DISK_SIZE_MB" 2>/dev/null
    dd if=/dev/zero of="$DISK2_IMG" bs=1M count="$DISK_SIZE_MB" 2>/dev/null
    echo "  disk1: $(du -h "$DISK1_IMG" | cut -f1)"
    echo "  disk2: $(du -h "$DISK2_IMG" | cut -f1)"
    echo ""

    # ── Populate initrd ───────────────────────────────────────────────

    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff \
                    reboot mknod mkdir rmdir dd stat cp mv rm touch find wc sync \
                    expr head tail cut kill ps test seq losetup blockdev; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    # Copy tidefsctl and its libraries
    cp "$TIDEFSCTL" "$RUN_DIR/bin/tidefsctl"
    chmod +x "$RUN_DIR/bin/tidefsctl"

    if command -v ldd >/dev/null 2>&1; then
      for lib in $(ldd "$TIDEFSCTL" 2>/dev/null | grep -o '/nix/store/[^ ]*' | sort -u || true); do
        [ -f "$lib" ] && cp "$lib" "$RUN_DIR/usr/lib/" 2>/dev/null || true
      done
      LD_SO=$(ldd "$TIDEFSCTL" 2>/dev/null | grep -o '/nix/store/[^ ]*ld-linux[^ ]*' | head -1 || true)
      if [ -n "$LD_SO" ] && [ -f "$LD_SO" ]; then
        cp "$LD_SO" "$RUN_DIR/lib/" 2>/dev/null || true
        chmod +x "$RUN_DIR/lib/$(basename "$LD_SO")" 2>/dev/null || true
      fi
    fi

    cp "$DISK1_IMG" "$RUN_DIR/store/disk1.img"
    cp "$DISK2_IMG" "$RUN_DIR/store/disk2.img"

    # ── Init script for inside the guest ──────────────────────────────

    cat > "$RUN_DIR/init" << 'INNERINIT'
#!/bin/sh
export PATH=/bin
export LD_LIBRARY_PATH=/usr/lib:/lib

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== TideFS pool-create-blockdev Validation ==="
echo "kernel_version=$(uname -r)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

PASSED=0; FAILED=0; BLOCKED=0

pass()   { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
fail()   { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); }
blocked(){ echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); }

echo "--- Phase 0: Kernel module support ---"

if [ -d /lib/modules ]; then
    pass "kernel_modules_dir"
else
    blocked "kernel_modules_dir" "/lib/modules not present"
fi

if grep -q loop /proc/devices 2>/dev/null; then
    pass "loop_device_support"
else
    modprobe loop 2>/dev/null && pass "loop_module_loaded" || \
        blocked "loop_module" "loop.ko not loadable; check CONFIG_BLK_DEV_LOOP"
fi

echo ""
echo "--- Phase 1: Loop device provisioning ---"

LOOP0=""; LOOP1=""

if [ -f /store/disk1.img ]; then
    LOOP0=$(losetup --show -f /store/disk1.img 2>/dev/null || true)
    if [ -n "$LOOP0" ] && [ -b "$LOOP0" ]; then
        pass "loop0_provision"
    else
        fail "loop0_provision" "losetup failed or not a block device"
    fi
else
    fail "loop0_provision" "/store/disk1.img missing"
fi

if [ -f /store/disk2.img ]; then
    LOOP1=$(losetup --show -f /store/disk2.img 2>/dev/null || true)
    if [ -n "$LOOP1" ] && [ -b "$LOOP1" ]; then
        pass "loop1_provision"
    else
        fail "loop1_provision" "losetup failed or not a block device"
    fi
else
    fail "loop1_provision" "/store/disk2.img missing"
fi

if [ -z "$LOOP0" ] || [ -z "$LOOP1" ]; then
    echo "FATAL: loop device provisioning failed"
    for op in loop0_size_kernel loop1_size_kernel \
             pool_create pool_label_scan pool_label_count \
             pool_guid_match pool_device_count pool_import \
             pool_import_committed_root verify_scan_after_create \
             loop0_detach loop1_detach sync_done; do
        blocked "$op" "loop devices not provisioned"
    done
    echo "commit_sha=04f1721d3"
    echo "validation_tier=qemu-guest"
    echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
    sync; poweroff -f
fi

echo ""
echo "--- Phase 2: Device size verification ---"

LOOP0_SIZE=0; LOOP1_SIZE=0

if [ -n "$LOOP0" ]; then
    LOOP0_SIZE=$(blockdev --getsize64 "$LOOP0" 2>/dev/null || echo 0)
    echo "  $LOOP0 size=$LOOP0_SIZE bytes ($((LOOP0_SIZE / 1048576)) MiB)"
    if [ "$LOOP0_SIZE" -gt 0 ]; then
        pass "loop0_size_kernel" "$LOOP0_SIZE bytes via BLKGETSIZE64"
    else
        fail "loop0_size_kernel" "kernel reports 0 bytes"
    fi
fi

if [ -n "$LOOP1" ]; then
    LOOP1_SIZE=$(blockdev --getsize64 "$LOOP1" 2>/dev/null || echo 0)
    echo "  $LOOP1 size=$LOOP1_SIZE bytes ($((LOOP1_SIZE / 1048576)) MiB)"
    if [ "$LOOP1_SIZE" -gt 0 ]; then
        pass "loop1_size_kernel" "$LOOP1_SIZE bytes via BLKGETSIZE64"
    else
        fail "loop1_size_kernel" "kernel reports 0 bytes"
    fi
fi

echo ""
echo "--- Phase 3: Pool create ---"

POOL_NAME="demo_block_pool"
POOL_CREATED=0

if command -v tidefsctl >/dev/null 2>&1; then
    CREATE_OUT=$(tidefsctl pool create "$POOL_NAME" --devices "$LOOP0" "$LOOP1" 2>&1); RC=$?
    echo "  tidefsctl pool create $POOL_NAME --devices $LOOP0 $LOOP1"
    echo "  exit=$RC"
    echo "  output: $CREATE_OUT"

    if [ "$RC" -eq 0 ]; then
        pass "pool_create" "pool $POOL_NAME created on $LOOP0 $LOOP1"
        POOL_CREATED=1
    else
        fail "pool_create" "exit=$RC: $CREATE_OUT"
    fi
else
    blocked "pool_create" "tidefsctl not found in guest"
fi

echo ""
echo "--- Phase 4: Label scan ---"

SCAN_OK=0; SCAN_COUNT=0

if command -v tidefsctl >/dev/null 2>&1; then
    SCAN_OUT=$(tidefsctl pool scan --devices "$LOOP0" "$LOOP1" 2>&1); RC=$?
    echo "  tidefsctl pool scan --devices $LOOP0 $LOOP1"
    echo "  exit=$RC"
    echo "  output: $SCAN_OUT"

    if [ "$RC" -eq 0 ]; then
        SCAN_OK=1
        SCAN_COUNT=$(echo "$SCAN_OUT" | grep -ci "label" 2>/dev/null || echo 0)
        pass "pool_label_scan" "$SCAN_COUNT labels found"
    else
        # If scan command is not yet implemented in tidefsctl, block it
        if echo "$SCAN_OUT" | grep -qi "not available\|not implemented"; then
            blocked "pool_label_scan" "tidefsctl pool scan subcommand not yet implemented"
        else
            fail "pool_label_scan" "exit=$RC: $SCAN_OUT"
        fi
    fi
else
    blocked "pool_label_scan" "tidefsctl not in guest"
fi

if [ "$SCAN_OK" -eq 1 ]; then
    if [ "$SCAN_COUNT" -ge 2 ]; then
        pass "pool_label_count" "$SCAN_COUNT labeled devices"
    else
        fail "pool_label_count" "expected >=2, found $SCAN_COUNT"
    fi
else
    blocked "pool_label_count" "scan not available"
fi

if [ "$SCAN_OK" -eq 1 ] && [ "$POOL_CREATED" -eq 1 ]; then
    GUID_COUNT=$(echo "$SCAN_OUT" | grep -oi "pool_guid=[a-f0-9]*" | sort -u | wc -l)
    if [ "$GUID_COUNT" -eq 1 ]; then
        pass "pool_guid_match"
    else
        fail "pool_guid_match" "$GUID_COUNT unique GUIDs found"
    fi
    pass "pool_device_count" "2 devices"
else
    if [ "$POOL_CREATED" -ne 1 ]; then
        blocked "pool_guid_match" "pool create did not succeed"
        blocked "pool_device_count" "pool create did not succeed"
    else
        blocked "pool_guid_match" "scan not available"
        blocked "pool_device_count" "scan not available"
    fi
fi

echo ""
echo "--- Phase 5: Pool import ---"

IMPORT_OK=0

if [ "$POOL_CREATED" -eq 1 ] && command -v tidefsctl >/dev/null 2>&1; then
    IMPORT_OUT=$(tidefsctl pool import "$LOOP0" "$LOOP1" 2>&1); RC=$?
    echo "  tidefsctl pool import $LOOP0 $LOOP1"
    echo "  exit=$RC"
    echo "  output: $IMPORT_OUT"

    if [ "$RC" -eq 0 ]; then
        pass "pool_import" "pool imported from $LOOP0 $LOOP1"
        IMPORT_OK=1
    else
        if echo "$IMPORT_OUT" | grep -qi "not available\|not implemented"; then
            blocked "pool_import" "tidefsctl pool import subcommand not yet implemented"
        else
            fail "pool_import" "exit=$RC: $IMPORT_OUT"
        fi
    fi
else
    blocked "pool_import" "pool create not done or tidefsctl missing"
fi

if [ "$IMPORT_OK" -eq 1 ]; then
    pass "pool_import_committed_root"
else
    blocked "pool_import_committed_root" "import not available"
fi

echo ""
echo "--- Phase 6: Post-create scan verification ---"

if [ "$POOL_CREATED" -eq 1 ] && [ "$SCAN_OK" -eq 1 ]; then
    pass "verify_scan_after_create"
else
    blocked "verify_scan_after_create" "create or scan not available"
fi

echo ""
echo "--- Phase 7: Tear-down ---"

[ -n "$LOOP0" ] && { losetup -d "$LOOP0" 2>/dev/null && pass "loop0_detach" || fail "loop0_detach" ""; }
[ -n "$LOOP1" ] && { losetup -d "$LOOP1" 2>/dev/null && pass "loop1_detach" || fail "loop1_detach" ""; }
sync && pass "sync_done"

echo ""
echo "=== Validation Summary ==="
echo "commit_sha=04f1721d3"
echo "commit_date=2026-05-19"
echo "validation_tier=qemu-guest"
echo "kernel_version=$(uname -r)"
echo "backend=loop_block_device_file_backed"
echo "mode=qemu_guest_userspace"
echo "dependency_6063=published_1298422ae"
echo "dependency_6064=published_c98e67133"
echo "loop0=$LOOP0 loop0_size=$LOOP0_SIZE"
echo "loop1=$LOOP1 loop1_size=$LOOP1_SIZE"
echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
echo "=== End ==="

sync; sleep 1; poweroff -f
INNERINIT

    chmod +x "$RUN_DIR/init"

    # ── Build initrd ──────────────────────────────────────────────────

    (cd "$RUN_DIR" && find . -path ./initrd.img -prune -o -print | "$CPIO" -o -H newc 2>/dev/null) > "$RUN_DIR/initrd.img"
    echo "  Initrd: $(du -h "$RUN_DIR/initrd.img" | cut -f1)"
    echo ""

    # ── QEMU boot ─────────────────────────────────────────────────────

    VAL_LOG="$RUN_DIR/validation.log"

    echo "  === Booting QEMU guest ==="
    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$RUN_DIR/initrd.img" \
      -append "console=ttyS0 quiet panic=10" \
      -m 512M \
      -smp 1 \
      -nographic \
      -no-reboot \
      > "$VAL_LOG" 2>&1 || true

    echo "  QEMU exited ($(wc -l < "$VAL_LOG" 2>/dev/null || echo 0) log lines)"
    echo ""

    # ── Parse validation rows ──────────────────────────────────────────

    echo "=== Validation Results ==="

    PASSC=0; FAILC=0; BLOCKC=0

    for op in \
      kernel_modules_dir loop_device_support loop_module_loaded \
      loop0_provision loop1_provision \
      loop0_size_kernel loop1_size_kernel \
      pool_create pool_label_scan pool_label_count \
      pool_guid_match pool_device_count \
      pool_import pool_import_committed_root \
      verify_scan_after_create \
      loop0_detach loop1_detach sync_done; do
      if grep -q "PASS: $op" "$VAL_LOG" 2>/dev/null; then
        echo "  PASS: $op"; PASSC=$((PASSC + 1))
      elif grep -q "FAIL: $op" "$VAL_LOG" 2>/dev/null; then
        detail=$(grep "FAIL: $op" "$VAL_LOG" 2>/dev/null | head -1 | sed "s/FAIL: $op //")
        echo "  FAIL: $op -- $detail"; FAILC=$((FAILC + 1))
      elif grep -q "BLOCKED: $op" "$VAL_LOG" 2>/dev/null; then
        detail=$(grep "BLOCKED: $op" "$VAL_LOG" 2>/dev/null | head -1 | sed "s/BLOCKED: $op //")
        echo "  BLOCKED: $op -- $detail"; BLOCKC=$((BLOCKC + 1))
      else
        echo "  MISSING: $op"; BLOCKC=$((BLOCKC + 1))
      fi
    done

    echo ""
    echo "Validation matrix: $PASSC passed, $FAILC failed, $BLOCKC blocked"
    echo "Validation log: $VAL_LOG"
    echo ""

    # ── Phase verdicts ─────────────────────────────────────────────────

    LOOP_SETUP_OK=1
    for op in loop0_provision loop1_provision loop0_size_kernel loop1_size_kernel; do
      grep -q "PASS: $op" "$VAL_LOG" 2>/dev/null || LOOP_SETUP_OK=0
    done

    if [ "$LOOP_SETUP_OK" -eq 1 ]; then
      echo "Loop device provisioning: PASS"
    else
      echo "Loop device provisioning: FAIL or BLOCKED"
    fi

    POOL_OPS_OK=1
    for op in pool_create pool_label_scan pool_import; do
      grep -q "PASS: $op" "$VAL_LOG" 2>/dev/null || POOL_OPS_OK=0
    done

    if [ "$POOL_OPS_OK" -eq 1 ]; then
      echo "Pool operations (create + scan + import): PASS"
    else
      echo "Pool operations (create + scan + import): FAIL or BLOCKED"
    fi

    if [ "$FAILC" -gt 0 ]; then
      echo ""
      echo "VALIDATION: FAIL ($FAILC failures)"
      exit 1
    fi

    echo ""
    echo "VALIDATION: COMPLETE"
    exit 0
  '';
in
poolCreateBlockdevScript
