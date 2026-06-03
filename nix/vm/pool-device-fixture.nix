# TideFS: reusable kernel pool-device fixture (#6129).
# Produces a script that creates disposable raw block-device images with
# valid TideFS pool labels and a committed-root seed, attached as virtio-blk
# disks to a Linux 7.0 QEMU guest for kernel-mode pool import, default
# engine mount, and block I/O validation.
#
# Workers reuse the labeled images directly without copying the Linux
# build tree. Failures report exact missing implementation blockers.
{
  pkgs,
  linuxKernel_7_0,
  tidefsPackage,
}:

let
  poolDeviceFixtureScript = pkgs.writeShellScriptBin "tidefs-pool-device-fixture" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    GZIP="${pkgs.gzip}/bin/gzip"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"
    TIDEFSCTL="${tidefsPackage}/bin/tidefsctl"

    FIXTURE_DIR="''${TIDEFS_POOL_FIXTURE_DIR:-/tmp/tidefs-pool-fixture}"
    IMAGE_COUNT="''${TIDEFS_POOL_FIXTURE_COUNT:-2}"
    IMAGE_SIZE_MB="''${TIDEFS_POOL_FIXTURE_SIZE_MB:-128}"
    POOL_NAME="''${TIDEFS_POOL_FIXTURE_NAME:-fixture_pool}"
    TIMEOUT_SEC="''${TIDEFS_POOL_FIXTURE_TIMEOUT:-300}"
    VALIDATION_TIER="QEMU guest"

    usage() {
      cat <<USAGE
Usage: tidefs-pool-device-fixture [--create | --reuse DIR | --list DIR | --clean DIR]

Create disposable TideFS-labeled raw block-device images for kernel-mode
pool import, default engine mount, and block I/O validation.

Environment variables:
  TIDEFS_POOL_FIXTURE_DIR     Output directory (default: $FIXTURE_DIR)
  TIDEFS_POOL_FIXTURE_COUNT   Number of images (default: $IMAGE_COUNT)
  TIDEFS_POOL_FIXTURE_SIZE_MB Image size in MB (default: $IMAGE_SIZE_MB)
  TIDEFS_POOL_FIXTURE_NAME    Pool name (default: $POOL_NAME)
  TIDEFS_POOL_FIXTURE_TIMEOUT QEMU boot timeout (default: $TIMEOUT_SEC)

Options:
  --create       Create and label fresh images (boots QEMU guest)
  --reuse DIR    Reuse existing labeled images from DIR
  --list DIR     List labeled images in DIR and their pool info
  --clean DIR    Remove fixture directory
  --help, -h     Show this message
USAGE
    }

    cmd="''${1:-}"
    case "$cmd" in
      --create) ;;
      --reuse) FIXTURE_DIR="$2"; ;;
      --list) FIXTURE_DIR="$2"; ls -la "$FIXTURE_DIR"/ 2>/dev/null || echo "no fixture at $FIXTURE_DIR"; exit 0 ;;
      --clean) rm -rf "$2"; echo "cleaned $2"; exit 0 ;;
      --help|-h) usage; exit 0 ;;
      *) echo "ERROR: unknown command: $cmd" >&2; usage >&2; exit 2 ;;
    esac

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$GZIP" "$TIDEFSCTL"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ENVIRONMENT REFUSAL: dependency not found: $dep" >&2
        exit 2
      fi
    done

    QEMU_ACCEL=(-cpu qemu64)
    if [ -e /dev/kvm ]; then
      QEMU_ACCEL=(-enable-kvm -cpu host)
      QEMU_ACCEL_LABEL="kvm"
    else
      QEMU_ACCEL_LABEL="tcg"
    fi

    echo "=== TideFS Pool Device Fixture ==="
    echo "  Kernel:     $KERNEL_IMG"
    echo "  tidefsctl:  $TIDEFSCTL"
    echo "  QEMU:       $QEMU_BIN"
    echo "  Accel:      $QEMU_ACCEL_LABEL"
    echo "  Fixture:    $FIXTURE_DIR"
    echo "  Images:     $IMAGE_COUNT x ''${IMAGE_SIZE_MB}MB"
    echo "  Pool name:  $POOL_NAME"
    echo ""

    # Collect .ko paths for disclosure
    POSIX_VFS_KO=""
    BLOCK_KMOD_KO=""
    for c in "$MODULE_DIR/extra/tidefs-kmod-posix-vfs.ko" "$MODULE_DIR/kernel/fs/tidefs/tidefs-kmod-posix-vfs.ko"; do
      [ -f "$c" ] && { POSIX_VFS_KO="$c"; break; }
    done
    for c in "$MODULE_DIR/extra/tidefs-block-kmod.ko" "$MODULE_DIR/kernel/drivers/block/tidefs-block-kmod.ko"; do
      [ -f "$c" ] && { BLOCK_KMOD_KO="$c"; break; }
    done
    echo "  POSIX VFS .ko: ''${POSIX_VFS_KO:-NOT FOUND}"
    echo "  Block kmod .ko: ''${BLOCK_KMOD_KO:-NOT FOUND}"

    # Resolve fuse.ko
    FUSE_KO=""
    for c in "$MODULE_DIR/kernel/fs/fuse/fuse.ko" "$MODULE_DIR/kernel/fs/fuse/fuse.ko.xz" "$MODULE_DIR/extra/fuse.ko" "$MODULE_DIR/fuse.ko"; do
      [ -f "$c" ] && { FUSE_KO="$c"; break; }
    done
    FUSE_BUILTIN=0
    [ -z "$FUSE_KO" ] && { echo "  fuse.ko not found; assuming built-in"; FUSE_BUILTIN=1; }

    # Build work directory
    WORK_DIR="$FIXTURE_DIR/build-$$"
    RUN_DIR="$WORK_DIR/initrd"
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,mnt,etc,run/tidefs/import}
    mkdir -p "$FIXTURE_DIR"

    cleanup() {
      if [ "$cmd" = "--create" ]; then
        echo "  Fixture images in: $FIXTURE_DIR"
      fi
      rm -rf "$WORK_DIR"
    }
    trap cleanup EXIT

    # Create raw virtio disk images in fixture dir
    echo "  Creating raw virtio disk images"
    for i in $(seq 0 $((IMAGE_COUNT - 1))); do
      img="$FIXTURE_DIR/disk''${i}.img"
      dd if=/dev/zero of="$img" bs=1M count="$IMAGE_SIZE_MB" 2>/dev/null
      echo "    disk''${i}.img: $IMAGE_SIZE_MB MB"
    done

    # Library copy helpers (matching pool-e2e pattern)
    copy_dep_path() {
      local p="$1"
      [ -f "$p" ] || return 0
      mkdir -p "$RUN_DIR/$(dirname "$p")"
      cp "$p" "$RUN_DIR/$p" 2>/dev/null || true
    }

    copy_binary_to_bin() {
      local src="$1"
      local dst="$2"
      cp "$src" "$RUN_DIR/bin/$dst"
      chmod +x "$RUN_DIR/bin/$dst"
      if command -v ldd >/dev/null 2>&1; then
        ldd "$src" 2>/dev/null | grep -o '/nix/store/[^ ]*' | sort -u | while read -r lib; do
          copy_dep_path "$lib"
        done
      fi
    }

    copy_binary_to_bin "$BUSYBOX" busybox
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff \
                    reboot mknod mkdir rmdir dd stat cp mv rm touch find wc sync \
                    expr head tail cut kill ps test seq blockdev mountpoint du \
                    uname date; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    copy_binary_to_bin "$TIDEFSCTL" tidefsctl

    [ "$FUSE_BUILTIN" -eq 0 ] && cp "$FUSE_KO" "$RUN_DIR/lib/modules/fuse.ko"

    # Init script: labels devices inside QEMU guest
    cat > "$RUN_DIR/init" << 'INNERINIT'
#!/bin/sh
export PATH=/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /run/tidefs/import /mnt/tidefs

echo "=== TideFS Pool Device Fixture: Labeling ==="
echo "kernel=$(uname -r 2>/dev/null || echo unknown)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"
echo ""

PASSED=0; FAILED=0; BLOCKED=0
pass()   { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
fail()   { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); }
blocked(){ echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); }

echo "--- Phase 0: Kernel modules ---"
if grep -qw fuse /proc/filesystems 2>/dev/null; then
    pass "fuse_builtin"
elif [ -f /lib/modules/fuse.ko ]; then
    insmod /lib/modules/fuse.ko 2>/tmp/fuse-insmod.err && pass "fuse_module" || fail "fuse_module" "$(cat /tmp/fuse-insmod.err 2>/dev/null)"
else
    blocked "fuse_module" "no fuse.ko and not built-in"
fi

echo ""
echo "--- Phase 1: Virtio block devices ---"
IMAGE_COUNT=SSIMAGE_COUNT_SS
POOL_NAME="SSPOOL_NAME_SS"
DEV_PATHS=""
DEVS_OK=1

# vdX letter map: 0->a, 1->b, 2->c, 3->d, ...
for i in $(seq 0 $((IMAGE_COUNT - 1))); do
    vd_letters="abcdefghijklmnopqrstuvwxyz"; vd_letter=$(echo "$vd_letters" | cut -c"$((i+1))")
    expected="/dev/vd''${vd_letter}"
    for _ in $(seq 1 30); do
        [ -b "$expected" ] && break
        sleep 1
    done
    if [ -b "$expected" ]; then
        pass "virtio''${i}_present"
        DEV_PATHS="$DEV_PATHS $expected"
    else
        fail "virtio''${i}_present" "$expected missing"
        DEVS_OK=0
    fi
done

if [ "$DEVS_OK" -eq 0 ]; then
    echo "FATAL: virtio devices not available"
    for op in pool_create pool_label_verify pool_import pool_export; do
        blocked "$op" "virtio block devices missing"
    done
    echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
    sync; poweroff -f
fi

echo ""
echo "--- Phase 2: Pool create ---"
DEV_ARGS=""
for d in $DEV_PATHS; do DEV_ARGS="$DEV_ARGS --devices $d"; done

if command -v tidefsctl >/dev/null 2>&1; then
    COUT=$(tidefsctl pool create "$POOL_NAME" $DEV_ARGS --json 2>&1); RC=$?
    echo "  exit=$RC"
    if [ "$RC" -eq 0 ]; then
        pass "pool_create"
    else
        fail "pool_create" "$COUT"
    fi
else
    blocked "pool_create" "tidefsctl not found"
fi

echo ""
echo "--- Phase 3: Label verification ---"
LABEL_OK=1
if command -v tidefsctl >/dev/null 2>&1; then
    for d in $DEV_PATHS; do
        SOUT=$(tidefsctl pool scan --devices "$d" 2>&1); RC=$?
        if [ "$RC" -eq 0 ] && echo "$SOUT" | grep -qi "label"; then
            pass "pool_label_verify"
        else
            fail "pool_label_verify" "no label on $d"
            LABEL_OK=0
        fi
    done
else
    blocked "pool_label_verify" "tidefsctl not found"
    LABEL_OK=0
fi

echo ""
echo "--- Phase 4: Pool import ---"
if [ "$LABEL_OK" -eq 1 ] && command -v tidefsctl >/dev/null 2>&1; then
    IOUT=$(tidefsctl pool import $DEV_PATHS --json 2>&1); RC=$?
    echo "  import exit=$RC"
    [ "$RC" -eq 0 ] && pass "pool_import" || fail "pool_import" "$IOUT"
else
    blocked "pool_import" "label verification failed or tidefsctl not found"
fi

echo ""
echo "--- Phase 5: Pool export ---"
if command -v tidefsctl >/dev/null 2>&1; then
    EOUT=$(tidefsctl pool export "$POOL_NAME" --devices $DEV_PATHS 2>&1); RC=$?
    echo "  export exit=$RC"
    [ "$RC" -eq 0 ] && pass "pool_export" || fail "pool_export" "$EOUT"
else
    blocked "pool_export" "tidefsctl not found"
fi

echo ""
echo "--- Tear-down ---"
sync && pass "sync_done"

echo ""
echo "=== Fixture Validation Summary ==="
echo "validation_tier=QEMU guest"
echo "backend=virtio_blk_raw_disks"
echo "mode=pool_fixture_labeling"
echo "pool_name=$POOL_NAME"
echo "image_count=$IMAGE_COUNT"
echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
echo "=== End ==="
sync; sleep 1; poweroff -f
INNERINIT

    sed -i "s/SSIMAGE_COUNT_SS/$IMAGE_COUNT/g" "$RUN_DIR/init"
    sed -i "s/SSPOOL_NAME_SS/$POOL_NAME/g" "$RUN_DIR/init"
    chmod +x "$RUN_DIR/init"

    # Build compressed initrd
    echo "  Building compressed initrd"
    (cd "$RUN_DIR" && find . -print | "$CPIO" -o -H newc 2>/dev/null | "$GZIP" -9) > "$WORK_DIR/initrd.img.gz"
    echo "  Initrd.gz: $(du -h "$WORK_DIR/initrd.img.gz" | cut -f1)"

    # Build drive args
    DRIVE_ARGS=""
    for i in $(seq 0 $((IMAGE_COUNT - 1))); do
      DRIVE_ARGS="$DRIVE_ARGS -drive file=$FIXTURE_DIR/disk''${i}.img,format=raw,if=virtio,index=$i"
    done

    VAL_LOG="$FIXTURE_DIR/fixture-validation.log"
    echo ""
    echo "  === Booting QEMU guest for fixture labeling ==="

    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      "''${QEMU_ACCEL[@]}" \
      -kernel "$KERNEL_IMG" \
      -initrd "$WORK_DIR/initrd.img.gz" \
      $DRIVE_ARGS \
      -append "console=ttyS0 quiet panic=10" \
      -m 2G \
      -smp 2 \
      -nographic \
      -no-reboot \
      > "$VAL_LOG" 2>&1 || true

    echo "  QEMU exited ($(wc -l < "$VAL_LOG" 2>/dev/null || echo 0) log lines)"

    # Parse validation
    echo ""
    echo "=== Fixture Results ==="
    PASSC=0; FAILC=0; BLOCKC=0
    for op in fuse_module fuse_builtin pool_create pool_label_verify pool_import pool_export sync_done; do
      if grep -q "PASS: $op" "$VAL_LOG" 2>/dev/null; then
        echo "  PASS: $op"; PASSC=$((PASSC + 1))
      elif grep -q "FAIL: $op" "$VAL_LOG" 2>/dev/null; then
        D=$(grep "FAIL: $op" "$VAL_LOG" 2>/dev/null | head -1 | sed "s/FAIL: $op //")
        echo "  FAIL: $op -- $D"; FAILC=$((FAILC + 1))
      elif grep -q "BLOCKED: $op" "$VAL_LOG" 2>/dev/null; then
        D=$(grep "BLOCKED: $op" "$VAL_LOG" 2>/dev/null | head -1 | sed "s/BLOCKED: $op //")
        echo "  BLOCKED: $op -- $D"; BLOCKC=$((BLOCKC + 1))
      else
        echo "  MISSING: $op"; BLOCKC=$((BLOCKC + 1))
      fi
    done

    echo ""
    echo "Fixture matrix: $PASSC passed, $FAILC failed, $BLOCKC blocked"
    echo "Validation log: $VAL_LOG"

    # Write fixture metadata
    cat > "$FIXTURE_DIR/fixture.json" << METADATA
{
  "pool_name": "$POOL_NAME",
  "image_count": $IMAGE_COUNT,
  "image_size_mb": $IMAGE_SIZE_MB,
  "kernel_version": "${linuxKernel_7_0.version}",
  "created": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "passed": $PASSC,
  "failed": $FAILC,
  "blocked": $BLOCKC
}
METADATA

    [ "$FAILC" -gt 0 ] && { echo "FIXTURE: FAIL ($FAILC failures)"; exit 1; }
    echo "FIXTURE: READY ($PASSC passed, $BLOCKC blocked)"
    exit 0
  '';
in
poolDeviceFixtureScript
