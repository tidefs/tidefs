# TideFS: kernel fsync/syncfs durability validation in QEMU.
#
# Builds the kmod-posix-vfs kernel module against Linux 7.0, boots a
# QEMU guest with persistent virtio-blk backing storage across an actual
# power-loss cycle, and exercises fsync(2), fdatasync(2), and syncfs(2)
# against the mounted TideFS kernel filesystem.
#
# Two-phase crash-consistency protocol:
#   Phase 1: mount, write, fsync/fdatasync/syncfs, poweroff -f (crash)
#   Phase 2: reboot with same backing storage, remount, verify survival
#
# The validation fails closed when the module, helper, or storage setup
# is missing.  It distinguishes infrastructure failure (BLOCKED),
# TideFS semantic failure (FAIL), and clean durability success (PASS).
#
# Validation tier: full-kernel (Tier 5) QEMU guest with power-loss cycle.
{
  pkgs,
  linuxKernel_7_0,
  tidefsPackage,
}:

let
  # Statically-compiled C helper that exercises fsync(2), fdatasync(2),
  # and syncfs(2) inside the QEMU guest.
  fsyncHelperSrc = ./tidefs-fsync-guest-helper.c;

  fsyncHelperBin = pkgs.runCommandCC "tidefs-fsync-guest-helper"
    {
      src = fsyncHelperSrc;
      # Dynamically linked; glibc is copied into initramfs at Nix store paths
      # so the dynamic linker resolves correctly inside the guest.
    }
    ''
      mkdir -p "$out/bin"
      $CC -Wall -O2 "$src" -o "$out/bin/tidefs-fsync-guest-helper"
      strip "$out/bin/tidefs-fsync-guest-helper"
    '';

  validateScript = pkgs.writeShellScriptBin "tidefs-kmod-fsync-validation" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    GZIP="${pkgs.gzip}/bin/gzip"
    LDD_BIN="${pkgs.lib.getBin pkgs.glibc}/bin/ldd"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"
    FSYNC_HELPER="${fsyncHelperBin}/bin/tidefs-fsync-guest-helper"
    TIDEFSCTL="${tidefsPackage}/bin/tidefsctl"
    GLIBC_LIB="${pkgs.glibc}/lib"

    TMPDIR="''${TIDEFS_FSYNC_TMPDIR:-/tmp/tidefs-kmod-fsync-validation}"
    SUMMARY_ROOT="''${TIDEFS_FSYNC_SUMMARY_DIR:-/tmp/tidefs-validation/kernel-fsync-validation}"
    SUMMARY_DIR="$SUMMARY_ROOT/validation-$(date -u +%Y%m%dT%H%M%SZ)-$$"
    TIMEOUT_SEC="''${TIDEFS_FSYNC_TIMEOUT:-600}"
    POOL_SIZE_MB="''${TIDEFS_FSYNC_POOL_SIZE:-256}"

    write_blocked_summary() {
      local blocker="$1"
      local detail="$2"

      mkdir -p "$SUMMARY_DIR"
      cat > "$SUMMARY_DIR/summary.env" << SUMMEOF
TIDEFS_FSYNC_STATUS=BLOCKED
TIDEFS_FSYNC_PASSED=0
TIDEFS_FSYNC_FAILED=0
TIDEFS_FSYNC_BLOCKED=1
TIDEFS_FSYNC_BLOCKER=$blocker
TIDEFS_FSYNC_KERNEL=${linuxKernel_7_0.version}
TIDEFS_FSYNC_TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
SUMMEOF
      printf 'BLOCKED: %s -- %s\n' "$blocker" "$detail" > "$SUMMARY_DIR/blocker.log"
      echo "Validation logs: $SUMMARY_DIR"
    }

    KEEP_TMP=""
    KO_PATH=""
    KERNEL_OVERRIDE=""
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --pool-size) POOL_SIZE_MB="$2"; shift 2 ;;
        --module) KO_PATH="$2"; shift 2 ;;
        --kernel) KERNEL_OVERRIDE="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h)
          cat <<USAGE
Usage: tidefs-kmod-fsync-validation [--timeout SEC] [--pool-size MB]
       [--module PATH] [--kernel PATH] [--keep-tmp]

Validate kmod-posix-vfs fsync(2), fdatasync(2), and syncfs(2) durability
across a QEMU power-loss cycle with persistent virtio-blk backing storage.

Options:
  --timeout SECONDS   QEMU boot timeout (default: $TIMEOUT_SEC)
  --pool-size MB      Backing pool disk size in MB (default: $POOL_SIZE_MB)
  --module PATH       Path to pre-built tidefs_posix_vfs.ko
  --kernel PATH       Path to Linux bzImage (default: Nix-built 7.0)
  --keep-tmp          Do not remove temp directory on exit
  --help, -h          Show this message

Exit codes:
  0  All exercised fsync/syncfs operations passed across crash cycle
  1  One or more operations failed
  2  Argument or environment error
USAGE
          exit 0
          ;;
        *) echo "ERROR: unknown option: $1" >&2; exit 2 ;;
      esac
    done

    if [ -n "$KERNEL_OVERRIDE" ] && [ -f "$KERNEL_OVERRIDE" ]; then
      KERNEL_IMG="$KERNEL_OVERRIDE"
    fi

    echo "=== TideFS Kernel Fsync/Syncfs Durability Validation ==="
    echo "  Kernel:   $KERNEL_IMG"
    echo "  QEMU:     $QEMU_BIN"
    echo "  Helper:   $FSYNC_HELPER"
    echo "  Module:   kmod-posix-vfs (tidefs_posix_vfs.ko)"
    echo "  Pool:     ''${POOL_SIZE_MB}M"
    echo "  Timeout:  ''${TIMEOUT_SEC}s"
    echo ""

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$GZIP" "$FSYNC_HELPER" "$TIDEFSCTL"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "BLOCKED: dependency not found: $dep" >&2
        write_blocked_summary "dependency_missing" "$dep"
        exit 2
      fi
    done

    # ── Resolve module .ko ─────────────────────────────────────────

    if [ -n "$KO_PATH" ] && [ -f "$KO_PATH" ]; then
      MODULE_KO="$KO_PATH"
      echo "  Module .ko (user): $MODULE_KO"
    elif [ -f "$MODULE_DIR/tidefs_posix_vfs.ko" ]; then
      MODULE_KO="$MODULE_DIR/tidefs_posix_vfs.ko"
      echo "  Module .ko (nix):  $MODULE_KO"
    else
      echo "BLOCKED: tidefs_posix_vfs.ko not found"
      echo "  Looked in: $MODULE_DIR"
      echo "  Build the kmod first with the linux_7_0 kernel tree."
      write_blocked_summary "module_missing" "tidefs_posix_vfs.ko not found in $MODULE_DIR"
      exit 1
    fi

    # ── Prepare run directory ──────────────────────────────────────

    RUN_DIR="$TMPDIR/validation-$$"
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,mnt/tidefs,validation,etc,run/tidefs/import}
    trap 'if [ -z "''${KEEP_TMP:-}" ]; then chmod -R u+w "$RUN_DIR" 2>/dev/null || true; rm -rf "$RUN_DIR"; fi' EXIT

    # Busybox + applet symlinks
    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff \
      mknod mkdir rmdir dd stat cp mv rm touch find wc head cut sync umount \
      uname date expr test mountpoint tr seq tail awk which basename dirname \
      env true false printf lsmod; do
      ln -sf /bin/busybox "$RUN_DIR/bin/$applet" 2>/dev/null || true
    done

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

    # glibc shared libraries at absolute Nix store paths
    if [ -d "$GLIBC_LIB" ]; then
      GLIBC_STORE_DIR="$(dirname "$GLIBC_LIB")"
      mkdir -p "$RUN_DIR/$GLIBC_STORE_DIR"
      cp -a "$GLIBC_LIB" "$RUN_DIR/$GLIBC_STORE_DIR/"
    fi
    copy_elf_deps "$BUSYBOX"

    cp "$TIDEFSCTL" "$RUN_DIR/bin/tidefsctl"
    chmod +x "$RUN_DIR/bin/tidefsctl"
    copy_elf_deps "$TIDEFSCTL"

    # Copy module and fsync helper into initramfs
    cp "$MODULE_KO" "$RUN_DIR/lib/modules/tidefs_posix_vfs.ko"
    mkdir -p "$RUN_DIR/usr/bin"
    cp "$FSYNC_HELPER" "$RUN_DIR/usr/bin/tidefs-fsync-guest-helper"
    chmod +x "$RUN_DIR/usr/bin/tidefs-fsync-guest-helper"
    echo "root:x:0:0:root:/root:/bin/sh" > "$RUN_DIR/etc/passwd"
    echo "root:x:0:" > "$RUN_DIR/etc/group"

    # ── Create persistent pool disk image ──────────────────────────

    POOL_DISK="$RUN_DIR/pool.img"
    dd if=/dev/zero of="$POOL_DISK" bs=1M count="$POOL_SIZE_MB" 2>/dev/null
    echo "  Pool disk: $POOL_DISK ($(du -h "$POOL_DISK" | cut -f1))"

    # ── Build initramfs helper ─────────────────────────────────────

    pack_initramfs() {
      local out_file="$1"
      (cd "$RUN_DIR" && find . \
        -path ./pool.img -prune -o \
        -path './initrd-*.gz' -prune -o \
        -path './validation-phase*.log' -prune -o \
        -path ./tidefs-validation -prune -o \
        -print | "$CPIO" -o -H newc 2>/dev/null | "$GZIP" -9) > "$out_file"
    }

    build_initramfs() {
      local init_src="$1"
      local out_file="$2"
      cat > "$RUN_DIR/init" << "INITEOF"
#!/bin/sh
export PATH=/bin:/usr/bin

mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

# devtmpfs should provide virtio-blk nodes; create the first two common nodes
# explicitly so minimal guests can still discover the attached pool image.
[ ! -b /dev/vda ] && mknod /dev/vda b 254 0 2>/dev/null || true
[ ! -b /dev/vdb ] && mknod /dev/vdb b 254 16 2>/dev/null || true

echo "=== TideFS Kernel Fsync Validation ==="
echo "kernel=$(uname -r)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

PASSED=0
FAILED=0
BLOCKED=0

pass()    { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
fail()    { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); }
blocked() { echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); }

MNT=/mnt/tidefs
EVDIR=/validation
POOL_NAME=fsync_qemu_pool
POOL_READY=0
mkdir -p "$EVDIR" "$MNT" /run/tidefs/import 2>/dev/null

# ── Discover virtio-blk pool device ──────────────────────────────
POOL_DEV=""
for _ in $(seq 1 30); do
  for d in /dev/vda /dev/vdb; do
    [ -b "$d" ] && { POOL_DEV="$d"; break; }
  done
  [ -n "$POOL_DEV" ] && break
  sleep 1
done
if [ -z "$POOL_DEV" ]; then
  blocked "virtio_blk_device" "no virtio block device found"
  echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
  poweroff -f
fi
pass "virtio_blk_device"

# ── Load kmod-posix-vfs ──────────────────────────────────────────
echo "--- Loading kmod-posix-vfs ---"
MOD=/lib/modules/tidefs_posix_vfs.ko
if [ -f "$MOD" ]; then
  if insmod "$MOD" 2>/tmp/insmod.err; then
    pass "module_load"
  else
    INSERR=$(head -3 /tmp/insmod.err 2>/dev/null || echo "insmod failure")
    fail "module_load" "$INSERR"
    echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
    poweroff -f
  fi
else
  blocked "module_load" "tidefs_posix_vfs.ko not found in initramfs"
  echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
  poweroff -f
fi

# Verify module is loaded
sleep 1
if grep -qi tidefs /proc/modules 2>/dev/null; then
  pass "module_lsmod"
else
  blocked "module_lsmod" "tidefs not in /proc/modules"
fi

INITEOF

      cat >> "$RUN_DIR/init" << "INITEOF2"

# ── Seed a configured TideFS pool member ─────────────────────────
echo "--- Creating TideFS pool label and committed-root seed ---"
if [ -b "$POOL_DEV" ] && command -v tidefsctl >/dev/null 2>&1; then
  COUT=$(tidefsctl pool create "$POOL_NAME" --devices "$POOL_DEV" --json 2>&1)
  RC=$?
  echo "  tidefsctl pool create exit=$RC"
  if [ "$RC" -eq 0 ]; then
    pass "pool_member_created"
    SOUT=$(tidefsctl pool scan --devices "$POOL_DEV" 2>&1)
    SRC=$?
    if [ "$SRC" -eq 0 ] && echo "$SOUT" | grep -qi "label"; then
      pass "pool_label_verified"
      POOL_READY=1
    else
      fail "pool_label_verified" "$SOUT"
    fi
  else
    fail "pool_member_created" "$COUT"
    blocked "pool_label_verified" "pool member was not created"
  fi
else
  if [ ! -b "$POOL_DEV" ]; then
    blocked "pool_member_created" "virtio pool device missing"
  else
    blocked "pool_member_created" "tidefsctl not found in initramfs"
  fi
  blocked "pool_label_verified" "pool member was not created"
fi

# ── Mount TideFS ─────────────────────────────────────────────────
echo "--- Mounting TideFS ---"

MOUNT_OK=0
if [ "$POOL_READY" -eq 1 ]; then
  if mount -t tidefs "$POOL_DEV" "$MNT" 2>/tmp/mount.err; then
    pass "mount_pool_backed"
    MOUNT_OK=1
  else
    MERR=$(head -3 /tmp/mount.err 2>/dev/null | tr '\n' ' ')
    fail "mount_pool_backed" "$MERR"
  fi
else
  blocked "mount_pool_backed" "pool member was not ready"
fi

# Bootstrap mounts are intentionally not accepted for this durability row:
# they do not prove persistence across the attached virtio-backed crash cycle.
if [ "$MOUNT_OK" -eq 0 ]; then
  if mount -t tidefs -o bootstrap none "$MNT" 2>/tmp/mount_bootstrap.err; then
    blocked "mount_bootstrap_diagnostic" "bootstrap mount works, but persistent device mount failed"
    umount "$MNT" 2>/dev/null || true
  else
    MERR=$(head -3 /tmp/mount_bootstrap.err 2>/dev/null | tr '\n' ' ')
    blocked "mount_bootstrap_diagnostic" "$MERR"
  fi
fi

if [ "$MOUNT_OK" -eq 0 ]; then
  echo "FILESYSTEM_NOT_MOUNTED=1"
  echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
  poweroff -f
fi

# ── Run the fsync/fdatasync/syncfs helper ────────────────────────
echo "--- Running fsync/fdatasync/syncfs helper ---"
HELPER=/usr/bin/tidefs-fsync-guest-helper
if [ -x "$HELPER" ]; then
  "$HELPER" "$MNT" 2>/tmp/helper.err
  HELPER_RC=$?
  if [ -f /tmp/helper.err ] && [ -s /tmp/helper.err ]; then
    echo "  helper stderr: $(head -5 /tmp/helper.err | tr '\n' ' ')"
  fi
else
  blocked "fsync_helper" "tidefs-fsync-guest-helper not found or not executable"
fi

echo ""
echo "=== Phase 1 Durability Setup Complete ==="
echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
# Do not run sync here. The crash row must depend only on the fsync,
# fdatasync, and syncfs calls exercised above.
poweroff -f
INITEOF2

      chmod +x "$RUN_DIR/init"
      pack_initramfs "$out_file"
    }

    # ── Phase 1: write + fsync + crash ─────────────────────────────
    echo ""
    echo "=== Phase 1: Write, fsync/syncfs, simulated crash ==="

    build_initramfs "$RUN_DIR/init-phase1" "$RUN_DIR/initrd-p1.gz"

    VAL_LOG_P1="$RUN_DIR/validation-phase1.log"
    echo "  Booting QEMU phase 1..."

    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$RUN_DIR/initrd-p1.gz" \
      -append "console=ttyS0 quiet panic=10" \
      -m 512M \
      -smp 1 \
      -nographic \
      -no-reboot \
      -drive file="$POOL_DISK",if=virtio,format=raw \
      > "$VAL_LOG_P1" 2>&1 || true

    echo "  Phase 1 QEMU exited ($(wc -l < "$VAL_LOG_P1" 2>/dev/null || echo 0) lines)"

    # ── Phase 2: reboot + verify persistence ───────────────────────
    echo ""
    echo "=== Phase 2: Reboot + durability verification ==="

    # Build fresh init for phase 2: remount and verify
    cat > "$RUN_DIR/init" << 'P2INIT'
#!/bin/sh
export PATH=/bin:/usr/bin

mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

[ ! -b /dev/vda ] && mknod /dev/vda b 254 0 2>/dev/null || true
[ ! -b /dev/vdb ] && mknod /dev/vdb b 254 16 2>/dev/null || true

echo "=== TideFS Kernel Fsync Phase 2: Post-Crash Verification ==="
echo "kernel=$(uname -r)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

PASSED=0
FAILED=0
BLOCKED=0

pass()    { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
fail()    { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); }
blocked() { echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); }

MNT=/mnt/tidefs
EVDIR=/validation
mkdir -p "$EVDIR" "$MNT" /run/tidefs/import 2>/dev/null

# ── Rediscover persistent virtio-blk pool device ─────────────────
POOL_DEV=""
for _ in $(seq 1 30); do
  for d in /dev/vda /dev/vdb; do
    [ -b "$d" ] && { POOL_DEV="$d"; break; }
  done
  [ -n "$POOL_DEV" ] && break
  sleep 1
done
if [ -z "$POOL_DEV" ]; then
  blocked "p2_virtio_blk_device" "no virtio block device found"
  echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
  poweroff -f
fi
pass "p2_virtio_blk_device"

# ── Reload module after crash ────────────────────────────────────
echo "--- Reloading kmod-posix-vfs after crash ---"
MOD=/lib/modules/tidefs_posix_vfs.ko
if [ -f "$MOD" ]; then
  if insmod "$MOD" 2>/tmp/insmod_p2.err; then
    pass "p2_module_reload"
  else
    INSERR=$(head -3 /tmp/insmod_p2.err 2>/dev/null || echo "insmod failure")
    fail "p2_module_reload" "$INSERR"
    echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
    poweroff -f
  fi
else
  blocked "p2_module_reload" "tidefs_posix_vfs.ko not found"
  echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
  poweroff -f
fi

sleep 1
grep -qi tidefs /proc/modules 2>/dev/null && pass "p2_module_lsmod" \
  || blocked "p2_module_lsmod" "tidefs not in /proc/modules"

# ── Remount after crash ──────────────────────────────────────────
echo "--- Remounting TideFS after crash ---"
REMOUNT_OK=0
if mount -t tidefs "$POOL_DEV" "$MNT" 2>/tmp/mount_p2.err; then
  pass "p2_remount_pool"
  REMOUNT_OK=1
else
  MERR=$(head -3 /tmp/mount_p2.err 2>/dev/null | tr '\n' ' ')
  fail "p2_remount_pool" "$MERR"
fi

if [ "$REMOUNT_OK" -eq 0 ]; then
  if mount -t tidefs -o bootstrap none "$MNT" 2>/tmp/mount_p2_bootstrap.err; then
    blocked "p2_remount_bootstrap_diagnostic" "bootstrap remount works, but persistent device remount failed"
    umount "$MNT" 2>/dev/null || true
  else
    MERR=$(head -3 /tmp/mount_p2_bootstrap.err 2>/dev/null | tr '\n' ' ')
    blocked "p2_remount_bootstrap_diagnostic" "$MERR"
  fi
fi

if [ "$REMOUNT_OK" -eq 0 ]; then
  echo "FILESYSTEM_NOT_MOUNTED_P2=1"
  echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
  poweroff -f
fi

# ── Verify fsync test file survived crash ────────────────────────
echo "--- Verifying fsync durability ---"
FSYNC_FILE="$MNT/fsync_test.dat"
if [ -f "$FSYNC_FILE" ]; then
  CONTENT=$(cat "$FSYNC_FILE" 2>/dev/null || echo "")
  if echo "$CONTENT" | grep -q "FSYNC_TEST_DATA"; then
    pass "p2_fsync_data_survived"
  else
    fail "p2_fsync_data_survived" "content mismatch: got $(echo "$CONTENT" | head -c 40)"
  fi
else
  fail "p2_fsync_data_survived" "fsync_test.dat not found after crash"
fi

# ── Verify fdatasync test file survived crash ────────────────────
FDAT_FILE="$MNT/fdatasync_test.dat"
if [ -f "$FDAT_FILE" ]; then
  CONTENT=$(cat "$FDAT_FILE" 2>/dev/null || echo "")
  if echo "$CONTENT" | grep -q "FDATASYNC_TEST_DATA"; then
    pass "p2_fdatasync_data_survived"
  else
    fail "p2_fdatasync_data_survived" "content mismatch: got $(echo "$CONTENT" | head -c 40)"
  fi
else
  fail "p2_fdatasync_data_survived" "fdatasync_test.dat not found after crash"
fi

# ── Verify syncfs extra file survived crash ──────────────────────
SYNCFS_FILE="$MNT/syncfs_extra.dat"
if [ -f "$SYNCFS_FILE" ]; then
  CONTENT=$(cat "$SYNCFS_FILE" 2>/dev/null || echo "")
  if echo "$CONTENT" | grep -q "SYNCFS_EXTRA"; then
    pass "p2_syncfs_data_survived"
  else
    fail "p2_syncfs_data_survived" "content mismatch: got $(echo "$CONTENT" | head -c 40)"
  fi
else
  fail "p2_syncfs_data_survived" "syncfs_extra.dat not found after crash"
fi

# ── Run helper again post-crash ──────────────────────────────────
echo "--- Running fsync helper post-crash ---"
HELPER=/usr/bin/tidefs-fsync-guest-helper
if [ -x "$HELPER" ]; then
  "$HELPER" "$MNT" 2>/tmp/helper_p2.err || true
else
  blocked "p2_fsync_helper" "helper not found post-crash"
fi

# ── Post-crash dmesg integrity ───────────────────────────────────
echo "--- Post-crash dmesg integrity ---"
DMESG_BUGS=$(dmesg 2>/dev/null | grep -cE "BUG:|Kernel panic|Oops:|WARNING:" || true)
if [ "$DMESG_BUGS" -eq 0 ]; then
  pass "p2_dmesg_clean"
else
  fail "p2_dmesg_clean" "dmesg has $DMESG_BUGS bug/panic lines"
fi

echo ""
echo "=== Phase 2 Verification Complete ==="
echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
sync
poweroff -f
P2INIT

    chmod +x "$RUN_DIR/init"
    pack_initramfs "$RUN_DIR/initrd-p2.gz"

    VAL_LOG_P2="$RUN_DIR/validation-phase2.log"
    echo "  Booting QEMU phase 2 (same backing disk)..."

    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$RUN_DIR/initrd-p2.gz" \
      -append "console=ttyS0 quiet panic=10" \
      -m 512M \
      -smp 1 \
      -nographic \
      -no-reboot \
      -drive file="$POOL_DISK",if=virtio,format=raw \
      > "$VAL_LOG_P2" 2>&1 || true

    echo "  Phase 2 QEMU exited ($(wc -l < "$VAL_LOG_P2" 2>/dev/null || echo 0) lines)"

    # ── Parse results ──────────────────────────────────────────────

    parse_results() {
      local log="$1"
      local label="$2"
      local p=0; local f=0; local b=0

      while IFS= read -r line; do
        case "$line" in
          "PASS: "*) p=$((p + 1)) ;;
          "FAIL: "*) f=$((f + 1)) ;;
          "BLOCKED: "*) b=$((b + 1)) ;;
        esac
      done < "$log"

      echo "  $label: $p passed, $f failed, $b blocked"
      return 0
    }

    echo ""
    echo "=== TideFS Kernel Fsync/Syncfs Validation Results ==="

    parse_results "$VAL_LOG_P1" "Phase 1 (write+fsync+crash)"
    parse_results "$VAL_LOG_P2" "Phase 2 (reboot+verify)"

    # ── Detailed operation-level results ───────────────────────────

    echo ""
    echo "--- Per-operation results ---"

    TOTAL_PASS=0
    TOTAL_FAIL=0
    TOTAL_BLOCKED=0

    for op in \
      virtio_blk_device module_load module_lsmod \
      pool_member_created pool_label_verified mount_pool_backed \
      fsync_fd fdatasync_fd syncfs_fd \
      p2_virtio_blk_device p2_module_reload p2_module_lsmod p2_remount_pool \
      p2_fsync_data_survived p2_fdatasync_data_survived \
      p2_syncfs_data_survived p2_dmesg_clean; do
      found=0
      for log in "$VAL_LOG_P1" "$VAL_LOG_P2"; do
        if grep -q "PASS: $op" "$log" 2>/dev/null; then
          echo "  PASS: $op"
          TOTAL_PASS=$((TOTAL_PASS + 1))
          found=1
          break
        elif grep -q "FAIL: $op" "$log" 2>/dev/null; then
          detail=$(grep "FAIL: $op" "$log" 2>/dev/null | head -1 | sed "s/FAIL: $op -- //")
          echo "  FAIL: $op -- $detail"
          TOTAL_FAIL=$((TOTAL_FAIL + 1))
          found=1
          break
        elif grep -q "BLOCKED: $op" "$log" 2>/dev/null; then
          detail=$(grep "BLOCKED: $op" "$log" 2>/dev/null | head -1 | sed "s/BLOCKED: $op -- //")
          echo "  BLOCKED: $op -- $detail"
          TOTAL_BLOCKED=$((TOTAL_BLOCKED + 1))
          found=1
          break
        fi
      done
      if [ "$found" -eq 0 ]; then
        echo "  MISSING: $op (no result in either phase log)"
        TOTAL_BLOCKED=$((TOTAL_BLOCKED + 1))
      fi
    done

    echo ""
    echo "Summary: $TOTAL_PASS passed, $TOTAL_FAIL failed, $TOTAL_BLOCKED blocked"

    # ── Write summary env for artifact upload ──────────────────────
    mkdir -p "$SUMMARY_DIR"
    SUMMARY_STATUS=PASS
    if [ "$TOTAL_FAIL" -gt 0 ]; then
      SUMMARY_STATUS=FAIL
    elif [ "$TOTAL_BLOCKED" -gt 0 ]; then
      SUMMARY_STATUS=BLOCKED
    fi
    cat > "$SUMMARY_DIR/summary.env" << SUMMEOF
TIDEFS_FSYNC_STATUS=$SUMMARY_STATUS
TIDEFS_FSYNC_PASSED=$TOTAL_PASS
TIDEFS_FSYNC_FAILED=$TOTAL_FAIL
TIDEFS_FSYNC_BLOCKED=$TOTAL_BLOCKED
TIDEFS_FSYNC_KERNEL=${linuxKernel_7_0.version}
TIDEFS_FSYNC_TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
SUMMEOF

    cp "$VAL_LOG_P1" "$SUMMARY_DIR/phase1.log" 2>/dev/null || true
    cp "$VAL_LOG_P2" "$SUMMARY_DIR/phase2.log" 2>/dev/null || true

    echo "Validation logs: $SUMMARY_DIR"

    if [ "$TOTAL_FAIL" -gt 0 ]; then
      echo ""
      echo "VALIDATION: FAIL -- $TOTAL_FAIL fsync/syncfs durability failures"
      exit 1
    fi

    if [ "$TOTAL_BLOCKED" -gt 0 ]; then
      echo ""
      echo "VALIDATION: BLOCKED -- $TOTAL_BLOCKED setup or durability rows blocked"
      exit 1
    fi

    echo ""
    echo "VALIDATION: PASS -- all fsync/syncfs durability rows passed across crash cycle"
    exit 0
  '';
in
validateScript
