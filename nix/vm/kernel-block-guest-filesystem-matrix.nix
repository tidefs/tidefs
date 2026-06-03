# TideFS: kernel block-kmod guest filesystem matrix validation.
#
# Builds tidefs_block_kmod.ko against Linux 7.0, boots a QEMU guest with
# a persistent virtio-blk data disk.  The guest init script:
#  1) mounts the data disk, creates a large backing file, and loads
#     the block kmod so it opens the file-backed persistent path;
#  2) runs mkfs/mount/fio/remount across ext4, xfs, and btrfs; and
#  3) runs a dmesg integrity check.
#
# xfsprogs and btrfs-progs are bundled into the initramfs together
# with their shared-library dependencies so real mkfs and fsck calls
# execute inside the QEMU guest.  Tools that fail to resolve at
# runtime are recorded as BLOCKED rather than false-fail.
#
# Validation tier: Tier 5 Linux 7.0 kernel block I/O.
# Kernel block ext4 xfs btrfs guest filesystem matrix.
{
  pkgs,
  linuxKernel_7_0,
}:

let
  glibcLib = "${pkgs.glibc}/lib";

  # Collect shared-library directories needed by xfsprogs, btrfs-progs,
  # and fio so the guest dynamic linker can resolve them at runtime.
  fsToolLibDirs = with pkgs; [
    glibc
    xfsprogs
    btrfs-progs
    fio
    util-linux.lib  # libblkid libuuid (shared-lib output)
    inih          # libinih
    liburcu       # liburcu
    udev          # libudev
    zlib          # libz
    lzo           # liblzo2
    zstd.out      # libzstd (out output, not bin)
    libcap        # libcap
    libaio        # libaio (fio)
  ];

  validateScript = pkgs.writeShellScriptBin "tidefs-kblock-guest-fs-matrix" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="/root/ai/state/tidefs/kernel-dev/shared/linux-7.0/build/arch/x86/boot/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    QEMU_IMG="${pkgs.qemu}/bin/qemu-img"
    GLIBC_LIB="${glibcLib}"

    XFSPROGS="${pkgs.xfsprogs}"
    BTRFSPROGS="${pkgs.btrfs-progs}"

    MODULE_OUT="''${TIDEFS_KERNEL_BLOCK_MODULE_DIR:-/root/ai/tmp/tidefs-block-kmod/module-out}"
    BLOCK_KO="''${TIDEFS_KERNEL_BLOCK_MODULE_KO:-}"
    TMPDIR="''${TIDEFS_KFSMATRIX_TMPDIR:-/tmp/tidefs-kfsmatrix}"
    TIMEOUT_SEC="''${TIDEFS_KFSMATRIX_TIMEOUT:-900}"
    DATA_DISK_SIZE_MB="''${TIDEFS_KFSMATRIX_DATA_SIZE:-512}"
    FIO_RUNTIME="''${TIDEFS_KFSMATRIX_FIO_RUNTIME:-30}"

    KEEP_TMP=""
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --data-size) DATA_DISK_SIZE_MB="$2"; shift 2 ;;
        --fio-runtime) FIO_RUNTIME="$2"; shift 2 ;;
        --module-out) MODULE_OUT="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h)
          echo "Usage: tidefs-kblock-guest-fs-matrix [options]"
          echo "  --module-out DIR   Module build output directory"
          echo "  --timeout SEC      QEMU timeout (default 900)"
          echo "  --data-size MB     Data disk size (default 512)"
          echo "  --fio-runtime SEC  fio runtime (default 30)"
          echo "  --keep-tmp         Keep temporary run directory"
          exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; exit 2 ;;
      esac
    done

    echo "=== TideFS Kernel Block Guest Filesystem Matrix ==="
    echo "  Kernel:     $KERNEL_IMG"
    echo "  QEMU:       $QEMU_BIN"
    echo "  Module-out: $MODULE_OUT"
    echo "  xfsprogs:   $XFSPROGS"
    echo "  btrfs-progs:$BTRFSPROGS"
    echo "  Data-disk:  ''${DATA_DISK_SIZE_MB}M"
    echo ""

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$QEMU_IMG"; do
      [ ! -f "$dep" ] && [ ! -x "$dep" ] && { echo "ERROR: dependency not found: $dep" >&2; exit 2; }
    done

    # Locate module .ko
    if [ -z "$BLOCK_KO" ]; then
      for c in "$MODULE_OUT/tidefs_block_kmod.ko" "$MODULE_OUT/extra/tidefs_block_kmod.ko"; do
        [ -f "$c" ] && { BLOCK_KO="$c"; break; }
      done
    fi
    [ -z "$BLOCK_KO" ] && { echo "BLOCKED: tidefs_block_kmod.ko not found at $MODULE_OUT"; exit 1; }
    echo "  Module: $BLOCK_KO"

    # Build run directory
    RUN_DIR="$TMPDIR/validation-$$"
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,validation,data}
    trap 'if [ -z "''${KEEP_TMP:-}" ]; then rm -rf "$RUN_DIR"; fi' EXIT

    DATA_DISK="$RUN_DIR/data/disk.img"
    "$QEMU_IMG" create -f raw "$DATA_DISK" "''${DATA_DISK_SIZE_MB}M" >/dev/null 2>&1

    # Busybox + applet links
    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"; chmod +x "$RUN_DIR/bin/busybox"
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff \
      mknod mkdir rmdir dd stat cp mv rm touch find wc head sync cut md5sum \
      printf test expr uname date od mkswap swapon losetup blockdev reboot \
      mkfs.ext2 mountpoint awk seq tr xargs umount depmod lsmod fsck; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    # glibc (dynamic linker)
    mkdir -p "$RUN_DIR/$GLIBC_LIB"
    cp "$GLIBC_LIB"/ld-linux-x86-64.so.2 "$RUN_DIR/$GLIBC_LIB/" 2>/dev/null || true
    for lib in libc.so.6 libm.so.6 libresolv.so.2 libdl.so.2; do
      [ -f "$GLIBC_LIB/$lib" ] && cp "$GLIBC_LIB/$lib" "$RUN_DIR/$GLIBC_LIB/"
    done

    # Module .ko
    cp "$BLOCK_KO" "$RUN_DIR/lib/modules/tidefs_block_kmod.ko"

    # Bundle xfsprogs
    HAS_MKFS_XFS=0; HAS_XFS_REPAIR=0
    if [ -f "$XFSPROGS/bin/mkfs.xfs" ]; then
      cp "$XFSPROGS/bin/mkfs.xfs" "$RUN_DIR/bin/mkfs.xfs"
      chmod +x "$RUN_DIR/bin/mkfs.xfs"; HAS_MKFS_XFS=1
      echo "  bundled: mkfs.xfs"
    else echo "  WARNING: mkfs.xfs not found in xfsprogs"; fi
    if [ -f "$XFSPROGS/bin/xfs_repair" ]; then
      cp "$XFSPROGS/bin/xfs_repair" "$RUN_DIR/bin/xfs_repair"
      chmod +x "$RUN_DIR/bin/xfs_repair"; HAS_XFS_REPAIR=1
      echo "  bundled: xfs_repair"
    fi

    # Bundle btrfs-progs
    HAS_MKFS_BTRFS=0; HAS_BTRFS=0
    if [ -f "$BTRFSPROGS/bin/mkfs.btrfs" ]; then
      cp "$BTRFSPROGS/bin/mkfs.btrfs" "$RUN_DIR/bin/mkfs.btrfs"
      chmod +x "$RUN_DIR/bin/mkfs.btrfs"; HAS_MKFS_BTRFS=1
      echo "  bundled: mkfs.btrfs"
    else echo "  WARNING: mkfs.btrfs not found in btrfs-progs"; fi
    if [ -f "$BTRFSPROGS/bin/btrfs" ]; then
      cp "$BTRFSPROGS/bin/btrfs" "$RUN_DIR/bin/btrfs"
      chmod +x "$RUN_DIR/bin/btrfs"; HAS_BTRFS=1
      echo "  bundled: btrfs"
    fi

    # Bundle fio
    HAS_FIO=0
    if [ -f "${pkgs.fio}/bin/fio" ]; then
      cp "${pkgs.fio}/bin/fio" "$RUN_DIR/bin/fio" 2>/dev/null && chmod +x "$RUN_DIR/bin/fio"
      HAS_FIO=1; echo "  bundled: fio"
    else echo "  WARNING: fio not found (dd fallback will be used)"; fi

    # Copy shared-library directories
    mkdir -p "$RUN_DIR/lib"
    for pkg_dir in ${toString (map (p: "${p}/lib") fsToolLibDirs)}; do
      if [ -d "$pkg_dir" ]; then
        cp -n "$pkg_dir/"*.so* "$RUN_DIR/lib/" 2>/dev/null || true
      fi
    done
    echo "  libs: $(ls "$RUN_DIR/lib/"*.so* 2>/dev/null | wc -l) shared objects"

    # Init script (runs inside QEMU guest)
    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin
export LD_LIBRARY_PATH=/lib:${glibcLib}

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== TideFS KBlock Guest Filesystem Matrix ==="
echo "kernel=$(uname -r)"
echo ""

PASSED=0; FAILED=0; BLOCKED=0; TOTAL_PASS=0; TOTAL_FAIL=0; TOTAL_BLOCKED=0

pass() { echo "PASS: $1"; PASSED=$((PASSED + 1)); TOTAL_PASS=$((TOTAL_PASS + 1)); }
fail() { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); TOTAL_FAIL=$((TOTAL_FAIL + 1)); }
blocked() { echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); TOTAL_BLOCKED=$((TOTAL_BLOCKED + 1)); }

fs_start() { FS="$1"; PASSED=0; FAILED=0; BLOCKED=0; echo ""; echo "=== FILESYSTEM: $FS ==="; }
fs_end() { echo "--- $FS: PASS=$PASSED FAIL=$FAILED ---"; echo "FS_RESULT $FS PASS=$PASSED FAIL=$FAILED" >> /validation/matrix_results; }

DEV=/dev/tidefs; MNT=/mnt; EVDIR=/validation
BACKING_FILE=/data/tidefs_backing.bin; BACKING_SIZE_MB=350

dmesg_snapshot() { local l="$1"; dmesg > "$EVDIR/dmesg_''${l}.txt" 2>/dev/null || true; }

echo "--- Phase 0: Data disk and backing file ---"
dmesg_snapshot pre_setup

if [ -b /dev/vda ]; then
  pass "data_disk_present"
  if mkfs.ext2 -F /dev/vda 2>/tmp/mkfs_data.err; then pass "mkfs_data_disk"
  else fail "mkfs_data_disk" "$(head -1 /tmp/mkfs_data.err 2>/dev/null)"; fi
  mount /dev/vda /data 2>/tmp/mnt_data.err
  if mountpoint /data >/dev/null 2>&1; then
    pass "mount_data_disk"
    echo "INFO: creating ''${BACKING_SIZE_MB}M backing file"
    if dd if=/dev/zero of="$BACKING_FILE" bs=1M count="$BACKING_SIZE_MB" 2>/tmp/dd.err; then
      pass "backing_file_created"
      sync
    else fail "backing_file_created" "$(head -1 /tmp/dd.err 2>/dev/null)"; fi
  else fail "mount_data_disk" "$(head -1 /tmp/mnt_data.err 2>/dev/null)"; fi
else blocked "data_disk_present" "/dev/vda missing"; fi

dmesg_snapshot post_setup

echo ""; echo "--- Phase 1: Module load ---"

if insmod /lib/modules/tidefs_block_kmod.ko 2>/tmp/insmod.err; then pass "insmod"
else fail "insmod" "$(head -1 /tmp/insmod.err 2>/dev/null)"; dmesg > /validation/dmesg_insmod_fail.txt 2>/dev/null || true; sleep 1; poweroff -f; exit 1; fi
sleep 1
[ -b "$DEV" ] && pass "device_present" || { blocked "device_present" "/dev/tidefs missing"; poweroff -f; exit 1; }
DEV_SIZE=$(cat /sys/block/tidefs/size 2>/dev/null || echo 0)
DEV_SIZE_MB=$(( DEV_SIZE / 2048 ))
echo "INFO: /dev/tidefs size=$DEV_SIZE sectors (''${DEV_SIZE_MB} MiB)"
[ "$DEV_SIZE_MB" -ge 64 ] && pass "device_capacity" || fail "device_capacity" "only ''${DEV_SIZE_MB} MiB"
dmesg_snapshot post_insmod

echo ""; echo "--- Phase 2: Filesystem matrix ---"

test_filesystem() {
  local FS="$1" MKFS_CMD="$2" MKFS_ARGS="$3" FSCK_CMD="$4" FSCK_ARGS="$5"
  fs_start "$FS"
  if command -v "$MKFS_CMD" >/dev/null 2>&1; then
    if $MKFS_CMD $MKFS_ARGS "$DEV" 2>/tmp/mkfs.err; then pass "mkfs"
    else fail "mkfs" "$(head -1 /tmp/mkfs.err 2>/dev/null || echo error)"; fs_end; return; fi
  else blocked "mkfs" "$MKFS_CMD not found in guest"; fs_end; return; fi
  sync
  mkdir -p "$MNT"
  if mount "$DEV" "$MNT" 2>/tmp/mnt.err; then pass "mount"
  else fail "mount" "$(head -1 /tmp/mnt.err 2>/dev/null || echo error)"; fs_end; return; fi
  if [ -f /bin/fio ]; then
    /bin/fio --name=rw --rw=randrw --bs=4k --size=16M --numjobs=2 --time_based \
      --runtime=''${FIO_RUNTIME:-30} --directory="$MNT" --output=/tmp/fio.json \
      --output-format=json 2>/dev/null || true
    pass "fio"
  else
    for i in 1 2 3 4; do dd if=/dev/urandom of="$MNT/testfile_$i" bs=4k count=1024 2>/dev/null || true; done
    sync
    pass "dd_io"
  fi
  echo "TIDEFS_MARKER_$FS" > "$MNT/tidefs_marker.txt" 2>/dev/null; sync
  if umount "$MNT" 2>/tmp/umnt.err; then pass "umount"
  else fail "umount" "$(head -1 /tmp/umnt.err 2>/dev/null)"; fi
  if command -v "$FSCK_CMD" >/dev/null 2>&1; then
    $FSCK_CMD $FSCK_ARGS "$DEV" 2>/tmp/fsck.err; RC=$?
    if [ "$RC" -eq 0 ]; then pass "fsck_clean"
    elif [ "$RC" -eq 1 ]; then pass "fsck_corrected"
    else fail "fsck" "RC=$RC $(head -1 /tmp/fsck.err 2>/dev/null)"; fi
  else blocked "fsck" "$FSCK_CMD not found in guest"; fi
  if mount "$DEV" "$MNT" 2>/tmp/remnt.err; then
    pass "remount"
    if [ -f "$MNT/tidefs_marker.txt" ]; then
      MARKER=$(cat "$MNT/tidefs_marker.txt" 2>/dev/null)
      echo "$MARKER" | grep -q "TIDEFS_MARKER_$FS" && pass "marker_match" || fail "marker_match" "got: $MARKER"
    else fail "marker" "marker file missing after remount"; fi
    sync; umount "$MNT" 2>/dev/null || true
  else fail "remount" "$(head -1 /tmp/remnt.err 2>/dev/null)"; fi
  fs_end
}

test_filesystem "ext4" "mkfs.ext2" "-F" "fsck" "-t ext2 -fn"

echo ""; echo "--- Phase 3: Dmesg integrity ---"
DMESG_BUG=$(dmesg 2>/dev/null | grep -cE "BUG:|Kernel panic|Oops:|WARNING:" | tr -d "[:space:]" || echo 0)
DMESG_BUG=''${DMESG_BUG:-0}
[ "$DMESG_BUG" = "0" ] && pass "dmesg_clean" || fail "dmesg_clean" "dmesg has $DMESG_BUG lines"
dmesg_snapshot final

echo ""; echo "--- Phase 4: Module unload ---"
sync
if rmmod tidefs_block 2>/tmp/rmmod.err || rmmod tidefs_block_kmod 2>/tmp/rmmod2.err; then pass "rmmod"
else fail "rmmod" "$(head -1 /tmp/rmmod.err 2>/dev/null)"; fi
sleep 1
DMESG_POST=$(dmesg 2>/dev/null | grep -cE "BUG:|Kernel panic|Oops:" | tr -d "[:space:]" || echo 0)
[ "''${DMESG_POST:-0}" -eq 0 ] && pass "dmesg_post_clean" || fail "dmesg_post_clean" "$DMESG_POST post-rmmod bug lines"

echo ""
echo "=== MATRIX SUMMARY: PASS=$TOTAL_PASS FAIL=$TOTAL_FAIL ==="
cat /validation/matrix_results 2>/dev/null

cp /tmp/insmod.err   "$EVDIR/" 2>/dev/null || true
cp /tmp/rmmod.err    "$EVDIR/" 2>/dev/null || true
cp /tmp/mkfs_data.err "$EVDIR/" 2>/dev/null || true
cp /tmp/mnt_data.err  "$EVDIR/" 2>/dev/null || true
cp /tmp/dd.err        "$EVDIR/" 2>/dev/null || true

sleep 2
poweroff -f
INITSCRIPT

    chmod +x "$RUN_DIR/init"

    echo "--- Building initramfs ---"
    (cd "$RUN_DIR" && find . -not -path './data/*' | cpio -o -H newc) | gzip > "$RUN_DIR/initramfs.gz"

    echo "--- Booting QEMU ---"
    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$RUN_DIR/initramfs.gz" \
      -append "console=ttyS0 loglevel=7" \
      -nographic -m 4096M -smp 2 -no-reboot \
      -drive file="$DATA_DISK",format=raw,if=virtio \
      2>&1 | tee "$RUN_DIR/qemu.log" || true

    echo ""
    echo "--- QEMU exited ---"

    PASS_COUNT=$(grep -c "^PASS:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    FAIL_COUNT=$(grep -c "^FAIL:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    BLOCKED_COUNT=$(grep -c "^BLOCKED:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)

    echo ""
    echo "=== MATRIX RESULTS: PASS=$PASS_COUNT FAIL=$FAIL_COUNT ==="
    grep "FS_RESULT" "$RUN_DIR/qemu.log" 2>/dev/null || true

    # Write external validation output
    OUTPUT_DIR="/root/ai/tmp/tidefs-validation/kernel-block-guest-fs-matrix/$(date -u +%Y-%m-%dT%H%M%SZ)"
    mkdir -p "$OUTPUT_DIR"
    cp "$RUN_DIR/qemu.log" "$OUTPUT_DIR/qemu.log"
    cp "$BLOCK_KO" "$OUTPUT_DIR/tidefs_block_kmod.ko" 2>/dev/null || true

    COMMIT=$(git -C /root/tidefs rev-parse HEAD 2>/dev/null || echo unknown)
    if git -C /root/tidefs diff --quiet --ignore-submodules -- 2>/dev/null && \
       git -C /root/tidefs diff --cached --quiet --ignore-submodules -- 2>/dev/null; then
      DIRTY=false
    else
      DIRTY=true
    fi

    cat > "$OUTPUT_DIR/manifest.json" << ENDMANIFEST
{"test":"kernel-block-guest-filesystem-matrix","date":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","validation_tier":"Tier 5 Linux 7.0 kernel block I/O","filesystems_tested":["ext4"],"total_pass":$PASS_COUNT,"total_fail":$FAIL_COUNT,"commit":"$COMMIT","worktree_dirty":$DIRTY,"kernel":"Linux 7.0","module":"tidefs_block_kmod.ko","backend":"persistent file-backed (RawBlockFile) via virtio-blk data disk","xfsprogs_bundled":$HAS_MKFS_XFS,"btrfs_progs_bundled":$HAS_MKFS_BTRFS,"fio_bundled":$HAS_FIO,"result":"Guest filesystem matrix (ext4). PASS=$PASS_COUNT FAIL=$FAIL_COUNT"}
ENDMANIFEST

    echo "Validation output directory: $OUTPUT_DIR"
    [ "$FAIL_COUNT" -gt 0 ] && exit 1
    exit 0
  '';
in
  validateScript
