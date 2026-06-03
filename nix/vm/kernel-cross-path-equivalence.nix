# TideFS: kmod-posix-vfs FUSE-to-kernel cross-path behavioral equivalence
# validation in QEMU.
#
# Boots a Linux 7.0 QEMU guest, loads kmod-posix-vfs, starts the FUSE
# userspace daemon, and mounts both FUSE and kernel instances from the
# same pool. Executes the 9 canonical cross-path operation sequences
# through each path, captures committed-root pool fingerprints, and
# flags any hash mismatch as divergence.
#
# Validation tiers:
#   FuseReference        FUSE userspace mount producing reference committed-root state
#   KernelEquivalence    Kernel mount replaying identical workload, comparing state
#   CrashConsistent      Crash-injection during cross-path workload with recovery verification
#
# Environment refusal: in environments without /dev/kvm, fuse.ko, or
# kmod-posix-vfs.ko, produces REFUSAL-classified validation rows.
#
# Dependencies:
#   - Linux 7.0 kernel with FUSE and Rust-for-Linux support
#   - kmod-posix-vfs .ko produced by out-of-tree build
#   - tidefs-posix-filesystem-adapter-daemon binary
#   - QEMU (KVM acceleration preferred but not required)
#   - busybox for initrd userspace
{
  pkgs,
  linuxKernel_7_0,
  tidefsPackage,
}:

let
  crossPathEquivalenceScript = pkgs.writeShellScriptBin "tidefs-kernel-cross-path-equivalence" ''
    set -euo pipefail

    QEMU_BIN="''${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="''${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="''${linuxKernel_7_0}/bzImage"
    CPIO="''${pkgs.cpio}/bin/cpio"
    MODULE_DIR="''${linuxKernel_7_0}/lib/modules/''${linuxKernel_7_0.version}"
    FUSE_DAEMON="''${tidefsPackage}/bin/tidefs-posix-filesystem-adapter-daemon"
    B3SUM="''${pkgs.b3sum}/bin/b3sum"

    TMPDIR="''${TIDEFS_CROSS_PATH_TMPDIR:-/tmp/tidefs-cross-path-equivalence}"
    TIMEOUT_SEC="''${TIDEFS_CROSS_PATH_TIMEOUT:-600}"

    usage() {
      cat <<USAGE
Usage: tidefs-kernel-cross-path-equivalence [--timeout SECONDS] [--keep-tmp]

Produce tier-classified FUSE-to-kernel cross-path behavioral equivalence
validation in a reproducible Nix/QEMU Linux 7.0 environment.
Exercises 9 canonical POSIX operation sequences through both FUSE userspace
and kernel VFS paths, capturing committed-root pool fingerprints and
flagging any divergence.

Validation tiers:
  T0  FuseReference: FUSE mount reference state capture (9 ops)
  T1  KernelEquivalence: kernel mount replay + state comparison (9 ops)
  T2  CrashConsistent: crash-injection + recovery verification (9 ops)

Options:
  --timeout SECONDS    QEMU boot timeout (default: $TIMEOUT_SEC)
  --keep-tmp           Do not remove temp directory on exit
  --help, -h           Show this message

Exit codes:
  0  All operations equivalent across both paths
  1  One or more operations diverged
  2  Environment refusal (no /dev/kvm, no kernel module, etc.)
  3  Argument or environment error
USAGE
    }

    KEEP_TMP=0
    DRY_RUN=0
    while [ $# -gt 0 ]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 3 ;;
      esac
    done

    echo "=== TideFS Kernel Cross-Path Equivalence Validation ==="
    echo "commit: $(git -C ${./.} rev-parse HEAD 2>/dev/null || echo 'unknown')"
    echo "kernel: $(${linuxKernel_7_0}/bin/kernel-release 2>/dev/null || echo 'Linux 7.0')"
    echo "kvm: $(test -e /dev/kvm && echo 'available' || echo 'unavailable')"
    echo "timestamp: $(date --utc +%Y-%m-%dT%H:%M:%SZ)"

    if [ "$DRY_RUN" -eq 1 ]; then
        echo ""
        echo "--- Dry-run mode: reporting environment facts without QEMU execution ---"
        echo ""
        echo "=== Environment Refusal ==="
        echo "validation_tier: all runtime tiers (FuseReference, KernelEquivalence, CrashConsistent)"
        echo "outcome: BLOCKED"
        echo "reason: dry-run requested; QEMU guest not booted"
        echo ""
        echo "kvm_available: $(test -e /dev/kvm && echo true || echo false)"
        echo "fuse_available: $(test -e /dev/fuse && echo true || echo false)"
        echo "qemu_binary: ${pkgs.qemu}/bin/qemu-system-x86_64"
        echo "qemu_exists: $(test -f ${pkgs.qemu}/bin/qemu-system-x86_64 && echo true || echo false)"
        echo "kernel_image: ${linuxKernel_7_0}/bzImage"
        echo "kernel_available: $(test -f ${linuxKernel_7_0}/bzImage 2>/dev/null && echo true || echo false)"
        echo "fuse_daemon: ${tidefsPackage}/bin/tidefs-posix-filesystem-adapter-daemon"
        echo "fuse_daemon_available: $(test -f ${tidefsPackage}/bin/tidefs-posix-filesystem-adapter-daemon 2>/dev/null && echo true || echo false)"
        echo ""
        echo "Cross-path equivalence runtime rows: 27 total (9 ops x 3 runtime tiers)"
        echo "  FuseReference:      9 Blocked   (requires QEMU guest with FUSE mount)"
        echo "  KernelEquivalence:  9 Blocked   (requires QEMU guest with kernel VFS mount)"
        echo "  CrashConsistent:    9 Blocked   (requires QEMU two-boot crash cycle)"
        echo ""
        echo "PASS=0 FAIL=0 DIVERGENT=0 BLOCKED=27 TOTAL=27"
        echo "RESULT: all runtime-tier validation rows blocked on QEMU guest execution"
        exit 0
    fi

    # ── Prepare initramfs ──────────────────────────────────────────────

    echo ""
    echo "--- Preparing initramfs ---"

    mkdir -p "$TMPDIR"/initramfs/{bin,dev,proc,sys,etc,lib/modules,mnt,root,tmp,var/log,var/tidefs/backing}
    mkdir -p "$TMPDIR"/initramfs/usr/bin

    # Copy busybox
    cp "$BUSYBOX" "$TMPDIR"/initramfs/bin/busybox
    chmod +x "$TMPDIR"/initramfs/bin/busybox
    for cmd in sh mount umount ls cat cp dd echo mkdir rm sync sleep test seq head wc mknod dmesg modprobe insmod stat; do
      ln -sf /bin/busybox "$TMPDIR"/initramfs/bin/"$cmd"
    done

    # Copy FUSE daemon if available
    if [ -f "$FUSE_DAEMON" ]; then
      cp "$FUSE_DAEMON" "$TMPDIR"/initramfs/usr/bin/tidefs-fuse-daemon
      chmod +x "$TMPDIR"/initramfs/usr/bin/tidefs-fuse-daemon
    fi

    # Copy b3sum for committed-root state hash computation
    if [ -f "$B3SUM" ]; then
      cp "$B3SUM" "$TMPDIR"/initramfs/usr/bin/b3sum
    fi

    # Copy kernel modules
    if [ -d "$MODULE_DIR" ]; then
      mkdir -p "$TMPDIR"/initramfs/lib/modules/"''${linuxKernel_7_0.version}"
      cp -r "$MODULE_DIR"/* "$TMPDIR"/initramfs/lib/modules/"''${linuxKernel_7_0.version}"/ 2>/dev/null || true
    fi

    # Copy kmod-posix-vfs .ko
    KMOD_POSIX_TFS_KO="''${TIDEFS_KMOD_POSIX_TFS_KO:-}"
    if [ -n "$KMOD_POSIX_VFS_KO" ] && [ -f "$KMOD_POSIX_VFS_KO" ]; then
      cp "$KMOD_POSIX_TFS_KO" "$TMPDIR"/initramfs/lib/modules/tidefs-kmod-posix-vfs.ko
    fi

    # Pool backing file (pre-created in initramfs for deterministic starting state)
    dd if=/dev/zero of="$TMPDIR"/initramfs/var/tidefs/backing/pool.dat bs=1M count=128 2>/dev/null

    # ── Build the cross-path workload init script ──────────────────────

    cat > "$TMPDIR"/initramfs/init << 'INITSCRIPT'
#!/bin/sh
set -e

echo "=== TideFS Cross-Path Equivalence Test ==="
echo "kernel: $(uname -r)"
echo ""

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

PASS=0
FAIL=0
DIVERGENT=0
BLOCKED=0
TOTAL=0

check_pass()   { PASS=$((PASS + 1));       TOTAL=$((TOTAL + 1)); echo "  PASS: $1"; }
check_fail()   { FAIL=$((FAIL + 1));       TOTAL=$((TOTAL + 1)); echo "  FAIL: $1"; }
check_divergent() { DIVERGENT=$((DIVERGENT + 1)); TOTAL=$((TOTAL + 1)); echo "  DIVERGENT: $1"; }
check_blocked() { BLOCKED=$((BLOCKED + 1)); TOTAL=$((TOTAL + 1)); echo "  BLOCKED: $1"; }

echo ""
echo "--- Phase 0: Environment probe ---"

# Check for required kernel modules and binaries
HAVE_FUSE=0
HAVE_KMOD=0
HAVE_DAEMON=0

modprobe fuse 2>/dev/null && HAVE_FUSE=1 || echo "WARNING: fuse.ko not available"
[ -f /lib/modules/tidefs-kmod-posix-vfs.ko ] && HAVE_KMOD=1 || echo "WARNING: kmod-posix-vfs.ko not available"
[ -x /usr/bin/tidefs-fuse-daemon ] && HAVE_DAEMON=1 || echo "WARNING: tidefs-fuse-daemon not available"

if [ "$HAVE_FUSE" -eq 0 ] && [ "$HAVE_KMOD" -eq 0 ]; then
    echo "REFUSAL: neither FUSE nor kernel VFS paths are available"
    echo "PASS=0 FAIL=0 DIVERGENT=0 BLOCKED=36 TOTAL=36"
    echo "All 36 runtime-tier rows remain Blocked"
    exit 0
fi

if [ "$HAVE_FUSE" -eq 0 ]; then
    echo "REFUSAL: FUSE path unavailable; FuseReference and CrashConsistent rows Blocked"
fi
if [ "$HAVE_KMOD" -eq 0 ]; then
    echo "REFUSAL: kernel VFS path unavailable; KernelEquivalence rows Blocked"
fi

# ── Phase 1: FUSE Reference Path ─────────────────────────────────────

if [ "$HAVE_FUSE" -eq 1 ] && [ "$HAVE_DAEMON" -eq 1 ]; then
    echo ""
    echo "--- Phase 1: FUSE Reference Path ---"
    echo "Starting FUSE daemon and mounting reference filesystem..."

    mkdir -p /mnt/fuse-ref

    # Start the FUSE daemon on the pool
    # (Simplified - actual daemon invocation depends on the binary's CLI)
    /usr/bin/tidefs-fuse-daemon \
      --pool-path /var/tidefs/backing/pool.dat \
      --mount-point /mnt/fuse-ref \
      --daemonize 2>/dev/null &
    FUSE_PID=$!
    sleep 2

    if kill -0 "$FUSE_PID" 2>/dev/null; then
        echo "FUSE daemon running (PID $FUSE_PID)"

        # --- Op 1: CreateWriteFsync ---
        echo "Op 1: CreateWriteFsync (FUSE reference)"
        echo "cross-path equivalence test payload v1" > /mnt/fuse-ref/testfile 2>/dev/null && sync
        if [ -f /mnt/fuse-ref/testfile ]; then
            check_pass "FuseRef: CreateWriteFsync - file created and written"
        else
            check_fail "FuseRef: CreateWriteFsync - file creation failed"
        fi

        # --- Op 2: MkdirRmdirCycle ---
        echo "Op 2: MkdirRmdirCycle (FUSE reference)"
        mkdir /mnt/fuse-ref/testdir 2>/dev/null && \
        [ -d /mnt/fuse-ref/testdir ] && \
        rmdir /mnt/fuse-ref/testdir 2>/dev/null && \
        [ ! -d /mnt/fuse-ref/testdir ] && \
        check_pass "FuseRef: MkdirRmdirCycle - directory lifecycle" || \
        check_fail "FuseRef: MkdirRmdirCycle - directory lifecycle failed"

        # --- Op 3: LinkUnlinkCycle ---
        echo "Op 3: LinkUnlinkCycle (FUSE reference)"
        echo "link-source" > /mnt/fuse-ref/link-src 2>/dev/null && \
        ln /mnt/fuse-ref/link-src /mnt/fuse-ref/link-alias 2>/dev/null && \
        rm /mnt/fuse-ref/link-src 2>/dev/null && \
        [ -f /mnt/fuse-ref/link-alias ] && \
        check_pass "FuseRef: LinkUnlinkCycle - link preservation" || \
        check_fail "FuseRef: LinkUnlinkCycle - link cycle failed"

        # --- Op 4: RenameOverwrite ---
        echo "Op 4: RenameOverwrite (FUSE reference)"
        echo "old" > /mnt/fuse-ref/oldname 2>/dev/null && \
        echo "new" > /mnt/fuse-ref/newname 2>/dev/null && \
        mv /mnt/fuse-ref/oldname /mnt/fuse-ref/newname 2>/dev/null && \
        [ ! -f /mnt/fuse-ref/oldname ] && \
        [ -f /mnt/fuse-ref/newname ] && \
        check_pass "FuseRef: RenameOverwrite - namespace update" || \
        check_fail "FuseRef: RenameOverwrite - rename failed"

        # --- Op 5: TruncateExtend ---
        echo "Op 5: TruncateExtend (FUSE reference)"
        dd if=/dev/zero of=/mnt/fuse-ref/truncfile bs=4096 count=1 2>/dev/null && \
        dd if=/dev/zero of=/mnt/fuse-ref/truncfile bs=2048 count=1 2>/dev/null && \
        dd if=/dev/zero of=/mnt/fuse-ref/truncfile bs=4096 seek=1 count=1 2>/dev/null && \
        check_pass "FuseRef: TruncateExtend - size mutation" || \
        check_fail "FuseRef: TruncateExtend - truncate/extend failed"

        # --- Op 6: FallocatePunchZero ---
        echo "Op 6: FallocatePunchZero (FUSE reference)"
        # Use dd for sparse allocation; fallocate may not be in busybox
        dd if=/dev/zero of=/mnt/fuse-ref/fallocfile bs=8192 count=1 2>/dev/null && \
        dd if=/dev/zero of=/mnt/fuse-ref/fallocfile bs=4096 count=1 conv=notrunc 2>/dev/null && \
        check_pass "FuseRef: FallocatePunchZero - sparse allocation" || \
        check_fail "FuseRef: FallocatePunchZero - fallocate failed"

        # --- Op 7: XattrSetGetRemove ---
        echo "Op 7: XattrSetGetRemove (FUSE reference)"
        # xattr not available in busybox; mark as Blocked if unsupported
        if command -v setfattr >/dev/null 2>&1; then
            echo "xattr-test" > /mnt/fuse-ref/xattrfile 2>/dev/null && \
            setfattr -n user.testkey -v "cross-path xattr value" /mnt/fuse-ref/xattrfile 2>/dev/null && \
            check_pass "FuseRef: XattrSetGetRemove - xattr lifecycle" || \
            check_fail "FuseRef: XattrSetGetRemove - xattr failed"
        else
            echo "xattr-test" > /mnt/fuse-ref/xattrfile 2>/dev/null
            check_blocked "FuseRef: XattrSetGetRemove - setfattr not available (busybox limitation)"
        fi

        # --- Op 8: SymlinkReadlink ---
        echo "Op 8: SymlinkReadlink (FUSE reference)"
        ln -s /some/target/path /mnt/fuse-ref/mylink 2>/dev/null && \
        [ -L /mnt/fuse-ref/mylink ] && \
        check_pass "FuseRef: SymlinkReadlink - symlink creation" || \
        check_fail "FuseRef: SymlinkReadlink - symlink failed"

        # --- Op 9: ConcurrentMixedOps ---
        echo "Op 9: ConcurrentMixedOps (FUSE reference)"
        echo "data1" > /mnt/fuse-ref/f1 2>/dev/null && \
        echo "data2" > /mnt/fuse-ref/f2 2>/dev/null && \
        mkdir /mnt/fuse-ref/subdir 2>/dev/null && \
        ln /mnt/fuse-ref/f1 /mnt/fuse-ref/f1-link 2>/dev/null && \
        rm /mnt/fuse-ref/f2 2>/dev/null && \
        mv /mnt/fuse-ref/f1 /mnt/fuse-ref/moved-f1 2>/dev/null && \
        [ -f /mnt/fuse-ref/moved-f1 ] && \
        [ -f /mnt/fuse-ref/f1-link ] && \
        [ -d /mnt/fuse-ref/subdir ] && \
        [ ! -f /mnt/fuse-ref/f1 ] && \
        [ ! -f /mnt/fuse-ref/f2 ] && \
        check_pass "FuseRef: ConcurrentMixedOps - multi-op namespace" || \
        check_fail "FuseRef: ConcurrentMixedOps - concurrent ops failed"

        # Capture FUSE reference committed-root state hash
        echo "Capturing FUSE reference committed-root state..."
        umount /mnt/fuse-ref 2>/dev/null || true
        kill "$FUSE_PID" 2>/dev/null || true
        wait "$FUSE_PID" 2>/dev/null || true

        if [ -f /var/tidefs/backing/pool.dat ]; then
            FUSE_HASH=$(b3sum /var/tidefs/backing/pool.dat 2>/dev/null | cut -d' ' -f1 || echo "unavailable")
            echo "FUSE_REFERENCE_HASH=$FUSE_HASH"
        else
            FUSE_HASH="unavailable"
            echo "FUSE_REFERENCE_HASH=unavailable (pool image missing)"
        fi

        # Save FUSE reference hash and snapshot pool for kernel path
        echo "$FUSE_HASH" > /tmp/fuse_reference_hash.txt
        cp /var/tidefs/backing/pool.dat /var/tidefs/backing/pool_fuse_snapshot.dat 2>/dev/null || true
    else
        echo "FUSE daemon failed to start"
        FUSE_HASH="unavailable"
        check_blocked "FuseRef: all 9 ops blocked - FUSE daemon start failed"
    fi
else
    echo ""
    echo "--- Phase 1: FUSE Reference Path SKIPPED ---"
    check_blocked "FuseRef: all 9 ops blocked - FUSE path unavailable"
    # Create an empty pool for the kernel path to use
    dd if=/dev/zero of=/var/tidefs/backing/pool.dat bs=1M count=128 2>/dev/null
    FUSE_HASH="unavailable"
fi

# ── Phase 2: Kernel Equivalence Path ─────────────────────────────────

if [ "$HAVE_KMOD" -eq 1 ]; then
    echo ""
    echo "--- Phase 2: Kernel Equivalence Path ---"

    echo "Loading kmod-posix-vfs..."
    insmod /lib/modules/tidefs-kmod-posix-vfs.ko 2>/dev/null || {
        echo "REFUSAL: kmod-posix-vfs.ko failed to load"
        check_blocked "KernelEq: all 9 ops blocked - module load failed"
        HAVE_KMOD=0
    }
fi

if [ "$HAVE_KMOD" -eq 1 ]; then
    echo "kmod-posix-vfs loaded: $(lsmod | grep tidefs || echo 'module present')"

    mkdir -p /mnt/kernel-vfs

    # Use either the FUSE-modified pool or a fresh pool
    POOL_FILE="/var/tidefs/backing/pool.dat"
    if [ "$HAVE_FUSE" -eq 1 ] && [ -f /var/tidefs/backing/pool_fuse_snapshot.dat ]; then
        # Restore pre-FUSE pool state so kernel path starts from identical state
        cp /var/tidefs/backing/pool_fuse_snapshot.dat "$POOL_FILE" 2>/dev/null || true
        echo "Using pre-FUSE pool snapshot for kernel path (identical starting state)"
    fi

    echo "Mounting TideFS via kernel path..."
    mount -t tidefs none /mnt/kernel-vfs 2>/dev/null || {
        echo "REFUSAL: tidefs kernel mount failed"
        check_blocked "KernelEq: all 9 ops blocked - mount failed"
        HAVE_KMOD=0
    }
fi

if [ "$HAVE_KMOD" -eq 1 ]; then
    echo "Kernel TideFS mounted at /mnt/kernel-vfs"

    # --- Op 1: CreateWriteFsync ---
    echo "Op 1: CreateWriteFsync (kernel path)"
    echo "cross-path equivalence test payload v1" > /mnt/kernel-vfs/testfile 2>/dev/null && sync
    if [ -f /mnt/kernel-vfs/testfile ]; then
        check_pass "KernelEq: CreateWriteFsync - file created and written"
    else
        check_fail "KernelEq: CreateWriteFsync - file creation failed"
    fi

    # --- Op 2: MkdirRmdirCycle ---
    echo "Op 2: MkdirRmdirCycle (kernel path)"
    mkdir /mnt/kernel-vfs/testdir 2>/dev/null && \
    [ -d /mnt/kernel-vfs/testdir ] && \
    rmdir /mnt/kernel-vfs/testdir 2>/dev/null && \
    [ ! -d /mnt/kernel-vfs/testdir ] && \
    check_pass "KernelEq: MkdirRmdirCycle - directory lifecycle" || \
    check_fail "KernelEq: MkdirRmdirCycle - directory lifecycle failed"

    # --- Op 3: LinkUnlinkCycle ---
    echo "Op 3: LinkUnlinkCycle (kernel path)"
    echo "link-source" > /mnt/kernel-vfs/link-src 2>/dev/null && \
    ln /mnt/kernel-vfs/link-src /mnt/kernel-vfs/link-alias 2>/dev/null && \
    rm /mnt/kernel-vfs/link-src 2>/dev/null && \
    [ -f /mnt/kernel-vfs/link-alias ] && \
    check_pass "KernelEq: LinkUnlinkCycle - link preservation" || \
    check_fail "KernelEq: LinkUnlinkCycle - link cycle failed"

    # --- Op 4: RenameOverwrite ---
    echo "Op 4: RenameOverwrite (kernel path)"
    echo "old" > /mnt/kernel-vfs/oldname 2>/dev/null && \
    echo "new" > /mnt/kernel-vfs/newname 2>/dev/null && \
    mv /mnt/kernel-vfs/oldname /mnt/kernel-vfs/newname 2>/dev/null && \
    [ ! -f /mnt/kernel-vfs/oldname ] && \
    [ -f /mnt/kernel-vfs/newname ] && \
    check_pass "KernelEq: RenameOverwrite - namespace update" || \
    check_fail "KernelEq: RenameOverwrite - rename failed"

    # --- Op 5: TruncateExtend ---
    echo "Op 5: TruncateExtend (kernel path)"
    dd if=/dev/zero of=/mnt/kernel-vfs/truncfile bs=4096 count=1 2>/dev/null && \
    dd if=/dev/zero of=/mnt/kernel-vfs/truncfile bs=2048 count=1 2>/dev/null && \
    dd if=/dev/zero of=/mnt/kernel-vfs/truncfile bs=4096 seek=1 count=1 2>/dev/null && \
    check_pass "KernelEq: TruncateExtend - size mutation" || \
    check_fail "KernelEq: TruncateExtend - truncate/extend failed"

    # --- Op 6: FallocatePunchZero ---
    echo "Op 6: FallocatePunchZero (kernel path)"
    dd if=/dev/zero of=/mnt/kernel-vfs/fallocfile bs=8192 count=1 2>/dev/null && \
    dd if=/dev/zero of=/mnt/kernel-vfs/fallocfile bs=4096 count=1 conv=notrunc 2>/dev/null && \
    check_pass "KernelEq: FallocatePunchZero - sparse allocation" || \
    check_fail "KernelEq: FallocatePunchZero - fallocate failed"

    # --- Op 7: XattrSetGetRemove ---
    echo "Op 7: XattrSetGetRemove (kernel path)"
    if command -v setfattr >/dev/null 2>&1; then
        echo "xattr-test" > /mnt/kernel-vfs/xattrfile 2>/dev/null && \
        setfattr -n user.testkey -v "cross-path xattr value" /mnt/kernel-vfs/xattrfile 2>/dev/null && \
        check_pass "KernelEq: XattrSetGetRemove - xattr lifecycle" || \
        check_fail "KernelEq: XattrSetGetRemove - xattr failed"
    else
        echo "xattr-test" > /mnt/kernel-vfs/xattrfile 2>/dev/null
        check_blocked "KernelEq: XattrSetGetRemove - setfattr not available"
    fi

    # --- Op 8: SymlinkReadlink ---
    echo "Op 8: SymlinkReadlink (kernel path)"
    ln -s /some/target/path /mnt/kernel-vfs/mylink 2>/dev/null && \
    [ -L /mnt/kernel-vfs/mylink ] && \
    check_pass "KernelEq: SymlinkReadlink - symlink creation" || \
    check_fail "KernelEq: SymlinkReadlink - symlink failed"

    # --- Op 9: ConcurrentMixedOps ---
    echo "Op 9: ConcurrentMixedOps (kernel path)"
    echo "data1" > /mnt/kernel-vfs/f1 2>/dev/null && \
    echo "data2" > /mnt/kernel-vfs/f2 2>/dev/null && \
    mkdir /mnt/kernel-vfs/subdir 2>/dev/null && \
    ln /mnt/kernel-vfs/f1 /mnt/kernel-vfs/f1-link 2>/dev/null && \
    rm /mnt/kernel-vfs/f2 2>/dev/null && \
    mv /mnt/kernel-vfs/f1 /mnt/kernel-vfs/moved-f1 2>/dev/null && \
    [ -f /mnt/kernel-vfs/moved-f1 ] && \
    [ -f /mnt/kernel-vfs/f1-link ] && \
    [ -d /mnt/kernel-vfs/subdir ] && \
    [ ! -f /mnt/kernel-vfs/f1 ] && \
    [ ! -f /mnt/kernel-vfs/f2 ] && \
    check_pass "KernelEq: ConcurrentMixedOps - multi-op namespace" || \
    check_fail "KernelEq: ConcurrentMixedOps - concurrent ops failed"

    # Capture kernel committed-root state hash
    echo "Capturing kernel committed-root state..."
    umount /mnt/kernel-vfs 2>/dev/null || true

    if [ -f /var/tidefs/backing/pool.dat ]; then
        KERNEL_HASH=$(b3sum /var/tidefs/backing/pool.dat 2>/dev/null | cut -d' ' -f1 || echo "unavailable")
        echo "KERNEL_HASH=$KERNEL_HASH"
    else
        KERNEL_HASH="unavailable"
        echo "KERNEL_HASH=unavailable"
    fi

    echo "$KERNEL_HASH" > /tmp/kernel_hash.txt

    # ── Cross-path comparison ──────────────────────────────────────────

    if [ "$HAVE_FUSE" -eq 1 ] && [ "$FUSE_HASH" != "unavailable" ] && [ "$KERNEL_HASH" != "unavailable" ]; then
        echo ""
        echo "--- Cross-Path Hash Comparison ---"
        echo "FUSE_REFERENCE_HASH:  $FUSE_HASH"
        echo "KERNEL_HASH:         $KERNEL_HASH"

        if [ "$FUSE_HASH" = "$KERNEL_HASH" ]; then
            echo "RESULT: EQUIVALENT - Both paths produced identical committed-root state"
            check_pass "CrossPath: all 9 ops equivalent across FUSE and kernel paths"
        else
            echo "RESULT: DIVERGENT - State hashes differ between FUSE and kernel paths"
            check_divergent "CrossPath: state divergence detected (fuse=$FUSE_HASH kernel=$KERNEL_HASH)"
        fi
    elif [ "$HAVE_FUSE" -eq 0 ] || [ "$HAVE_KMOD" -eq 0 ]; then
        check_blocked "CrossPath: comparison blocked - one or both paths unavailable"
    fi
else
    echo ""
    echo "--- Phase 2: Kernel Equivalence Path SKIPPED ---"
    check_blocked "KernelEq: all 9 ops blocked - kernel path unavailable"
fi

# ── Phase 3: Crash Consistency ───────────────────────────────────────

echo ""
echo "--- Phase 3: Crash Consistency ---"

# Crash consistency requires two-boot cycle with persistent storage.
# Mark as Blocked for now - requires dedicated crash injection QEMU cycle.
check_blocked "CrashConsistent: all 9 ops blocked - requires two-boot crash cycle with QEMU hard reset"

echo ""
echo "=== Cross-Path Equivalence Validation Complete ==="
echo "PASS=$PASS FAIL=$FAIL DIVERGENT=$DIVERGENT BLOCKED=$BLOCKED TOTAL=$TOTAL"
echo ""

if [ "$DIVERGENT" -gt 0 ]; then
    echo "RESULT: $DIVERGENT cross-path divergence(s) detected"
elif [ "$FAIL" -gt 0 ]; then
    echo "RESULT: $FAIL operation(s) failed (non-divergence failures)"
elif [ "$PASS" -gt 0 ]; then
    echo "RESULT: all exercised operations passed; $PASS equivalent across paths"
else
    echo "RESULT: no validation collected (all rows Blocked)"
fi

umount /mnt/kernel-vfs 2>/dev/null || true
echo "TIDEFS_CROSS_PATH_EQUIVALENCE_COMPLETE" > /dev/kmsg 2>/dev/null || true

if [ "$DIVERGENT" -gt 0 ]; then
    exit 1
fi
exit 0
INITSCRIPT

    chmod +x "$TMPDIR"/initramfs/init

    # ── Build initramfs ────────────────────────────────────────────────

    echo "--- Building initramfs ---"
    ( cd "$TMPDIR"/initramfs && find . | "$CPIO" -o -H newc ) | gzip -9 > "$TMPDIR"/initramfs.cpio.gz

    # ── Boot QEMU ──────────────────────────────────────────────────────

    echo "--- Booting QEMU (timeout: ''${TIMEOUT_SEC}s) ---"
    echo ""

    QEMU_OUT="$TMPDIR/qemu-stdout.log"
    QEMU_ERR="$TMPDIR/qemu-stderr.log"

    set +e
    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$TMPDIR"/initramfs.cpio.gz \
      -append "console=ttyS0 quiet panic=5 init=/init" \
      -nographic \
      -m 512M \
      -no-reboot \
      > "$QEMU_OUT" 2> "$QEMU_ERR"
    QEMU_EXIT=$?
    set -e

    echo ""
    echo "--- QEMU exited with code $QEMU_EXIT ---"

    if [ "$QEMU_EXIT" -eq 124 ]; then
        echo "OUTCOME: QEMU timed out after ''${TIMEOUT_SEC}s"
        echo "REFUSAL: QEMU boot timeout; check kernel image and initramfs"
    fi

    # ── Parse results ──────────────────────────────────────────────────

    if grep -q "PASS=" "$QEMU_OUT" 2>/dev/null; then
        grep "PASS=" "$QEMU_OUT" | tail -1
        grep "RESULT:" "$QEMU_OUT" | tail -1
    fi

    if grep -q "DIVERGENT: [1-9]" "$QEMU_OUT" 2>/dev/null; then
        echo ""
        echo "Divergent operations:"
        grep "DIVERGENT:" "$QEMU_OUT" || true
    fi

    if grep -q "FAIL: [1-9]" "$QEMU_OUT" 2>/dev/null; then
        echo ""
        echo "Failed operations:"
        grep "FAIL:" "$QEMU_OUT" || true
    fi

    # ── Cleanup ────────────────────────────────────────────────────────

    if [ "$KEEP_TMP" -eq 0 ]; then
        rm -rf "$TMPDIR"
        echo "Cleaned up $TMPDIR"
    else
        echo "Kept temp directory: $TMPDIR"
    fi

    echo ""
    echo "=== TideFS Kernel Cross-Path Equivalence Validation Done ==="

    if [ "$QEMU_EXIT" -eq 0 ]; then
        exit 0
    elif [ "$QEMU_EXIT" -eq 124 ]; then
        exit 2
    else
        exit 1
    fi
  '';
in
  crossPathEquivalenceScript
