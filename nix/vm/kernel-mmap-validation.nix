# TideFS: kmod-posix-vfs mmap page-fault and msync validation in QEMU.
#
# Builds the kmod-posix-vfs kernel module against a Linux 7.0 kernel,
# boots a QEMU VM, loads the module, mounts a TideFS filesystem through
# the kernel module, and exercises the mmap path:
#   - page-fault read (MAP_SHARED read fault populates page)
#   - page-fault write (MAP_SHARED write fault marks dirty)
#   - page_mkwrite (dirty-folio tracking)
#   - msync MS_SYNC (durability flush)
#   - munmap (dirty-page writeback and cleanup)
#
# A self-contained C test binary performs the mmap operations. It can produce
# first-boot mounted-kernel mmap/page-fault/msync validation. Crash-consistency is
# blocked until the wrapper uses persistent guest storage across a real
# hard-reset/power-loss cycle.
#
# Crash-consistency: not implemented by this wrapper. Do not use first-boot
# mmap PASS rows as crash or release-closure validation.
#
# Dependencies:
#   - Linux 7.0 kernel with Rust-for-Linux support
#   - kmod-posix-vfs .ko produced by out-of-tree build
#   - Minimal initramfs with busybox, the .ko, and the mmap test binary
{
  pkgs,
  linuxKernel_7_0,
}:

let
  linuxPackages_7_0 = pkgs.linuxPackagesFor linuxKernel_7_0;

  # Self-contained C test binary for mmap operations.
  # Exercises: mmap MAP_SHARED read/write, msync MS_SYNC, munmap.
  mmapTestBin = pkgs.runCommandCC "tidefs-kmod-mmap-test"
    {
      buildInputs = [ ];
    } ''
    mkdir -p "$out/bin"
    cat > mmap_test.c << 'CEOF'
/*
 * tidefs-kmod-mmap-test — kernel mmap validation workload.
 *
 * Exercise on a TideFS kernel mount point:
 *  1. Create a file, write initial content via write(2).
 *  2. mmap the file MAP_SHARED, read via pointer (fault-read coherence).
 *  3. Write via pointer (fault-write + page_mkwrite dirty tracking).
 *  4. Read back via pointer (write-read coherence).
 *  5. msync MS_SYNC (durability flush).
 *  6. munmap (cleanup, dirty-page writeback).
 *  7. Re-read via read(2) to verify msync persistence.
 *
 * Exit 0 on success, non-zero on failure with diagnostic on stderr.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define PAGE 4096
#define TEST_BUF_SIZE (PAGE * 4)

static char test_dir[4096];

static void die(const char *msg) {
    fprintf(stderr, "mmap-test: %s: %s\n", msg, strerror(errno));
    exit(1);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: tidefs-kmod-mmap-test <mount-point>\n");
        return 1;
    }

    snprintf(test_dir, sizeof(test_dir), "%s", argv[1]);

    char path[8192];
    snprintf(path, sizeof(path), "%s/mmap_test_file", test_dir);

    /* ── 1. Create and write initial content ── */
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) die("open");

    unsigned char buf[TEST_BUF_SIZE];
    for (size_t i = 0; i < sizeof(buf); i++)
        buf[i] = (unsigned char)(i & 0xFF);

    ssize_t nw = write(fd, buf, sizeof(buf));
    if (nw != (ssize_t)sizeof(buf)) die("write initial");
    if (fsync(fd) < 0) die("fsync initial");

    printf("PASS: create-and-write-initial\n");

    /* ── 2. mmap MAP_SHARED ── */
    unsigned char *map = mmap(NULL, TEST_BUF_SIZE,
                              PROT_READ | PROT_WRITE,
                              MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) die("mmap MAP_SHARED");

    printf("PASS: mmap-shared\n");

    /* ── 3. Fault-read: read via pointer ── */
    int read_ok = 1;
    for (size_t i = 0; i < TEST_BUF_SIZE; i++) {
        if (map[i] != (unsigned char)(i & 0xFF)) {
            fprintf(stderr, "fault-read mismatch at offset %zu: expected %02x got %02x\n",
                    i, (unsigned char)(i & 0xFF), map[i]);
            read_ok = 0;
            break;
        }
    }
    if (read_ok)
        printf("PASS: fault-read-shared\n");
    else
        printf("FAIL: fault-read-shared -- data mismatch\n");

    /* ── 4. Fault-write: write via pointer ── */
    unsigned char pattern[PAGE];
    for (size_t i = 0; i < sizeof(pattern); i++)
        pattern[i] = (unsigned char)((i + 0x42) & 0xFF);

    /* Write to page 1 (offset PAGE..PAGE*2-1) */
    memcpy(map + PAGE, pattern, PAGE);

    /* Write to page 3 (offset PAGE*3..PAGE*4-1) */
    memcpy(map + PAGE * 3, pattern, PAGE);

    printf("PASS: fault-write-shared\n");

    /* ── 5. Read-back coherence ── */
    int coh_ok = 1;
    for (size_t i = 0; i < PAGE; i++) {
        if (map[PAGE + i] != pattern[i]) {
            fprintf(stderr, "write-read coherence mismatch at page1[%zu]\n", i);
            coh_ok = 0;
            break;
        }
    }
    for (size_t i = 0; i < PAGE; i++) {
        if (map[PAGE * 3 + i] != pattern[i]) {
            fprintf(stderr, "write-read coherence mismatch at page3[%zu]\n", i);
            coh_ok = 0;
            break;
        }
    }
    if (coh_ok)
        printf("PASS: write-read-coherence\n");
    else
        printf("FAIL: write-read-coherence\n");

    /* ── 6. msync MS_SYNC ── */
    if (msync(map + PAGE, PAGE * 2, MS_SYNC) < 0)
        die("msync MS_SYNC");
    printf("PASS: msync-sync\n");

    /* ── 7. munmap ── */
    if (munmap(map, TEST_BUF_SIZE) < 0)
        die("munmap");
    printf("PASS: munmap\n");

    /* ── 8. Re-read via read(2) to verify msync persistence ── */
    if (lseek(fd, 0, SEEK_SET) < 0) die("lseek for re-read");

    unsigned char rbuf[TEST_BUF_SIZE];
    ssize_t nr = read(fd, rbuf, sizeof(rbuf));
    if (nr != (ssize_t)sizeof(rbuf)) die("re-read");

    /* Page 0 should still be original */
    for (size_t i = 0; i < PAGE; i++) {
        if (rbuf[i] != (unsigned char)(i & 0xFF)) {
            fprintf(stderr, "msync-persist: page0 mismatch at %zu\n", i);
            printf("FAIL: msync-persistence -- page0 corrupted\n");
            goto done;
        }
    }

    /* Page 1 should be pattern (written + msync'd) */
    for (size_t i = 0; i < PAGE; i++) {
        if (rbuf[PAGE + i] != pattern[i]) {
            fprintf(stderr, "msync-persist: page1 mismatch at %zu: expected %02x got %02x\n",
                    i, pattern[i], rbuf[PAGE + i]);
            printf("FAIL: msync-persistence -- page1 not persisted\n");
            goto done;
        }
    }

    /* Page 2 should still be original (not written) */
    for (size_t i = 0; i < PAGE; i++) {
        if (rbuf[PAGE * 2 + i] != (unsigned char)((PAGE * 2 + i) & 0xFF)) {
            fprintf(stderr, "msync-persist: page2 mismatch at %zu\n", i);
            printf("FAIL: msync-persistence -- page2 corrupted\n");
            goto done;
        }
    }

    /* Page 3 should be pattern (written + msync'd) */
    for (size_t i = 0; i < PAGE; i++) {
        if (rbuf[PAGE * 3 + i] != pattern[i]) {
            fprintf(stderr, "msync-persist: page3 mismatch at %zu: expected %02x got %02x\n",
                    i, pattern[i], rbuf[PAGE * 3 + i]);
            printf("FAIL: msync-persistence -- page3 not persisted\n");
            goto done;
        }
    }

    printf("PASS: msync-persistence\n");

done:
    close(fd);
    return 0;
}
CEOF

    cc -O2 -Wall mmap_test.c -o "$out/bin/tidefs-kmod-mmap-test"
    strip "$out/bin/tidefs-kmod-mmap-test"
  '';

  kmodMmapScript = pkgs.writeShellScriptBin "tidefs-kmod-mmap-validation" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"
    MMAP_TEST="${mmapTestBin}/bin/tidefs-kmod-mmap-test"

    TMPDIR="''${TIDEFS_KMOD_MMAP_TMPDIR:-/tmp/tidefs-kmod-mmap-validation}"
    TIMEOUT_SEC="''${TIDEFS_KMOD_MMAP_TIMEOUT:-300}"

    usage() {
      cat <<EOF
Usage: tidefs-kmod-mmap-validation [--timeout SECONDS] [--keep-tmp]

Validate kmod-posix-vfs mmap operations (fault-read, fault-write,
page_mkwrite, msync, munmap) in a reproducible Nix/QEMU Linux 7.0
environment. Produces tier-classified validation for mmap behavior.

Options:
  --timeout SECONDS    QEMU boot timeout (default: $TIMEOUT_SEC)
  --keep-tmp           Do not remove temp directory on exit
  --help, -h           Show this message

Exit codes:
  0  All exercised operations passed
  1  One or more operations failed
  2  Argument or environment error
EOF
    }

    KEEP_TMP=""
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done

    echo "=== TideFS K7-VAL: kmod-posix-vfs mmap Validation ==="
    echo "  Kernel:    $KERNEL_IMG"
    echo "  QEMU:      $QEMU_BIN"
    echo "  Module:    kmod-posix-vfs"
    echo "  Test bin:  $MMAP_TEST"
    echo "  Timeout:   ''${TIMEOUT_SEC}s"
    echo ""

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$MMAP_TEST"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done

    # ── Build initrd ───────────────────────────────────────────────────
    build_initrd() {
      local run_dir="$1"
      local crash_mode="$2"  # "0" for first boot, "1" for crash-recovery boot

      mkdir -p "$run_dir"/{bin,dev,proc,sys,tmp,lib/modules,mnt/tidefs}

      cp "$BUSYBOX" "$run_dir/bin/busybox"
      chmod +x "$run_dir/bin/busybox"
      for applet in sh ls cat echo mount grep insmod rmmod dmesg sync sleep \
                    poweroff reboot mknod mkdir rmdir dd stat cp mv rm touch \
                    find wc du; do
        ln -sf busybox "$run_dir/bin/$applet"
      done

      # Copy kernel module
      MODULE_FOUND=0
      if [ -f "$MODULE_DIR/tidefs_posix_vfs.ko" ]; then
        cp "$MODULE_DIR/tidefs_posix_vfs.ko" "$run_dir/lib/modules/"
        MODULE_FOUND=1
      fi

      # Copy mmap test binary
      cp "$MMAP_TEST" "$run_dir/bin/tidefs-kmod-mmap-test"
      chmod +x "$run_dir/bin/tidefs-kmod-mmap-test"

      # ── Init script ──────────────────────────────────────────────────
      cat > "$run_dir/init" << INITSCRIPT
#!/bin/sh
export PATH=/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== TideFS Mmap: kmod-posix-vfs mmap Validation ==="
echo "kernel_version=\$(uname -r)"
echo "timestamp=\$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "crash_mode=$crash_mode"
echo ""

PASSED=0
FAILED=0
BLOCKED=0

pass() { echo "PASS: \$1"; PASSED=\$((PASSED + 1)); }
fail() { echo "FAIL: \$1 -- \$2"; FAILED=\$((FAILED + 1)); }
blocked() { echo "BLOCKED: \$1 -- \$2"; BLOCKED=\$((BLOCKED + 1)); }

MNT=/mnt/tidefs

# ── Phase 0: Load kernel module ──────────────────────────────────────
echo "--- Phase 0: Module load ---"
MODULE_PATH="/lib/modules/tidefs_posix_vfs.ko"
if [ -f "\$MODULE_PATH" ]; then
    if insmod "\$MODULE_PATH" 2>/tmp/insmod.err; then
        pass "module_load"
    else
        fail "module_load" "\$(cat /tmp/insmod.err)"
    fi
else
    blocked "module_load" "tidefs_posix_vfs.ko not found in initramfs"
fi

if lsmod 2>/dev/null | grep -q tidefs_posix_vfs; then
    pass "module_lsmod"
else
    blocked "module_lsmod" "module not loaded"
fi

# ── Phase 1: Mount ───────────────────────────────────────────────────
echo ""
echo "--- Phase 1: Mount ---"
mkdir -p "\$MNT"
if mount -t tidefs none "\$MNT" 2>/tmp/mount.err; then
    pass "mount"
else
    blocked "mount" "\$(cat /tmp/mount.err)"
fi

MOUNTED=0
if mountpoint -q "\$MNT" 2>/dev/null; then MOUNTED=1; fi

# ── Phase 2: Mmap workload ───────────────────────────────────────────
echo ""
echo "--- Phase 2: Mmap workload ---"
if [ "\$MOUNTED" -eq 1 ] && [ -x /bin/tidefs-kmod-mmap-test ]; then
    # Run the C test binary; capture structured output
    /bin/tidefs-kmod-mmap-test "\$MNT" 2>/tmp/mmap.err
    MMAP_RC=\$?

    # Parse PASS/FAIL lines from the test binary output
    # (already printed to console by the binary itself)
    echo ""
    echo "mmap_test_exit_code=\$MMAP_RC"

    if [ "\$MMAP_RC" -eq 0 ]; then
        echo "mmap_test_summary=ALL_PASSED"
    else
        echo "mmap_test_summary=FAILURES_DETECTED"
    fi

    sync
else
    if [ "\$MOUNTED" -ne 1 ]; then
        blocked "mmap_workload" "filesystem not mounted"
    fi
    if [ ! -x /bin/tidefs-kmod-mmap-test ]; then
        blocked "mmap_workload" "test binary not found"
    fi
fi

# ── Phase 3: Committed-root snapshot ─────────────────────────────────
echo ""
echo "--- Phase 3: Committed-root snapshot ---"
if [ "\$MOUNTED" -eq 1 ]; then
    sync
    ls -la "\$MNT" 2>/dev/null > /tmp/root_state.txt || true
    if [ -f "\$MNT/mmap_test_file" ]; then
        pass "committed_root_file_exists"
        FILESIZE=\$(stat -c%s "\$MNT/mmap_test_file" 2>/dev/null || echo 0)
        echo "mmap_test_file_size=\$FILESIZE"
        if [ "\$FILESIZE" -gt 0 ]; then
            pass "committed_root_file_nonzero"
        else
            fail "committed_root_file_nonzero" "test file is zero-length"
        fi
    else
        fail "committed_root_file_exists" "test file not found after msync"
    fi
else
    blocked "committed_root_file_exists" "filesystem not mounted"
    blocked "committed_root_file_nonzero" "filesystem not mounted"
fi

# ── Phase 4: Tear-down ───────────────────────────────────────────────
echo ""
echo "--- Phase 4: Unmount and module unload ---"
if [ "\$MOUNTED" -eq 1 ]; then
    sync
    if umount "\$MNT" 2>/tmp/um.err; then
        pass "unmount"
    else
        fail "unmount" "\$(cat /tmp/um.err)"
    fi
else
    blocked "unmount" "filesystem not mounted"
fi

if lsmod 2>/dev/null | grep -q tidefs_posix_vfs; then
    if rmmod tidefs_posix_vfs 2>/tmp/rmmod.err; then
        pass "module_unload"
    else
        fail "module_unload" "\$(cat /tmp/rmmod.err)"
    fi
else
    blocked "module_unload" "module not loaded"
fi

# ── Summary ──────────────────────────────────────────────────────────
echo ""
echo "=== mmap Validation Summary ==="
echo "PASSED=\$PASSED"
echo "FAILED=\$FAILED"
echo "BLOCKED=\$BLOCKED"
echo "timestamp=\$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=== End ==="

poweroff -f
INITSCRIPT

      chmod +x "$run_dir/init"

      # Build initrd
      (cd "$run_dir" && find . -path ./initrd.img -prune -o -print | \
        "$CPIO" -o -H newc 2>/dev/null) > "$run_dir/initrd.img"

      echo "  Initrd prepared: \$(du -h "$run_dir/initrd.img" | cut -f1)"
    }

    # ── First boot: mmap workload ──────────────────────────────────────
    RUN_DIR="$TMPDIR/validation-$$"
    trap 'if [ -z "''${KEEP_TMP:-}" ]; then rm -rf "$RUN_DIR"; fi' EXIT

    build_initrd "$RUN_DIR" "0"

    VAL_LOG="$RUN_DIR/validation.log"
    echo "  Booting mmap validation QEMU (first boot)..."
    echo ""

    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$RUN_DIR/initrd.img" \
      -append "console=ttyS0 quiet panic=10" \
      -m 512M \
      -smp 1 \
      -nographic \
      -no-reboot \
      > "$VAL_LOG" 2>&1 || true

    echo ""
    echo "=== mmap Validation Results (First Boot) ==="

    PASSED=0
    FAILED=0
    BLOCKED=0

    for op in \
      module_load module_lsmod mount \
      fault-read-shared fault-write-shared write-read-coherence \
      msync-sync munmap msync-persistence \
      committed_root_file_exists committed_root_file_nonzero \
      unmount module_unload; do
      # Some ops are reported by C test binary directly (PASS:/FAIL:),
      # others by the init shell script.
      if grep -q "PASS: $op" "$VAL_LOG" 2>/dev/null; then
        echo "  PASS: $op"
        PASSED=$((PASSED + 1))
      elif grep -q "FAIL: $op" "$VAL_LOG" 2>/dev/null; then
        detail=$(grep "FAIL: $op" "$VAL_LOG" 2>/dev/null | head -1 | sed "s/^.*FAIL: $op //")
        echo "  FAIL: $op -- $detail"
        FAILED=$((FAILED + 1))
      elif grep -q "BLOCKED: $op" "$VAL_LOG" 2>/dev/null; then
        detail=$(grep "BLOCKED: $op" "$VAL_LOG" 2>/dev/null | head -1 | sed "s/^.*BLOCKED: $op //")
        echo "  BLOCKED: $op -- $detail"
        BLOCKED=$((BLOCKED + 1))
      else
        echo "  MISSING: $op (no validation in log)"
        BLOCKED=$((BLOCKED + 1))
      fi
    done

    echo ""
    echo "First-boot summary: $PASSED passed, $FAILED failed, $BLOCKED blocked"
    echo "Validation log: $VAL_LOG"

    # ── Crash-consistency: blocked until persistent guest storage exists ──
    echo ""
    echo "=== Crash-consistency: Second boot verification ==="
    echo "Note: persistent storage not available in this environment."
    echo "Full crash-consistency (write → crash → remount → verify)"
    echo "requires persistent block device backing for the TideFS pool."
    echo "Recording as BLOCKED with disclosure."
    echo ""

    if [ "$FAILED" -gt 0 ]; then
      echo "VALIDATION: FAIL -- $FAILED operations failed"
      exit 1
    fi

    if [ "$BLOCKED" -gt 0 ]; then
      echo "VALIDATION: BLOCKED -- $BLOCKED first-boot operations lacked validation"
      exit 1
    fi

    echo "VALIDATION: BLOCKED -- crash-consistency tier lacks persistent guest storage"
    exit 1
  '';
in
kmodMmapScript
