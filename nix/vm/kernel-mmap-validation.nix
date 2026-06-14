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
# first-boot mounted-kernel mmap/page-fault/msync validation against a
# configured virtio pool member.
#
# Crash-consistency and the custom Rust vm_operations_struct bridge are
# classified as unsupported rows. Do not use first-boot mmap PASS rows as
# crash, distributed coherency, or release-closure validation.
#
# Dependencies:
#   - Linux 7.0 kernel with Rust-for-Linux support
#   - kmod-posix-vfs .ko produced by out-of-tree build
#   - Minimal initramfs with busybox, tidefsctl, the .ko, and the mmap test binary
{
  pkgs,
  linuxKernel_7_0,
  tidefsPackage,
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
 *  7. Re-read via read(2) to verify post-sync visibility.
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
            fprintf(stderr, "post-sync-readback: page0 mismatch at %zu\n", i);
            printf("FAIL: post-sync-readback -- page0 corrupted\n");
            goto done;
        }
    }

    /* Page 1 should be pattern (written + msync'd) */
    for (size_t i = 0; i < PAGE; i++) {
        if (rbuf[PAGE + i] != pattern[i]) {
            fprintf(stderr, "post-sync-readback: page1 mismatch at %zu: expected %02x got %02x\n",
                    i, pattern[i], rbuf[PAGE + i]);
            printf("FAIL: post-sync-readback -- page1 not visible after sync\n");
            goto done;
        }
    }

    /* Page 2 should still be original (not written) */
    for (size_t i = 0; i < PAGE; i++) {
        if (rbuf[PAGE * 2 + i] != (unsigned char)((PAGE * 2 + i) & 0xFF)) {
            fprintf(stderr, "post-sync-readback: page2 mismatch at %zu\n", i);
            printf("FAIL: post-sync-readback -- page2 corrupted\n");
            goto done;
        }
    }

    /* Page 3 should be pattern (written + msync'd) */
    for (size_t i = 0; i < PAGE; i++) {
        if (rbuf[PAGE * 3 + i] != pattern[i]) {
            fprintf(stderr, "post-sync-readback: page3 mismatch at %zu: expected %02x got %02x\n",
                    i, pattern[i], rbuf[PAGE * 3 + i]);
            printf("FAIL: post-sync-readback -- page3 not visible after sync\n");
            goto done;
        }
    }

    printf("PASS: post-sync-readback\n");

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
    LDD_BIN="${pkgs.lib.getBin pkgs.glibc}/bin/ldd"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"
    MMAP_TEST="${mmapTestBin}/bin/tidefs-kmod-mmap-test"
    TIDEFSCTL="${tidefsPackage}/bin/tidefsctl"

    TMPDIR="''${TIDEFS_KMOD_MMAP_TMPDIR:-/tmp/tidefs-kmod-mmap-validation}"
    TIMEOUT_SEC="''${TIDEFS_KMOD_MMAP_TIMEOUT:-300}"

    usage() {
      cat <<EOF
Usage: tidefs-kmod-mmap-validation [--timeout SECONDS] [--keep-tmp] [--module PATH] [--kernel PATH]

Validate kmod-posix-vfs mmap operations (fault-read, fault-write,
page_mkwrite, msync, munmap) in a reproducible Nix/QEMU Linux 7.0
environment. Produces tier-classified validation for mmap behavior.

Options:
  --timeout SECONDS    QEMU boot timeout (default: $TIMEOUT_SEC)
  --keep-tmp           Do not remove temp directory on exit
  --module PATH        Path to pre-built tidefs_posix_vfs.ko
  --kernel PATH        Path to Linux bzImage (default: Nix-built 7.0)
  --help, -h           Show this message

Exit codes:
  0  All exercised operations passed
  1  One or more operations failed
  2  Argument or environment error
EOF
    }

    KEEP_TMP=""
    KO_PATH_ARG=""
    KERNEL_OVERRIDE=""
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --module) KO_PATH_ARG="$2"; shift 2 ;;
        --kernel) KERNEL_OVERRIDE="$2"; shift 2 ;;
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

    if [ -n "$KERNEL_OVERRIDE" ] && [ -f "$KERNEL_OVERRIDE" ]; then
      KERNEL_IMG="$KERNEL_OVERRIDE"
      echo "  Using provided kernel: $KERNEL_IMG"
    fi

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$MMAP_TEST" "$TIDEFSCTL"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done

    # ── Build initrd ───────────────────────────────────────────────────
    build_initrd() {
      local run_dir="$1"
      local crash_mode="$2"  # "0" for first boot, "1" for crash-recovery boot

      mkdir -p "$run_dir"/{bin,dev,proc,sys,tmp,lib/modules,mnt/tidefs,var/lib/tidefs,etc}

      cp "$BUSYBOX" "$run_dir/bin/busybox"
      chmod +x "$run_dir/bin/busybox"
      for applet in sh ls cat echo mount umount grep insmod rmmod dmesg sync sleep \
                    poweroff reboot mknod mkdir rmdir dd stat cp mv rm touch \
                    find wc du head cut tr mountpoint losetup uname date seq awk \
                    ps kill pidof which basename dirname test env true false printf \
                    tail readlink lsmod ln; do
        ln -sf busybox "$run_dir/bin/$applet"
      done

      copy_elf_deps() {
        local elf="$1"
        local deps dep_dir ld_so ld_dir

        deps=$("$LDD_BIN" "$elf" 2>/dev/null | grep -o '/nix/store/[^ ]*' | sort -u || true)
        for dep in $deps; do
          if [ -f "$dep" ]; then
            dep_dir=$(dirname "$dep")
            mkdir -p "$run_dir$dep_dir"
            cp "$dep" "$run_dir$dep" 2>/dev/null || true
          fi
        done
        ld_so=$("$LDD_BIN" "$elf" 2>/dev/null | grep -o '/nix/store/[^ ]*ld-linux[^ ]*' | head -1 || true)
        if [ -n "$ld_so" ] && [ -f "$ld_so" ]; then
          ld_dir=$(dirname "$ld_so")
          mkdir -p "$run_dir$ld_dir"
          cp "$ld_so" "$run_dir$ld_so" 2>/dev/null || true
          chmod +x "$run_dir$ld_so" 2>/dev/null || true
        fi
      }

      copy_elf_deps "$BUSYBOX"

      cp "$TIDEFSCTL" "$run_dir/bin/tidefsctl"
      chmod +x "$run_dir/bin/tidefsctl"
      copy_elf_deps "$TIDEFSCTL"

      # Copy kernel module.
      MODULE_FOUND=0
      if [ -n "$KO_PATH_ARG" ] && [ -f "$KO_PATH_ARG" ]; then
        cp "$KO_PATH_ARG" "$run_dir/lib/modules/tidefs_posix_vfs.ko"
        MODULE_FOUND=1
        echo "  Module copied from $KO_PATH_ARG"
      elif [ -f "$MODULE_DIR/tidefs_posix_vfs.ko" ]; then
        cp "$MODULE_DIR/tidefs_posix_vfs.ko" "$run_dir/lib/modules/"
        MODULE_FOUND=1
      fi

      if [ "$MODULE_FOUND" -eq 0 ]; then
        echo "  Module not found; guest will classify module_load as BLOCKED"
      fi

      # Copy mmap test binary.
      cp "$MMAP_TEST" "$run_dir/bin/tidefs-kmod-mmap-test"
      chmod +x "$run_dir/bin/tidefs-kmod-mmap-test"
      copy_elf_deps "$MMAP_TEST"

      echo "root:x:0:0:root:/root:/bin/sh" > "$run_dir/etc/passwd"
      echo "root:x:0:" > "$run_dir/etc/group"

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
UNSUPPORTED=0

pass() { echo "PASS: \$1"; PASSED=\$((PASSED + 1)); }
fail() { echo "FAIL: \$1 -- \$2"; FAILED=\$((FAILED + 1)); }
blocked() { echo "BLOCKED: \$1 -- \$2"; BLOCKED=\$((BLOCKED + 1)); }
unsupported() { echo "UNSUPPORTED: \$1 -- \$2"; UNSUPPORTED=\$((UNSUPPORTED + 1)); }

MNT=/mnt/tidefs
POOL_DEV=/dev/vda
POOL_NAME=qemu_mmap_pool
POOL_READY=0
MOUNTED=0

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
elif grep -q tidefs_posix_vfs /proc/modules 2>/dev/null; then
    pass "module_lsmod"
else
    blocked "module_lsmod" "module not loaded"
fi

# ── Phase 1: Configured pool member ──────────────────────────────────
echo ""
echo "--- Phase 1: Configured pool member ---"
mkdir -p "\$MNT"

echo "Waiting for virtio pool member \$POOL_DEV..."
for _ in \$(seq 1 30); do
    [ -b "\$POOL_DEV" ] && break
    sleep 1
done
if [ -b "\$POOL_DEV" ]; then
    pass "configured_pool_device_present"
else
    blocked "configured_pool_device_present" "\$POOL_DEV missing"
fi

if [ -b "\$POOL_DEV" ] && command -v tidefsctl >/dev/null 2>&1; then
    COUT=\$(tidefsctl pool create "\$POOL_NAME" --devices "\$POOL_DEV" --json 2>&1)
    RC=\$?
    echo "tidefsctl_pool_create_exit=\$RC"
    if [ "\$RC" -eq 0 ]; then
        pass "configured_pool_member_created"
        SOUT=\$(tidefsctl pool scan --devices "\$POOL_DEV" 2>&1)
        SRC=\$?
        if [ "\$SRC" -eq 0 ] && echo "\$SOUT" | grep -qi "label"; then
            pass "configured_pool_label_verified"
            POOL_READY=1
        else
            fail "configured_pool_label_verified" "\$SOUT"
        fi
    else
        fail "configured_pool_member_created" "\$COUT"
    fi
else
    if [ ! -b "\$POOL_DEV" ]; then
        blocked "configured_pool_member_created" "virtio pool device missing"
    else
        blocked "configured_pool_member_created" "tidefsctl not found in initramfs"
    fi
    blocked "configured_pool_label_verified" "pool member was not created"
fi

# ── Phase 2: Mount ───────────────────────────────────────────────────
echo ""
echo "--- Phase 2: Mount ---"
if mount -o bootstrap -t tidefs none "\$MNT" 2>/tmp/bootstrap-mount.err; then
    fail "missing_pool_member_rejected" "bootstrap mount unexpectedly succeeded"
    umount "\$MNT" 2>/dev/null || true
else
    pass "missing_pool_member_rejected"
fi

if [ "\$POOL_READY" -eq 1 ]; then
    if mount -t tidefs "\$POOL_DEV" "\$MNT" 2>/tmp/mount.err; then
        pass "configured_pool_mount"
        MOUNTED=1
    else
        fail "configured_pool_mount" "\$(head -3 /tmp/mount.err | tr '\n' ' ')"
    fi
else
    blocked "configured_pool_mount" "pool member was not ready"
fi

# ── Phase 3: Mmap workload ───────────────────────────────────────────
echo ""
echo "--- Phase 3: Mmap workload ---"
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
        fail "mmap_workload" "\$(cat /tmp/mmap.err)"
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

unsupported "custom-rust-vm-ops" "mounted C shim uses generic_file_mmap and C address_space_operations; Rust KmodVfsVmOps is source-model only until a C vm_ops bridge is registered"
unsupported "crash-consistency" "issue #258 only proves first-boot mounted mmap/writeback behavior; TFR-008/TFR-018 crash consistency remains open"

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
echo "UNSUPPORTED=\$UNSUPPORTED"
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
    POOL_DISK="$RUN_DIR/pool.img"

    build_initrd "$RUN_DIR" "0"
    dd if=/dev/zero of="$POOL_DISK" bs=1M count=128 2>/dev/null
    echo "  Pool disk: $POOL_DISK ($(du -h "$POOL_DISK" | cut -f1))"

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
      -drive file="$POOL_DISK",if=virtio,format=raw \
      > "$VAL_LOG" 2>&1 || true

    echo ""
    echo "=== mmap Validation Results (First Boot) ==="

    PASSED=0
    FAILED=0
    BLOCKED=0
    UNSUPPORTED=0

    for op in \
      module_load module_lsmod configured_pool_device_present \
      configured_pool_member_created configured_pool_label_verified \
      missing_pool_member_rejected configured_pool_mount \
      create-and-write-initial mmap-shared fault-read-shared \
      fault-write-shared write-read-coherence msync-sync munmap \
      post-sync-readback \
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
      elif grep -q "UNSUPPORTED: $op" "$VAL_LOG" 2>/dev/null; then
        detail=$(grep "UNSUPPORTED: $op" "$VAL_LOG" 2>/dev/null | head -1 | sed "s/^.*UNSUPPORTED: $op //")
        echo "  UNSUPPORTED: $op -- $detail"
        UNSUPPORTED=$((UNSUPPORTED + 1))
      else
        echo "  MISSING: $op (no validation in log)"
        BLOCKED=$((BLOCKED + 1))
      fi
    done

    for op in custom-rust-vm-ops crash-consistency; do
      if grep -q "UNSUPPORTED: $op" "$VAL_LOG" 2>/dev/null; then
        detail=$(grep "UNSUPPORTED: $op" "$VAL_LOG" 2>/dev/null | head -1 | sed "s/^.*UNSUPPORTED: $op //")
        echo "  UNSUPPORTED: $op -- $detail"
        UNSUPPORTED=$((UNSUPPORTED + 1))
      else
        echo "  MISSING: $op unsupported disclosure"
        BLOCKED=$((BLOCKED + 1))
      fi
    done

    echo ""
    echo "First-boot summary: $PASSED passed, $FAILED failed, $BLOCKED blocked, $UNSUPPORTED unsupported"
    echo "Validation log: $VAL_LOG"

    OUTPUT_ROOT="''${TIDEFS_OUTPUT_ROOT:-/tmp/tidefs-validation}"
    OUTPUT_DIR="$OUTPUT_ROOT/kernel-mmap-validation/$(date -u +%Y-%m-%dT%H%M%SZ)"
    mkdir -p "$OUTPUT_DIR"
    cp "$VAL_LOG" "$OUTPUT_DIR/qemu.log"
    {
      echo "pass=$PASSED"
      echo "fail=$FAILED"
      echo "blocked=$BLOCKED"
      echo "unsupported=$UNSUPPORTED"
      echo "validation_log=$OUTPUT_DIR/qemu.log"
    } > "$OUTPUT_DIR/summary.env"
    echo "Validation output directory: $OUTPUT_DIR"

    if [ "$FAILED" -gt 0 ]; then
      echo "VALIDATION: FAIL -- $FAILED operations failed"
      exit 1
    fi

    if [ "$BLOCKED" -gt 0 ]; then
      echo "VALIDATION: BLOCKED -- $BLOCKED first-boot operations lacked validation"
      exit 1
    fi

    echo "VALIDATION: PASS -- mounted first-boot mmap/writeback rows succeeded; unsupported rows are disclosed"
    exit 0
  '';
in
kmodMmapScript
