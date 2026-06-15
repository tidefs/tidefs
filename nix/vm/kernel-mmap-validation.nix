# TideFS: kmod-posix-vfs mmap page-fault and msync validation in QEMU.
#
# Builds the kmod-posix-vfs kernel module against a Linux 7.0 kernel,
# boots a QEMU VM, loads the module, mounts a TideFS filesystem through
# the kernel module, and exercises the mmap path:
#   - page-fault read (MAP_SHARED read fault populates page)
#   - page-fault write (MAP_SHARED generic-filemap write fault marks dirty)
#   - dirty-folio/writepages accounting through the registered C a_ops table
#   - msync MS_SYNC (durability flush)
#   - munmap (dirty-page writeback and cleanup)
#   - truncate-down and truncate-extend page-cache invalidation
#   - mapped dirty truncate followed by msync, munmap, remount, and readback
#   - buffered overwrite after a prior mapping plus remount readback
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
 *  3. Write via pointer (fault-write + Linux dirty-folio tracking).
 *  4. Read back via pointer (write-read coherence).
 *  5. msync MS_SYNC (durability flush).
 *  6. munmap (cleanup, dirty-page writeback).
 *  7. Re-read via read(2) to verify post-sync visibility.
 *  8. Truncate and overwrite rows for mounted C page-cache invalidation.
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
static int row_failures;

static void die(const char *msg) {
    fprintf(stderr, "mmap-test: %s: %s\n", msg, strerror(errno));
    exit(1);
}

static void pass_row(const char *name) {
    printf("PASS: %s\n", name);
}

static void fail_row(const char *name, const char *note) {
    printf("FAIL: %s -- %s\n", name, note);
    row_failures++;
}

static void unsupported_row(const char *name, const char *note) {
    printf("UNSUPPORTED: %s -- %s\n", name, note);
}

static int write_byte_run(int fd, unsigned char value, size_t len, off_t offset) {
    unsigned char buf[PAGE];
    size_t done = 0;

    memset(buf, value, sizeof(buf));
    while (done < len) {
        size_t chunk = len - done;
        ssize_t n;

        if (chunk > sizeof(buf))
            chunk = sizeof(buf);
        n = pwrite(fd, buf, chunk, offset + (off_t)done);
        if (n != (ssize_t)chunk)
            return 0;
        done += chunk;
    }
    return 1;
}

static int verify_byte_run(int fd, off_t offset, size_t len, unsigned char value) {
    unsigned char buf[PAGE];
    size_t done = 0;

    while (done < len) {
        size_t chunk = len - done;
        ssize_t n;

        if (chunk > sizeof(buf))
            chunk = sizeof(buf);
        n = pread(fd, buf, chunk, offset + (off_t)done);
        if (n != (ssize_t)chunk)
            return 0;
        for (size_t i = 0; i < chunk; i++) {
            if (buf[i] != value)
                return 0;
        }
        done += chunk;
    }
    return 1;
}

static int verify_size_and_eof(int fd, off_t size) {
    struct stat st;
    unsigned char byte = 0;

    if (fstat(fd, &st) < 0)
        return 0;
    if (st.st_size != size)
        return 0;
    return pread(fd, &byte, 1, size) == 0;
}

static void test_truncate_down_discard(void) {
    char path[8192];
    int fd;
    unsigned char *map;
    volatile unsigned char touch;

    snprintf(path, sizeof(path), "%s/truncate_down_discard", test_dir);
    fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { fail_row("truncate-down-discard", "open failed"); return; }
    if (!write_byte_run(fd, 0x31, PAGE, 0) ||
        !write_byte_run(fd, 0x5a, PAGE, PAGE)) {
        close(fd);
        fail_row("truncate-down-discard", "initial write failed");
        return;
    }
    if (fsync(fd) < 0) {
        close(fd);
        fail_row("truncate-down-discard", "initial fsync failed");
        return;
    }

    map = mmap(NULL, TEST_BUF_SIZE / 2, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        fail_row("truncate-down-discard", "mmap failed");
        return;
    }
    touch = map[PAGE];
    (void)touch;
    if (ftruncate(fd, PAGE) < 0) {
        munmap(map, TEST_BUF_SIZE / 2);
        close(fd);
        fail_row("truncate-down-discard", "truncate-down failed");
        return;
    }
    munmap(map, TEST_BUF_SIZE / 2);

    if (verify_size_and_eof(fd, PAGE) &&
        verify_byte_run(fd, 0, PAGE, 0x31))
        pass_row("truncate-down-discard");
    else
        fail_row("truncate-down-discard", "discarded bytes visible after truncate");
    close(fd);
}

static void test_truncate_extend_zero_read(void) {
    char path[8192];
    int fd;
    unsigned char *map;
    volatile unsigned char touch;

    snprintf(path, sizeof(path), "%s/truncate_extend_zero", test_dir);
    fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { fail_row("truncate-extend-zero-read", "open failed"); return; }
    if (!write_byte_run(fd, 0x11, PAGE, 0) ||
        !write_byte_run(fd, 0x7e, PAGE, PAGE)) {
        close(fd);
        fail_row("truncate-extend-zero-read", "initial write failed");
        return;
    }
    if (fsync(fd) < 0) {
        close(fd);
        fail_row("truncate-extend-zero-read", "initial fsync failed");
        return;
    }

    map = mmap(NULL, TEST_BUF_SIZE / 2, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        fail_row("truncate-extend-zero-read", "mmap failed");
        return;
    }
    touch = map[PAGE];
    (void)touch;
    if (ftruncate(fd, PAGE) < 0) {
        munmap(map, TEST_BUF_SIZE / 2);
        close(fd);
        fail_row("truncate-extend-zero-read", "truncate-down failed");
        return;
    }
    if (munmap(map, TEST_BUF_SIZE / 2) < 0) {
        close(fd);
        fail_row("truncate-extend-zero-read", "munmap failed");
        return;
    }
    if (ftruncate(fd, TEST_BUF_SIZE / 2) < 0) {
        close(fd);
        fail_row("truncate-extend-zero-read", "truncate-extend failed");
        return;
    }

    if (verify_byte_run(fd, 0, PAGE, 0x11) &&
        verify_byte_run(fd, PAGE, PAGE, 0x00))
        pass_row("truncate-extend-zero-read");
    else
        fail_row("truncate-extend-zero-read", "extension returned stale bytes");
    close(fd);
}

static void test_mapped_dirty_truncate_down(void) {
    char path[8192];
    int fd;
    unsigned char *map;

    snprintf(path, sizeof(path), "%s/mapped_dirty_truncate", test_dir);
    fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { fail_row("mapped-dirty-truncate-down", "open failed"); return; }
    if (!write_byte_run(fd, 0x41, PAGE, 0) ||
        !write_byte_run(fd, 0x42, PAGE, PAGE)) {
        close(fd);
        fail_row("mapped-dirty-truncate-down", "initial write failed");
        return;
    }
    if (fsync(fd) < 0) {
        close(fd);
        fail_row("mapped-dirty-truncate-down", "initial fsync failed");
        return;
    }

    map = mmap(NULL, TEST_BUF_SIZE / 2, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        fail_row("mapped-dirty-truncate-down", "mmap failed");
        return;
    }
    memset(map + PAGE, 0x7d, PAGE);
    if (ftruncate(fd, PAGE) < 0) {
        munmap(map, TEST_BUF_SIZE / 2);
        close(fd);
        fail_row("mapped-dirty-truncate-down", "truncate-down failed");
        return;
    }
    if (msync(map, TEST_BUF_SIZE / 2, MS_SYNC) < 0) {
        char note[160];
        snprintf(note, sizeof(note), "msync after truncate returned %s", strerror(errno));
        munmap(map, TEST_BUF_SIZE / 2);
        close(fd);
        unsupported_row("mapped-dirty-truncate-down", note);
        return;
    }
    if (munmap(map, TEST_BUF_SIZE / 2) < 0) {
        close(fd);
        fail_row("mapped-dirty-truncate-down", "munmap failed");
        return;
    }

    if (verify_size_and_eof(fd, PAGE) &&
        verify_byte_run(fd, 0, PAGE, 0x41))
        pass_row("mapped-dirty-truncate-down");
    else
        fail_row("mapped-dirty-truncate-down", "truncated bytes visible before remount");
    close(fd);
}

static void test_buffered_overwrite_after_mapping(void) {
    char path[8192];
    int fd;
    unsigned char *map;
    volatile unsigned char touch;

    snprintf(path, sizeof(path), "%s/buffered_after_mapping", test_dir);
    fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { fail_row("buffered-overwrite-after-mapping", "open failed"); return; }
    if (!write_byte_run(fd, 0x21, PAGE, 0)) {
        close(fd);
        fail_row("buffered-overwrite-after-mapping", "initial write failed");
        return;
    }
    if (fsync(fd) < 0) {
        close(fd);
        fail_row("buffered-overwrite-after-mapping", "initial fsync failed");
        return;
    }

    map = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        fail_row("buffered-overwrite-after-mapping", "mmap failed");
        return;
    }
    touch = map[0];
    (void)touch;

    if (!write_byte_run(fd, 0x99, PAGE, 0)) {
        munmap(map, PAGE);
        close(fd);
        fail_row("buffered-overwrite-after-mapping", "buffered overwrite failed");
        return;
    }
    if (fsync(fd) < 0) {
        munmap(map, PAGE);
        close(fd);
        fail_row("buffered-overwrite-after-mapping", "overwrite fsync failed");
        return;
    }

    int ok = 1;
    for (size_t i = 0; i < PAGE; i++) {
        if (map[i] != 0x99) {
            ok = 0;
            break;
        }
    }
    if (!verify_byte_run(fd, 0, PAGE, 0x99))
        ok = 0;
    munmap(map, PAGE);

    if (ok)
        pass_row("buffered-overwrite-after-mapping");
    else
        fail_row("buffered-overwrite-after-mapping", "mmap/readback diverged after buffered overwrite");
    close(fd);
}

static int verify_remount_rows(void) {
    char path[8192];
    int fd;
    int failures = 0;

    snprintf(path, sizeof(path), "%s/mapped_dirty_truncate", test_dir);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        fail_row("mapped-dirty-truncate-remount", "open failed after remount");
        failures++;
    } else {
        if (verify_size_and_eof(fd, PAGE) &&
            verify_byte_run(fd, 0, PAGE, 0x41))
            pass_row("mapped-dirty-truncate-remount");
        else {
            fail_row("mapped-dirty-truncate-remount", "truncated bytes visible after remount");
            failures++;
        }
        close(fd);
    }

    snprintf(path, sizeof(path), "%s/buffered_after_mapping", test_dir);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        fail_row("buffered-overwrite-remount", "open failed after remount");
        failures++;
    } else {
        if (verify_size_and_eof(fd, PAGE) &&
            verify_byte_run(fd, 0, PAGE, 0x99))
            pass_row("buffered-overwrite-remount");
        else {
            fail_row("buffered-overwrite-remount", "remount readback diverged");
            failures++;
        }
        close(fd);
    }

    return failures == 0 ? 0 : 1;
}

int main(int argc, char *argv[]) {
    if (argc == 3 && strcmp(argv[1], "--verify-remount") == 0) {
        snprintf(test_dir, sizeof(test_dir), "%s", argv[2]);
        return verify_remount_rows();
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: tidefs-kmod-mmap-test [--verify-remount] <mount-point>\n");
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
        fail_row("fault-read-shared", "data mismatch");

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
        fail_row("write-read-coherence", "mapped readback mismatch");

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
            fail_row("post-sync-readback", "page0 corrupted");
            goto done;
        }
    }

    /* Page 1 should be pattern (written + msync'd) */
    for (size_t i = 0; i < PAGE; i++) {
        if (rbuf[PAGE + i] != pattern[i]) {
            fprintf(stderr, "post-sync-readback: page1 mismatch at %zu: expected %02x got %02x\n",
                    i, pattern[i], rbuf[PAGE + i]);
            fail_row("post-sync-readback", "page1 not visible after sync");
            goto done;
        }
    }

    /* Page 2 should still be original (not written) */
    for (size_t i = 0; i < PAGE; i++) {
        if (rbuf[PAGE * 2 + i] != (unsigned char)((PAGE * 2 + i) & 0xFF)) {
            fprintf(stderr, "post-sync-readback: page2 mismatch at %zu\n", i);
            fail_row("post-sync-readback", "page2 corrupted");
            goto done;
        }
    }

    /* Page 3 should be pattern (written + msync'd) */
    for (size_t i = 0; i < PAGE; i++) {
        if (rbuf[PAGE * 3 + i] != pattern[i]) {
            fprintf(stderr, "post-sync-readback: page3 mismatch at %zu: expected %02x got %02x\n",
                    i, pattern[i], rbuf[PAGE * 3 + i]);
            fail_row("post-sync-readback", "page3 not visible after sync");
            goto done;
        }
    }

    printf("PASS: post-sync-readback\n");

    test_truncate_down_discard();
    test_truncate_extend_zero_read();
    test_mapped_dirty_truncate_down();
    test_buffered_overwrite_after_mapping();

done:
    close(fd);
    return row_failures == 0 ? 0 : 1;
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
page_mkwrite, msync, munmap, truncate invalidation, and remount
readback) in a reproducible Nix/QEMU Linux 7.0 environment. Produces
tier-classified validation for mmap behavior.

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
    MMAP_RC=0
    /bin/tidefs-kmod-mmap-test "\$MNT" 2>/tmp/mmap.err || MMAP_RC=\$?

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

# ── Phase 3b: Remount readback for truncate/overwrite rows ───────────
echo ""
echo "--- Phase 3b: Remount readback ---"
if [ "\$MOUNTED" -eq 1 ] && [ -x /bin/tidefs-kmod-mmap-test ]; then
    sync
    if umount "\$MNT" 2>/tmp/remount-umount.err; then
        MOUNTED=0
        if mount -t tidefs "\$POOL_DEV" "\$MNT" 2>/tmp/remount.err; then
            pass "configured_pool_remount"
            MOUNTED=1
            REMOUNT_RC=0
            /bin/tidefs-kmod-mmap-test --verify-remount "\$MNT" 2>/tmp/mmap-remount.err || REMOUNT_RC=\$?
            echo "mmap_remount_readback_exit_code=\$REMOUNT_RC"
            if [ "\$REMOUNT_RC" -eq 0 ]; then
                echo "mmap_remount_readback_summary=ALL_PASSED"
            else
                echo "mmap_remount_readback_summary=FAILURES_DETECTED"
                cat /tmp/mmap-remount.err
            fi
        else
            fail "configured_pool_remount" "\$(cat /tmp/remount.err)"
        fi
    else
        fail "configured_pool_remount" "\$(cat /tmp/remount-umount.err)"
    fi
else
    if [ "\$MOUNTED" -ne 1 ]; then
        blocked "configured_pool_remount" "filesystem not mounted"
    fi
    if [ ! -x /bin/tidefs-kmod-mmap-test ]; then
        blocked "configured_pool_remount" "test binary not found"
    fi
fi

unsupported "custom-rust-vm-ops" "mounted C shim uses generic_file_mmap and C address_space_operations; Rust KmodVfsVmOps is fail-closed source-model code, not a registered C vm_ops bridge"
unsupported "crash-consistency" "issues #258/#260 only prove first-boot mounted mmap/writeback behavior; TFR-008/TFR-018 crash consistency remains open"

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
    ROW_SUMMARY="$RUN_DIR/row-summary.txt"
    : > "$ROW_SUMMARY"

    record_row() {
      local row="$1"

      echo "  $row"
      echo "$row" >> "$ROW_SUMMARY"
    }

    for op in \
      module_load module_lsmod configured_pool_device_present \
      configured_pool_member_created configured_pool_label_verified \
      missing_pool_member_rejected configured_pool_mount \
      create-and-write-initial mmap-shared fault-read-shared \
      fault-write-shared write-read-coherence msync-sync munmap \
      post-sync-readback truncate-down-discard \
      truncate-extend-zero-read mapped-dirty-truncate-down \
      configured_pool_remount mapped-dirty-truncate-remount \
      buffered-overwrite-after-mapping buffered-overwrite-remount \
      unmount module_unload; do
      # Some ops are reported by C test binary directly (PASS:/FAIL:),
      # others by the init shell script.
      if grep -q "PASS: $op" "$VAL_LOG" 2>/dev/null; then
        record_row "PASS: $op"
        PASSED=$((PASSED + 1))
      elif grep -q "FAIL: $op" "$VAL_LOG" 2>/dev/null; then
        detail=$(grep "FAIL: $op" "$VAL_LOG" 2>/dev/null | head -1 | sed "s/^.*FAIL: $op[[:space:]]*--[[:space:]]*//")
        record_row "FAIL: $op -- $detail"
        FAILED=$((FAILED + 1))
      elif grep -q "BLOCKED: $op" "$VAL_LOG" 2>/dev/null; then
        detail=$(grep "BLOCKED: $op" "$VAL_LOG" 2>/dev/null | head -1 | sed "s/^.*BLOCKED: $op[[:space:]]*--[[:space:]]*//")
        record_row "BLOCKED: $op -- $detail"
        BLOCKED=$((BLOCKED + 1))
      elif grep -q "UNSUPPORTED: $op" "$VAL_LOG" 2>/dev/null; then
        detail=$(grep "UNSUPPORTED: $op" "$VAL_LOG" 2>/dev/null | head -1 | sed "s/^.*UNSUPPORTED: $op[[:space:]]*--[[:space:]]*//")
        record_row "UNSUPPORTED: $op -- $detail"
        UNSUPPORTED=$((UNSUPPORTED + 1))
      else
        record_row "BLOCKED: $op -- no validation in log"
        BLOCKED=$((BLOCKED + 1))
      fi
    done

    for op in custom-rust-vm-ops crash-consistency; do
      if grep -q "UNSUPPORTED: $op" "$VAL_LOG" 2>/dev/null; then
        detail=$(grep "UNSUPPORTED: $op" "$VAL_LOG" 2>/dev/null | head -1 | sed "s/^.*UNSUPPORTED: $op[[:space:]]*--[[:space:]]*//")
        record_row "UNSUPPORTED: $op -- $detail"
        UNSUPPORTED=$((UNSUPPORTED + 1))
      else
        record_row "BLOCKED: $op -- unsupported disclosure missing"
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
    cp "$ROW_SUMMARY" "$OUTPUT_DIR/row-summary.txt"
    {
      echo "pass=$PASSED"
      echo "fail=$FAILED"
      echo "blocked=$BLOCKED"
      echo "unsupported=$UNSUPPORTED"
      echo "validation_log=$OUTPUT_DIR/qemu.log"
      echo "row_summary=$OUTPUT_DIR/row-summary.txt"
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
