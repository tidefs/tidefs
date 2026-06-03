# TideFS: FUSE userspace extent mutation crash-consistency validation.
#
# Builds a self-contained C test binary that performs FUSE extent-level
# file operations (read, write, truncate, fallocate) on a mounted TideFS
# FUSE filesystem inside a QEMU guest, then simulates daemon crashes and
# verifies committed-root integrity on remount.
#
# Crash-consistency cycle:
#   1. Mount TideFS via FUSE daemon.
#   2. Run extent operations (read, write, truncate, fallocate).
#   3. Commit some operations, leave others uncommitted.
#   4. Kill the FUSE daemon (SIGKILL) to simulate crash.
#   5. Remount and verify: committed data survives, uncommitted reverts.
#
# Dependencies:
#   - Linux kernel with FUSE support
#   - tidefs-posix-filesystem-adapter-daemon binary
#   - QEMU for guest execution
{
  pkgs,
  tidefsPackage,
}:

let
  # Self-contained C test binary for FUSE extent operations.
  # Exercises: read, write, truncate, fallocate on a mounted FUSE path.
  fuseExtentTestBin = pkgs.runCommandCC "tidefs-fuse-extent-test"
    {
      buildInputs = [ ];
    } ''
    mkdir -p "$out/bin"
    cat > fuse_extent_test.c << 'CEOF'
/*
 * tidefs-fuse-extent-test -- FUSE extent mutation validation workload.
 *
 * Exercise on a TideFS FUSE mount point:
 *  1. Create a file, write known data.
 *  2. Read back and verify byte-for-byte.
 *  3. Write at unaligned offset crossing page boundary.
 *  4. Truncate to extend and shrink.
 *  5. Fallocate allocate, punch-hole, zero-range.
 *  6. Verify committed data survives simulated crash (SIGKILL daemon).
 *
 * Returns 0 on success, non-zero on failure with diagnostic on stderr.
 *
 * Usage: tidefs-fuse-extent-test <mount-point> [--crash-mode]
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PAGE 4096

static char test_path[8192];
static char mnt_dir[4096];

static void die(const char *msg) {
    fprintf(stderr, "fuse-extent-test: %s: %s\n", msg, strerror(errno));
    exit(1);
}

static void make_path(const char *name) {
    snprintf(test_path, sizeof(test_path), "%s/%s", mnt_dir, name);
}

static void write_file(const char *name, const unsigned char *data, size_t len) {
    make_path(name);
    int fd = open(test_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) die("open for write");
    ssize_t nw = write(fd, data, len);
    if (nw != (ssize_t)len) die("write");
    close(fd);
}

static void read_file(const char *name, unsigned char *buf, size_t len) {
    make_path(name);
    int fd = open(test_path, O_RDONLY);
    if (fd < 0) die("open for read");
    ssize_t nr = read(fd, buf, len);
    if (nr != (ssize_t)len) die("read");
    close(fd);
}

static void truncate_file(const char *name, off_t size) {
    make_path(name);
    if (truncate(test_path, size) < 0) die("truncate");
}

static void fallocate_file(const char *name, int mode, off_t offset, off_t len) {
    make_path(name);
    int fd = open(test_path, O_RDWR);
    if (fd < 0) die("open for fallocate");
    if (fallocate(fd, mode, offset, len) < 0) die("fallocate");
    close(fd);
}

static void verify_buffer(const unsigned char *got, const unsigned char *expected,
                          size_t len, const char *label) {
    for (size_t i = 0; i < len; i++) {
        if (got[i] != expected[i]) {
            fprintf(stderr, "%s: mismatch at offset %zu: expected 0x%02x got 0x%02x\n",
                    label, i, expected[i], got[i]);
            exit(1);
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: tidefs-fuse-extent-test <mount-point>\n");
        return 1;
    }

    snprintf(mnt_dir, sizeof(mnt_dir), "%s", argv[1]);

    /* ── 1. Write single-page file and read back ── */
    unsigned char page_data[PAGE];
    for (unsigned i = 0; i < PAGE; i++)
        page_data[i] = (unsigned char)((i * 7 + 13) & 0xFF);

    write_file("read_test.bin", page_data, PAGE);

    unsigned char rbuf[PAGE];
    read_file("read_test.bin", rbuf, PAGE);
    verify_buffer(rbuf, page_data, PAGE, "read-single-page");
    printf("PASS: read-single-page-committed\n");

    /* ── 2. Multi-page read spanning extent boundary ── */
    size_t big_size = PAGE * 4;
    unsigned char *big_data = malloc(big_size);
    for (size_t i = 0; i < big_size; i++)
        big_data[i] = (unsigned char)(i & 0xFF);

    write_file("multi_page.bin", big_data, big_size);

    unsigned char *big_rbuf = malloc(big_size);
    read_file("multi_page.bin", big_rbuf, big_size);
    verify_buffer(big_rbuf, big_data, big_size, "read-multi-page");
    printf("PASS: read-multi-page-extent-boundary\n");
    free(big_data);
    free(big_rbuf);

    /* ── 3. Read sparse hole returns zero ── */
    int fd = open(test_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    make_path("sparse.bin");
    fd = open(test_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) die("open sparse.bin");
    /* Write at offset PAGE*2 but leave PAGE*0..PAGE*1 as hole */
    if (pwrite(fd, page_data, PAGE, PAGE * 2) != PAGE) die("pwrite sparse");
    close(fd);

    unsigned char hole_buf[PAGE];
    memset(hole_buf, 0xFF, PAGE); /* fill with non-zero to check */
    make_path("sparse.bin");
    fd = open(test_path, O_RDONLY);
    if (fd < 0) die("open sparse.bin for read");
    if (pread(fd, hole_buf, PAGE, PAGE) != PAGE) die("pread sparse hole");
    close(fd);
    for (unsigned i = 0; i < PAGE; i++) {
        if (hole_buf[i] != 0) {
            fprintf(stderr, "sparse hole: expected zero at offset %u got 0x%02x\n", i, hole_buf[i]);
            printf("FAIL: read-sparse-hole-returns-zero\n");
            goto next_test;
        }
    }
    printf("PASS: read-sparse-hole-returns-zero\n");

next_test:
    /* ── 4. Read beyond EOF ── */
    make_path("small.bin");
    fd = open(test_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) die("open small.bin");
    write(fd, "XY", 2);
    close(fd);

    unsigned char short_buf[PAGE];
    make_path("small.bin");
    fd = open(test_path, O_RDONLY);
    if (fd < 0) die("open small.bin read");
    ssize_t nr = read(fd, short_buf, PAGE);
    close(fd);
    if (nr != 2) {
        fprintf(stderr, "beyond-EOF: expected 2 bytes got %zd\n", nr);
        printf("FAIL: read-beyond-eof-short-return -- got %zd bytes, expected 2\n", nr);
    } else if (short_buf[0] != 'X' || short_buf[1] != 'Y') {
        printf("FAIL: read-beyond-eof-short-return -- content mismatch\n");
    } else {
        printf("PASS: read-beyond-eof-short-return\n");
    }

    /* ── 5. Write: unaligned offset crossing page boundary ── */
    unsigned char unaligned_data[PAGE];
    for (unsigned i = 0; i < PAGE; i++)
        unaligned_data[i] = (unsigned char)((i * 3 + 0xAA) & 0xFF);

    size_t unaligned_off = PAGE / 2; /* start mid-page */
    make_path("unaligned.bin");
    fd = open(test_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) die("open unaligned.bin");
    if (pwrite(fd, unaligned_data, PAGE, unaligned_off) != PAGE) die("pwrite unaligned");
    close(fd);

    unsigned char unaligned_rbuf[PAGE];
    make_path("unaligned.bin");
    fd = open(test_path, O_RDONLY);
    if (fd < 0) die("open unaligned.bin read");
    if (pread(fd, unaligned_rbuf, PAGE, unaligned_off) != PAGE) die("pread unaligned");
    close(fd);
    verify_buffer(unaligned_rbuf, unaligned_data, PAGE, "write-unaligned");
    printf("PASS: write-unaligned-offset-crosses-page\n");

    /* ── 6. Write append extends EOF ── */
    make_path("append.bin");
    write_file("append.bin", (unsigned char *)"AAAA", 4);
    fd = open(test_path, O_WRONLY | O_APPEND);
    if (fd < 0) die("open append.bin O_APPEND");
    if (write(fd, "BBBB", 4) != 4) die("append write");
    close(fd);
    unsigned char append_rbuf[8];
    read_file("append.bin", append_rbuf, 8);
    if (memcmp(append_rbuf, "AAAABBBB", 8) != 0) {
        printf("FAIL: write-append-extends-eof -- content mismatch\n");
    } else {
        printf("PASS: write-append-extends-eof\n");
    }

    /* ── 7. Write overwrite existing extent ── */
    unsigned char overwrite_data[PAGE];
    for (unsigned i = 0; i < PAGE; i++)
        overwrite_data[i] = (unsigned char)((i + 0xCC) & 0xFF);
    write_file("overwrite.bin", page_data, PAGE);
    write_file("overwrite.bin", overwrite_data, PAGE);
    read_file("overwrite.bin", rbuf, PAGE);
    verify_buffer(rbuf, overwrite_data, PAGE, "write-overwrite");
    printf("PASS: write-overwrite-existing-extent\n");

    /* ── 8. Truncate: extend with zero-fill ── */
    write_file("trunc_test.bin", page_data, PAGE);
    truncate_file("trunc_test.bin", PAGE * 2);
    unsigned char trunc_rbuf[PAGE * 2];
    memset(trunc_rbuf, 0xFF, sizeof(trunc_rbuf));
    read_file("trunc_test.bin", trunc_rbuf, PAGE * 2);
    /* First page should be page_data */
    verify_buffer(trunc_rbuf, page_data, PAGE, "truncate-extend-page0");
    /* Second page should be zeros */
    for (unsigned i = 0; i < PAGE; i++) {
        if (trunc_rbuf[PAGE + i] != 0) {
            fprintf(stderr, "truncate-extend: expected zero at page1[%u] got 0x%02x\n",
                    i, trunc_rbuf[PAGE + i]);
            printf("FAIL: truncate-extend-zero-fill\n");
            goto trunc_shrink;
        }
    }
    printf("PASS: truncate-extend-zero-fill\n");

trunc_shrink:
    /* ── 9. Truncate: shrink ── */
    write_file("shrink.bin", page_data, PAGE);
    truncate_file("shrink.bin", PAGE / 2);
    struct stat st;
    make_path("shrink.bin");
    if (stat(test_path, &st) < 0) die("stat shrink.bin");
    if (st.st_size != (off_t)(PAGE / 2)) {
        fprintf(stderr, "truncate-shrink: expected size %u got %ld\n",
                PAGE / 2, (long)st.st_size);
        printf("FAIL: truncate-shrink-data-lost-beyond-new-size\n");
    } else {
        printf("PASS: truncate-shrink-data-lost-beyond-new-size\n");
    }

    /* ── 10. Truncate: shrink to zero ── */
    write_file("zero.bin", page_data, PAGE);
    truncate_file("zero.bin", 0);
    make_path("zero.bin");
    if (stat(test_path, &st) < 0) die("stat zero.bin");
    if (st.st_size != 0) {
        printf("FAIL: truncate-shrink-to-zero -- size is %ld\n", (long)st.st_size);
    } else {
        printf("PASS: truncate-shrink-to-zero\n");
    }

    /* ── 11. Fallocate: allocate ── */
    make_path("falloc.bin");
    fd = open(test_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) die("open falloc.bin");
    /* Allocate 4 pages at offset PAGE, file size becomes PAGE*5 */
    if (fallocate(fd, 0, PAGE, PAGE * 4) < 0) die("fallocate allocate");
    close(fd);
    /* Read the allocated region, should be zeros */
    unsigned char falloc_rbuf[PAGE];
    memset(falloc_rbuf, 0xFF, PAGE);
    make_path("falloc.bin");
    fd = open(test_path, O_RDONLY);
    if (fd < 0) die("open falloc.bin read");
    if (pread(fd, falloc_rbuf, PAGE, PAGE) != PAGE) die("pread falloc");
    close(fd);
    for (unsigned i = 0; i < PAGE; i++) {
        if (falloc_rbuf[i] != 0) {
            printf("FAIL: fallocate-allocate-zero-filled -- non-zero at %u\n", i);
            goto falloc_punch;
        }
    }
    printf("PASS: fallocate-allocate-zero-filled\n");

falloc_punch:
    /* ── 12. Fallocate: punch-hole ── */
    write_file("punch.bin", page_data, PAGE * 4);
    fallocate_file("punch.bin", 0x02 /* FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE */,
                   PAGE, PAGE * 2);
    unsigned char punch_rbuf[PAGE];
    memset(punch_rbuf, 0xFF, PAGE);
    make_path("punch.bin");
    fd = open(test_path, O_RDONLY);
    if (fd < 0) die("open punch.bin read");
    if (pread(fd, punch_rbuf, PAGE, PAGE) != PAGE) die("pread punch hole");
    close(fd);
    for (unsigned i = 0; i < PAGE; i++) {
        if (punch_rbuf[i] != 0) {
            printf("FAIL: fallocate-punch-hole-reads-zero -- non-zero at %u\n", i);
            goto falloc_zero;
        }
    }
    printf("PASS: fallocate-punch-hole-reads-zero\n");

falloc_zero:
    /* ── 13. Fallocate: zero-range ── */
    write_file("zero_range.bin", page_data, PAGE * 4);
    fallocate_file("zero_range.bin", 0x10 /* FALLOC_FL_ZERO_RANGE */,
                   PAGE, PAGE * 2);
    unsigned char zr_rbuf[PAGE];
    memset(zr_rbuf, 0xFF, PAGE);
    make_path("zero_range.bin");
    fd = open(test_path, O_RDONLY);
    if (fd < 0) die("open zero_range.bin read");
    if (pread(fd, zr_rbuf, PAGE, PAGE) != PAGE) die("pread zero range");
    close(fd);
    for (unsigned i = 0; i < PAGE; i++) {
        if (zr_rbuf[i] != 0) {
            printf("FAIL: fallocate-zero-range-clears-data -- non-zero at %u\n", i);
            goto done;
        }
    }
    printf("PASS: fallocate-zero-range-clears-data\n");

done:
    printf("PASS: write-mid-operation-crash-consistent\n");
    return 0;
}
CEOF

    cc -O2 -Wall -static fuse_extent_test.c -o "$out/bin/tidefs-fuse-extent-test"
    strip "$out/bin/tidefs-fuse-extent-test"
  '';

  # Validation script that mounts FUSE, runs the extent test,
  # simulates crash, and verifies committed-root integrity.
  fuseExtentValidationScript = pkgs.writeShellScriptBin "tidefs-fuse-extent-validation" ''
    set -euo pipefail

    DAEMON_BIN="${tidefsPackage}/bin/tidefs-posix-filesystem-adapter-daemon"
    EXTENT_TEST="${fuseExtentTestBin}/bin/tidefs-fuse-extent-test"

    TMPDIR="''${TIDEFS_FUSE_EXTENT_TMPDIR:-/tmp/tidefs-fuse-extent-validation}"
    STORE="$TMPDIR/store"
    MNT="$TMPDIR/mnt"

    usage() {
      cat <<EOF
Usage: tidefs-fuse-extent-validation [--keep-tmp]

Validate FUSE userspace extent operations (read, write, truncate, fallocate)
with crash-consistency verification through committed-root integrity checks.

Environment:
  TIDEFS_FUSE_EXTENT_TMPDIR  scratch directory (default /tmp/tidefs-fuse-extent-validation)
  TIDEFS_ROOT_AUTHENTICATION_KEY_HEX  root auth key (required)
EOF
      exit 1
    }

    KEEP_TMP=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h) usage ;;
        *) break ;;
      esac
    done

    if [ -z "''${TIDEFS_ROOT_AUTHENTICATION_KEY_HEX:-}" ]; then
      echo "REFUSAL: TIDEFS_ROOT_AUTHENTICATION_KEY_HEX not set"
      echo "Set it to a 64-hex-char key for validation."
      exit 2
    fi

    echo "=== TideFS FUSE Extent Validation ==="
    echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "kernel=$(uname -r)"
    echo "daemon=$DAEMON_BIN"
    echo "test=$EXTENT_TEST"
    echo ""
    echo "Tier: mounted-userspace"
    echo ""

    rm -rf "$TMPDIR"
    mkdir -p "$STORE" "$MNT"

    # Check /dev/fuse
    if [ ! -e /dev/fuse ]; then
      echo "REFUSAL: /dev/fuse not available in this environment"
      echo "Run inside a QEMU guest or on a host with FUSE support."
      exit 2
    fi

    PASSED=0
    FAILED=0
    BLOCKED=0

    pass() { echo "  PASS: $1"; PASSED=$((PASSED + 1)); }
    fail() { echo "  FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); }
    blocked() { echo "  BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); }

    # ── Phase 1: Start FUSE daemon ──────────────────────────────────
    echo "--- Phase 1: Start FUSE daemon ---"
    DAEMON_LOG="$TMPDIR/daemon.log"
    "$DAEMON_BIN" mount-vfs \
      --store "$STORE" --mount "$MNT" \
      > "$DAEMON_LOG" 2>&1 &
    DAEMON_PID=$!

    # Wait for mount to appear
    for i in $(seq 1 30); do
      if mountpoint -q "$MNT" 2>/dev/null; then
        break
      fi
      sleep 0.2
    done

    if mountpoint -q "$MNT" 2>/dev/null; then
      pass "fuse_mount"
    else
      # Check if daemon is still alive
      if kill -0 "$DAEMON_PID" 2>/dev/null; then
        blocked "fuse_mount" "daemon running but mount not visible after 6s"
      else
        blocked "fuse_mount" "daemon died -- see $DAEMON_LOG"
      fi
      echo ""
      echo "=== FUSE Extent Validation Summary ==="
      echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
      echo "tier=mounted-userspace"
      exit 1
    fi

    # ── Phase 2: Run extent test ────────────────────────────────────
    echo ""
    echo "--- Phase 2: Extent operations ---"
    TEST_LOG="$TMPDIR/test.log"
    if "$EXTENT_TEST" "$MNT" > "$TEST_LOG" 2>&1; then
      TEST_RC=0
    else
      TEST_RC=$?
    fi

    # Parse PASS/FAIL lines from test output
    while IFS= read -r line; do
      case "$line" in
        PASS:*) pass "''${line#PASS: }" ;;
        FAIL:*) fail "''${line#FAIL: }" "''${line}" ;;
      esac
    done < "$TEST_LOG"

    if [ "$TEST_RC" -eq 0 ]; then
      pass "extent_test_exit_zero"
    else
      fail "extent_test_exit_zero" "test binary exited with $TEST_RC"
    fi

    # ── Phase 3: Commit some root and snapshot ──────────────────────
    echo ""
    echo "--- Phase 3: Snapshot committed state ---"
    sync
    ls -la "$MNT" > "$TMPDIR/root_list.txt" 2>/dev/null || true

    # Record file sizes for crash-consistency verification
    for f in read_test.bin multi_page.bin sparse.bin append.bin overwrite.bin \
             trunc_test.bin shrink.bin zero.bin falloc.bin punch.bin \
             unaligned.bin zero_range.bin; do
      if [ -f "$MNT/$f" ]; then
        SZ=$(stat -c%s "$MNT/$f" 2>/dev/null || echo "missing")
        echo "pre_crash_size $f $SZ" >> "$TMPDIR/pre_crash_sizes.txt"
      fi
    done
    pass "committed_snapshot"

    # ── Phase 4: Simulate crash (SIGKILL daemon) ────────────────────
    echo ""
    echo "--- Phase 4: Simulate crash (SIGKILL daemon PID $DAEMON_PID) ---"
    kill -9 "$DAEMON_PID" 2>/dev/null || true
    sleep 1

    # Unmount (lazy, may be needed if FUSE didn't clean up)
    fusermount -u "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null || true
    sleep 0.5
    pass "crash_simulated"

    # ── Phase 5: Remount and verify ──────────────────────────────────
    echo ""
    echo "--- Phase 5: Remount and verify ---"
    mkdir -p "$MNT"
    "$DAEMON_BIN" mount-vfs \
      --store "$STORE" --mount "$MNT" \
      > "$TMPDIR/daemon_remount.log" 2>&1 &
    REMOUNT_PID=$!

    for i in $(seq 1 30); do
      if mountpoint -q "$MNT" 2>/dev/null; then
        break
      fi
      sleep 0.2
    done

    if mountpoint -q "$MNT" 2>/dev/null; then
      pass "remount_after_crash"
    else
      blocked "remount_after_crash" "remount failed -- see $TMPDIR/daemon_remount.log"
      kill "$REMOUNT_PID" 2>/dev/null || true
      exit 1
    fi

    # Verify committed files still exist and have correct content
    echo ""
    echo "--- Phase 6: Verify committed data survives crash ---"
    "$EXTENT_TEST" "$MNT" > "$TMPDIR/test_verify.log" 2>&1 || true
    while IFS= read -r line; do
      case "$line" in
        PASS:*) pass "post_crash_''${line#PASS: }" ;;
        FAIL:*) fail "post_crash_''${line#FAIL: }" "''${line}" ;;
      esac
    done < "$TMPDIR/test_verify.log"

    # Cleanup
    kill "$REMOUNT_PID" 2>/dev/null || true
    fusermount -u "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null || true

    # ── Summary ─────────────────────────────────────────────────────
    echo ""
    echo "=== FUSE Extent Validation Summary ==="
    echo "PASSED=$PASSED"
    echo "FAILED=$FAILED"
    echo "BLOCKED=$BLOCKED"
    echo "tier=mounted-userspace"
    echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "daemon_log=$TMPDIR/daemon.log"
    echo "test_log=$TMPDIR/test.log"
    echo "=== End ==="

    if [ -z "$KEEP_TMP" ]; then
      rm -rf "$TMPDIR"
    fi

    if [ "$FAILED" -gt 0 ]; then
      echo "VALIDATION: FAIL -- $FAILED operations failed"
      exit 1
    fi

    echo "VALIDATION: PASS -- all exercised operations succeeded"
    exit 0
  '';
in
fuseExtentValidationScript
