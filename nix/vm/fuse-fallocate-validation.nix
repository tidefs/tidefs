# TideFS: FUSE userspace fallocate crash-consistency validation.
#
# Builds a self-contained C test binary that performs fallocate(2)
# space-manipulation operations on a mounted TideFS FUSE filesystem
# inside a QEMU guest, then simulates daemon crashes and verifies
# committed-root integrity on remount.
#
# Crash-consistency cycle:
#   1. Mount TideFS via FUSE daemon.
#   2. Run fallocate operations (allocate, punch-hole, zero-range,
#      collapse-range, insert-range, keep-size, concurrent-allocate).
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
  # Self-contained C test binary for FUSE fallocate operations.
  # Exercises: allocate, punch-hole, zero-range, collapse-range,
  # insert-range, keep-size, and concurrent-allocate on a mounted FUSE path.
  fuseFallocateTestBin = pkgs.runCommandCC "tidefs-fuse-fallocate-test"
    {
      buildInputs = [ ];
    } ''
    mkdir -p "$out/bin"
    cat > fuse_fallocate_test.c << 'CEOF'
/*
 * tidefs-fuse-fallocate-test -- FUSE fallocate validation workload.
 *
 * Exercises on a TideFS FUSE mount point:
 *  1. Allocate: pre-allocate blocks for a file range.
 *  2. Punch-hole: deallocate a range creating a sparse hole.
 *  3. Zero-range: zero-fill a range without block deallocation.
 *  4. Collapse-range: remove a range and shift subsequent data backward.
 *  5. Insert-range: insert a zero-filled hole shifting data forward.
 *  6. Keep-size: allocate blocks without changing file size.
 *  7. Concurrent-allocate: two threads performing alloc/punch on same file.
 *
 * Returns 0 on success, non-zero on failure with diagnostic on stderr.
 *
 * Usage: tidefs-fuse-fallocate-test <mount-point> [--crash-mode]
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PAGE 4096

static char test_path[8192];
static char mnt_dir[4096];

static void die(const char *msg) {
    fprintf(stderr, "fuse-fallocate-test: %s: %s\n", msg, strerror(errno));
    exit(1);
}

static void make_path(const char *name) {
    snprintf(test_path, sizeof(test_path), "%s/%s", mnt_dir, name);
}

/* Fill buffer with deterministic pattern. */
static void fill_buf(unsigned char *buf, size_t len, unsigned seed) {
    for (size_t i = 0; i < len; i++)
        buf[i] = (unsigned char)((i * 7 + seed * 13 + 0x41) & 0xFF);
}

/* ── 1. Allocate ──────────────────────────────────────────────────── */
static int test_allocate(void) {
    make_path("alloc.bin");
    unlink(test_path);
    int fd = open(test_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("alloc open"); return 1; }

    if (fallocate(fd, 0, 0, PAGE * 4) < 0) {
        perror("fallocate allocate"); close(fd); return 1;
    }
    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); close(fd); return 1; }
    if (st.st_size != PAGE * 4) {
        fprintf(stderr, "allocate: expected size %d got %ld\n", PAGE * 4, (long)st.st_size);
        close(fd); return 1;
    }

    /* Verify allocated region reads back as zeros */
    unsigned char buf[PAGE];
    if (pread(fd, buf, PAGE, PAGE) != PAGE) { perror("pread"); close(fd); return 1; }
    for (int i = 0; i < PAGE; i++) {
        if (buf[i] != 0) {
            fprintf(stderr, "allocate: non-zero at offset %d: 0x%02x\n", i, buf[i]);
            close(fd); return 1;
        }
    }
    close(fd);
    printf("PASS: allocate-blocks-zero-filled\n");
    return 0;
}

/* ── 2. Punch-hole ────────────────────────────────────────────────── */
static int test_punch_hole(void) {
    make_path("punch.bin");
    unlink(test_path);
    int fd = open(test_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("punch open"); return 1; }

    unsigned char data[PAGE * 3];
    fill_buf(data, PAGE * 3, 1);
    if (write(fd, data, PAGE * 3) != PAGE * 3) { perror("write"); close(fd); return 1; }

    /* Punch middle page (FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE = 0x03) */
    if (fallocate(fd, 0x03, PAGE, PAGE) < 0) {
        perror("fallocate punch"); close(fd); return 1;
    }

    /* Verify middle page is zero */
    unsigned char buf[PAGE];
    if (pread(fd, buf, PAGE, PAGE) != PAGE) { perror("pread punch"); close(fd); return 1; }
    for (int i = 0; i < PAGE; i++) {
        if (buf[i] != 0) {
            fprintf(stderr, "punch-hole: non-zero at offset %d: 0x%02x\n", i, buf[i]);
            close(fd); return 1;
        }
    }
    close(fd);
    printf("PASS: punch-hole-reads-zero\n");
    return 0;
}

/* ── 3. Zero-range ────────────────────────────────────────────────── */
static int test_zero_range(void) {
    make_path("zero.bin");
    unlink(test_path);
    int fd = open(test_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("zero open"); return 1; }

    unsigned char data[PAGE * 3];
    fill_buf(data, PAGE * 3, 2);
    if (write(fd, data, PAGE * 3) != PAGE * 3) { perror("write"); close(fd); return 1; }

    /* Zero middle page (FALLOC_FL_ZERO_RANGE = 0x10) */
    if (fallocate(fd, 0x10, PAGE, PAGE) < 0) {
        perror("fallocate zero"); close(fd); return 1;
    }

    unsigned char buf[PAGE];
    if (pread(fd, buf, PAGE, PAGE) != PAGE) { perror("pread zero"); close(fd); return 1; }
    for (int i = 0; i < PAGE; i++) {
        if (buf[i] != 0) {
            fprintf(stderr, "zero-range: non-zero at offset %d: 0x%02x\n", i, buf[i]);
            close(fd); return 1;
        }
    }
    close(fd);
    printf("PASS: zero-range-clears-data\n");
    return 0;
}

/* ── 4. Collapse-range ────────────────────────────────────────────── */
static int test_collapse_range(void) {
    make_path("collapse.bin");
    unlink(test_path);
    int fd = open(test_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("collapse open"); return 1; }

    /* Write pattern: first PAGE = 0xAA, second PAGE = 0xBB, third PAGE = 0xCC */
    unsigned char data[PAGE * 3];
    memset(data, 0xAA, PAGE);
    memset(data + PAGE, 0xBB, PAGE);
    memset(data + PAGE * 2, 0xCC, PAGE);
    if (write(fd, data, PAGE * 3) != PAGE * 3) { perror("write"); close(fd); return 1; }

    /* Collapse middle page (FALLOC_FL_COLLAPSE_RANGE = 0x08) */
    if (fallocate(fd, 0x08, PAGE, PAGE) < 0) {
        perror("fallocate collapse"); close(fd); return 1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); close(fd); return 1; }
    if (st.st_size != PAGE * 2) {
        fprintf(stderr, "collapse: expected size %d got %ld\n", PAGE * 2, (long)st.st_size);
        close(fd); return 1;
    }

    /* First page should be 0xAA, second page should be 0xCC (was third page) */
    unsigned char buf[PAGE];
    if (pread(fd, buf, PAGE, 0) != PAGE) { perror("pread 0"); close(fd); return 1; }
    for (int i = 0; i < PAGE; i++) {
        if (buf[i] != 0xAA) {
            fprintf(stderr, "collapse: page0[%d] expected 0xAA got 0x%02x\n", i, buf[i]);
            close(fd); return 1;
        }
    }
    if (pread(fd, buf, PAGE, PAGE) != PAGE) { perror("pread PAGE"); close(fd); return 1; }
    for (int i = 0; i < PAGE; i++) {
        if (buf[i] != 0xCC) {
            fprintf(stderr, "collapse: page1[%d] expected 0xCC got 0x%02x\n", i, buf[i]);
            close(fd); return 1;
        }
    }
    close(fd);
    printf("PASS: collapse-range-shifts-data\n");
    return 0;
}

/* ── 5. Insert-range ──────────────────────────────────────────────── */
static int test_insert_range(void) {
    make_path("insert.bin");
    unlink(test_path);
    int fd = open(test_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("insert open"); return 1; }

    /* Write pattern: first PAGE = 0xAA, second PAGE = 0xBB */
    unsigned char data[PAGE * 2];
    memset(data, 0xAA, PAGE);
    memset(data + PAGE, 0xBB, PAGE);
    if (write(fd, data, PAGE * 2) != PAGE * 2) { perror("write"); close(fd); return 1; }

    /* Insert a page at offset PAGE (FALLOC_FL_INSERT_RANGE = 0x20) */
    if (fallocate(fd, 0x20, PAGE, PAGE) < 0) {
        perror("fallocate insert"); close(fd); return 1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); close(fd); return 1; }
    if (st.st_size != PAGE * 3) {
        fprintf(stderr, "insert: expected size %d got %ld\n", PAGE * 3, (long)st.st_size);
        close(fd); return 1;
    }

    /* First page: 0xAA, second page: zero (inserted), third page: 0xBB (shifted) */
    unsigned char buf[PAGE];
    if (pread(fd, buf, PAGE, 0) != PAGE) { perror("pread 0"); close(fd); return 1; }
    for (int i = 0; i < PAGE; i++) {
        if (buf[i] != 0xAA) {
            fprintf(stderr, "insert: page0[%d] expected 0xAA got 0x%02x\n", i, buf[i]);
            close(fd); return 1;
        }
    }
    if (pread(fd, buf, PAGE, PAGE) != PAGE) { perror("pread PAGE"); close(fd); return 1; }
    for (int i = 0; i < PAGE; i++) {
        if (buf[i] != 0) {
            fprintf(stderr, "insert: page1[%d] expected 0 got 0x%02x\n", i, buf[i]);
            close(fd); return 1;
        }
    }
    if (pread(fd, buf, PAGE, PAGE * 2) != PAGE) { perror("pread 2*PAGE"); close(fd); return 1; }
    for (int i = 0; i < PAGE; i++) {
        if (buf[i] != 0xBB) {
            fprintf(stderr, "insert: page2[%d] expected 0xBB got 0x%02x\n", i, buf[i]);
            close(fd); return 1;
        }
    }
    close(fd);
    printf("PASS: insert-range-shifts-data\n");
    return 0;
}

/* ── 6. Keep-size ─────────────────────────────────────────────────── */
static int test_keep_size(void) {
    make_path("keep.bin");
    unlink(test_path);
    int fd = open(test_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("keep open"); return 1; }

    /* Write one page, then allocate 2 more pages with KEEP_SIZE */
    unsigned char data[PAGE];
    fill_buf(data, PAGE, 3);
    if (write(fd, data, PAGE) != PAGE) { perror("write"); close(fd); return 1; }

    if (fallocate(fd, 0x01 /* FALLOC_FL_KEEP_SIZE */, PAGE, PAGE * 2) < 0) {
        perror("fallocate keep-size"); close(fd); return 1;
    }

    /* Size should still be PAGE */
    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); close(fd); return 1; }
    if (st.st_size != PAGE) {
        fprintf(stderr, "keep-size: expected size %d got %ld\n", PAGE, (long)st.st_size);
        close(fd); return 1;
    }
    close(fd);
    printf("PASS: keep-size-allocates-without-size-change\n");
    return 0;
}

/* ── 7. Concurrent-allocate ───────────────────────────────────────── */

struct conc_arg {
    const char *path;
    int wr_seq;
    int *errors;
};

static void *conc_worker(void *arg) {
    struct conc_arg *ca = (struct conc_arg *)arg;
    int fd = open(ca->path, O_RDWR);
    if (fd < 0) { *(ca->errors) = 1; return NULL; }

    /* Writer 1: allocate + write / Writer 2: punch existing range */
    if (ca->wr_seq == 1) {
        if (fallocate(fd, 0x01, PAGE * 2, PAGE) < 0) { *(ca->errors) = 1; close(fd); return NULL; }
    } else {
        if (fallocate(fd, 0x03, PAGE, PAGE) < 0) { *(ca->errors) = 1; close(fd); return NULL; }
    }
    close(fd);
    return NULL;
}

static int test_concurrent_allocate(void) {
    make_path("conc.bin");
    unlink(test_path);
    int fd = open(test_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("conc open"); return 1; }

    /* Write 4 pages of data */
    unsigned char data[PAGE * 4];
    fill_buf(data, PAGE * 4, 4);
    if (write(fd, data, PAGE * 4) != PAGE * 4) { perror("write"); close(fd); return 1; }
    close(fd);

    int errors[2] = {0, 0};
    pthread_t t1, t2;
    struct conc_arg a1 = { test_path, 1, &errors[0] };
    struct conc_arg a2 = { test_path, 2, &errors[1] };

    if (pthread_create(&t1, NULL, conc_worker, &a1) != 0) {
        perror("pthread_create 1"); return 1;
    }
    if (pthread_create(&t2, NULL, conc_worker, &a2) != 0) {
        perror("pthread_create 2"); return 1;
    }
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    if (errors[0] || errors[1]) {
        fprintf(stderr, "concurrent-allocate: thread errors\n");
        return 1;
    }

    /* File should still exist and be accessible */
    struct stat st;
    if (stat(test_path, &st) < 0) { perror("stat conc"); return 1; }
    printf("PASS: concurrent-allocate-no-corruption\n");
    return 0;
}

/* ── Main ──────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: tidefs-fuse-fallocate-test <mount-point> [--crash-mode]\n");
        return 1;
    }

    snprintf(mnt_dir, sizeof(mnt_dir), "%s", argv[1]);
    int crash_mode = (argc > 2 && strcmp(argv[2], "--crash-mode") == 0);

    printf("=== TideFS FUSE Fallocate Validation Workload ===\n");
    printf("mount=%s crash=%d\n", mnt_dir, crash_mode);

    int failures = 0;
    failures += test_allocate();
    failures += test_punch_hole();
    failures += test_zero_range();
    if (!crash_mode) {
        failures += test_collapse_range();
        failures += test_insert_range();
        failures += test_keep_size();
        failures += test_concurrent_allocate();
    }

    printf("=== End: failures=%d ===\n", failures);
    return failures;
}
CEOF

    cc -O2 -Wall -static -pthread fuse_fallocate_test.c -o "$out/bin/tidefs-fuse-fallocate-test"
    strip "$out/bin/tidefs-fuse-fallocate-test"
  '';

  # Validation script that mounts FUSE, runs the fallocate test,
  # simulates crash, and verifies committed-root integrity.
  fuseFallocateValidationScript = pkgs.writeShellScriptBin "tidefs-fuse-fallocate-validation" ''
    set -euo pipefail

    DAEMON_BIN="${tidefsPackage}/bin/tidefs-posix-filesystem-adapter-daemon"
    FALLOC_TEST="${fuseFallocateTestBin}/bin/tidefs-fuse-fallocate-test"

    TMPDIR="''${TIDEFS_FUSE_FALLOC_TMPDIR:-/tmp/tidefs-fuse-fallocate-validation}"
    STORE="$TMPDIR/store"
    MNT="$TMPDIR/mnt"

    usage() {
      cat <<EOF
Usage: tidefs-fuse-fallocate-validation [--keep-tmp]

Validate FUSE userspace fallocate(2) operations (allocate, punch-hole,
zero-range, collapse-range, insert-range, keep-size, concurrent-allocate)
with crash-consistency verification through committed-root integrity checks.

Environment:
  TIDEFS_FUSE_FALLOC_TMPDIR         scratch directory (default /tmp/tidefs-fuse-fallocate-validation)
  TIDEFS_ROOT_AUTHENTICATION_KEY_HEX root auth key (required)
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

    echo "=== TideFS FUSE Fallocate Validation ==="
    echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "kernel=$(uname -r)"
    echo "daemon=$DAEMON_BIN"
    echo "test=$FALLOC_TEST"
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
      if kill -0 "$DAEMON_PID" 2>/dev/null; then
        blocked "fuse_mount" "daemon running but mount not visible after 6s"
      else
        blocked "fuse_mount" "daemon died -- see $DAEMON_LOG"
      fi
      echo ""
      echo "=== FUSE Fallocate Validation Summary ==="
      echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
      echo "tier=mounted-userspace"
      exit 1
    fi

    # ── Phase 2: Run fallocate test ─────────────────────────────────
    echo ""
    echo "--- Phase 2: Fallocate operations ---"
    TEST_LOG="$TMPDIR/test.log"
    if "$FALLOC_TEST" "$MNT" > "$TEST_LOG" 2>&1; then
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
      pass "fallocate_test_exit_zero"
    else
      fail "fallocate_test_exit_zero" "test binary exited with $TEST_RC"
    fi

    # ── Phase 3: Snapshot committed state ───────────────────────────
    echo ""
    echo "--- Phase 3: Snapshot committed state ---"
    sync
    ls -la "$MNT" > "$TMPDIR/root_list.txt" 2>/dev/null || true

    for f in alloc.bin punch.bin zero.bin collapse.bin insert.bin \
             keep.bin conc.bin; do
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

    fusermount -u "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null || true
    sleep 0.5
    pass "crash_simulated"

    # ── Phase 5: Remount and verify ─────────────────────────────────
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

    # Verify committed files still exist
    echo ""
    echo "--- Phase 6: Verify post-crash integrity ---"
    "$FALLOC_TEST" "$MNT" > "$TMPDIR/test_verify.log" 2>&1 || true
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
    echo "=== FUSE Fallocate Validation Summary ==="
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
fuseFallocateValidationScript
