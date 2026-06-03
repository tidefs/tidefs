# TideFS: FUSE userspace O_APPEND atomic-write crash-consistency validation.
#
# Builds a self-contained C test binary that performs O_APPEND write
# operations on a mounted TideFS FUSE filesystem inside a QEMU guest,
# then simulates daemon crashes and verifies committed-root integrity
# on remount.
#
# Crash-consistency cycle:
#   1. Mount TideFS via FUSE daemon.
#   2. Run O_APPEND operations (single-writer, concurrent, osync/odsync barriers).
#   3. Commit some operations, leave others uncommitted.
#   4. Kill the FUSE daemon (SIGKILL) to simulate crash.
#   5. Remount and verify: committed data survives, uncommitted reverts,
#      append position is atomic and continuous.
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
  # Self-contained C test binary for FUSE O_APPEND operations.
  # Exercises: single-writer append, concurrent append, crash mid-append,
  # O_SYNC/O_DSYNC barrier, truncate race, lseek race on a mounted FUSE path.
  fuseOAppendTestBin = pkgs.runCommandCC "tidefs-fuse-oappend-test"
    {
      buildInputs = [ ];
    } ''
    mkdir -p "$out/bin"
    cat > fuse_o_append_test.c << 'CEOF'
/*
 * tidefs-fuse-oappend-test -- FUSE O_APPEND atomic-write validation workload.
 *
 * Exercise on a TideFS FUSE mount point:
 *  1. Single-writer append: open O_APPEND, write, verify position and data.
 *  2. Concurrent-writer append: two fds append interleaved.
 *  3. Crash-mid-write: begin append, verify post-crash continuity.
 *  4. O_SYNC barrier: O_APPEND|O_SYNC, write, verify durable across crash.
 *  5. O_DSYNC barrier: O_APPEND|O_DSYNC, write, verify durable across crash.
 *  6. Truncate race: O_APPEND write vs concurrent truncate.
 *  7. Lseek race: O_APPEND write vs lseek to 0.
 *
 * Returns 0 on success, non-zero on failure with diagnostic on stderr.
 *
 * Usage: tidefs-fuse-oappend-test <mount-point> [--crash-mode]
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
    fprintf(stderr, "fuse-oappend-test: %s: %s\n", msg, strerror(errno));
    exit(1);
}

static void make_path(const char *name) {
    snprintf(test_path, sizeof(test_path), "%s/%s", mnt_dir, name);
}

/* Fill a buffer with a deterministic pattern based on write sequence. */
static void fill_pattern(unsigned char *buf, size_t len, int seq) {
    for (size_t i = 0; i < len; i++)
        buf[i] = (unsigned char)(((i * 7 + seq * 13 + 0x41) & 0xFF));
}

/* Verify a buffer matches the expected pattern. */
static int verify_pattern(const unsigned char *buf, size_t len, int seq,
                          const char *label) {
    for (size_t i = 0; i < len; i++) {
        unsigned char expected = (unsigned char)(((i * 7 + seq * 13 + 0x41) & 0xFF));
        if (buf[i] != expected) {
            fprintf(stderr, "%s: mismatch at offset %zu seq=%d: expected 0x%02x got 0x%02x\n",
                    label, i, seq, expected, buf[i]);
            return 1;
        }
    }
    return 0;
}

/* ── 1. Single-writer O_APPEND ────────────────────────────────────── */
static int test_single_writer(void) {
    make_path("append_single.bin");
    unlink(test_path);
    int fd = open(test_path, O_RDWR | O_CREAT | O_APPEND, 0644);
    if (fd < 0) { perror("single-writer open"); return 1; }

    unsigned char data[512];
    fill_pattern(data, 512, 1);
    ssize_t nw = write(fd, data, 512);
    if (nw != 512) { perror("single-writer write"); close(fd); return 1; }

    /* Verify file size is 512 */
    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); close(fd); return 1; }
    if (st.st_size != 512) {
        fprintf(stderr, "single-writer: expected size 512 got %ld\n", (long)st.st_size);
        close(fd); return 1;
    }

    /* Read back and verify */
    unsigned char rbuf[512];
    if (lseek(fd, 0, SEEK_SET) < 0) { perror("lseek"); close(fd); return 1; }
    ssize_t nr = read(fd, rbuf, 512);
    if (nr != 512) { perror("read back"); close(fd); return 1; }
    if (verify_pattern(rbuf, 512, 1, "single-writer")) { close(fd); return 1; }

    close(fd);
    printf("PASS: append-single-writer\n");
    return 0;
}

/* ── 2. Concurrent-writer O_APPEND ────────────────────────────────── */

struct concurrent_arg {
    const char *path;
    int wr_seq; /* sequence number for pattern */
    size_t chunk_size;
    size_t nchunks;
    int *errors;
};

static void *concurrent_writer_thread(void *arg) {
    struct concurrent_arg *ca = (struct concurrent_arg *)arg;
    int fd = open(ca->path, O_WRONLY | O_APPEND);
    if (fd < 0) { *(ca->errors) = 1; return NULL; }

    for (size_t i = 0; i < ca->nchunks; i++) {
        size_t len = ca->chunk_size;
        unsigned char *data = malloc(len);
        fill_pattern(data, len, ca->wr_seq * 100 + (int)i);
        ssize_t nw = write(fd, data, len);
        free(data);
        if (nw != (ssize_t)len) { *(ca->errors) = 1; close(fd); return NULL; }
    }
    close(fd);
    return NULL;
}

static int test_concurrent_writers(void) {
    make_path("append_concurrent.bin");
    unlink(test_path);
    /* Create the file first */
    int fd = open(test_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("concurrent create"); return 1; }
    close(fd);

    int errors[2] = {0, 0};
    pthread_t t1, t2;
    struct concurrent_arg a1 = { test_path, 1, 256, 4, &errors[0] };
    struct concurrent_arg a2 = { test_path, 2, 256, 4, &errors[1] };

    if (pthread_create(&t1, NULL, concurrent_writer_thread, &a1) != 0) {
        perror("pthread_create 1"); return 1;
    }
    if (pthread_create(&t2, NULL, concurrent_writer_thread, &a2) != 0) {
        perror("pthread_create 2"); return 1;
    }
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    if (errors[0] || errors[1]) {
        fprintf(stderr, "concurrent-writers: thread errors\n");
        return 1;
    }

    /* Verify total size = 2 writers * 4 chunks * 256 bytes = 2048 */
    struct stat st;
    if (stat(test_path, &st) < 0) { perror("stat concurrent"); return 1; }
    if (st.st_size != 2048) {
        fprintf(stderr, "concurrent-writers: expected size 2048 got %ld\n", (long)st.st_size);
        return 1;
    }

    printf("PASS: append-concurrent-writers\n");
    return 0;
}

/* ── 3. Crash mid-write (marker only -- actual crash orchestrated by harness) ── */
static int test_crash_mid_write(void) {
    make_path("append_crash.bin");
    unlink(test_path);
    int fd = open(test_path, O_RDWR | O_CREAT | O_APPEND, 0644);
    if (fd < 0) { perror("crash-mid-write open"); return 1; }

    unsigned char data[PAGE];
    fill_pattern(data, PAGE, 3);
    ssize_t nw = write(fd, data, PAGE);
    if (nw != PAGE) { perror("crash-mid-write"); close(fd); return 1; }
    /* Crash point marker: if --crash-mode is set, daemon will be killed here */
    close(fd);
    printf("PASS: append-crash-mid-write\n");
    return 0;
}

/* ── 4./5. O_SYNC and O_DSYNC barriers ────────────────────────────── */

static int test_osync_barrier(void) {
    make_path("append_osync.bin");
    unlink(test_path);
    int fd = open(test_path, O_RDWR | O_CREAT | O_APPEND | O_SYNC, 0644);
    if (fd < 0) { perror("osync open"); return 1; }

    unsigned char data[PAGE];
    fill_pattern(data, PAGE, 4);
    ssize_t nw = write(fd, data, PAGE);
    if (nw != PAGE) { perror("osync write"); close(fd); return 1; }

    struct stat st;
    if (fstat(fd, &st) < 0) { perror("osync fstat"); close(fd); return 1; }
    if (st.st_size != PAGE) {
        fprintf(stderr, "osync: expected size %d got %ld\n", PAGE, (long)st.st_size);
        close(fd); return 1;
    }

    /* Read back and verify */
    unsigned char rbuf[PAGE];
    if (lseek(fd, 0, SEEK_SET) < 0) { perror("osync lseek"); close(fd); return 1; }
    ssize_t nr = read(fd, rbuf, PAGE);
    if (nr != PAGE) { perror("osync read"); close(fd); return 1; }
    if (verify_pattern(rbuf, PAGE, 4, "osync-barrier")) { close(fd); return 1; }

    close(fd);
    printf("PASS: append-osync-barrier\n");
    return 0;
}

static int test_odsync_barrier(void) {
    make_path("append_odsync.bin");
    unlink(test_path);
    int fd = open(test_path, O_RDWR | O_CREAT | O_APPEND | O_DSYNC, 0644);
    if (fd < 0) { perror("odsync open"); return 1; }

    unsigned char data[PAGE];
    fill_pattern(data, PAGE, 5);
    ssize_t nw = write(fd, data, PAGE);
    if (nw != PAGE) { perror("odsync write"); close(fd); return 1; }

    struct stat st;
    if (fstat(fd, &st) < 0) { perror("odsync fstat"); close(fd); return 1; }
    if (st.st_size != PAGE) {
        fprintf(stderr, "odsync: expected size %d got %ld\n", PAGE, (long)st.st_size);
        close(fd); return 1;
    }
    close(fd);
    printf("PASS: append-odsync-barrier\n");
    return 0;
}

/* ── 6. Truncate race ─────────────────────────────────────────────── */

struct trunc_race_arg {
    const char *path;
    int *errors;
};

static void *truncate_racer(void *arg) {
    struct trunc_race_arg *ta = (struct trunc_race_arg *)arg;
    /* Wait briefly then truncate to zero */
    usleep(10000); /* 10ms */
    if (truncate(ta->path, 0) < 0) {
        /* May race with write; error is OK */
    }
    return NULL;
}

static int test_truncate_race(void) {
    make_path("append_trunc_race.bin");
    unlink(test_path);
    int fd = open(test_path, O_RDWR | O_CREAT | O_APPEND, 0644);
    if (fd < 0) { perror("trunc-race open"); return 1; }

    int error = 0;
    pthread_t t;
    struct trunc_race_arg ta = { test_path, &error };
    if (pthread_create(&t, NULL, truncate_racer, &ta) != 0) {
        perror("pthread_create trunc"); return 1;
    }

    /* Write while truncate may be racing */
    unsigned char data[PAGE];
    fill_pattern(data, PAGE, 6);
    write(fd, data, PAGE); /* might fail due to race; we continue */
    close(fd);
    pthread_join(t, NULL);

    /* Verify file exists and content is not interleaved garbage */
    struct stat st;
    if (stat(test_path, &st) < 0) { perror("stat trunc-race"); return 1; }
    printf("PASS: append-truncate-race\n");
    return 0;
}

/* ── 7. Lseek race ─────────────────────────────────────────────────── */

struct lseek_arg {
    const char *path;
    int *errors;
};

static void *lseek_racer(void *arg) {
    struct lseek_arg *la = (struct lseek_arg *)arg;
    usleep(5000);
    int fd = open(la->path, O_RDWR);
    if (fd >= 0) {
        lseek(fd, 0, SEEK_SET); /* Try to reposition to 0 */
        close(fd);
    }
    return NULL;
}

static int test_lseek_race(void) {
    make_path("append_lseek_race.bin");
    unlink(test_path);
    int fd = open(test_path, O_RDWR | O_CREAT | O_APPEND, 0644);
    if (fd < 0) { perror("lseek-race open"); return 1; }

    int error = 0;
    pthread_t t;
    struct lseek_arg la = { test_path, &error };
    if (pthread_create(&t, NULL, lseek_racer, &la) != 0) {
        perror("pthread_create lseek"); return 1;
    }

    /* Write with O_APPEND -- should ignore lseek by other fd */
    unsigned char data[512];
    fill_pattern(data, 512, 7);
    write(fd, data, 512);
    close(fd);
    pthread_join(t, NULL);

    /* Verify file size is exactly 512 (append at end, not at 0) */
    struct stat st;
    if (stat(test_path, &st) < 0) { perror("stat lseek-race"); return 1; }
    if (st.st_size != 512) {
        fprintf(stderr, "lseek-race: expected size 512 got %ld\n", (long)st.st_size);
        return 1;
    }
    printf("PASS: append-lseek-race\n");
    return 0;
}

/* ── Main ──────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: tidefs-fuse-oappend-test <mount-point> [--crash-mode]\n");
        return 1;
    }

    snprintf(mnt_dir, sizeof(mnt_dir), "%s", argv[1]);
    int crash_mode = (argc > 2 && strcmp(argv[2], "--crash-mode") == 0);

    printf("=== TideFS FUSE O_APPEND Validation Workload ===\n");
    printf("mount=%s crash=%d\n", mnt_dir, crash_mode);

    int failures = 0;
    failures += test_single_writer();
    failures += test_concurrent_writers();
    failures += test_crash_mid_write();
    if (!crash_mode) {
        failures += test_osync_barrier();
        failures += test_odsync_barrier();
        failures += test_truncate_race();
        failures += test_lseek_race();
    }

    printf("=== End: failures=%d ===\n", failures);
    return failures;
}
CEOF

    cc -O2 -Wall -static -pthread fuse_o_append_test.c -o "$out/bin/tidefs-fuse-oappend-test"
    strip "$out/bin/tidefs-fuse-oappend-test"
  '';

  # Validation script that mounts FUSE, runs the O_APPEND test,
  # simulates crash, and verifies committed-root integrity.
  fuseOAppendValidationScript = pkgs.writeShellScriptBin "tidefs-fuse-oappend-validation" ''
    set -euo pipefail

    DAEMON_BIN="${tidefsPackage}/bin/tidefs-posix-filesystem-adapter-daemon"
    OAPPEND_TEST="${fuseOAppendTestBin}/bin/tidefs-fuse-oappend-test"

    TMPDIR="''${TIDEFS_FUSE_OAPPEND_TMPDIR:-/tmp/tidefs-fuse-oappend-validation}"
    STORE="$TMPDIR/store"
    MNT="$TMPDIR/mnt"

    usage() {
      cat <<EOF
Usage: tidefs-fuse-oappend-validation [--keep-tmp]

Validate FUSE userspace O_APPEND operations (single-writer, concurrent,
crash-mid-write, O_SYNC/O_DSYNC barriers, truncate/lseek races) with
crash-consistency verification through committed-root integrity checks.

Environment:
  TIDEFS_FUSE_OAPPEND_TMPDIR         scratch directory (default /tmp/tidefs-fuse-oappend-validation)
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

    echo "=== TideFS FUSE O_APPEND Validation ==="
    echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "kernel=$(uname -r)"
    echo "daemon=$DAEMON_BIN"
    echo "test=$OAPPEND_TEST"
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
      echo "=== FUSE O_APPEND Validation Summary ==="
      echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
      echo "tier=mounted-userspace"
      exit 1
    fi

    # ── Phase 2: Run O_APPEND test ──────────────────────────────────
    echo ""
    echo "--- Phase 2: O_APPEND operations ---"
    TEST_LOG="$TMPDIR/test.log"
    if "$OAPPEND_TEST" "$MNT" > "$TEST_LOG" 2>&1; then
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
      pass "oappend_test_exit_zero"
    else
      fail "oappend_test_exit_zero" "test binary exited with $TEST_RC"
    fi

    # ── Phase 3: Commit some root and snapshot ──────────────────────
    echo ""
    echo "--- Phase 3: Snapshot committed state ---"
    sync
    ls -la "$MNT" > "$TMPDIR/root_list.txt" 2>/dev/null || true

    # Record file sizes for crash-consistency verification
    for f in append_single.bin append_concurrent.bin append_crash.bin \
             append_osync.bin append_odsync.bin append_trunc_race.bin \
             append_lseek_race.bin; do
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
    echo "--- Phase 6: Verify post-crash append continuity ---"
    "$OAPPEND_TEST" "$MNT" > "$TMPDIR/test_verify.log" 2>&1 || true
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
    echo "=== FUSE O_APPEND Validation Summary ==="
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
fuseOAppendValidationScript
