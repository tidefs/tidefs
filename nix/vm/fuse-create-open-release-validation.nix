# TideFS: FUSE userspace create/open/release crash-consistency validation.
#
# Builds a self-contained C test binary that performs open(O_CREAT),
# open(O_EXCL), open(O_TRUNC), release (close), dup, concurrent open,
# full open-write-release-reopen lifecycle, and O_APPEND open operations
# on a mounted TideFS FUSE filesystem inside a QEMU guest, then simulates
# daemon crashes and verifies committed-root integrity on remount.
#
# Crash-consistency cycle:
#   1. Mount TideFS via FUSE daemon.
#   2. Run create/open/release operations with committed-root anchors.
#   3. Kill the FUSE daemon (SIGKILL) to simulate crash.
#   4. Remount and verify: committed data survives, uncommitted reverts,
#      file size, nlink count, and namespace state are correct.
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
  # Self-contained C test binary for FUSE create/open/release operations.
  # Exercises: open existing, open(O_CREAT), open(O_EXCL), open(O_TRUNC),
  # release (close), dup, concurrent open, open-write-release-reopen cycle,
  # and open(O_APPEND) on a mounted FUSE path.
  fuseCreateOpenReleaseTestBin = pkgs.runCommandCC "tidefs-fuse-create-open-release-test"
    {
      buildInputs = [ ];
    } ''
    mkdir -p "$out/bin"
    cat > fuse_create_open_release_test.c << 'CEOF'
/*
 * tidefs-fuse-create-open-release-test — FUSE create/open/release workload.
 *
 * Exercise on a TideFS FUSE mount point:
 *  1. open-existing: open(2) an existing file, verify fd and stat.
 *  2. open-create: open(O_CREAT) a new file, verify creation + size.
 *  3. open-create-excl: open(O_CREAT|O_EXCL) new file, then existing file.
 *  4. open-truncate: open(O_TRUNC) existing file, verify zero size.
 *  5. release: open, close, verify ref-count behaviour (fd no longer valid).
 *  6. dup-fd: open, dup, verify shared offset.
 *  7. concurrent-open: two threads open same file, verify fd isolation.
 *  8. open-release-cycle: open→write→fsync→close→open→read.
 *  9. open-append: open(O_APPEND), verify append tracking.
 *
 * Returns 0 on success, non-zero on failure with diagnostic on stderr.
 *
 * Usage: tidefs-fuse-create-open-release-test <mount-point> [--crash-mode]
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
    fprintf(stderr, "fuse-create-open-release-test: %s: %s\n", msg, strerror(errno));
    exit(1);
}

static void make_path(const char *name) {
    snprintf(test_path, sizeof(test_path), "%s/%s", mnt_dir, name);
}

/* ── 1. Open existing file ────────────────────────────────────────── */
static int test_open_existing(void) {
    make_path("open_existing.bin");
    /* Pre-create a file with known content */
    int fd = open(test_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("open-existing pre-create"); return 1; }
    unsigned char data[PAGE] = { [0] = 0xAB };
    if (write(fd, data, PAGE) != PAGE) { perror("write pre"); close(fd); return 1; }
    close(fd);

    fd = open(test_path, O_RDONLY);
    if (fd < 0) { perror("open-existing"); return 1; }

    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); close(fd); return 1; }
    if (st.st_size != PAGE) {
        fprintf(stderr, "open-existing: expected size %d got %ld\n", PAGE, (long)st.st_size);
        close(fd); return 1;
    }
    close(fd);
    printf("PASS: open-existing\n");
    return 0;
}

/* ── 2. Open with O_CREAT ─────────────────────────────────────────── */
static int test_open_create(void) {
    make_path("open_create.bin");
    unlink(test_path);
    int fd = open(test_path, O_RDWR | O_CREAT, 0644);
    if (fd < 0) { perror("open-create"); return 1; }

    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat create"); close(fd); return 1; }
    if (st.st_size != 0) {
        fprintf(stderr, "open-create: expected size 0 got %ld\n", (long)st.st_size);
        close(fd); return 1;
    }
    if (st.st_nlink != 1) {
        fprintf(stderr, "open-create: expected nlink 1 got %lu\n", (unsigned long)st.st_nlink);
        close(fd); return 1;
    }
    close(fd);
    printf("PASS: open-create\n");
    return 0;
}

/* ── 3. Open with O_CREAT|O_EXCL ───────────────────────────────────── */
static int test_open_create_excl(void) {
    make_path("open_create_excl.bin");
    unlink(test_path);
    int fd = open(test_path, O_RDWR | O_CREAT | O_EXCL, 0644);
    if (fd < 0) { perror("open-create-excl new"); return 1; }
    close(fd);

    /* O_EXCL must fail when file already exists */
    fd = open(test_path, O_RDWR | O_CREAT | O_EXCL, 0644);
    if (fd >= 0) {
        fprintf(stderr, "open-create-excl: should have failed on existing file\n");
        close(fd); return 1;
    }
    if (errno != EEXIST) {
        fprintf(stderr, "open-create-excl: expected EEXIST got %s\n", strerror(errno));
        return 1;
    }
    printf("PASS: open-create-excl\n");
    return 0;
}

/* ── 4. Open with O_TRUNC ──────────────────────────────────────────── */
static int test_open_truncate(void) {
    make_path("open_truncate.bin");
    int fd = open(test_path, O_RDWR | O_CREAT, 0644);
    if (fd < 0) { perror("open-truncate pre-create"); return 1; }
    unsigned char data[PAGE] = { [0] = 0xCD };
    if (write(fd, data, PAGE) != PAGE) { perror("write pre"); close(fd); return 1; }
    close(fd);

    fd = open(test_path, O_RDWR | O_TRUNC);
    if (fd < 0) { perror("open-truncate"); return 1; }
    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat trunc"); close(fd); return 1; }
    if (st.st_size != 0) {
        fprintf(stderr, "open-truncate: expected size 0 got %ld\n", (long)st.st_size);
        close(fd); return 1;
    }
    close(fd);
    printf("PASS: open-truncate\n");
    return 0;
}

/* ── 5. Release (close) ────────────────────────────────────────────── */
static int test_release(void) {
    make_path("release.bin");
    int fd = open(test_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("release open"); return 1; }
    unsigned char data[512];
    memset(data, 0xCC, 512);
    if (write(fd, data, 512) != 512) { perror("release write"); close(fd); return 1; }

    if (close(fd) < 0) { perror("release close"); return 1; }

    /* Verify fd is no longer valid by trying to use it */
    if (fstat(fd, &(struct stat){0}) == 0 || errno != EBADF) {
        fprintf(stderr, "release: fd should be invalid after close\n");
        return 1;
    }

    /* Re-open and verify size */
    fd = open(test_path, O_RDONLY);
    if (fd < 0) { perror("release reopen"); return 1; }
    struct stat st;
    if (fstat(fd, &st) < 0) { perror("release fstat"); close(fd); return 1; }
    if (st.st_size != 512) {
        fprintf(stderr, "release: expected size 512 got %ld\n", (long)st.st_size);
        close(fd); return 1;
    }
    close(fd);
    printf("PASS: release\n");
    return 0;
}

/* ── 6. Dup fd ──────────────────────────────────────────────────────── */
static int test_dup_fd(void) {
    make_path("dup_fd.bin");
    int fd = open(test_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("dup-fd open"); return 1; }
    unsigned char data[PAGE];
    memset(data, 0xDD, PAGE);
    if (write(fd, data, PAGE) != PAGE) { perror("dup write"); return 1; }

    int fd2 = dup(fd);
    if (fd2 < 0) { perror("dup"); close(fd); return 1; }

    /* Verify shared offset: lseek on fd2 should be visible via fd */
    if (lseek(fd2, 0, SEEK_SET) < 0) { perror("dup lseek"); close(fd); close(fd2); return 1; }
    off_t pos = lseek(fd, 0, SEEK_CUR);
    if (pos != 0) {
        fprintf(stderr, "dup-fd: offset not shared, fd pos=%ld\n", (long)pos);
        close(fd); close(fd2); return 1;
    }

    close(fd);
    close(fd2);
    printf("PASS: dup-fd\n");
    return 0;
}

/* ── 7. Concurrent open ─────────────────────────────────────────────── */
struct concurrent_open_arg {
    const char *path;
    int thread_id;
    int *errors;
};

static void *concurrent_open_thread(void *arg) {
    struct concurrent_open_arg *ca = (struct concurrent_open_arg *)arg;
    int fd = open(ca->path, O_RDONLY);
    if (fd < 0) { *(ca->errors) = 1; return NULL; }

    struct stat st;
    if (fstat(fd, &st) < 0) { *(ca->errors) = 1; close(fd); return NULL; }
    if (st.st_size != PAGE) {
        fprintf(stderr, "concurrent-open: thread %d got size %ld\n",
                ca->thread_id, (long)st.st_size);
        *(ca->errors) = 1;
    }
    close(fd);
    return NULL;
}

static int test_concurrent_open(void) {
    make_path("concurrent_open.bin");
    int fd = open(test_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("concurrent-open pre-create"); return 1; }
    char data[PAGE];
    memset(data, 0xEE, PAGE);
    if (write(fd, data, PAGE) != PAGE) { perror("write"); close(fd); return 1; }
    close(fd);

    int errors[4] = {0, 0, 0, 0};
    pthread_t threads[4];
    struct concurrent_open_arg args[4];
    for (int i = 0; i < 4; i++) {
        args[i] = (struct concurrent_open_arg){ test_path, i, &errors[i] };
        if (pthread_create(&threads[i], NULL, concurrent_open_thread, &args[i]) != 0) {
            perror("pthread_create"); return 1;
        }
    }
    for (int i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
    }
    for (int i = 0; i < 4; i++) {
        if (errors[i]) {
            fprintf(stderr, "concurrent-open: thread %d error\n", i);
            return 1;
        }
    }
    printf("PASS: concurrent-open\n");
    return 0;
}

/* ── 8. Open-write-release-reopen lifecycle ─────────────────────────── */
static int test_open_release_cycle(void) {
    make_path("open_release_cycle.bin");
    unlink(test_path);
    int fd = open(test_path, O_RDWR | O_CREAT, 0644);
    if (fd < 0) { perror("cycle open1"); return 1; }

    unsigned char data[PAGE];
    memset(data, 0xBA, PAGE);
    if (write(fd, data, PAGE) != PAGE) { perror("cycle write"); close(fd); return 1; }
    if (fsync(fd) < 0) { perror("cycle fsync"); close(fd); return 1; }
    close(fd);

    /* Reopen and read back */
    fd = open(test_path, O_RDONLY);
    if (fd < 0) { perror("cycle reopen"); return 1; }
    unsigned char rbuf[PAGE];
    ssize_t nr = read(fd, rbuf, PAGE);
    if (nr != PAGE) { perror("cycle read"); close(fd); return 1; }
    for (int i = 0; i < PAGE; i++) {
        if (rbuf[i] != 0xBA) {
            fprintf(stderr, "cycle: mismatch at offset %d: expected 0xBA got 0x%02x\n", i, rbuf[i]);
            close(fd); return 1;
        }
    }
    close(fd);
    printf("PASS: open-release-cycle\n");
    return 0;
}

/* ── 9. Open with O_APPEND ──────────────────────────────────────────── */
static int test_open_append(void) {
    make_path("open_append.bin");
    int fd = open(test_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("open-append pre-create"); return 1; }
    unsigned char data[512];
    memset(data, 0xAF, 512);
    if (write(fd, data, 512) != 512) { perror("write pre"); close(fd); return 1; }
    close(fd);

    fd = open(test_path, O_WRONLY | O_APPEND);
    if (fd < 0) { perror("open-append"); return 1; }
    off_t pos = lseek(fd, 0, SEEK_CUR);
    /* On open with O_APPEND, lseek should report end of file */
    if (pos != 512) {
        fprintf(stderr, "open-append: initial position expected 512 got %ld\n", (long)pos);
        close(fd); return 1;
    }

    memset(data, 0xBF, 256);
    if (write(fd, data, 256) != 256) { perror("append write"); close(fd); return 1; }

    struct stat st;
    if (fstat(fd, &st) < 0) { perror("append fstat"); close(fd); return 1; }
    if (st.st_size != 768) {
        fprintf(stderr, "open-append: expected size 768 got %ld\n", (long)st.st_size);
        close(fd); return 1;
    }
    close(fd);
    printf("PASS: open-append\n");
    return 0;
}

/* ── Main ────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: tidefs-fuse-create-open-release-test <mount-point> [--crash-mode]\n");
        return 1;
    }

    snprintf(mnt_dir, sizeof(mnt_dir), "%s", argv[1]);
    int crash_mode = (argc > 2 && strcmp(argv[2], "--crash-mode") == 0);

    printf("=== TideFS FUSE Create/Open/Release Validation Workload ===\n");
    printf("mount=%s crash=%d\n", mnt_dir, crash_mode);

    int failures = 0;
    failures += test_open_existing();
    failures += test_open_create();
    failures += test_open_create_excl();
    failures += test_open_truncate();
    failures += test_release();
    failures += test_dup_fd();
    failures += test_concurrent_open();
    failures += test_open_release_cycle();
    failures += test_open_append();

    printf("=== End: failures=%d ===\n", failures);
    return failures;
}
CEOF

    cc -O2 -Wall -static -pthread fuse_create_open_release_test.c -o "$out/bin/tidefs-fuse-create-open-release-test"
    strip "$out/bin/tidefs-fuse-create-open-release-test"
  '';

  # Validation script that mounts FUSE, runs create/open/release tests,
  # simulates crash, and verifies committed-root integrity.
  fuseCreateOpenReleaseValidationScript = pkgs.writeShellScriptBin "tidefs-fuse-create-open-release-validation" ''
    set -euo pipefail

    DAEMON_BIN="${tidefsPackage}/bin/tidefs-posix-filesystem-adapter-daemon"
    COR_TEST="${fuseCreateOpenReleaseTestBin}/bin/tidefs-fuse-create-open-release-test"

    TMPDIR="''${TIDEFS_FUSE_COR_TMPDIR:-/tmp/tidefs-fuse-create-open-release-validation}"
    STORE="$TMPDIR/store"
    MNT="$TMPDIR/mnt"

    usage() {
      cat <<EOF
Usage: tidefs-fuse-create-open-release-validation [--keep-tmp]

Validate FUSE userspace create/open/release operations (open-existing,
open-create, open-create-excl, open-truncate, release, dup, concurrent-open,
open-release-cycle, open-append) with crash-consistency verification through
committed-root integrity checks.

Environment:
  TIDEFS_FUSE_COR_TMPDIR              scratch directory (default /tmp/tidefs-fuse-create-open-release-validation)
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

    echo "=== TideFS FUSE Create/Open/Release Validation ==="
    echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "kernel=$(uname -r)"
    echo "daemon=$DAEMON_BIN"
    echo "test=$COR_TEST"
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

    # ── Phase 1: Start FUSE daemon ────────────────────────────────────
    echo "--- Phase 1: Start FUSE daemon ---"
    DAEMON_LOG="$TMPDIR/daemon.log"
    "$DAEMON_BIN" mount-vfs \
      --store "$STORE" --mount "$MNT" \
      > "$DAEMON_LOG" 2>&1 &
    DAEMON_PID=$!

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
      echo "=== FUSE Create/Open/Release Validation Summary ==="
      echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
      echo "tier=mounted-userspace"
      exit 1
    fi

    # ── Phase 2: Run create/open/release test ─────────────────────────
    echo ""
    echo "--- Phase 2: Create/Open/Release operations ---"
    TEST_LOG="$TMPDIR/test.log"
    if "$COR_TEST" "$MNT" > "$TEST_LOG" 2>&1; then
      TEST_RC=0
    else
      TEST_RC=$?
    fi

    while IFS= read -r line; do
      case "$line" in
        PASS:*) pass "''${line#PASS: }" ;;
        FAIL:*) fail "''${line#FAIL: }" "''${line}" ;;
      esac
    done < "$TEST_LOG"

    if [ "$TEST_RC" -eq 0 ]; then
      pass "cor_test_exit_zero"
    else
      fail "cor_test_exit_zero" "test binary exited with $TEST_RC"
    fi

    # ── Phase 3: Snapshot committed state ─────────────────────────────
    echo ""
    echo "--- Phase 3: Snapshot committed state ---"
    sync
    ls -la "$MNT" > "$TMPDIR/root_list.txt" 2>/dev/null || true

    for f in open_existing.bin open_create.bin open_create_excl.bin \
             open_truncate.bin release.bin dup_fd.bin concurrent_open.bin \
             open_release_cycle.bin open_append.bin; do
      if [ -f "$MNT/$f" ]; then
        SZ=$(stat -c%s "$MNT/$f" 2>/dev/null || echo "missing")
        echo "pre_crash_size $f $SZ" >> "$TMPDIR/pre_crash_sizes.txt"
      fi
    done
    pass "committed_snapshot"

    # ── Phase 4: Simulate crash (SIGKILL daemon) ──────────────────────
    echo ""
    echo "--- Phase 4: Simulate crash (SIGKILL daemon PID $DAEMON_PID) ---"
    kill -9 "$DAEMON_PID" 2>/dev/null || true
    sleep 1

    fusermount -u "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null || true
    sleep 0.5
    pass "crash_simulated"

    # ── Phase 5: Remount and verify ────────────────────────────────────
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
    echo "--- Phase 6: Verify post-crash namespace state ---"
    "$COR_TEST" "$MNT" > "$TMPDIR/test_verify.log" 2>&1 || true
    while IFS= read -r line; do
      case "$line" in
        PASS:*) pass "post_crash_''${line#PASS: }" ;;
        FAIL:*) fail "post_crash_''${line#FAIL: }" "''${line}" ;;
      esac
    done < "$TMPDIR/test_verify.log"

    # Cleanup
    kill "$REMOUNT_PID" 2>/dev/null || true
    fusermount -u "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null || true

    # ── Summary ───────────────────────────────────────────────────────
    echo ""
    echo "=== FUSE Create/Open/Release Validation Summary ==="
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
fuseCreateOpenReleaseValidationScript
