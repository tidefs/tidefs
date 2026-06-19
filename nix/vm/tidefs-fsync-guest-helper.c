// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
/*
 * tidefs-fsync-guest-helper.c -- explicit fsync(2), fdatasync(2), and
 * syncfs(2) syscall exercise for TideFS kernel fsync runtime validation.
 *
 * Runs inside a Linux 7.0 QEMU guest after kmod-posix-vfs is loaded
 * and the TideFS filesystem is mounted.  Each syscall is exercised
 * against a dedicated test file and the outcome is reported as
 * PASS / FAIL / BLOCKED with an errno detail on failure.
 *
 * Compile (static or dynamic, inside guest initramfs):
 *   cc -Wall -O2 -o tidefs-fsync-guest-helper tidefs-fsync-guest-helper.c
 *
 * Usage:
 *   ./tidefs-fsync-guest-helper <mount-point-directory>
 *
 * Exit status:
 *   0  all exercised syscalls succeeded
 *   1  one or more syscalls failed or were blocked
 *   2  usage or environment error (no rows emitted)
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PATH_MAX_GUEST 4096

static int passed;
static int failed;
static int blocked;

static void emit_pass(const char *name) {
    printf("PASS: %s\n", name);
    passed++;
}

static void emit_fail(const char *name, const char *detail) {
    printf("FAIL: %s -- %s\n", name, detail);
    failed++;
}

static void emit_blocked(const char *name, const char *detail) {
    printf("BLOCKED: %s -- %s\n", name, detail);
    blocked++;
}

/* ── fsync(2) exercise ─────────────────────────────────────────── */

static void exercise_fsync(const char *mnt) {
    char path[PATH_MAX_GUEST];
    int n;

    n = snprintf(path, sizeof(path), "%s/fsync_test.dat", mnt);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        emit_blocked("fsync_fd", "path buffer overflow");
        return;
    }

    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        emit_blocked("fsync_fd", "open failed");
        return;
    }

    static const char payload[] = "FSYNC_TEST_DATA_V1_HELLO_TIDEFS_KERNEL_FSYNC";
    ssize_t written = write(fd, payload, sizeof(payload) - 1);
    if (written < 0) {
        emit_fail("fsync_fd", "write failed");
        close(fd);
        return;
    }
    if ((size_t)written != sizeof(payload) - 1) {
        emit_fail("fsync_fd", "short write");
        close(fd);
        return;
    }

    /* fsync(2) the file descriptor */
    if (fsync(fd) < 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "fsync errno=%d (%s)", errno, strerror(errno));
        emit_fail("fsync_fd", buf);
        close(fd);
        return;
    }

    emit_pass("fsync_fd");
    close(fd);
}

/* ── fdatasync(2) exercise ─────────────────────────────────────── */

static void exercise_fdatasync(const char *mnt) {
    char path[PATH_MAX_GUEST];
    int n;

    n = snprintf(path, sizeof(path), "%s/fdatasync_test.dat", mnt);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        emit_blocked("fdatasync_fd", "path buffer overflow");
        return;
    }

    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        emit_blocked("fdatasync_fd", "open failed");
        return;
    }

    static const char payload[] = "FDATASYNC_TEST_DATA_V2_HELLO";
    ssize_t written = write(fd, payload, sizeof(payload) - 1);
    if (written < 0) {
        emit_fail("fdatasync_fd", "write failed");
        close(fd);
        return;
    }
    if ((size_t)written != sizeof(payload) - 1) {
        emit_fail("fdatasync_fd", "short write");
        close(fd);
        return;
    }

    /* fdatasync(2) -- data-only sync, no metadata unless needed for size */
    if (fdatasync(fd) < 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "fdatasync errno=%d (%s)", errno, strerror(errno));
        emit_fail("fdatasync_fd", buf);
        close(fd);
        return;
    }

    emit_pass("fdatasync_fd");
    close(fd);
}

/* ── syncfs(2) exercise ────────────────────────────────────────── */

static void exercise_syncfs(const char *mnt) {
    /*
     * syncfs(2) operates on a file descriptor that refers to any file
     * on the target filesystem.  We open the mount point itself.
     */
    int fd = open(mnt, O_RDONLY);
    if (fd < 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "open mount point failed: %s", strerror(errno));
        emit_blocked("syncfs_fd", buf);
        return;
    }

    /* Write one extra file so syncfs has dirty pages to flush */
    char path[PATH_MAX_GUEST];
    int n = snprintf(path, sizeof(path), "%s/syncfs_extra.dat", mnt);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        emit_blocked("syncfs_fd", "path buffer overflow");
        close(fd);
        return;
    }

    int wfd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (wfd < 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "open dirty file failed: %s", strerror(errno));
        emit_fail("syncfs_fd", buf);
        close(fd);
        return;
    }

    static const char payload[] = "SYNCFS_EXTRA_PAYLOAD";
    ssize_t written = write(wfd, payload, sizeof(payload) - 1);
    if (written < 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "write dirty file failed: %s", strerror(errno));
        emit_fail("syncfs_fd", buf);
        close(wfd);
        close(fd);
        return;
    }
    if ((size_t)written != sizeof(payload) - 1) {
        emit_fail("syncfs_fd", "short dirty-file write");
        close(wfd);
        close(fd);
        return;
    }
    if (close(wfd) < 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "close dirty file failed: %s", strerror(errno));
        emit_fail("syncfs_fd", buf);
        close(fd);
        return;
    }

    /* syncfs(2) */
    if (syncfs(fd) < 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "syncfs errno=%d (%s)", errno, strerror(errno));
        emit_fail("syncfs_fd", buf);
        close(fd);
        return;
    }

    emit_pass("syncfs_fd");
    close(fd);
}

/* ── main ──────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <mount-point>\n", argv[0]);
        return 2;
    }

    const char *mnt = argv[1];

    /* Sanity: mount point must exist */
    struct stat st;
    if (stat(mnt, &st) < 0) {
        fprintf(stderr, "mount point not accessible: %s: %s\n",
                mnt, strerror(errno));
        return 2;
    }
    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "mount point is not a directory: %s\n", mnt);
        return 2;
    }

    passed = 0;
    failed = 0;
    blocked = 0;

    exercise_fsync(mnt);
    exercise_fdatasync(mnt);
    exercise_syncfs(mnt);

    /* Emit summary counters so the host parser can score the run */
    printf("FSYNC_HELPER_PASSED=%d\n", passed);
    printf("FSYNC_HELPER_FAILED=%d\n", failed);
    printf("FSYNC_HELPER_BLOCKED=%d\n", blocked);

    return (failed > 0 || blocked > 0) ? 1 : 0;
}
