// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
/*
 * Perform one O_SYNC or O_DSYNC write, report its successful return, and keep
 * the descriptor open until the crash harness proves the mount owner died.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int write_all(int fd, const char *payload, size_t length) {
    size_t offset = 0;

    while (offset < length) {
        ssize_t written = write(fd, payload + offset, length - offset);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (written == 0) {
            errno = EIO;
            return -1;
        }
        offset += (size_t)written;
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *mode;
    const char *path;
    const char *release_path;
    const char *payload;
    int sync_flag;
    int fd;
    size_t payload_length;

    if (argc != 5) {
        fprintf(stderr, "usage: %s <sync|dsync> <path> <release-path> <payload>\n", argv[0]);
        return 2;
    }

    mode = argv[1];
    path = argv[2];
    release_path = argv[3];
    payload = argv[4];
    if (strcmp(mode, "sync") == 0)
        sync_flag = O_SYNC;
    else if (strcmp(mode, "dsync") == 0)
        sync_flag = O_DSYNC;
    else {
        fprintf(stderr, "unsupported sync mode: %s\n", mode);
        return 2;
    }

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | sync_flag, 0644);
    if (fd < 0) {
        fprintf(stderr, "open failed: errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }

    payload_length = strlen(payload);
    if (write_all(fd, payload, payload_length) < 0) {
        fprintf(stderr, "write failed: errno=%d (%s)\n", errno, strerror(errno));
        close(fd);
        return 1;
    }

    printf("WRITE_SUCCEEDED mode=%s bytes=%zu\n", mode, payload_length);
    if (fflush(stdout) != 0) {
        fprintf(stderr, "success marker flush failed: errno=%d (%s)\n", errno, strerror(errno));
        close(fd);
        return 2;
    }

    while (access(release_path, F_OK) != 0) {
        if (errno != ENOENT) {
            fprintf(stderr, "release check failed: errno=%d (%s)\n", errno, strerror(errno));
            close(fd);
            return 2;
        }
        usleep(10000);
    }

    /*
     * The harness releases us only after proving the FUSE owner is dead.
     * Closing a descriptor on that dead connection can report EIO or ENOTCONN;
     * it cannot contribute to the durability result already being measured.
     */
    (void)close(fd);
    return 0;
}
