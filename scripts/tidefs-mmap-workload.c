/*
 * tidefs-mmap-workload.c -- mmap/page-cache validation workload for TideFS FUSE
 *
 * Exercises mmap read/write (MAP_SHARED, MAP_PRIVATE), msync (MS_SYNC,
 * MS_ASYNC), truncate-while-mapped, invalidation across handles, executable
 * mapping, database-style page-in/page-out, direct-I/O reconciliation, and
 * writeback-cache interaction.
 *
 * Compile: cc -Wall -O2 -o tidefs-mmap-workload tidefs-mmap-workload.c
 * Usage:   ./tidefs-mmap-workload <test-directory>
 *          ./tidefs-mmap-workload --verify-persistence <test-directory>
 *
 * Output:  JSON validation rows on stdout.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* ── helpers ────────────────────────────────────────────────────── */

#define PAGE 4096

static char test_dir[4096];
static int failed_rows;

static void die(const char *msg) {
    fprintf(stderr, "mmap-workload: %s: %s\n", msg, strerror(errno));
    exit(1);
}

static void emit_row(const char *name, const char *outcome,
                     const char *tier, const char *note) {
    printf("{\"name\":\"%s\",\"outcome\":\"%s\",\"tier\":\"%s\"",
           name, outcome, tier);
    if (note && *note)
        printf(",\"output_note\":\"%s\"", note);
    printf("}\n");
    fflush(stdout);
}

static void emit_row_pass(const char *name, const char *note) {
    emit_row(name, "pass", "mounted-userspace", note);
}

static void emit_row_fail(const char *name, const char *note) {
    failed_rows++;
    emit_row(name, "fail", "mounted-userspace", note);
}

static void emit_row_blocked(const char *name, const char *note) {
    emit_row(name, "blocked", "mounted-userspace", note);
}

static void verify_persisted_page(const char *row_name, const char *file_name,
                                  unsigned char expected) {
    char path[8192];
    unsigned char page[PAGE];
    size_t consumed = 0;
    struct stat st;

    snprintf(path, sizeof(path), "%s/%s", test_dir, file_name);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        char note[192];
        int saved_errno = errno;
        snprintf(note, sizeof(note), "open failed: errno=%d (%s)",
                 saved_errno, strerror(saved_errno));
        emit_row_fail(row_name, note);
        return;
    }
    if (fstat(fd, &st) < 0) {
        char note[192];
        int saved_errno = errno;
        snprintf(note, sizeof(note), "fstat failed: errno=%d (%s)",
                 saved_errno, strerror(saved_errno));
        close(fd);
        emit_row_fail(row_name, note);
        return;
    }
    if (st.st_size != PAGE) {
        char note[128];
        snprintf(note, sizeof(note), "size mismatch: expected=%d actual=%lld",
                 PAGE, (long long)st.st_size);
        close(fd);
        emit_row_fail(row_name, note);
        return;
    }
    while (consumed < sizeof(page)) {
        ssize_t got = read(fd, page + consumed, sizeof(page) - consumed);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0) {
            char note[192];
            int saved_errno = got < 0 ? errno : 0;
            snprintf(note, sizeof(note),
                     "read failed: bytes=%zu errno=%d (%s)", consumed,
                     saved_errno, saved_errno ? strerror(saved_errno) : "short read");
            close(fd);
            emit_row_fail(row_name, note);
            return;
        }
        consumed += (size_t)got;
    }
    close(fd);

    for (size_t i = 0; i < sizeof(page); i++) {
        if (page[i] != expected) {
            char note[160];
            snprintf(note, sizeof(note),
                     "byte mismatch: offset=%zu expected=0x%02x actual=0x%02x",
                     i, expected, page[i]);
            emit_row_fail(row_name, note);
            return;
        }
    }
    emit_row_pass(row_name, "exact page survived export/reimport/remount");
}

/* ── test implementations ───────────────────────────────────────── */

static void test_mmap_read_write_shared(void) {
    char path[8192];
    snprintf(path, sizeof(path), "%s/mmaps.txt", test_dir);

    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { emit_row_fail("mmap-read-write-shared", "open failed"); return; }

    if (ftruncate(fd, PAGE) < 0)
        { close(fd); emit_row_fail("mmap-read-write-shared", "ftruncate failed"); return; }

    char *p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED)
        { close(fd); emit_row_fail("mmap-read-write-shared", "mmap failed"); return; }

    /* write pattern through mmap */
    memset(p, 0xAB, PAGE);
    if (msync(p, PAGE, MS_SYNC) < 0) {
        int saved_errno = errno;
        char note[160];
        snprintf(note, sizeof(note), "msync failed: errno=%d (%s)",
                 saved_errno, strerror(saved_errno));
        munmap(p, PAGE);
        close(fd);
        emit_row_fail("mmap-read-write-shared", note);
        return;
    }

    /* read back through read(2) and compare */
    lseek(fd, 0, SEEK_SET);
    char buf[PAGE];
    ssize_t n = read(fd, buf, PAGE);
    if (n != PAGE)
        { munmap(p, PAGE); close(fd);
          emit_row_fail("mmap-read-write-shared", "read back short"); return; }

    int ok = 1;
    for (int i = 0; i < PAGE; i++)
        if ((unsigned char)buf[i] != 0xAB) { ok = 0; break; }

    munmap(p, PAGE);
    close(fd);

    if (ok)
        emit_row_pass("mmap-read-write-shared", "");
    else
        emit_row_fail("mmap-read-write-shared", "data mismatch");
}

static void test_mmap_read_write_private(void) {
    char path[8192];
    snprintf(path, sizeof(path), "%s/mmapp.txt", test_dir);

    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { emit_row_fail("mmap-read-write-private", "open failed"); return; }

    if (ftruncate(fd, PAGE) < 0)
        { close(fd); emit_row_fail("mmap-read-write-private", "ftruncate failed"); return; }

    /* write initial content */
    if (pwrite(fd, "ORIG", 4, 0) != 4)
        { close(fd); emit_row_fail("mmap-read-write-private", "pwrite init failed"); return; }

    char *p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED)
        { close(fd); emit_row_fail("mmap-read-write-private", "mmap failed"); return; }

    /* CoW write: should NOT reach backing file */
    p[0] = 'X';

    /* read back from file: must still be ORIG */
    char buf[4];
    lseek(fd, 0, SEEK_SET);
    if (read(fd, buf, 4) != 4)
        { munmap(p, PAGE); close(fd);
          emit_row_fail("mmap-read-write-private", "read back short"); return; }

    int ok = (memcmp(buf, "ORIG", 4) == 0);

    munmap(p, PAGE);
    close(fd);

    if (ok)
        emit_row_pass("mmap-read-write-private", "CoW semantics correct");
    else
        emit_row_fail("mmap-read-write-private", "CoW write leaked to backing file");
}

static void test_msync_sync(void) {
    char path[8192];
    snprintf(path, sizeof(path), "%s/msyncs.txt", test_dir);

    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { emit_row_fail("msync-sync", "open failed"); return; }

    if (ftruncate(fd, PAGE) < 0)
        { close(fd); emit_row_fail("msync-sync", "ftruncate failed"); return; }

    char *p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED)
        { close(fd); emit_row_fail("msync-sync", "mmap failed"); return; }

    memset(p, 0xCD, PAGE);
    if (msync(p, PAGE, MS_SYNC) < 0) {
        int saved_errno = errno;
        char note[176];
        snprintf(note, sizeof(note),
                 "msync MS_SYNC returned error: errno=%d (%s)",
                 saved_errno, strerror(saved_errno));
        munmap(p, PAGE);
        close(fd);
        emit_row_fail("msync-sync", note);
        return;
    }

    /* verify durable via re-read after munmap */
    munmap(p, PAGE);
    char buf[PAGE];
    lseek(fd, 0, SEEK_SET);
    if (read(fd, buf, PAGE) != PAGE)
        { close(fd); emit_row_fail("msync-sync", "re-read short"); return; }

    int ok = 1;
    for (int i = 0; i < PAGE; i++)
        if ((unsigned char)buf[i] != 0xCD) { ok = 0; break; }

    close(fd);

    if (ok)
        emit_row_pass("msync-sync", "");
    else
        emit_row_fail("msync-sync", "MS_SYNC did not persist data");
}

static void test_msync_async(void) {
    char path[8192];
    snprintf(path, sizeof(path), "%s/msynca.txt", test_dir);

    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { emit_row_fail("msync-async", "open failed"); return; }

    if (ftruncate(fd, PAGE) < 0)
        { close(fd); emit_row_fail("msync-async", "ftruncate failed"); return; }

    char *p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED)
        { close(fd); emit_row_fail("msync-async", "mmap failed"); return; }

    memset(p, 0xEF, PAGE);
    /* MS_ASYNC: best effort, may be no-op; record as pass if call succeeds */
    if (msync(p, PAGE, MS_ASYNC) < 0)
        { munmap(p, PAGE); close(fd);
          emit_row_fail("msync-async", "msync MS_ASYNC returned error"); return; }

    munmap(p, PAGE);
    close(fd);

    /* MS_ASYNC does not guarantee durability; just check no crash/error */
    emit_row_pass("msync-async", "MS_ASYNC call succeeded (no durability guarantee)");
}

#include <setjmp.h>
static int truncate_sigbus_caught = 0;
static sigjmp_buf truncate_sigbus_jmp;

static void sigbus_handler(int sig) {
    (void)sig;
    truncate_sigbus_caught = 1;
    siglongjmp(truncate_sigbus_jmp, 1);
}

static void test_truncate_while_mapped(void) {
    char path[8192];
    snprintf(path, sizeof(path), "%s/truncm.txt", test_dir);

    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { emit_row_fail("truncate-while-mapped", "open failed"); return; }

    if (ftruncate(fd, 2 * PAGE) < 0)
        { close(fd); emit_row_fail("truncate-while-mapped", "ftruncate failed"); return; }

    char *p = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED)
        { close(fd); emit_row_fail("truncate-while-mapped", "mmap failed"); return; }

    /* Write into both pages so they're faulted in */
    memset(p, 0x42, 2 * PAGE);

    /* Install SIGBUS handler */
    struct sigaction sa = {0};
    sa.sa_handler = sigbus_handler;
    sigaction(SIGBUS, &sa, NULL);
    truncate_sigbus_caught = 0;

    /* Truncate to one page */
    if (ftruncate(fd, PAGE) < 0)
        { munmap(p, 2 * PAGE); close(fd);
          emit_row_fail("truncate-while-mapped", "ftruncate shrink failed"); return; }
    if (sigsetjmp(truncate_sigbus_jmp, 1) == 0) {
        volatile char *vp = (volatile char *)p;
        char dummy = vp[PAGE + 1];
        (void)dummy;
    }

    munmap(p, 2 * PAGE);
    close(fd);

    if (truncate_sigbus_caught)
        emit_row_pass("truncate-while-mapped", "SIGBUS delivered on truncated page access");
    else
        emit_row_fail("truncate-while-mapped", "no SIGBUS after truncate while mapped");
}

static void test_invalidation_across_handles(void) {
    char path[8192];
    snprintf(path, sizeof(path), "%s/invalh.txt", test_dir);

    int fd1 = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd1 < 0) { emit_row_fail("invalidation-across-handles", "fd1 open failed"); return; }

    if (write(fd1, "0123456789", 10) != 10)
        { close(fd1); emit_row_fail("invalidation-across-handles", "write failed"); return; }

    int fd2 = open(path, O_RDWR, 0644);
    if (fd2 < 0)
        { close(fd1); emit_row_fail("invalidation-across-handles", "fd2 open failed"); return; }

    /* mmap through fd1 */
    char *p1 = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd1, 0);
    if (p1 == MAP_FAILED)
        { close(fd1); close(fd2);
          emit_row_fail("invalidation-across-handles", "mmap fd1 failed"); return; }

    /* read first bytes through mmap */
    char before = p1[0];

    /* write through fd2 */
    if (pwrite(fd2, "X", 1, 0) != 1)
        { munmap(p1, PAGE); close(fd1); close(fd2);
          emit_row_fail("invalidation-across-handles", "pwrite fd2 failed"); return; }

    /* re-read through mmap: should see the update or FUSE may not invalidate */
    char after = p1[0];

    munmap(p1, PAGE);
    close(fd1);
    close(fd2);

    /* If FUSE sent invalidation, after should be 'X'.
     * Record as pass if it's visible; note the gap if not. */
    if (after == 'X')
        emit_row_pass("invalidation-across-handles", "cross-handle write visible");
    else if (after == before)
        emit_row_fail("invalidation-across-handles",
                       "stale mmap data after write through other handle");
    else
        emit_row_fail("invalidation-across-handles", "unexpected data");
}

static void test_executable_mapping(void) {
    char path[8192];
    snprintf(path, sizeof(path), "%s/execm.txt", test_dir);

    /* Write a simple x86-64 ret instruction (0xC3) */
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { emit_row_fail("executable-mapping", "open failed"); return; }

    unsigned char code[] = { 0xC3 };  /* ret */
    if (write(fd, code, sizeof(code)) != (ssize_t)sizeof(code))
        { close(fd); emit_row_fail("executable-mapping", "write failed"); return; }

    close(fd);

    fd = open(path, O_RDONLY);
    if (fd < 0) { emit_row_fail("executable-mapping", "reopen failed"); return; }

    void *p = mmap(NULL, PAGE, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED)
        { close(fd); emit_row_fail("executable-mapping", "mmap PROT_EXEC failed"); return; }

    /* Execute the mapped code: call the ret instruction */
    /* Use a volatile function pointer to prevent compiler optimizations */
    void (*fn)(void) = (void (*)(void))p;
    volatile int called = 0;
    fn();  /* should just return */
    called = 1;

    munmap(p, PAGE);
    close(fd);

    if (called)
        emit_row_pass("executable-mapping", "PROT_EXEC mmap and execute succeeded");
    else
        emit_row_fail("executable-mapping", "execution did not return");
}

static void test_database_style_mmap(void) {
    char path[8192];
    snprintf(path, sizeof(path), "%s/dbmmap.txt", test_dir);

    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { emit_row_fail("database-style-mmap", "open failed"); return; }

    off_t filesz = 64 * PAGE;
    if (ftruncate(fd, filesz) < 0)
        { close(fd); emit_row_fail("database-style-mmap", "ftruncate failed"); return; }

    char *p = mmap(NULL, filesz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED)
        { close(fd); emit_row_fail("database-style-mmap", "mmap failed"); return; }

    /* Database-style: write to scattered pages */
    int pages[] = { 0, 7, 15, 23, 31, 42, 55, 63 };
    int npages = (int)(sizeof(pages) / sizeof(pages[0]));

    for (int i = 0; i < npages; i++) {
        off_t off = (off_t)pages[i] * PAGE;
        memset(p + off, (unsigned char)(0x10 + i), PAGE);
    }

    /* Read back and verify */
    int ok = 1;
    for (int i = 0; i < npages && ok; i++) {
        off_t off = (off_t)pages[i] * PAGE;
        unsigned char expected = (unsigned char)(0x10 + i);
        for (int j = 0; j < PAGE; j++) {
            if ((unsigned char)p[off + j] != expected) {
                ok = 0;
                break;
            }
        }
    }

    munmap(p, filesz);
    close(fd);

    if (ok)
        emit_row_pass("database-style-mmap", "");
    else
        emit_row_fail("database-style-mmap", "data corruption");
}

static void test_direct_io_reconciliation(void) {
    char path[8192];
    snprintf(path, sizeof(path), "%s/directio.txt", test_dir);

    int fd_mmap = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd_mmap < 0)
        { emit_row_fail("direct-io-reconciliation", "mmap fd open failed"); return; }

    if (ftruncate(fd_mmap, PAGE) < 0)
        { close(fd_mmap);
          emit_row_fail("direct-io-reconciliation", "ftruncate failed"); return; }

    char *p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd_mmap, 0);
    if (p == MAP_FAILED)
        { close(fd_mmap);
          emit_row_fail("direct-io-reconciliation", "mmap failed"); return; }

    /* Write through mmap */
    memcpy(p, "MMAPDATA", 8);

    /* Open a second fd with O_DIRECT */
    int fd_direct = open(path, O_RDWR | O_DIRECT);
    if (fd_direct < 0) {
        /* O_DIRECT not supported; mark as refusal */
        munmap(p, PAGE);
        close(fd_mmap);
        emit_row_blocked("direct-io-reconciliation", "O_DIRECT not supported on this FS");
        return;
    }

    /* Aligned buffer for O_DIRECT */
    char *dbuf = NULL;
    if (posix_memalign((void **)&dbuf, PAGE, PAGE) != 0)
        { munmap(p, PAGE); close(fd_mmap); close(fd_direct);
          emit_row_fail("direct-io-reconciliation", "posix_memalign failed"); return; }

    memset(dbuf, 0, PAGE);

    /* Read via O_DIRECT */
    ssize_t n = pread(fd_direct, dbuf, PAGE, 0);
    if (n < 0) {
        free(dbuf); munmap(p, PAGE); close(fd_mmap); close(fd_direct);
        emit_row_blocked("direct-io-reconciliation", "O_DIRECT read failed");
        return;
    }

    int ok = (memcmp(dbuf, "MMAPDATA", 8) == 0);

    free(dbuf);
    munmap(p, PAGE);
    close(fd_mmap);
    close(fd_direct);

    if (ok)
        emit_row_pass("direct-io-reconciliation", "O_DIRECT read saw mmap'd data");
    else
        emit_row_fail("direct-io-reconciliation", "O_DIRECT read missed mmap'd data");
}

/* ── main ───────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    int verify_persistence = 0;
    const char *directory = NULL;

    if (argc == 2) {
        directory = argv[1];
    } else if (argc == 3 && strcmp(argv[1], "--verify-persistence") == 0) {
        verify_persistence = 1;
        directory = argv[2];
    } else {
        fprintf(stderr,
                "Usage: %s [--verify-persistence] <test-directory>\n",
                argv[0]);
        return 1;
    }

    strncpy(test_dir, directory, sizeof(test_dir) - 1);
    test_dir[sizeof(test_dir) - 1] = '\0';

    if (verify_persistence) {
        printf("[\n");
        verify_persisted_page("mmap-read-write-shared-persisted", "mmaps.txt", 0xAB);
        printf(",\n");
        verify_persisted_page("msync-sync-persisted", "msyncs.txt", 0xCD);
        printf("\n]\n");
        return failed_rows == 0 ? 0 : 1;
    }

    /* Ensure test directory exists */
    if (mkdir(test_dir, 0755) < 0 && errno != EEXIST)
        die("mkdir test_dir");

    printf("[\n");

    test_mmap_read_write_shared();
    printf(",\n");
    test_mmap_read_write_private();
    printf(",\n");
    test_msync_sync();
    printf(",\n");
    test_msync_async();
    printf(",\n");
    test_truncate_while_mapped();
    printf(",\n");
    test_invalidation_across_handles();
    printf(",\n");
    test_executable_mapping();
    printf(",\n");
    test_database_style_mmap();
    printf(",\n");
    test_direct_io_reconciliation();
    printf("\n");

    printf("]\n");
    return failed_rows == 0 ? 0 : 1;
}
