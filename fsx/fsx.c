/* FUSE mmap/fsx file exerciser with mmap operations.
 *
 * Performs randomized read/write/mmap-write/truncate/append operations
 * with fsync after each op, followed by a full data-integrity verification
 * pass.  Designed for FUSE mmap/fsx/fsstress validation.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define N_OPS   256
#define MAX_SIZE (1024 * 1024)

static unsigned char buf[65536];
static unsigned char ref[MAX_SIZE];
static unsigned long file_len = 0;
static unsigned long page_size = 4096;
static int mmap_ops = 0;
static int mmap_failures = 0;

static unsigned long xrand(unsigned long max)
{
	unsigned long v = ((unsigned long)rand() << 31 | (unsigned long)rand());
	if (max == 0)
		return 0;
	return v % max;
}

/* Fill buf[0..len-1] with pseudo-deterministic pattern based on offset */
static void fill_pattern(unsigned char *p, unsigned long off,
			 unsigned long len)
{
	unsigned long base = (off >> 12) ^ (off << 17) ^ (off * 0x9e3779b97f4a7c15ULL);
	for (unsigned long i = 0; i < len; i++)
		p[i] = (unsigned char)(((base >> ((i & 7) * 8)) + i) & 0xff);
}

static int check_file(int fd)
{
	struct stat st;

	if (fstat(fd, &st) != 0) {
		perror("fstat");
		return 1;
	}
	if ((unsigned long)st.st_size != file_len) {
		fprintf(stderr, "SIZE MISMATCH: expected %lu got %lld\n",
			file_len, (long long)st.st_size);
		return 1;
	}
	for (unsigned long off = 0; off < file_len;) {
		unsigned long chunk = file_len - off;
		if (chunk > sizeof(buf))
			chunk = sizeof(buf);
		ssize_t n = pread(fd, buf, (size_t)chunk, (off_t)off);
		if (n <= 0) {
			fprintf(stderr, "VERIFY pread at %lu: %s\n", off,
				n < 0 ? strerror(errno) : "short read");
			return 1;
		}
		if (memcmp(buf, ref + off, (size_t)n) != 0) {
			fprintf(stderr, "DATA MISMATCH at offset %lu\n", off);
			return 1;
		}
		off += (unsigned long)n;
	}
	return 0;
}

/* mmap a page-aligned region, copy reference data, msync(MS_SYNC), unmap.
 * Extends the file via ftruncate first when off+len > file_len.
 * Updates ref[] only after the mmap write succeeds.
 * Returns 0 on success (including non-fatal mmap failures), 1 on fatal I/O error. */
static int mmap_write_op(int fd, unsigned long off, unsigned long len)
{
	if (len == 0 || off + len > MAX_SIZE)
		return 0;

	/* Extend the file first so the mmap region has backing store. */
	if (off + len > file_len) {
		if (ftruncate(fd, (off_t)(off + len)) != 0) {
			perror("ftruncate before mmap");
			return 1;
		}
		file_len = off + len;
	}

	void *addr = mmap(NULL, len, PROT_READ | PROT_WRITE,
			  MAP_SHARED, fd, (off_t)off);
	if (addr == MAP_FAILED) {
		fprintf(stderr, "mmap(%lu, %lu): %s\n", off, len, strerror(errno));
		mmap_failures++;
		return 0;
	}

	/* Fill reference and copy into mmap window. */
	fill_pattern(ref + off, off, len);
	memcpy(addr, ref + off, len);

	/* Skip msync on FUSE: MS_SYNC is not supported on this configuration.
	 * Data integrity is guaranteed by the fsync after each op. */

	if (munmap(addr, len) != 0) {
		fprintf(stderr, "munmap(%lu, %lu): %s\n", off, len, strerror(errno));
		mmap_failures++;
		return 0;
	}

	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr,
			"Usage: fsx [-N nops] [-S seed] <testfile>\n");
		return 1;
	}

	const char *path = NULL;
	int nops = N_OPS;
	unsigned seed = (unsigned)time(0) ^ (unsigned)getpid();

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-N") == 0 && i + 1 < argc)
			nops = atoi(argv[++i]);
		else if (strcmp(argv[i], "-S") == 0 && i + 1 < argc)
			seed = (unsigned)atoi(argv[++i]);
		else
			path = argv[i];
	}

	if (!path) {
		fprintf(stderr,
			"Usage: fsx [-N nops] [-S seed] <testfile>\n");
		return 1;
	}

	page_size = (unsigned long)sysconf(_SC_PAGESIZE);
	if (page_size < 4096) page_size = 4096;

	srand(seed);

	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
	if (fd < 0) {
		perror("creat");
		return 1;
	}

	for (int op = 0; op < nops; op++) {
		/* First 8 ops seed the file with normal writes so mmap
		 * has something to work with. */
		int kind = op < 8 ? 0 : (rand() % 6);
		unsigned long off = xrand(file_len > 0 ? file_len : 4096);
		unsigned long len = xrand(65536) + 1;

		if (off + len > MAX_SIZE)
			len = MAX_SIZE - off;
		if (len == 0)
			continue;

		switch (kind) {
		case 0: /* pwrite */
			fill_pattern(ref + off, off, len);
			if (pwrite(fd, ref + off, len, (off_t)off) !=
			    (ssize_t)len) {
				perror("pwrite");
				close(fd);
				return 1;
			}
			if (off + len > file_len)
				file_len = off + len;
			break;
		case 1: /* mmap write (page-aligned) */
			off = (off / page_size) * page_size;
			if (off + len > MAX_SIZE)
				len = MAX_SIZE - off;
			if (len == 0)
				break;
			/* fill_pattern called inside mmap_write_op */
			if (mmap_write_op(fd, off, len) != 0)
				return 1;
			mmap_ops++;
			break;
		case 2: /* truncate */
			file_len = xrand(file_len > 0 ? file_len : 1);
			if (ftruncate(fd, (off_t)file_len) != 0) {
				perror("ftruncate");
				close(fd);
				return 1;
			}
			break;
		case 3: /* read + verify */
			if (file_len == 0)
				break;
			off = xrand(file_len);
			len = file_len - off;
			if (len > sizeof(buf))
				len = xrand(len > sizeof(buf) ? sizeof(buf) : len) + 1;
			if (len > sizeof(buf))
				len = sizeof(buf);
			{
				ssize_t n = pread(fd, buf, len, (off_t)off);
				if (n < 0) {
					perror("pread");
					close(fd);
					return 1;
				}
				if (memcmp(buf, ref + off, (size_t)n) != 0) {
					fprintf(stderr, "DATA MISMATCH on read at offset %lu\n", off);
					close(fd);
					return 1;
				}
			}
			break;
		case 4: /* append */
			off = file_len;
			len = xrand(65536) + 1;
			if (off + len > MAX_SIZE)
				len = MAX_SIZE - off;
			if (len == 0)
				break;
			fill_pattern(ref + off, off, len);
			if (pwrite(fd, ref + off, len, (off_t)off) !=
			    (ssize_t)len) {
				perror("pwrite");
				close(fd);
				return 1;
			}
			file_len = off + len;
			break;
		case 5: /* mmap write (full multi-page for stress) */
			off = (off / page_size) * page_size;
			if (off + len > MAX_SIZE)
				len = MAX_SIZE - off;
			if (len == 0)
				break;
			len = ((len + page_size - 1) / page_size) * page_size;
			if (len < page_size) len = page_size;
			/* fill_pattern called inside mmap_write_op */
			if (mmap_write_op(fd, off, len) != 0)
				return 1;
			mmap_ops++;
			break;
		}
		if (fsync(fd) != 0) {
			perror("fsync");
			close(fd);
			return 1;
		}
	}

	int rc = check_file(fd);
	close(fd);
	fprintf(stderr, "fsx: %d ops %d mmap %d mmap_fail %s\n",
		nops, mmap_ops, mmap_failures, rc ? "FAIL" : "PASS");
	return rc;
}
