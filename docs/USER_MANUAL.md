# TideFS User Manual

This manual covers the current TideFS userspace filesystem. TideFS is under
active development. The filesystem is functional for local experiments but is
not yet production-ready or POSIX-complete.

Use this manual with:
- `docs/STATUS.md` for current project state
- `docs/ARCHITECTURE.md` for system architecture and design rationale
- `docs/POSIX_COMPLIANCE.md` for per-operation POSIX status
- `docs/GAP_ANALYSIS.md` for known gaps against ZFS and CephFS
- `docs/FEATURE_MATRIX.md` for capability boundaries
- `docs/POSIX_SUBSET.md` for the mounted syscall matrix
- `docs/FUSE_MOUNT.md` for the FUSE adapter surface

## What You Can Do

The mounted filesystem supports:

### File Operations
- Create, open, read, write, truncate, close
- Sparse files (holes consume no storage)
- fsync, fdatasync, syncfs
- fallocate mode-zero (EOF extension, zero-fill)
- lseek SEEK_SET/SEEK_CUR/SEEK_END/SEEK_DATA/SEEK_HOLE
- poll for readable/writable status

### Directory Operations
- Create and remove directories
- Open, read, close directories
- Directory fsync

### Metadata
- stat, fstat, lstat, statx
- chmod, fchmod, chown, fchown
- utimensat, futimens (timestamp updates)
- access (R_OK/W_OK/X_OK/F_OK)

### Namespace
- Hard links (link, unlink)
- Symbolic links (symlink, readlink)
- Rename including RENAME_NOREPLACE and RENAME_EXCHANGE
- mknod for regular files, FIFOs, block/character devices

### Locking
- BSD flock (LOCK_SH, LOCK_EX, LOCK_UN, LOCK_NB)
- POSIX advisory byte-range locks (fcntl F_GETLK, F_SETLK, F_SETLKW)
- Automatic lock release on close

### Extended Attributes
- getxattr, setxattr, listxattr, removexattr
- POSIX ACL (system.posix_acl_access, system.posix_acl_default)
  - ACL encode/decode through Linux binary xattr format
  - ACL evaluation for permission checks
  - Default ACL inheritance for new directories
  - Mode-to-ACL and ACL-to-mode synchronization

### Filesystem Information
- statfs, fstatfs (filesystem statistics)
- Filesystem capacity and free space

## Quick Start

### Prerequisites
- Linux host with FUSE support (`/dev/fuse` accessible)
- Nix with flakes enabled (for building)
- OpenSSL (for key generation)

### Build

    cd tidefs
    nix develop
    cargo build --workspace

### Mount

    mkdir -p /tmp/tidefs-store /tmp/tidefs-mnt
    export TIDEFS_ROOT_AUTHENTICATION_KEY_HEX="$(openssl rand -hex 32)"
    cargo run -p tidefs-posix-filesystem-adapter-daemon -- \
      mount --store /tmp/tidefs-store --mount /tmp/tidefs-mnt

Use `/tmp/tidefs-mnt` with standard POSIX tools:

    echo "hello" > /tmp/tidefs-mnt/test.txt
    cat /tmp/tidefs-mnt/test.txt
    mkdir /tmp/tidefs-mnt/subdir
    ln /tmp/tidefs-mnt/test.txt /tmp/tidefs-mnt/subdir/link
    ls -la /tmp/tidefs-mnt/

### Unmount

    fusermount3 -u /tmp/tidefs-mnt

### Smoke Test

    cargo run -p tidefs-posix-filesystem-adapter-daemon -- smoke-mount


    nix run .#posix-scoreboard
    nix run .#qemu-smoke

## Filesystem Semantics

### Data Durability

TideFS commits data in transaction groups (CommitGroup). An fsync or fdatasync call
ensures the file's data and metadata are committed to stable storage before
returning. After a clean unmount, all committed data persists. After a crash,
committed CommitGroups are recovered; uncommitted data from the last CommitGroup may be lost.

### Snapshots

Snapshots capture the filesystem state at a point in time. Snapshot data is
previous snapshot state.

### Space Management

Free space is tracked by the block allocator. When the filesystem is full,
writes return ENOSPC. fallocate can pre-allocate space with mode-zero.

### Integrity

All data is content-addressed with BLAKE3-256 hashes. On every read, the
hash is verified. Corruption is detected and logged (SuspectLog). The
online verifier can scan all data for integrity without modifying it.

### Encryption

Per-object encryption is available using ChaCha20-Poly1305 AEAD with
256-bit keys. Each object gets a unique random nonce. Encryption is
transparent: put and get operations automatically encrypt and decrypt.

### Compression

Per-object compression is available using zstd or LZ4. Objects smaller than
64 bytes are stored uncompressed. Incompressible payloads fall back to
uncompressed storage automatically.

## Known Limitations

This section is a summary. The authoritative inventory is
`docs/KNOWN_LIMITATIONS.md`, which distinguishes product limitations from
environment refusals (host/sandbox constraints that are not product defects).

Key product limitations:

- No mmap support (database workloads, executable loading)
- No online device replacement
- No separate intent log device (SLOG/LOG_DEVICE)
- No key rotation for encryption
- No network transport for send/receive
- No automated self-healing (online verifier is read-only)
- Broad xfstests coverage not yet runtime output at Tier 3

See `docs/KNOWN_LIMITATIONS.md` for the complete list and
`docs/GAP_ANALYSIS.md` for gap severity classification.
