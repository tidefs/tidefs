# TideFS User Manual

This manual covers the current TideFS userspace filesystem. TideFS is under
active development. The filesystem is functional for local experiments but is
not yet production-ready or POSIX-complete. It is not a release-readiness,
distributed-storage, kernelspace, RDMA, or OpenZFS/Ceph-class capability
claim.

Use this manual with:
- `README.md` for repository scope, current policy, and readiness caveats
- `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` for documentation authority state
- `docs/ARCHITECTURE.md` for system architecture and design rationale
- `docs/POSIX_COMPLIANCE.md` for per-operation POSIX status
- `docs/REVIEW_TODO_REGISTER.md` for current review debt and capability blockers
- `docs/CLAIMS_GATE_POLICY.md` and `docs/UNRELEASED_AUTHORITY_POLICY.md` for
  publishing-facing claim hygiene
- `docs/RELEASE_READINESS_VERDICT_CONTRACT.md` and
  `docs/PRODUCT_ADMISSION_PROOF_TRAINS.md` for release-readiness and
  whole-product admission boundaries
- `docs/OPERATOR_PRODUCT_SURFACE_DECISION.md` for the current operator
  product-surface boundary
- `docs/POSIX_SUBSET.md` for historical first-FUSE subset context

## Current Capability Boundary

The current reader-facing product surface is the local mounted userspace
filesystem path. The operation list below summarizes behavior documented for
that path; `docs/POSIX_COMPLIANCE.md` remains the per-operation authority for
DONE, GAP, UNTEST, and NONE status.

Capability outside that local mounted path remains constrained by the review
register and claim-policy documents. In particular, TideFS does not currently
claim a production release, a complete POSIX implementation, distributed
storage behavior, a runtime-fed operator product surface, a product RDMA data
path, or a production full-kernel/no-daemon storage path. Planning docs, CI
artifacts, model evidence, issue closeout notes, and gate-local receipts are
evidence inputs only; they do not become whole-product admission without the
authority surfaces named above.

## What You Can Do

The mounted userspace filesystem documents support for:

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

TideFS commits local data in transaction groups (CommitGroup). `fsync` and
`fdatasync` are mounted userspace operations, and a clean unmount preserves
committed CommitGroups. The integrated recovery, dirty-page writeback, mmap,
and page-cache authority proof remains open under `docs/REVIEW_TODO_REGISTER.md`
TFR-008, so this manual does not elevate those operations into a broader
release or production durability claim.

### Snapshots

Snapshots describe local point-in-time filesystem state. Snapshot retention,
clone lineage, deadlists, and send/receive are still tracked as a broader
storage-model boundary in `docs/REVIEW_TODO_REGISTER.md` TFR-010; this manual
does not claim distributed snapshot shipping or network send/receive behavior.

### Space Management

Free space is tracked by the block allocator. When the filesystem is full,
writes return ENOSPC. fallocate can pre-allocate space with mode-zero.

### Integrity

All data is content-addressed with BLAKE3-256 hashes. On every read, the
hash is verified. Corruption is detected and logged (SuspectLog). The
online verifier can scan local data for integrity without modifying it; it is
not automated self-healing.

### Encryption

Object-store transform paths include per-object encryption using
ChaCha20-Poly1305 AEAD with 256-bit keys and unique random nonces. Mounted
device-level encryption is not claimed by this manual; transform conformance
remains governed by `docs/REVIEW_TODO_REGISTER.md` TFR-006 and
`docs/TRANSFORM_PIPELINE_AUTHORITY.md`.

### Compression

Object-store transform paths include per-object compression using zstd or LZ4.
Objects smaller than 64 bytes are stored uncompressed, and incompressible
payloads fall back to uncompressed storage. Mounted device-level compression is
not claimed by this manual; use the same TFR-006 authority boundary as
encryption.

## Known Limitations

This section is a summary, not an exhaustive authority. For current review
debt and capability blockers, use `docs/REVIEW_TODO_REGISTER.md`; for mounted
operation status, use `docs/POSIX_COMPLIANCE.md`.

Key product limitations:

- No mmap support (database workloads, executable loading)
- No complete POSIX or broad xfstests release gate
- No mounted device-level compression/encryption product claim
- No online device replacement
- No separate intent log device (SLOG/LOG_DEVICE)
- No key rotation for encryption
- No distributed storage product claim, network transport for send/receive, or
  product RDMA data path
- No production full-kernel/no-daemon storage claim
- No runtime-fed operator product surface
- No automated self-healing (online verifier is read-only)

See `docs/REVIEW_TODO_REGISTER.md` for the broader review-debt inventory.
