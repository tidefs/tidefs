# tidefs-kernel-storage-io

Kernel-portable block-I/O storage adapter for TideFS.

## Purpose

This crate defines `KernelStorageIo`, a `no_std` trait that provides
sector-aligned read, write, and flush/barrier primitives. It is the
common I/O contract consumed by:

- **intent-log append**: writing sealed intent-log segments to durable
  storage at known sector positions.
- **txg commit-barrier**: writing committed-root blocks and issuing
  durability barriers after transaction-group commit.

The trait lives here so that neither intent-log nor commit_group needs
a direct dependency on `KernelPoolCore` or any specific block-device
backend.

## Trait contract

`KernelStorageIo` methods operate exclusively in **sectors** (not byte
offsets). Every read/write buffer must be an integer multiple of the
sector size (queried via `sector_size()`). Durability is gated by
`flush()`, which implements a write barrier/FUA.

The companion `RawBlockIo` trait abstracts byte-offset block I/O.
`KernelStorageAdapter<B: RawBlockIo>` bridges any `RawBlockIo` backend
into the sector-aligned `KernelStorageIo` contract.

## no_std

The crate is `#![no_std]` with an optional `alloc` feature. It has no
filesystem, threading, or networking dependencies, making it suitable
for Linux kernel module contexts where the Rust standard library is
unavailable.

## Usage

```rust
use tidefs_kernel_storage_io::{KernelStorageAdapter, KernelStorageIo, RawBlockIo};

// 1. Implement RawBlockIo for your block-device backend.
struct MyBackend { /* … */ }
impl RawBlockIo for MyBackend { /* … */ }

// 2. Wrap it in the adapter.
let adapter = KernelStorageAdapter::new(MyBackend::new());

// 3. Use sector-aligned primitives.
let mut buf = [0u8; 4096];
adapter.read_sectors(0, &mut buf)?;
adapter.write_sectors(1, &[0xABu8; 4096])?;
adapter.flush()?;
```

## Downstream integration

- **intent-log**: `IntentLogWriter` produces sealed segment bytes;
  the caller writes them via `write_sectors` and calls `flush` after
  each sealed segment.
- **txg commit-barrier**: `CommitGroupWriter` writes committed-root
  blocks; the caller uses `write_sectors` + `flush` to make them
  durable before advancing the superblock root pointer.

## Testing

```bash
cargo test -p tidefs-kernel-storage-io
```

All tests use an in-memory `RawBlockIo` backend and cover:
- sector-aligned read/write roundtrips at 512 and 4096 byte sectors
- unaligned buffer rejection
- out-of-range detection
- flush barrier semantics (including `ENOSYS` fallback)
- capacity/sector-size querying
- `validate_range` boundary conditions
- object safety for both `KernelStorageIo` and `RawBlockIo`

## Pool Superblock Scan

The `pool_superblock` module provides kernel-mode pool device identification
through `KernelStorageIo`:

- `read_pool_superblock` reads and validates the TideFS pool label from
  sector 0 of a block device. It checks the VBFS magic bytes, decodes the
  label with BLAKE3-256 checksum verification, and returns a
  `KernelPoolSuperblock` with pool identity (GUID, name), recovery
  commit_group, and the committed-root ledger location (system_area_pointer).

- `read_pool_superblock_at` is the same but starts at an arbitrary sector,
  used for reading the tail label copy (label copy 1) at the end of the
  device.

- `KernelPoolSuperblock` is a no_std-friendly subset of the full
  `PoolLabelV1`: it carries the fields needed by the VFS mount path to
  initialize KernelPoolCore without pulling in the full userspace
  pool-scan dependency tree.

- `PoolSuperblockError` enumerates failure modes: I/O error, device too
  small, bad magic, unsupported version, and corrupt (checksum mismatch).

### Import evidence receipts

`PoolSuperblockImportEvidence` records focused source/unit evidence for one
member-device import decision. A receipt carries the observed primary and
secondary label evidence, the candidate member id, the superblock generation
(the label recovery `commit_group`), the verified label digest, the import
decision, the validation tier, and the claim/issue references introduced for
GitHub issue #537.

The receipt constructor is fail-closed. It accepts import only when primary
and secondary label copies are both present and agree on pool identity, member
id, superblock generation, and label digest. Unknown evidence, a missing label
copy, mixed labels, stale generations, or digest mismatch all produce rejected
import decisions.

These receipts are evidence metadata for `tidefs-kernel-storage-io` unit
behavior. They are not a replacement for mounted kernel validation,
multi-device runtime validation, pool import policy, recovery policy, or
claim-status changes in `validation/claims.toml`.

### Integration

The `tidefs-kmod-posix-vfs` mount path uses `PoolImportContext::scan_device_io`
which internally calls `read_pool_superblock` and falls back to
`read_pool_superblock_at` for the tail label copy. This replaces the
raw-buffer `scan_device` path for kernel-mode mounts where block-device I/O
must go through the portable sector-aligned `KernelStorageIo` trait.
