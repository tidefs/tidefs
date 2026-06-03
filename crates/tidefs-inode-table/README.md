# tidefs-inode-table

In-memory inode table for TideFS: authoritative inode-number-to-attributes registry with slot allocator, free list, and thread-safe concurrent access.

## Features

- **`std`** (default): Enables the full `InodeTable` implementation with `parking_lot`-backed thread safety, `LocalObjectStore` persistence, and the POSIX attribute API. This is the userspace (FUSE/ublk) path.
- **`kernel`**: Enables the no_std `KernelInodeTableReader` for kernel-mode inode resolution through `KernelStorageIo`. Does not require `std` or `alloc` for the reader itself (the reader uses fixed-size stack buffers), though `alloc` is available for tests.

## Kernel-mode reader

When the `kernel` feature is enabled, the crate exposes:

- **`KernelInodeTableReader`** — reads and decodes individual inode records from a raw on-disk inode table region through `KernelStorageIo`.
- **`InodeRecord`** — decoded record containing POSIX attributes, object store locator, and extent map root pointer.
- **`InodeKind`** — exported as `KernelInodeKind` to avoid name conflict with the std-mode `InodeKind`.
- **`KernelInodeTableError`** — error enum for inode-not-found, empty slot, corrupt record, and I/O failures.

### Usage

```rust
use tidefs_inode_table::kernel_reader::{KernelInodeTableReader, InodeRecord};

// io: &dyn KernelStorageIo
let reader = KernelInodeTableReader::new(io, table_start_sector, table_sector_count);

match reader.read_inode(1) {
    Ok(record) => {
        // record.mode, record.size, record.object_store_locator, ...
    }
    Err(KernelInodeTableError::InodeNotFound) => { /* handle */ }
    Err(KernelInodeTableError::SlotEmpty) => { /* handle */ }
    Err(_) => { /* I/O or corruption */ }
}
```

### On-disk format

Each inode record is 100 bytes, stored contiguously in the table region. Record `N` (inode `N+1`) is at byte offset `N * 100`.

```
Offset  Size  Field
0       4     magic "VINO"
4       4     mode (u32 LE)
8       4     uid (u32 LE)
12      4     gid (u32 LE)
16      8     size (u64 LE)
24      8     blocks (u64 LE)
32      8     atime_secs (u64 LE)
40      4     atime_nanos (u32 LE)
44      8     mtime_secs (u64 LE)
52      4     mtime_nanos (u32 LE)
56      8     ctime_secs (u64 LE)
64      4     ctime_nanos (u32 LE)
68      4     nlink (u32 LE)
72      8     generation (u64 LE)
80      1     kind (0=File, 1=Directory, 2=Symlink)
81      3     reserved
84      8     object_store_locator (u64 LE)
92      8     extent_map_root (u64 LE)
```

### no_std constraints

The kernel reader module is `no_std` compatible. It uses fixed-size stack buffers for sector I/O (2 sectors max per read) and `core` primitives for record decoding. The `alloc` crate is used only in tests for the `TestStorage` double.
