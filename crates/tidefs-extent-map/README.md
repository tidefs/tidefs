# tidefs-extent-map

V1 inline-list extent map implementing `ExtentMapOps` for
per-file byte-range-to-physical mapping with HOLE/UNWRITTEN/DATA tristate
semantics. Up to 6 entries per extent map; larger maps use V2 B-tree
backed by tidefs-btree.

## Representations

- **V1 InlineExtentMap**: sorted vector of up to 6 entries, O(n) per mutation.
- **V2 BTreeExtentMap**: B+tree-backed, supports larger files (up to 100K extents).
- **V3 MultiLevelBTreeExtentMap**: multi-level B+tree for huge files (>100K extents).
- **PolymorphicExtentMap**: hysteresis-based switching between V1/V2/V3.

## Kernel-Mode Extent Map Reader

Gated behind the `kernel` feature:

```toml
[dependencies]
tidefs-extent-map = { path = "...", default-features = false, features = ["kernel"] }
```

The default build enables the userspace extent-map API through the `std`
feature. Kernel-only validation disables default features so the no_std reader
surface can be checked without pulling in userspace helpers.

### `ExtentMapKernelReader`

A `no_std`-compatible reader that traverses on-disk extent map B-tree pages
through `KernelStorageIo`, translating logical file offsets to physical
block addresses for kernel VFS read and write dispatch.

```rust,ignore
use tidefs_extent_map::kernel::{ExtentMapKernelReader, ExtentMapping};

let reader = ExtentMapKernelReader::new(storage_io, root_page_addr, 9); // 9 = 512-byte sectors
let mapping: ExtentMapping = reader.lookup(4096)?;
// mapping.phys_addr gives the physical block address
// mapping.is_hole tells the caller to read zeros
```

### API

| Method | Description |
|--------|-------------|
| `new(io, root_page_addr, sector_shift)` | Create a reader for the given root page |
| `lookup(logical_offset) -> Result<ExtentMapping, Errno>` | Find the extent covering the offset |

### `ExtentMapping` fields

- `phys_addr: u64` — physical byte address on the block device
- `length: u64` — extent length in bytes
- `logical_offset: u64` — logical file offset
- `logical_end: u64` — logical end (offset + length)
- `compression: u8` — compression hint
- `extent_kind: u8` — 0=DATA, 1=UNWRITTEN
- `locator_id: LocatorId` — physical storage locator
- `is_hole: bool` — true when no physical storage backs this range

### On-disk format

Pages are 4096 bytes with a 54-byte header (magic "EXMP"), BLAKE3-256
checksum over header prefix + body, and either leaf entries (89-byte
`ExtentMapEntryV2` records) or internal node child/page pointers.
See `kernel.rs` for the full format specification.

### Constraints

- Requires `KernelStorageIo` from `tidefs-kernel-storage-io`
- Returns `Errno::EIO` on page corruption, checksum mismatch, or I/O failure
- Zero-allocations after construction; uses a single 4096-byte scratch buffer
  plus a recursive call stack
