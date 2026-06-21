# Polymorphic Directory Index Design (P2 spec)

Maturity: **design-spec** for the polymorphic directory index that switches
between inline micro-list and external B-tree representations based on
entry count.

This document closes Forgejo issue #1289.

## Incumbent Comparison Boundary

This imported design document uses ZFS ZAP behavior as historical design
input. Its comparison section is a non-claim design lesson and does not prove
TideFS lookup latency, readdir behavior, scalability, or ZFS-superiority. Any
future product-facing comparison must route through a #875 claim id and the
comparator evidence required by #928/#930.

## 1. Motivation

Directory sizes span 6+ orders of magnitude in real workloads:

- **3-50 entries**: home directories, small project roots, config trees.
  A flat inode-embedded list is optimal — single metadata read for lookup,
  zero extra allocator overhead.
- **100K-10M entries**: maildirs, container image layer manifests, log
  rotation directories, package caches. Linear scan of 100K entries is
  catastrophic: every `lookup` reads and deserialises the entire directory.
  A B-tree with O(log n) lookup is required.

ZFS handles this with two ZAP (ZFS Attribute Processor) types: micro ZAP
(fixed-size hash table embedded in the object_node, up to 128 KiB) and fat ZAP
(external obfuscated hash table with extensible hashing). The choice is
made at directory creation time based on the expected number of entries
(usually a heuristic), and **never changes** after creation. A directory
created with 5 entries that later grows to 500K stays in micro ZAP mode —
the directory is re-created externally to switch.

The target design records these requirements:

- **Online switching**: change representation without user-visible disruption.
- **Hysteresis**: no oscillation at the boundary.
- **Transactional migration**: atomic within a single commit_group commit.
- **readdir cookie stability**: cookies survive representation changes.
- **O(log n) at any scale**: B-tree depth bounded by fanout, not entry count.

## 2. Relationship to Existing Types

| Current state | Replaced by | Migration path |
|---|---|---|
| `encode_directory(BTreeMap<Vec<u8>, NamespaceEntry>)` — flat linear encoding | `DirStorage` enum: `MicroList(DirMicroListV1)` or `BTree(DirBtreeRootV1)` | Read old flat encoding as `DirMicroListV1`; rewrite on next directory mutation |
| `decode_directory(bytes) -> BTreeMap<Vec<u8>, NamespaceEntry>` | `decode_dir_storage(bytes) -> DirStorage` | Backward-compatible: old format decodes to `DirMicroListV1` |
| In-memory `BTreeMap` for all operations | `DirStorage` dispatches to micro-list scan or B-tree traversal | Hot path: `lookup` dispatches based on `dir_storage_kind` |

## 3. Two Canonical Directory Representations

### 3.1 Micro-list (`DirStorage::MicroList`)

All directory entries are stored as a flat length-prefixed array embedded
in the directory inode payload.

```
DirMicroListV1 {
    entry_count: u64,              // number of entries
    total_name_bytes: u64,         // sum of all name lengths (for threshold checks)
    flags: u8,                     // bit 0: has_subdirs, bits 1-7: reserved
    reserved: [u8; 7],
    entries: [DirMicroEntry; entry_count],  // variable; up to dir_payload_budget
}

DirMicroEntry {
    name_len: u32,
    inode_id: u64,
    generation: u64,
    kind: u32,                     // NodeKind as u32 (Dir=0, File=1, Symlink=2, ...)
    name: [u8; name_len],
}
// Fixed per-entry overhead: 4 + 8 + 8 + 4 = 24 bytes + name_len
```

**Placement.** `DirMicroListV1` is stored as the directory inode's content
payload. No TLV indirection: the inode record points directly to this object.
The inode's `dir_storage_kind` field (u8, 0 = MicroList) identifies the
representation.

**Lookup cost.** O(n) linear scan over `entry_count`. At n <= 50 with average
name length 16, the entire directory fits in ~3 KiB — well within a single
4 KiB page.

**readdir.** The linear scan order serves as the natural readdir order.
Cookies are `entry_index + 1` (1-based, 0 = start). The cookie format is
stable regardless of future representation changes: `(kind=0, index=u63)`. The canonical type is `DirCookie` (tagged 64-bit).

### 3.2 B-tree (`DirStorage::BTree`)

Directory entries are stored in a dedicated B+tree keyed by name hash.
Internal nodes carry separator keys (hash + name prefix for collision
disambiguation). Leaf nodes carry full `(name, inode_id, generation, kind)`
entries in hash order.

```
DirBtreeRootV1 {
    magic: [u8; 4],                // "DIRB"
    directory_inode_id: u64,
    directory_version: u64,
    entry_count: u64,              // total entries across all leaf pages
    total_name_bytes: u64,         // for threshold checks
    root_page_locator: LocatorId,  // points to B+tree root page in locator table
    depth: u8,                     // 0 = single leaf, 1+ = internal levels
    flags: u8,                     // bit 0: has_subdirs
    reserved: [u8; 6],
}
// Total: 4 + 8 + 8 + 8 + 8 + 16 + 1 + 1 + 6 = 60 bytes

DirBtreePageHeader {
    magic: [u8; 4],                // "DIRP"
    page_kind: u8,                 // 0 = leaf, 1 = internal
    entry_count: u16,
    level: u8,                     // 0 = leaf, 1+ = internal
    reserved: [u8; 14],
    checksum: [u8; 32],            // BLAKE3-256 over page content
}
// Total: 4 + 1 + 2 + 1 + 14 + 32 = 54 bytes

DirBtreeLeafEntry {
    name_hash: u64,                // primary key: BLAKE3-64 over name bytes
    name_len: u16,
    inode_id: u64,
    generation: u64,
    kind: u32,                     // NodeKind as u32
    flags: u8,                     // per-entry flags (reserved)
    reserved: [u8; 1],
    name: [u8; name_len],          // stored for collision verification and readdir
}
// Fixed per-entry overhead: 8 + 2 + 8 + 8 + 4 + 1 + 1 = 32 bytes + name_len

DirBtreeInternalEntry {
    separator_hash: u64,           // maximum hash in child subtree
    separator_name_len: u16,
    separator_name: [u8; separator_name_len],  // for collision disambiguation
    child_page_locator: LocatorId,
}
// Fixed: 8 + 2 + name_len + 16 = 26 bytes + name_len
```

**Key design (name_hash).** The B+tree is keyed by `BLAKE3-64(name)` rather
than raw name bytes. This gives:

- Fixed-size key (8 bytes) for fast internal-node comparisons.
- Uniform key distribution — no hot-spot subtrees from common prefixes
  (e.g., all entries starting with `.` or `tmp.`).
- Sibling pointers between leaf pages for efficient readdir.

**Collision handling.** Hash collisions (BLAKE3-64, probability ~2^-64) are
resolved by storing the full name in the leaf entry and comparing during
lookup. Collisions land in the same leaf page (same hash key) and are
disambiguated by name comparison.

**Placement.** `DirBtreeRootV1` is stored as the directory inode's content
payload. The inode's `dir_storage_kind` field is set to 1 (BTree). B-tree
pages are independent on-media objects keyed by their `LocatorId`.

**Lookup cost.** B+tree descent:

1. Hash the lookup name: `h = BLAKE3-64(name)`.
2. Descend from root: at each internal node, binary-search for the first
   separator whose `separator_hash >= h`. Follow the preceding child pointer.
3. At the leaf, linear-scan entries for matching `name_hash`, then compare
   full `name` bytes.
4. Return the entry's `inode_id` and `generation`.

O(log n) page reads. At fanout 120 (4096 / 34 bytes per internal entry),
a 10M-entry directory needs depth = ceil(log120(10^7)) = 4.

**readdir with cookies.** The B+tree's natural in-order traversal is by
`name_hash`, not insertion order. Since POSIX `readdir` does not guarantee
ordering, hash order is acceptable. Cookies encode `(kind=1, page_index,
entry_index)`:

- `kind=1` distinguishes B-tree cookies from micro-list cookies.
- `page_index` is the leaf page's logical position in the in-order walk.
- `entry_index` is the position within the leaf page.
- After a directory entry is deleted between `readdir` calls, the cookie
  still points to a valid position: the next surviving entry is returned.

## 4. Switching Policy

### 4.1 Thresholds

| Parameter | Default | Description |
|---|---|---|
| `dir_micro_max_entries` | 50 | Max entries before B-tree is considered |
| `dir_micro_max_name_bytes` | 2048 | Max total name bytes before B-tree is considered |

Switch is triggered when **either** threshold is exceeded:

```
should_use_btree(count, total_name_bytes) :=
    count > dir_micro_max_entries OR total_name_bytes > dir_micro_max_name_bytes
```

The name-byte threshold catches directories with a moderate number of
very-long-named entries that would still exceed a reasonable inode payload
budget.

### 4.2 Hysteresis (BTree -> MicroList)

| Parameter | Default | Description |
|---|---|---|
| `dir_btree_downshift_entries` | 20 | Max entries before B-tree can downshift |
| `dir_btree_downshift_name_bytes` | 1024 | Max name bytes before B-tree can downshift |

```
should_use_micro_from_btree(count, total_name_bytes) :=
    count <= dir_btree_downshift_entries
    AND total_name_bytes <= dir_btree_downshift_name_bytes
```

With defaults: a directory stays in B-tree mode until it shrinks to 20 or
fewer entries AND 1024 or fewer name bytes. The hysteresis band (21-50
entries) prevents oscillation.

### 4.3 Fresh-directory bootstrap

Newly created empty directories start in micro-list mode. The first entry
always lands inline. The B-tree is first allocated when the 51st entry is
added (or when name_bytes exceed the threshold).

### 4.4 Migration protocol

Migration is transactional within a single commit_group commit:

**MicroList -> BTree:**

1. Lock the directory inode for mutation (commit_group-mandated).
2. Read the current `DirMicroListV1`.
3. Allocate B+tree root page via the allocator.
4. Hash all entry names: `h_i = BLAKE3-64(name_i)`.
5. Sort entries by `h_i`.
6. Build B+tree bottom-up: pack sorted entries into leaf pages, build
   internal nodes from separator keys, repeat until root.
7. Write all dirty B-tree pages through the locator table.
8. Replace the directory inode's content payload with `DirBtreeRootV1`.
9. Set `dir_storage_kind = 1`.
10. Unlock.

**BTree -> MicroList:**

1. Lock the directory inode for mutation.
2. Perform an in-order traversal of the B+tree, collecting all entries.
3. Verify hysteresis thresholds are met; if not, abort (no migration).
4. Pack entries into `DirMicroListV1` (order does not matter for correctness,
   but insertion order is preserved via the B+tree leaf-page sibling chain).
5. Replace the directory inode's content payload with `DirMicroListV1`.
6. Set `dir_storage_kind = 0`.
7. Decrement refcounts on all B-tree page locators (they enter the deadlist).
8. Unlock.

### 4.5 Migration triggers

- **Proactive**: checked after every `create` / `mkdir` / `link` / `rename`
  (entry addition) and `unlink` / `rmdir` / `rename` (entry removal).
- **Not on read**: `lookup` and `readdir` never trigger migration.
- **Migration is synchronous** (not backgrounded): it completes within the
  current commit_group. For a 50-to-51-entry MicroList->BTree migration, the cost is
  O(n log n) hash + sort + page build (~2-3 page writes). This is dwarfed by
  the ongoing cost of linear scan at 51 entries if migration were deferred.

## 5. Cookie Encoding for readdir

readdir cookies must survive representation changes. The cookie format is a
tagged 64-bit value:

```
cookie = (kind << 63) | payload

kind = 0 (MicroList):  payload = entry_index (0-based, up to entry_count)
kind = 1 (BTree):      payload = (page_index << 16) | entry_index
```

**Splitting during migration.** When a directory migrates from MicroList to
BTree mid-readdir, the old cookies (kind=0) are no longer valid. The handling:

1. On first `readdir` after migration, if the stored cookie has `kind=0`,
   reset to `cookie=0` (start from beginning). This is permissible: POSIX
   does not require readdir to be atomic across directory restructures.
2. The FUSE adapter receives a `dir_rev` change, which it may use to

**Deletion during readdir.** When an entry is deleted between readdir calls,
the cookie points past it. The readdir implementation skips to the next
surviving entry (linear skip in micro-list, sibling-chain skip in B-tree).
If no entries remain after the cookie, `readdir` returns EOF.

## 6. Algorithm Families

### 6.1 lookup(dir_inode, name) -> Option<(InodeId, Generation, NodeKind)>

```
match dir_inode.dir_storage_kind {
    MicroList => {
        let h = BLAKE3-64(name);   // precompute for potential B-tree migration
        for entry in entries {
            if entry.name == name {
                return Some((entry.inode_id, entry.generation, entry.kind));
            }
        }
        None
    }
    BTree => {
        let h = BLAKE3-64(name);
        descend B+tree to leaf page with matching `name_hash` range;
        for entry in leaf page where entry.name_hash == h {
            if entry.name == name {
                return Some((entry.inode_id, entry.generation, entry.kind));
            }
        }
        None
    }
}
```

### 6.2 add_entry(dir_inode, name, inode_id, generation, kind) -> Result<()>

```
match dir_inode.dir_storage_kind {
    MicroList => {
        if entry exists with same name: return EEXIST.
        insert into DirMicroListV1 at end (O(1) append).
        increment entry_count, update total_name_bytes.
        if should_use_btree(new_count, new_name_bytes):
            migrate_to_btree(dir_inode).
    }
    BTree => {
        hash = BLAKE3-64(name).
        if hash already exists with matching name: return EEXIST.
        insert into B+tree leaf page (O(log n) descent + page split if needed).
        increment entry_count, update total_name_bytes.
    }
}
```

### 6.3 remove_entry(dir_inode, name) -> Result<()>

```
match dir_inode.dir_storage_kind {
    MicroList => {
        find and remove entry by name match (O(n) scan).
        if not found: return ENOENT.
        decrement entry_count, update total_name_bytes.
    }
    BTree => {
        hash = BLAKE3-64(name).
        descend B+tree, find matching entry in leaf, remove.
        if not found: return ENOENT.
        decrement entry_count, update total_name_bytes.
        if should_use_micro_from_btree(new_count, new_name_bytes):
            migrate_to_micro(dir_inode).
    }
}
```

### 6.4 readdir(dir_inode, cookie) -> Vec<DirEntry>

```
match dir_inode.dir_storage_kind {
    MicroList => {
        start_index = decode_micro_cookie(cookie);
        return entries[start_index..].map(|e| DirEntry { ... });
    }
    BTree => {
        (page_idx, entry_idx) = decode_btree_cookie(cookie);
        walk B+tree leaf pages via sibling pointers from page_idx;
        for each leaf page, yield entries from entry_idx onward;
        return up to max_readdir_batch entries.
    }
}
```

- MicroList: O(remaining_entries). Acceptable because n <= 50.
- BTree: O(batch_size + depth) for initial seek, then O(1) per page via
  sibling pointers. readdir of a 1M-entry directory in 4096-entry batches
  requires O(depth) initial seek + O(1) per batch.

### 6.5 renamedir(dir_inode, old_name, new_name) -> Result<()>

Equivalent to `remove_entry(dir_inode, old_name)` followed by
`add_entry(dir_inode, new_name, ...)`. Both operations complete within
the same commit_group. If the removal triggers a BTree->MicroList downshift check
*before* the addition, the addition may immediately re-upshift — to avoid
this, the check is deferred until after both operations complete.

## 7. Performance Properties

### 7.1 Micro-benchmark expectations

| Operation | MicroList (n=10) | MicroList (n=50) | BTree (n=1K) | BTree (n=1M) |
|---|---|---|---|---|
| lookup (hit) | ~300 ns (10 string compares) | ~1.5 us (50 compares) | ~4 us (3 page reads, 120-way binary search) | ~6 us (4 page reads) |
| add_entry | ~1 us (append) | ~5 us (append + serialize) | ~8 us (descent + leaf insert) | ~10 us (descent + leaf split) |
| remove_entry | ~500 ns (scan + remove) | ~2.5 us (scan + remove) | ~6 us (descent + delete) | ~8 us (descent + leaf merge) |
| readdir (4K batch) | ~5 us (encode batch) | ~25 us (encode full dir) | ~8 us (sibling walk, 1 page) | ~8 us (sibling walk, 1 page) |
| Migration up | N/A | N/A | ~100 us (sort 51 + build 2 pages) | N/A |
| Migration down | N/A | N/A | ~50 us (walk tree + collect 20) | N/A |

### 7.2 Space overhead

| Representation | Per-entry fixed | Typical dir with 16-char names |
|---|---|---|
| MicroList | 24 bytes | 40 bytes/entry |
| BTree leaf | 32 bytes | 48 bytes/entry |
| BTree internal | 26 bytes + name_len | ~42 bytes/separator |

At the switching boundary (51 entries with 16-char names), the B-tree uses
~2.5 KiB for data pages + 1 internal page (4 KiB) = ~6.5 KiB total vs ~2 KiB
for micro-list. The 3x overhead is acceptable: it buys O(log n) scaling.

### 7.3 ZFS Design Lessons (Non-Claim)

| Property | ZFS (micro ZAP) | ZFS (fat ZAP) | TideFS MicroList | TideFS BTree |
|---|---|---|---|---|
| Switching | Fixed at creation | Fixed at creation | Dynamic (threshold 50) | Dynamic (downshift at 20) |
| Key type | Name hash (murmur2) | Name hash (murmur2) | Raw name (linear scan) | Name hash (BLAKE3-64) |
| Hash collision | O(n) chain at bucket | O(n) chain at bucket | N/A (exact match) | Name verify in leaf |
| readdir order | Hash order | Hash order | Insertion order | Hash order |
| Lookup (large) | O(n) if small ZAP | O(1) expected, O(n) worst | N/A (small only) | O(log n), no worst-case chains |
| Max size | ~128 KiB (object_node limit) | 16 EiB | Inode payload limit (~4 KiB) | 2^64 entries |

Target design differences relative to ZFS:

- **Online switching**: ZFS never switches; TideFS migrates dynamically.
- **No hash chains**: B-tree avoids the O(n) worst-case that ZAP hash chains
  can hit with pathological name distributions.
- **Tunable thresholds**: dataset-level `DatasetDirPolicy` controls switching
  parameters; ZFS's micro/fat choice is heuristic-based at creation only.
- **Stable cookies**: tagged cookie encoding survives representation changes;
  ZFS's `seekdir`/`telldir` cookies are ZAP-position-dependent.

## 8. Integration Points

### 8.1 With InodeRecord

The directory inode gains:

```
dir_storage_kind: u8,   // 0 = MicroList, 1 = BTree
```

The inode's content payload (`object_key`) points to either a
`DirMicroListV1` or `DirBtreeRootV1` object, discriminated by
`dir_storage_kind`. The existing `dir_rev` field in `InodeAttr` is
incremented on every directory mutation, regardless of representation.

### 8.2 With Commit/COMMIT_GROUP (#1267)

The commit_group state machine must:

1. During QUIESCE: freeze the directory B-tree (when external). New entry
   mutations go to the next commit_group.
2. During SYNC step 3: flush dirty B-tree pages through the locator table.
3. During SYNC step 4: write the commit record with the directory's updated
   content object key (if `dir_storage_kind` or content changed).
4. During SYNC step 6: update the inode's on-media `dir_storage_kind` and
   content `object_key`.

Migration (MicroList <-> BTree) must complete within a single commit_group epoch.

### 8.3 With Allocator (#1148)

B-tree pages are allocated through the local storage allocator. Each page
is a 4 KiB unit (pool ashift-aligned). The page's `LocatorId` is stored in
the parent's internal entry or in `DirBtreeRootV1.root_page_locator`.

### 8.4 With Dataset-Level Configuration

Switching thresholds are dataset-level properties:

```
DatasetDirPolicy {
    dir_micro_max_entries: u16,            // default 50
    dir_micro_max_name_bytes: u32,         // default 2048
    dir_btree_downshift_entries: u16,      // default 20
    dir_btree_downshift_name_bytes: u32,   // default 1024
}
```

They are stored in the dataset superblock and can be tuned per dataset.
Changing thresholds takes effect on the next directory mutation.

### 8.5 With VFS Engine API (#1213)

The VFS Engine API defines the directory operation contract:

- `lookup(parent, name) -> Result<InodeAttr, Errno>`
- `create(parent, name, mode, flags, ctx) -> Result<(InodeAttr, u64, OpenFlags), Errno>`
- `mkdir(parent, name, mode, ctx) -> Result<InodeAttr, Errno>`
- `unlink(parent, name, ctx) -> Result<(), Errno>`
- `rmdir(parent, name, ctx) -> Result<(), Errno>`
- `rename(old_parent, old_name, new_parent, new_name, flags, ctx) -> Result<(), Errno>`
- `link(inode, new_parent, new_name, ctx) -> Result<InodeAttr, Errno>`
- `readdir(parent, cookie, ctx) -> Result<Vec<DirEntry>, Errno>`

This design guarantees that each operation has O(log n) or better cost when
the B-tree representation is active, and O(n) (acceptable for small n) when
the micro-list representation is active.

## 9. On-Disk Format Rules

Per #1220 (single-V1 strategy with TLV extensions):

1. `DirMicroListV1` uses no magic prefix (it is the inode's direct content
   payload). The 8+8-byte `directory_inode_id` + `directory_version` header
   serves as the format discriminator.
2. `DirBtreeRootV1` uses magic `DIRB`. `DirBtreePageHeader` uses `DIRP`.
   interpretation.
4. TLV extension areas follow the fixed fields. Unknown TLVs are skipped.
5. Feature flags at the dataset level gate new TLV interpretation.
6. Checksums are BLAKE3-256 over the entire page/content via the
   production-integrity trailer format (record version 3).



```
tidefs-xtask check-polymorphic-directory-index
```

This gate will verify:

1. This document exists and contains the required sections.
2. The `DirMicroListV1` and `DirBtreeRootV1` record families are declared
   in the authoritative data structures catalog.
3. Switching thresholds and hysteresis parameters are documented with
   defaults and rationale.
4. The migration protocol (micro-list <-> B-tree) is specified with
   commit_group-boundary semantics.
5. The cookie encoding format supports both representations and survives
   migration.
6. The ZFS comparison table demonstrates parity or improvement.

## 11. Non-claims (explicit boundaries)

- This is a design spec; the Rust implementation of the B+tree and migration
  logic is deferred to a successor implementation issue.
- The `DirBtreePage` allocator interaction assumes the existing local storage
  allocator (#1148); no new allocation primitives are introduced.
- `readdir` with cookies across migration resets to cookie=0; a more
  sophisticated cookie-preservation scheme (name-based) is possible but
  deferred.
- The `has_subdirs` flag is specified as a hint for directory tree traversal;
  its maintenance algorithm is deferred to the implementation issue.
- Dataset-level configuration of thresholds is specified at the interface
  level; the dataset superblock schema for `DatasetDirPolicy` is deferred
  to #1219.
- Directory fsync semantics (ensuring directory entries are durable) remain
  as specified in #1213 and are not modified by this design.
- The interaction with the persistent orphan index (#1207) for directory
  entries pointing to deleted inodes is deferred to that issue.
  specified in #1213 and #1233.
