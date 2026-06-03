# Polymorphic Xattr Storage Design (P2 spec)

Maturity: **design-spec** for the polymorphic xattr storage scheme that
selects between inline packing and a separate B-tree based on xattr count
and size.

This document closes Forgejo issue #1290.

## 1. Motivation

xattr storage faces a bimodal distribution in real-world filesystem workloads:

- **Common case (0-3 small xattrs).** Most files carry a handful of xattrs:
  `system.posix_acl_access`, `system.posix_acl_default`, `security.selinux`,
  and occasionally `user.*` tags. Together they rarely exceed 1 KiB. Storing
  these inline in the inode record avoids extra metadata reads.
- **Large case (dozens to hundreds of xattrs).** Container images, backup
  tools, and user-space databases can attach tens or hundreds of xattrs,
  collectively exceeding tens of KiB. Inline storage bloats the inode record,
  increases read-modify-write cost on every metadata mutation, and wastes
  space.

ZFS handles this with the same mechanism: `znode_phys_t` embeds a
fixed-size xattr array inline; when the array overflows, xattrs spill into
a separate hidden ZAP object. The threshold and spill/upspill logic is
hardcoded and coupling is tight.

TideFS must match or exceed that behaviour while keeping the design
principled. This means:

- Explicit, configurable switching thresholds (count and byte budget).
- Hysteresis to prevent oscillation at the boundary.
- Transactional migration between representations within a single commit_group commit.
- ACL semantics unchanged regardless of storage representation.
- O(log n) lookup for the large-xattr case.

## 2. Relationship to Existing Types

| Current state | Replaced by | Migration path |
|---|---|---|
| `InodeRecord.xattrs: BTreeMap<Vec<u8>, Vec<u8>>` (flat inline) | `XattrStorage` enum: `Inline(XattrBundle)` or `External(XattrBtreeRoot)` | Read old flat encoding; write grouped TLV on next xattr mutation |
| TLV `xattrs_bundle` (proposed v0.262, not yet authoritative) | `XattrBundleV1` record with fixed header + length-prefixed entries | Inline case: re-encode into formal `XattrBundleV1` |
| TLV `xattr_root_ptr` (proposed v0.262, not yet authoritative) | `XattrBtreeRootV1` locator pointing into `XattrBtreePage` chain | External case: formalise locator + root page format |

## 3. Two Canonical Xattr Representations

### 3.1 Inline packing (`XattrStorage::Inline`)

All xattrs are stored as length-prefixed `(name, value)` pairs within a
single `XattrBundleV1` record embedded in the inode TLV tail.

```
XattrBundleV1 {
    magic: [u8; 4],            // "XATB"
    entry_count: u16,          // number of (name, value) pairs
    total_value_bytes: u32,    // sum of all value lengths (for threshold checks)
    flags: u8,                 // bit 0: contains_acl, bits 1-7: reserved
    reserved: [u8; 5],
    entries: [XattrInlineEntry; entry_count],  // variable; up to inode_payload_budget
}

XattrInlineEntry {
    name_len: u16,
    value_len: u32,
    name: [u8; name_len],
    value: [u8; value_len],
}
// Fixed per-entry overhead: 2 + 4 = 6 bytes + name_len + value_len
```

**Placement.** The `XattrBundleV1` record is stored as a TLV extension in the
inode record. The TLV tag is `xattrs_bundle = 0x0A10`. The inode's
`xattr_storage_kind` field (u8, 0 = Inline) identifies the representation.

**Lookup cost.** O(n) scan over `entry_count` entries. For the common case
(n <= 16), this is a single-cacheline linear walk.

### 3.2 Separate B-tree (`XattrStorage::External`)

xattrs are stored in a dedicated B-tree keyed by `(name_bytes)`, with values
stored in the leaf pages.

```
XattrBtreeRootV1 {
    magic: [u8; 4],            // "XATR"
    entry_count: u64,          // total xattr count across all leaf pages
    total_value_bytes: u64,    // for threshold checks
    root_page_locator: LocatorId,  // points to root page in locator table
    depth: u8,                 // 0 = single leaf, 1+ = internal levels
    flags: u8,                 // bit 0: contains_acl
    reserved: [u8; 6],
}
// Total: 4 + 8 + 8 + 16 + 1 + 1 + 6 = 44 bytes

XattrBtreePageHeader {
    magic: [u8; 4],            // "XATP"
    page_kind: u8,             // 0 = leaf, 1 = internal
    entry_count: u16,
    level: u8,                 // 0 = leaf, 1+ = internal
    checksum: [u8; 32],        // BLAKE3-256 over page content
    reserved: [u8; 14],
}
// Total: 4 + 1 + 2 + 1 + 32 + 14 = 54 bytes

XattrBtreeLeafEntry {
    name_len: u16,
    value_len: u32,
    flags: u8,                 // per-xattr flags (e.g., trusted namespace)
    reserved: [u8; 1],
    name: [u8; name_len],
    value: [u8; value_len],
}
// Fixed per-entry overhead: 2 + 4 + 1 + 1 = 8 bytes + name_len + value_len

XattrBtreeInternalEntry {
    name_len: u16,
    name: [u8; name_len],      // separator key
    child_page_locator: LocatorId,
}
// Fixed: 2 + name_len + 16 = 18 bytes + name_len
```

**Placement.** The `XattrBtreeRootV1` record is stored as the inode TLV
`xattr_root_ptr = 0x0A11`. The inode's `xattr_storage_kind` field is set to 1
(External). Xattr B-tree pages are stored as independent on-media objects
keyed by their `LocatorId`.

**Lookup cost.** O(log n) B-tree traversal. At fanout 64 (page size 4096 /
~64 bytes per internal entry), 3-4 page reads for n <= 262,144.

## 4. Switching Policy

### 4.1 Thresholds

Two independent thresholds gate the migration decision:

| Parameter | Default | Description |
|---|---|---|
| `xattr_inline_max_count` | 16 | Max inline entries before tree is considered |
| `xattr_inline_max_bytes` | 4096 | Max total inline value bytes before tree is considered |

The switch is triggered when **either** threshold is exceeded:

```
should_use_tree(count, total_bytes) :=
    count > xattr_inline_max_count OR total_bytes > xattr_inline_max_bytes
```

### 4.2 Hysteresis (Tree -> Inline)

Oscillation at the boundary is prevented by requiring the tree-to-inline
migration to pass a stricter re-entry check:

| Parameter | Default | Description |
|---|---|---|
| `xattr_tree_downshift_count` | 8 | Max entries before tree can downshift to inline |
| `xattr_tree_downshift_bytes` | 2048 | Max total value bytes before tree can downshift |

```
should_use_inline_from_tree(count, total_bytes) :=
    count <= xattr_tree_downshift_count AND total_bytes <= xattr_tree_downshift_bytes
```

With defaults: once a file has 16 xattrs, it stays in tree mode until the
count drops to 8 or fewer and the total byte size drops below 2048. This
creates a stable band between 9-16 entries where neither transition fires.

### 4.3 Fresh-file bootstrap

Newly created files with no xattrs are always inline. On first xattr set:

- If the inline thresholds are not exceeded after the set, stay inline.
- If the set would exceed a threshold, pre-allocate the B-tree and insert
  directly into it (no inline-to-tree migration for the first entry).

### 4.4 Migration protocol

Migration between representations must be transactional within a single commit_group
commit:

**Inline -> Tree:**

1. Lock the inode for xattr mutation (commit_group-mandated).
2. Read the current `XattrBundleV1` from the inode.
3. Allocate B-tree root page via the allocator.
4. Insert all entries from the bundle into leaf pages (batch insert, page
   splits as needed).
5. Write all dirty B-tree pages through the locator table.
6. Replace the inode TLV: remove `xattrs_bundle` (0x0A10), insert
   `xattr_root_ptr` (0x0A11) with the new `XattrBtreeRootV1`.
7. Set `xattr_storage_kind = 1`.
8. Unlock.

**Tree -> Inline:**

1. Lock the inode for xattr mutation.
2. Traverse the B-tree, collecting `(name, value)` pairs into a flat list.
3. Verify hysteresis thresholds are met; if not, abort (no migration).
4. Encode entries into a new `XattrBundleV1`.
5. Insert `xattrs_bundle` TLV into inode, remove `xattr_root_ptr` TLV.
6. Set `xattr_storage_kind = 0`.
7. Decrement refcounts on all B-tree page locators (they enter the deadlist).
8. Unlock.

### 4.5 Migration triggers

- **Proactive**: checked after every `setxattr` / `removexattr` mutation.
- **Not on read**: `getxattr` / `listxattr` never trigger migration.

## 5. POSIX ACL Integration

### 5.1 ACLs as regular xattrs

`system.posix_acl_access` and `system.posix_acl_default` are stored as regular
xattrs. No special path: they participate in the same switching policy as any
other xattr.

### 5.2 ACL evaluation path

The ACL evaluation path (`tidefs-acl-eval` engine, #1199) must:

1. Call `getxattr(inode, "system.posix_acl_access")` regardless of storage
   representation.
2. If not present, fall back to mode bits.
3. If the xattr is stored externally (B-tree), the `getxattr` path traverses
   the B-tree transparently.

This decouples ACL evaluation from storage layout. The ACL codec (#1199) is
responsible for encoding/decoding the ACL binary format; this design only
guarantees that `getxattr`/`setxattr` work consistently regardless of which
representation is active.

### 5.3 Switching invariants

- An xattr migration (inline <-> tree) must not change the byte content of
  any ACL xattr. The bytes returned by `getxattr` before and after migration
  must be identical.
- The `contains_acl` flag (bit 0 in both `XattrBundleV1.flags` and
  `XattrBtreeRootV1.flags`) is set whenever `system.posix_acl_access` or
  `system.posix_acl_default` is present. This allows the ACL evaluation path
  to skip xattr reads entirely when the flag is clear.

## 6. Algorithm Families

### 6.1 getxattr(inode, name) -> Option<Vec<u8>>

```
match inode.xattr_storage_kind {
    Inline  => linear scan XattrBundleV1 for matching name,
    External => B-tree point lookup by name,
}
```

- Inline: O(n) where n = entry_count, single inode read.
- External: O(log n) B-tree traversal, 3-4 page reads typical.

### 6.2 setxattr(inode, name, value, flags)

```
match inode.xattr_storage_kind {
    Inline => {
        if exists(name):
            replace inline entry in XattrBundleV1 (read-modify-write).
        else:
            insert inline entry.
        if should_use_tree(new_count, new_total_bytes):
            migrate_to_tree(inode).
    }
    External => {
        B-tree insert-or-replace by name.
        if should_use_inline_from_tree(new_count, new_total_bytes):
            migrate_to_inline(inode).
    }
}
```

`XATTR_CREATE` and `XATTR_REPLACE` flag semantics are enforced before the
insertion.

### 6.3 removexattr(inode, name)

```
match inode.xattr_storage_kind {
    Inline => {
        remove entry from XattrBundleV1.
    }
    External => {
        B-tree delete by name.
        if should_use_inline_from_tree(new_count, new_total_bytes):
            migrate_to_inline(inode).
    }
}
```

If the name does not exist, `ENODATA` is returned regardless of storage
representation.

### 6.4 listxattr(inode) -> Vec<Vec<u8>>

Returns all xattr names in alphabetical order.

```
match inode.xattr_storage_kind {
    Inline  => collect all names from XattrBundleV1, sort.
    External => B-tree in-order traversal, names are already sorted by key.
}
```

- Inline: O(n log n) for sort (n is small, typically <= 16).
- External: O(n) in-order walk.

## 7. Performance Properties

| Operation | Inline (n=3) | External (n=100) | ZFS comparison |
|---|---|---|---|
| getxattr (hit) | 1 inode read, O(3) scan | ~3 B-tree page reads, O(log 100=7) | ~1-3 IOs (inline/spill) |
| setxattr (new) | 1 inode RMW | ~3 page reads + 1 write | comparable |
| listxattr | 1 inode read + sort(3) | in-order B-tree walk (~2 pages) | comparable |
| removexattr | 1 inode RMW | ~3 page reads + 1 delete | comparable |
| Migration inline->tree | N/A (long tail) | O(n) batch insert (~2 page writes per 64 entries) | ZFS spill: O(n) copy to hidden ZAP |
| Migration tree->inline | N/A (short tail) | O(n) collect + 1 inode write | ZFS unspill: O(n) copy from hidden ZAP |

### 7.1 Worst-case analysis

- **inline_max_count = 16**: worst-case inline lookup is 16 string comparisons,
  fitting in a single 4096-byte inode payload. No pathological regressions.
- **External with n=100,000**: B-tree depth at fanout 64 is
  ceil(log64(100000)) = 4. Each getxattr reads 4 pages. Acceptable for a
  rare workload.

### 7.2 Compared to ZFS

ZFS xattr storage has two modes:

- **Inline (SA xattrs)**: stored in the System Attribute area of the object_node.
  Limited to ~2 KiB total. Lookup is O(1) (indexed by attribute number).
- **Spill (dir-based)**: stored in a hidden directory object. Lookup is O(log n)
  via ZAP micro/large.

TideFS matches this bimodal pattern but improves on it:

- Inline uses variable-length entries rather than fixed slots, so small
  xattrs waste less space.
- The switching policy is tunable (thresholds are dataset-level properties,
  not compile-time constants).
- Hysteresis prevents oscillation, which ZFS's fixed SA layout avoids only
  by not having a dynamic spill-back path at all (ZFS xattrs never spill back
  to SA).
- Migration is transactional within a single commit_group, not spread across
  multiple IOs without atomicity guarantees.

## 8. Integration Points

### 8.1 With InodeRecord

The `InodeRecord` gains:

```
xattr_storage_kind: u8,  // 0 = Inline, 1 = External
xattr_bundle: Option<XattrBundleV1>,       // when kind = 0
xattr_btree_root: Option<XattrBtreeRootV1>, // when kind = 1
```

These fields are serialized as TLVs in the inode record tail:

- `xattrs_bundle` (tag 0x0A10): present when `xattr_storage_kind == 0`.
- `xattr_root_ptr` (tag 0x0A11): present when `xattr_storage_kind == 1`.

Exactly one of the two TLVs must be present when `xattr_count > 0`. When
`xattr_count == 0`, neither TLV is present.

### 8.2 With Commit/COMMIT_GROUP (#1267)

The commit_group state machine must:

1. During QUIESCE: freeze the xattr B-tree (when external). New xattr
   mutations go to the next commit_group.
2. During SYNC step 3: flush dirty xattr B-tree pages through the locator
   table.
3. During SYNC step 4: write the commit record with the inode's updated
   `xattr_btree_root.root_page_locator` (if changed).
4. During SYNC step 6: update the inode's on-media xattr TLVs.

Migration (inline <-> tree) must complete within a single commit_group epoch.
Partial migration (crash halfway) is rolled back: the commit_group commit is
all-or-nothing.

### 8.3 With Allocator (#1148)

Xattr B-tree pages are allocated through the local storage allocator. Each
page allocation returns a `(device_id, physical_offset, physical_length)`.
The page is written and its `LocatorId` is stored in the parent page's
`XattrBtreeInternalEntry.child_page_locator` or in `XattrBtreeRootV1`.

Page size is the pool's `ashift`-aligned minimum allocation unit (default
4096 bytes). Large xattr values that exceed one page are stored as
fragmented entries across multiple pages (keyed by `(name, fragment_index)`),
though this is rare: a single xattr must exceed ~4080 bytes to require
fragmentation.

### 8.4 With Dataset-Level Configuration

The switching thresholds are dataset-level properties, not compile-time
constants:

```
DatasetXattrPolicy {
    xattr_inline_max_count: u16,           // default 16
    xattr_inline_max_bytes: u32,           // default 4096
    xattr_tree_downshift_count: u16,       // default 8
    xattr_tree_downshift_bytes: u32,       // default 2048
}
```

They are stored in the dataset superblock and can be tuned per dataset at
creation time. Changing thresholds on an existing dataset takes effect on
the next xattr mutation (no bulk migration of existing xattrs).

## 9. On-Disk Format Rules

Per #1220 (single-V1 strategy with TLV extensions):

1. `XattrBundleV1` uses magic `XATB` for page-level identification.
2. `XattrBtreeRootV1` uses magic `XATR`, `XattrBtreePageHeader` uses `XATP`.
   interpretation.
4. TLV extension areas follow the fixed fields in `XattrBundleV1` and
   `XattrBtreePageHeader`. Unknown TLVs are skipped.
5. Feature flags at the dataset level gate new TLV interpretation.
6. Checksums are BLAKE3-256 over the entire page/content via the
   production-integrity trailer format (record version 3).



```
tidefs-xtask check-polymorphic-xattr-storage
```

This gate will verify:

1. This document exists and contains the required sections.
2. The `XattrBundleV1` and `XattrBtreeRootV1` record families are declared
   in the authoritative data structures catalog.
3. Switching thresholds and hysteresis parameters are documented with
   defaults and rationale.
4. The migration protocol (inline <-> tree) is specified with commit_group-boundary
   semantics.
5. ACL evaluation path independence from storage representation is
   documented.
6. The ZFS comparison table demonstrates parity or improvement.

## 11. Non-claims (explicit boundaries)

- This is a design spec; the Rust implementation of the B-tree and migration
  logic is deferred to a successor implementation issue.
- The `XattrBtreePage` allocator interaction assumes the existing local
  storage allocator (#1148); no new allocation primitives are introduced.
- Fragmentation of oversized xattr values (>1 page) is specified at the
  interface level; the implementation detail of multi-page xattr values is
  deferred.
- The `contains_acl` flag is specified as a hint for ACL evaluation (#1199);
  the ACL codec itself is out of scope.
- Dataset-level configuration of thresholds is specified at the interface
  level; the dataset superblock schema for `DatasetXattrPolicy` is deferred
  to #1219.
- The `trusted.*` and `security.*` namespace enforcement is deferred to the
  VFS Engine API contract (#1213), which owns the capability-check surface.
- The inode TLV tag allocation (0x0A10, 0x0A11) is provisional and must be
  confirmed against the authoritative inode TLV registry.
