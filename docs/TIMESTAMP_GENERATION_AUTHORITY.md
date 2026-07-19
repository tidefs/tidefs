# Timestamp and Generation Authority

Maturity: design authority for TFR-005; produced under GitHub issue #499.
Recovery-generation drift contract narrowed under GitHub issue #694.
Supersedes the guardrail version from issue #325.

This document specifies one authority model for POSIX wall-clock timestamps,
VFS inode generations, transaction group (txg / commit group) identifiers,
content object versions, scrub identity, replay ordering, format versions, and
the namespace revision counters `subtree_rev` / `dir_rev`. It names the owning
crate for each concept, defines monotonicity and wraparound rules, maps
cross-authority relationships, and records the on-disk format compatibility
contract for version field changes.

This is a planning/design authority document. It does not claim production
readiness and does not close TFR-005.

## 1. Crate-to-Concept Ownership Matrix

Each concept has exactly one defining crate. The defining crate owns the type,
the construction/validation invariants, and the serialized representation.
Callers that consume a concept must go through the defining crate's public API.

| Concept                          | Defining crate                     | Primary type / constant                         |
|----------------------------------|------------------------------------|--------------------------------------------------|
| POSIX wall-clock timestamp       | `tidefs-types-vfs-core`            | `PosixTimestampNs`, `split_posix_time_ns`, `compose_posix_time_ns` |
| POSIX timestamp record group     | `tidefs-local-filesystem`          | `PosixTimeRecord` (atime/mtime/ctime/btime_ns)   |
| POSIX setattr timestamp planning | `tidefs-inode-attributes`          | `PosixTimestampAction`, `SetattrTimestampUpdate` |
| VFS inode/file-handle generation | `tidefs-types-vfs-core`            | `Generation`                                     |
| Transaction group identifier     | `tidefs-commit_group`              | `CommitGroupId`                                  |
| Content object version           | `tidefs-local-filesystem`          | `data_version: u64` on `InodeRecord`             |
| Metadata version                 | `tidefs-local-filesystem`          | `metadata_version: u64` on `InodeRecord`         |
| Namespace subtree revision       | `tidefs-types-vfs-core`            | `InodeAttr::subtree_rev: u64`                    |
| Namespace directory revision     | `tidefs-types-vfs-core`            | `InodeAttr::dir_rev: u64`                        |
| Scrub block identity             | `tidefs-local-filesystem`          | `ScrubBlockId` (inode_id + data_version + kind)  |
| On-disk format version           | `tidefs-local-filesystem`          | `FILESYSTEM_FORMAT_VERSION` (u16, currently 6)   |
| Content dedup redirect version   | `tidefs-local-filesystem`          | `CONTENT_DEDUP_REDIRECT_FORMAT_VERSION` (u16, 1) |
| Object store format manifest     | `tidefs-local-object-store`        | `LocalObjectStoreFormatManifest`                 |
| Pool label version               | `tidefs-pool-import`               | label `version` field (u16, currently 1)         |
| Committed-root version           | `tidefs-commit_group`              | version discriminant in root entry header (V1)   |
| Dataset feature flags            | `tidefs-dataset-feature-flags`     | per-dataset B-trees, `org.tidefs:<name>` keys    |
| Intent-log record version        | `tidefs-intent-log` / `tidefs-commit_group` | version discriminant in intent-log frame header |

### 1.1 Ownership Rules

- The defining crate publishes the canonical constructor, accessor, and
  comparison functions. Other crates may use the type but must not invent
  constructors that bypass the defining crate's invariants.
- A raw `u64` or `i64` passed across crate boundaries is not authority. The
  defining crate's named type or named accessor must appear at the boundary.
- When a concept appears in multiple crates (e.g., `data_version` is both
  serialized by `tidefs-local-filesystem` encoding and consumed by
  `tidefs-scrub-core` scrub identity), the defining crate is the one that
  owns the storage record and encoding format.

## 2. Monotonicity, Wraparound, and Epoch Rules

### 2.1 POSIX Wall-Clock Timestamps (`PosixTimestampNs`)

- **Domain**: `i64`, nanoseconds since 1970-01-01T00:00:00Z (UNIX epoch).
- **Monotonicity**: Not guaranteed. POSIX time can move backward (clock
  adjustment, NTP step, suspend/resume). Callers must not rely on POSIX
  timestamp ordering for correctness.
- **Wraparound**: The `i64` range covers roughly +/-292 years from the epoch.
  Wraparound is not a practical concern, but saturating helpers
  (`compose_posix_time_ns`) clamp subsecond overflow defensively.
- **Epoch**: UNIX epoch (1970-01-01T00:00:00Z). Negative values represent
  pre-1970 timestamps.
- **Authority boundary**: `current_posix_time_ns()` in
  `tidefs-local-filesystem` samples `std::time::SystemTime::now()` and
  saturates to `i64::MAX` on overflow. This is the single wall-clock source
  for the local filesystem; all POSIX timestamp writes go through this or
  through explicit caller-supplied values.

### 2.2 VFS Inode Generation (`Generation`)

- **Domain**: `u64`.
- **Monotonicity**: Strictly monotonic for file-handle identity changes on a
  given inode id. A new or reconstructed VFS identity must not reuse the same
  `(inode_id, generation)` pair for a different inode lifetime. Ordinary
  content writes, POSIX timestamp updates, link-count changes, xattr changes,
  and namespace mutations that keep the same VFS file-handle identity do not
  use `generation` as their freshness token; they advance `data_version` and/or
  `metadata_version` instead.
- **Wraparound**: `checked_next()` returns `None` at `u64::MAX`. In practice,
  wraparound is not reached within the lifetime of a single mount.
- **Epoch**: No epoch. `Generation::ZERO` (0) is the sentinel value before a
  durable VFS file-handle identity generation is assigned. Persisted
  local-filesystem records normally use a nonzero generation when the inode is
  created or reconstructed.
- **Authority boundary**: `Generation::new()` and
  `Generation::from_vfs_generation()` in `tidefs-types-vfs-core` are the
  only valid constructors.

### 2.3 Transaction Group Identifier (`CommitGroupId`)

- **Domain**: `u64`.
- **Monotonicity**: Strictly monotonic across a mount lifetime. Starts at 1
  (`CommitGroupId::FIRST`) and increments by 1 per committed transaction
  group.
- **Wraparound**: `next()` saturates at `u64::MAX`. The nil value (0,
  `CommitGroupId::NIL`) represents "no open commit group."
- **Epoch**: Each mount starts a fresh txg sequence at 1. The txg counter is
  not preserved across unmount/remount; recovery replays the journal to
  determine the last committed txg and resumes from `last_txg + 1`.
- **Persistence**: `CommitGroupId` is persisted in the commit_group journal
  header, superblock, and committed-root entries for replay.
- **Authority boundary**: `CommitGroupId` constructors and `next()` in
  `tidefs-commit_group/src/types.rs`.

### 2.4 Content Object Version (`data_version`)

- **Domain**: `u64`.
- **Monotonicity**: Monotonically increasing per inode. Each content write
  that produces a new object allocates a fresh `data_version` (typically the
  current txg tick). An inode with no content has `data_version == 0`.
- **Wraparound**: `data_version` is bounded by `u64`. No explicit wraparound
  guard exists; design expects `u64` range to exceed practical inode write
  counts.
- **Relationship to txg**: During normal operation, `data_version` advances
  to the current `CommitGroupId` tick on content write. During crash
  recovery, `data_version` is set to the recovery generation tick.
- **Authority boundary**: Owned by `tidefs-local-filesystem`; encoded in
  `InodeRecord`, `ContentManifest`, and `ContentChunk` serialization.
  Consumed by object key generation (`content_object_key_for_version`) and
  scrub identity (`ScrubBlockId.data_version`).

### 2.5 Metadata Version (`metadata_version`)

- **Domain**: `u64`.
- **Monotonicity**: Monotonically increasing per inode. Advanced on metadata
  mutations (setattr, link/unlink, rename, xattr changes) that do not
  necessarily change content.
- **Wraparound**: Same as `data_version` (bounded by `u64`).
- **Resolved coupling (issue #688)**: `InodeRecord::to_inode_attr()` no longer projects
  `metadata_version` into `subtree_rev` or `dir_rev`. Both counters are now
  persisted and projected independently from their own stored fields.
- **Authority boundary**: Owned by `tidefs-local-filesystem`; serialized in
  `InodeRecord`.

### 2.6 Namespace Revision Counters (`subtree_rev`, `dir_rev`)

- **Domain**: `u64` each.
- **Monotonicity**: Both are monotonically increasing per inode.
  `subtree_rev` advances on any attribute or content change; `dir_rev`
  advances on directory entry mutations (create, unlink, rename within that
  directory). Non-directory inodes keep `dir_rev == 0`.
- **Wraparound**: Bounded by `u64`. Saturation at advance sites
  (`.saturating_add(1).max(1)`).
- **Epoch**: Initial value is 0 for new inodes.
- **Authority boundary**: Defined in `tidefs-types-vfs-core` as fields on
  `InodeAttr`. As of issue #688, the local filesystem projects both counters
  from their own stored `InodeRecord` fields, persisted via a backward-compatible
  tail extension in the encode/decode path. The coupling to `metadata_version`
  described in section 9.1 is resolved.
- **Ownership**: `tidefs-types-vfs-core` owns the field definitions.
  `tidefs-local-filesystem` drives the values through
  stored `subtree_rev` and `dir_rev` counters, which are incremented
  independently of `metadata_version` (see `advance_subtree_revision` and
directory entry mutation paths).

### 2.7 Scrub Block Identity (`ScrubBlockId`)

- **Domain**: `(inode_id: u64, data_version: u64, kind: ScrubBlockKind)`.
- **Monotonicity**: Not applicable. Scrub identity is a snapshot key, not a
  sequence.
- **Authority boundary**: Owned by `tidefs-local-filesystem/src/scrub.rs`.
  Constructed from the inode's current `data_version` at scrub time.

### 2.8 Format Versions

- **Domain**: `u16` per format family.
- **Monotonicity**: Monotonically increasing across TideFS releases. A format
  version is never decremented.
- **Wraparound**: Bounded by `u16::MAX`. Not a practical concern within the
  projected release cadence.
- **Epoch**: V1 is the first public-release format surface. Pre-V1 and
  pre-release internal versions (record versions 1-5 for the local
  filesystem) are development inputs only, not format commitments.
- **Authority boundary**: `FILESYSTEM_FORMAT_VERSION` (currently 6) in
  `tidefs-local-filesystem/src/constants.rs`. Each format family has its own
  version constant.

## 3. Cross-Authority Relationship Map

```
POSIX wall clock (PosixTimestampNs, PosixTimeRecord)
  │
  │  PROJECTED INTO (via PosixTimeRecord)
  ▼
POSIX inode timestamps (atime_ns, mtime_ns, ctime_ns, btime_ns)
  │
  │  MUST NOT DERIVE (forbidden shortcut)
  ▼
┌─────────────────────────────────────────────────────┐
│                                                     │
│  Storage / ordering authorities (separate domains)  │
│                                                     │
│  CommitGroupId (txg)                                │
│    │  -- drives -->  data_version (on write)        │
│    │  -- drives -->  metadata_version (on mutate)   │
│    │                                                │
│  data_version                                       │
│    │  -- keyed into -->  content object keys        │
│    │  -- keyed into -->  ScrubBlockId               │
│    │  -- serialized in -->  InodeRecord,            │
│    │       ContentManifest, ContentChunk            │
│    │                                                │
│  metadata_version                                   │
│    │  -- projected as -->  subtree_rev (debt)       │
│    │  -- projected as -->  dir_rev (debt)           │
│    │  -- serialized in -->  InodeRecord             │
│    │                                                │
│  Generation (VFS inode gen)                         │
│    │  -- may share -->  recovery initialization tick │
│    │       with data_version / metadata_version     │
│    │  -- serialized in -->  InodeRecord,            │
│    │       DirEntry, InodeAttr                      │
│    │                                                │
│  FILESYSTEM_FORMAT_VERSION (u16, currently 6)       │
│    │  -- gates -->  encode/decode of all records    │
│    │  -- compared on -->  every record decode       │
│    │                                                │
└─────────────────────────────────────────────────────┘
```

### 3.1 Key Relationships

**txg to data_version**: During normal writes, a new content object is stamped
with the current `CommitGroupId` as its `data_version`. This ties the object
to the transaction group that committed it, enabling replay ordering and
recovery selection.

**txg to metadata_version**: Metadata mutations (setattr, link, unlink,
rename) advance `metadata_version` to the current `CommitGroupId` tick.

**data_version to object keys**: Content object keys are derived from
`(inode_id, data_version)`. The `data_version` component ensures that each
content version has a distinct storage identity.

**data_version to scrub identity**: `ScrubBlockId` uses `data_version` to
identify which version of a content block is being checked.

 **metadata_version to subtree_rev / dir_rev (resolved, issue #688)**:
`InodeRecord::to_inode_attr()` projects both `subtree_rev` and `dir_rev` from
their own stored `InodeRecord` fields (not `metadata_version`). Both counters are
persisted via a backward-compatible encode/decode tail extension and advanced
independently of `metadata_version` (see section 9.1).

**Generation alongside data_version / metadata_version (during recovery)**:
Crash recovery may initialize `generation`, `data_version`, and
`metadata_version` from the same recovery tick when it materializes one
accepted inode record from one replay boundary. That shared tick is only a
common recovery provenance fence. It does not make the three fields the same
authority after mount. See section 3.2 for the drift contract.

**Format version to all records**: Every serialized record (inode, content
manifest, content chunk, dedup redirect, changed-record export) carries
`FILESYSTEM_FORMAT_VERSION` in its header. Decode refuses records with
versions outside `FORMAT_COMPAT_WINDOW_MIN..=FILESYSTEM_FORMAT_VERSION`.

### 3.2 Recovery-Generation Drift Contract

Recovery, intent-log replay, and commit-group replay may rebuild a complete
inode record at a single accepted replay boundary. When they do, they may stamp
the same fresh recovery tick into all three local fields:

- `generation` is the VFS file-handle identity generation. It protects the
  `(inode_id, generation)` identity observed through directory entries,
  `InodeAttr`, and file handles. It is not a content freshness counter, a POSIX
  timestamp, or a scrub row id.
- `data_version` is the content-object version. It selects the stored content
  identity through `content_object_key_for_version()` and the content chunk /
  manifest records. Scrub consumes this value through `ScrubBlockId`.
- `metadata_version` is the local metadata storage version. It orders durable
  inode metadata changes. The `subtree_rev` and `dir_rev` counters are now
  projected and advanced independently (section 9.1, resolved by issue #688).

Using one recovery tick for all three fields is allowed only while recovery is
materializing or replaying one coherent inode state. The tick is a recovery
initialization fence: it says the accepted content bytes, metadata record, and
VFS identity were rebuilt from the same replay decision. It is not an invariant
that must continue to hold after the next mounted operation.

Post-recovery drift is intentional:

- The next normal content write must allocate a fresh `data_version` for the
  new content object. It may also advance `metadata_version` when the write
  changes metadata such as size or POSIX timestamps. It must not rely on
  `generation == data_version` for content freshness.
- The next metadata-only mutation must advance `metadata_version` and leave
  `data_version` unchanged unless the operation also creates a new content or
  directory object version. It must not rely on `generation ==
  metadata_version` for metadata freshness.
- `generation` advances only when a VFS file-handle identity is newly created
  or deliberately reconstructed. Recovery-created equality between
  `generation`, `data_version`, and `metadata_version` must not be repaired or
  re-established merely because later storage versions drifted.
- Scrub must identify content by the inode's current `data_version` (or by a
  chunk reference's current `data_version` for chunked content). Scrub must
  tolerate `generation`, `data_version`, and `metadata_version` being unequal
  and must not rewrite version fields simply to restore equality.

This contract does not reopen the POSIX timestamp projection work completed by
issues #325, #330, #331, #348, and #499. POSIX `atime_ns`, `mtime_ns`,
`ctime_ns`, and `btime_ns` remain wall-clock fields and must not be
reconstructed from recovery ticks, content object versions, metadata versions,
or VFS generations.

## 4. On-Disk Format Compatibility Rules

### 4.1 Format Version Families

TideFS on-disk state is organized into independent format families, each with
its own version. TideFS has not shipped a public on-disk compatibility
contract; pre-release format handling follows `docs/UNRELEASED_AUTHORITY_POLICY.md`.
This section records the authority boundaries relevant to TFR-005.

| Format family                    | Version field                | Current | Governing doc                                    |
|----------------------------------|------------------------------|---------|--------------------------------------------------|
| Local filesystem records         | `FILESYSTEM_FORMAT_VERSION`  | 6       | This document; `encoding.rs` constants           |
| Local object store manifest      | `manifest_version`           | 1       | `format_manifest.rs`; local object-store format manifest source |
| Local object store records       | `record_format_version`      | 1-3     | `format_manifest.rs`; local object-store format manifest source |
| Pool labels                      | `version`                    | 1       | `POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md`   |
| Dataset feature flags            | per-dataset B-trees          | N/A     | `crates/tidefs-types-dataset-feature-flags-core/src/lib.rs` and source callers |
| Committed roots / intent log     | version discriminant         | V1      | Source behavior plus TFR-005/TFR-008 review register |
| Content dedup redirects          | `CONTENT_DEDUP_REDIRECT_FORMAT_VERSION` | 1 | `encoding.rs` constants                        |

### 4.2 Version Bump Rules

A format version in the local filesystem family (`FILESYSTEM_FORMAT_VERSION`)
is incremented when:

- The serialized layout of `InodeRecord`, `ContentManifest`, `ContentChunk`,
  or `ChangedRecordExport` changes (field additions, reordering, type width
  changes).
- A new required header field is added to the record framing.
- The checksum or digest algorithm for record integrity changes.
- A magic number or framing marker changes.

A format version is **not** incremented for:

- Adding an optional TLV extension field that older code can skip.
- Changing in-memory-only structures.
- Adding a feature gated behind a dataset feature flag.

### 4.3 Decode Compatibility Window

- **Current**: `FILESYSTEM_FORMAT_VERSION = 6`
- **Compatibility window**: `FORMAT_COMPAT_WINDOW_MIN = 1` (all known
  versions are accepted by the current decoder)
- **Pre-release note**: Per `docs/UNRELEASED_AUTHORITY_POLICY.md`, version
  < 5 inode records produce a clean decode error. This was enacted in issue
  #330 to remove the `legacy_from_versions` shortcut. Pre-release format
  artifacts are not product compatibility commitments.

### 4.4 Refusal Behavior

- An inode record with a version outside the compat window returns a decode
  error. The store open path surfaces this as a `CorruptState` or format
  error.
- A committed-root entry with an unknown version discriminant is quarantined
  (not replayed). The dataset is frozen at the last supported committed root.
- A pool label with an unsupported version or unknown `features_incompat`
  bits refuses import.
- A dataset with an unknown `incompat` feature flag refuses open.

### 4.5 Timestamp/Version Fields Under Format Change

When `FILESYSTEM_FORMAT_VERSION` is incremented:

- POSIX timestamp fields (`atime_ns`, `mtime_ns`, `ctime_ns`, `btime_ns`)
  maintain their `i64` nanoseconds-since-epoch representation unless a
  specific issue changes the POSIX timestamp ABI.
- `data_version` and `metadata_version` maintain their `u64` domain. Their
  semantics (monotonic, per-inode) are format-invariant.
- `Generation` maintains its `u64` VFS inode generation semantics.
- `subtree_rev` and `dir_rev` maintain their `u64` domain; they are now
  projected from their own stored fields (not `metadata_version`), persisted
  via a backward-compatible tail extension, with no serialized layout change.

## 5. Allowed Projections

- A POSIX wall-clock timestamp may be projected through
  `PosixTimestampNs::from_unix_nanos`, `PosixTimestampNs::from_split`,
  `split_posix_time_ns`, and `compose_posix_time_ns` when entering or leaving
  POSIX `*_ns` fields or Linux stat-style `(sec, nsec)` fields.
- A `SetAttr` timestamp request may write `atime_ns`, `mtime_ns`, and
  `ctime_ns` only through explicit timestamp flags or NOW flags. The NOW value
  is the caller-supplied current wall clock for that POSIX operation.
- POSIX atime/mtime updates may advance POSIX ctime when the setattr/timestamp
  rule requires it. That ctime write remains POSIX wall-clock time.
- `Generation::from_vfs_generation`, `Generation::new`,
  `Generation::as_vfs_generation`, and `Generation::checked_next` may be used
  at VFS inode/file-handle identity boundaries.
- `CommitGroupId::next()` advances the txg counter; `CommitGroupId::FIRST`
  starts a fresh mount sequence. The txg counter may be stamped into
  `data_version` and `metadata_version` at commit time.
- Storage commit/replay generation, object version, scrub identity, and format
  version may cross into POSIX or VFS inode APIs only through a named runtime
  projection documented by the owning storage issue or current policy.

## 6. Forbidden Shortcuts

- Do not derive `Generation`, `CommitGroupId`, `data_version`, scrub
  identity, or format versions from POSIX `atime_ns`, `mtime_ns`, `ctime_ns`,
  `btime_ns`, or the current wall clock.
- Do not write POSIX timestamps into storage generation or object-version
  fields as a convenient ordering token.
- Do not reconstruct POSIX timestamps from storage generations, content object
  keys, scrub row ids, replay ticks, or format-version numbers unless a named
  runtime projection issue defines and validates that conversion.
- Do not treat POSIX ctime as storage change identity. POSIX ctime is a
  metadata-change timestamp projection, not a content manifest version.
- Do not use format-version numbers as storage object generations or VFS inode
  generations.
- Do not use `CommitGroupId` values as POSIX timestamps or VFS inode
  generations.
- Do not preserve pre-release timestamp/generation coupling as compatibility
  behavior unless a current issue names a real external ABI, protocol, or
  operator-owned data set under `docs/UNRELEASED_AUTHORITY_POLICY.md`.

## 7. Shared Code Contract

`crates/tidefs-types-vfs-core` keeps `repr(C)` inode/setattr records layout
stable for this slice. The raw POSIX fields remain named `*_ns`, but shared
callers should prefer the named helpers:

- `PosixTimestampNs` for POSIX nanoseconds since the UNIX epoch.
- `split_posix_time_ns` and `compose_posix_time_ns` for POSIX timespec
  projection, including negative subsecond normalization.
- `SetAttr::set_atime_timestamp`, `SetAttr::set_mtime_timestamp`, and
  `SetAttr::set_ctime_timestamp` for explicit POSIX timestamp requests.
- `PosixAttrs::{atime,mtime,ctime,btime}_timestamp` and
  `SetAttr::{atime,mtime,ctime}_timestamp` when reading raw timestamp fields at
  authority boundaries.
- `Generation` helpers for VFS inode/file-handle identity.
- `CommitGroupId` for transaction group ordering; `CommitGroupId::NIL`,
  `CommitGroupId::FIRST`, and `CommitGroupId::next()` for lifecycle management.

`crates/tidefs-inode-attributes` timestamp planning must mutate only POSIX
timestamp fields unless the caller uses a separately named API that explicitly
updates VFS generation or revision fields. POSIX timestamp plans must preserve
`InodeAttr::generation`, `subtree_rev`, and `dir_rev`.

`crates/tidefs-commit_group` owns the txg counter lifecycle. Callers in
`tidefs-local-filesystem` stamp `data_version` and `metadata_version` from
the current `CommitGroupId` during commit, but the txg counter itself is
driven by the commit_group subsystem.

`crates/tidefs-local-filesystem/src/encoding.rs` is the single serialization
authority for `InodeRecord`, `ContentManifest`, `ContentChunk`, and
`ChangedRecordExport`. Every record encode/decode includes
`FILESYSTEM_FORMAT_VERSION` as the first field after any framing magic.

## 8. Issue #330: Local-Filesystem Runtime Projection (Partial)

Issue #330 narrows TFR-005 for the local-filesystem / local content-object
projection slice:

- **Removed**: `PosixTimeRecord::from_generation` and
  `PosixTimeRecord::legacy_from_versions`.  These methods projected storage
  generations and object versions back into POSIX timestamp fields, violating
  the authority boundary.
- **Added**: `PosixTimeRecord::synthetic(now_ns: i64)` as the named authority
  boundary for synthetic inodes and test fixtures.  The `now_ns` argument must
  be a POSIX wall-clock timestamp (typically `current_posix_time_ns()`), never
  a storage version, generation, or object key.
- **Removed**: The encoding format version < 5 decode path that used
  `legacy_from_versions` to fabricate POSIX timestamps from storage fields.
  Version < 5 inode records now produce a clean decode error per
  `docs/UNRELEASED_AUTHORITY_POLICY.md`.
- **Fixed**: `update_anonymous_size` in the VFS engine no longer derives a
  synthetic version counter from `mtime_ns`.  It uses wall-clock time for
  POSIX timestamp advancement and a separate counter for `subtree_rev`.
- **Verified**: `InodeRecord::to_inode_attr` correctly projects `posix_time`
  fields into POSIX attributes and `data_version` / `metadata_version` into
  storage identity fields.  The encode path (`encode_inode`) always writes
  explicit POSIX timestamps at format version 6.

## 9. Remaining TFR-005 Runtime Sites

These rows are the closeout map for the original section 9 sites. Each row is
classified as resolved by closed evidence, delegated to a live non-overlapping
issue family, conditional/future-only, or still-needs-prepared-issue. A
delegated or conditional row does not close TFR-005; closure still requires the
runtime owners to land and any claim evidence to support closure.

| Site | Classification | Closeout / owner |
| --- | --- | --- |
| `metadata_version` to `subtree_rev` / `dir_rev` coupling | Resolved by closed source/docs | Issues #688 and #994 split namespace revision counters from `metadata_version`. `InodeRecord::to_inode_attr()` projects from stored `subtree_rev` and `dir_rev` fields, the counters persist across encode/decode round trips, content and metadata mutation paths advance `subtree_rev` independently, directory mutation paths advance `dir_rev`, and non-directory inodes keep `dir_rev == 0`. |
| Intent-log replay and commit-group recovery | Resolved by closed decision; conditional/future-only coverage | Issue #694 recorded the recovery-generation drift contract in section 3.2. Recovery paths may initialize `generation`, `data_version`, and `metadata_version` from one accepted recovery tick, and later mounted writes intentionally let those identities diverge. No recovery source change is required merely to preserve or restore equality. A future focused issue is needed only if executable recovery/write/scrub coverage or runtime guards are added for this contract. |
| Scrub and repair identity | Delegated to live non-overlapping issue family | Issue #742 records the local scrub identity boundary: `ScrubBlockId` identifies content by `(inode_id, data_version)` and must not treat POSIX time, `metadata_version`, storage-generation ticks, or intent-log epochs as identity substitutes. Issue #650 closed the mounted content scrub-read authority slice. Issues #651 and #652 (now closed) resolved transform-aware scrub routing and repair dispatch gating while preserving this identity boundary. |
| Send/receive export/import | Resolved by closed docs/source issues | Issue #695 records that changed-record stream versions own only envelope shape, while each local record payload's local filesystem format version owns POSIX timestamp, `data_version`, and `metadata_version` layout. Issue #1002 added the focused VFSSEND1 guard coverage; related sender-authority and receive-merge follow-ups #777 and #703 are closed. Future send-stream work must preserve this rule instead of adding a timestamp/version reconciliation pass. |
| Content object reclaim and orphan cleanup | Delegated to live non-overlapping issue family | Issue #746 records `data_version` as the `(inode_id, data_version)` content identity token and names the separate reclaim liveness guard: commit-group death/stability, placement receipt epoch/generation evidence, and orphan replay watermarks. Issues #675 and #676 (now closed) resolved receipt-driven consumer policy and rebake/reclaim trims without treating `data_version` as the reclaim clock. |
| Format-golden and codec surfaces | Conditional/future-only; gate resolved by closed issue | Issue #696 made VFS codec/vector manifest drift fail in focused tooling. No source, serialized ABI, or golden-vector update is due for this document-only reconciliation. If a later slice intentionally changes serialized ABI, such as a `FILESYSTEM_FORMAT_VERSION` bump from 6 to 7, that slice must update the golden-format corpus and codec surfaces atomically with the format version change. |

Current still-needs-prepared-issue classification: none discovered by this
reconciliation. If a future audit finds implementation work outside the
delegated live families or conditional rows above, record a focused prepared
issue before editing runtime source.

## 10. Non-Claim

This document is a planning and design authority document. It does not:

- Change on-disk format or runtime behavior.
- Close TFR-005. The delegated live issue families and conditional/future-only
  rows in section 9 must be satisfied, and claims evidence must support
  closure, before TFR-005 can close.
- Claim production readiness. Production claims are gated on closing TFR-005
  and its descendant issues.
