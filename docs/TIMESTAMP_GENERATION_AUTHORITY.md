# Timestamp and Generation Authority

Maturity: current guardrail for TFR-005 and GitHub issue #325.

This document names the shared VFS and inode-attribute authority boundary for
POSIX wall-clock timestamps, VFS inode generations, storage generations,
content object versions, scrub identity, replay ordering, and format versions.
It does not rewire mounted local-filesystem runtime behavior and does not close
TFR-005.

## Authority Terms

| Authority | Current shared name | Value domain | Owns |
|---|---|---|---|
| POSIX wall-clock timestamp | `PosixTimestampNs`; raw ABI fields named `*_ns` | signed nanoseconds since the UNIX epoch | `atime_ns`, `mtime_ns`, `ctime_ns`, `btime_ns`, Linux `stat` timestamp projection, explicit and NOW-style `setattr` timestamp updates |
| VFS inode generation | `Generation` | unsigned VFS inode/file-handle generation token | VFS identity freshness for inode attributes, directory entries, and file handles |
| Transaction group / commit group / replay generation | storage runtime generation terms | storage ordering tokens | commit ordering, replay ordering, recovery selection, and storage mutation sequencing |
| Storage object version | `data_version` or named storage version fields | storage object/content version token | object key material, content-manifest identity, and storage object lifetime |
| Scrub identity | named scrub digest, block, or repair identity | integrity scan identity | the exact bytes, object, block, checksum, or repair row being checked |
| Format version | named format/canon version fields | codec and schema version numbers | decode/encode compatibility, golden-format manifests, and format admission |

The domains may share machine scalar widths, but they are different
authorities. A raw `i64` or `u64` is not enough evidence that a value belongs
to a different authority.

## Allowed Projections

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
- Storage commit/replay generation, object version, scrub identity, and format
  version may cross into POSIX or VFS inode APIs only through a named runtime
  projection documented by the owning storage issue or current policy.

## Forbidden Shortcuts

- Do not derive `Generation`, transaction groups, commit groups, replay
  generations, `data_version`, scrub identity, or format versions from
  POSIX `atime_ns`, `mtime_ns`, `ctime_ns`, `btime_ns`, or the current wall
  clock.
- Do not write POSIX timestamps into storage generation or object-version
  fields as a convenient ordering token.
- Do not reconstruct POSIX timestamps from storage generations, content object
  keys, scrub row ids, replay ticks, or format-version numbers unless a named
  runtime projection issue defines and validates that conversion.
- Do not treat POSIX ctime as storage change identity. POSIX ctime is a
  metadata-change timestamp projection, not a content manifest version.
- Do not use format-version numbers as storage object generations or VFS inode
  generations.
- Do not preserve pre-release timestamp/generation coupling as compatibility
  behavior unless a current issue names a real external ABI, protocol, or
  operator-owned data set under `docs/UNRELEASED_AUTHORITY_POLICY.md`.

## Shared Code Contract

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

`crates/tidefs-inode-attributes` timestamp planning must mutate only POSIX
timestamp fields unless the caller uses a separately named API that explicitly
updates VFS generation or revision fields. POSIX timestamp plans must preserve
`InodeAttr::generation`, `subtree_rev`, and `dir_rev`.

## Issue #330: Local-Filesystem Runtime Projection (Partial)

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
  explicit POSIX timestamps at format version 5.

### Remaining TFR-005 Runtime Sites (after issue #330)

These runtime projection sites still need owned issues, implementation, and
validation before TFR-005 can close:

- `InodeRecord::to_inode_attr()` uses `metadata_version` as both
  `subtree_rev` and `dir_rev`.  These are VFS namespace revision counters,
  not storage metadata versions; a separate namespace-revision authority is
  needed.
- Intent-log replay and commit-group recovery paths that rebuild content under
  fresh generation ticks and store those ticks into inode metadata fields
  (`data_version`, `metadata_version`).
- Scrub and repair paths that must distinguish wall-clock time, object version,
  checksum scope, and scrub row identity.
- Send/receive export/import paths that serialize timestamp and storage
  version fields through one current authority.
- Content object reclaim and orphan cleanup paths that use `data_version` as
  both a content identity token and a storage-ordering hint.
- Format-golden and codec surfaces, if a later slice intentionally changes the
  serialized ABI or golden-format shape.
