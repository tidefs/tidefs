# VfsEngine-Boundary Trace Emission Contract: JSONL Format, Allowed Nondeterminism, Cross-Implementation Comparison

**Issue**: [#1235](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1235)
**Status**: design-spec
**Priority**: P2
**Layer**: 11 (Export)

## Abstract

This document defines the formal contract for trace emission at the [`VfsEngine`][VfsEngine]
API boundary — issue #1213's 29-operation contract. Every call to a `VfsEngine` operation
is recorded as a trace step in JSONL format, producing the canonical regression oracle for
cross-implementation (Python vs Rust) semantic equivalence.

The contract explicitly enumerates allowed nondeterminism (timestamps, inode allocation,
generation numbers, handle IDs) and deterministic fields (errno, mode, size, extent layout,
directory sets, statfs, xattrs, ACLs, fiemap, SEEK results, lock state). It defines golden
vectors for individual record codecs and the cross-implementation comparison protocol.

per issue #1250, complementing the on-media format (Contract 1) and the VFS semantic
contract (Contract 2, #1213).

## Relationship to other issues

| Issue | Role | Dependency |
|---|---|---|
| #1213 | VFS Engine API contract | This doc describes trace emission at that exact boundary |
| #1174 | Trace corpus (golden traces, minimization, cross-backend comparison) | This doc defines the format and contract that #1174's corpus exercises |
| #1185 | Golden vectors for individual record codecs | Golden vectors complement operation-level traces described here (§5) |
| #1230 | Crash injection harness | Crash tests are trace-replayable (§7) |
| #1250 | Three-contract organizing principle | This is Contract 3 |

---

## 1. Trace emission point

### 1.1 The VfsEngine boundary

Traces are emitted at the [`VfsEngine`][VfsEngine] trait boundary — the single interface
that all frontend adapters (FUSE daemon, ublk surface, admin proxy, VFS_RPC) implement.

The 29 VfsEngine operations are:

```text
Namespace (14):  get_root_inode, lookup, getattr, setattr, mkdir, create,
                 tmpfile, unlink, rmdir, rename, link, symlink, readlink, mknod
File I/O (7):    open, release, read, write, flush, fsync, fallocate
Directory (4):   opendir, releasedir, readdir, fsyncdir
Xattr (4):       getxattr, setxattr, listxattr, removexattr
```

### 1.2 Emission semantics

For every call to a VfsEngine operation, the engine MUST emit exactly one trace step
*after* the operation completes (success or error). The trace step records:

- **Step metadata**: step number, operation name, dataset identifier
- **Input arguments**: all parameters passed to the VfsEngine call
- **Completion result**: errno + output values on success; errno only on failure
- **Optional IO cost deltas**: bytes read/written, flush count (for profiling, not equivalence)

Traces are emitted in strict monotonic step order. Step numbering starts at 1 and increments
by 1 for each operation. Resets are not permitted within a single trace session.

### 1.3 What is *not* traced

The following are explicitly *not* recorded in the trace:

- **Internal engine state transitions** below the VfsEngine API (commit_group lifecycle, extent allocation
  internals, cache eviction, journal compaction). These are engine-internal and not comparable
  across implementations.
- **Adapter-level transformations** (FUSE wire protocol serialization, ublk command mapping,
  RPC framing). These happen above the VfsEngine boundary and are adapter-specific.
- **Non-deterministic by-design fields** that the comparator ignores (§3).

---

## 2. JSONL trace format

### 2.1 Format specification

Each trace step is a single JSON object on its own line (JSONL). No trailing comma,
no array wrapper, no multi-line JSON. The format is:

```json
{"step":1,"op":"lookup","dataset_id":1,"parent_ino":2,"name_b64":"Zm9v","ctx":{"uid":1000,"gid":1000,"pid":1234},"result":{"errno":0,"ino":5,"gen":1,"attr":{...}}}
```

### 2.2 `ctx` block

Every step that passes a `RequestCtx` records it as a `ctx` block. The `ctx` block is
omitted for operations that do not receive a `RequestCtx` (`release`, `releasedir`).

```json
"ctx": {
  "uid": 1000,
  "gid": 1000,
  "pid": 1234,
  "umask": 18,
  "groups": [1000, 1001]
}
```

### 2.3 `result` block

Every step has a `result` block with at minimum an `errno` field. `errno: 0` means success.
On error, `errno` is the Linux-positive errno value (e.g., `2` for `ENOENT`). On success,
the result block includes the operation's output values.

### 2.4 `io_cost` block (optional, for profiling)

An optional `io_cost` block records approximate IO deltas for profiling and regression
detection. This block is NOT used for semantic equivalence comparison.

```json
"io_cost": {
  "bytes_read": 4096,
  "bytes_written": 0,
  "flush_count": 0
}
```

### 2.5 Per-operation schemas

#### Namespace operations

| Op | Input fields | Success output fields |
|---|---|---|
| `get_root_inode` | (none beyond ctx) | `ino`, `gen`, `kind`, `attr` |
| `lookup` | `parent_ino`, `name_b64` | `ino`, `gen`, `kind`, `attr` |
| `getattr` | `ino`, `fh_id?` | `attr` |
| `setattr` | `ino`, `fh_id?`, `attr_valid`, `mode?`, `uid?`, `gid?`, `size?`, `atime?`, `mtime?`, `atime_now?`, `mtime_now?`, `lock_owner?` | `attr` |
| `mkdir` | `parent_ino`, `name_b64`, `mode` | `ino`, `gen`, `attr` |
| `create` | `parent_ino`, `name_b64`, `mode`, `flags` | `ino`, `gen`, `fh_id`, `attr` |
| `tmpfile` | `parent_ino`, `mode`, `flags` | `ino`, `gen`, `fh_id`, `attr` |
| `unlink` | `parent_ino`, `name_b64` | (none beyond errno) |
| `rmdir` | `parent_ino`, `name_b64` | (none beyond errno) |
| `rename` | `old_parent_ino`, `old_name_b64`, `new_parent_ino`, `new_name_b64`, `flags` | (none beyond errno) |
| `link` | `ino`, `new_parent_ino`, `new_name_b64` | `attr` |
| `symlink` | `parent_ino`, `name_b64`, `target_b64` | `ino`, `gen`, `attr` |
| `readlink` | `ino` | `target_b64` |
| `mknod` | `parent_ino`, `name_b64`, `mode`, `rdev` | `ino`, `gen`, `attr` |

#### File I/O operations

| Op | Input fields | Success output fields |
|---|---|---|
| `open` | `ino`, `flags` | `fh_id`, `attr` |
| `release` | `fh_id`, `ino` | (none beyond errno) |
| `read` | `fh_id`, `offset`, `size` | `data_b64`, `bytes_read` |
| `write` | `fh_id`, `offset`, `data_b64` | `bytes_written`, `attr` |
| `flush` | `fh_id` | (none beyond errno) |
| `fsync` | `fh_id`, `datasync` | (none beyond errno) |
| `fallocate` | `fh_id`, `mode`, `offset`, `length` | `attr` |

#### Directory operations

| Op | Input fields | Success output fields |
|---|---|---|
| `opendir` | `ino` | `dh_id` |
| `releasedir` | `dh_id`, `ino` | (none beyond errno) |
| `readdir` | `dh_id`, `offset` | `entries[]` (array of {`name_b64`, `ino`, `kind`, `gen`, `cookie`}), `eof` |
| `fsyncdir` | `dh_id`, `datasync` | (none beyond errno) |

#### Extended attribute operations

| Op | Input fields | Success output fields |
|---|---|---|
| `getxattr` | `ino`, `name_b64` | `value_b64` |
| `setxattr` | `ino`, `name_b64`, `value_b64`, `flags` | (none beyond errno) |
| `listxattr` | `ino` | `names_b64` (null-separated name list, base64-encoded) |
| `removexattr` | `ino`, `name_b64` | (none beyond errno) |

### 2.6 attr encoding

The `attr` object within a result block encodes `InodeAttr` as:

```json
"attr": {
  "mode": 33188,
  "uid": 1000,
  "gid": 1000,
  "nlink": 1,
  "rdev": 0,
  "size": 4096,
  "blocks_512": 8,
  "blksize": 4096,
  "atime_ns": 1700000000000000000,
  "mtime_ns": 1700000000000000000,
  "ctime_ns": 1700000000000000000,
  "btime_ns": 1700000000000000000,
  "immutable": false,
  "append_only": false,
  "noatime": false,
  "nodump": false,
  "subtree_rev": 0,
  "dir_rev": 0
}
```

### 2.7 Binary data encoding

All binary fields (names, symlink targets, file data, xattr names/values) are
base64-encoded and suffixed with `_b64` in the field name. This ensures the trace
is valid JSON regardless of byte content (non-UTF-8 names, null bytes, control characters).

### 2.8 Full example trace

```jsonl
{"step":1,"op":"get_root_inode","dataset_id":1,"ctx":{"uid":0,"gid":0,"pid":1,"umask":0,"groups":[0]},"result":{"errno":0,"ino":1,"gen":0,"kind":1,"attr":{"mode":16877,"uid":0,"gid":0,"nlink":2,"rdev":0,"size":4096,"blocks_512":8,"blksize":4096,"atime_ns":1700000000000000000,"mtime_ns":1700000000000000000,"ctime_ns":1700000000000000000,"btime_ns":1700000000000000000,"immutable":false,"append_only":false,"noatime":false,"nodump":false,"subtree_rev":0,"dir_rev":0}}}
{"step":2,"op":"lookup","dataset_id":1,"parent_ino":1,"name_b64":"Zm9v","ctx":{"uid":1000,"gid":1000,"pid":42,"umask":18,"groups":[1000]},"result":{"errno":2}}
{"step":3,"op":"mkdir","dataset_id":1,"parent_ino":1,"name_b64":"Zm9v","mode":493,"ctx":{"uid":1000,"gid":1000,"pid":42,"umask":18,"groups":[1000]},"result":{"errno":0,"ino":3,"gen":0,"attr":{"mode":16877,"uid":1000,"gid":1000,"nlink":2,"rdev":0,"size":4096,"blocks_512":8,"blksize":4096,"atime_ns":1700000000000000000,"mtime_ns":1700000000000000000,"ctime_ns":1700000000000000000,"btime_ns":1700000000000000000,"immutable":false,"append_only":false,"noatime":false,"nodump":false,"subtree_rev":0,"dir_rev":0}}}
{"step":4,"op":"create","dataset_id":1,"parent_ino":3,"name_b64":"YmFy","mode":420,"flags":32768,"ctx":{"uid":1000,"gid":1000,"pid":42,"umask":18,"groups":[1000]},"result":{"errno":0,"ino":4,"gen":0,"fh_id":1,"attr":{"mode":33188,"uid":1000,"gid":1000,"nlink":1,"rdev":0,"size":0,"blocks_512":0,"blksize":4096,"atime_ns":1700000000000000000,"mtime_ns":1700000000000000000,"ctime_ns":1700000000000000000,"btime_ns":1700000000000000000,"immutable":false,"append_only":false,"noatime":false,"nodump":false,"subtree_rev":0,"dir_rev":0}}}
{"step":5,"op":"write","dataset_id":1,"fh_id":1,"offset":0,"data_b64":"SGVsbG8gV29ybGQ=","ctx":{"uid":1000,"gid":1000,"pid":42,"umask":18,"groups":[1000]},"result":{"errno":0,"bytes_written":11,"attr":{"mode":33188,"uid":1000,"gid":1000,"nlink":1,"rdev":0,"size":11,"blocks_512":8,"blksize":4096,"atime_ns":1700000000000000000,"mtime_ns":1700000000001000000,"ctime_ns":1700000000001000000,"btime_ns":1700000000000000000,"immutable":false,"append_only":false,"noatime":false,"nodump":false,"subtree_rev":0,"dir_rev":0}}}
```

---

## 3. Allowed nondeterminism

The following fields MAY differ between the Python reference implementation and the
Rust implementation without constituting a semantic equivalence failure:

### 3.1 Timestamps (wall-clock dependent)

| Field | JSON key | Rationale |
|---|---|---|
| Access time | `atime_ns` | Wall-clock time of last access; depends on host clock |
| Modification time | `mtime_ns` | Wall-clock time of last modification |
| Status change time | `ctime_ns` | Wall-clock time of last metadata change |
| Birth time | `btime_ns` | Wall-clock time of inode creation |

**Constraint**: Timestamps must be monotonic within each field per inode
(ctime ≥ mtime ≥ atime; ctime ≥ btime). Comparison between implementations
must not check timestamp values.

### 3.2 Inode numbers (`ino`)

Inode numbers are allocated by the engine's internal allocator. The Python and
Rust implementations may use different allocation strategies (linear scan, free-list,
b-tree). Inode numbers are not semantically meaningful across implementations.

**Constraint**: Root inode is always `ino: 1` in both implementations.

### 3.3 Generation numbers (`gen`)

Generation numbers increment on inode reuse and serve `ESTALE` detection. The
allocation order determines the generation sequence. Different implementations
may produce different generation values. Only monotonicity matters:

- Within a single implementation's trace, generation numbers for a given inode
  must strictly increase across reuses.
- Cross-implementation comparison ignores generation values entirely.

### 3.4 File handle IDs (`fh_id`)

File handle IDs are daemon-local numeric identifiers assigned by the engine's
open-file table. Different implementations use different allocation strategies.
`fh_id` values are not compared across implementations.

**Constraint**: Within a single implementation's trace, `fh_id` values must be
unique per open file and must not be reused until `release`. The ordering of
`fh_id` assignments is not constrained.

### 3.5 Directory handle IDs (`dh_id`)

Same rules as `fh_id`: daemon-local, allocated by the engine, not comparable
across implementations. Within a single trace, `dh_id` values must be unique
per open directory handle and must not be reused until `releasedir`.

### 3.6 `subtree_rev` and `dir_rev`

These revision counters track internal tree modification state and may differ
between implementations due to batching, concurrent operation ordering, or
internal metadata update strategies. They are engine-internal and not compared.

---

## 4. Determinism rules

The following fields and structures MUST be identical across the Python reference
implementation and the Rust implementation:

### 4.1 Errno values

For every operation, given identical input state, the errno result must match.
Success (errno 0) and every error code (ENOENT=2, EEXIST=17, ENOTDIR=20, etc.)
must be identical.

### 4.2 Inode attributes (non-timestamp)

| Field | JSON key | Rationale |
|---|---|---|
| File mode | `mode` | POSIX mode bits; includes type (S_IFREG, S_IFDIR, etc.) and permissions |
| User ID | `uid` | Owner UID |
| Group ID | `gid` | Owner GID |
| Link count | `nlink` | Hard link count; must match directory entry count |
| Device ID | `rdev` | Device number for device nodes |
| File size | `size` | Logical file size in bytes |
| Block count | `blocks_512` | Number of 512-byte blocks allocated |
| Block size | `blksize` | Preferred I/O block size |
| Immutable flag | `immutable` | InodeFlags::immutable |
| Append-only flag | `append_only` | InodeFlags::append_only |
| Noatime flag | `noatime` | InodeFlags::noatime |
| Nodump flag | `nodump` | InodeFlags::nodump |

### 4.3 Extent layout

Extent maps (logical offsets, lengths, HOLE/UNWRITTEN/DATA kinds) must be identical.
Given the same write workload, the same logical byte ranges must be backed by the same
extent types and cover the same logical spans.

- Logical offsets: identical
- Lengths: identical
- Kind (HOLE, UNWRITTEN, DATA): identical
- This covers `SEEK_HOLE`/`SEEK_DATA` results and `fiemap` output structure

### 4.4 Directory entry sets

For every directory, the set of `(name, inode reference, kind)` entries must be
identical. Ordering is directory-internal and may differ between implementations
(not semantically meaningful). The comparator checks set equality, not list equality.

Specifically:
- The comparator builds a set of `(name_b64, kind)` pairs from each implementation's `readdir` output
- The sets must be equal
- `cookie` values are not compared (they are stable within a session but may differ across implementations)

### 4.5 Statfs values

All fields of `StatFs` must be identical:
- `block_size`, `fragment_size`
- `total_blocks`, `free_blocks`, `avail_blocks`
- `files`, `files_free`
- `name_max`
- `fsid_hi`, `fsid_lo` (these are dataset identifiers, not host-specific)

### 4.6 Extended attribute name/value sets

For every inode, the set of `(name, value)` xattr pairs must be identical.
The comparator sorts by name and compares lexicographically.

### 4.7 ACL representations (canonical form)

POSIX ACLs (when present) must be representable in a canonical form that is
identical across implementations. The canonical form strips host-local
UID/GID → name mappings and stores only numeric identifiers.

### 4.8 Fiemap output structure

`fiemap` (file extent map) output must have identical structure across implementations:
same number of extents, same logical offsets and lengths, same extent flags (last, unknown,
delalloc, encoded, data_encrypted, not_aligned, inline, tail_merged).

### 4.9 Lock state

Held POSIX lock ranges (advisory byte-range locks) must be identical across implementations.
The lock state is defined as the set of `(owner, start, end, type)` records.

### 4.10 Symlink targets

Symlink target content (the path stored in the symlink) must be byte-for-byte identical.

---

## 5. Golden vectors for record codecs

### 5.1 Purpose

In addition to operation-level traces, individual record codecs need golden vectors.
Record codecs encode/decode internal data structures (inode records, extent map entries,
directory entries) to/from on-media binary format. Golden vectors ensure that the Rust
port's binary encoder produces byte-for-byte identical output to the Python reference
for each record type.

### 5.2 V1 record types requiring golden vectors

Per issue #1220 (record format strategy), V1 record codecs include:

| Record type | Python reference | Rust target |
|---|---|---|
| `InodeRecordV1` | `python:src/tidefs/records/inode_v1.py` | Rust struct (TBD) |
| `ExtentMapEntryV1` | `python:src/tidefs/records/extent_v1.py` | Rust struct (TBD) |
| `DirEntryV1` | `python:src/tidefs/records/dir_entry_v1.py` | Rust struct (TBD) |
| `XattrRecordV1` | `python:src/tidefs/records/xattr_v1.py` | Rust struct (TBD) |
| `SymlinkRecordV1` | `python:src/tidefs/records/symlink_v1.py` | Rust struct (TBD) |
| `ACLRecordV1` | `python:src/tidefs/records/acl_v1.py` | Rust struct (TBD) |

### 5.3 Golden vector format

Each golden vector is a JSON object containing:

```json
{
  "record_type": "InodeRecordV1",
  "canonical_struct": { ... },
  "canonical_bytes_b64": "AAAA..."
}
```

- `canonical_struct`: The Rust/Python struct representation in JSON form
- `canonical_bytes_b64`: The expected on-media byte sequence, base64-encoded

### 5.4 Golden vector lifecycle

1. Python reference generates `canonical_struct` → `canonical_bytes_b64` pairs
   and writes them to `tests/golden/records/`.
2. The Rust port reads the golden vectors and round-trips: decode bytes → struct →
   encode to bytes → compare against `canonical_bytes_b64`.
3. Golden vectors live alongside the format specification (in `tests/golden/`),
   not in the trace corpus. They are checked-in, versioned, and immutable once
   a format version is frozen.
4. When a new record format version is introduced (e.g., `InodeRecordV2`),
   new golden vectors are generated for the new version. Old golden vectors
   remain for the V1 codec.

---

## 6. Cross-implementation comparison protocol

### 6.1 Protocol

```text
1. Python reference replays trace → emits result stream + fingerprint
2. Rust implementation replays same trace → emits result stream + fingerprint
3. Comparator ignores allowed-nondeterministic fields (§3)
4. Mismatch in any deterministic field (§4) → test failure
5. Mismatch in fingerprint → test failure
```

### 6.2 Fingerprint

The fingerprint is a single hash covering only the deterministic fields (§4) of
the result stream. It is computed as:

```
fingerprint = SHA256(
    step_1_deterministic_result ||
    step_2_deterministic_result ||
    ...
    step_N_deterministic_result
)
```

Where `step_N_deterministic_result` is the canonical serialization of the result
block after stripping allowed-nondeterministic fields.

### 6.3 Comparator implementation

The comparator script:

1. Reads the trace `.jsonl` file
2. Feeds it to both implementations (Python and Rust)
3. Collects both result streams (also `.jsonl`)
4. For each step, compares deterministic fields pairwise
5. Reports any mismatches with step number, field name, expected value, actual value
6. Re-computes fingerprints and compares

### 6.4 Fingerprint canonicalization rules

To ensure deterministic fingerprinting across implementations:

- JSON keys are sorted lexicographically
- No whitespace outside string values
- Floating-point values are not used (all numeric fields are integers)
- `null` fields are omitted (not written as `"key": null`)
- Boolean fields use lowercase `true`/`false`
- Base64 values are unpadded (no trailing `=`)

---

## 7. Integration with trace minimization (#1174)

When a cross-implementation mismatch is found, the minimization tool from #1174
reduces the trace to the minimal sequence that reproduces the failure:

1. Bisect the trace: find the earliest step where the result streams diverge
2. Produce a minimal failing subsequence: start from dataset creation, include
   only the steps necessary to reproduce the mismatch
3. Output a small, human-debuggable reproducer trace that can be manually inspected

### 7.1 Minimization invariants

- The minimal trace must be self-contained (it must start from a known state,
  typically an empty dataset)
- The minimal trace must reproduce the exact same mismatch (same step, same field,
  same divergence)
- Minimization must not introduce new mismatches or alter the semantics of the
  failing step

### 7.2 Integration with crash testing (#1230)

Crash tests from #1230 are trace-replayable. A crash test trace includes
injection points that instruct the comparator to kill the engine at a specific
that recovery produces the correct deterministic state after restart.

---

## 8. Trace emission implementation guide

### 8.1 Rust-side architecture

The trace emitter is implemented as a standalone crate `tidefs-trace-emitter`
with a `TraceEmitter` trait:

```rust
pub trait TraceEmitter: Send + Sync {
    /// Begin a new trace session with the given dataset ID.
    fn begin_session(&mut self, dataset_id: u64);

    /// Emit a trace step for a completed VfsEngine operation.
    fn emit(&mut self, step: TraceStep);

    /// End the trace session and flush any buffered output.
    fn end_session(&mut self);
}
```

### 8.2 Integration with VfsEngine

The trace emitter is *not* part of the `VfsEngine` trait. Instead, a tracing
wrapper (`TracedVfsEngine<T: VfsEngine>`) wraps any `VfsEngine` implementation
and emits trace steps before returning results:

```
┌──────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│  FUSE daemon  │────▶│ TracedVfsEngine<T>   │────▶│ T: VfsEngine    │
│  (adapter)    │     │  - emits trace step  │     │  (real engine)  │
└──────────────┘     │  - delegates to inner │     └─────────────────┘
                     └──────────────────────┘
```

### 8.3 Trace step buffer

The `TracedVfsEngine` maintains a monotonic step counter (starting at 1) and
a buffer of trace steps. The `TraceEmitter` implementation writes JSONL to a
file, a pipe, or an in-memory buffer for testing.

### 8.4 Feature gating

Trace emission is gated behind a Cargo feature `trace-emit` (off by default).
When disabled, `TracedVfsEngine` is a zero-cost transparent wrapper that
delegates directly to the inner engine with no tracing overhead.

### 8.5 Python-side reference

The Python reference implementation mirrors the Rust trace emitter: it writes
the same JSONL format and supports the same `TracedVfsEngine` pattern wrapping
the Python `VfsEngine` class.

---

## 9. Trace storage and naming

### 9.1 Trace file naming convention

```
```


### 9.2 Golden trace storage

Pre-generated golden traces live in:
```
tests/golden/traces/<scenario_name>.jsonl
```

### 9.3 Existing golden vectors storage

```
tests/golden/records/<record_type>.json
```

---

## 10. Acceptance criteria

1. **Trace emission format specified and stable**: JSONL schema is fully defined
   in §2 with per-operation schemas and examples.
2. **Allowed nondeterminism explicitly enumerated**: §3 lists every field that
   may differ across implementations, with rationale and constraints.
3. **Determinism rules cover all VfsEngine operations**: §4 covers errno, inode
   attributes, extent layout, directory sets, statfs, xattrs, ACLs, fiemap,
   lock state, and symlink targets.
4. **Golden vectors exist for every V1 record codec**: §5 defines the format
   and lifecycle for record codec golden vectors.
   equivalence**: §6 defines the comparison protocol and fingerprint algorithm.

## 11. References

- [VfsEngine trait definition][VfsEngine] — `crates/tidefs-vfs-engine/src/lib.rs`
- [Core types][VfsCoreTypes] — `crates/tidefs-types-vfs-core/src/lib.rs`
- [VFS Engine API contract][VfsEngineContract] — `docs/VFS_ENGINE_API_CONTRACT.md`
- [Three-contract architecture (#1250)][Issue1250]
- [Trace corpus (#1174)][Issue1174]
- [Golden vectors (#1185)][Issue1185]
- [Record format strategy (#1220)][Issue1220]
- [Crash injection harness (#1230)][Issue1230]

[VfsEngine]: ../../crates/tidefs-vfs-engine/src/lib.rs
[VfsCoreTypes]: ../../crates/tidefs-types-vfs-core/src/lib.rs
[VfsEngineContract]: ../VFS_ENGINE_API_CONTRACT.md
[Issue1250]: http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1250
[Issue1174]: http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1174
[Issue1185]: http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1185
[Issue1220]: http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1220
[Issue1230]: http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1230
