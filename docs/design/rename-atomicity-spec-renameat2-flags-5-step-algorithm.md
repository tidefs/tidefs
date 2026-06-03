# Rename Atomicity Specification: renameat2 Flags and 5-Step Transaction/Locking Algorithm

**Issue**: [#1205](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1205)
**Status**: design-spec
**Priority**: P1
**Lane**: storage-core
**Depends on**: #1206 (Lock hierarchy and deterministic concurrency model), #1213 (VFS Engine API contract)
**Related**: #1233 (FUSE binding strategy), #1224 (Torn-commit recovery), #1267 (CommitGroup state machine)
**Source**: tidefs v0.262 FUSE notes §7.2 (`docs/notes/2026-02-06-fuse-userspace-api-and-mmap.7-10-semantics-errors-durability.md`)

## Abstract

This document specifies the rename atomicity contract for tidefs: the complete
and a deterministic 5-step transaction/locking algorithm. The goal is to match
Linux kernel rename behavior byte-for-byte so that xfstests and real workloads
see identical errno selection, directory-entry ordering, and crash consistency
semantics.

No existing POSIX filesystem gets rename atomicity exactly right without
careful specification. ZFS, btrfs, and ext4 each have subtle deviations from
Linux VFS rename semantics that show up under xfstests generic/02[3-7]*.
tidefs must not recapitulate those mistakes. This design locks in the contract
before implementation diverges.

---

## 1. Flag Support

### 1.1 renameat2 flag enumeration

tidefs implements Linux `renameat2(2)` semantics for all four flag variants,
encoded as bitmask bits in the `flags: u32` parameter of `VfsEngine::rename`:

| Flag | Value | Constant | Semantics |
|------|-------|----------|-----------|
| (none) | `0` | — | Plain `rename(2)`: atomically replace destination if it exists; succeeds if source and destination are the same |
| `RENAME_NOREPLACE` | `1` | `tidefs_types_vfs_core::RENAME_NOREPLACE` | Fail with `EEXIST` if destination exists; otherwise identical to plain rename |
| `RENAME_EXCHANGE` | `2` | `tidefs_types_vfs_core::RENAME_EXCHANGE` | Atomically swap source and destination dentries; both must exist (`ENOENT` otherwise); type compatibility enforced |
| `RENAME_WHITEOUT` | `4` | `tidefs_types_vfs_core::RENAME_WHITEOUT` | Plain rename, then atomically create a whiteout device node (`S_IFCHR`, `rdev=0:0`) at the source location; requires `CAP_MKNOD` or `uid==0` |

### 1.2 Flag composition rules

- `RENAME_NOREPLACE` and `RENAME_EXCHANGE` are mutually exclusive. Setting both returns `EINVAL`.
- `RENAME_NOREPLACE | RENAME_WHITEOUT` is valid: rename without clobbering the target, and leave a whiteout at the source.
- `RENAME_EXCHANGE | RENAME_WHITEOUT` returns `EINVAL` (Linux 7.0 behavior: exchange does not produce whiteouts).
- Unknown flag bits (`!(flags & 0x7)`) return `EINVAL`.


```rust
const VALID_RENAME_FLAGS: u32 = RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT;

    if flags & !VALID_RENAME_FLAGS != 0 {
        return Err(Errno::EINVAL);
    }
    let noreplace = flags & RENAME_NOREPLACE != 0;
    let exchange  = flags & RENAME_EXCHANGE != 0;
    let whiteout  = flags & RENAME_WHITEOUT != 0;
    if noreplace && exchange {
        return Err(Errno::EINVAL);
    }
    if exchange && whiteout {
        return Err(Errno::EINVAL);
    }
    Ok(())
}
```

---



For all rename variants, both `old_name` and `new_name` are raw byte slices.
The engine applies these checks before touching any on-disk state:

- **NUL bytes**: names containing `\0` are rejected with `EINVAL`.
- **Slash bytes**: names containing `/` are rejected with `EINVAL`.
- **`.` and `..`**: setting either as a rename *target* is always rejected with `EINVAL`. Using them as a *source* is allowed (matches Linux: `rename(".", "foo")` fails with `EBUSY` on the VFS side, but tidefs's fast path can return `EINVAL` early).
- **Empty names**: rejected with `ENOENT` (matching Linux VFS behavior for zero-length component).
- **Name length**: the engine must accept names up to `NAME_MAX` (255 bytes for tidefs). Longer names return `ENAMETOOLONG`.

### 2.2 Subtree check

When `old` is a directory, the engine must detect and reject moves into `old`'s
own subtree. This is the classic "can't move a directory into itself" check:

```rust
fn is_subdirectory_of(
    candidate_child: InodeId,
    candidate_parent: InodeId,
) -> bool {
    // Walk up from candidate_child to root.
    // If candidate_parent appears in the ancestor chain, return true.
    // Detected by following ".." entries from candidate_child.
    // Fails with EINVAL if detected during rename.
}
```

The check uses the `..` entry in each directory (not a cached parent pointer)
to survive concurrent renames. Per the locking algorithm (section 5), both
directories are locked when this check runs, so the ancestor chain is stable.

### 2.3 No-op detection

When `(old_parent, old_name) == (new_parent, new_name)` and `flags == 0`,
the operation is a no-op. Linux returns success without touching link counts,
timestamps, or `dir_rev`. tidefs matches this exactly:

```rust
if old_parent == new_parent && old_name == new_name && flags == 0 {
    return Ok(());
}
```

For `RENAME_NOREPLACE` with same source/destination: still succeeds (Linux behavior).
For `RENAME_EXCHANGE` with same source/destination: succeeds (no swap needed).

### 2.4 Sticky-bit gate

For directories with the sticky bit (`S_ISVTX`), the caller must pass the
sticky-bit ownership check defined in `tidefs_posix_semantics::sticky_dir_allows_unlink_or_rename`.
This check is applied to both the old parent and the new parent (when
the destination exists and would be overwritten). The function is:

```rust
pub fn sticky_dir_allows_unlink_or_rename(
    parent_mode: u32,
    parent_uid: u32,
    entry_uid: u32,
    caller_uid: u32,
) -> bool;
```

Applied:
- To `old_parent`: with `entry_uid` = old entry's uid
- To `new_parent` (overwrite case only): with `entry_uid` = overwritten entry's uid

### 2.5 Permission checks

The engine must check:
- **Search (`x`) permission** on every ancestor of `old_parent` up to the common ancestor with `new_parent`, and on every ancestor of `new_parent` up to the common ancestor. Fails with `EACCES`.
- **Write (`w`) permission** on `old_parent` and `new_parent`. Fails with `EACCES`.
- For `RENAME_WHITEOUT`: **write + execute** on `old_parent` plus `CAP_MKNOD` or `uid==0`.

Root (`uid==0`) bypasses all permission checks except execute-only directory traversal (Linux `CAP_DAC_READ_SEARCH`).

---

## 3. Type and Emptiness Rules for Overwrites

before any mutation:

### 3.1 Type compatibility

| Source type | Destination type | Action |
|-------------|-----------------|--------|
| Regular file / symlink / special | Regular file / symlink / special | Overwrite allowed |
| Directory | Directory (empty) | Overwrite allowed |
| Directory | Directory (non-empty) | `ENOTEMPTY` |
| Directory | Not directory | `ENOTDIR` / `EISDIR` |
| Not directory | Directory | `EISDIR` |

The errno returned for directory-vs-non-directory mismatch follows Linux
convention precisely:
- If `old` is a directory and `new` exists but is not a directory: `ENOTDIR`.
- If `old` is not a directory and `new` exists and is a directory: `EISDIR`.

### 3.2 Directory emptiness check

When overwriting a directory target, the target directory must be empty.
"Empty" means the directory contains only `.` and `..`. The check is performed
5-step algorithm).

Per Linux behavior, the emptiness check considers:
- Deferred-deletion inodes (nlink==0, still open) that still have directory
  entries: **these count as non-empty** (the directory entry is still visible).
- The check is against the directory's current state under the exclusive lock.
  If a concurrent rmdir emptied the directory between step 1 and step 3, the

### 3.3 Exchange type compatibility

For `RENAME_EXCHANGE`, both entries must exist. Additionally, the kernel
requires type compatibility: a directory can only be exchanged with another
directory, and a non-directory can only be exchanged with another non-directory.
Mismatched types return `ENOTDIR` (if trying to exchange a directory with a
non-directory) or `EISDIR` (if trying to exchange a non-directory with a
directory).

```rust
if flags & RENAME_EXCHANGE != 0 {
    let old_kind = old_entry.kind;
    let new_kind = new_entry.kind;
    if old_kind != new_kind {
        return if old_kind == NodeKind::Dir {
            Err(Errno::ENOTDIR)
        } else {
            Err(Errno::EISDIR)
        };
    }
}
```

---

## 4. Whiteout Semantics

### 4.1 Whiteout inode

A whiteout is a special character device inode with `rdev=0:0` and `S_IFCHR`
file type. It is not a regular directory entry; it is a marker that says
"there used to be an entry here in a lower layer."

### 4.2 Creation sequence

Under `RENAME_WHITEOUT`, after the old entry is removed from `old_parent`'s
directory, a new entry with the same name is created as a whiteout marker:

```rust
if flags & RENAME_WHITEOUT != 0 {
    // After removing old entry, create whiteout at old_name in old_parent
    let whiteout_inode = create_whiteout_inode(tick);
    insert_directory_entry(old_parent_id, old_name, whiteout_inode, tick)?;
}
```

The whiteout inode:
- Has `NodeKind::CharDev`, `rdev=(0,0)`
- Has `nlink=1`
- Is owned by `root:root` (uid=0, gid=0)
- Has mode `000` (no access bits)
- Inherits no attributes from the renamed inode

### 4.3 Whiteout permission requirement

Creating a whiteout requires `CAP_MKNOD` (or `uid==0`). The check is:

```rust
fn can_create_whiteout(ctx: &RequestCtx) -> bool {
    ctx.uid == 0  // In the PoC, only root can create whiteouts
}
```

### 4.4 Whiteout interaction with other operations

- `lookup`: encountering a whiteout returns `ENOENT` (unless overmount in
  a union/overlay context, which is deferred).
- `unlink`: can remove a whiteout normally.
- `mkdir`, `create`, `mknod`: can overwrite a whiteout (the whiteout is just
  a regular entry with an unusual inode type).
- `readdir`: whiteouts are NOT listed (filtered by the engine). The kernel
  overlay layer expects them to be invisible to userspace.

---

## 5. 5-Step Transaction/Locking Algorithm

This is the canonical algorithm for every rename operation, integrating the
lock hierarchy from #1206 with optimistic concurrency control and a single
atomic mutation transaction.

### 5.1 Algorithm overview

```
STEP 1 — RESOLVE (shared locks)
  ├── Acquire shared locks on old_parent + new_parent dirs (level 2)
  ├── Resolve old_name → old_entry (ENOENT if missing)
  ├── Resolve new_name → Optional new_entry
  ├── Snapshot revision counters for both directories
  ├── Compute full lock set
  └── Release shared locks

STEP 2 — ACQUIRE LOCK SET (deterministic order)
  ├── Build sorted lock request list:
  │     [old_parent_dir (X), new_parent_dir (X),
  │      old_entry_inode (X), new_entry_inode (X, if overwrite),
  │      whiteout_inode (X, if RENAME_WHITEOUT)]
  ├── Sort by (level, inode_id); strip duplicates
  ├── Acquire all in sorted order
  └── On contention: release held, exponential backoff, retry step 1

  ├── Re-check: old_entry still exists? (ENOENT if missing)
  ├── Re-check: new_entry existence matches flags
  │     (NOREPLACE → must be absent; EXCHANGE → must be present)
  ├── Re-check: type compatibility
  │     (dir→non-dir, non-dir→dir, non-empty dir→ENOTEMPTY)
  ├── Re-check: subtree loop (dir cannot move into self)
  │     Walk .. from old entry up to new_parent
  ├── Re-check: permission + sticky-bit gates
  ├── Compare revision counters to step-1 snapshots
  │     If mismatched → release, retry step 1
  └── All checks pass → proceed

STEP 4 — APPLY TRANSACTION (single engine transaction)
  ├── begin_mutation()
  ├── bump_generation() → tick
  ├── [If overwrite] Remove new entry from new_parent
  │     ├── remove_directory_entry(new_parent_id, &new_name, tick)
  │     ├── Decrement overwritten inode nlink
  │     │     If nlink→0 + no open handles → schedule deferred deletion
  │     │     If directory: new_parent.nlink -= 1, remove dir inode
  │     └── mark_inode_metadata_dirty(overwritten_inode_id)
  ├── Remove old entry from old_parent
  │     └── remove_directory_entry(old_parent_id, &old_name, tick)
  ├── Insert renamed entry into new_parent
  │     └── insert_directory_entry(new_parent_id, new_name, renamed_entry, tick)
  ├── [If RENAME_WHITEOUT] Insert whiteout entry into old_parent
  │     └── insert_directory_entry(old_parent_id, old_name, whiteout_entry, tick)
  ├── [If cross-parent directory move]
  │     ├── old_parent.nlink -= 1 (saturating, min 2)
  │     └── new_parent.nlink += 1
  ├── [If RENAME_EXCHANGE] Swap both entries (see 5.6)
  ├── Update timestamps:
  │     ├── old_parent: mtime, ctime updated
  │     ├── new_parent: mtime, ctime updated
  │     └── moved inode: ctime updated
  ├── Bump dir_entry_rev for both parents
  ├── Mark dirty:
  │     ├── mark_dir_dirty(old_parent_id)
  │     ├── mark_inode_metadata_dirty(old_parent_id)
  │     ├── mark_dir_dirty(new_parent_id)
  │     └── mark_inode_metadata_dirty(new_parent_id)
  └── commit_mutation(())

STEP 5 — COMMIT AND RELEASE
  ├── commit_mutation() writes intent-log record + returns
  ├── Release all exclusive locks in reverse acquisition order
```

### 5.2 Lock set computation

For a plain rename (`old → new`, overwriting target):

| Resource | Level | Mode | Purpose |
|----------|-------|------|---------|
| `old_parent` inode | 2 (Directory) | Exclusive | Directory entry map mutation |
| `new_parent` inode | 2 (Directory) | Exclusive | Directory entry map mutation |
| `old_entry` inode | 3 (Inode metadata) | Exclusive | ctime update, nlink (if dir cross-parent) |
| `overwritten_entry` inode | 3 (Inode metadata) | Exclusive | nlink decrement, deferred-delete scheduling |

For `RENAME_EXCHANGE`:

| Resource | Level | Mode | Purpose |
|----------|-------|------|---------|
| `old_parent` inode | 2 (Directory) | Exclusive | Swap old → new entry |
| `new_parent` inode | 2 (Directory) | Exclusive | Swap new → old entry |
| `old_entry` inode | 3 (Inode metadata) | Exclusive | ctime update |
| `new_entry` inode | 3 (Inode metadata) | Exclusive | ctime update |

For `RENAME_WHITEOUT`:

| Resource | Level | Mode | Purpose |
|----------|-------|------|---------|
| `old_parent` inode | 2 (Directory) | Exclusive | Remove old entry + insert whiteout |
| `new_parent` inode | 2 (Directory) | Exclusive | Insert renamed entry |
| `old_entry` inode | 3 (Inode metadata) | Exclusive | ctime update |
| `overwritten_entry` inode | 3 (Inode metadata) | Exclusive | nlink decrement (if overwriting) |

The sort key is `(level, inode_id)`. Duplicate resources (e.g., when
`old_parent == new_parent`) are deduplicated after sorting.


Each directory has a `dir_entry_rev: u64` that is incremented on every
directory entry mutation (create, unlink, rename). During step 1, the engine
captures:

```rust
let old_parent_rev = state.inodes[&old_parent_id].dir_rev;
let new_parent_rev = state.inodes[&new_parent_id].dir_rev;
```

During step 3, it compares these to the current values. If either has
changed, a concurrent operation modified one of the directories. The engine
releases all locks and retries from step 1.

For `RENAME_WHITEOUT`, only `old_parent`'s revision counter matters for
the whiteout insertion (the old entry removal is already covered by the
directory lock).

### 5.4 No-op and same-directory fast path

When `old_parent == new_parent` and there is no overwrite (target does not
exist), the engine can skip the `new_parent` directory lock entirely (it's
the same resource). The lock set reduces to:

- `old_parent` directory (exclusive)
- `old_entry` inode metadata (exclusive)

This is the common case for `mv foo bar` within a directory and should be
optimized.

### 5.5 Crash consistency

The rename transaction (step 4) is a single commit group in the commit_group state
machine (#1267). It follows the 7-step commit ordering:

1. If overwriting a non-empty inode: data journal flush (steps 1-2)
2. Metadata records (directory entries, inode nlink updates, timestamps) (step 3)
3. Commit record (step 4)
4. Metadata journal flush (step 5)
5. Checkpoint pointer update (steps 6-7)

On crash before commit, the rename is atomically rolled back. On crash after
commit but before checkpoint, the recovery contract (#1224) replays the commit
record. On crash after checkpoint, the rename is fully durable.

### 5.6 RENAME_EXCHANGE algorithm

The exchange transaction swaps two directory entries atomically:

```
1. remove_directory_entry(old_parent, old_name, tick)
2. remove_directory_entry(new_parent, new_name, tick)
3. insert_directory_entry(old_parent, old_name, new_entry_renamed, tick)
4. insert_directory_entry(new_parent, new_name, old_entry_renamed, tick)
```

Where `old_entry_renamed.name = new_name` and `new_entry_renamed.name = old_name`.

Both entries' ctimes are bumped. If both parents are the same, the directory
`dir_entry_rev` increments once (one logical mutation, even though two
entries change). For distinct parents, each parent's `dir_entry_rev` increments.

Cross-parent directory exchange requires nlink adjustments on both parents
in both directions, which cancel out (old_parent: +1 from receiving new dir,
-1 from losing old dir; new_parent: symmetric). The implementation can
detect this and skip the nlink adjustments for directory exchange.

---

## 6. Error Mapping

The complete errno contract for `VfsEngine::rename`:

| Condition | Errno |
|-----------|-------|
| `old_name` or `new_name` contains NUL or `/` | `EINVAL` |
| `new_name` is `.` or `..` | `EINVAL` |
| `old_name` is `.` or `..` (as rename *source*) | `EBUSY` (PoC: `EINVAL` acceptable) |
| Unknown flag bits | `EINVAL` |
| `NOREPLACE \| EXCHANGE` | `EINVAL` |
| `EXCHANGE \| WHITEOUT` | `EINVAL` |
| `old_name` does not exist in `old_parent` | `ENOENT` |
| `old_parent` or `new_parent` is not a directory | `ENOTDIR` |
| `old` entry is a directory, `new` entry exists and is not a directory | `ENOTDIR` |
| `old` entry is not a directory, `new` entry exists and is a directory | `EISDIR` |
| `old` is a directory, `new` is a non-empty directory (overwrite) | `ENOTEMPTY` |
| `NOREPLACE` and `new_name` exists | `EEXIST` |
| `EXCHANGE` and `new_name` does not exist | `ENOENT` |
| `EXCHANGE` and type mismatch (dir ↔ non-dir) | `ENOTDIR` / `EISDIR` |
| Directory moved into its own subtree | `EINVAL` |
| `WHITEOUT` without `CAP_MKNOD`/`uid==0` | `EPERM` |
| Search/write permission denied on `old_parent` | `EACCES` |
| Search/write permission denied on `new_parent` | `EACCES` |
| Sticky-bit restriction on `old_parent` | `EPERM` |
| Sticky-bit restriction on `new_parent` (overwrite case) | `EPERM` |
| Read-only filesystem | `EROFS` |
| `ENOSPC` on directory entry allocation | `ENOSPC` |

### 6.1 Error priority

When multiple error conditions apply, the engine evaluates them in this order:

3. Directory type checks (ENOTDIR on parent)
4. Source existence (ENOENT)
5. Destination existence checks by flag (EEXIST for NOREPLACE, ENOENT for EXCHANGE)
6. Type compatibility (ENOTDIR, EISDIR)
7. Emptiness (ENOTEMPTY)
8. Subtree check (EINVAL)
9. Permission checks (EACCES, EPERM)
10. Space checks (ENOSPC)

This matches the Linux kernel's VFS `vfs_rename()` error evaluation order,
confirmed by xfstests generic/023 through generic/028.

---

## 7. Directory Change-Stream Monotonicity

### 7.1 `dir_rev` semantics

Each directory inode carries a `dir_rev: u64` field that is a monotonic
counter incremented on every directory entry mutation:

- **Increment on**: create, unlink, rmdir, rename (source and destination),
  link, whiteout creation
- **No increment on**: no-op rename (same source and dest, flags=0),
  failed operations, read-only operations

### 7.2 Rename's impact on `dir_rev`

A rename operation bumps `dir_entry_rev` for every directory whose entry
map changes:

| Scenario | Revisions bumped |
|----------|-----------------|
| `rename(a, b)` — same parent, no overwrite | `parent.dir_rev += 1` |
| `rename(a, b)` — same parent, overwrite target | `parent.dir_rev += 1` |
| `rename(a, b)` — cross-parent, no overwrite | `old_parent.dir_rev += 1`, `new_parent.dir_rev += 1` |
| `rename(a, b)` — cross-parent, overwrite target | `old_parent.dir_rev += 1`, `new_parent.dir_rev += 1` |
| `RENAME_EXCHANGE(a, b)` — same parent | `parent.dir_rev += 1` |
| `RENAME_EXCHANGE(a, b)` — cross-parent | `old_parent.dir_rev += 1`, `new_parent.dir_rev += 1` |
| `RENAME_WHITEOUT(a, b)` | `old_parent.dir_rev += 1` (entry removal + whiteout insertion), `new_parent.dir_rev += 1` |

The `dir_rev` increment is part of the atomic transaction: it either commits
with the rest of the mutation or is rolled back entirely.

### 7.3 Atomicity with respect to concurrent lookup/readdir

Under the locking protocol, a concurrent `lookup` or `readdir` sees either
the fully pre-rename state or the fully post-rename state—never a partial
intermediate result. This is enforced by:

- Exclusive locks on both directories during the entire step 4 (mutation).
- `readdir` acquires a shared lock on the directory (level 2), so it serializes
  against the rename's exclusive lock.
- `lookup` acquires a shared lock on the parent directory (level 2) and the
  target inode (level 3), so it sees a consistent snapshot.

---

## 8. Integration with Existing Code

### 8.1 Current state (v0.454)

| Component | File | Status |
|-----------|------|--------|
| `VfsEngine::rename` trait | `crates/tidefs-vfs-engine/src/lib.rs:186` | Declared with full flag semantics in doc comment |
| `VfsLocalFileSystem::rename` | `crates/tidefs-local-filesystem/src/vfs_engine_impl.rs:327` | Partial: basic rename + NOREPLACE; EXCHANGE returns `EOPNOTSUPP`; no WHITEOUT; no locking |
| `LocalFileSystem::rename` | `crates/tidefs-local-filesystem/src/lib.rs:2522` | Full rename with type checks, no-op detection, nlink updates; no locking |
| `LocalFileSystem::rename_exchange` | `crates/tidefs-local-filesystem/src/lib.rs:2652` | Full exchange with type checks; no locking |
| Flag constants | `crates/tidefs-types-vfs-core/src/lib.rs:362-364` | `RENAME_NOREPLACE`, `RENAME_EXCHANGE`, `RENAME_WHITEOUT` defined |
| Sticky-bit gate | `crates/tidefs-posix-semantics/src/lib.rs:232` | `sticky_dir_allows_unlink_or_rename` |

### 8.2 Implementation path

The implementation of this design is split across two issues:

1. **This issue (#1205)**: Design document. No code changes.
2. **Follow-up implementation issue** (to be filed): Implement the 5-step
   algorithm in `VfsLocalFileSystem::rename`, integrating the lock manager
   from #1206, wiring `RENAME_WHITEOUT`, and adding xfstests-grade tests.

### 8.3 Required changes in vfs_engine_impl.rs

The `VfsLocalFileSystem::rename` method must be rewritten to follow the
5-step algorithm. Key changes from current code:

- **Current**: directly calls `self.fs.borrow_mut().link_file()` then
  `self.fs.borrow_mut().unlink()`. No locking, no atomicity.
- **Target**: resolves under shared locks → acquires exclusive lock set →
  all four flag variants in one transaction.

### 8.4 Required changes in LocalFileSystem

rules (type checks, no-op, subtree check). It needs:

- A `rename_atomic` entry point that takes the full flag set (not just a
  `noreplace: bool`).
- Whiteout creation helper.
- Integration with mutation begin/commit (already present: `begin_mutation()`,
  `commit_mutation()`).

---

## 9. Test Strategy

### 9.1 VfsEngine-level tests

All tests live in `crates/tidefs-local-filesystem/src/vfs_engine_impl.rs`
(test module). Minimum test set:

|------|-------------------|
| `rename_file` | Basic rename within same directory (exists) |
| `rename_noreplace` | `RENAME_NOREPLACE` returns `EEXIST` when target exists (exists) |
| `rename_noreplace_ok` | `RENAME_NOREPLACE` succeeds when target does not exist |
| `rename_noreplace_noop` | `RENAME_NOREPLACE` with same source/dest succeeds |
| `rename_exchange` | `RENAME_EXCHANGE` swaps two entries atomically |
| `rename_exchange_missing_source` | `RENAME_EXCHANGE` returns `ENOENT` if source missing |
| `rename_exchange_missing_target` | `RENAME_EXCHANGE` returns `ENOENT` if target missing |
| `rename_exchange_type_mismatch` | Dir ↔ file exchange returns appropriate errno |
| `rename_whiteout_root_only` | `RENAME_WHITEOUT` succeeds for uid=0 |
| `rename_whiteout_eperm` | `RENAME_WHITEOUT` returns `EPERM` for non-root |
| `rename_dir_to_nonempty` | Overwriting non-empty dir returns `ENOTEMPTY` |
| `rename_dir_into_self` | Moving dir into subtree returns `EINVAL` |
| `rename_noop` | Same source/dest with flags=0 is no-op |
| `rename_invalid_flags` | Unknown flags return `EINVAL` |
| `rename_noreplace_and_exchange` | Mutually exclusive flags return `EINVAL` |
| `rename_exchange_and_whiteout` | Mutually exclusive flags return `EINVAL` |
| `rename_into_subdir` | Subtree detection across multiple levels |
| `rename_cross_parent_nlink` | Cross-parent directory move adjusts parent nlinks |
| `rename_overwrite_nlink` | Overwriting a file with nlink>1 decrements nlink |
| `rename_ctime_updated` | Moved inode ctime is updated |
| `path_cache_updated_on_rename` | Path cache reflects new path after rename (exists) |

### 9.2 Deterministic trace oracle

The test oracle must record kernel behavior for exact errno selection.
For each test case:

1. Run the operation on a tmpfs/ext4 reference.
2. Record the exact errno (or success + resulting state).
3. Encode this in the Rust test as the expected behavior.
4. Run tidefs and assert the same outcome.

This is tracked as a separate trace-oracle test suite using the
`tidefs-trace-oracle` crate.

### 9.3 xfstests coverage

Relevant xfstests tests for rename:

| Test | Coverage |
|------|----------|
| `generic/023` | Rename file over file, same dir |
| `generic/024` | Rename file over file, different dirs |
| `generic/025` | Rename dir over empty dir |
| `generic/026` | Rename dir over non-empty dir (ENOTEMPTY) |
| `generic/027` | Rename into subdirectory (EINVAL) |
| `generic/028` | renameat2 RENAME_NOREPLACE |
| `generic/029` | renameat2 RENAME_EXCHANGE |
| `generic/030` | renameat2 RENAME_WHITEOUT |
| `generic/078` | Rename with open file handles |
| `generic/228` | Cross-device rename (EXDEV) |
| `generic/361` | renameat2 error priority |

---

## 10. Non-Goals (Deferred)

- **Overlay/union whiteout semantics**: Whiteouts in a union mount context
  (overlayfs) require `RENAME_WHITEOUT` with overlay-specific behavior.
  tidefs is not an overlay filesystem; whiteout support is limited to the
  POSIX `renameat2` contract.
- **Cross-dataset rename**: Cross-dataset renames return `EXDEV`. No
  distributed rename protocol in this design.
- **Rename across nodes in a cluster**: Cluster VFS RPC rename forwarding
  is handled by #1234 (VFS_RPC wire protocol). The lock hierarchy extends
  naturally to the cluster model (dataset writer lease + local lock
  hierarchy), but the distributed rename protocol is deferred.
- **renameat2 with RENAME_NOREPLACE on a dentry that becomes present
  locks. No additional work needed.
- **Performance optimization for rename-heavy workloads**: Directory
  entry batching, extent-based rename (for large directories), and
  rename journaling optimization are deferred.

---

## 11. Tradeoffs and Design Rationale

### 11.1 Why optimistic concurrency instead of pure pessimistic locking?

The 5-step algorithm uses optimistic concurrency: resolve under shared locks,
for higher concurrency. Rename operations typically conflict rarely in practice
(different directories, different names). Pure pessimistic locking (acquire
exclusive from the start) would serialize all namespace operations globally.


Directory entry hashes would require computing a hash over the entire directory
entry map, which is O(n) in directory size. Revision counters are O(1) and
detect any mutation to the directory's entry set. A hash-based approach would
also have a (vanishingly small) collision risk.

### 11.3 Why deterministic lock ordering instead of deadlock detection?

Deterministic lock ordering (by level, then by inode_id) prevents deadlocks
by construction. Deadlock detection (wait-for graphs, timeout+retry) would
add complexity and non-deterministic latency. The tradeoff is that every
operation must know its full lock set in advance, but for rename this is
always computable.


for the entire duration of permission checks, subtree walks, and name
(name resolution, subtree walk, permission checks on ancestor paths) and
minimizes the time directories are locked exclusively.

### 11.5 Why whiteout as a separate inode instead of a directory entry flag?

A separate inode for whiteouts enables:
- Normal inode lifecycle (nlink, deletion, stat)
- Future overlayfs compatibility (overlayfs expects `S_IFCHR 0:0` whiteouts)
- Clean separation: the inode type field carries the semantics

A directory-entry flag would require modifying every code path that reads
directory entries to check the flag, which is more error-prone.

---

## 12. Related Design Documents

- **#1206** (`docs/LOCK_HIERARCHY_AND_CONCURRENCY_MODEL.md`): Canonical lock hierarchy used by the 5-step algorithm's lock set computation (section 5.2).
- **#1213** (`docs/VFS_ENGINE_API_CONTRACT.md`): The `VfsEngine::rename` trait definition that this algorithm implements.
- **#1224**: Torn-commit recovery: after a crash during rename, the recovery contract replays the commit record.
- **#1267** (`docs/design/canonical-commit-ordering-commit_group-state-machine.md`): The 7-step commit_group commit ordering that guarantees rename durability.
- **#1292** (`docs/FUSE_OPERATION_COVERAGE_MATRIX.md`): The FUSE-level rename operation mapping.
- **#1233** (`docs/FUSE_BINDING_STRATEGY_AND_FEATURE_MATRIX_P1-05.md`): The FUSE adapter's rename method dispatch.
