# POSIX subset notes (OW-104/OW-106/OW-107/OW-102/OW-014/OW-015/OW-108/OW-109)

> TFR-019 authority note: this imported implementation note is review material,
> the behavior below as needing reconciliation with current source,
> `docs/REVIEW_TODO_REGISTER.md`, and `docs/WHOLE_REPO_REVIEW.md`.

This document describes historical tracker item 104 by defining the first
userspace FUSE contract before any mount implementation claims POSIX
capability. The source of truth is `current_posix_subset_entries()` in
`crates/tidefs-local-filesystem/src/lib.rs`; this document explains the same
matrix in human terms.

The v0.409 code has a userspace FUSE adapter wired through
`docs/FUSE_MOUNT.md`. Rows marked "included in first FUSE current" are
the original v0.408 mount target. Rows marked "included after first FUSE
current" are OW-106 semantics added in v0.409.
v0.410 adds the OW-107 pass/fail/skip scoreboard harness without expanding the
supported syscall matrix.
v0.411 adds the OW-101 chunked file-content layout without expanding the
supported syscall matrix.
v0.412 adds OW-102 statfs and fallocate mode-zero allocator behavior.
v0.414 adds OW-014 object-store v3 record integrity without expanding the
supported syscall matrix.
v0.415 adds OW-015 committed-root authentication without expanding the
supported syscall matrix.
v0.416 adds OW-108 local snapshots/rollback without expanding the supported
syscall matrix.
v0.417 adds OW-109 changed-record send/receive without expanding the supported
syscall matrix.
PC-004B adds a bounded dense-file `lseek` surface for the userspace FUSE
current without claiming a POSIX-complete sparse extent map.
OW-204 now source-binds the page-cache/writeback/mmap law, but live mmap
coherency remains deferred until runtime implementation and live mmap tests
exist.


```text
cargo run -p tidefs-xtask -- check-current-posix-subset
```

The full Nix gate also runs this command through:

```text
```

## Matrix states

| State | Meaning |
|---|---|
| included in first FUSE current | Required for the first mounted current once FUSE wiring exists. |
| included after first FUSE current | Added after the first mount path and covered by targeted useful-current tests. |
| blocked before useful current | Must not be claimed until the named blocker is resolved. |
| deferred after first current | Intentionally outside the first useful current; must return an explicit unsupported error. |
| explicitly unsupported | Not part of the first userspace current. |

## Syscall and semantic matrix

| Operation / semantic | State | Expected error boundary | Notes |
|---|---|---|---|
| `lookup/getattr` | included in first FUSE current | `ENOENT` / `EIO` | Path lookup and inode attributes map to existing namespace and `InodeAttr` surfaces. |
| `opendir/readdir/releasedir` | included in first FUSE current | `ENOENT` / `ENOTDIR` / `EIO` | Directory reads expose stable names without mutating truth. |
| `create/open/release` | included in first FUSE current | `EEXIST` / `ENOENT` / `EISDIR` / `EIO` | Simple regular-file open is included; handle lifetime is separate. |
| `read/write/truncate` | included in first FUSE current | `ENOENT` / `EISDIR` / `EIO` | Backed by the OW-101 chunked content layout. |
| `mkdir/rmdir-empty` | included in first FUSE current | `EEXIST` / `ENOENT` / `ENOTEMPTY` / `ENOTDIR` / `EIO` | Non-empty directory removal must fail explicitly. |
| `link/unlink` | included in first FUSE current | `ENOENT` / `EISDIR` / `EIO` | Closed-path unlink is included in the first current; unlink-while-open is a separate OW-106 row. |
| `rename` / `renameat2` | included in first FUSE current | `ENOENT` / `ENOTDIR` / `EISDIR` / `ENOTEMPTY` / `EINVAL` / `EIO` | Basic rename is included; rename replacement is a separate OW-106 row. `renameat2` `RENAME_EXCHANGE` and `RENAME_NOREPLACE` flags implemented (PC-004F, v0.418); `RENAME_WHITEOUT` is unsupported. |
| `symlink/readlink` | included in first FUSE current | `EEXIST` / `ENOENT` / `EINVAL` / `EIO` | Symlink targets are byte-preserving local namespace data. |
| `fsync-file` | included after first FUSE current | `EIO` on store sync failure | `OW-106` binds file fsync success to root-slot publication plus Local Object Store sync. |
| `fsync-directory` | included after first FUSE current | `EIO` on store sync failure | `OW-106` maps directory fsync to the same committed namespace root-slot and store sync boundary. |
| `unlink-while-open` | included after first FUSE current | `ENOENT` / `EISDIR` / `EIO` | `OW-106` preserves last-link regular-file content in FUSE session state until final release. |
| `rename-over-target` | included after first FUSE current | `ENOENT` / `ENOTDIR` / `EISDIR` / `ENOTEMPTY` / `EINVAL` / `EIO` | `OW-106` commits replacement rename atomically and preserves replaced open regular-file handles in FUSE session state. |
| `statfs` | included after first FUSE current | `EIO` on allocator/report failure | `OW-102` reports finite content/inode allocator truth; free blocks exclude content still protected by committed fallback roots. |
| `chmod/chown/utimens` | included after first FUSE current | `ENOENT` | PC-001M stores ownership and mode mutations in FUSE session metadata; these are visible through `getattr` within the session but are not persisted across remounts. |
| `flock` / POSIX locks (`getlk`/`setlk`) | included after first FUSE current | `EOPNOTSUPP` on unsupported lock types | `getlk`/`setlk` handlers wired (PC-007, v0.419) and exercised through mounted byte-range lock coverage (#2931). `getlk` reports tracked conflicts, non-blocking locks update `LockTracker`, shared read locks coexist, overlapping write locks conflict, adjacent ranges remain independent, and close/flush releases PID-owned ranges. Blocking `setlkw` semantics use waiter/wakeup through the lock dispatch with FUSE_INTERRUPT-aware blocking (no arbitrary timeout). |
| `fallocate` | included after first FUSE current | `ENOSPC` / `EOPNOTSUPP` / `EINVAL` | Mode `0` (allocate), `FALLOC_FL_PUNCH_HOLE`, `FALLOC_FL_ZERO_RANGE`, `FALLOC_FL_KEEP_SIZE`, `FALLOC_FL_COLLAPSE_RANGE`, and `FALLOC_FL_INSERT_RANGE` implemented (OW-102, v0.412; PC-008B, v0.418). |
| `mmap-coherency` | deferred after first current | `EOPNOTSUPP` | `OW-204` specifies page-cache/writeback/mmap law, but live mmap coherency remains deferred until runtime implementation and live mmap tests exist. |
| `lseek`: `SEEK_SET` / `SEEK_CUR` / `SEEK_END` / `SEEK_DATA` / `SEEK_HOLE` | included after first FUSE current | `EINVAL` / `ENXIO` / `EOPNOTSUPP` | `PC-004B` supports truthful dense-file answers: bytes before EOF are data, EOF is the only hole boundary, offsets at or beyond EOF return `ENXIO`. `SEEK_CUR` supported (v0.418). |
| `fiemap` (`FS_IOC_FIEMAP`) | included after first FUSE current | `EINVAL` / `ERANGE` | Dense-file extent reporting via FUSE ioctl handler (PC-008, v0.418). Reports a single extent covering the requested logical range to EOF; query-mode (`fm_extent_count=0`) and beyond-EOF cases handled. |

## Non-claims

This matrix does not claim POSIX-complete behavior, a mounted filesystem, xfstests
readiness, or production readiness. It only defines the boundary the first FUSE
implementation must obey.

## FUSE binding strategy

This POSIX subset matrix assumes the FUSE binding strategy defined in
[FUSE_BINDING_STRATEGY_AND_FEATURE_MATRIX_P1-05.md](FUSE_BINDING_STRATEGY_AND_FEATURE_MATRIX_P1-05.md).
Capability-dependent operations (ACL, killpriv, writeback cache) require the
corresponding FUSE capabilities to be negotiated at mount time per the binding
strategy's coherency profile.
