# Preview UAPI/ABI Boundary (OW-202)

> TFR-019 authority note: this imported implementation note is review material,
> the behavior below as needing reconciliation with current source,
> `docs/REVIEW_TODO_REGISTER.md`, and `docs/WHOLE_REPO_REVIEW.md`.

This document describes historical tracker item 202 for the preview boundary.
It freezes the source-visible layout contract for `vfs_boundary_mirror` records in
`crates/tidefs-schema-codec-vfs-boundary`, not a production Linux kernel UAPI.

## Frozen Preview Surface

The current preview boundary is the fixed-size mirror layer between portable VFS
engine values and ABI-safe scalar records:

| Mirror | Size | Align | Continuity rule |
|---|---:|---:|---|
| `EngineFileHandleMirror` | 32 | 8 | Carries inode id, open flags, file-handle id, and lock-owner as fixed-width scalars. |
| `EngineDirHandleMirror` | 16 | 8 | Carries inode id and directory-handle id as fixed-width scalars. |
| `SetAttrMirror` | 48 | 8 | Carries the current fixed setattr mask and timestamp/size scalars. |
| `LockSpecMirror` | 32 | 8 | Carries lock type, whence, byte range, and pid. |
| `PosixAttrsMirror` | 72 | 8 | Carries current POSIX attr projection scalars. |
| `InodeFlagsMirror` | 4 | 1 | Carries boolean inode flags as byte values. |
| `InodeAttrMirror` | 120 | 8 | Carries inode id, generation, node-kind tag, POSIX attrs, flags, and revision counters. |
| `StatFsMirror` | 72 | 8 | Carries allocator/statfs projection scalars. |

These layout numbers are implementation-tracked non-release by compile-time size assertions and unit
tests in `crates/tidefs-schema-codec-vfs-boundary/src/lib.rs`.

## Continuity Rules

- Mirror structs are `#[repr(C)]`, fixed-size, and scalar-only.
- Core-to-mirror conversions emit reserved fields as zero.
- `InodeAttrMirror` rejects unknown `NodeKind` tags during conversion back to
  the VFS engine type.
- Variable-sized values such as request groups, directory-entry names, path
  bytes, xattr bytes, and symlink payloads remain outside this frozen preview
  surface.
- Mirror records are non-authoritative projections. Local filesystem truth,
  committed roots, policy receipts, and response/refusal semantics remain owned
  by their source modules.



```sh
cargo test -p tidefs-schema-codec-vfs-boundary --all-targets
```


```sh
```



## Non-Claims

This is not a production Linux ioctl/statx/ublk ABI freeze, not a kernel module
contract, and not proof that TideFS is kernelspace-ready. Later production UAPI
work must either preserve these preview layouts or create a new compatibility
