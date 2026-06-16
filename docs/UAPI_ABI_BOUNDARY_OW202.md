# Preview UAPI/ABI Boundary (OW-202)

> TFR-019 authority note: this imported tracker-era note is historical input.
> The checked preview authority is
> `docs/PREVIEW_UAPI_ABI_BOUNDARY_OW202.md`; this file must not be cited as a
> current Linux ioctl/statx/ublk ABI, kernel module ABI, or production freeze.

This document describes historical tracker item 202 for the preview boundary.
It captured an old source-visible layout snapshot for `vfs_boundary_mirror`
records in the retired `crates/tidefs-schema-codec-vfs-boundary` path. Current
source uses `crates/tidefs-schema-codec-vfs` for fixed-width VFS codec hooks.

## Historical Preview Surface

This historical preview boundary recorded a fixed-size mirror layer between
portable VFS engine values and ABI-safe scalar records:

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

These layout numbers are not current release authority. They remain useful only
as review input when comparing old mirror-layout expectations with the current
`tidefs-schema-codec-vfs` codec hooks.

## Continuity Rules

- Mirror structs are `#[repr(C)]`, fixed-size, and scalar-only.
- Core-to-mirror conversions emit reserved fields as zero.
- `InodeAttrMirror` rejects unknown `NodeKind` tags during conversion back to
  the VFS engine type.
- Variable-sized values such as request groups, directory-entry names, path
  bytes, xattr bytes, and symlink payloads remain outside this historical
  surface.
- Mirror records are non-authoritative projections. Local filesystem truth,
  committed roots, policy receipts, and response/refusal semantics remain owned
  by their source modules.



Historical validation command from the imported note:

```sh
cargo test -p tidefs-schema-codec-vfs-boundary --all-targets
```

That package name is no longer present in the current workspace.



## Non-Claims

This is not a production Linux ioctl/statx/ublk ABI freeze, not a kernel module
contract, and not proof that TideFS is kernelspace-ready. Later production UAPI
work must either deliberately preserve any relevant preview shape or create a
new tracked compatibility plan with implementation proof and an explicit freeze
decision.
