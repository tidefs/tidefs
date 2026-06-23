# POSIX ACL Xattr Codec and ACL Evaluation Design (P2 spec) — **SUPERSEDED**

> TFR-019 authority classification: Historical input. See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

> ⚠️ **This document has been superseded** by the consolidated design-spec at
> [`docs/design/posix-acl-xattr-codec-and-evaluation-design.md`](design/posix-acl-xattr-codec-and-evaluation-design.md)
> with historical Forgejo issue #2032 provenance.


Maturity: **design-spec** for the POSIX ACL xattr encode/decode layer,
canonical ACL evaluation algorithm, and mode↔ACL synchronisation.

This document carries historical Forgejo issue #1199 provenance.

## 1. Motivation

POSIX Access Control Lists extend the traditional owner/group/other permission
model with named user and named group entries, enabling fine-grained access
control beyond what `st_mode` bits alone can express. Linux stores POSIX ACLs
in extended attributes (`system.posix_acl_access` and
`system.posix_acl_default`) using a compact binary format.

The Rust codebase currently has no ACL logic at any layer: xattr get/set/list/remove
work generically, the FUSE adapter delegates to the local filesystem, but the
engine has no awareness that ACL xattrs carry semantic weight. This means:

- **Permission checking is incomplete.** Without ACL evaluation, permission
  decisions fall through to kernel `default_permissions` (fragile and not
  always sufficient) or to basic mode-bit checks that ignore named user/group
  entries entirely.
- **xfstests cannot pass the ACL suite.** Tests `generic/099`, `generic/237`,
  `generic/307`, `generic/319`, and others exercise ACL behaviour. A filesystem
  that stores ACL xattrs but doesn't evaluate them fails these tests.
- **Mode bits drift from ACL truth.** When `setxattr` writes a new access ACL,
  the visible `st_mode` permission bits must be recomputed from the ACL. When
  `chmod` changes mode bits, the ACL equivalence entries must be updated.
  Without this synchronisation, `ls -l` and `getfacl` report contradictory
  information.

ZFS handles ACLs at the ZPL layer with a dedicated ACL implementation in
`zfs_acl.c`. TideFS must provide an equivalent layer that is deterministic,
testable, and integrated with the existing xattr infrastructure.

## 2. Linux POSIX ACL xattr format

### 2.1 Binary layout

```
offset  size  field
0       4     version (u32 LE, must be 0x0002)
4       8*N   entries (N × entry record)
```

Each entry is 8 bytes:

```
offset  size  field
0       2     tag   (u16 LE)
2       2     perm  (u16 LE, only bits 0..2 used)
4       4     id    (u32 LE, uid/gid for USER/GROUP; 0 otherwise)
```

Total xattr payload: `4 + 8*N` bytes.

### 2.2 Tag types (from linux/posix_acl_xattr.h)

| Constant | Value | Meaning |
|---|---|---|
| `ACL_USER_OBJ` | 0x01 | File owner |
| `ACL_USER` | 0x02 | Named user (id = uid) |
| `ACL_GROUP_OBJ` | 0x04 | File owning group |
| `ACL_GROUP` | 0x08 | Named group (id = gid) |
| `ACL_MASK` | 0x10 | Maximum permissions for group class |
| `ACL_OTHER` | 0x20 | Everyone else |

A valid minimal access ACL has exactly 4 entries: `USER_OBJ`, `GROUP_OBJ`,
`OTHER`, and optionally `MASK`. Named `USER` and `GROUP` entries extend this
base set. `MASK` is required whenever any named `USER` or named `GROUP` entry
is present.

### 2.3 Rust types

```rust
/// One entry in a POSIX ACL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PosixAclEntry {
    pub tag: u16,
    pub perm: u16,   // 0..7
    pub id: u32,
}

/// A decoded POSIX ACL (up to 32 entries per ext4 limit, enforced at decode).
pub type PosixAcl = Vec<PosixAclEntry>;

/// ACL xattr version constant.
pub const POSIX_ACL_XATTR_VERSION: u32 = 0x0002;
```

## 3. Core algorithms

All algorithms are ported from the v0.262 Python reference
(`tidefs_core/posix_acl_xattr.py`, 300 lines) and are deterministic: no OS
I/O, no internal allocation beyond the decoded `Vec<PosixAclEntry>`, and
explicit `Result` returns for all expected failure modes.

### 3.1 decode_posix_acl_xattr

```rust
pub fn decode_posix_acl_xattr(data: &[u8]) -> Result<PosixAcl, AclError>
```

- Read version u32 LE; reject if != 0x0002.
- Iterate entry records: unpack `tag: u16 LE`, `perm: u16 LE`, `id: u32 LE`.
- Return `Vec<PosixAclEntry>`.

Error cases:
- Payload too short (< 4 bytes)
- Unsupported version
- Payload length not `4 + 8*N`
- Entry count exceeds 32 (ext4-style safety bound)

### 3.2 encode_posix_acl_xattr

```rust
pub fn encode_posix_acl_xattr(entries: &[PosixAclEntry]) -> Vec<u8>
```

- Allocate `4 + 8 * entries.len()` bytes.
- Write version u32 LE at offset 0.
- Pack each entry as `(tag u16 LE, perm u16 LE, id u32 LE)`.
- Deterministic: entries are serialised in input order.

### 3.3 apply_chmod_to_acl

```rust
pub fn apply_chmod_to_acl(acl: &PosixAcl, new_mode: u32) -> PosixAcl
```

Implements the Linux convention for updating ACL equivalence entries when
`chmod(2)` changes permission bits:

- `USER_OBJ.perm` ← `(new_mode >> 6) & 0x7` (owner bits)
- `GROUP_OBJ.perm` ← `(new_mode >> 3) & 0x7` (group bits)
- `OTHER.perm` ← `new_mode & 0x7` (other bits)
- `MASK.perm` (if present) ← `(new_mode >> 3) & 0x7` (group bits)
- Named `USER` and named `GROUP` entries are **unchanged**.

Returns a new `PosixAcl`; does not mutate the input.

This is the function called when the FUSE adapter handles a `setattr` with
`FATTR_MODE` and the inode carries an access ACL.

### 3.4 posix_acl_perm_bits_for_caller

```rust
pub fn posix_acl_perm_bits_for_caller(
    acl: &PosixAcl,
    file_uid: u32,
    file_gid: u32,
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
    mode_fallback: u32,
) -> u8
```

The canonical POSIX ACL evaluation algorithm, returning `0..7` rwx bits:

1. **Owner check.** If `caller_uid == file_uid`, return `USER_OBJ.perm`.
   If `USER_OBJ` is missing (degraded ACL), fall back to owner bits from
   `mode_fallback`.

2. **Named user check.** Iterate named `USER` entries; if `entry.id ==
   caller_uid`, return `entry.perm & MASK.perm` (when MASK is present) or
   `entry.perm` directly. First match wins.

3. **Group class check.** If the caller's gid matches `file_gid`, or any of
   the caller's supplementary groups matches `file_gid` or any named `GROUP`
   entry's id, compute the union of permissions:
   - Start with `GROUP_OBJ.perm` (if matching owning group)
   - OR-in each matching named `GROUP.perm`
   - Clamp by `MASK.perm` (if present)
   Return the result.

4. **Other fallback.** Return `OTHER.perm`. If `OTHER` is missing, fall back
   to other bits from `mode_fallback`.

The `mode_fallback` parameter ensures the algorithm works even when the ACL
is incomplete (e.g., after manual xattr manipulation). In the normal case
(well-formed ACL), all required entries are present and `mode_fallback` is
never consulted.

### 3.5 posix_mode_from_access_acl

```rust
pub fn posix_mode_from_access_acl(acl: &PosixAcl, old_mode: u32) -> u32
```

Derives `st_mode` permission bits from an access ACL, preserving file-type
and special bits (setuid/setgid/sticky) from `old_mode`:

- User bits ← `USER_OBJ.perm` (or `(old_mode >> 6) & 0x7` if missing)
- Group bits ← `MASK.perm` if `MASK` present, else `GROUP_OBJ.perm`
  (or `(old_mode >> 3) & 0x7` if missing)
- Other bits ← `OTHER.perm` (or `old_mode & 0x7` if missing)

This is the function called after `setxattr("system.posix_acl_access", ...)`
to update the inode's visible `st_mode`.

## 4. Default ACL inheritance

When an object is created inside a directory that carries a
`system.posix_acl_default` xattr, the new object inherits ACL entries.

### 4.1 File creation

1. Read parent's `system.posix_acl_default`.
2. Apply `apply_chmod_to_acl` with the raw requested create mode to produce
   the file's access ACL. When a parent default ACL exists, Linux ignores the
   process umask for this inheritance calculation; the explicit mode argument
   still limits the inherited ACL.
3. Store the result as `system.posix_acl_access` on the new file.
4. Derive the visible permission bits from the inherited access ACL with
   `posix_mode_from_access_acl`.
5. The file does **not** inherit `system.posix_acl_default`.

### 4.2 Directory creation

1. Read parent's `system.posix_acl_default`.
2. Copy it verbatim as the new directory's `system.posix_acl_default`.
3. Apply `apply_chmod_to_acl` with the raw requested mkdir mode to produce
   the new directory's `system.posix_acl_access`.
4. Derive the visible permission bits from the inherited access ACL.
5. Store both `system.posix_acl_access` and `system.posix_acl_default` on
   the new directory.

### 4.3 No-parent-ACL case

When the parent directory has no `system.posix_acl_default`, the new object
is created with traditional mode bits only, including the process umask. No
ACL xattrs are set on the new object. This is the default behaviour and
matches Linux ext4/xfs semantics.

### 4.4 Inheritance integration point

Inheritance must fire during `create`, `mkdir`, and metadata-only `mknod`
creation in the local filesystem (not in the FUSE adapter), because it
requires atomic xattr writes within the same transaction as the inode
creation. The integration point is:

- `LocalFileSystem::create()` — after inode allocation, before commit
- `LocalFileSystem::mkdir()` — after inode allocation, before commit
- `VfsLocalFileSystem::mknod()` / metadata-only node creation — after inode
  allocation, before commit

The parent directory's default ACL is read via the existing xattr storage path
and processed through the codec functions above. FUSE passes the raw request
mode through to the local filesystem when the parent has a default ACL, then
skips a follow-up `FATTR_MODE` chmod so the inherited ACL is not overwritten.

## 5. ACL ↔ mode synchronisation

### 5.1 setxattr(access_acl) → mode update

When `setxattr` writes a new `system.posix_acl_access` value:

2. Compute new mode bits via `posix_mode_from_access_acl`.
3. Update the inode's `st_mode` permission bits (preserving file-type and
   special bits).
4. The xattr payload is stored as-is through the existing xattr path.

This requires the `setxattr` handler in `LocalFileSystem` to recognise the
`system.posix_acl_access` name and trigger the mode update atomically within
the same transaction.

### 5.2 setattr(chmod) → ACL update

When `setattr` changes `st_mode` permission bits and the inode carries a
`system.posix_acl_access` xattr:

1. Read the existing access ACL.
2. Apply Linux chmod synchronization with the new mode: `USER_OBJ` and
   `OTHER` receive the owner/other mode bits, `ACL_MASK` receives the group
   mode bits when present, and `GROUP_OBJ` receives the group mode bits only
   when no `ACL_MASK` entry exists.
3. Store the updated ACL via the xattr path.
4. The mode bits are updated through the existing setattr path.

This requires the `setattr` handler in `LocalFileSystem` to recognise when
mode bits change on an inode that carries an access ACL.

### 5.3 removexattr(access_acl) → no mode change

When `removexattr` removes `system.posix_acl_access`, the inode's mode bits
are **not** recomputed. The existing mode bits remain as-is. This matches
Linux behaviour: removing an ACL does not reset permissions; it only stops
ACL evaluation, falling back to traditional mode-bit checking.

## 6. Crate placement

The ACL codec and evaluation functions are pure, deterministic, and have no
I/O dependencies. They fit naturally in a shared library crate accessible to
both the local filesystem and the FUSE adapter.

**Decision: `tidefs-posix-acl` (new crate)**

| Dependency | Rationale |
|---|---|
| `tidefs-types-vfs-core` (optional) | For `Errno` type in error returns |
| No I/O crates | All functions are pure computation |
| No async runtime | No I/O, no spawning |

Alternative considered: embedding in `tidefs-local-filesystem`. Rejected
because the FUSE adapter needs ACL evaluation for permission checking
(§3.4) without importing the entire local filesystem crate. A separate
crate keeps the dependency graph clean.

The crate exposes:

```
tidefs-posix-acl/
  src/
    lib.rs          — re-exports
    codec.rs        — decode_posix_acl_xattr, encode_posix_acl_xattr
    chmod.rs        — apply_chmod_to_acl
    eval.rs         — posix_acl_perm_bits_for_caller
    mode.rs         — posix_mode_from_access_acl
    types.rs        — PosixAclEntry, PosixAcl, AclError, tag constants
```

Wire-up crates (in separate implementation issues):

| Wire-up | Issue |
|---|---|
| `tidefs-local-filesystem` — xattr/mode sync hooks | #NEW |
| `tidefs-posix-filesystem-adapter-daemon` — ACL eval in permission check | #NEW |
| `tidefs-local-filesystem` — default ACL inheritance on create/mkdir/mknod | #NEW |


### 7.1 Unit tests (in `tidefs-posix-acl`)

- **Round-trip**: encode arbitrary `PosixAcl` → decode → assert equality.
  Cover all tag types, edge perm values (0, 7), uid/gid values (0,
  0xFFFFFFFF).
- **Decode errors**: too short, wrong version, misaligned payload, >32
  entries.
- **Chmod application**: USER_OBJ/GROUP_OBJ/OTHER/MASK perm update with
  named entries unchanged. Verify mode bits 000..777 produce correct
  perms.
- **ACL evaluation matrix**: owner access, named user match, named user
  no-match, group match (owning group), group match (named group with
  and without MASK), MASK clamping, other fallback. Cover all 4 algorithm
  steps with explicit assertions.
- **Mode-from-ACL**: MASK present → group bits from MASK; MASK absent →
  group bits from GROUP_OBJ; missing entries → fallback from old_mode.
- **Degraded ACL fallback**: ACLs missing USER_OBJ/GROUP_OBJ/OTHER should
  fall back to `mode_fallback` bits without panicking.

### 7.2 Integration tests (in `tidefs-local-filesystem`)

- **ACL inheritance on create**: dir with default ACL → new file inherits
  access ACL limited by the raw requested mode, no default ACL on file.
- **ACL inheritance on mkdir**: dir with default ACL → new dir inherits
  both access ACL limited by the raw requested mode and default ACL copied
  verbatim.
- **Chmod updates ACL**: file with access ACL → chmod 600 → ACL USER_OBJ,
  MASK, and OTHER entries update; GROUP_OBJ updates only when no MASK exists.
- **Setxattr updates mode**: file → setxattr access ACL with USER_OBJ=7,
  GROUP_OBJ=5, MASK=3, OTHER=5 → mode bits show 0o735.
- **Removexattr leaves mode unchanged**: file with access ACL → removexattr
  → mode bits unchanged, ACL evaluation falls back to mode bits.
- **No-default-ACL case**: parent without default ACL → new file/dir
  created with traditional umask-adjusted mode bits only, no ACL xattrs.

### 7.3 xfstests gate

the FUSE adapter. This is deferred to the wire-up implementation issues;
this design spec only provides the building blocks.

## 8. Relationship to existing issues

| Issue | Relationship |
|---|---|
| Tracker-era #1290 (Polymorphic xattr storage) | ACL xattrs are stored through the polymorphic xattr layer. The codec described here is a consumer of that storage. |
| Tracker-era #1213 (VFS Engine API contract) | ACL xattrs travel through the same `getxattr`/`setxattr`/`listxattr`/`removexattr` ops. No new engine ops are required. |
| Tracker-era #1145 (FUSE daemon topology) | ACL evaluation (§3.4) is part of the permission enforcement the daemon must perform. |
| Tracker-era #1156 (xfstests matrix) | ACL tests are part of the xfstests baseline; this spec provides the algorithmic building blocks. |
| Tracker-era #1233 (FUSE binding strategy) | ACL evaluation runs in the daemon process and is subject to the same coherency profile constraints. |

## 9. Deferred to implementation issues

- **Permission check integration**: wiring `posix_acl_perm_bits_for_caller`
  into the FUSE daemon's access check path requires a separate issue covering
  the full permission model (ACL + mode bits + capability checks).
- **NFSv4 / RichACL**: this spec covers POSIX draft ACLs only (the Linux
  `system.posix_acl_*` xattrs). NFSv4-style rich ACLs are out of scope.
- **Performance**: ACL decode/encode per permission check is acceptable for
  correctness-first phases. A decoded-ACL cache in the inode structure is
  deferred to a performance issue.
- **setfacl command-line tool**: the POSIX ACL CLI tool for managing ACLs
  from userspace is deferred. The kernel's existing `getfacl`/`setfacl`
  work through the xattr interface and need no special support.
- **ACL mask recalculation**: automatic `MASK` recalculation when adding
  or removing named entries is deferred. The design book notes this as a
  future feature; the initial implementation accepts the ACL as written by
  userspace.

## 10. Implementation plan

| Phase | Scope | Crate |
|---|---|---|
| 1 | `PosixAclEntry`, `PosixAcl`, `AclError`, tag constants | `tidefs-posix-acl` |
| 2 | `decode_posix_acl_xattr`, `encode_posix_acl_xattr` | `tidefs-posix-acl` |
| 3 | `apply_chmod_to_acl`, `posix_mode_from_access_acl` | `tidefs-posix-acl` |
| 4 | `posix_acl_perm_bits_for_caller` | `tidefs-posix-acl` |
| 5 | xattr/mode sync hooks in `LocalFileSystem` | `tidefs-local-filesystem` |
| 6 | Default ACL inheritance on create/mkdir | `tidefs-local-filesystem` |
| 7 | ACL eval wire-up in FUSE adapter permission check | FUSE adapter |

Phases 1-4 deliver the self-contained `tidefs-posix-acl` crate with full unit
test coverage. Phases 5-8 were planned as wire-up and integration, each a
separate tracker-era issue.
