# POSIX ACL xattr codec and ACL evaluation design

**Issues**: [#2032](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/2032) (primary, consolidated design-spec finalized), [#1908](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1908) (original tracking), [#1818](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1818) (coordinator-generated design-spec entry), [#1690](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1690) (design-spec tracking), [#1635](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1635)
**Status**: design-spec
**Maturity**: design-spec — definitive specification for the on-wire codec, canonical evaluation algorithm, and integration contracts for POSIX ACL support
**Lane**: storage-core
**Depends on**: polymorphic xattr storage (implemented), dataset feature flags (implemented), per-inode xattr persistence (implemented)
**Related**: FUSE xattr ops, VFS access check path, namespace operation security model

## 1. Problem statement

POSIX.1e access control lists (ACLs) are the industry-standard mechanism for
fine-grained file and directory permissions beyond the traditional owner/group/other
mode bits. The Linux kernel stores ACLs as extended attributes with the well-known
names `system.posix_acl_access` and `system.posix_acl_default`. A complete
implementation requires:

1. **On-wire codec**: encode/decode the Linux binary xattr format for interop
   with `getfacl`/`setfacl` and kernel-internal representations.
2. **Canonical evaluation**: given an ACL and caller credentials (uid, gid,
   supplementary groups), determine the effective permission mask.
3. **mode ↔ ACL synchronisation**: keep the traditional `st_mode` permission bits
   consistent with the access ACL after `setxattr` or `chmod`.
4. **Default-ACL inheritance**: when a file or directory is created inside a
   directory that carries a default ACL, the new object inherits an access ACL
   (and, for directories, a default ACL) derived from the parent.

TideFS must support all of these as a pure, deterministic, allocation-conscious
library that integrates with the polymorphic xattr storage layer and the
feature-flag system.

## 2. Scope and non-scope

### In scope

- Binary xattr codec (Linux `POSIX_ACL_XATTR_VERSION` v2, little-endian)
- Canonical ACL evaluation against caller credentials (uid/gid/groups)
- `mode_from_access_acl` — derive `st_mode` permission bits from an access ACL
- `minimal_access_acl_from_mode` — produce a minimal (3-entry) ACL from mode bits
- `apply_chmod_to_acl` — synchronise an existing ACL with a new `chmod` mode
- `default_acl_inheritance_for_parent` — compute child ACLs during creation
- Integration contract: read ACL from xattr storage → evaluate → return permission mask
- Integration contract: deserialise ACL xattr → apply chmod → re-serialise → write back
- Integration contract: on file/directory/special-node create, inherit from
  parent default ACL
- Feature gate: dataset feature flag `org.tidefs:posix_acl`

### Explicitly out of scope

- NFSv4 / RichACL / CIFS ACL formats (POSIX only)
- ACL caching strategies (deferred to the evaluation hot-path optimisation)
- Cluster-distributed ACL evaluation (local-node evaluation only; cluster
  replication is a separate wire-up issue)
- LDAP/NIS/AD uid↔username resolution (caller provides numeric uid/gid)
- SELinux / SMACK / AppArmor label xattrs (`security.*` namespace)
- setfacl command-line tool (deferred to CLI subcommand)
- ACL inheritance across cluster nodes (deferred to cluster namespace wire-up)

## 3. Architecture overview

```
┌─────────────────────────────────────────────────────┐
│  FUSE / NFS / VFS access path                        │
│  ┌──────────┐                                        │
│  │ access() │── checks feature flag ──┐               │
│  └──────────┘                         ▼               │
│                          ┌───────────────────────┐    │
│                          │  ACL evaluator         │    │
│                          │  posix_acl_perm_bits_  │    │
│                          │  for_caller()          │    │
│                          └───────────┬───────────┘    │
│                                      │                │
│                     reads ACL from   │                │
│                     xattr storage    │                │
│                                      ▼                │
│  ┌──────────────────────────────────────────┐        │
│  │  Polymorphic xattr storage               │        │
│  │  (Inline XattrBundleV1 → XattrBtreeRootV1)│       │
│  └──────────────┬───────────────────────────┘        │
│                 │                                     │
│                 │ key: "system.posix_acl_access"      │
│                 │ key: "system.posix_acl_default"     │
│                 ▼                                     │
│  ┌──────────────────────────────────────────┐        │
│  │  POSIX ACL codec (tidefs-posix-acl)      │        │
│  │  ┌─────────────────────────────────┐     │        │
│  │  │ decode_posix_acl_xattr(&[u8])   │     │        │
│  │  │ encode_posix_acl_xattr(&[Entry])│     │        │
│  │  │ PosixAclEntry / PosixAcl        │     │        │
│  │  └─────────────────────────────────┘     │        │
│  └──────────────────────────────────────────┘        │
│                                                      │
│  ┌──────────────────────────────────────────┐        │
│  │  mode ↔ ACL synchronisation               │        │
│  │  ┌─────────────────────────────────┐     │        │
│  │  │ mode_from_access_acl()          │     │        │
│  │  │ minimal_access_acl_from_mode()  │     │        │
│  │  │ apply_chmod_to_acl()            │     │        │
│  │  └─────────────────────────────────┘     │        │
│  └──────────────────────────────────────────┘        │
│                                                      │
│  ┌──────────────────────────────────────────┐        │
│  │  Default ACL inheritance                  │        │
│  │  ┌─────────────────────────────────┐     │        │
│  │  │ default_acl_inheritance_for_    │     │        │
│  │  │ parent()                        │     │        │
│  │  └─────────────────────────────────┘     │        │
│  └──────────────────────────────────────────┘        │
└─────────────────────────────────────────────────────┘
```

The `tidefs-posix-acl` crate is the single authority for all ACL semantics.
It is `no_std` + `forbid(unsafe_code)`, pure and deterministic. Higher layers
(FUSE handler, VFS engine, namespace operations) do not interpret ACL entries;
they call into this crate.

## 4. On-wire format

### 4.1 Binary layout

The Linux kernel uses a simple packed binary format for `system.posix_acl_access`
and `system.posix_acl_default`:

```
Offset  Size  Field
─────────────────────────────────────────
0       4     version (u32 LE, must be 0x0002)
4       8     entry[0]: tag (u16 LE) + perm (u16 LE) + id (u32 LE)
12      8     entry[1]: ...
...
4+8N    -     end of payload
```

Total payload size: `4 + 8 × N` bytes, where N is the number of entries.

### 4.2 Entry structure

Each entry occupies exactly 8 bytes:

```
Offset  Size  Field
─────────────────────────────
+0      2     e_tag  (u16 LE)
+2      2     e_perm (u16 LE)
+4      4     e_id   (u32 LE, uid/gid or 0)
```

- `e_tag`: one of `ACL_USER_OBJ` (0x01), `ACL_USER` (0x02), `ACL_GROUP_OBJ` (0x04),
  `ACL_GROUP` (0x08), `ACL_MASK` (0x10), `ACL_OTHER` (0x20).
- `e_perm`: only bits 0..2 are meaningful (rwx), value must be 0..7.
- `e_id`: uid for `ACL_USER`, gid for `ACL_GROUP`; set to `ACL_UNDEFINED_ID` (0xFFFFFFFF)
  for other tag types in some implementations; TideFS normalises to 0.

### 4.3 Design tradeoffs

| Decision | Rationale |
|---|---|
| Fixed 8-byte entries, no variable-length fields | Simpler indexing, zero heap allocation during decode, O(1) random access |
| Version 0x0002 only | All Linux kernels since 2.6 use v2; no interop requirement for v1 |
| Max 32 entries (`MAX_ACL_ENTRIES`) | ext4 safety bound; prevents memory exhaustion from corrupt/malicious payloads |
| Little-endian only | Linux native byte order; no big-endian interop needed |
| No `ACL_UNDEFINED_ID` sentinel | Simplifies comparisons; 0 for unused id fields is unambiguous |

## 5. Data structures

### 5.1 `PosixAclEntry`

```rust
pub struct PosixAclEntry {
    pub tag: u16,   // ACL_USER_OBJ, ACL_USER, ACL_GROUP_OBJ, ACL_GROUP, ACL_MASK, ACL_OTHER
    pub perm: u16,  // 0..7 (rwx bits)
    pub id: u32,    // uid/gid for named user/group; 0 otherwise
}
```

### 5.2 `PosixAcl`

```rust
pub type PosixAcl = Vec<PosixAclEntry>;
```

Ordered list. The ACL evaluation algorithm (Section 6) relies on the canonical
entry ordering defined by POSIX.1e: `USER_OBJ`, named users, `GROUP_OBJ`, named
groups, `MASK`, `OTHER`. The xattr storage layer stores the ordered list; the
codec preserves order.

### 5.3 `AclError`

```rust
pub enum AclError {
    TooShort,            // < 4 bytes
    UnsupportedVersion,  // != 0x0002
    BadLength,           // not (4 + 8*N) bytes
    TooManyEntries,      // > MAX_ACL_ENTRIES (32)
    InvalidTag,          // unknown tag value
    InvalidPerm,         // perm > 0x7
}
```

All errors are `Copy` + `Eq`, suitable for zero-allocation error paths.

## 6. Algorithms

### 6.1 Decode (`decode_posix_acl_xattr`)

```
function decode_posix_acl_xattr(data: &[u8]) -> Result<PosixAcl, AclError>:
    if len(data) < 4: return TooShort
    version = u32_le(data[0..4])
    if version != 0x0002: return UnsupportedVersion
    remaining = data[4..]
    if len(remaining) % 8 != 0: return BadLength
    n = len(remaining) / 8
    if n > MAX_ACL_ENTRIES: return TooManyEntries

    entries = Vec::with_capacity(n)
    for each 8-byte chunk in remaining:
        tag = u16_le(chunk[0..2])
        perm = u16_le(chunk[2..4])
        id = u32_le(chunk[4..8])
        if perm > 0x7: return InvalidPerm
        if tag not in {USER_OBJ, USER, GROUP_OBJ, GROUP, MASK, OTHER}: return InvalidTag
        entries.push(PosixAclEntry{tag, perm, id})

    return Ok(entries)
```

**Complexity**: O(n) time, O(n) heap (one `Vec` allocation). The `Vec::with_capacity`
call ensures a single allocation regardless of entry count.

### 6.2 Encode (`encode_posix_acl_xattr`)

```
function encode_posix_acl_xattr(entries: &[PosixAclEntry]) -> Vec<u8>:
    buf = Vec::with_capacity(4 + 8 * len(entries))
    append u32_le(0x0002)  // version
    for each entry:
        append u16_le(entry.tag)
        append u16_le(entry.perm)
        append u32_le(entry.id)
    return buf
```

**Complexity**: O(n) time, O(n) heap (one allocation). The output is exactly
`4 + 8 × len(entries)` bytes.

### 6.3 Canonical ACL evaluation (`posix_acl_perm_bits_for_caller`)

POSIX.1e defines the following evaluation algorithm. TideFS implements it
exactly, with no deviation from the specification.

```
function posix_acl_perm_bits_for_caller(
    acl: &[PosixAclEntry],   // access ACL
    uid: u32,                 // caller's uid
    gid: u32,                 // caller's gid
    owner_uid: u32,           // file owner uid
    owner_gid: u32,           // file owning group gid
    groups: &[u32],           // caller's supplementary groups
    requested: u16,           // requested r/w/x bits
) -> u16:

    // Step 1: File owner match
    if uid == owner_uid:
        user_obj_entry = find entry with tag == ACL_USER_OBJ
        return user_obj_entry.perm & requested

    // Step 2: Named user match (first-match-wins)
    for entry in acl where tag == ACL_USER:
        if entry.id == uid:
            // mask limits apply to named users
            mask_entry = find entry with tag == ACL_MASK
            if mask_entry exists:
                return entry.perm & mask_entry.perm & requested
            else:
                // No mask: group class entries map to GROUP_OBJ perm
                group_obj_entry = find entry with tag == ACL_GROUP_OBJ
                return entry.perm & (group_obj_entry?.perm ?? 0) & requested

    // Step 3: Group match
    group_matched = (gid == owner_gid) OR (any group in groups == owner_gid)
    if group_matched:
        group_obj_entry = find entry with tag == ACL_GROUP_OBJ
        base_group_perm = group_obj_entry.perm

        // Check named groups (first-match-wins)
        for entry in acl where tag == ACL_GROUP:
            if entry.id == gid or entry.id in groups:
                mask_entry = find entry with tag == ACL_MASK
                if mask_entry exists:
                    max_group_perm = entry.perm & mask_entry.perm
                else:
                    max_group_perm = entry.perm & base_group_perm
                return max(max_group_perm, base_group_perm) & requested

        // No named group matched
        mask_entry = find entry with tag == ACL_MASK
        if mask_entry exists:
            return mask_entry.perm & requested
        else:
            return group_obj_entry.perm & requested

    // Step 4: Other
    other_entry = find entry with tag == ACL_OTHER
    return other_entry.perm & requested
```

**Key invariants**:
- File owner (`uid == owner_uid`) bypasses all group and mask checks; only
  `ACL_USER_OBJ` entry applies.
- Named user entries are mask-limited when a mask entry is present.
- Group evaluation is cumulative: the caller gets the maximum of the owning-group
  permission and any matching named-group permissions, all subject to the mask.
- When no mask entry exists (minimal ACL), GROUP_OBJ acts as the effective
  mask for named users and named groups.

### 6.4 Mode from access ACL (`posix_mode_from_access_acl`)

Derives `st_mode` permission bits (the lower 9 bits) from an access ACL.

```
function posix_mode_from_access_acl(acl: &[PosixAclEntry], other_bits: u32) -> u32:
    owner_perm  = find(ACL_USER_OBJ).perm
    group_perm  = find(ACL_MASK)?.perm ?? find(ACL_GROUP_OBJ).perm
    other_perm  = find(ACL_OTHER).perm

    return (owner_perm << 6) | (group_perm << 3) | other_perm | other_bits
```

Since POSIX ACLs carry only rwx bits, the setuid/setgid/sticky bits (`other_bits`)
must be passed through from the file's existing mode. This is the caller's
responsibility.

### 6.5 Minimal access ACL from mode (`minimal_access_acl_from_mode`)

Produces the minimal 3-entry ACL equivalent to a given `st_mode` permission mask.

```
function minimal_access_acl_from_mode(mode: u32) -> PosixAcl:
    return [
        PosixAclEntry { tag: ACL_USER_OBJ,  perm: (mode >> 6) & 0x7, id: 0 },
        PosixAclEntry { tag: ACL_GROUP_OBJ, perm: (mode >> 3) & 0x7, id: 0 },
        PosixAclEntry { tag: ACL_OTHER,     perm: mode & 0x7,        id: 0 },
    ]
```

This function is used when:
- A file is created on a dataset with ACLs enabled but the parent has no default ACL.
- `chmod` is called and the file has no existing ACL (mode-only permission path).
- Converting from non-ACL to ACL-aware mode.

### 6.6 Chmod on ACL (`apply_chmod_to_acl`)

When `chmod` is called on a file that carries an access ACL, specific entries
are updated while preserving named user/group entries.

```
function apply_chmod_to_acl(acl: &[PosixAclEntry], new_mode: u32) -> PosixAcl:
    owner_perm  = (new_mode >> 6) & 0x7
    group_perm  = (new_mode >> 3) & 0x7
    other_perm  = new_mode & 0x7
    has_mask    = any(entry.tag == ACL_MASK for entry in acl)

    result = clone each entry from acl
    for entry in result:
        if entry.tag == ACL_USER_OBJ:              entry.perm = owner_perm
        if entry.tag == ACL_GROUP_OBJ && !has_mask: entry.perm = group_perm
        if entry.tag == ACL_OTHER:                 entry.perm = other_perm
        if entry.tag == ACL_MASK:                  entry.perm = group_perm
    return result
```

**Tradeoff**: Named user/group entries are preserved unchanged. This matches
Linux kernel behaviour: `chmod` updates `ACL_MASK` for the group class when a
mask exists, otherwise it updates `ACL_GROUP_OBJ`.

### 6.7 Default ACL inheritance (`default_acl_inheritance_for_parent`)

When creating a file, directory, or special node inside a directory that has a
default ACL (`system.posix_acl_default`), the new object inherits:

- **For files and special nodes**: an access ACL derived from the parent's
  default ACL, modified by the raw requested creation mode. When a parent
  default ACL exists, Linux ignores process umask for this inheritance
  calculation.
- **For directories**: both an access ACL (as above) AND a copy of the parent's
  default ACL as the child's default ACL.

```
function default_acl_inheritance_for_parent(
    parent_default: &[PosixAclEntry],  // decoded parent default ACL
    creation_mode: u32,                 // raw requested create/mkdir/mknod mode
    is_directory: bool,
) -> Vec<(key: &[u8], value: Vec<u8>)>:

    if parent_default is empty:
        return []  // No inheritance; mode-only permissions

    // Step 1: Build access ACL from parent default, then apply chmod
    access_acl = apply_chmod_to_acl(parent_default, creation_mode)

    // Step 2: Encode access ACL
    result = [("system.posix_acl_access", encode_posix_acl_xattr(&access_acl))]

    // Step 3: For directories, copy default ACL verbatim
    if is_directory:
        result.push(("system.posix_acl_default", encode_posix_acl_xattr(parent_default)))

    return result
```

**Key invariants**:
- The access ACL always gets `chmod` applied after inheritance; the creation
  mode supplied by the caller limits permissions.
- The resulting visible mode is derived from the inherited access ACL.
- The default ACL is copied unchanged to subdirectories; this is the mechanism
  for recursive ACL inheritance.
- Empty parent default ACL → no xattrs set on child → traditional mode-based
  permissions apply, including normal umask handling before the mode-only
  create.

## 7. Integration contracts

### 7.1 Feature gate

ACL evaluation is gated behind the dataset feature flag `org.tidefs:posix_acl`.
The check is:

```rust
if !dataset_flags.contains(FEATURE_POSIX_ACL) {
    // Fall back to traditional mode-based access check
}
```

When the flag is absent:
- `system.posix_acl_access` and `system.posix_acl_default` xattrs are not
  interpreted for access control.
- getxattr/listxattr/setxattr/removexattr for these keys may still operate
  (store/retrieve raw bytes) but the VFS access path ignores them.
- Default ACL inheritance is skipped during file/directory creation.

### 7.2 xattr storage integration

The polymorphic xattr storage stores ACLs as opaque byte blobs keyed by:

| Key | Type | Scope |
|---|---|---|
| `system.posix_acl_access` | binary | per-inode (files and directories) |
| `system.posix_acl_default` | binary | per-inode (directories only) |

**Read path**: xattr storage → `decode_posix_acl_xattr()` → `PosixAcl` → evaluation.
**Write path**: `PosixAcl` → `encode_posix_acl_xattr()` → xattr storage.

The codec is agnostic to whether xattrs are stored inline (`XattrBundleV1`) or
in the external B+tree (`XattrBtreeRootV1`); the storage layer abstracts this.

### 7.3 VFS access check integration

```
function check_access(inode, uid, gid, groups, requested_mask) -> Result<()>:

    if FEATURE_POSIX_ACL not in dataset_flags:
        return traditional_mode_check(inode.mode, uid, gid, requested_mask)

    // 1. Read ACL from xattr storage
    acl_bytes = xattr_storage.get(inode, "system.posix_acl_access")
    if acl_bytes is None:
        // No ACL: derive minimal ACL from mode bits
        acl_entries = minimal_access_acl_from_mode(inode.mode)
    else:
        acl_entries = decode_posix_acl_xattr(acl_bytes)?

    // 2. Evaluate
    granted = posix_acl_perm_bits_for_caller(
        acl_entries, uid, gid,
        inode.uid, inode.gid, groups, requested_mask)

    // 3. Check sufficiency
    if granted != requested_mask:
        return Err(EACCES)

    return Ok(())
```

### 7.4 setxattr ACL hook

When `setxattr("system.posix_acl_access", ...)` is called:

1. Decode the new ACL payload with `decode_posix_acl_xattr()`.
3. If valid, recompute `st_mode` permission bits via `posix_mode_from_access_acl()`
   and update the inode's mode field atomically with the xattr write.
4. If invalid, return the appropriate error to the caller.

### 7.5 chmod ACL hook

When `chmod(new_mode)` is called on an inode:

1. Read the existing access ACL from xattr storage.
2. If an ACL exists: apply `apply_chmod_to_acl(acl, new_mode)` and write back.
3. If no ACL exists: no xattr write needed; mode bits suffice.
4. Update the inode's `st_mode` field.

### 7.6 Create-with-inheritance hook

When `create()` / `mkdir()` / `mknod()` is called inside a directory:

1. Read the parent directory's default ACL xattr.
2. If present: pass the raw requested mode to
   `default_acl_inheritance_for_parent()`.
3. Derive the child's visible permission bits from the inherited access ACL.
4. Write the resulting xattrs and mode to the new child inode atomically with
   the create transaction.
5. If no parent default ACL exists, use the traditional umask-adjusted mode-only
   create path.


Before accepting a `setxattr` for `system.posix_acl_access` or

1. **Required entries**: `ACL_USER_OBJ`, `ACL_GROUP_OBJ`, and `ACL_OTHER` must
   be present exactly once.
2. **Mask rule**: if any named user (`ACL_USER`) or named group (`ACL_GROUP`)
   entry exists, an `ACL_MASK` entry must also exist.
3. **Canonical ordering**: entries must appear in the standard order:
   `USER_OBJ`, `USER*`, `GROUP_OBJ`, `GROUP*`, `MASK`, `OTHER`.
4. **Duplicate check**: no duplicate `id` within `ACL_USER` entries; no
   duplicate `id` within `ACL_GROUP` entries.
5. **Permissions range**: every `perm` field is 0..7.

the FUSE adapter. The core codec is deliberately permissive (it only checks

## 9. Crate structure

```
crates/tidefs-posix-acl/
├── Cargo.toml    # no_std, forbid(unsafe_code), no dependencies
└── src/
    └── lib.rs    # ~1130 lines: types, constants, codec, evaluation,
                  # mode sync, inheritance, tests
```

| Property | Value |
|---|---|
| `#![no_std]` | Yes (uses `alloc` for `Vec`) |
| `#![forbid(unsafe_code)]` | Yes |
| Dependencies | None (only `alloc`) |
| Public API surface | 10 functions, 1 struct, 1 type alias, 1 error enum, 6 tag constants |
| Test coverage | Round-trip, decode errors, evaluation, mode sync, inheritance |

## 10. Test strategy

### 10.1 Unit tests (in `tidefs-posix-acl`)

| Test | Coverage |
|---|---|
| `round_trip_minimal_access_acl` | 3-entry ACL encode→decode |
| `round_trip_with_named_user_and_mask` | 5-entry ACL with mask |
| `decode_too_short` | 0-byte payload → TooShort |
| `decode_unsupported_version` | v1 → UnsupportedVersion |
| `decode_bad_length` | misaligned payload → BadLength |
| `decode_too_many_entries` | >32 entries → TooManyEntries |
| `decode_invalid_tag` | unknown tag → InvalidTag |
| `decode_invalid_perm` | perm > 7 → InvalidPerm |
| `evaluation_owner_match` | uid == owner_uid → USER_OBJ perm |
| `evaluation_named_user_no_mask` | named user match without mask |
| `evaluation_named_user_with_mask` | named user match with mask |
| `evaluation_group_match_gid` | gid == owner_gid → group perm |
| `evaluation_named_group_with_mask` | named group match with mask |
| `evaluation_other` | no match → OTHER perm |
| `evaluation_no_acl_mask_fallback` | no mask → GROUP_OBJ as mask |
| `evaluation_multiple_named_groups` | max across matching groups |
| `mode_from_acl_reflects_accurate_perms` | mode bits match ACL |
| `minimal_access_acl_from_mode_standard` | 3-entry from 0o751 |
| `minimal_access_acl_round_trips_through_mode` | mode→acl→mode = original |
| `minimal_access_acl_applies_chmod` | chmod propagates correctly |
| `default_acl_inheritance_empty` | empty parent → no inheritance |
| `default_acl_inheritance_file_gets_access_only` | file gets only access ACL |
| `default_acl_inheritance_directory_gets_both` | dir gets access + default |
| `default_acl_inheritance_chmod_applied_to_access` | creation mode limits bits |

### 10.2 Integration tests (deferred to wire-up)

- `test_access_check_with_acl` — VFS access() uses ACL when feature flag is set
- `test_access_check_mode_fallback` — VFS access() uses mode when feature flag is off
- `test_setxattr_acl_updates_mode` — setxattr(access) synchronises st_mode
- `test_chmod_updates_acl` — chmod() updates ACL entries
- `test_create_inherits_default_acl` — new file in ACL'd directory gets ACL
- `test_mkdir_inherits_access_and_default` — new dir inherits both
- `test_xfstests_generic_acl` — passes xfstests generic ACL test suite

## 11. Tradeoffs and design decisions

### 11.1 Pure codec in no_std vs. integration with xattr storage

**Decision**: The codec and evaluation are a standalone `no_std` crate with
zero dependencies. Integration with xattr storage is done by callers.

**Rationale**: The codec has no need for async I/O, storage engines, or FUSE
wire format. Keeping it pure makes it testable in isolation, fuzzable, and
reusable across different storage backends (inline vs. B+tree) and transport
layers (FUSE vs. NFS vs. cluster RPC).

**Tradeoff**: Callers must orchestrate xattr read → decode → evaluate → result.
This adds a small amount of boilerplate but the integration contracts (Section 7)
make the orchestration pattern explicit.

### 11.2 Vec-based ACL vs. fixed-capacity array

**Decision**: `PosixAcl` is `Vec<PosixAclEntry>`, not `[PosixAclEntry; 32]`.

**Rationale**: The max is 32 but the typical case is 3-5 entries. A fixed
array would waste stack space on the common path and complicate iteration
(need to carry a separate length).

**Tradeoff**: Heap allocation on every decode. Mitigated by `Vec::with_capacity`
ensuring a single allocation per decode, and by the fact that decode is not
on the hot path (ACL evaluation is, but evaluation works on the decoded `&[PosixAclEntry]`
slice, not on the allocation).

### 11.3 No ACL caching in this design

**Decision**: ACL evaluation re-reads the ACL from xattr storage on every call.

**Rationale**: Caching strategy depends on the broader cache architecture
(inode cache, xattr cache, negative caching for absent ACLs). Designing a
cache layer here would duplicate or conflict with the cache lattice design.

**Tradeoff**: Hot-path access checks pay a decode cost on every call for the
common case where the ACL is small (3-5 entries). This is acceptable because
the decode is O(n) with n ≤ 32 and no allocation beyond the Vec.

### 11.4 Mask semantics: no mask → GROUP_OBJ as mask

**Decision**: When no `ACL_MASK` entry exists, the `ACL_GROUP_OBJ` permission
acts as the effective mask for named users and named groups.

**Rationale**: This is the POSIX.1e draft specification behaviour and matches
the Linux kernel implementation. The alternative (treating absence of mask as
"no masking") would grant named users full permission regardless of GROUP_OBJ,
which is a security risk and incompatible with existing tools.

### 11.5 Feature gate at dataset granularity

**Decision**: ACL support is enabled per-dataset via the `org.tidefs:posix_acl`
feature flag.

**Rationale**: Some datasets may not need ACLs (e.g., block volume metadata,
internal system datasets). Gating at the dataset level follows the existing
pattern for compression, encryption, and other per-dataset features.

**Tradeoff**: There is no per-file ACL toggle. A file in an ACL-enabled dataset
always uses ACL evaluation. This matches the ZFS `aclmode` / `aclinherit` property
model and avoids the complexity of per-inode ACL state tracking.

### 11.6 Default ACL inheritance: access ACL gets chmod'd

**Decision**: During file creation, the inherited access ACL is modified by
`apply_chmod_to_acl()` using the raw requested creation mode when the parent
directory has a default ACL.

**Rationale**: This matches Linux default-ACL semantics. The process umask is
ignored when a parent default ACL exists, but the explicit mode argument to
`open()`/`creat()`/`mkdir()`/`mknod()` still limits the inherited access ACL.
Without this step, a permissive default ACL could create broader permissions
than the caller's requested mode allows.

**Tradeoff**: The creation mode limits the inherited ACL but cannot expand it.
If the default ACL specifies `USER_OBJ=r--` and the caller passes mode 0700,
the resulting ACL has `USER_OBJ=r--`. This matches POSIX.1e semantics: the
default ACL is an upper bound; the mode can only further restrict. When the
parent has no default ACL, TideFS follows the traditional umask-adjusted
mode-only create path.

## 12. Wire-up checklist

The following items are deferred to wire-up implementation issues and are
documented here for completeness:

| Step | Description | Issue |
|---|---|---|
| 1 | Wire `getxattr`/`listxattr` for `system.posix_acl_*` in FUSE adapter | TBD |
| 3 | Integrate ACL evaluation into VFS access() path | TBD |
| 4 | Integrate default ACL inheritance into create()/mkdir()/mknod() path | TBD |
| 5 | Add `setfacl`/`getfacl` CLI subcommands | TBD |
| 7 | Cluster replication for ACL xattrs (namespace sync) | TBD |

## 13. References

- POSIX.1e draft 17 (withdrawn): IEEE Std 1003.1e
- Linux kernel: `fs/posix_acl.c`, `include/linux/posix_acl_xattr.h`
- `man 5 acl` — Linux ACL man page
- `docs/design/polymorphic-xattr-storage-design.md` — xattr storage architecture
- `docs/DATASET_FEATURE_FLAGS_DESIGN.md` — feature flag system
- `crates/tidefs-posix-acl/src/lib.rs` — implementation
- `crates/tidefs-types-polymorphic-xattr-core/src/lib.rs` — xattr type definitions

## 14. Data structure details

### 14.1 PosixAclEntry

```rust
pub struct PosixAclEntry {
    pub tag: u16,   // ACL_USER_OBJ | ACL_USER | ACL_GROUP_OBJ | ACL_GROUP | ACL_MASK | ACL_OTHER
    pub perm: u16,  // 0..7 (rwx bits only; bits 3..15 reserved)
    pub id: u32,    // uid for ACL_USER, gid for ACL_GROUP, 0 otherwise
}
```

Each entry is 8 bytes with no padding (all fields are power-of-two aligned).
On-wire, this maps to the Linux `posix_acl_entry` struct with `e_tag`, `e_perm`,
and `e_id` fields.

### 14.2 AclError

```rust
pub enum AclError {
    TooShort,            // payload < 4 bytes
    UnsupportedVersion,  // version != 0x0002
    BadLength,           // (len - 4) not divisible by 8
    TooManyEntries,      // entry count > 32
    InvalidTag,          // tag not in known set
    InvalidPerm,         // perm > 0x7
}
```

All errors are `Copy + Clone + Eq`. This avoids allocation on error paths
and makes the codec suitable for `no_std` contexts.

### 14.3 ACL structural invariants

Every valid access ACL MUST satisfy these invariants (checked by

1. **Required entries present**: USER_OBJ, GROUP_OBJ, and OTHER must always
   be present (positions 0, 1, and last respectively).
2. **Mask entry rule**: MASK is required when the ACL has >3 entries
   (extended ACL). MASK is optional for exactly 3 entries (minimal ACL).
3. **Tag ordering**: Entries must appear in canonical order: USER_OBJ,
   USER*, GROUP_OBJ, GROUP*, MASK, OTHER. All USER entries precede all
   GROUP entries; all GROUP entries precede MASK.
4. **Duplicate prohibition**: No duplicate USER entries (same uid) and
   no duplicate GROUP entries (same gid).
5. **ID constraints**: USER_OBJ, GROUP_OBJ, MASK, and OTHER must have
   `id == 0`. USER must have a non-zero `id` (uid). GROUP must have a
   non-zero `id` (gid).

Every valid default ACL MUST additionally satisfy:

6. **No MASK checking for default ACLs**: The MASK entry semantics in
   default ACLs are conventional only; they set the default mask for
   child access ACLs.
7. **USER_OBJ permutation**: The USER_OBJ entry in a default ACL is
   replaced by the creating user's uid when inherited into a child
   access ACL.


```text
    if acl is empty: return Err(EmptyAcl)
    if len(acl) > MAX_ACL_ENTRIES: return Err(TooManyEntries)

    // Check required entries at their canonical positions
    if acl[0].tag != ACL_USER_OBJ:  return Err(MissingUserObj)
    if acl[0].id != 0:              return Err(UserObjHasId)
    if acl[1].tag != ACL_GROUP_OBJ: return Err(MissingGroupObj)
    if acl[1].id != 0:              return Err(GroupObjHasId)
    if acl[last].tag != ACL_OTHER: return Err(MissingOther)
    if acl[last].id != 0:          return Err(OtherHasId)

    seen_mask = false
    seen_users = Set::new()
    seen_groups = Set::new()
    in_group_section = false

    for i in 1..len-1:
        entry = acl[i]
        match entry.tag:
            ACL_USER:
                if in_group_section or seen_mask: return Err(OrderViolation)
                if entry.id == 0: return Err(UserHasNoId)
                if seen_users.contains(entry.id): return Err(DuplicateUser)
                seen_users.insert(entry.id)
            ACL_GROUP:
                in_group_section = true
                if seen_mask: return Err(OrderViolation)
                if entry.id == 0: return Err(GroupHasNoId)
                if seen_groups.contains(entry.id): return Err(DuplicateGroup)
                seen_groups.insert(entry.id)
            ACL_MASK:
                if seen_mask: return Err(DuplicateMask)
                seen_mask = true
                if entry.id != 0: return Err(MaskHasId)
            _:
                return Err(UnexpectedTag)

    // Extended ACL requires mask
    if len(acl) > 3 and not seen_mask:
        return Err(MaskRequired)

    return Ok(())
```

## 16. Integration with FUSE adapter

### 16.1 getxattr path

When the FUSE adapter receives a `getxattr` request for
`system.posix_acl_access` or `system.posix_acl_default`:

1. Look up the inode's xattr store via `XattrStore::get()`.
2. If the xattr is not found, return `ENODATA` (the standard Linux response
   for absent ACL xattrs — the kernel synthesizes a minimal ACL from `st_mode`).
3. Return the raw binary payload. The FUSE kernel module will translate it
   to the `getfacl` text format for userspace.

### 16.2 setxattr path

When the FUSE adapter receives a `setxattr` request for
`system.posix_acl_access`:

1. Decode the payload with `decode_posix_acl_xattr()`.
3. Compute the new `st_mode` from the ACL with `posix_mode_from_access_acl()`.
4. Update the inode's `st_mode` to the new value (with S_IFMT preserved).
5. Store the encoded ACL in the inode's xattr store via `XattrStore::set()`.
6. Set the ACL flag: `XattrStore::set_has_acl(true)`.
7. Return success (0 bytes written).

For `system.posix_acl_default`:

2. Store the encoded ACL in the xattr store.
3. Return success.

### 16.3 removexattr path

Removing `system.posix_acl_access`:

1. Call `XattrStore::remove("system.posix_acl_access")`.
2. Leave `st_mode` unchanged; after the ACL is absent, permission evaluation
   falls back to the existing mode bits.
3. Clear the ACL flag if no ACL xattrs remain.

Removing `system.posix_acl_default`:

1. Call `XattrStore::remove("system.posix_acl_default")`.
2. No mode change required (default ACLs do not affect current permissions).

### 16.4 create/mkdir/mknod local filesystem path

During file creation:

1. Look up parent directory's default ACL via `XattrStore::get("system.posix_acl_default")`.
2. If present, decode and call `default_acl_inheritance_for_parent()` with the
   raw requested mode.
3. Apply owner/group substitution to the inherited ACL entries.
4. Derive the new inode's visible permission bits from the inherited access ACL.
5. Store the resulting access ACL (and default ACL for directories) in the
   new inode's xattr store as part of the local filesystem create transaction.
6. Set the ACL flag on the new inode.

The FUSE adapter must not perform a second adapter-local inheritance pass or
follow-up `FATTR_MODE` chmod when the parent default ACL path was used, because
that can overwrite the ACL computed by the local filesystem transaction.

## 17. Security considerations

### 17.1 Chmod restriction: non-owner cannot chmod

Only the file owner (or root) can `chmod` a file. If a non-owner attempts
`setxattr("system.posix_acl_access", ...)`, the operation must be rejected
with `EPERM` because setting the access ACL implicitly changes the permission
bits.

### 17.2 Chown drops setuid/setgid

When a non-root user changes the owner or group of a file (`chown`), the
setuid and setgid bits must be cleared. This is handled by the existing
POSIX semantics crate (`tidefs-posix-semantics`), not by the ACL layer.
The ACL layer does NOT need to duplicate this logic.

### 17.3 Sticky bit on directories

The sticky bit on directories (e.g., `/tmp`) restricts deletion/renaming
to the file owner, directory owner, or root. This is evaluated before ACL
checking and is independent of ACL entries. Handled by
`tidefs-posix-semantics::posix_may_delete()`.

### 17.4 ACL on symlinks

Linux does not evaluate ACLs on symlinks. `getxattr`/`setxattr` on symlinks
with `system.posix_acl_*` names should return `ENODATA` / `EPERM` respectively.
TideFS follows this behaviour.

### 17.5 Read-only filesystems

If the dataset or mount is read-only, `setxattr` and `removexattr` for ACL
xattrs must return `EROFS`. This is enforced at the FUSE adapter or VFS
layer, not in the ACL codec.

## 18. Future extensions

### 18.1 NFSv4 ACL support

NFSv4 uses a richer ACL model with ALLOW/DENY ACEs, inheritance flags, and
16 access mask bits per entry. A future `tidefs-nfsv4-acl` crate could
provide an NFSv4 codec and evaluator. The POSIX ACL crate would remain
unchanged; the VFS access path would select the evaluator based on the ACL
format flag stored alongside the xattr.

### 18.2 ACL caching

The hot path for repeated `access()` checks on the same file would benefit
from caching the decoded ACL. The cache could live in the inode cache layer
for ACL xattrs and on `chmod`/`chown`.

### 18.3 ACL support in cluster replication

When ACL xattrs are replicated across cluster nodes, the numeric uid/gid
values in ACL entries must be preserved as-is (no name-based translation).
The cluster transport layer treats ACL xattrs as opaque binary blobs.
This avoids the need for a cluster-wide uid/gid namespace.

### 18.4 ACL inheritance on copy/rename across datasets

When a file is copied or moved across datasets, ACL inheritance may differ
if the target directory has a different default ACL or if ACL support is
enabled/disabled on the target dataset. The exact policy is deferred to
the cross-dataset copy/move design.

## 19. Crate inventory

| Crate | Purpose | Status |
|---|---|---|
| `tidefs-posix-acl` | Codec, evaluation, mode sync, inheritance | Implemented |
| `tidefs-posix-semantics` | Traditional mode-bit evaluation, chmod, sticky bit | Implemented |
| `tidefs-xattr-storage` | Runtime polymorphic xattr store with ACL flag | Implemented |
| `tidefs-types-polymorphic-xattr-core` | Type definitions, policy, thresholds | Implemented |
| active POSIX adapter runtime/daemon boundary | FUSE request dispatch and wire handling | Existing active surface; old standalone fusewire/ingress shards are not present |

## 20. Build and test

The `tidefs-posix-acl` crate compiles as `no_std` with `alloc` for `Vec`.
It has zero external dependencies.

Tests can be run with:

```bash
cargo test -p tidefs-posix-acl
```

The test suite covers:

- **Codec roundtrips**: encode→decode and decode→encode for minimal and
  extended ACLs.
- **Error handling**: all 6 `AclError` variants triggered explicitly.
- **ACL evaluation**: owner access, named user with/without mask, named
  group with/without mask, supplementary group matching, OTHER fallback,
  root bypass, root execute restriction.
- **Mode ↔ ACL**: `mode_from_access_acl`, `minimal_access_acl_from_mode`,
  `apply_chmod_to_acl`, roundtrip consistency.
- **Inheritance**: empty parent, file inherits access only, directory
  inherits both access and default, chmod narrowing during inheritance.
- **Edge cases**: zero mode, full mode, zero-length ACL bits.

## 21. Format versioning and forward compatibility

The xattr payload version is `POSIX_ACL_XATTR_VERSION = 0x0002`. This is
the only version supported by Linux since 2.6.x. Version 0x0001 was never
widely deployed. Future ACL format changes (e.g., to support 64-bit uids
or NFSv4-style rich ACLs) would use a different xattr name
(e.g., `system.nfs4_acl`) rather than bumping this version.

TideFS's `decode_posix_acl_xattr` returns `UnsupportedVersion` for any
version other than 0x0002. This is a hard error, not a warning, because
there is no fallback format to use.

## 22. Relationship to other design documents

| Document | Relationship |
|---|---|
| `POLYMORPHIC_XATTR_STORAGE_DESIGN.md` | Defines the xattr storage layer that hosts ACL xattrs |
| Historical P2 ACL codec design | Earlier version of this spec; superseded by this document |
| `CHECKSUM_ARCHITECTURE_DESIGN.md` | Checksum scheme used by xattr B+tree pages (not ACL-specific) |
| `DATASET_FEATURE_FLAGS_DESIGN.md` | Defines `org.tidefs:posix_acl` feature flag |
| `AUTHN_AUTHZ_OVERRIDE_AUDIT_MODEL_P9-02.md` | Security model; ACL evaluation fits into the access() check |
| `apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_vfs_adapter.rs` | Source-scoped FUSE dispatch evidence for getxattr, setxattr, removexattr, listxattr, access, create, and mkdir |
