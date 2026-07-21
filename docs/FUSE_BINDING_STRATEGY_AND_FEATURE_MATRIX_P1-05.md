# FUSE binding strategy and capability feature matrix (P1-05) (v0.422)

> TFR-019 authority classification: Historical input. See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

Maturity: imported production-design FUSE binding note from tracker-era issue
#1233.

This document is historical design input for the TideFS FUSE binding strategy.
Current adapter authority comes from issue-scoped source audits and the
documentation authority register. It answers:

1. Which Rust FUSE binding is chosen and why.
2. Which protocol capabilities are required, which are tracked as future,
   and which are permanently excluded.
3. How binding gaps (e.g. `NOTIFY_PRUNE`) are bridged without waiting for upstreams.
4. How byte-native names, ACLs, killpriv, and capability checks are enforced.
5. How the binding strategy maps to the future kernel module path.

The binding strategy is a **first-class design decision**, not an implementation detail.
The v0.262 design review (§19.1) identified the binding as a dead-end risk: if the binding
cannot express the full kernel FUSE surface, xfstests failures become untriable.

See also:

- `docs/TIDEFS_DOCTRINE.md` — authority model and projection charters
- `docs/SHARED_DOCTRINE_NATIVE_SEAM_MAP_P0-03.md` — seam ownership
- `docs/XFSTESTS_DISPATCH_CONTRACT.md` — current xfstests workflow dispatch context
- `docs/FUSE_ADAPTER_CONTRACT_ASSUMPTIONS.md` — current FUSE adapter boundary
- `docs/PREVIEW_UAPI_ABI_BOUNDARY_OW202.md` — preview boundary mirror spec
- `docs/CURRENT_VS_FUTURE_CAPABILITIES.md` — capability tracking
- `docs/KERNEL_RESIDENCY_AUTHORITY.md` — current kernel residency boundary

---

## 1. Binding strategy decision

### 1.1 Evaluated options

Three strategies were evaluated:

| Strategy | Crate | Protocol access | Pros | Cons |
|---|---|---|---|---|
| A: High-level async | `fuser` v0.14 | `Filesystem` trait abstracts wire | Mature, well-tested, already integrated | Hides low-level opcodes; limited notify surface |
| B: Low-level C shim | custom `tidefs-fusewire` over `libfuse3` via FFI | Raw `fuse_lowlevel_ops` | Full protocol access; every opcode and notify | FFI maintenance burden; unsafe boundary audit |
| C: Raw protocol binding | custom `tidefs-fusewire` over `/dev/fuse` read/write directly | Wire-level opcodes | Zero dependency on libfuse; full control | Reimplements session, queue, mount, and protocol framing |

### 1.2 Decision: Strategy A (fuser) as primary, with explicit escape hatches

Strategy A (`fuser`) is the chosen primary binding for the userspace FUSE daemon. Rationale:

- `fuser` is the most mature Rust FUSE binding, used in production filesystems (e.g. `virtiofs`-adjacent work).
- It already provides the full Linux FUSE protocol surface through its `Filesystem` trait (all opcodes
  through `COPY_FILE_RANGE`, `LSEEK`, `IOCTL`). Protocol ≥ 7.45 features (`COPY_FILE_RANGE_64`) are
  available in `fuser` v0.14+.
- It uses `OsStr` for pathnames, preserving byte-native names on Linux.
- It uses `spawn_mount2` which gives access to `Notifier` while keeping the session alive.

**Escape hatches** (no redesign required if binding limits are hit):

1. **NOTIFY_PRUNE shim**: `fuser` does not expose `FUSE_NOTIFY_PRUNE` (protocol ≥ 7.45).
   A minimal raw-ioctl shim is specified in §4 below.

2. **Low-level opcode access**: If a future kernel FUSE opcode is needed before `fuser` exposes it,
   the daemon may open `/dev/fuse` directly alongside the `fuser` session for that single opcode family.
   This is an explicit extension point, not a binding replacement.

3. **Future kernel module**: The kernel module (`docs/KERNELSPACE_ENTRY_GATE_OW201.md`) will bypass
   `fuser` entirely. The userspace binding is a continuity projection, not the final authority.

### 1.3 Non-strategies explicitly rejected

- **Python bindings**: The v0.262 Python PoC used a Python FUSE binding, but the Rust rewrite
  makes Python binding evaluation irrelevant. The Python PoC's binding risk analysis (§19.1)
  informed this Rust binding analysis.
- **Switching binding mid-project**: The escape hatches above mean that `fuser` limitations
  are bridged without a binding rewrite. A wholesale binding replacement is treated as a
  project-level architectural change requiring its own design issue.

---

## 2. Capability feature matrix

### 2.1 Protocol capability negotiation

The FUSE `INIT` handshake negotiates capabilities bidirectionally. The daemon sets capability
flags in `KernelConfig` during `init()`, and the kernel responds with its supported set.

The current adapter selects an explicit capability set. Capabilities with
semantic side effects (for example, page-cache ownership changes) remain
excluded until the mounted carrier can preserve its receipt-authority contract.

### 2.2 Required capabilities (must be negotiated)

| Capability flag | FUSE protocol | fuser exposure | Purpose | Status |
|---|---|---|---|---|
| `FUSE_CAP_POSIX_ACL` | protocol ≥ 7.8 | `KernelConfig` writable | ACL xattr ops over FUSE | **Required** — xfstests ACL suite |
| `FUSE_CAP_DONT_MASK` | protocol ≥ 7.12 | `KernelConfig` writable | Daemon receives raw create/mkdir/mknod mode plus umask | **Required** — default ACL inheritance ignores umask when parent default ACL exists |
| `FUSE_CAP_HANDLE_KILLPRIV_V2` | protocol ≥ 7.38 | `KernelConfig` writable | Proper SGID/security.capability clearing on chown/truncate | **Required** — xfstests killpriv |
| `FUSE_CAP_SETXATTR_EXT` | protocol ≥ 7.40 | `KernelConfig` writable | Extended xattr flags for ACL | **Required** — ACL flag passthrough |
| `FUSE_CAP_PARALLEL_DIROPS` | protocol ≥ 7.25 | `KernelConfig` writable | Parallel directory operations | **Required** — dir concurrency |
| `FUSE_CAP_SPLICE_WRITE` | protocol ≥ 7.1 | `KernelConfig` writable | Zero-copy splice from pipe | **Perf gate** |
| `FUSE_CAP_SPLICE_MOVE` | protocol ≥ 7.1 | `KernelConfig` writable | Zero-copy splice to pipe | **Perf gate** |
| `FUSE_CAP_SPLICE_READ` | protocol ≥ 7.1 | `KernelConfig` writable | Zero-copy splice for reads | **Perf gate** |
| `FUSE_CAP_READDIRPLUS` | protocol ≥ 7.13 | `KernelConfig` writable | readdirplus support | **Required** — directory perf |
| `FUSE_CAP_IOCTL_DIR` | protocol ≥ 7.23 | `KernelConfig` writable | ioctl on directories | Deferred — not needed for POSIX surface |

### 2.3 Opt-in capabilities (chosen per coherency profile)

| Capability flag | Profile | Notes |
|---|---|---|
| `FUSE_CAP_SPLICE_*` | `perf` and `cluster` | Zero-copy I/O paths |

### 2.4 Explicitly excluded capabilities

| Capability flag | Reason |
|---|---|
| `FUSE_CAP_ASYNC_READ` | Not negotiated by the current direct engine-dispatch carrier; no adapter read worker-pool authority exists |
| `FUSE_CAP_WRITEBACK_CACHE` | Product mounts force direct I/O and refuse both writeback-cache option spellings; no adapter byte mirror or writeback scheduler exists |
| `FUSE_CAP_PASSTHROUGH` | tidefs does not delegate to a backing filesystem |
| `FUSE_CAP_NO_OPENDIR_SUPPORT` | tidefs needs opendir/releasedir for handle lifecycle |

### 2.5 Capability negotiation law

The `init()` implementation must:

1. Set the exact capability set based on the active coherency profile (§6).
2. Not blindly accept all kernel capabilities.
3. Log negotiated vs rejected capabilities for observability.
4. Fail mount if a *required* capability (from §2.2) is rejected by the kernel.

Anti-regression rule:

**No new capability may be added to the negotiated set without:**
- A corresponding entry in this matrix,
- A decision about which profile(s) it applies to,

---

## 3. Opcode coverage matrix

This matrix records TideFS adapter behavior, not only whether the vendored
`fuser` trait exposes a callback. Rows outside the current POSIX subset must
say so directly, and rows that still need a product decision must name the
follow-up issue that owns support vs intentional non-support.

The #713 audit identified `FUSE_BMAP` as a visible FUSE operation gap in this
document. Issue #786 resolved the current userspace adapter boundary as
explicit non-support: BMAP returns a physical block-device address, while the
daemon has no stable block-device address authority. FIEMAP remains the
supported extent-query surface.

Issue #1081 refreshed this section from the current
`FuseVfsAdapter` daemon callback surface. Rows below classify adapter behavior,
including deliberately limited command sets, instead of carrying historical
stub placeholders.

### 3.1 Required and adapter-exposed opcodes

| Opcode | fuser method | Status | Notes |
|---|---|---|---|
| `FUSE_INIT` | `init()` | **Implemented** | Negotiates required and performance capabilities through `KernelConfig` |
| `FUSE_LOOKUP` | `lookup()` | **Implemented** | Byte-native names required (§5) |
| `FUSE_FORGET` | `forget()` | **Implemented** | Inline forget-ref dispatch |
| `FUSE_BATCH_FORGET` | `batch_forget()` | **Implemented** | Batched forget entries are dispatched through the same forget-ref path |
| `FUSE_GETATTR` | `getattr()` | **Implemented** | TTL-aware |
| `FUSE_ACCESS` | `access()` | **Implemented** | Adapter permission checks against inode metadata |
| `FUSE_SETATTR` | `setattr()` | **Implemented** | chmod/chown/truncate/utimens |
| `FUSE_READLINK` | `readlink()` | **Implemented** | Byte output |
| `FUSE_SYMLINK` | `symlink()` | **Implemented** | Byte target |
| `FUSE_MKNOD` | `mknod()` | **Implemented** | Creates regular, FIFO, character-device, block-device, and socket metadata nodes; unsupported type bits return `EOPNOTSUPP` |
| `FUSE_MKDIR` | `mkdir()` | **Implemented** | |
| `FUSE_UNLINK` | `unlink()` | **Implemented** | |
| `FUSE_RMDIR` | `rmdir()` | **Implemented** | |
| `FUSE_RENAME` | `rename()` | **Partially implemented** | Normal rename, `RENAME_NOREPLACE`, and `RENAME_EXCHANGE` are implemented; `RENAME_WHITEOUT` intentionally returns `EINVAL` until overlay/whiteout semantics enter the POSIX subset |
| `FUSE_RENAME2` | `rename(... flags)` | **Partially implemented** | fuser passes rename flags through `rename()` rather than a separate `rename2()` callback |
| `FUSE_EXCHANGE` | `exchange()` | **Implemented** | Linux 6.13+/macOS exchange callback dispatches through `dispatch_exchange_entry()` as an additional exchange surface |
| `FUSE_LINK` | `link()` | **Implemented** | |
| `FUSE_OPEN` | `open()` | **Implemented** | `O_TMPFILE` is handled as an open-flag adjunct through `dispatch_tmpfile()`, not a distinct fuser callback |
| `FUSE_READ` | `read()` | **Implemented** | |
| `FUSE_WRITE` | `write()` | **Implemented** | Bounded by dirty-window budget |
| `FUSE_STATFS` | `statfs()` | **Implemented** | |
| `FUSE_RELEASE` | `release()` | **Implemented** | |
| `FUSE_FSYNC` | `fsync()` | **Implemented** | |
| `FUSE_FSYNCDIR` | `fsyncdir()` | **Implemented** | |
| `FUSE_OPENDIR` | `opendir()` | **Implemented** | |
| `FUSE_READDIR` | `readdir()` | **Implemented** | |
| `FUSE_READDIRPLUS` | `readdirplus()` | **Implemented** | |
| `FUSE_RELEASEDIR` | `releasedir()` | **Implemented** | |
| `FUSE_CREATE` | `create()` | **Implemented** | |
| `FUSE_FLUSH` | `flush()` | **Implemented** | |
| `FUSE_GETXATTR` | `getxattr()` | **Implemented** | user.* namespace |
| `FUSE_SETXATTR` | `setxattr()` | **Implemented** | user.* namespace |
| `FUSE_LISTXATTR` | `listxattr()` | **Implemented** | user.* namespace |
| `FUSE_REMOVEXATTR` | `removexattr()` | **Implemented** | user.* namespace |
| `FUSE_GETLK` | `getlk()` | **Implemented** | Advisory lock surface (PC-007) |
| `FUSE_SETLK` | `setlk()` | **Implemented** | Advisory lock surface (PC-007) |
| `FUSE_SETLKW` | `setlkw()` | **Implemented** | Blocking lock (queue_class_6) |
| `FUSE_FLOCK` | `flock()` | **Implemented** | BSD whole-file advisory lock surface |
| `FUSE_FALLOCATE` | `fallocate()` | **Implemented** | mode 0, KEEP_SIZE, PUNCH_HOLE, ZERO_RANGE, COLLAPSE_RANGE, INSERT_RANGE |
| `FUSE_LSEEK` | `lseek()` | **Implemented** | SEEK_SET/END/CUR/DATA/HOLE (PC-004B) |
| `FUSE_IOCTL` | `ioctl()` | **Partial-boundary** | `FS_IOC_FIEMAP`, `FS_IOC_FSGETXATTR`, and `TIDEFS_IOC_DEFRAG` are wired; other commands return `EOPNOTSUPP` |
| `FUSE_POLL` | `poll()` | **Implemented** | Regular-file readiness and schedule-notify registration bookkeeping |
| `FUSE_COPY_FILE_RANGE` | `copy_file_range()` | **Implemented** | Engine copy path with derived dirty-state reconciliation |
| `FUSE_SYNCFS` | `syncfs()` | **Implemented** | Mount-wide engine dirty flush, engine syncfs, and txg barrier |
| `FUSE_STATX` | `statx()` | **Implemented** | Encodes `ReplyStatx` from adapter metadata projection |
| `FUSE_BMAP` | `bmap()` | **Explicitly unsupported** | Current userspace adapter returns `EOPNOTSUPP`; FIEMAP is the supported extent-query surface, and BMAP support would require a real block-device address mapping |
| `FUSE_DESTROY` | `destroy()` | **Implemented** | |
| `FUSE_INTERRUPT` | (internal to fuser) | **Binding-internal** | No TideFS daemon callback; blocking `setlk(..., sleep = true)` observes fuser's abort handle |

### 3.2 Future opcodes (deferred)

| Opcode | Protocol | Needed for | Deferral reason |
|---|---|---|---|
| `FUSE_TMPFILE` | ≥ 7.9 | xfstests O_TMPFILE | No distinct fuser callback in the current daemon; `O_TMPFILE` is handled as an open-flag adjunct, while broader orphan-index lifecycle authority remains separate |
| `FUSE_COPY_FILE_RANGE_64` | ≥ 7.45 | Large file clone | No distinct daemon callback in the current fuser surface; current `copy_file_range()` is implemented and tested |

---

## 4. NOTIFY_PRUNE shim

### 4.1 Problem

`FUSE_NOTIFY_PRUNE` (protocol ≥ 7.45, Linux 7.0+) allows the daemon to proactively
request that the kernel shrink its inode/dentry caches for a specific subtree. This is
critical for daemon memory pressure handling (tracker-era issue #1211,
v0.262 §19.1).

`fuser` v0.14 does not expose `FUSE_NOTIFY_PRUNE`. The `Notifier` type provides
`inval_inode`, `inval_entry`, and `inval_delete`, but not `notify_prune`.

### 4.2 Design: raw-ioctl shim

A minimal shim writes the `FUSE_NOTIFY_PRUNE` message directly to `/dev/fuse` using
the `FUSE_DEV_IOC_NOTIFY_PRUNE` ioctl or the raw notify wire format, depending on kernel
version.

The old standalone `fusewire` shard is not present in the active workspace. If
this shim is implemented, it must live in the active POSIX adapter daemon or
runtime boundary with no dependency on `fuser` internals.

#### Wire format

```
FUSE_NOTIFY_PRUNE (code 8, protocol ≥ 7.45):
  struct fuse_notify_prune_out {
      uint64_t nodeid;     // inode to prune from
      uint64_t name_len;   // 0 = prune subtree; N > 0 = prune named child
      char     name[];     // optional: specific child name (bytes, not UTF-8)
  };
```

The shim opens `/dev/fuse` independently (read-only, non-blocking) and sends the
notify message through the same file descriptor that `fuser` owns. Since `fuser`
v0.14 exposes the raw fd via `Session::fd()` (or can be accessed through the
`Notifier`), the shim acquires the fd through the notifier handle.

#### Interface

```rust
/// Send FUSE_NOTIFY_PRUNE to the kernel.
///
/// `prune_subtree`: if true, prune the entire subtree rooted at `inode`.
/// If false, `name` specifies a single dentry to prune.
///
/// Returns `Ok(())` on successful ioctl, `Err` if the kernel does not
/// support NOTIFY_PRUNE or the fd is invalid.
pub fn notify_prune(
    fuse_fd: std::os::unix::io::RawFd,
    inode: u64,
    prune_subtree: bool,
    name: Option<&[u8]>,
) -> std::io::Result<()>;
```

#### Upgrade path

When `fuser` adds `FUSE_NOTIFY_PRUNE` support, the shim is deprecated and the
call sites switch to `fuser::Notifier::notify_prune()`. The shim module is
transition window.



1. A unit test that constructs the wire message and compares it against a known-good
   byte sequence.
2. A kernel integration test (QEMU smoke with 7.0+ kernel) that triggers daemon memory
   pressure and verifies the kernel shrinks dentry/inode caches.

---

## 5. Byte-native names

### 5.1 Policy

All pathnames in the FUSE daemon must be byte-native from kernel wire to engine
and back. UTF-8 conversion is forbidden at any layer that handles FUSE pathnames.

This is a correctness prerequisite: xfstests creates filenames that are not valid
UTF-8 (v0.262 §19.2).

### 5.2 Enforcement

| Layer | Current state | Required change |
|---|---|---|
| FUSE wire → fuser | `fuser` uses `OsStr` which is byte-native on Linux | None |
| fuser → daemon | daemon methods receive `&OsStr` | None |
| Daemon → Local Filesystem | Local Filesystem API uses `std::path::Path` which is `OsStr`-backed on Linux | Need to audit for accidental `to_str()` calls |
| Local Filesystem → Object Store | Object Store keys are already `[u8; 32]` hashes | None |
| Daemon → FUSE reply | `reply.entry()` etc. use `OsStr` | None |
| Daemon logging/tracing | Log messages may use `{:?}` or `display()` which can mangle non-UTF-8 | Sanitize log paths through hex-escape for non-UTF-8 bytes |

### 5.3 Audit checkpoint

The following patterns are forbidden in daemon code:

- `path.to_str()` — panics on non-UTF-8
- `path.to_string_lossy()` — silently mangles bytes, corrupting names
- `format!("{:?}", path)` — `OsStr` Debug on some platforms may escape non-UTF-8
- `String::from(path.to_string_lossy())` — round-trip will not preserve original bytes

Allowed patterns:

- `path.as_os_str().as_bytes()` — raw bytes for engine consumption
- `OsString::from_vec(name_bytes)` — reconstruct from bytes for replies
- Custom `display_bytes(&[u8])` helper for logging that hex-escapes non-printable bytes

---

## 6. Coherency profiles and capability selection

### 6.1 Profile-gated capability sets

The FUSE daemon operates in one of three coherency profiles, with current
page-cache and invalidation authority in
`docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md` and
`docs/PAGE_CACHE_INVALIDATION_AUTHORITY.md`:

|---|---|---|---|---|
| `strict` | No writeback, no auto-inval, `FOPEN_DIRECT_IO` | Bypass kernel page cache | Not needed (direct I/O) | Direct-I/O diagnostics and non-mmap correctness verification |

### 6.2 Profile selection

The profile is selected at mount time via a daemon flag:

```text
tidefs-posix-filesystem-adapter-daemon mount \
  --profile strict|perf|cluster \
  --store /data/tidefs --mount /mnt/tidefs
```

Default: `perf` for single-node production; `strict` for xfstests harness.

### 6.3 Profile transition rules

- Profile changes across remounts must be explicit (no silent fallback).
- Downgrading from `perf` to `strict` is always safe (drops caches, loses no data).
- Upgrading from `strict` to `perf` requires a remount (cannot change mid-session).

---

## 7. ACL and capability check design

### 7.1 POSIX ACL surface

From the v0.262 design review (§19.4) and the existing xattr wiring (PC-006, v0.418):

- ACL xattrs (`system.posix_acl_access`, `system.posix_acl_default`) are stored as
  per-inode xattr entries.
- The daemon negotiates `FUSE_CAP_POSIX_ACL` and `FUSE_CAP_SETXATTR_EXT` so the kernel
  routes ACL operations through the daemon's `getxattr`/`setxattr` handlers.
- ACL normalization (ordered, deduplicated, minimal) is enforced on set.
- ACL ↔ mode synchronization follows Linux rules: chmod updates ACL mask; ACL set
  updates mode group bits.

### 7.2 Capability checks

For `setxattr`/`removexattr` on `system.*` xattrs, Linux requires `CAP_FOWNER` in
the caller's user namespace. The daemon must verify this.

Implementation:

1. Read `/proc/<pid>/status` for the calling PID (available from `Request::pid()` in fuser):
   - Parse `CapEff:` line to extract effective capability bitmap.
   - Check `CAP_FOWNER` (bit 3) and `CAP_SYS_ADMIN` (bit 21).
2. For Rust-native capability checks, use the `caps` crate or `libc::capget()`.
3. Cache capability results per-PID for the duration of the FUSE request (single-use).

### 7.3 killpriv enforcement

`FUSE_CAP_HANDLE_KILLPRIV_V2` causes the kernel to request killpriv processing on
`setattr` (chown/truncate) and `write` (when suid/sgid is set). The daemon must:

1. Clear `S_ISUID` and `S_ISGID` on chown (unless caller has `CAP_FSETID`).
2. Clear `S_ISUID` and `S_ISGID` on truncate (unless caller has `CAP_FSETID`).
3. Clear `security.capability` xattr on chown/truncate (unless caller has `CAP_FSETID`).
4. Preserve `S_ISGID` when the group exec bit is set and the file is group-owned
   (Linux-specific nuance — the `S_IXGRP` + group-ownership test).

The killpriv response is encoded in the `setattr` reply via `wrctr` field (protocol
≥ 7.38), which `fuser` exposes through the `setattr` reply mechanism.

---

## 8. Binding observability

### 8.1 Metrics

The daemon exposes the following binding-related metrics:

- `fuse_capability_negotiated{flag}` — gauge, 1 if capability was negotiated
- `fuse_capability_rejected{flag}` — counter, kernel rejected this capability
- `fuse_notify_prune_total` — counter (when shim is active)
- `fuse_mount_profile{profile}` — gauge, current profile
- `fuse_byte_name_rejections_total` — counter, non-UTF-8 name handling (should be 0)

### 8.2 Debug interface

The daemon's admin socket (P9-01) exposes:

```text
tidefs-admin fuse binding-status    -- show negotiated caps, profile, binding version
```

---

## 9. Future kernel module path

### 9.1 Relationship to userspace binding

The userspace FUSE daemon is a continuity projection (design rule rule 6). The future
kernel module (`docs/KERNELSPACE_ENTRY_GATE_OW201.md`) will bypass FUSE and implement
VFS operations directly.

The binding strategy must not create dependencies that block the kernel path:

- AuthZ/authN logic (capability checks, ACL enforcement) must be extractable into
  `core` crates with `no_std` compatibility.
- The FUSE opcode dispatch table must be separable from the semantic handlers.
- Pathname handling in the engine must be byte-native (already required by FUSE).

### 9.2 Seam map

| Concern | Userspace FUSE | Future kmod |
|---|---|---|
| Capability negotiation | `KernelConfig` in `init()` | N/A (kernel native) |
| Pathname encoding | `OsStr` → bytes | `struct dentry` / `struct qstr` — already byte-native |
| ACL enforcement | Daemon-side checks | Kernel VFS checks + module callbacks |
| Killpriv | FUSE killpriv v2 reply | Direct inode metadata mutation |
| Memory pressure | `NOTIFY_PRUNE` shim | `shrinker` registration + `d_prune_aliases()` |

---



```text
cargo test -p tidefs-posix-filesystem-adapter-daemon --all-targets
cargo run -p tidefs-xtask -- check-fuse-mount-path
cargo run -p tidefs-xtask -- check-posix-scoreboard
```

### 10.2 Binding-specific gates added by this design

|---|---|---|
| `FUSE_BINDING_CAP_NEGOTIATION_GATE` | All required caps negotiated; excluded caps absent | Unit test inspects `KernelConfig` after `init()` |
| `FUSE_BINDING_BYTE_NAMES_GATE` | Non-UTF-8 paths round-trip correctly | Integration test with non-UTF-8 filenames |
| `NOTIFY_PRUNE_SHIM_GATE` | Shim wire message matches kernel expectation | Unit test against known-good bytes |
| `FUSE_BINDING_PROFILE_SWITCH_GATE` | Profile changes take effect on remount | Integration test: strict → perf → strict |

### 10.3 xfstests relevance

The binding strategy gates xfstests success in these areas:

- ACL tests (`generic/099`, `generic/237`, `generic/319`, etc.) — require `FUSE_CAP_POSIX_ACL` + ACL handlers
- killpriv tests (`generic/472`, `generic/497`, etc.) — require `FUSE_CAP_HANDLE_KILLPRIV_V2`
- Non-UTF-8 name tests (`generic/453`, etc.) — require byte-native names throughout
- Directory performance tests — require `FUSE_CAP_READDIRPLUS` + `FUSE_CAP_PARALLEL_DIROPS`

---

## 11. Non-claims

This design does not:

- Claim that `fuser` will never need replacement. The escape hatches (§1.2) exist precisely
  because binding limitations may surface.
- Implement any of the gates listed in §10.2. Gate implementation is separate implementation
  work tracked in future issues.
- Design the kernel module FUSE replacement. That lives in `docs/KERNELSPACE_ENTRY_GATE_OW201.md`.
- Design the full ACL state machine. That lives in the v0.262 design book §6.4.6 and its Rust
  implementation issue.
- Design mmap/page-cache/writeback integration. That lives in `docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md` and `docs/PAGE_CACHE_INVALIDATION_AUTHORITY.md`.

---

## 12. Reference chain

- Linux FUSE UAPI: `include/uapi/linux/fuse.h` (protocol changelog, opcodes, capabilities)
- Linux FUSE docs: `Documentation/filesystems/fuse.rst`, `fuse-io.rst`
- libfuse reference: `lib/fuse_lowlevel.c` (low-level callback wiring)
- fuser crate: <https://docs.rs/fuser/0.14> (Rust binding API surface)
- v0.262 design book: `docs/notes/2026-02-06-fuse-userspace-api-and-mmap.18-20-roadmap-review-references.md` §19
