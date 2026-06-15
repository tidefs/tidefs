# TideFS kmod-posix-vfs VFS Operation Dispatch Gap Analysis

Baseline: crate `tidefs-kmod-posix-vfs` (32 source files, ~4800 lines, 282 lib tests + integration tests).
Audit date: 2026-05-24 (updated: #6398 NEXT-KTFS-035 wired setlease refusal contract returning -EOPNOTSUPP on both regular and directory file_operations; Kbuild validation — tidefs_posix_vfs.ko built against Linux 7.0; Tier 0 bootstrap mount, Tier 1 fail-closed, Tier 2 engine-backed mount wired through C shim via label parse + committed-root selection; #6144 adds a fixed-table mounted basic-ops QEMU pass; #6225 publishes mounted VCRL committed-root ledgers and proves remount selects the advanced txg; #6646 KTFS-REMAP-001 wired remap_file_range refusal contract returning -EOPNOTSUPP). Target: Linux 7.0 VFS operation contracts.
Cross-referenced against `VfsEngine` trait at `crates/tidefs-vfs-engine/src/lib.rs:136`.

## Classification Legend

- **Implemented**: dispatch wired to VfsEngine with full delegation path
- **Stub**: code path exists but body is a no-op or returns ENOSYS unconditionally
- **Missing**: no code path exists in the crate
- **OutOfScope**: explicitly declared out of scope in `lib.rs` crate-level docs
- **NeedsBridge**: dispatch point exists but requires kernel-side adapter work (e.g. iov_iter conversion)

---

## 1. inode_operations

| Operation | Status | Source File | Dispatch Target | Notes |
|---|---|---|---|---|
| lookup | **Implemented** | `src/inode.rs:7` | `engine.lookup()` | LookupPlan with negative dentry tracking and generation validation. 15 unit tests. |
| getattr | Implemented | `src/inode.rs:14` | `engine.getattr()` | Supports both inode-only and handle-qualified getattr |
| setattr | Implemented | `src/setattr.rs:13`, `tidefs_posix_vfs_shim.c:tidefs_posix_vfs_setattr` | `engine.setattr()` | Mounted truncate first takes the C mapping invalidate lock, runs `filemap_write_and_wait_range()` over the size-change range, unmaps and invalidates that page-cache range, then calls the Rust engine bridge and applies `truncate_setsize()`/canonical inode attributes. Rust `setattr.rs` dirty-tracker/page-authority cleanup is source-model only for mounted kernels. |
| create | **Implemented** | `src/create.rs:7` | `engine.create()` | CreatePlan returning (CreatePlan, OpenFileState). 16 unit tests. |
| create_excl | Implemented | `src/create_excl.rs:11` | `engine.create_excl()` | Atomic O_EXCL\|O_CREAT with EEXIST on collision |
| mkdir | Implemented | `src/mkdir.rs:22` | `engine.mkdir()` | Mode validation rejects non-directory type bits |
| rmdir | Implemented | `src/rmdir.rs:8` | `engine.rmdir()` | Returns ENOTEMPTY when non-empty |
| unlink | **Implemented** | `src/unlink.rs:8` | `engine.unlink()` | UnlinkPlan with entry removal and nlink decrement delegation. 16 unit tests. |
| rename | Implemented | `src/rename.rs:10` | `engine.rename()` | Supports RENAME_NOREPLACE and RENAME_EXCHANGE flags |
| link | Implemented | `src/link.rs:9` | `engine.link()` | Hard link creation with nlink accounting |
| symlink | Implemented | `src/symlink.rs:83` | `engine.symlink()` | Name validation (no dots, NUL, slash, 255-byte limit); target validation (non-empty, <=4096) |
| readlink | Implemented | `src/symlink.rs:90` | `engine.readlink()` | Returns symlink target as raw bytes |
| mknod | Implemented | `src/mknod.rs:18` | `engine.mknod()` | Char, block, FIFO, socket; rejects S_IFREG |
| tmpfile | Implemented | `src/tmpfile.rs:9` | `engine.tmpfile()` | O_TMPFILE unnamed file creation |
| getxattr | Implemented | `src/xattr.rs` | `engine.getxattr()` | Namespace-validated; ENODATA missing; EOPNOTSUPP unknown prefix; BLAKE3 integrity |
| setxattr | Implemented | `src/xattr.rs` | `engine.setxattr()` | Namespace-validated; XATTR_CREATE/REPLACE flags; EOPNOTSUPP unknown prefix; BLAKE3 integrity |
| listxattr | Implemented | `src/xattr.rs:34` | `engine.listxattr()` | NUL-separated name list |
| removexattr | Implemented | `src/xattr.rs` | `engine.removexattr()` | Namespace-validated; ENODATA absent; EOPNOTSUPP unknown prefix |
| permission | **Implemented** | `src/permission.rs:159` | `engine.getattr()` + POSIX mode evaluation | PermissionPlan with POSIX mode evaluation. 19 unit tests. |
| update_time | **Implemented** | `src/update_time.rs` | `engine.getattr()` + `engine.setattr()` | UpdateTimePlan with timestamp field coverage. 40 tests (15 inline + 25 validation). |
| get_inode_acl | OutOfScope | -- | -- | ACL operations explicitly out of scope (lib.rs:48) |
| get_inode_acl | Implicit | `tidefs_posix_vfs_shim.c` | xattr-engine getxattr bridge | ACL read through system.posix_acl_access xattr; engine-backed storage |
| set_acl | Implicit | `tidefs_posix_vfs_shim.c` | xattr-engine setxattr/removexattr bridge | ACL write/clear through system.posix_acl_* xattr; engine-backed storage |
---

## 2. file_operations

| Operation | Status | Source File | Dispatch Target | Notes |
|---|---|---|---|---|
| open | Implemented | `src/file.rs:7` | `engine.open()` | Returns OpenFileState with handle, flags tracking |
| release | Implemented | `src/file.rs:13` | `engine.release()` | Handle invalidation |
| read | Implemented | `src/read.rs:9` | `engine.read()` | Byte-buffer read (not iov_iter) |
| write | Implemented | `src/write.rs:9` | `engine.write()` | Byte-buffer write (not iov_iter) |
| read_iter | **Implemented** | `tidefs_posix_vfs_shim.c` `tidefs_posix_vfs_file_read_iter` | `pool->inode_table[]->copy_to_iter()` | iov_iter-aware vectored read copied directly from pool data; replaces legacy .read. Registered in `file_operations`. K7-IOVEC-001. |
| write_iter | **Implemented** | `tidefs_posix_vfs_shim.c` `tidefs_posix_vfs_file_write_iter` | `copy_from_iter()->pool->inode_table[]` or `tidefs_posix_vfs_engine_write` | iov_iter-aware vectored write: engine-backed path copies iovec data into a kernel buffer and delegates to Rust engine; fixed-table path copies directly into pool. Registered in `file_operations`. K7-IOVEC-001. |
| llseek | **Implemented** | `src/llseek.rs:46`, `tidefs_posix_vfs_main.rs` (C bridge), `tidefs_posix_vfs_shim.c` (callback) | `engine.data_ranges()` via `tidefs_posix_vfs_engine_llseek` | SEEK_SET/CUR/END computed from InodeAttr::size; SEEK_DATA/SEEK_HOLE routed through C bridge to VfsEngine::data_ranges() with dense-file fallback when engine unavailable. #6644. |
| fsync | Implemented | `src/fsync.rs:13` | `engine.fsync()` | datasync flag propagated |
| mmap | **Implemented, generic filemap** | `tidefs_posix_vfs_shim.c:tidefs_posix_vfs_file_mmap` | `generic_file_mmap()` + C `address_space_operations` | Engine-backed mounted-pool mmap is admitted through the generic filemap VM operations; bootstrap/fixed-table files fail closed because they have no mmap writeback authority. `MAP_SHARED` read faults populate folios through C `read_folio` -> `tidefs_posix_vfs_engine_read`; dirty shared mappings use Linux dirty folios and C `writepages` -> `tidefs_posix_vfs_engine_write`. The Rust `KmodVfsVmOps` model is not registered as `vma->vm_ops`; `KmodPosixVfs::mmap()` returns `EOPNOTSUPP`, and the custom bridge remains an explicit unsupported row under TFR-018. |
| fallocate | Implemented | `src/fallocate.rs:7` | `engine.fallocate()` | Full mode/offset/length delegation |
| fadvise | **Implemented** | `src/fadvise.rs:22` | `KmodPosixVfs::fadvise()` | No-op returning success. The kernel page cache applies default advice behavior. |
| copy_file_range | **Wired** | `src/copy_file_range.rs:7` + C shim | `engine.copy_file_range()` via `tidefs_posix_vfs_engine_copy_file_range` bridge | Server-side copy delegation registered in `file_operations`. Falls back to `do_splice_direct` when engine is not mounted. 7 unit tests. |
| remap_file_range | **Refused** | C shim `tidefs_posix_vfs_remap_file_range_nosupport()` | `tidefs_posix_vfs_remap_file_range_nosupport()` | Explicit refusal (KTFS-REMAP-001): returns -EOPNOTSUPP until kernel reflink is in scope. |

| splice_read | **Wired** | C shim `tidefs_posix_vfs_file_splice_read` | `kernel_read` -> `.read` -> engine | Registered in `file_operations`. Allocates pages, reads file data via `kernel_read`, pipes via `splice_to_pipe`. Preserves extent/hole semantics through `.read` dispatch. |
| splice_write | **Wired** | C shim `tidefs_posix_vfs_file_splice_write` | `__splice_from_pipe` + actor -> `kernel_write` -> `.write` -> engine | Registered in `file_operations`. Reads pipe buffers, delegates to `kernel_write` (which calls `.write`). Preserves extent allocation and hole semantics. |
| lock (getlk) | Implemented | `src/lock.rs:11` | `engine.getlk()` | Returns None or conflicting LockSpec |
| lock (setlk) | Implemented | `src/lock.rs:22` | `engine.setlk()` | Non-blocking advisory lock |
| flock | **Implemented, runtime validation required** | `src/lock.rs:44` | `engine.setlk()`/`engine.setlkw()` | Whole-file flock(2) dispatch (LOCK_SH/LOCK_EX/LOCK_UN/LOCK_NB) with fd-as-owner mapping to LockSpec. The old cargo validation harness is retired; mounted-kernel validation remains required. |
| setlkw | OutOfScope | -- | -- | Blocking lock explicitly out of scope (lib.rs:47) |
| setlease | **Implemented** | `tidefs_posix_vfs_shim.c` setlease callback | `tidefs_posix_vfs_setlease_nosupport()` | Lease/delegation refusal contract (NEXT-KTFS-035): returns -EOPNOTSUPP on every fcntl(F_SETLEASE/F_GETLEASE). |
| flush | Implemented | `src/flush.rs:8` | `engine.flush()` | Per-fd dirty data push |
| readahead | **Implemented** | `src/file.rs:119-129` | `engine.readahead()` | Forwards nonzero readahead hints to VfsEngine::readahead() with error tolerance and zero-length skip (9 unit tests). File-operation hint forwarding exists; kernel address_space_ops callback registration blocked on #6622. |
| readdir | Implemented | `src/readdir.rs:94` | `engine.readdir()` | Full dirent64 packing with cookie-based pagination and resume-offset support |

**Mounted #6144 note**: the Linux VFS C shim now also provides mounted
block-device callbacks for lookup, create, mkdir, unlink, rmdir, readdir,
regular-file open/release/read/write/fsync, and directory fsync against a
small fixed `KernelPoolCore` table. This is real Linux 7.0 QEMU validation for
the basic mounted operations, but it is not the final object/extent/intent
engine and must not be counted as page-cache/writeback, mmap, xfstests, or
terminal no-daemon validation.

---

## 3. dentry_operations

| Operation | Status | Source File | Dispatch Target | Notes |
|---|---|---|---|---|
| d_revalidate | Implemented | `src/inode.rs:19-20` | -- | `is_generation_valid()` for positive dentries; `revalidate_negative()` for negative dentries |
| d_compare | **Missing** | -- | -- | No case-insensitive or custom name comparison. Not needed for case-sensitive TideFS. |
| d_delete | **Implemented** | `tidefs_posix_vfs_shim.c` dentry_ops | C shim `tidefs_posix_vfs_d_delete` | Returns 0 to let VFS drop dentry via d_drop; tracks deletion count in mount context for lifecycle validation. |
| d_release | **Implemented** | `tidefs_posix_vfs_shim.c` dentry_ops | C shim `tidefs_posix_vfs_d_release` | Tracks dentry free events in mount context for lifecycle validation. |
| d_iput | **Implemented** | `tidefs_posix_vfs_shim.c` dentry_ops | C shim `tidefs_posix_vfs_d_iput` | Calls standard iput() and tracks the call plus orphan (nlink==0) counts for open-unlink lifecycle validation. |
| d_dname | **Missing** | -- | -- | No dynamic dentry name (only needed for pseudo-filesystems). |
| d_automount | **Missing** | -- | -- | No autofs-style automount. Not required for TideFS. |
| d_manage | **Missing** | -- | -- | No custom dentry management (mountpoint traversal). Not required for TideFS. |

**Dentry lifecycle validation**: The old simulated dentry lifecycle cargo
test was retired. It modeled dcache state without Linux dentry operation
dispatch and must not be treated as product validation.

---

## 4. address_space_operations

| Operation | Status | Source File | Dispatch Target | Notes |
|---|---|---|---|---|
| read_folio | **Implemented** | `src/address_space_ops.rs:161`, `tidefs_posix_vfs_shim.c:tidefs_posix_vfs_read_folio` | `engine.read()` via `tidefs_posix_vfs_engine_read` bridge | Page-cache population callback registered in `address_space_operations` vtable. Reads folio data through VfsEngine::read bridge, copies into folio pages via kmap_local_folio, marks uptodate. Set as `inode->i_mapping->a_ops->read_folio` on regular-file inode init. No userspace daemon required. |
| readahead (a_ops) | OutOfScope | -- | -- | read_folio a_ops prereq is now wired (#6622). KmodAddressSpaceOps::readahead() exists at src/address_space_ops.rs:191-212; C callback wiring is Review debt TFR-018. |
| writepages | **Implemented** | `tidefs_posix_vfs_shim.c:tidefs_posix_vfs_writepages` | `tidefs_posix_vfs_engine_write` | Drains Linux dirty folios discovered by `writeback_iter()`, copies folio bytes, writes them through the mounted Rust engine bridge, records mapping errors, and re-dirties the folio on engine error or short write so dirty data can be retried. Registered in `address_space_operations` vtable. Rust `DirtyFolioTracker::writeback_folios` and page-authority integration remain fail-closed source-model only under TFR-018. |
| write_begin | **Implemented** | `src/address_space_ops.rs:237`, `tidefs_posix_vfs_shim.c:tidefs_posix_vfs_write_begin` | `engine.read()` via `tidefs_posix_vfs_engine_read` bridge | Reads existing data into folio for partial-page merge during buffered writes. Registered in `address_space_operations` vtable. No userspace daemon required. |
| write_end | **Implemented** | `src/address_space_ops.rs:261`, `tidefs_posix_vfs_shim.c:tidefs_posix_vfs_write_end` | `engine.write()` via `tidefs_posix_vfs_engine_write` bridge | Writes modified folio data back to engine after buffered write. Registered in `address_space_operations` vtable. Increments lifecycle counter for QEMU validation. No userspace daemon required. |
| dirty_folio | **Implemented** | `src/address_space_ops.rs:284`, `tidefs_posix_vfs_shim.c:tidefs_posix_vfs_dirty_folio` | Linux `filemap_dirty_folio()` | Acknowledges dirty-folio transition from the kernel page-cache layer and registers the folio with Linux dirty accounting. It deliberately does not sleep or call the engine from atomic MM paths. The Rust `DirtyFolioTracker` bridge remains deferred under TFR-018. |
| invalidate_folio | **Missing in mounted C vtable** | `src/address_space_ops.rs:548`, C shim helpers | Kernel truncate/invalidate helpers | Rust model removes discarded byte ranges from `DirtyFolioTracker` and calls `VfsEngine::invalidate_cache_range()`, but the mounted C `address_space_operations` vtable does not register `.invalidate_folio`. Mounted truncate, truncate-extend, fallocate, direct-write, and copy mutations use the C mapping invalidate lock plus `filemap_write_and_wait_range`, `unmap_mapping_range`, `invalidate_inode_pages2_range`, and `truncate_setsize()` for ranges Linux discards or revalidates. Direct Rust page-authority cleanup remains TFR-018 and is not a mounted product claim. |
| bmap | OutOfScope | -- | -- | FIEMAP alternative preferred; not required. |
| direct_IO | OutOfScope | -- | -- | Block-level direct I/O. TideFS uses file-level read/write delegation. |

---

## 5. super_operations

| Operation | Status | Source File | Dispatch Target | Notes |
|---|---|---|---|---|
| fill_super (bootstrap) | **Refused** | `tidefs_posix_vfs_shim.c` `-o bootstrap` | None | Fails with `EOPNOTSUPP` because no explicit kernel pool I/O authority is bound. |
| fill_super (engine) | **Mounted** | C shim `get_tree_bdev` → `tidefs_posix_vfs_fill_super_bdev()` → `tidefs_posix_vfs_engine_fill_super_label()` | mounted `KernelPoolCore` in `s_fs_info` | Block-device-backed default mount path reads the pool label via `sb_bread`, validates the label and committed-root ledger through the Rust bridge, and installs the mounted pool context/root inode into `s_fs_info`. |
| statfs (bootstrap) | **Refused** | `tidefs_posix_vfs_shim.c` `-o bootstrap` | None | No bootstrap superblock is created, so statfs cannot synthesize hardcoded capacity. |
| statfs (engine) | **Mounted** | C shim `tidefs_posix_vfs_statfs()` -> `tidefs_posix_vfs_engine_statfs()` | mounted `s_fs_info` pool context -> `KernelEngine` -> `VfsEngineStatFs::statfs()` | Engine-backed mounts hand the live `KernelPoolCore` statfs counters to the Rust bridge and fail closed if the VfsEngine statfs validation rejects them. |
| sync_fs (engine) | **Mounted** | C shim `tidefs_posix_vfs_sync_fs()` -> `tidefs_posix_vfs_engine_sync_fs()` | mounted `s_fs_info` pool context -> `KernelEngine::syncfs()` | Registered in the live Linux `super_operations` table. Linux calls it from `sync_filesystem()` during sync/unmount while `s_fs_info` remains valid. ENOSYS is tolerated only for the current no-dirty-state kernel engine; other errors propagate as negative errno. |
| put_super | **Mounted** | C shim `tidefs_posix_vfs_put_super()` | mounted `s_fs_info` pool context | Registered in the live Linux `super_operations` table and invoked by `generic_shutdown_super()` before the C shim frees the mount context. Logs lifecycle counters for QEMU validation output. |
| umount_begin | **Mounted** | C shim `tidefs_posix_vfs_umount_begin()` | forced unmount lifecycle hook | Registered in the live Linux `super_operations` table and invoked by the Linux 7.0 `MNT_FORCE` unmount path. Logs committed txg and callback count for QEMU validation output. |
| show_options | **Mounted** | C shim `tidefs_posix_vfs_show_options()` | `seq_file` /proc/mounts display | Registered in the live Linux `super_operations` table. Displays bootstrap/engine-backed, ro/rw, debug, commit_timeout_ms, and recovery status in /proc/mounts and mountinfo. |
| kill_sb (bootstrap) | **Refused** | `tidefs_posix_vfs_shim.c` `-o bootstrap` | None | No bootstrap superblock context is installed. |
| kill_sb (engine) | **Mounted** | C shim `tidefs_posix_vfs_kill_sb()` -> Linux `kill_block_super()` -> `tidefs_posix_vfs_engine_kill_sb()` | mounted `KernelPoolCore` teardown + final `engine.syncfs()` | Engine-backed unmount now keeps `s_fs_info` live until Linux has run `sync_fs`/`put_super`, then calls the Rust bridge for final sync handling, tears down the mounted pool context, and uses block-super teardown for block-device mounts. |
| syncfs adapter | Implemented | `src/syncfs.rs:14` | `engine.syncfs()` | Default returns ENOSYS if engine doesn't support it. The loaded module reaches this contract through the C shim `sync_fs` bridge. |
| get_root_inode | Implemented | `src/superblock.rs` | `engine.get_root_inode()` | Committed-root-anchored mount validation with BLAKE3 integrity. |
| mount/unmount lifecycle | **Runtime validation required** | Linux 7.0 QEMU | mounted product module | The old cargo lifecycle harness is retired; QEMU output must close this gate. |
| mount-path error validation | **Runtime-required** | mounted Linux 7.0 QEMU validation | `tidefs_posix_vfs_require_*` dispatch + mount pipeline | The old cargo-only `kernel_root_inode_validation.rs` report is retired. Closure requires QEMU output from the product mount path or an exact blocker. |
| root-inode dispatch validation | **Runtime-required** | mounted Linux 7.0 QEMU validation | mounted root inode through real engine context | The old MockEngine/root-inode cargo report is retired and must not be treated as proof. |
| write_inode | **Implemented** | `tidefs_posix_vfs_shim.c` `tidefs_posix_vfs_write_inode()` | `tidefs_posix_vfs_super_ops.write_inode` | Registered in live Linux `super_operations`. Called by the kernel VFS writeback machinery when inode metadata is dirty (I_DIRTY_SYNC, I_DIRTY_DATASYNC, I_DIRTY_TIME). Explicit metadata persistence is handled by `.setattr` bridge; this callback acknowledges lazy timestamp writeback and clears dirty flags. Tracks per-mount `write_inode_calls` counter for lifecycle validation. |
| evict_inode | **Implemented** | `tidefs_posix_vfs_shim.c` super_ops | C shim `tidefs_posix_vfs_evict_inode` | Wired via #6277: truncates page cache via truncate_inode_pages_final, clears inode, tracks eviction and orphan (nlink==0) counts. kill_sb lifecycle summary reports evict_inode_calls and evict_orphan_calls. |
| freeze | OutOfScope | -- | -- | Explicitly out of scope (lib.rs:49) |
| thaw | OutOfScope | -- | -- | Explicitly out of scope (lib.rs:49) |
| remount | OutOfScope | -- | -- | Explicitly out of scope (lib.rs:49) |

---

## 6. file_operations for Directory Handles

| Operation | Status | Source File | Dispatch Target | Notes |
|---|---|---|---|---|
| opendir | Implemented | `src/dir.rs:8` | `engine.opendir()` | Returns OpenDirState |
| releasedir | Implemented | `src/dir.rs:17` | `engine.releasedir()` | Handle release |
| readdir | Implemented, runtime validation required | `src/dir.rs:12` + `src/readdir.rs:94` | `engine.readdir()` | Engine-level iteration (dir.rs); kernel dirent64 packing (readdir.rs). The old cargo validation harness is retired; fresh mounted-kernel validation must verify behavior. |
| fsyncdir | Implemented | `src/fsync.rs:26` | `engine.fsyncdir()` | Directory metadata flush |
| setlease | **Implemented** | `tidefs_posix_vfs_shim.c` setlease callback | `tidefs_posix_vfs_setlease_nosupport()` | Lease/delegation refusal contract (NEXT-KTFS-035): returns -EOPNOTSUPP on F_SETLEASE/F_GETLEASE. |

---

## 7. Summary Gap Table: Actionable Items

### Priority P1 — Blocks Kernel Delivery Gate

| Gap | Operation | Impact | Recommended Action |
|---|---|---|---|
| ~~permission~~ | ~~inode_operations::permission~~ | Resolved: see #5673. Implemented via `check_permission` in `src/permission.rs`. | |
 | llseek | file_operations::llseek | SEEK_DATA/SEEK_HOLE dispatched through VfsEngine::data_ranges(). | Implemented in llseek.rs (29 inline tests). |
| ~~update_time~~ | ~~inode_operations::update_time~~ | Resolved: see #5754. Implemented via `update_time()` in `src/update_time.rs`. 40 tests. | |
| ~~Stub readahead~~ | file_operations::readahead | Resolved: see #6079. Implemented via `engine.readahead()` dispatch with error tolerance and zero-length skip. | |
| ~~Missing read_iter/write_iter~~ | ~~file_operations::read_iter, write_iter~~ | Resolved: see #6624. read_iter and write_iter implemented in C shim tidefs_posix_vfs_file_read_iter / tidefs_posix_vfs_file_write_iter with iov_iter-aware dispatch. Removed legacy .read/.write from file_operations. | K7-IOVEC-001 |

### Priority P2 — xfstests Compatibility

| Gap | Operation | Impact | Recommended Action |
|---|---|---|---|
| ~~fadvise~~ | ~~file_operations::fadvise~~ | Resolved: see #5704. Implemented as no-op dispatch returning success. |
| ~~remap_file_range~~ | ~~file_operations::remap_file_range~~ | Resolved: see #6646. Explicit refusal returning -EOPNOTSUPP. |
| dentry_operations (dispatch) | d_delete, d_release, d_iput | Wired in C shim via #6623: d_delete, d_release, d_iput track lifecycle counters in mount context for mounted-kernel validation. |

### Priority P3 — Out of Scope (Explicit)

These operations are explicitly listed as out of scope in `lib.rs` lines 47-49 and do not block the kernel delivery gate unless the product direction changes:

- custom Rust vm_operations_struct bridge, Rust DirtyFolioTracker/page-authority
  live C bridge, direct-I/O, distributed mmap coherency, crash consistency, and
  setlkw
- ACL / ioctl (get_inode_acl, set_acl, unlocked_ioctl, compat_ioctl)
- freeze / thaw / remount

---

## 8. Bridge Module

The `bridge.rs` module provides:

- `KmodRegistration` — placeholder for kernel module registration state
- `bridge_errno()` — maps `BridgeError` variants to VFS `Errno`
- `kmod_init()` — registration entry point (placeholder)
- `kmod_exit()` — cleanup entry point

The `dir_ops_bridge.rs` module provides:

- `bridge_lookup()` — resolve a directory entry name to inode attributes
- `bridge_create()` — allocate inode and insert a regular-file dentry
- `bridge_rename()` — atomically move or swap directory entries with renameat2 flags
- `bridge_unlink()` — remove a directory entry with nlink decrement

These functions are no_std-compatible pure delegation wrappers without BLAKE3
attestation, serving as the production kernel namespace mutation surface.
Each function accepts `&dyn VfsEngine` via `+ ?Sized` bound for object safety.
22 unit tests cover all four operations plus a multi-operation sequence.

The bridge module depends on `tidefs_kmod_bridge` (K7-04/#5283). The kernel registration is a stub that will be replaced by concrete Linux 7.0 kernel bindings in the build environment.

---

## 9. Test Infrastructure

The crate uses a `MockEngine` (src/test_util.rs) that implements `VfsEngine` with Box<dyn Fn> closures for adapter unit tests. Mock coverage is not release validation for missing Linux callbacks; mounted-kernel claims require the real C shim / Rust bridge path and kernel validation. Tests are structured as `#[cfg(test)] mod tests` within each source file.

Test counts by module:
- fadvise: 4
- inode: 5, file: 4, dir: 4, create: 6, create_excl: 7, write: 7, read: 7
- flush: 4, mkdir: 9, link: 7, unlink: 6, rmdir: 7, rename: 9
- setattr: 8, symlink: 19, mknod: 8, fallocate: 8, xattr: 27
- lock: 16, copy_file_range: 7, tmpfile: 8, statfs: 20 (src) + 20 (validation) = 27 total, syncfs: 4, readdir: 28
- fsync: 8, readahead: 9, bridge: 7, statx: 5, readdir: 48
- superblock: 3, mount lifecycle: 21 (integration), test_util: 7, permission: 19, readdir: 28

Standalone cargo/mock validation reports are retired from this count; use current
`cargo test --workspace --locked` output for exact test totals.

## 9.1 Kernel Environment Source Model

`src/kernel_env_model.rs` is the kmod-local source model for Linux VFS context
tokens and teardown race exploration. The model records sleepable/non-sleepable
context, RCU/pin or workqueue ownership, mmap and page-cache callback
boundaries, teardown-state assumptions, and the callback classes that may hand
off to deferred workqueue bodies for the modeled kernel-facing operations. Its
deterministic workqueue harness explores bounded interleavings for enqueue,
work start, work completion, begin-teardown, final-teardown, and owner
generation invalidation.

The durable source-model artifact for `kernel.teardown.no_work_after.v1` is
`validation/artifacts/kernel/teardown-race-proof-artifact.json`. It records
the model version, depth-8 schedule bound, action alphabet, covered operation
classes, callback-to-work handoffs, refusal counters, blocked final-teardown
counters, and a passing verdict: no explored schedule starts modeled work after
final teardown.

This source model is not mounted runtime evidence and is not a C shim callback
registration surface. Unsupported mounted paths remain fail-closed through the
live kmod shim and the source-model Rust vm-ops/page-cache helpers remain
non-product unless a later issue wires and validates them through the mounted
Linux 7.0 path. The mounted C shim teardown review for this artifact found no
separate mounted Linux workqueue in the reviewed path: `sync_fs`, `put_super`,
and `kill_sb` keep `s_fs_info` live until the Rust engine teardown bridge runs.
The claim `kernel.teardown.no_work_after.v1` remains planned until claims-gate
review and any required mounted-kernel validation artifacts are recorded.

---

## 10. Implementation Completeness Score

| Category | Total Operations | Implemented | Stub | Missing | Out of Scope | Validated |
|---|---|---|---|---|---|
| inode_operations | 22 | 19 | 0 | 1 | 2 | -- |
| file_operations | 20 | 17 | 0 | 1 | 2 | -- |
| dentry_operations | 8 | 4 | 0 | 4 | 0 | -- |
| address_space_ops | 8 | 5 | 0 | 0 | 3 | -- |
| super_operations | 13 | 8 | 0 | 2 | 3 | 4 (mount lifecycle 21, mount-path error 50, root-inode dispatch 50, Linux 7.0 QEMU lifecycle validation for `sync_fs`/`put_super`/`umount_begin`) |
| **Totals** | **72** | **55** | **0** | **7** | **10** | **4** |

**Dispatch coverage for required operations**: 55 of 72 (76.4%), or 55 of 62 excluding out-of-scope items (88.7%).

---

## 11. Next Actions

0. **Completed (2026-05-20)**: Block-device-backed default mount path wired. The C shim now provides `get_tree_bdev` -> `tidefs_posix_vfs_fill_super_bdev()` which reads the pool label region (first 256 KiB) from the block device via `sb_bread`, passes the label and optional committed-root ledger buffers to the Rust engine bridge via `tidefs_posix_vfs_engine_fill_super_label()`, and installs an engine-backed superblock with mounted `KernelPoolCore` state in `s_fs_info`.
1. **Completed (2026-05-20, #6144/#6225 slice)**: Mounted basic operations are now real Linux 7.0 QEMU behavior. The C shim persists a small fixed kernel namespace/data table in the pool data region and proves no-daemon statfs, create/write/read, mkdir/readdir, sync, unmount, remount readback, unlink, rmdir, clean unmount, module unload, and kernel-warning scan. #6225 adds VCRL committed-root ledger publication from mounted mutations and proves remount selection advances from `txg=1` to `txg=6`. Validation: `/tmp/tidefs-workers/s995/kernel-dev/issue-6144/qemu-runs/basic-ops-rebased-20260520T152600Z/qemu.log` with `RESULTS: pass=24 fail=0 blocked=0`; `/tmp/tidefs-workers/s999/kernel-dev/issue-6225/qemu-runs/committed-root-ledger-20260520T144036Z/qemu.log` with `RESULTS: pass=25 fail=0 blocked=0`. Next step: replace the fixed table with the full object/extent/intent-log engine.
2. **Retired**: cargo-only mount/unmount lifecycle validation. Replacement
   validation must be Linux 7.0 QEMU output from the mounted product
   module.
3. **Retired**: cargo-only readdir/iterate validation. Replacement validation
   must be fresh mounted-kernel output.
4. **Completed**: `permission` dispatch — PermissionPlan (19 tests).
5. **Completed**: `update_time` dispatch — UpdateTimePlan (40 tests).
6. **Completed**: `lookup/create/unlink` dispatch coverage — See issue #5777. LookupPlan (15 tests), CreatePlan (16 tests), UnlinkPlan (16 tests). All 713 total tests pass.
7. **Completed (2026-05-24, #6079)**: `readahead` forwarding — See issue #6079. File-operation readahead hints forwarded through engine.readahead() in file.rs:119-129 with error tolerance and zero-length skip (9 unit tests). Kernel address_space_ops callback registration requires #6622
8. **Completed (2026-05-28, #6624)**: read_iter and write_iter implemented in tidefs_posix_vfs_shim.c with iov_iter-aware dispatch. See `tidefs_posix_vfs_file_read_iter` and `tidefs_posix_vfs_file_write_iter`. Registered in `file_operations` replacing legacy `.read`/`.write`. Kbuild validation: tidefs_posix_vfs.ko builds against Linux 7.0.
9. **Still open for product closure**: custom Rust vm_operations_struct
   registration, Rust DirtyFolioTracker/page-authority live C bridge,
   direct-I/O, distributed mmap coherency, crash consistency, ACL, and
   freeze/thaw remain outside this mounted mmap/writeback proof.
10. **Partial**: `VfsEngine::allocate_inode` exists, but mock/unit coverage is
    not proof that kmod callbacks allocate through mounted `KernelPoolCore`.
    Closure requires real engine-backed wiring and Linux 7.0 validation.
11. **Retired**: Mount-path and root-inode-dispatch cargo/mock validation.
    `src/kernel_root_inode_validation.rs` was removed because it did not close
    the mounted Linux 7.0 root-inode path. Replacement work must produce
    QEMU output or an exact product blocker.
