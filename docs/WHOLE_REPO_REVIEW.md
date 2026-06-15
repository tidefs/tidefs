# Whole-Repo Review

Date: 2026-06-01

This is the active review snapshot for the fresh TideFS baseline. It records
what has been inspected so far and which broad areas must be resolved before
TideFS can make OpenZFS/Ceph-class claims.

## Root Cause

The bad working pattern was enabled by stale imported legacy material, not by a
single timestamp bug. Historical docs and automation packets treated issue
authority. That pushed work toward small surface fixes and output
bookkeeping even when the underlying filesystem authority model was still
unsettled.

The current policy is different:

- source behavior, live issue state, repo docs, and git history are review
  inputs;
- durable debt is recorded in `docs/REVIEW_TODO_REGISTER.md`;
- anonymous inline debt markers are not allowed;
- fixes should land as small, bisectable, Linux-style commits on `master`.
- each commit should have one reason to exist; review notes, workspace
  be lumped together.

## Current Scope

The first inventory found:

- 148 Cargo metadata packages and 148 workspace members;
- 153 `Cargo.toml` files under `apps/`, `crates/`, `kmod/`, `xtask/`, and
  `fuzz/`;
- five manifests outside the root workspace metadata after deleting the four
  abandoned POSIX adapter split-shard crates, the broken `tidefs-chaos` app
  root, and the five excluded non-fuzz scaffold type roots;
- 483 test, bench, or fuzz-path files by filename/path inventory;
- no bare `TODO`, `FIXME`, or `HACK` matches in non-vendored active source
  outside the review policy/register text;
- 244 files with stage words such as `stub`, `placeholder`, `mock`,
  `synthetic`, `continuation`, or `not implemented`, excluding the vendored
  `crates/tidefs-fuser` tree.

## Rename Surface Audit

The active repository rename surface is now mostly clean at the literal source
level. A case-insensitive legacy project-name scan over `/root/tidefs`,
excluding `target/`, `Cargo.lock`, and the vendored `crates/tidefs-fuser`
package, no longer reports active hits. `git ls-files` reports no tracked paths
with the old project name, `find` reports no non-target path names with that
name, and Cargo metadata reports no workspace package names or manifest paths
with that name.

The Forgejo remote rename is now complete: `/root/tidefs` tracks
`http://172.16.106.12/forgejo/forgeadmin/tidefs.git`, the live Forgejo
repository reports `forgeadmin/tidefs`, and the checkout no longer needs a
local `tidefs.forgejo-repo` override. This closes the mechanical remote-slug
drift, not the whole documentation-authority drift. Historical process docs
may still describe the old slug and remain `TFR-019` review input, not release
truth.

## Priority Findings

### TFR-001: Current Status And Claim Drift

`docs/00_user_requirements.md` still carried old version-by-version closeout
language, a mandatory state tarball requirement, and checked-in scoreboard
wording. `docs/CLAIMS_GATE_POLICY.md` also described current-claim gating in

Imported design docs may remain useful, but they are not current status until

### TFR-002: Workspace Authority

The root workspace does not cover every manifest. The current non-workspace
manifests are fuzz harnesses:

- `crates/tidefs-binary_schema-core/fuzz/Cargo.toml`
- `crates/tidefs-local-filesystem/fuzz/Cargo.toml`
- `crates/tidefs-local-object-store/fuzz/Cargo.toml`
- `crates/tidefs-validation/fuzz/Cargo.toml`
- `fuzz/Cargo.toml`

Meanwhile `tidefs-types-control-plane-core`,
`tidefs-types-publication-pipeline-core`, and
`tidefs-types-response-registry-core` are still workspace packages. This is not
yet a clean product/harness/archive split.

Spot checks against non-workspace packages confirm that Cargo cannot inspect
them in isolation because each package still believes it belongs to the root
workspace. Before cleanup, the root `fuzz/` manifest referenced the missing
`crates/tidefs-schema-codec-outcome`, the abandoned writeback worker manifest
referenced a missing adapter scheduler package, and the quarantined
`tidefs-chaos` app imported a missing `tidefs_chaos_campaign` package. These
are not harmless timestamps or naming residue; they are workspace-authority
blockers.

The root workspace lists those five harness manifests in `workspace.exclude`,
so Cargo root metadata cannot silently infer them as members. This is
quarantine, not closure: each harness must remain standalone-checkable or be

The five excluded non-fuzz scaffold type crates
`tidefs-types-archive-control-core`, `tidefs-types-observe-core`,
`tidefs-types-policy-authority-core`, `tidefs-types-shadow-pilot`, and
`tidefs-types-truth-view-core` have been deleted. Each failed standalone
manifest parsing because it inherited workspace fields while excluded, and
reverse-reference review found no live code consumers outside stale docs and
xtask classifier fixtures. The current archive/observe/policy/truth-view
record surfaces are already represented by `tidefs-types-vfs-core` or
product-local code.

The four non-workspace POSIX adapter split-shard directories
`tidefs-posix-filesystem-adapter-maintenance`,
`tidefs-posix-filesystem-adapter-workers-meta`,
`tidefs-posix-filesystem-adapter-workers-ns`, and
`tidefs-posix-filesystem-adapter-workers-writeback` have been deleted. Current
reverse-reference review found no active workspace users, their manifests were
outside Cargo metadata, and the stale classification docs already recorded
them as consolidated into the adapter runtime by #5725. The live POSIX adapter
workspace surface is now the daemon runtime module plus `reply`, `workers-io`,
`workers-locks`, and the vendored `fuser` package.

A fresh sweep confirms this is broader than a member-count mismatch:

- `cargo metadata --locked --no-deps` reports 148 packages, 148 workspace
  members, and 148 default members, while `rg --files -g Cargo.toml` now finds
  the root manifest plus five nonmember fuzz harness manifests.
- The root `fuzz/` manifest no longer depends on missing
  `crates/tidefs-schema-codec-outcome`, and its placeholder
  `fuse_request_deser` target has been deleted. The root fuzz package still
  cargo-fuzz harness.
- The four crate-local fuzz manifests now have explicit cargo-fuzz bin
  targets, dummy lib targets, and committed lockfiles. They pass standalone
  `cargo check --manifest-path ... --locked`, which fixes the harness
  packaging leak but does not decide whether each fuzz root stays, moves, or is
  archived.
- `docs/ARCHITECTURE.md` now marks the deleted scaffold type roots as deleted
  rather than archived-on-disk roots, but the broader workspace authority split
  remains open because other scaffold type crates still have live workspace
  dependency edges and need issue-backed disposition.
- `docs/workspace-package-classification.md` now records the current package
  role authority for 148 workspace packages, five excluded fuzz package roots,
  app roots, `kmod`, `xtask`, and vendored `fuser`.
- `xtask` policy validates that authority against Cargo metadata, manifest
  discovery, and root `workspace.exclude`, and fails product/operator/tooling
  dependencies on scaffold-transitional package roots.
- `apps/README.md` and `crates/README.md` now defer to the checked authority
  instead of carrying separate package-role tables.

That reduces the package-authority split, but workspace authority remains a
live product-boundary problem: scaffold-transitional type crates still exist in
the workspace, and broader xtask/doc authority classification is not complete.

The current `workspace.exclude` quarantine still does not close the scaffold
split. Current metadata shows the remaining hard control-plane type edges from
publication-pipeline and response-registry type crates into
`tidefs-types-control-plane-core`; proof-harness code may inspect that
transitional surface, but product/operator/tooling packages must not grow new
dependencies on it.

The secret-key policy edge has been narrowed since the prior sweep:
`tidefs-types-secret-key-policy-core` now owns local
`SecretKeyPolicyId128`/`SecretKeyPolicyDigest32` scalar types, and
`tidefs-secret-key-policy-runtime` consumes those local types instead of
depending on `tidefs-types-control-plane-core`. Current metadata no longer
reports either secret-key policy crate as a direct control-plane scaffold
consumer.

The standalone `tidefs-posix-filesystem-adapter-runtime` crate was removed
after current metadata showed no in-workspace reverse dependency and source
review showed the daemon already owns the live runtime module at
`apps/tidefs-posix-filesystem-adapter-daemon/src/runtime/mod.rs`. That removes
one hard scaffold dependency chain but does not close TFR-002; remaining
scaffold type crates still need separate migration, deletion, or explicit
workspace-membership review.

The POSIX receipt-demo edge is now local to the POSIX family instead of pulling
control/publication/response scaffold crates into the adapter. The POSIX core
crate owns its wake-receipt id, digest, request, journal, receipt, and
witness-ref types; the POSIX schema codec and format-golden path use those
types directly; and the daemon demo path uses local publication-ticket and
visible-answer demo records. Current metadata reports no direct scaffold
dependencies from the POSIX daemon, POSIX core, POSIX schema codec, or
`xtask`. `check-workspace-policy` now reports 148 members and 595 internal
dependency edges, with the publication-pipeline and response-registry type
crates listed as zero-consumer workspace crates to inspect before removal.
This still does not close TFR-002: publication/response type crates retain hard
control-plane type feature edge, and package/docs authority outside the
package-role table still needs deliberate review.

The first xtask gate cleanup narrowed the stale terminology, authority, and
observe checks to current workspace surfaces. The following now pass with
`CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target`: `check-group terminology`,
`check-terminology`, `check-human-readability`, `check-human-api-aliases`,
`check-authority-publication-spine`, `check-observation-substrate`,
replacement checks verify live control-plane/publication/response/POSIX wake
types, current human alias modules, VFS truth-view records, and block-volume
host-preflight surfaces. The pre-preview naming check no longer scans the
entire repository for normal historical wording and broad two-letter/digit
patterns; it now checks the current terminology constants. These gates no
longer require deleted policy-authority client/runtime, control-plane
runtime/API, response-registry query, observe-truth-view render, control-plane
paths.

The block-volume and cluster xtask gates have now been narrowed the same way:
they no longer require deleted `docs/MODULE_MAP.md`, `docs/STATUS.md`,
`docs/FEATURE_MATRIX.md`, `docs/CURRENT_VS_FUTURE_CAPABILITIES.md`,
output paths as active gate inputs. The block acceptance harness gate also no
longer requires the deleted `docs/PUBLISHING_CHECKLIST.md`, and the live
verification engine source now carries the `data_copy_2.verification_engine`
component id consumed by the cluster gate. The gates still carry `OW-*`/`PC-*`
labels, so this is authority cleanup, not label cleanup or TFR-002 closure.

This does not close the workspace scaffold split. `xtask` still contains other
old issue-era gate labels and other groups must be reviewed before
`check-group all` can be treated as current product authority.
The `tidefs-xtask` unit test suite itself now passes after removing the stale
claims unit assertion for `open-work item 010` and making the background
service framework marker check match the current `JobKind::Recovery` priority
mapping.

`docs/workspace-package-classification.md` is now the current package-role
authority for workspace members, app roots, `kmod`, `xtask`, vendored `fuser`,
and excluded fuzz package roots. `check-workspace-policy` validates that table
against Cargo metadata, manifest discovery, and root `workspace.exclude`, and
`crates/README.md` plus `apps/README.md` defer to it instead of carrying
competing package inventories. This reduces the package-authority split but
does not close TFR-002 or TFR-019: scaffold-transitional type crates still
need issue-backed migration, reclassification, or deletion, and broader
imported docs still need authority classification.

### TFR-004: Dataset And Inode Authority

`crates/tidefs-local-filesystem/src/lib.rs` still holds one global
`FileSystemState` with global inode maps, directory maps, known inode ids,
extent maps, and a global `next_inode_id`. The fresh root dataset catalog path
now uses the same `ROOT_DATASET_ID = [0u8; 16]` as the mounted filesystem and
SpaceBook bridge, and the FUSE mount path now pushes a resolved catalog
`DatasetId` into `LocalFileSystem::mounted_dataset_id()` before wrapping the
engine. Existing pre-rebuild catalogs whose `root` entry already carries a
different ID now fail closed on mount, but still need a deliberate dataset-ID
migration design under TFR-004.

The namespace and inode-table crates also have their own allocation/state
models:

- `tidefs-namespace` has `MemInodeTable` with an atomic bump allocator,
  `HashMap` storage, and a freed set.
- `tidefs-inode-table` has a separate slot/free-list table with its own
  generation and time source.
- `tidefs-namespace/src/local_fs_persist.rs` bridges namespace allocation back
  into `LocalFileSystem` using `fs.next_inode_id()` and `insert_inode_at()`.
- FUSE lookup/forget dispatch wraps a standalone `tidefs-inode-table`
  registry, so adapter lookup reference tracking is not sourced from the
  mounted dataset authority.
- The 2026-05-31 scalable-storage review records earlier namespace import
  breakage from bump-allocating loaded directory entries instead of preserving
  persisted inode IDs, plus remaining full-table hydration caveats in
  `InodeTable::open` and `InodeTable::iter`.

That confirms the operator concern: inode authority is not yet clearly
dataset-scoped or single-sourced.

The current code hotspots are marked with register-backed `TFR-004` comments
in `tidefs-local-filesystem`, `tidefs-namespace`, and `tidefs-inode-table` so
future behavior changes do not treat the global/local allocators as settled
authority.

`CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p
tidefs-local-filesystem --locked
root_dataset_catalog_id_matches_mounted_dataset_id`,
`CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p
tidefs-posix-filesystem-adapter-daemon --locked
mount_lookup_resolves_root_dataset`, and `git diff --check`. The adapter test
build also repaired stale test initializers for `SyncGuarantee` and namespace
`rdev` so the touched package can compile its focused dataset mount test.

Commit `0aac81e6` fixes the next mounted-dataset authority leak: committed
space deltas now synchronize store-layer `SpaceBook` counters with
`mounted_dataset_id` rather than the hard-coded root dataset. The regression
test sets a non-root mounted dataset, writes data, syncs, and verifies the
store usage is charged to that dataset rather than `ROOT_DATASET_ID`.
test, and `git diff --check`. This is only another bridge cleanup; it does not
settle old catalog migration or the global inode authority model.

Commit `b789492c` removes the warning-only root dataset mismatch path. A
persisted catalog whose `root` entry has an ID different from
`ROOT_DATASET_ID` now refuses mount with `FileSystemError::CorruptState`
instead of letting the catalog root and mounted root disagree. The regression
test persists a mismatched root catalog entry and verifies reopen fails
closed. This is still not a migration design for old catalogs and does not
settle dataset-scoped inode identity.

Commit `ba5e7647` fixes a narrower namespace-persistence allocator leak. The
in-memory `PersistentInodeStore` now preserves explicit nonzero inode IDs from
`InodeAttributes`, advances its bump allocator beyond those IDs, and therefore
matches the local-filesystem-backed store's root/bootstrap behavior. Before
that change, `Namespace::with_persistent_stores` could ask the persistent
store to create `ROOT_INODE` while the memory-backed store silently allocated a
`tidefs-namespace` test suite, `cargo fmt -p tidefs-namespace --check`, and
`git diff --check`. This still leaves the broader duplicate inode authorities
open.

Commit `feaaa6b2` fixes a narrower inode-table persistence fail-open path. The
`persist.rs` object-store path now fails closed when the named inode-table
header exists but cannot be decoded, instead of treating the store as fresh.
Direct persisted lookup, bounded windows, and full `InodeTable::open` also now
return corruption for present-but-invalid inode records or xattr sidecars,
the focused corrupt-record tests, the full `tidefs-inode-table` package test
suite, the no-default-features kernel check, `cargo fmt -p
tidefs-inode-table --check`, and `git diff --check`. This is still only a
corruption-handling cleanup; it does not settle root inode allocation,
dataset-scoped inode identity, FUSE lookup-reference authority, or the split
`persistent.rs`/`persist.rs` storage formats.

Commit `27cbcd67` fixes a namespace/local-filesystem persistence bridge leak.
For non-shared persistent directory stores, `Namespace` now hydrates delegated
directory mirrors from the store and writes create, symlink, hard-link, mknod,
mkdir, unlink, rename, `RENAME_NOREPLACE`, and `RENAME_EXCHANGE` through the
delegated store instead of treating it as bootstrap-only state. The
LocalFileSystem directory bridge synthesizes `.` and `..`, updates parent
directory link counts when child-directory entries are inserted or removed,
and can recover a child directory's parent from real entries. The same commit
keeps special nodes metadata-only at the facet layer and preserves special mode
bits, directory-entry kinds, and `rdev` through the LocalFileSystem-backed
namespace bridge.

This is still not TFR-004 or TFR-018 closure. Generic `NamespaceEntry` intent
insert records still have no device-number authority for special-node `rdev`,
the delegated LocalFileSystem store update sequence is not a crash-consistency
rename claims, and inode authority remains split across namespace,
LocalFileSystem, FUSE lookup-reference, and inode-table paths.

### TFR-005: Timestamp, Revision, And Format Coupling

`InodeRecord` persists `data_version` and `metadata_version`, and
`InodeRecord::to_inode_attr()` projects the same fields back as POSIX time:
atime and ctime come from `metadata_version`, mtime is
`max(data_version, metadata_version)`, and btime comes from inode generation.
That makes POSIX timestamp projection depend on storage version fields before
any adapter-specific timestamp path runs.

`LocalFileSystem::apply_timestamp_update()` captures wall clock internally and
writes POSIX time transitions back through those version fields:
ctime/atime advance `metadata_version`, while mtime advances `data_version`.
The FUSE setattr dispatcher and VFS engine setattr path duplicate the same
shape: explicit atime/ctime write `metadata_version`, explicit mtime writes
`data_version`, and `_NOW` or implicit ctime cases use a bumped generation
tick. This means a "timestamp-only" edit can change storage version identity.

That storage identity is live in multiple independent subsystems:

- versioned content object keys include `data_version`;
  `data_version`;
- scrub reads content by `(inode_id, data_version)` and reports violations
  with that version as block identity;
- inode encoding serializes both version fields, while content-manifest
  encoding serializes manifest and chunk `data_version`;
- intent-log replay reconstructs content under
  `next_generation_after(state.generation)`, stores the manifest under that
  versioned key, and writes the same tick back into
  `data_version`/`metadata_version`;
- namespace rename paths stamp parent or overwritten-inode metadata with the
  moved entry generation, not an independently specified timestamp/version
  authority.

The FUSE operation matrix still treats write timestamp coverage as a local
adapter claim, with explicit nonclaim scaffolding for inactive write paths.
That coverage is useful, but it does not close version authority: POSIX time,
storage generation, replay, scrub, object keys, and on-disk compatibility must
be specified as one contract before behavior changes land.

The current authority crossings are marked with register-backed `TFR-005`
comments in inode record projection, local timestamp writeback, FUSE/VFS
setattr paths, and versioned content object key generation.

### TFR-006: Compression, Encryption, And Dedup Authority

Transform handling has multiple live entry points rather than one ordered
storage contract.

`crates/tidefs-compression/src/lib.rs` now names the mounted content write path
as `resolve_compression_policy()` to `ContentCompressionPolicy` to
`encode_content_chunk()`, and correctly says the helper crate's
filesystem then resolves content compression from dataset properties or feature
flags, and `write_chunked_content()` hashes plaintext chunk bytes for dedup,
encodes canonical dedup chunks with the mounted compression policy, and stores
per-inode redirect payloads.

Commit `ef2cb86c` cleans up one API-boundary leak in this area. The public
`LocalFileSystem::effective_compression_policy_report()` no longer returns the
crate-local mutable `ContentCompressionPolicy`; it returns an owned
`EffectiveCompressionPolicyReport` snapshot with the active algorithm, level,
savings threshold, and resolution source. That removes the known
`private_interfaces` warning without making the internal write-encoding policy
a public authority.

At the same time, `LocalFileSystem::default_pool()` and `block_device_pool()`
pass optional device-level encryption and compression configs into the object
store pool. Normal `PoolStore` handles go through the `Device` stack, but
`Pool::raw_primary_store()` explicitly bypasses compression and encryption.
The mounted filesystem uses that raw handle widely for open/recovery, state
selection, content read/write, snapshot export/import, fsync and intent-log
paths, scrub, reclaim, allocator scans, and space accounting. This is a
transform-boundary problem, not only a missing wrapper.

Issue #218 moved the raw-store inventory into the checked current-policy doc
`docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md`. The guarded counts
are now 89 matches in `crates/tidefs-local-filesystem/src/lib.rs`, 21 in
`crates/tidefs-local-filesystem/src/crash_recovery.rs`, 7 in
`crates/tidefs-local-filesystem/src/journal_cleaner.rs`, 6 in
`crates/tidefs-local-filesystem/src/vfs_engine_impl.rs`, and 7 lower
object-store accessor/escape-hatch matches in
`crates/tidefs-local-object-store/src/pool/mod.rs`. The inventory classifies
mounted production paths as transform-aware, metadata/raw-only, blocked, or
owned by later receipt/placement issues, and it names the ordering terms
plaintext identity, compression frame, encryption frame, checksum, raw media
bytes, and reclaim identity. The blocked rows still cover open/recovery,
file-content read/write, snapshot export/import, intent-log and fsync paths,
scrub, reclaim, allocator scans, directory/inode fallback reads, and validation
fixtures.

Commit `8b5b0f70` therefore makes the mounted local-filesystem
device-transform helpers fail closed for now. `LocalFileSystem` rejects open
configs carrying device-level encryption or compression with
`FileSystemError::Unsupported` while the TFR-006 raw-store inventory has
blocked production rows. The lower-level object-store pool transform stack is
still present; this gate
prevents the mounted filesystem API from presenting incomplete encryption or
compression coverage as a working end-to-end feature.

The device transform order was also ambiguous. `open_single_device()` wraps
encryption first and compression outside it, so a write through
`CompressedDevice` compresses plaintext and then calls the encrypted inner
device. Commit `91a05295` corrects the nearby comments and repairs the pool
label subcase where encrypted+compressed devices were top-level
`Device::Compressed`: `Device::is_encrypted()` now recurses through the
compression wrapper, and a regression test proves such a pool reopens as
locked when the key is absent. This is only a label/lock-detection repair; it
does not define the complete transform contract.

Dedup adds a third transform authority. `write_chunked_content()` fingerprints
the uncompressed chunk bytes, writes canonical objects with
`encode_content_chunk()`, stores dedup redirects at per-inode keys, and the
chunks. Reclaim drains dedup redirect refcounts and queues canonical objects
when the last ref drops. Those pieces may be useful, but they are not yet one
specified ordering for plaintext, compression frame, encryption frame,
checksum, dedup identity, raw-store access, and reclaim.

### TFR-007: Capacity And Accounting Authority

The repository now has a `CapacityAuthority`, but the current implementation
still bridges several ledgers.

`crates/tidefs-local-filesystem/src/capacity_authority.rs` claims every statfs,
quota, pool, and device counter derives from one authority and that no
side-ledger paths remain. Source inspection does not support closing that
claim. `LocalFileSystem::statfs()` derives pool physical counters from
`CapacityAuthority`, updates the store-layer `SpaceBook`, pulls an allocator
report, quota-clamps `reusable_free_bytes`, derives block counters from
`CapacityAuthority`, then starts from `LocalStorageAllocatorReport::to_statfs()`
and clamps block counts through quota/effective capacity.

Mutation paths also remain spread out. Writes, fallocate, KEEP_SIZE reserve,
truncate, block discard, punch-hole, zero-range, collapse/insert, mknod-style
allocation, and unlink/reclaim paths combine quota table decisions,
hierarchy checks, `CapacityAuthority::reserve()` and `record_free()`,
`SpaceAccounting` deltas, physical tracking, extent allocator changes, reclaim
deltas, and obligation ledger checks. `commit_space_delta()` then bridges
engine counters into a store-layer `SpaceBook`, while store code still exposes
`statfs_for_dataset()` and automatic dataset counter persistence.

Commit `5a01cc11` repairs one zero-range leak inside that broader split.
`zero_range()` now inspects the target extent map before admission and charges
fresh capacity only for holes that become allocated. Existing DATA ranges keep
their capacity count, and UNWRITTEN ranges are converted out of reservation
accounting rather than being charged again. This removes a concrete ENOSPC bug
where zeroing already allocated data on a nearly full pool could fail even
though no new logical allocation was needed.

Commit `3e1ab660` repairs one statfs projection leak. The FUSE engine statfs
path now preserves the canonical `LocalFileSystem::statfs()` counters instead
of re-deriving raw `CapacityAuthority` block counts after quota/effective
capacity clamping. `statvfs()` now uses the same clamp helper, statfs reports
a stable 4096-byte reporting block size, and inode totals use configured inode
capacity instead of live inode count so `files_free <= files` remains true.
This closes the observed FUSE/statvfs clamp drift, not the whole capacity
model.

This is improved from the old dual-query statfs path, but it is not yet a
complete capacity authority. The honest next design step is to specify which
state is authoritative for logical used bytes, physical used/free bytes,
reserved bytes, snapshot-pinned bytes, quota hierarchy, pending writes,
allocator extents, and store persistence, then make adapters consume that
model.

### TFR-008: Recovery, Fsync, Writeback, Mmap, And Cache Authority

Durability and cache coherency still cross several mechanisms that are not one
contract.

`LocalFileSystem` owns committed-root publication, a data intent log, an
optional metadata intent-log buffer, a commit-group state machine, per-inode
write buffers, a sync gate, `DirtySet`, a range `DirtyPageTracker`, a local
page cache, inode and hot-read caches, and a best-effort `Drop` commit. The
write path buffers bytes, records a `SyncWriteRange` intent, marks dirty
ranges, and only clears those ranges after `flush_write_buffer()` rewrites the
content layout. Fsync/fdatasync then choose among intent-log flush, targeted
content-object sync, full `do_commit()`, `sync_data()`, sync-gate waiting, and
store-wide `sync_all()`. That is useful machinery, but there is not yet one
specified answer for what survives each syscall, each close path, and each
crash boundary.

Recovery is similarly split. Mount selects the latest committed root and
replays the object-store intent log before `IntentLog::open_log_device()` is
called. Opening the LOG_DEVICE can merge extra entries into the in-memory log,
but that happens after `load_latest_committed_state()` already performed
replay. The same open path then separately runs commit-group recovery, txg
replay, dataset-catalog side persistence, and the `tidefs-recovery-loop`
namespace intent replay, with some failures logged while mount continues.
Those are not yet one import-side durability state machine.

The cache model also overstates closure. `docs/cache-authority-model.md` names
`tidefs-cache-core::PageCache`, local `DirtyPageTracker`, and `DirtySet` as
authoritative in different dimensions while also classifying the local-fs page
cache as derived. Source comments in `dirty_page_tracker.rs` and
`writeback.rs` both claim authority, and the daemon adds FUSE
`writeback_page_cache`, `writeback_cache`, `dirty_state`, block-volume dirty
ranges, and commit barriers. FUSE fsync dispatch drains daemon page-cache
pages, marks daemon caches clean, flushes block-volume ranges, calls the
engine fsync/fdatasync path, commits the adapter txg cycle, and then uses the
ownership a product boundary, not a settled implementation detail.

Mmap and pre-full-kernel writeback remain especially risky, but the current
mounted-kernel path is narrower and more concrete than the older source-model
claims. The live C shim admits engine-backed mounted-pool `mmap(2)` through
`tidefs_posix_vfs_file_mmap()` -> `generic_file_mmap()` and refuses
bootstrap/fixed-table files because they have no mmap writeback authority.
Linux filemap then
calls the registered C `address_space_operations`: `read_folio` reads through
`tidefs_posix_vfs_engine_read`, `dirty_folio` records Linux dirty accounting,
`writepages` copies dirty folio bytes into `tidefs_posix_vfs_engine_write`,
and `fsync` drains `filemap_write_and_wait_range()` before
`tidefs_posix_vfs_engine_fsync()`. Engine writeback errors and short writes
re-dirty the folio for retry. Mounted truncate now takes the C mapping
invalidate lock, waits dirty mapped or buffered folios with
`filemap_write_and_wait_range()`, unmaps and invalidates the size-change
range, calls the Rust engine `setattr` bridge, and then applies
`truncate_setsize()` to the canonical size. Truncate-extend, direct-write,
fallocate, and copy invalidation remain C-helper-owned mounted cleanup rather
than Rust source-model page-authority claims.

That first-boot mounted C/generic-filemap proof is not TFR-008 or TFR-018
closure. The Rust `KmodVfsVmOps`, `DirtyFolioTracker`, and page-authority
model remain a fail-closed source/model path until a C `vm_operations_struct`
and direct Rust aops bridge are registered. `KmodPosixVfs::mmap()` returns
`EOPNOTSUPP`; mounted mmap authority is the C generic-filemap path above.
Crash-consistent mmap, broad xfstests,
direct-I/O, FUSE writeback-cache correctness, placement receipt correctness,
and distributed mmap coherency remain open review debt before any
OpenZFS/Ceph-class durability or coherency claim is honest.

### TFR-009: Kernel Residency And Block Authority

The current kernel path is not a terminal full-kernel filesystem. The
kernel-resident architecture document is honest about this in one place: the
current module is no longer bootstrap-only, but its mounted operation slice
still keeps a small fixed in-kernel namespace/data table in the pool data
region and explicitly says that table is not the final object/extent/intent-log
engine, page-cache/writeback, xfstests, crash consistency, or terminal

The source confirms that this is not just conservative wording. The block-kmod
entrypoint opens a hard-coded `/dev/tidefs_pool_member` path and wraps it in a
local `KernelStoragePoolCoreAdapter`; if that device is absent, it falls back to
an in-kernel buffer for bring-up. The adapter module still says its local
`PoolCoreOps` trait should be removed once a canonical `KernelPoolCore` bridge
exists. The common kmod `VfsEngine` trait also defaults block capacity to zero
and returns `ENOSYS` for block read/write/flush/discard/write-zeroes/zero-range
unless an engine overrides those methods. On the storage side,
`RawBlockFile` uses kernel VFS `filp_open`, `kernel_read`, and `kernel_write`
under Kbuild, but its Kbuild flush path is a no-op that relies on guest sync
commands rather than a pool-authoritative lower-device flush contract.

That means "no daemon" is only true for narrow callbacks already exercised in
the current module. It does not yet prove one kernel-resident pool authority for
mounted VFS, block export, writeback, recovery, placement, reserve/admission,
flush/FUA, discard/remanence, and teardown. Kernel fixes in this area must be
Linux 7.0 Kbuild/QEMU/mounted-kernel work with exact scope; source-model,
residency item.

### TFR-010: Snapshot, Clone, Send/Receive, And Deadlist Authority

Snapshot state crosses catalog, lifecycle, root-retention, send/receive, and
space-accounting boundaries.

`LocalFileSystem::create_snapshot()` records a `SnapshotRecord`, commits the
state mutation, pins a `TraversalRoot` in dataset lifecycle GC state, creates a
name-derived `root@name` dataset catalog entry, and persists the catalog.
`delete_snapshot()` checks holds, unpins the full traversal root, removes the
state entry, destroys the dataset catalog entry, commits, and persists the
catalog. Mount/open reconstructs lifecycle pins and reconciles dataset catalog
entries from `state.snapshots`.

`snapshot.rs` does not follow that same authority boundary everywhere. It
states that reusing `SnapshotRecord` for clones and bookmarks provides "full
ZFS-equivalent lifecycle semantics"; however `create_clone()` inserts a
`SnapshotKind::Clone` record that shares a root, `delete_clone()` only removes
that record, and `promote_clone()` flips the kind to `Snapshot`. Retention
pruning removes regular snapshots from `state.snapshots` and commits the
mutation, but it does not mirror the explicit delete path's dataset-catalog
destroy or lifecycle unpin behavior.

Send/receive is another authority. Full export uses current roots plus
roots, filters changed content by object key/checksum, and always includes
structural records. Full receive stages into a temporary root and resumes via
checkpoint; incremental receive requires the base root to be present in the
target recovery audit and republishes roots after writing content records.
Those mechanics are useful but are not unified with retention, deadlist
accounting, clone lineage, snapshot holds, root GC pins, or dataset catalog
lifecycle.

### TFR-011: Operator CLI And UAPI Authority

The CLI is not yet a single, trustworthy public boundary. Earlier source
wording claimed `tidefsctl` was the single supported operator/UAPI client and
classified many commands as final UAPI in a source table. That table
contradicted live handlers and cluster maturity:

- commit `7dbb0759` removes the fake `pool list` parser surface instead of
  accepting a command whose handler only said the scaffolding had been removed;
  the live discovery path remains explicit `pool scan --devices ...`.
- commit `7dbb0759` also changes the source classification table so cluster
  placement/heal exercise commands are development diagnostics rather than
  final UAPI claims.
- Issue #243 makes `mount` construct standalone daemon mount authority and
  routes `pool mount --cluster` through typed `PoolLeaseToken` daemon
  admission instead of a separate boolean/raw-token pairing.
- `cluster pool create` now has a TCP transport adapter and quorum reporting,
  while adjacent cluster/orchestrator docs still say parts of live dispatch and
  runtime authority remain TFR-017 work.

This is an operator-safety problem, not just wording. An OpenZFS/Ceph-class CLI
needs a stable distinction between public UAPI, development harnesses,
diagnostics, exercises, and removed commands. Current code exposes those
categories side by side, and the status table is not authority by itself.

### TFR-012: Device Lifecycle, TRIM, And Remanence

Device add/remove, discard, and privacy semantics are still staged.

Pool-member backing must be byte-addressable: block devices for production and
regular files for hidden development mode. Directory `LocalObjectStore`
compatibility is not a valid pool-member device mode. The default device
discard operation is unsupported, and issues #14 and #16 make that boundary
explicit: pool-device admission rejects directories, `DeviceConfig` carries
the explicit backing kind, byte-addressable file and block devices share the
fixed-offset label/single-segment object-store path, directory object-store
compatibility no longer advertises discard, non-zero direct discard fails
explicitly, and directory-only pool trim/free paths report zero bytes
discarded. Segment reclaim still performs best-effort hole punching in the
compatibility path, but that is not a media-remanence guarantee.

The public local-filesystem `trim_blocks()` call simply forwards explicit byte
ranges to the store's discard path. Compression and encryption wrappers forward
discard ranges unchanged and say transforms do not affect TRIM byte ranges;
that needs a privacy contract, because discard observability and remanence are
different for plaintext, encrypted, compressed, regular-file-backed
development pools, and block-device-backed production pools.

`tidefsctl device remove` now imports pool config from labels and persists
updated survivor labels, which is progress. The flow still opens a target
store, preloads all target objects into memory, maps object ids to original
keys locally, relies on operator-provided surviving store directories, maps
synthetic `/dev/diskN` paths to those directories, writes survivors through
closures, syncs survivor stores, persists labels, and anchors the removal on
the target store. That is not yet a pool-authoritative online device lifecycle
with placement/refcount authority, resumable evacuation, replacement, zeroing,
and remanence policy.

### TFR-013 And TFR-016: Stage Residue

The repo has cleaned up bare debt markers, but stage residue remains broad.
Examples include:

- `apps/tidefsctl/src/main.rs` still needing broader UAPI authority review even
  after `7dbb0759` removed `pool list` scaffolding and downgraded exercise
  wording;
- `apps/tidefs-posix-filesystem-adapter-daemon/Cargo.toml` still calling the
  daemon a Wave Zero stub;
- `apps/tidefs-posix-filesystem-adapter-daemon/tests/fuse_e2e_smoke.rs`
  defining Claimed/NotReady test stubs;
- kernel compatibility stubs in `kmod/src/kernel_types.rs`;
  runner and placeholder scoreboard tests;
- `xtask/tidefs-xtask/src/claims.rs` still requiring old cluster-pool
  scaffolding markers in `tidefsctl` even though the source now has a TCP
  transport adapter;
- `crates/tidefs-node-drain/src/runtime.rs` containing an `unimplemented!()`
  path;
- imported docs and xtask gate modules that still require missing status,
  feature-matrix, and current-vs-future capability docs.

These may be legitimate test doubles or kernel-compatibility shims, but each
must be classified explicitly before product claims depend on it.

adapter. The dormant `src/observe/` metrics, Prometheus, structural, and
tracing module was deleted after the crate-level `#![deny(dead_code)]` gate
proved it was not wired into the live daemon. Live read, write, rename,
flush/fsync, and FUSE mount harness surfaces no longer carry
and stale local-filesystem helper were deleted; the append-handle helper now
runs as a unit test; and embedded NUL test literals in `fuse_vfs_adapter.rs`
are escaped so source scanners keep treating the file as text. A focused scan
TFR-013/TFR-016 closure, because broader stage wording and issue-era labels
remain open.

The active storage spec constants and their source-level gates no longer use
the issue-era `open-work item` phrase. Those strings now describe TideFS
storage/checksum items directly, and `xtask` no longer requires imported docs
to carry that phrase as an authority marker. This does not close TFR-016:
short `OW-*`, `PC-*`, and `NEXT-*` labels remain in source, xtask, and imported
docs until each surface is either renamed, classified as historical, or deleted.

The focused short-label scan now has a measured surface:

```text
```

It reports 104 active non-doc files: 13 `apps/`, 59 `crates/`, 16 `nix/`, 3
reports 82 files. The active clusters are storage/xtask gates, block-volume
labels, POSIX/FUSE/kernel `NEXT-*` notes, security/performance harness labels,
and storage authority comments/tests. Current source and operator-facing text
should name TideFS capabilities directly; old issue labels belong only in
historical/provenance context after documentation classification.

active non-doc short-label inventory is 96 files: 13 `apps/`, 59 `crates/`, 16
`nix/`, 3 `scripts/`, and 5 `xtask/`.

The adjacent scripts cleanup removed short issue labels from active
performance baseline scripts and removed issue-numbered output authority at the
same time. The FUSE, kernel VFS, and metadata scripts no longer emit `issue`
fields into generated JSON/environment output, no longer default to
longer searches old issue-bound worker module paths. The focused `scripts/`
scan now returns no `OW-*`, `PC-*`, or `NEXT-*` hits. The remaining active
non-doc short-label inventory is 93 files: 13 `apps/`, 59 `crates/`, 16
`nix/`, and 5 `xtask/`.

The kernel VFS performance Nix wrapper now follows the same rule: descriptive
worker module path, and no worker checkout path for commit discovery. The
wrapper also now copies the resolved `POSIX_VFS_KO` module path instead of the
undefined `POSIX_TFS_KO` variable. This reduces the active non-doc short-label
inventory to 92 files: 13 `apps/`, 59 `crates/`, 15 `nix/`, and 5 `xtask/`.
It is not Nix closure; a broader scan for short labels, JSON `issue` fields,
issue-numbered output paths, and packet headings still matches 26 `nix/`
files.

The kernel VFS long-haul soak Nix wrapper now follows that same policy:
scratch defaults, no JSON `issue` field, no issue-bound worker path, and
current `/root/tidefs` git metadata. It also had the same undefined
`POSIX_TFS_KO` copy bug and now copies the resolved `POSIX_VFS_KO` module. The
active non-doc short-label inventory is 91 files: 13 `apps/`, 59 `crates/`, 14
matches 25 `nix/` files.

The kernel block partition/reread, queue-depth, and guest-filesystem matrix
generic configurable module paths, external scratch output paths without issue
numbers, generated manifests without JSON `issue` fields, and current
`/root/tidefs` git metadata instead of worker checkout paths. The guest
filesystem matrix manifest also no longer writes old A-register provenance.
The active non-doc short-label inventory is now 88 files: 13 `apps/`, 59
residue scan still matches 22 `nix/` files.

The kernel block crash-consistency, no-daemon, and fio powercut wrappers are
configurable/generic module paths, external scratch output paths without issue
numbers, generated manifests without JSON `issue` fields or old A-register
provenance, and blocker text that names the remaining kernel pool-core
integration gap without issue numbers. The active non-doc short-label
inventory is now 87 files: 13 `apps/`, 59 `crates/`, 10 `nix/`, and 5
`nix/` files.

The FUSE fio baseline, open-unlink/rename soak, product demo soak,
namespace-scale QEMU, and namespace-scale host wrappers now avoid `NEXT-*`
labels, JSON `issue` fields, and cwd-dependent git metadata in the cleaned QEMU
wrappers. The active non-doc short-label inventory is now 84 files: 13
`apps/`, 59 `crates/`, 7 `nix/`, and 5 `xtask/`. The broader Nix
FUSE `xfstests` remain open because their QEMU-pin collection paths are still
issue-numbered.

module paths, no JSON `issue` field, current `/root/tidefs` git metadata, and
copies the resolved `POSIX_VFS_KO` module instead of the undefined
`POSIX_TFS_KO` variable. The active non-doc short-label inventory remains 84
`nix/` files.

of `NEXT-*` or issue-number banners. The active non-doc short-label inventory
is now 81 files: 13 `apps/`, 59 `crates/`, 4 `nix/`, and 5 `xtask/`. The

The QEMU pin-manifest path no longer requires issue authority: the manifest
wrapper script no longer accepts issue ids. The FUSE fsx pin path, FUSE
titles. The active non-doc short-label inventory remains 81 files, and the

The remaining kernel/kmod Nix wrappers now follow the same policy. The
lockdep/KCSAN/KASAN, mount namespace, mount-cycle, and crash-consistency
wrappers no longer emit old packet labels, issue fields, issue-numbered output
paths, worker worktree paths, or stale A-register metadata. They now use
module output paths, and the resolved `POSIX_VFS_KO` module copy. The active
non-doc short-label inventory is now 77 files: 13 `apps/`, 59 `crates/`, and
0 `nix/` files.

The `tidefsctl diag` support-bundle path no longer carries the stale
`NEXT-REL-013` tracker label in live Rustdoc or CLI help comments. The focused
support-bundle scan returns no `NEXT-REL-013` hits under `apps/tidefsctl` or
tidefsctl --locked` passes with `CARGO_TARGET_DIR` outside the repo. The active
non-doc short-label inventory is now 74 files: 11 `apps/`, 58 `crates/`, and
5 `xtask/`.

The storage-node and transport scrub/repair fanout comments no longer carry
the stale `NEXT-MN-023` tracker label in active source. The focused scrub/repair
scan returns no `NEXT-MN-023` hits under `apps/tidefs-storage-node` or
`crates/tidefs-transport/src/replication.rs`, and `cargo check -p
tidefs-storage-node -p tidefs-transport --locked` passes with
`CARGO_TARGET_DIR` outside the repo. This does not close TFR-017: cross-replica
scrub comparison, repair authority, rollback, and recovery semantics remain
open. The active non-doc short-label inventory is now 71 files: 9 `apps/`, 57
`crates/`, and 5 `xtask/`.

### TFR-014: Licensing And Provenance

The root package license is `GPL-2.0-only WITH Linux-syscall-note`. Cargo
metadata shows the only workspace package with a different license is the
vendored/patched `fuser` package under `crates/tidefs-fuser`, which reports
`MIT` and keeps its license text in `crates/tidefs-fuser/LICENSE.md`.
`docs/LICENSING.md` now records that third-party provenance explicitly.

The five excluded non-workspace cargo-fuzz harness manifests now declare
`GPL-2.0-only WITH Linux-syscall-note` explicitly instead of relying on root
workspace metadata they do not consume. A focused scan of those harness roots
found no file-local third-party notices requiring separate provenance handling.
`check-workspace-policy` now verifies those explicit license fields.
This closes the known non-workspace manifest license gap; TFR-014 remains open
for broader file-local notice and future third-party provenance audits.

### TFR-015: Runtime Output Doctrine


Remaining risk is imported wording that treats scoreboards, artifacts, proposal
labels, or old issue closeouts as release truth. That wording must be removed or
reclassified as historical context when each document is audited.

pin manifests and the helper scripts that emit them no longer carry legacy
no longer emit old metadata. The remaining rule is simple: runtime output is
scratch state outside the repo unless an operator asks for a separate handoff.
The POSIX and xfstests scoreboard formats may remain as external
authority.

ublk integrity, kernel readdir, kernel directory namespace, FUSE inode
metadata, page-cache writeback, no-daemon full-stack, crash-consistency, mmap
fuzz, recovery-loop, intent-log, block-kmod, kmod-posix-vfs, and performance
gate docs/readmes.

quarantine patterns or claim runtime proof storage, no-daemon and mmap
pre-existing formatting drift outside this authority cleanup.

self-test paths, issue-numbered operator-demo run ids, release-rehearsal
issue comments, and JSON `issue` manifest fields. The remaining metadata uses
`scripts/` now return no matches for that old interface or JSON issue
metadata.

A follow-up active-script scan found two surviving benchmark runners still
`issue=`.

The adjacent performance baseline package loader no longer treats the old
issue field as required authority. FUSE fio and ublk baseline JSON now carry
`baseline.*` ids, and the old `issue` field remains optional input
compatibility only.

The block-volume and cluster xtask marker gates no longer require old
deleted status docs, and the block acceptance gate no longer requires the
deleted publishing checklist. That removes another active-code dependency on
review input until classified.

A fresh `tidefs-xtask check-group storage` run shows why the next storage gate
work cannot be a narrow deleted-doc patch. Several early rows pass, including
local object-store, recovery, integrity pipeline, background scheduler, extent
map, and dataset lifecycle checks. The group still fails across multiple
authority classes: deleted current-status docs (`STATUS.md`, `FEATURE_MATRIX`,
`MODULE_MAP`, `PUBLISHING_CHECKLIST`, preview/scoreboard/FUSE docs), deleted
adapter preview source files (`fuse_preview.rs`, `coverage_gap.rs`), missing
or moved product surfaces (`crates/tidefs-online-verifier`, scrub CLI markers,
orphan-index integration markers), stale constructor expectations in btree and
dir-index checks, and old `OW-*`/`PC-*` label authority. That failure belongs
to TFR-002/TFR-013/TFR-016/TFR-019 as a storage authority rebuild queue, not
to a one-line missing-file fix.

The active storage group has now been narrowed to the live checks that match
current TideFS files and source authority. `check-group storage` covers current
local object-store, format/policy, local filesystem, recovery/no-fsck,
integrity pipeline, mount invariant, root retention, xattr storage,
background scheduler/orphan reclamation, polymorphic extent map, dataset
lifecycle, and space-accounting watermarks. It no longer aggregates retired
preview/status gates that require deleted docs or `fuse_preview.rs`, and the
current pass output no longer emits old issue/`OW-*`/`PC-*` labels. The
retired individual commands are still TFR-002/TFR-013/TFR-016/TFR-019 review
material until each one is retargeted to current code or removed.

The `check-group all` storage section has also been aligned with that current
storage aggregate. It no longer invokes retired preview/status/POSIX checks,
deleted docs, deleted adapter preview files, or the duplicated nested spacemap
branch. The first post-alignment `check-group all` run exposed only
non-storage authority work: policy clippy warnings, a stale platform
scaffolding doc gate, stale cluster extent-map and locator-table marker
checks, and format-golden drift. Those failures became visible without the
all-check path fabricating extra storage failures from retired gates.

The platform scaffolding gate has now been retargeted to current Nix/runtime
documentation instead of requiring a deleted guide with old `OW-*` markers.
non-mutating RDMA probes, all with scratch output under
reduced to policy clippy warnings, stale cluster extent-map and locator-table
marker checks, and format-golden drift.

The stale cluster extent-map and locator-table marker checks have since been
retargeted to current live source surfaces, and the format-golden corpus now
uses the manifest as fixture authority. Generation removes stale `.bin`
`.bin` vectors, and the checked-in corpus contains only the current VFS plus
`check-group all` failure set is reduced to `policy/check-code-navigability`
only, with 80 clippy warnings.

The first deeper clippy pass proved that "code navigability" was also hiding
all-target compile drift. Erasure-coded-store integration tests were missing
new placement fields, fuser all-features builds selected fuse3 code even when
the build script had fallen back to libfuse2, chunk-shipper carried a
deny-level unused mutable binding, and placement-runtime tests still used a
pre-tiering `FailureDomainPlacementPolicy` literal. Those compile blockers are
slice rather than a warning-only cleanup.

and the deleted POSIX runtime/observe/worker smoke mirrors. Live worker-IO
durable `StoreOptions` defaults with focused overrides, and previously
unreached capacity smoke helpers run with a corrected growth-rounding
workspace clippy pass now gets past that crate. The next hard
code-navigability blocker was the POSIX adapter FUSE mount harness, where
unused convenience helpers are compiled into test crates under deny-level
dead-code lints. The broad module-level `dead_code` allowance was removed.
Only the five helpers that are intentionally shared across different
integration-test binaries (`remount`, `create_read_write`, `open_read_only`,
`read_all`, and `patterned_bytes`) carry item-local shared-harness allowances;
focused adapter clippy now reaches the existing warning inventory only.

The next POSIX adapter warning slice removes the package-local clippy warning
sites that were still visible after the harness blocker: duplicated feature
cfgs, missing/derivable `Default` implementations, stale format strings,
unit-value bindings in placement persistence, and an identity bit-or in
placement tests. Focused adapter clippy now emits only dependency-crate
warnings from the broader workspace inventory, while `placement_recorder` and
`lock_dispatch` unit-test filters pass. Package-wide rustfmt remains a separate
pre-existing formatting-drift cleanup, so it is not counted as a clean gate for
this warning slice.

The next extent-map warning slice is intentionally narrow. The B-tree
serializer already depends on the backing `BPlusTree` for entry authority, and
the empty-map page decision now asks that tree directly with `is_empty()`
`enumerate()` after its index stopped being part of the ordering checks. This
only removes package-local clippy noise; it does not close the broader
extent-map, persistence, or storage layout review items.

A focused post-cleanup scan no longer finds active module/doc/readme residue
terminology has also been replaced across active docs,
imported status docs, `NEXT-*` labels, and release-closeout wording still need
classification before they can be current authority.

### TFR-017: Transport And Cluster Authority

The workspace contains real distributed building blocks: storage-node,
transport, membership, placement, replication, node-drain, node-join, rebuild,
relocation, and two-node harness packages all exist. That is useful source, but
it is not yet one product-grade distributed authority.

The storage-node authority spine is present and points in the right direction.
`apps/tidefs-storage-node/src/authority_spine.rs` stores a disclosed backend,
derived `TransportConfig`, node identity, failure domain, member class, and
replication factor. `StorageNode::start()` uses `authority.is_live()` to choose
between a transport-backed `TransportReplicatedStore` and the local
path-backed `ReplicatedObjectStore`. Commit `b1517c76` fixed the JSON
config-file bypass: `JsonStorageNodeConfig` now builds a live
`RuntimeAuthority` from the configured backend, node identity, member class,
failure domain, and replication factor, and `main.rs` no longer clears it before
startup. The focused `config_file_live_backend_uses_transport_store` regression
proves a config-started TCP node reaches the transport-backed store path.

The live transport-backed store also has correctness gaps that are larger than
backend disclosure. `TransportReplicatedStore::put_named()` writes the local
primary first, counts the primary as one acknowledgement, then fans out to
remote replicas over control sessions. Commit `6954336d` now snapshots the
previous primary payload and, when put/delete fails to reach quorum, restores
the primary and sends best-effort compensating put/delete messages to replicas
that acknowledged the failed mutation. That removes one obvious divergence
between the local primary and acknowledged replicas, with regression coverage
for no-quorum put and delete rollback. It is still not a distributed
transaction or recovery law: sent but unacknowledged replicas can have mutated,
rollback is not tied to membership/fencing epochs, and partition recovery is
not driven by authoritative replica inventory. `get_named()` reads the primary
first and may fall back to remote replicas, but that is not tied to an
authoritative self-heal/writeback contract for the transport-backed path.

The peer maintenance path is similarly incomplete. Inbound replication avoids
fan-out loops by using `put_local`, `get_local`, and `delete_local`, which is
the right local-only boundary. Commit `eead3eff` fixes the narrow
`SyncRequest` identity bug: `SyncResponse` now carries the raw 32-byte
`ObjectKey`, the storage-node sync handler reads payloads by exact key, and the
transport integration consumer materializes synced objects under the same key
bytes instead of a re-hashed lossy UTF-8 name. This makes the current sync
response an actual local key inventory, but it is still not a product-grade
cross-replica inventory authority: it lacks digest comparison, epoch binding,
membership/fencing interaction, and repair selection.
`ScrubResponse` is currently just logged with a `TFR-017` review-debt marker,
and `RepairObject` is a local put, not a cross-replica comparison, selection,
and repair law.

RDMA and carrier authority are also not claim-ready by default.
`Transport::with_rdma_or_tcp()` constructs RDMA when possible and otherwise
falls back to TCP. Carrier policy can enforce fail-closed RDMA negotiation, and
health reports disclose per-session backend information, but the default policy
is still `Prefer`, which permits fallback. A release or product claim therefore
needs a single admission rule that distinguishes "TCP product path", "RDMA
product path", "fallback disclosed and refused for RDMA claims", and
"deterministic or loopback harness only."

Cluster pool surfaces disagree about their maturity. The `tidefs-cluster`
orchestrator source still says it builds protocol messages and aggregation
helpers, and that no live transport backend is wired into the orchestrator.
Meanwhile `tidefsctl cluster pool create` contains a TCP `PoolTransport`
adapter and dispatches CP01-framed messages to storage-node sessions.
`tidefsctl` now classifies `cluster placement exercise` and `cluster heal
exercise` as development diagnostics, but the commands still sit beside live
cluster-pool dispatch and therefore remain part of the broader TFR-011/TFR-017
operator-surface authority review.

The docs already contain honest non-claims that must remain binding:
`REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md` says the replicated
object/root slice is deterministic model work and that networked replication
transport, streaming movement, relocation execution, and production runtime
remain deferred. `ARCHITECTURE.md` says TideFS has multi-node foundations but
is not production-scale against CephFS. The OW-307D blocker map says
deterministic demo rows do not prove a production operator surface. The Tier 7
multi-node/RDMA test is ignored by default and records that deterministic
loopback readiness still requires live TCP or RDMA runtime closure.

The next transport implementation work should therefore start with a written
authority contract, not another local patch. It needs to define the product
transport modes, replica write/delete rollback or repair law, cross-replica
inventory identity, scrub comparison and repair selection, membership/fencing
for each claim.

### TFR-018: Kernel And POSIX Edge Wiring

Kernel/POSIX work remains a high-risk area. The initial negative dentry,
shutdown-advertising, xfstests cleanup-probe, and kmod `MountOptions` test
initializer fixes have landed as their own commits, which is the right shape.
The K7 xfstests Nix runner now also reports QEMU runner timeouts before guest
environment refusals, and avoids a final-row remount probe after the requested
set is exhausted. Its aggregate pass/fail/skipped counters now count only
requested xfstests rows, with separate infrastructure counters for helper or
engine lookup path, so cached ENOENT is valid only while the engine still
reports ENOENT and a newly resolved name forces a VFS lookup retry. Remaining
writeback, xfstests, and mounted-kernel behavior still need separate review

The kmod address-space state now has two deliberately separate descriptions.
Committed C code registers `generic_file_mmap()` plus
`address_space_operations` callbacks for `read_folio`, `write_begin`,
`write_end`, `dirty_folio`, and `writepages`. The C `writepages` path walks
Linux dirty folios and writes copied bytes directly through
`tidefs_posix_vfs_engine_write()`, while `dirty_folio` only calls
`filemap_dirty_folio()` and increments lifecycle counters because the engine
bridge can sleep from atomic MM paths. The Rust `address_space_ops.rs` and
`mmap.rs` modules describe the source-model `DirtyFolioTracker`,
`VfsEngine::writeback_folios()`, `writepage`, `page_mkwrite`, Rust
`invalidate_folio`, and `KmodVfsVmOps` authority model that is not yet wired
as the mounted C callback path.

The practical result is not "mmap solved" or "writeback solved." The C shim
admits engine-backed mounted-pool mmap via the generic filemap path, but no
custom VM operations bridge registers the Rust `KmodVfsVmOps` policy, and the
registered C a_ops table still lacks direct Rust DirtyFolioTracker/
page-authority cleanup. Issue #260 makes that unsupported state fail-closed in
the Rust API: `KmodPosixVfs::mmap()` returns `EOPNOTSUPP`, and direct vm-ops
construction is named as source-model only. POSIX
matrix, compliance, and xfstests documents must continue to distinguish the
first-boot mounted mmap/writeback row from crash consistency, direct-I/O, FUSE
writeback-cache, distributed coherency, and broad xfstests closure. These
boundaries remain review debt, not closure.

The current page-cache reconciliation slice fixes real bugs without treating
the area as closed. Direct engine writes now follow the Linux write path shape:
generic write checks run under the inode lock, privilege stripping and timestamp
updates happen before the mutation, cached pages in the target range are
the mapping, and `generic_write_sync()` handles synchronous writes. Engine
engine-reported copied lengths, and updates destination size/times. The
address-space path now allocates/fills write-begin folios, returns real
allocation and short-write errors from write-end, writes dirty folios through a
real engine handle, re-dirties folios whose writeback failed, and persists
writeback mtime/ctime after successful dirty-folio flushes.

tests, `rustfmt --check` for the Kbuild type shim, `git diff --check`, and a
Linux 7.0 out-of-tree Kbuild module build with output under `/root/ai/tmp`.
The build emitted pre-existing objtool fall-through warnings from generated
Rust symbols, but produced `tidefs_posix_vfs.ko`.

The C shim now documents the matching writeback redirty invariant at the two
engine failure exits. Because `writeback_iter()` has already cleared the folio
dirty bit, an engine error or short engine write must re-dirty the folio before
`folio_end_writeback()` or the page-cache retry path can lose dirty data.
Focused Linux 7.0 Kbuild still produces `tidefs_posix_vfs.ko` for this shim
slice; the build repeats the pre-existing Rust objtool fall-through warnings.

Commit `e777ce9d` continues the same TFR-018 direction for fallocate and
writeback error visibility. Engine-backed fallocate now flushes, unmaps, and
collapse and insert checks run under `inode_lock()`; insert-range now rejects
`offset >= i_size` and over-`s_maxbytes` growth in the Linux shape; and
writeback engine, timestamp-persist, and release failures are logged alongside
`cargo check`, `git diff --check`, and Linux 7.0 Kbuild module compilation.
This is still source/Kbuild progress, not mounted runtime closure.

Commit `e300e053` picks up the other half of that insert-range path inside
Rust `KernelEngine`. After the C shim admits `FALLOC_FL_INSERT_RANGE`, the
engine now shifts live write-buffer entries and DATA/UNWRITTEN live extents,
splits entries that straddle the insertion point, grows inode size, and leaves
focused fallocate tests, `tidefs-kmod-bridge` `cargo check`, rustfmt on the
Kbuild Rust module source, `git diff --check`, and Linux 7.0 Kbuild module
compilation. This remains a source/Kbuild slice; mounted QEMU insert-range,

Commit `67669445` fixes a narrower zero-range writeback bug in the same live
engine area. A staged zero entry can cover DATA extents, UNWRITTEN extents,
and holes in one range. The previous flush logic persisted zeros only when one
DATA extent covered the full staged zero range; otherwise it dropped the entry
as clean, which could leave old DATA bytes in the live storage area. The engine
now discovers every overlapping DATA physical range and zeros only those
focused fallocate tests, `tidefs-kmod-bridge` `cargo check`, rustfmt on the
Kbuild Rust module source, `git diff --check`, and Linux 7.0 Kbuild module
compilation. This is still not mounted writeback closure.

Commit `3e223d4d` keeps the engine-backed `copy_file_range` source boundary in
page-cache range before calling into Rust; the live `KernelEngine` override now
also drains matching live source write-buffer entries to the mounted pool
copy_file_range tests, `tidefs-kmod-bridge` `cargo check`, rustfmt on the
Kbuild Rust module source, `git diff --check`, and Linux 7.0 Kbuild module
compilation. Mounted QEMU copy/writeback/mmap/direct-I/O behavior still
belongs to TFR-018.

Commit `d8af4a16` fixes another source-visible live-engine edge in the
reserved-tail append path. The append fast path now admits tail growth only
when the write range has no same-inode live extent overlap, including
UNWRITTEN fallocate ranges, and no pending write-buffer overlap. The direct
write path can still extend a DATA extent into reserved physical space, but it
no longer creates overlapping live extent state when a later live range already
Rust module source, `git diff --check`, focused fallocate tests,
`tidefs-kmod-bridge` `cargo check`, and Linux 7.0 Kbuild module compilation.
A broader `write`-filtered library test run still fails existing
address-space, mmap, and writeback expectation tests outside this Kbuild entry
file, so this is not writeback/mmap closure.

recorded and before collecting dmesg/journal diagnostics, then classifies
missing requested rows after a partial nonzero QEMU exit as harness failures.
That preserves partial truth when a wedged guest makes diagnostics hang, but it
acceptance.

The host wrapper now covers the earlier failure window too: when the generated
requested xfstests rows plus a separate QEMU infrastructure row. This preserves

The same wrapper now covers pre-launch Nix failures separately. If building
the generated VM runner artifact fails before QEMU starts, the wrapper writes
structured `NixVmArtifactBuildFailure` rows and keeps `nix-vm-build.log` with

The wrapper also freezes source provenance for isolated runs. At invocation
start it copies the TideFS source tree to an immutable Nix store path and
passes that path to every generated VM build, so a later concurrent worktree
hardening only; product behavior still requires the mounted-kernel rows.

Commit `886c4a42` fixes the non-zero half of the live writeback gap. The
previous flush path could only persist a staged non-zero write-buffer entry
when one DATA extent already covered the whole logical range. Sparse gaps and
UNWRITTEN extents inside that range therefore turned writeback into an error
instead of allocating storage for the staged bytes. The engine now materializes
DATA extents for missing or non-DATA spans, then writes each DATA segment
Rust source, `git diff --check --cached` for the staged source diff,
`tidefs-kmod-bridge` `cargo check`, focused fallocate tests, and Linux 7.0
Kbuild module compilation with output under `/root/ai/tmp`. The zero writeback
path remains sparse-preserving, and this is still not mounted writeback
closure.

Commit `91419e2a` keeps `copy_file_range` error accounting consistent across
the C and Rust halves. The C shim already returns a positive copied byte count
instead of a later error once progress has been made; the Rust engine loop now
does the same when destination writes hit `ENOSPC` after earlier chunks were
focused copy_file_range tests, `tidefs-kmod-bridge` `cargo check`, rustfmt on
the Kbuild Rust source, `git diff --check`, and Linux 7.0 Kbuild module
compilation with output under `/root/ai/tmp`. Mounted QEMU copy/writeback/mmap
and direct-I/O behavior still belongs to TFR-018.

Commit `822848b7` tightens the live write path by sending live inode writes
through active mounted storage when `KernelPoolCore` exposes a writable
committed-root I/O context. The new helper reuses
`write_live_data_range_to_storage()` so sparse or non-DATA spans are
materialized through the same writeback authority, clears overlapping staged
write-buffer bytes after the write, and updates inode size before returning.
When active storage is absent, the older staged/reserved write path remains the
`git diff --check`, `tidefs-kmod-bridge` `cargo check`, focused fallocate and
write-path library tests, and Linux 7.0 Kbuild module compilation with output
under `/root/ai/tmp/tidefs-kmod-live-write-active-storage/`. This is not
mounted runtime closure; QEMU writeback, mmap, direct-I/O, and no-daemon

Commit `38ac310e` closes the next mounted fallocate/page-cache bug exposed by
`generic/075`. When a buffered write left a dirty EOF folio resident and a
subsequent fallocate extended allocation past EOF from within that same page,
the Nix sandbox at
the run reported `generic/075` passed in Linux 7.0 mounted-kernel VFS with
`local_host_kernel_used=false`, `passed=1`, and no product or harness failures.
writeback, mmap, direct-I/O, and no-daemon contracts remain open TFR-018 work.

### TFR-019: Documentation Authority Drift

The imported documentation set is not yet an authority graph. It mixes current
policy, design intent, old issue closeout language, missing files, and source
gates that still assume removed docs.

Concrete current drift:

- `docs/PREVIEW_USER_MANUAL.md` now points readers to the review register and
  whole-repo review instead of missing status, feature-matrix, and release-focus
  docs.
- `docs/GETTING_STARTED.md` now points readers to the review register,
  whole-repo review, and preview user manual instead of missing status and
  feature-matrix docs. Its quick-start commands still need classification
- `xtask/tidefs-xtask/src/claims.rs` now scans current tracked docs rather than
  missing status, feature-matrix, current-vs-future, kernelspace, Nix
- The claims gate now checks the current `cluster pool create` source shape
  plus its open `TFR-017` limits instead of requiring old scaffolding markers
  that contradicted live transport dispatch.
- `docs/CLAIMS_GATE_POLICY.md` now says the gate scans current policy docs,
  preview docs, the review register, and the whole-repo review.
- `docs/workspace-package-classification.md` now records the current
  148-package workspace, five excluded fuzz package roots, and 153 classified
  package manifests. `check-workspace-policy` validates that package authority
  against Cargo metadata, manifest discovery, and root `workspace.exclude`;
  remaining TFR-002 work is the issue-backed migration, reclassification, or
  deletion of scaffold-transitional type surfaces.
- `apps/README.md` had listed deleted `tidefs-policy-authority-daemon` and
  `tidefs-control-plane-daemon` roots as current app roots. It now lists the
  roots currently present on disk and flags open TFR authority limits, but that
  does not classify the rest of the imported doc set.
- A first focused closeout-wording cleanup classified these imported docs as
  TFR-019 review material and removed their narrow `Maturity:`,
  framing:
  `docs/CHUNKED_FILE_LAYOUT_OW101.md`, `docs/HOT_READ_CACHE_PC003.md`,
  `docs/LOCAL_OBJECT_STORE_ON_DISK_FORMAT.md`,
  `docs/LOCAL_SNAPSHOTS_OW108.md`, `docs/LOCAL_STORAGE_ALLOCATOR_OW102.md`,
  `docs/NO_PRODUCTION_FSCK_FAILURE_MODEL.md`,
  `docs/POSIX_SEMANTICS_OW106.md`, `docs/POSIX_SUBSET.md`,
  `docs/PREVIEW_UAPI_ABI_BOUNDARY_OW202.md`,
  `docs/PRODUCTION_INTEGRITY_POLICY.md`,
  `docs/PRODUCTION_INTEGRITY_V3_RECORDS_OW014.md`,
  `docs/ROOT_AUTHENTICATION_OW015.md`,
  `docs/SAFE_LOCAL_RECLAMATION_OW103.md`,
  `docs/SEND_RECEIVE_OW109.md`, and `docs/UAPI_ABI_BOUNDARY_OW202.md`.
  They are not current status authority; they are historical implementation
  notes until reconciled with current source and the review register.
- A broader TFR-019 scan still finds 87 imported docs outside this review and
  the register with `Maturity:` or Forgejo/design-closeout wording. That is the
  remaining documentation-authority surface, and it must be classified in
  follow-up slices before the doc tree can be trusted as current TideFS truth.
  The open queue is listed in `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.
- A live `check-claims-gate` run with
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target` now passes against the
  canonical `forgeadmin/tidefs` Forgejo slug after compiling with the
  then-pre-existing `private_interfaces` warning; commit `ef2cb86c`
  subsequently removed that warning from `tidefs-local-filesystem`.
  the current outside-sandbox FUSE QEMU runner
  runner's stray/duplicated `--per-test` help/parser entries were removed.
  Current-facing docs no longer send readers to deleted
  owner map and docs index instead of deleted `MODULE_MAP`, `STATUS`, and
  `FEATURE_MATRIX` files. This is documentation and gate-authority cleanup
  FUSE `generic/001`-`generic/013` tranche.
- After that cleanup, a bounded outside-sandbox QEMU run on commit `a2b54d3f`
  KVM and Linux 7.0.0. The copied JSON at
  reports `passed=11`, `failed=0`, `blocked=0`, and `skipped=0`, including
  `xfstests_generic/001`; the copied QEMU boot log has 329 lines. This is real
- A follow-on outside-sandbox QEMU run on commit `74a4be91` executed
  with KVM and Linux 7.0.0. The copied JSON at
  reports `passed=22`, `failed=0`, `blocked=0`, and `skipped=0`, including
  `xfstests_generic/002` through `xfstests_generic/013`; the copied QEMU boot
  log has 373 lines. Together with the `generic/001` run, this completes the
  #6582 FUSE smoke tranche classification as PASS. This does not close the
  broader TFR-018 recovery/fsync/writeback/mmap or mounted-kernel/no-daemon
  edge-wiring review.
- A current-head outside-sandbox QEMU run on commit `302164e2` executed
  with KVM and Linux 7.0.0. The copied JSON at
  reports `passed=47`, `failed=0`, `blocked=0`, and `skipped=0`, including
  `xfstests_generic/014` through `xfstests_generic/050`; the copied QEMU boot
  log has 475 lines. Together with the #6582 runs, this completes the current
  `generic/001` through `generic/050` FUSE smoke classification as PASS. This
  does not close the broader TFR-018 recovery/fsync/writeback/mmap,
  mounted-kernel/no-daemon, or full-suite xfstests/fsx/fsstress edge-wiring
  review.
  rows printed after noisy helper output still become structured rows. A
  committed-head outside-sandbox QEMU run then executed
  with KVM and Linux 7.0.0. The copied JSON at
  reports `passed=12`, `failed=16`, `blocked=0`, `unsupported=15`, and
  `skipped=17`, with exactly one xfstests row for each requested
  `generic/051` through `generic/100`. `generic/084` and `generic/086` pass;
  the failed rows are product defects, while the rest are unsupported or
  skipped preconditions. This completes the #6586 tranche as classified
- Commit `b26233d4` cleans per-row FUSE xfstests scratch/result stores, and a
  committed-head outside-sandbox QEMU run then executed
  with KVM and Linux 7.0.0. The copied JSON at
  reports `passed=12`, `failed=15`, `blocked=0`, `unsupported=24`, and
  `skipped=9`, with exactly one xfstests row for each requested
  `generic/101` through `generic/150`. `generic/103`, `generic/117`, and
  `generic/141` pass; 14 xfstests rows fail as product defects; 24 rows are
  unsupported; and 9 rows are skipped preconditions. The extra failed row is
  the `unmount` teardown check reporting `Device or resource busy`. This
  and not as TFR-018 closure.
- A committed-head outside-sandbox QEMU run then executed
  with KVM and Linux 7.0.0. The copied JSON at
  reports `passed=10`, `failed=4`, `blocked=0`, `unsupported=43`, and
  `skipped=3`, with exactly one xfstests row for each requested `generic/151`
  through `generic/200`. That tranche had no xfstests pass rows:
  `generic/169`, `generic/184`, `generic/192`, and `generic/198` failed as
  product defects; 43 rows were unsupported; and 3 rows were skipped
  preconditions. A focused current-tree rerun recorded as
  `fuse-generic-184-20260603T183844Z.json`
  now passes `generic/184`. A second focused current-head run at
  `fuse-generic-192-20260603T190341Z.json`
  now passes `generic/192`. A focused patched-tree run at
  `fuse-generic-169-20260603T192830Z-fsgetxattr.json`
  now passes `generic/169` after `FS_IOC_FSGETXATTR` reports a Linux-shaped
  empty `struct fsxattr` and the xfstests helper keeps a stable per-device
  backing store across remounts. A focused patched-tree rerun at
  `fuse-generic-198-20260604T004023Z-final.json`
  now passes `generic/198` with `passed=12`, `failed=0`, `blocked=0`,
  `unsupported=0`, and `skipped=0` after sparse same-size direct-write
  overlays, open-unlink sparse anonymous data, deferred O_DIRECT flush
  behavior, and empty-mountpoint cleanup landed. All infrastructure rows in
  the original tranche, including `unmount` and `daemon_stop`, passed. This is
  still not TFR-018 closure.
- Commit `2bb253a6` replaces the FUSE xfstests guest BusyBox `mv` applet with
  coreutils `mv`, and commit `07262209` keeps future manifests from claiming
  clean unmount when the teardown row failed. A committed-head outside-sandbox
  QEMU run then executed
  with KVM and Linux 7.0.0. The copied JSON at
  reports `passed=16`, `failed=10`, `blocked=0`, `unsupported=19`, and
  `skipped=15`, with exactly one xfstests row for each requested `generic/201`
  through `generic/250`. `generic/208`, `generic/210`, `generic/211`,
  `generic/212`, `generic/221`, `generic/246`, and `generic/248` pass;
  `generic/207`, `generic/209`, `generic/214`, `generic/215`, `generic/237`,
  `generic/239`, `generic/245`, `generic/247`, and `generic/249` fail; 19
  rows are unsupported; and 15 rows are skipped preconditions. The extra
  failed row is `unmount`, which reports `Device or resource busy`; the
  `daemon_stop` row passes. This completes the #6592 tranche as no-go
- A committed-head outside-sandbox QEMU run then executed
  with KVM and Linux 7.0.0. The copied JSON at
  reports `passed=9`, `failed=7`, `blocked=0`, `unsupported=34`, and
  `skipped=10`, with exactly one xfstests row for each requested `generic/251`
  through `generic/300`. No xfstests rows pass; `generic/257`, `generic/258`,
  `generic/263`, `generic/285`, `generic/286`, and `generic/294` fail; 34
  rows are unsupported; and 10 rows are skipped preconditions. The extra
  failed row is `unmount`, which reports `Device or resource busy`; the
  `daemon_stop` row passes. This completes the #6594 tranche as no-go
- A committed-head outside-sandbox QEMU run then executed
  with KVM and Linux 7.0.0. The copied JSON at
  reports `passed=10`, `failed=12`, `blocked=5`, `unsupported=18`, and
  `skipped=12`. It produced xfstests rows through `generic/345`, then
  `generic/346` wedged after exceeding the 600s per-test timeout; the owned
  guest was terminated and the rescued primary JSON marked `generic/346`
  through `generic/350` blocked because no rows appeared after the hang. A
  tail run at
  classified `generic/347`, `generic/348`, `generic/349`, and `generic/350`
  as skipped preconditions. Commit `efe90d25` also copies coreutils
  `truncate` into the guest; the focused recheck at
  passes `generic/315`. The final #6596 xfstests row classification is 4
  PASS rows (`generic/308`, `315`, `337`, `339`), 11 FAIL rows
  (`generic/306`, `307`, `309`, `310`, `313`, `318`, `319`, `323`, `340`,
  `344`, `345`), 1 BLOCKED row (`generic/346`), 18 unsupported rows, and
  16 skipped rows. This completes the #6596 tranche as no-go classified
- Commit `4c3b6044` copies coreutils `md5sum` into the FUSE xfstests guest.
  The #6598 primary run at
  ran `generic/351` through `generic/418` with KVM and Linux 7.0.0 on commit
  `8f1e2a71`; it reported `passed=8`, `failed=6`, `blocked=23`,
  `unsupported=12`, and `skipped=26`, with xfstests rows through
  `generic/395`. `generic/391` exceeded the 600s per-test timeout and the
  owned guest was stopped after the wrapper failed to recover cleanly, so the
  rescued JSON marked `generic/396` through `generic/418` blocked. The focused
  `generic/360` recheck at
  ran on committed head and still fails, now as missing temp cleanup after the
  checksum command rather than missing `md5sum`. The committed-head tail run at
  reports `passed=11`, `failed=2`, `blocked=0`, `unsupported=8`, and
  `skipped=12`, replacing the artificial tail blocks. The final #6598
  xfstests row classification is 2 PASS rows (`generic/377`, `403`), 8 FAIL
  rows (`generic/354`, `360`, `375`, `391`, `393`, `394`, `401`, `412`), 0
  BLOCKED rows, 20 unsupported rows, and 38 skipped rows. This completes the
  TFR-018 closure.
- The #6587 mounted-kernel VFS tranche ran `generic/051` through
  `generic/100` in Linux 7.0.0 outside-sandbox QEMU/KVM with the Nix-built
  `tidefs_posix_vfs.ko` matching the generated guest kernel. The accepted
  matrix uses
  rows `generic/061` through `generic/069` from
  row `generic/070` from
  rows `generic/071` through `generic/074` from
  rows `generic/075` and `generic/077` through `generic/080` from
  row `generic/076` from
  rows `generic/081` through `generic/090` from
  and rows `generic/091` through `generic/100` from
  The final #6587 xfstests row classification is 23 PASS rows
  (`generic/056`, `058`, `059`, `060`, `061`, `062`, `063`, `064`, `065`,
  `066`, `067`, `070`, `071`, `072`, `075`, `076`, `080`, `088`, `089`,
  `090`, `096`, `097`, `098`), 11 product FAIL rows (`generic/057`, `069`,
  `073`, `074`, `083`, `084`, `085`, `086`, `087`, `092`, `100`), 0 BLOCKED
  rows, 12 unsupported rows, and 4 skipped rows. Deferred rows from the shared
  `061-070` and `071-080` runs and the first isolated `generic/076`
  Linux no-patch proof records `linux_ref: none`; no Linux source patch is
  required for this classification issue. This completes the #6587 tranche as
- The #6589 mounted-kernel VFS tranche ran `generic/101` through
  `generic/150` in Linux 7.0.0 outside-sandbox QEMU/KVM with the Nix-built
  `tidefs_posix_vfs.ko` matching the generated guest kernel. The accepted
  matrix uses rows `generic/101` and `generic/102` from
  rows `generic/103` through `generic/110` from
  rows `generic/111` through `generic/120` from
  rows `generic/121` through `generic/127` from
  rows `generic/128` through `generic/130` from
  rows `generic/131` through `generic/140` from
  and rows `generic/141` through `generic/150` from
  The final #6589 xfstests row classification is 14 PASS rows
  (`generic/101`, `103`, `104`, `106`, `107`, `109`, `112`, `117`, `120`,
  `124`, `126`, `131`, `132`, `141`), 3 product FAIL rows (`generic/102`,
  `127`, `129`), 0 BLOCKED rows, 29 unsupported rows, and 4 skipped rows.
  Rows after `generic/102` from the first shared `101-110` run and deferred
  rows `generic/128` through `generic/130` from the shared `121-130` run are
  `linux_ref: none` for `forgeadmin/linux:tidefs/linux-7.0`. This completes
  and not as TFR-018 closure.
- The #6591 mounted-kernel VFS tranche ran `generic/151` through
  `generic/200` in Linux 7.0.0 outside-sandbox QEMU/KVM with the Nix-built
  `tidefs_posix_vfs.ko` matching the generated guest kernel. The accepted
  matrix uses rows `generic/151` through `generic/160` from
  rows `generic/161` through `generic/163` from
  rows `generic/164` through `generic/170` from
  rows `generic/171` through `generic/180` from
  rows `generic/181` through `generic/190` from
  and rows `generic/191` through `generic/200` from
  The final #6591 xfstests row classification is 4 PASS rows
  (`generic/169`, `177`, `184`, `192`), no product FAIL rows, 0 BLOCKED rows,
  43 unsupported rows, and 3 skipped rows. The wedged shared `161-170` run is
  records `linux_ref: none` for `forgeadmin/linux:tidefs/linux-7.0`. This
  pass claim and not as TFR-018 closure.
- The #6593 mounted-kernel VFS tranche ran `generic/201` through
  `generic/250` in Linux 7.0.0 outside-sandbox QEMU/KVM with the Nix-built
  `tidefs_posix_vfs.ko` matching the generated guest kernel. The accepted
  matrix uses rows `generic/201` through `generic/204` from
  rows `generic/205` through `generic/210` from
  rows `generic/211` through `generic/220` from
  rows `generic/221` through `generic/230` from
  rows `generic/231` through `generic/240` from
  rows `generic/241` through `generic/247` from
  and rows `generic/248` through `generic/250` from
  The final #6593 xfstests row classification is 5 PASS rows
  (`generic/215`, `221`, `236`, `246`, `248`), 7 product FAIL rows
  (`generic/204`, `213`, `224`, `228`, `245`, `247`, `249`), 0 BLOCKED rows,
  36 unsupported rows, and 2 skipped rows. Deferred rows `generic/205`
  through `generic/210` from the first shared `201-210` run and
  `generic/248` through `generic/250` from the first shared `241-250` run are
  records `linux_ref: none` for `forgeadmin/linux:tidefs/linux-7.0`. This
  pass claim and not as TFR-018 closure.
- The #6595 mounted-kernel VFS tranche ran `generic/251` through
  `generic/300` in Linux 7.0.0 outside-sandbox QEMU/KVM with the Nix-built
  `tidefs_posix_vfs.ko` matching the generated guest kernel. The accepted
  matrix uses rows `generic/251` through `generic/260` from
  rows `generic/261` through `generic/270` from
  rows `generic/271` through `generic/273` from
  row `generic/274` from
  row `generic/275` from
  rows `generic/276` through `generic/280` from
  rows `generic/281` through `generic/290` from
  and rows `generic/291` through `generic/300` from
  The final #6595 xfstests row classification is 3 PASS rows
  (`generic/255`, `286`, `294`), 7 product FAIL rows (`generic/257`, `258`,
  `269`, `273`, `274`, `275`, `285`), 0 BLOCKED rows, 38 unsupported rows,
  and 2 skipped rows. Deferred rows `generic/274` through `generic/280` from
  the first shared `271-280` run are excluded from the accepted matrix, and
  `forgeadmin/linux:tidefs/linux-7.0`. This completes #6595 as no-go
  TFR-018 closure.
- The #6599 mounted-kernel VFS tranche ran `generic/351` through
  `generic/418` in Linux 7.0.0 outside-sandbox QEMU/KVM with the Nix-built
  `tidefs_posix_vfs.ko` matching the generated guest kernel. The helper-built
  matrix uses rows through `generic/361` from
  rows through `generic/371` from
  rows through `generic/387` from
  rows through `generic/403` from
  and isolated rows `generic/404` through `generic/418` from
  The final #6599 xfstests row classification is 8 PASS rows
  (`generic/354`, `360`, `376`, `377`, `393`, `394`, `403`, `404`), 8
  product FAIL rows (`generic/361`, `371`, `387`, `401`, `409`, `410`,
  `411`, `416`), 0 BLOCKED rows, 32 unsupported rows, and 20 skipped rows.
  `forgeadmin/linux:tidefs/linux-7.0`. This completes #6599 as no-go
  TFR-018 closure.
- The #6597 mounted-kernel VFS tranche ran `generic/301` through
  `generic/350` in Linux 7.0.0 outside-sandbox QEMU/KVM with the Nix-built
  `tidefs_posix_vfs.ko` matching the generated guest kernel. The accepted
  matrix uses rows through `generic/316` from
  isolated replacement rows `generic/317` through `generic/320` from
  rows `generic/321` through `generic/330` from
  rows `generic/331` through `generic/340` from
  and rows `generic/341` through `generic/350` from
  The final #6597 xfstests row classification is 13 PASS rows
  (`generic/308`, `309`, `310`, `315`, `316`, `321`, `325`, `335`, `337`,
  `338`, `341`, `343`, `348`), 11 product FAIL rows (`generic/306`, `313`,
  `320`, `322`, `336`, `339`, `340`, `342`, `344`, `345`, `346`), 0 BLOCKED
  rows, 21 unsupported rows, and 5 skipped rows. The shared-run no-space
  `generic/317` through `generic/320` rows are excluded from the accepted
  `forgeadmin/linux:tidefs/linux-7.0`. This completes #6597 as no-go
  TFR-018 closure.

The policy direction is to classify every doc before relying on it: current
policy, current implementation spec, historical design input, or delete
candidate. Until that is done, doc links and source gates are review material,
not proof.

### TFR-020: Test Signal Authority

TideFS has enough unit, integration, harness, xtask, and marker tests that test
count no longer predicts product confidence. The current policy is
`docs/TEST_SIGNAL_POLICY.md`.

The review direction is to keep tests that prove mounted behavior, runtime
durability, crash/reopen recovery, kernel/ublk/RDMA operation, xfstests rows,
durable format rejection, real security boundaries, and compact internal
invariants. Redundant branch-level tests, source-marker checks, scaffold tests,
stale expected-output tests, and weakened-fixture tests should be compressed,
demoted, or deleted when their owning surface is touched.

`StoreOptions::test_fast()` and equivalent relaxed fixtures are allowed for
narrow fast checks, but they must not support claims about production
durability, checksum verification, recovery, or durable reads. Harness tests
must be cited as harness signal, not product proof.

2026-06-05 application pass:

- Static inventory found 1,430 Rust files with `#[test]`, `#[cfg(test)]`,
  `#[tokio::test]`, or `#[proptest]` markers. The largest inline test surfaces
  remain `apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_vfs_adapter.rs`
  with 912 test attributes, `crates/tidefs-block-volume-adapter-ublk-control-runtime/src/lib.rs`
  with 318, `crates/tidefs-local-filesystem/src/vfs_engine_impl.rs` with 297,
  `crates/tidefs-local-filesystem/src/tests.rs` with 264, and
  `crates/tidefs-local-object-store/src/tests.rs` with 230.
- Cargo metadata reports the largest integration-test target surfaces in
  `tidefs-posix-filesystem-adapter-daemon` (48), `tidefs-validation` (27),
  `tidefs-local-filesystem` (26), `tidefs-local-object-store` (25), and
  `tidefs-transport` (16). These are the main review zones for future test
  compression or relocation.
- `#[ignore]` tests are limited and mostly legitimate opt-in harness/runtime
  lanes: FUSE mount validation, trace-golden regeneration, two-node/RDMA
  product-path validation, and timed transport budget measurement. The demo
  mount ignored tests and the ignored adapter dirty-tracking/fsync dispatch
  test still look like roadmap placeholders and should be removed or converted
  to executable runtime signal when those surfaces are touched.
- Source-marker xtask checks remain widespread. They are transitional
  policy/tooling signal only; do not cite them as product proof. When touching
  an owning surface, prefer replacing the marker check with cargo metadata,
  structured parsing, a public API check, or a runtime/harness test.
- The first fixture cleanup strengthened object-store and local-filesystem
  durability/read-integrity tests so tests that claim reopen survival,
  durable reads, or checksum-verified reads use `verify_read_checksums: true`
  while retaining small segment sizes and explicit `sync_all`/fsync boundaries
  where those boundaries are the behavior under test.
- A broader `tidefs-local-object-store --test object_store_validation` run
  still reproduces `compact_retaining_empty_protected_set_clears_store` with
  live objects remaining after empty-retention compaction. That is separate
  reclamation behavior, not test-signal cleanup; do not count the full
  validation suite as green until the compaction retention rule is fixed in an
  owning storage commit.

## Next Review Order

1. Workspace authority: classify every manifest as product, harness, third
   party, fuzz/test, archive, or delete candidate.
2. Runtime-output cleanup: remove release/proposal authority while
3. Dataset/inode authority: define dataset-scoped inode identity and remove
   duplicate allocation authorities.
4. Timestamp/version authority: split POSIX timestamps from storage generation
   and object-version semantics, or document one intentional contract.
5. Storage authority: unify transform ordering, capacity accounting,
   snapshot/deadlist lifecycle, and device/remanence semantics before making
   product claims in these areas.
6. Transport/cluster authority: make storage-node, transport carrier policy,
   membership/fencing, replica mutation, scrub/repair, and operator CLI claims
7. Documentation authority: audit imported docs for status/closeout language and
   rewrite or delete stale closeout claims.
8. Test signal authority: apply `docs/TEST_SIGNAL_POLICY.md` while touching
   tests, compress low-value coverage, and keep product/runtime signal primary.
9. Kernel/POSIX edge review: pick up remaining kmod/xfstests changes only as
   their own audited implementation commits.
