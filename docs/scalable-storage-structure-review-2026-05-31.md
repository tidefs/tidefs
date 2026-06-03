# Scalable Storage Structure Review

Initial issue: #6680
Current slice: #6715
Current branch: `codex/issue-6715-store-backed-rename-replace`
Current worktree: `/root/tidefs-worktrees/issue-6715-store-backed-rename-replace`
Started: 2026-05-31

## Operating State

- Nexus and the dashboard were verified inactive/disabled before this work.
- `/root/tidefs` is dirty with unrelated foreground xfstests/kernel work, so
  this review uses the dedicated worktree above.
- Foreground coordination is now explicit through `~/ai/bin/tidefs-claim`.
  The first #6680 coordination check reported #6680 and #6583 active with
  non-overlapping write sets.
- The coordination helper/docs checkpoint was published in `/root/ai` as
  `a5307a2` (`tidefs: restore foreground claim barrier`).
- The TideFS branch was pushed to Forgejo so other foreground Codex sessions can
  see the in-progress branch before implementation starts.
- #6680 landed on `master` as `c434c998` and closed. #6681 continues the same
  review in the current branch/worktree above.
- Before #6681 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6681 and #6583 claims with
  non-overlapping write sets. #6681 owns this doc plus
  `crates/tidefs-dir-index` and `crates/tidefs-local-filesystem`; #6583 owns
  only Nix/kernel xfstests paths.
- #6681 landed on `master` as `75104d067773` and closed. #6682 continues the
  FUSE-side cursor caller cleanup in the current branch/worktree above.
- #6682 landed on `master` as `90ac8d5cb445` and closed. #6683 continues the
  persistent directory page-reader cleanup in the current branch/worktree
  above.
- Before #6683 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6683 and #6583 claims with
  non-overlapping write sets. #6683 owns this doc plus
  `crates/tidefs-dir-index`; #6583 owns the unrelated kernel/Nix xfstests
  paths.
- #6683 landed on `master` as `62dec9f24319` and closed. #6684 continues the
  namespace persistent-import cleanup in the current branch/worktree above.
- Before #6684 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6684 and #6583 claims with
  non-overlapping write sets. #6684 owns this doc plus
  `crates/tidefs-namespace`; #6583 owns the unrelated kernel/Nix xfstests
  paths.
- #6684 landed on `master` as `14da2d01ff51` and closed. #6685 continues the
  kernel directory reader cleanup in the current branch/worktree above.
- Before #6685 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6583 with unrelated
  `~/ai/bin/tidefs-claim` with write set limited to this doc and
  `crates/tidefs-dir-index`.
- The #6685 branch was pushed before source edits so other foreground Codex
  sessions can see the claimed work.
- #6685 landed on `master` as `7c6157944086` and closed. #6686 continues the
  persistent inode-table read-window cleanup in the current branch/worktree
  above.
- Before #6686 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6583 with unrelated
  `~/ai/bin/tidefs-claim` with write set limited to this doc and
  `crates/tidefs-inode-table`.
- The #6686 branch was pushed before source edits so other foreground Codex
  sessions can see the claimed work.
- #6686 landed on `master` as `ec9ac6486649` and closed. #6687 continues the
  extent-map lookup/read-path cleanup in the current branch/worktree above.
- Before #6687 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6687 and #6583 with
  non-overlapping write sets. #6687 owns this doc plus `crates/tidefs-btree`
  paths.
- The #6687 branch was pushed before source edits so other foreground Codex
  sessions can see the claimed work.
- #6687 landed on `master` as `c10e7bd794ba` and closed. #6688 continues the
  extent-map read-query cleanup in the current branch/worktree above.
- Before #6688 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6583 with unrelated
  `~/ai/bin/tidefs-claim` with write set limited to this doc and
  `crates/tidefs-extent-map`.
- The #6688 branch was pushed before source edits so other foreground Codex
  sessions can see the claimed work.
- #6688 landed on `master` as `bfd9244537d1` and closed. #6689 continues the
  V3 extent-map read-query cleanup in the current branch/worktree above.
- Before #6689 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6689 and #6583 with
  non-overlapping write sets. #6689 owns this doc plus
  paths.
- The #6689 branch was pushed before source edits so other foreground Codex
  sessions can see the claimed work.
- #6689 landed on `master` as `f1acbd09` and closed. #6690 continues the V3
  above.
- Before #6690 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6583 with unrelated
  `~/ai/bin/tidefs-claim` with write set limited to this doc and
  `crates/tidefs-extent-map`.
- The #6690 branch was pushed before source edits so other foreground Codex
  sessions can see the claimed work.
- #6690 landed on `master` as `635b1588` and closed. #6691 continues the V3
  extent-map deserialize/import cleanup in the current branch/worktree above.
- Before #6691 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6583 with unrelated
  `~/ai/bin/tidefs-claim` with write set limited to this doc,
  `crates/tidefs-extent-map`, and `crates/tidefs-btree`.
- The #6691 branch was pushed before source edits so other foreground Codex
  sessions can see the claimed work.
- #6691 landed on `master` as `0926713a` and closed. #6692 continues the V3
  above.
- Before #6692 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6583 with unrelated
  branches for #6685 and #6687-#6690 were pruned after verifying they were
  clean ancestors of `origin/master`, leaving the active foreground map less
  ambiguous for future sessions.
- #6692 was filed and claimed through `~/ai/bin/tidefs-claim` with write set
  limited to this doc and `crates/tidefs-extent-map`.
- The #6692 branch was pushed before source edits so other foreground Codex
  sessions can see the claimed work.
- #6692 landed on `master` as `f1eb2073` and closed. #6693 continues the V3
  above.
- Before #6693 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6583 with unrelated
  #6685-#6692 were gone locally/remotely and their issue worktrees were pruned
  where they were clean ancestors of `origin/master`.
- #6693 was filed and claimed through `~/ai/bin/tidefs-claim` with write set
  limited to this doc and `crates/tidefs-extent-map`.
- The #6693 branch was pushed before source edits so other foreground Codex
  sessions can see the claimed work.
- #6693 landed on `master` as `1bc45d38` and closed. #6694 continues the V3
  above.
- Before #6694 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported only active #6583 with unrelated
  through `~/ai/bin/tidefs-claim` with write set limited to this doc and
  `crates/tidefs-extent-map`.
- The #6694 branch was pushed before source edits so other foreground Codex
  sessions can see the claimed work.
- #6694 landed on `master` as `aaddfdc0` and closed. Another foreground Codex
  then landed #6583 as `0827d69e`; #6695 continues from that current
  `origin/master` in the branch/worktree above.
- Before #6695 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported no active claimed/review issues.
  #6695 was filed and claimed through `~/ai/bin/tidefs-claim` with write set
  limited to this doc and `crates/tidefs-extent-map`.
- The #6695 branch was pushed before source edits so other foreground Codex
  sessions can see the claimed work.
- #6695 landed on `master` as `739dcc3f` and closed. #6696 continued the V3
  extent-map insert cleanup.
- #6696 landed on `master` as `d660d946` and closed. #6697 continued the V2
  extent-map insert cleanup.
- #6697 landed on `master` as `78679463` and closed. #6698 continues the V2
  extent-map truncate cleanup in the current branch/worktree above.
- Before #6698 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6698 and #6585 with
  non-overlapping write sets. #6698 owns this doc plus
  paths.
- The #6698 branch was pushed before source edits so other foreground Codex
  sessions can see the claimed work.
- #6698 landed on `master` as `0a65059e` and closed. #6699 continues the V2
  extent-map punch-hole cleanup in the current branch/worktree above.
- Before #6699 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6699 and #6585 with
  non-overlapping write sets. #6699 owns this doc plus
- The #6699 branch was pushed before source edits so other foreground Codex
  sessions can see the claimed work.
  documentation continuation and closed. #6700 continues the V2 extent-map
  collapse-range cleanup in the current branch/worktree above.
- Before #6700 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6700 and #6585 with
  non-overlapping write sets. #6700 owns this doc plus
- The #6700 branch was pushed before source edits so other foreground Codex
  sessions can see the claimed work.
  documentation continuation and closed. #6701 continues the V2 extent-map
  unwritten-conversion cleanup in the current branch/worktree above.
- Before #6701 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6701 and #6585 with
  non-overlapping write sets. #6701 owns this doc plus
- The #6701 branch was pushed before source edits so other foreground Codex
  sessions can see the claimed work.
- #6701 landed on `master` as `eac62660`.
  documentation continuation and closed. #6702 continues the polymorphic
  extent-map switch-policy cleanup in the current branch/worktree above.
- Before #6702 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6702 and #6585 with
  non-overlapping write sets. #6702 owns this doc plus
- The #6702 branch was pushed before source edits so other foreground Codex
  sessions can see the claimed work.
- #6702 landed on `master` as `45e065c8`.
- Before #6704 continuation, Nexus/dashboard were again verified
  inactive/disabled. `~/ai/bin/tidefs-claim status` reported active #6704 and
  #6585 with non-overlapping write sets. #6704 owns this doc plus
- The #6704 branch was pushed before source edits so other foreground Codex
  sessions can see the claimed work.
- #6704 source fix landed on `master` as `5ca6ee69`; this continuation records the
  documentation continuation and closed. #6705 continues the V2 deserialize/import
- Before #6705 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6705 and #6585 with
  non-overlapping write sets. #6705 owns this doc plus `crates/tidefs-btree`
  and `crates/tidefs-extent-map`; #6585 owns unrelated
- The #6705 branch was pushed before source edits so other foreground Codex
  sessions can see the claimed work.
  closeout.
  documentation continuation and closed. #6706 continues the polymorphic
  branch/worktree above.
- Before #6706 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6706 and #6585 with
  non-overlapping write sets. #6706 owns this doc plus
  `crates/tidefs-extent-map` and optional `crates/tidefs-btree`; #6585 owns
- The #6706 branch was pushed before source edits so other foreground Codex
  sessions can see the claimed work.
  documentation continuation and closed. #6707 continues the kernel root-dir
  full-snapshot reader API cleanup in the current branch/worktree above.
- Before #6707 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6707 and #6585 with
  non-overlapping write sets. #6707 owns this doc plus
  `crates/tidefs-dir-index/src/kernel_reader.rs`; #6585 owns unrelated
- The #6707 branch was pushed before source edits so other foreground Codex
  sessions can see the claimed work.
  documentation continuation and closed. #6708 continues the namespace persistent
  above.
- Before #6708 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6708 and #6585 with
  non-overlapping write sets. #6708 owns this doc plus
  `crates/tidefs-namespace` and `crates/tidefs-dir-index`; #6585 owns
- The #6708 branch `codex/issue-6708-bound-namespace-import-retention` was
  pushed before source edits so other foreground Codex sessions can see the
  claimed work.
  documentation and closed. #6709 continues the remaining production-visible
  dir-index full-snapshot API cleanup in the current branch/worktree above.
- Before #6709 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6709 and #6585 with
  non-overlapping write sets. #6709 owns this doc plus
- The #6709 branch `codex/issue-6709-dir-index-snapshot-apis` was pushed
  before source edits so other foreground Codex sessions can see the claimed
  work.
  documentation and closed. #6710 continues the namespace persistent
  above.
- Before #6710 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6710 and #6585 with
  non-overlapping write sets. #6710 owns this doc plus
  `crates/tidefs-dir-index` and `crates/tidefs-namespace`; #6585 owns
- The #6710 branch `codex/issue-6710-store-backed-namespace-lookup` was pushed
  before source edits so other foreground Codex sessions can see the claimed
  work.
  closed. #6711, #6712, and #6713 continue the same persistent namespace
  closed.
  closed.
- Before #6713 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6713 and #6585 with
  non-overlapping write sets. #6713 owns this doc plus
  `crates/tidefs-namespace/src/lib.rs`; #6585 owns unrelated
- The #6713 branch `codex/issue-6713-lazy-root-namespace` was pushed before
  source edits, and the first source/test checkpoint `d91ccdd0` was pushed
  documentation and closed. #6714 continues the persistent namespace
  branch/worktree above.
- Before #6714 edits, Nexus/dashboard were again verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6714 and #6585 with
  non-overlapping write sets. #6714 owns this doc plus
  `crates/tidefs-namespace/src/lib.rs`; #6585 owns unrelated
- The #6714 branch `codex/issue-6714-store-backed-rename-cycle` was pushed
  before source edits, and the source checkpoint `4a3e7338` was pushed after
  documentation. #6715 continues the persistent namespace replacement-target
- Before #6715 edits, Nexus/dashboard were verified inactive/disabled.
  `~/ai/bin/tidefs-claim status` reported active #6715 and #6585 with
  non-overlapping write sets. #6715 owns this doc plus
  `crates/tidefs-dir-index` and `crates/tidefs-namespace/src/lib.rs`; #6585

## Objective

Review TideFS data structures and storage-management behavior against the
OpenZFS/Ceph-class ambition, then fix concrete gaps. The review standard is:

- Metadata structures must scale by working-set and changed-set, not by loading
  all directories, inodes, extents, datasets, locators, or pool state into RAM.
- Reallocation, defrag, rebuild, device removal, and tier movement must be
  incremental, crash-safe, and budgeted.
- TideFS may compare with ZFS/Ceph to avoid their failure modes, but product
  vocabulary and APIs must remain TideFS-native.


| --- | --- | --- |
| Memory budget | `docs/UNIFIED_RESOURCE_GOVERNOR_DESIGN.md` defines one budget authority, cache categories, eviction, and backpressure. | Which source paths bypass the governor or keep unbounded metadata maps alive? |
| Extent maps | `docs/POLYMORPHIC_EXTENT_MAPS_DESIGN.md` defines V1 inline, V2 B-tree, and V3 multi-level B-tree promotion. | Does current source actually avoid O(all extents) mutation for large V2/V3 maps? |
| Directory index | `docs/POLYMORPHIC_DIRECTORY_INDEX_DESIGN.md` and `crates/tidefs-dir-index` advertise micro-list/B-tree behavior. | Are large directory iteration and lookup page/budget bounded, including kernel readers? |
| Inode table | `crates/tidefs-inode-table` has persistent and kernel-reader modules. | Does open/import require all inode records in memory, or is there a paged reader path? |
| Reallocation | `docs/ONLINE_DEFRAG_BPR_DESIGN.md` uses extent-id indirection and locator swaps. | Is relocation/defrag fed by real live ranges and persistent cursors in current source? |
| Pool/device geometry | `docs/design/variable-device-sector-alignment.md` and pool import/export docs define label/device metadata. | Do add/remove/replace flows stream topology/placement state or synthesize whole-pool views? |
| Dataset catalog | `crates/tidefs-dataset-catalog` and lifecycle docs define stable dataset records. | Are mount/import paths bound to stable dataset IDs without loading every dataset? |

## Current Findings

### F-001: Foreground Coordination Was Underspecified

Status: mitigated before source review.

The docs still described foreground Codex as if only one live issue existed at
a time, while live Forgejo already had #6583 and #6680 active. `~/ai/bin/tidefs-claim`
had also disappeared from disk even though docs still required it. This was a
coordination hazard for future multiple foreground sessions.

Mitigation:

- Restored `~/ai/bin/tidefs-claim` as a service-free Forgejo claim barrier.
- Added `claim` and `adopt` modes. `adopt` records branch/worktree/write-set for
  already-active manual foreground issues such as #6680.
- Updated `/root/ai/docs/projects/tidefs/README.md` and
  `/root/ai/docs/projects/tidefs/workflows/branch-sync-and-integration.md`.
- Published `/root/ai` commit `a5307a2`.

### F-002: Review Must Distinguish Design Prose From Source Behavior

Status: open.

Several designs already state the desired scalable model: resource-governed
caches, polymorphic extent maps, B-tree directory indexes, persistent reclaim
queues, and locator-swap relocation. The first implementation pass must verify
current source behavior and should prefer fixing a real code path over adding
more aspirational design text.

### F-003: BTree Directory `range_scan` Materialized the Whole Directory

Status: fixed in this branch.

`DirIndex::range_scan(start_name, max_entries)` promised bounded readdir-style
pagination, but the BTree path called `self.list()`, which cloned every live
entry and sorted the full directory before returning the requested page. That
made the memory and CPU cost proportional to the full directory size even when
callers requested a small batch.

Fix:

- Added a secondary in-memory name-ordered map for BTree directories. The
  existing hash-keyed BTree remains the lookup/collision-bucket authority; the
  name map exists only to serve sorted `list`, `list_from`, and `range_scan`
  without a collect-and-sort step.
- Kept the side index synchronized on promotion, insert, delete, demotion, and
  test-only forced-hash collision helpers.
- Reworked BTree `range_scan` to seek by full name and collect only
  `max_entries`.
- Added a collision-bucket regression test proving the name index follows
  forced hash collisions through delete and reinsert.

Remaining gap: `DirCursor::new` and the page-store `DirPageIndex::load` path
still have all-entry snapshot or all-page load behavior. They are now recorded
as successor review items rather than hidden behind the already-fixed
`range_scan` claim.

### F-004: BTree `DirIterator::next_entry` Rebuilt a Full Sorted Snapshot Per Entry

Status: fixed in this branch.

After F-003, the mutable `DirIterator` implementation still called
`self.list()` for every `next_entry` call. For BTree directories this meant
each single-entry iteration step cloned the whole directory through the sorted
list path. The iterator now uses the name-ordered map to fetch one BTree entry
at the current cursor index. Micro-list directories keep the older list path
because they are intentionally small.

Remaining caveat: BTree cursor seeking is still by ordinal index, so a late
cursor has to skip earlier map entries. That avoids full-directory allocation
but is not yet the final O(log n + batch) seekdir shape; stable name/hash
cookies or counted tree nodes remain continuation work.

### F-005: VFS Readdir Used a Full Cursor Snapshot Before Returning a 128-Entry Batch

Status: fixed in #6681.

`VfsLocalFileSystem::readdir` limited each reply to 128 entries, but it first
constructed `DirCursor::new(&dir_index, offset)`. That constructor verifies and
materializes every cursor entry at or after the requested offset, so a large
directory still paid for an unbounded cursor allocation before the caller took
one batch.

Fix:

- Added `DirCursor::new_window(idx, start_offset, max_entries)`, which preserves
  the existing offset convention (`.` at 0, `..` at 1, real entries from 2) and
  returns `(cursor, has_more)`.
- Added `DirIndex::entries_from_sorted_index(start, max_entries)` so BTree
  windows can use the name-ordered map from F-003 instead of building a full
  sorted vector.
- Rewired `VfsLocalFileSystem::readdir` to construct only the 128-entry cursor
  window it intends to return.
- Added cursor-window unit coverage and a local-filesystem readdir regression
  that proves a 140-entry directory returns a 128-entry first batch and a
  continuation batch with the expected cookies.

matched current API shapes (`ChangedRecordExport::placement_epoch` and
`DatasetCatalog::create(..., SyncGuarantee)`). They were updated mechanically so
the focused local-filesystem readdir test can compile and run.

Remaining caveats:

- `DirCursor::new` still exists for compatibility and remains a full snapshot
  constructor. Known successor callers included non-local-filesystem adapter
  paths such as FUSE-side readers before #6682.
- `VfsLocalFileSystem::readdir` still obtains all namespace entries through
  `fs.list_dir_by_inode` before building the bounded cursor. #6681 bounds the
  cursor/reply layer; it does not yet make the local-filesystem directory page
  source itself streaming.
- `DirCursor::new_window` still calls `verify_checksums()` for the index before
  windowing. That preserves current corruption checking but is not yet a
  page-local checksum strategy for extremely large on-disk directories.
- `DirPageIndex::load` and `KernelRootDirReader::new` remain in the next source
  audit because page-reader behavior may still load too much state.

### F-006: FUSE `drive_readdir_from_cursor` Used the Legacy Full Cursor

Status: fixed in #6682.

`crates/tidefs-fuser/src/readdir.rs` still used `DirCursor::new` after #6681.
That meant the FUSE helper could allocate a full sorted cursor snapshot before
packing one FUSE reply, even though the local-filesystem VFS caller had moved
to bounded cursor windows.

Fix:

- Added a 128-entry internal cursor window loop to
  `drive_readdir_from_cursor`.
- The helper now calls `DirCursor::new_window` repeatedly until the FUSE reply
  buffer fills or the directory is exhausted.
- The loop advances by the last emitted offset plus one between internal
  windows so one FUSE reply can cross a cursor-window boundary without
  duplicating entries or returning a premature short reply.
- Added a regression test that drives a 140-entry directory into a large reply
  and verifies entries beyond the first 128-entry internal window are present.

Remaining caveats:

- This fixes the FUSE helper allocation shape, not the persistent page source.
- `DirCursor::new_window` still verifies the whole index before returning each
  window.
- Persistent page-load paths (`DirPageIndex::load`,
  `DirPageIndex::load_with_replicas`, `PersistentDirIndex::load`) and
  `KernelRootDirReader::new` still assemble full in-memory page/entry sets.

### F-007: Persistent Directory Page Readers Still Exposed Full-Clone Paths

Status: fixed in #6683 for bounded windows and store-backed read-only helpers.

`PersistentDirIndex::list_from` returned at most 128 entries, but it first
called `DirPageIndex::list()`, cloning every live sorted entry before applying
`skip(...).take(128)`. That violated the review rule that a small output window
must not allocate proportional to the whole directory.

Fix:

- Added `DirPageIndex::entries_from_sorted_index(start, max_entries)` for
  already-loaded indexes, and rewired `PersistentDirIndex::list_from` to clone
  only the requested 128-entry window.
- Added `DirPageIndex::lookup_in_store(store, dir_ino, name)` for read-only
  lookup directly from persisted pages. It scans page payloads and returns as
  soon as the requested live entry is found, without constructing a full
  `DirPageIndex`.
- Added `DirPageIndex::range_scan_in_store(store, dir_ino, start_name,
  max_entries)` for read-only sorted windows directly from persisted pages. It
  scans page payloads sequentially but keeps only the requested sorted candidate
  window in memory.
- Shared page decoding through `dir_page_from_payload` so the new read-only
  helpers and existing load paths preserve the same invalid-page behavior.
- Added focused tests covering store-backed lookup across multiple persisted
  pages, store-backed sorted range windows where smaller names live on a later
  page, tombstone filtering, and `PersistentDirIndex::list_from` after a large
  skip.

Remaining caveats:

- `DirPageIndex::load`, `DirPageIndex::load_with_replicas`, and
  `PersistentDirIndex::load` still assemble the full page set and sorted entry
  index for callers that need a mutable loaded directory. Future read-only
  call sites should use the store-backed helpers instead of loading first.
- `PersistentDirIndex::lookup` still requires a loaded index. The new direct
  persisted-page lookup currently lives on `DirPageIndex`; exposing a
  higher-level persistent adapter should be a small continuation once callers are
  identified.
- `KernelRootDirReader::new` still reads all kernel directory pages and builds
  a name-sorted `Vec<KernelDirEntry>` before lookup/readdir. That remains a
  kernel-reader scalability gap.
- `Namespace::load` still loads every persistent directory into memory and
  then reads only the first `list_from(START)` window while rebuilding the
  fallback inode table. That is both a scalability gap and a correctness
  review item for directories with more than 128 entries. It is outside #6683's
  claimed write set and should be handled in a separate namespace slice.

### F-008: Namespace Persistent Load Stopped After One Directory Window

Status: fixed in #6684 for persistent directory pagination and loaded inode
attribute reconstruction.

`Namespace::load` loaded each persisted directory and then rebuilt fallback
inode attributes from `dir.list_from(DirCookie::START).0`. After #6683,
`PersistentDirIndex::list_from` intentionally returns one bounded 128-entry
window, so namespace import silently ignored directory entries beyond that
first window while rebuilding the fallback inode table. Source inspection also
found that import used `MemInodeTable::alloc(attrs)`, which assigns a new bump
inode instead of recording the persisted `entry.inode_id`.

Fix:

- Added a persistent-load helper on `MemInodeTable` that records loaded
  attributes at their persisted inode number and advances the bump allocator
  past that inode.
- Reworked `Namespace::load` to seed root attrs directly and iterate
  `PersistentDirIndex::list_from(cookie)` until the directory is exhausted,
  rebuilding fallback inode attributes from every returned window.
- Added a regression test that creates 200 persistent root entries, flushes and
  reloads the namespace, then verifies a file beyond the first 128-entry
  window still has lookup and `get_attrs` coverage after reload.

Remaining caveats:

- `Namespace::load` still calls `PersistentDirIndex::load` for every directory
  in the manifest, so it still assembles full mutable directory indexes during
  import. #6684 fixes the one-window correctness bug, not the final streaming
  namespace-import shape.
- Reconstructed fallback attrs remain minimal kind-derived attrs. Durable file
  size, ownership, timestamps, symlink target length, and link-count authority
  still belong in a persistent inode/metadata source rather than directory
  entries alone.
- `KernelRootDirReader::new` still reads all kernel directory pages and builds
  a name-sorted `Vec<KernelDirEntry>` before lookup/readdir.

### F-009: Kernel Directory Reader Required Full Entry Vector For Lookup/Readdir

Status: fixed in #6685 for direct read-only kernel-storage helpers.

`KernelRootDirReader::new` remains a compatibility constructor that reads every
directory page and builds one name-sorted `Vec<KernelDirEntry>`. Kernel lookup
or a small readdir window therefore had to allocate proportional to the whole
directory before answering even when the target entry was on the first page or
the caller requested only a small batch.

Fix:

- Added `KernelRootDirReader::lookup_in_storage`, which scans `KernelStorageIo`
  pages and returns as soon as a live matching entry is found.
- Added `KernelRootDirReader::readdir_in_storage`, which scans pages while
  retaining only `max_entries + 1` sorted candidates. This preserves the
  existing name-sorted readdir/next-cookie behavior without constructing the
  full reader vector.
- Shared page scanning with the compatibility constructor so page decoding,
  tombstone filtering, and error handling stay aligned.
- Added focused kernel-feature tests proving direct lookup stops before later
  pages and direct readdir returns sorted windows when physical page order and
  name order differ.

Remaining caveats:

- Mounted-kernel callers still need to be audited and rewired to the direct
- `KernelRootDirReader::new`, `all_entries`, and compatibility callers still
  expose full-load behavior by design.
- Direct readdir still scans page payloads to find a sorted window; it bounds
  directory B-tree root would be needed for O(log n + batch) kernel readdir.

### F-010: Persistent Inode Table Had No Direct Bounded Read Path

Status: fixed in #6686 for read-only persistent lookup/window helpers.

`InodeTable::open` remains a mutable compatibility constructor that calls
`persist::load_all_inodes` and allocates a `Vec<Option<InodeEntry>>` through
`header.next_free_cursor`. That means a caller that only needs one persisted
inode, or a small scan window, previously had to hydrate every persisted slot
between inode 1 and the cursor. `InodeTable::iter` also returns a full snapshot
vector of live inodes.

Fix:

- Added a shared direct inode-record loader in `persist.rs`, preserving the
  existing named-object encoding and xattr sidecar handling without constructing
  the slot vector.
- Added `InodeTable::lookup_persisted(store, ino)` for single-inode read-only
  lookup from `LocalObjectStore`.
- Added `InodeTable::persisted_window(store, start_ino, max_entries)`, which
  scans from a caller-supplied inode cursor, skips missing/deleted records, and
  retains at most the requested live entries plus a resume cursor.
- Added focused tests that seed sparse/high inode numbers directly in the
  object store, verify direct lookup at inode `1_000_000`, preserve xattrs,
  skip missing/deleted slots, and bound the returned live window.

Remaining caveats:

- `InodeTable::open` and `persist::load_all_inodes` still intentionally build a
  full mutable table for callers that need in-memory mutation. Callers that only
  need read-only probes should use the direct helpers instead of opening.
- `InodeTable::iter` still materializes all live entries into a vector.
  not total object lookups. A future persistent inode B-tree or page index is
  still needed for O(log n + batch) sparse namespace walks.

### F-011: V2 Extent Lookup Scanned From Zero For Late Ranges

Status: fixed in #6687 for V2 read lookups.

`BTreeExtentMap::lookup_range(offset, length)` used
`BPlusTree::range_from_to(&0, &end)` and then filtered by
`end_offset() > offset`. For a small late read in a heavily fragmented file,
that cloned every extent with a logical offset below the query end, including
all earlier non-overlapping extents. The design doc claims V2 lookup is
O(log n) B-tree traversal, but source behavior was O(all preceding extents) in

Fix:

- Added `BPlusTree::floor_entry(key)` as an O(log n) predecessor seek returning
  references, so callers can find the one extent that starts before a query
  offset without collecting earlier entries.
- Reworked V2 `lookup_range` to check only that predecessor for a left-edge
  overlap, then iterate `range_scan(offset..end)` lazily for extents whose
  keys start inside the query window.
- Kept result clipping behavior unchanged and avoided duplicating exact-offset
  extents by using the predecessor only when it starts before `offset`.
- Added B-tree predecessor tests across empty, leaf, and multi-level trees plus
  extent-map regressions for predecessor-spanning and late fragmented windows.

Remaining caveats:

- V2 mutation operations still call `collect_all()` and rebuild the whole
  B-tree. That known O(n) mutation baseline remains the next extent-map source
  audit target.
- `PolymorphicExtentMap::collect_all_btree` intentionally asks
  `lookup_range(0, u64::MAX)` for whole-map export/promotion. This fix bounds
  ordinary small lookups, not explicit full-map collection.
- V3 promotion/migration and multi-level mutation behavior were not audited in
  #6687.

### F-012: V2 Seek And FIEMAP Queries Collected The Whole Extent Map

Status: fixed in #6688 for V2 read-only seek/FIEMAP queries.

After #6687, V2 `lookup_range` was bounded by a predecessor seek and lazy range
scan, but `BTreeExtentMap::seek_data`, `seek_hole`, and `fiemap` still called
`collect_all()`. A late `SEEK_DATA`, `SEEK_HOLE`, or small FIEMAP request in a
heavily fragmented file therefore still cloned every V2 extent even when the
answer depended only on the local predecessor, the next extent, and the query
window.

Fix:

- Reused `BPlusTree::floor_entry` to account for the one extent that starts
  before the query offset.
- Reworked `seek_data` and `seek_hole` to scan from `offset` forward with
  `range_scan(offset..)`, preserving UNWRITTEN-as-data and explicit/implicit
  hole behavior.
- Reworked `fiemap` to process the predecessor overlap plus
  `range_scan(offset..end)`, preserving gap records, clipping, locator/flag
  mapping, overflow rejection, and `FLAG_LAST`.
- Added regressions for late fragmented seek and FIEMAP windows that include a
  predecessor-spanning extent, an implicit gap, and the next extent.

Remaining caveats:

- V2 mutation operations still call `collect_all()` and rebuild the whole
  B-tree. This slice only bounds read-only seek/FIEMAP query paths.
  #6703.
- V3 multi-level seek/FIEMAP and mutation behavior remain unaudited in this
  scale-review pass.

### F-013: V3 Extent Read Queries Collected The Whole Extent Map

Status: fixed in #6689 for V3 read-only lookup, seek, and FIEMAP queries.

`MultiLevelBTreeExtentMap` is the huge-file extent representation, but its
read-query methods still called `collect_all()`. A small late `lookup_range`,
`SEEK_DATA`, `SEEK_HOLE`, or FIEMAP request therefore cloned every V3 extent
before answering, exactly the failure mode the V3 structure is meant to avoid.
Source review also found that V3 seek treated DATA and pending DATA as
seekable but missed UNWRITTEN, contradicting the tristate model where
UNWRITTEN consumes space, reports for `SEEK_DATA`, and is skipped by
`SEEK_HOLE`.

Fix:

- Reused `BPlusTree::floor_entry` so V3 query paths account for the one extent
  that begins before the requested offset.
- Reworked V3 `lookup_range` to clip only the predecessor overlap plus
  `range_scan(offset..end)` entries.
- Reworked V3 `seek_data` and `seek_hole` to scan lazily from `offset`, with
  UNWRITTEN handled as seekable data rather than as a hole.
- Reworked V3 `fiemap` to process the predecessor overlap plus
  `range_scan(offset..end)`, preserving gap records, clipping, locator/flag
  mapping, overflow rejection, and `FLAG_LAST`.
- Added V3 regressions for late fragmented lookup, late fragmented seek,
  late-window FIEMAP, and UNWRITTEN seek semantics.

Remaining caveats:

- V3 mutation operations still use full-map `collect_all()` rebuilds for
  several edits. That contradicts the file header's page-split mutation claim
  and remains a source audit target.
  still require complete traversal by design before #6690.
- Polymorphic promotion/demotion paths still collect full V2/V3 maps and have
  not yet been made incremental.


memory.

After #6689, V3 ordinary read queries were bounded, but
sortedness, overlap, header stats, and invariant fields. Serialization cloned
every V3 extent before writing page chunks, even though the on-wire format is
already page-oriented. For huge fragmented files, those read-only maintenance

Fix:

  previous entry's comparison fields plus counters for entry count and
  allocated bytes.
- Kept sortedness, overlap, adjacent-merge, file-size, locator, header-count,
  alloc-byte, page-count, tree-structure, and depth checks intact.
- Reworked V3 serialization to derive entry count from the tree length and
  write one checksummed page buffer at a time from `range_scan(..)`.
- Preserved the existing `VX33` wire format: header entry count, page count,
  per-page entry count, serialized entries, and BLAKE3 checksum over the count
  prefix plus entries.

Remaining caveats:

- V3 deserialization still reads all entries into a vector, then rebuilds via
  `insert_extent` before #6691; that remains a whole-map import path until the
  streaming deserialize fix lands.
- V3 mutation operations still collect/rebuild full maps through the current
  B+tree mutation architecture.
- Polymorphic export/promotion/demotion still explicitly asks for whole-map
  collection.

### F-015: V3 Deserialization Staged The Whole Extent Map Before Rebuild

memory.

`MultiLevelBTreeExtentMap::deserialize()` still allocated
`Vec::with_capacity(entry_count)` and pushed every decoded entry into it before
calling `insert_extent(&entries)`. That `insert_extent` route sorted the input,
collected existing entries, applied inserts, merged, and rebuilt, so import had
out-of-order wire page could be silently sorted instead of rejected as corrupt.

Fix:

- Added `BPlusTree::rebuild_compact_from_sorted_iter` and fallible
  `try_rebuild_compact_from_sorted_iter` so callers can bulk-load exactly
  `expected_len` sorted owned entries without staging a complete slice first.
- The new B+tree builder computes compact leaf/internal distribution from the
  declared length, consumes the iterator once, rejects unsorted keys and count
  mismatches, and leaves the previous tree unchanged on error.
- Reworked V3 checksummed-page deserialization to verify one serialized leaf
  page at a time, buffer at most that page's entries, and feed entries directly
  into the sorted B+tree bulk rebuild.
- Reworked legacy flat V3 deserialization to feed decoded entries directly into
  the same sorted bulk rebuild path.
- Preserved the existing `VX33` wire format and roundtrip behavior while
  adding corruption coverage for out-of-order checked pages and header/page
  entry-count mismatches.

Remaining caveats:

- The resulting `MultiLevelBTreeExtentMap` is still an in-memory tree; this fix
  removes the extra deserialize staging vector and duplicate import rebuild,
  not the larger page-backed metadata residency gap.
- V3 mutation operations still collect/rebuild full maps through the current
  B+tree mutation architecture.
- Polymorphic export/promotion/demotion still explicitly asks for whole-map
  collection.

### F-016: V3 Truncate Shrink Cloned The Whole Map Before Rebuild

Status: fixed in #6692 for the V3 truncate shrink input scan.

After #6691, V3 import no longer staged the complete map, but
`MultiLevelBTreeExtentMap::truncate(new_size)` still began by calling
input vector before building the output vector needed by the current rebuild
path. Even a late-tail truncate paid for a second complete snapshot of the
source map.

Fix:

  `range_scan(..new_size)` and freed tail entries from `range_scan(new_size..)`.
- Preserved predecessor trimming when `new_size` falls inside an extent, full
  tail removal when an extent starts at or after `new_size`, freed extent
  ordering, DATA/UNWRITTEN/HOLE extent type reporting, file-size updates, and
  rebuild/header accounting.
  frees later DATA and UNWRITTEN extents, checks header allocation accounting,

Remaining caveats:

  this removes the extra full input snapshot but does not deliver true
  page-split/range-delete mutation.
- Other V3 mutations (`insert_extent`, `punch_hole`, `collapse_range`, and
  `convert_unwritten_to_data`) still collect/rebuild full maps.
- Polymorphic export/promotion/demotion still explicitly asks for whole-map
  collection.

### F-017: V3 Unwritten Conversion Cloned The Whole Map To Find One Entry

Status: fixed in #6693 for the V3 `convert_unwritten_to_data` input scan.

After #6692, V3 truncate shrink no longer cloned the whole map before rebuild,
but `MultiLevelBTreeExtentMap::convert_unwritten_to_data` still called
`collect_all()` to find one containing UNWRITTEN extent. A small late
replacement entry list.

Fix:

- Reworked V3 unwritten conversion to locate the candidate with
  `floor_entry(offset)`, preserving the requirement that the requested range be
  wholly contained in one UNWRITTEN entry.
  and suffix entries from `range_scan(end..)`, while preserving prefix/data/
  suffix splitting, `NotFound` behavior, file-size updates, and header
  accounting.
- Added a fragmented late-entry regression that converts the middle of one
  late UNWRITTEN extent, preserves surrounding entries, keeps allocation bytes

Remaining caveats:

  entries; this removes the extra full input snapshot but not the larger
  page-backed range-replace gap.
- Other V3 mutations (`insert_extent`, `punch_hole`, and `collapse_range`)
  still collect/rebuild full maps before #6694.
- Polymorphic export/promotion/demotion still explicitly asks for whole-map
  collection.

### F-018: V3 Punch-Hole Cloned The Whole Map Before Rebuild

Status: fixed in #6694 for the V3 `punch_hole` input scan.

After #6693, V3 truncate and unwritten conversion no longer cloned the whole
map before constructing their replacement entry lists, but
`MultiLevelBTreeExtentMap::punch_hole` still began with `collect_all()`. A
vector before splitting one predecessor, removing any covered entries, and
retaining the suffix.

Fix:

  `range_scan(..offset)`, affected entries from `range_scan(offset..end)`, and
- Preserved predecessor prefix trimming, successor suffix trimming, fully
  removed middle entries, DATA/UNWRITTEN/HOLE freed extent reporting,
  zero-length rejection, file-size updates, rebuild/header accounting, and
- Added a fragmented late-punch regression that trims a predecessor DATA
  extent, removes later DATA and UNWRITTEN extents, trims the final DATA

Remaining caveats:

  this removes the extra full input snapshot but not the larger page-backed
  range-delete gap.
- Other V3 mutations (`insert_extent` and `collapse_range`) still collect or
  rebuild full maps through current helper paths before #6695.
- Polymorphic export/promotion/demotion still explicitly asks for whole-map
  collection.

### F-019: V3 Collapse-Range Cloned The Whole Map Before Rebuild

Status: fixed in #6695 for the V3 `collapse_range` input scan.

After #6694, V3 truncate, unwritten conversion, and punch-hole no longer
cloned the whole map before constructing their replacement entry lists, but
`MultiLevelBTreeExtentMap::collapse_range` still called `collect_all()` before
feeding `collapse_entries`. A small late collapse in a huge fragmented file
the suffix left.

Fix:

  `range_scan(..offset)`, affected entries from `range_scan(offset..end)`, and
  shifted suffix entries from `range_scan(end..)`.
- Preserved zero-length no-op, overflow rejection, `end > file_size` rejection
  before mutation, predecessor prefix trimming, overlapped suffix trimming,
  DATA/UNWRITTEN/HOLE freed extent reporting, suffix shift-left semantics,
- Added a fragmented late-collapse regression that trims a predecessor DATA
  extent, removes later DATA and UNWRITTEN extents, trims the final DATA

Remaining caveats:

  shifted entries; this removes the extra full input snapshot but not the
  larger page-backed range-delete/shift gap.
- V3 `insert_extent` still collected the whole map before applying inserts
  until #6696.
- Polymorphic export/promotion/demotion still explicitly asks for whole-map
  collection.

### F-020: V3 Insert Cloned The Whole Map Before Rebuild

Status: fixed in #6696 for the V3 `insert_extent` input scan.

After #6695, V3 truncate, unwritten conversion, punch-hole, and
collapse-range no longer cloned the whole map before constructing their
replacement entry lists, but `MultiLevelBTreeExtentMap::insert_extent` still
called `collect_all()` before `apply_inserts`. A small late insert in a huge
overlapping existing entries, adding the new extent, merging adjacent entries,
and rebuilding the tree.

Fix:

  existing B+tree with `range_scan(..)` while subtracting the sorted
  non-overlapping insert ranges.
- Preserved zero-length rejection, overlapping batch rejection, overwrite and
  trim semantics, multi-entry batch behavior, adjacent merge behavior, header
- Added regressions for a fragmented late insert that trims predecessor and
  suffix entries, overwrites middle entries and gaps, merges adjacent
  same-locator fragments, and for a multi-entry batch replacing two ranges

Remaining caveats:

  entries; this removes the extra full input snapshot but not the larger
  page-backed range-replace gap.
- Polymorphic export/promotion/demotion still explicitly asks for whole-map
  collection.

### F-021: V2 Insert Cloned The Whole Map Before Rebuild

Status: fixed in #6697 for the V2 `insert_extent` input scan.

After #6696, direct V3 mutation input scans no longer cloned the whole map
before constructing replacement entry lists, but V2
`BTreeExtentMap::insert_extent` still called `collect_all()` before
a full input vector before trimming overlapping existing entries, adding the
new extent, merging adjacent entries, and rebuilding the tree.

Fix:

  existing B+tree with `range_scan(..)` while subtracting the sorted
  non-overlapping insert ranges.
- Preserved zero-length rejection, overlapping batch rejection, overwrite and
  trim semantics, multi-entry batch behavior, adjacent merge behavior, header
  accounting, and existing V2 rebuild behavior.
- Added regressions for a fragmented late insert that trims predecessor and
  suffix entries, overwrites middle entries and gaps, merges adjacent
  same-locator fragments, and for a multi-entry batch replacing two ranges

Remaining caveats:

  entries; this removes the extra full input snapshot but not the larger
  page-backed range-replace gap.
- Other V2 mutations still collect the whole map before rebuild.
- Polymorphic export/promotion/demotion still explicitly asks for whole-map
  collection.

### F-022: V2 Truncate Shrink Cloned The Whole Map Before Rebuild

Status: fixed in #6698 for the V2 `truncate` shrink input scan.

After #6697, V2 insert no longer cloned the whole map before rebuilding, but
`BTreeExtentMap::truncate(new_size)` still called `collect_all()` before
before trimming at the boundary, freeing the tail, and rebuilding the B+tree.

Fix:

  `range_scan(..new_size)` and freed tail entries from `range_scan(new_size..)`,
  avoiding the extra full input snapshot.
- Preserved truncate grow/no-op behavior, boundary trim semantics, DATA and
  UNWRITTEN freed extent reporting, header accounting, and existing V2 rebuild
  behavior.
- Added a fragmented late-tail regression that trims a DATA extent, frees later
  DATA and UNWRITTEN entries, checks allocation/file-size accounting, and

Remaining caveats:

  removes the extra full input snapshot but not the larger page-backed truncate
  gap.
- Other V2 mutations still collect the whole map before rebuild.
- Polymorphic export/promotion/demotion still explicitly asks for whole-map
  collection.

### F-023: V2 Punch-Hole Cloned The Whole Map Before Rebuild

Status: fixed in #6699 for the V2 `punch_hole` input scan.

After #6698, V2 insert and truncate shrink no longer cloned the whole map
before rebuilding, but `BTreeExtentMap::punch_hole` still called
`collect_all()` before splitting overlaps, reporting freed ranges, and
an extra full input vector before preserving the prefix, removing middle
entries, trimming the suffix, and updating file size.

Fix:

  `range_scan(..offset)`, affected entries from `range_scan(offset..end)`, and
- Preserved zero-length and overflow rejection, predecessor prefix trimming,
  successor suffix trimming, DATA/UNWRITTEN/HOLE freed extent reporting,
  punch-beyond-EOF file-size extension, rebuild/header accounting, and existing
- Added a fragmented late-punch regression that trims a predecessor DATA
  extent, removes later DATA and UNWRITTEN extents, trims the final DATA
  map.

Remaining caveats:

  removes the extra full input snapshot but not the larger page-backed
  range-delete gap.
- Other V2 mutations (`collapse_range` and `convert_unwritten_to_data`) still
  collect the whole map before rebuild.
- Polymorphic export/promotion/demotion still explicitly asks for whole-map
  collection.

### F-024: V2 Collapse-Range Cloned The Whole Map Before Rebuild

Status: fixed in #6700 for the V2 `collapse_range` input scan.

After #6699, V2 insert, truncate shrink, and punch-hole no longer cloned the
whole map before rebuilding, but `BTreeExtentMap::collapse_range` still called
`collect_all()` before feeding the flat list to `collapse_entries`. A late
before trimming the predecessor, reporting freed ranges, shifting the suffix
left, merging adjacent entries, and decrementing file size.

Fix:

  `range_scan(..offset)`, affected entries from `range_scan(offset..end)`, and
  shifted suffix entries from `range_scan(end..)`.
- Preserved zero-length no-op behavior, overflow and past-EOF rejection before
  mutation, predecessor prefix trimming, overlapped suffix trimming,
  DATA/UNWRITTEN/HOLE freed extent reporting, suffix shift-left semantics,
  behavior.
- Added a fragmented late-collapse regression that trims a predecessor DATA
  extent, removes later DATA and UNWRITTEN extents, trims the final DATA

Remaining caveats:

  shifted entries; this removes the extra full input snapshot but not the
  larger page-backed range-delete/shift gap.
- V2 `convert_unwritten_to_data` still collects the whole map before rebuild.
- Polymorphic export/promotion/demotion still explicitly asks for whole-map
  collection.

### F-025: V2 Unwritten Conversion Cloned The Whole Map Before Rebuild

Status: fixed in #6701 for the V2 `convert_unwritten_to_data` input scan.

After #6700, V2 insert, truncate shrink, punch-hole, and collapse-range no
longer cloned the whole map before rebuilding, but
`BTreeExtentMap::convert_unwritten_to_data` still called `collect_all()` before
finding the containing UNWRITTEN entry. A small late conversion in a fragmented
prefix, replacing the converted subrange with DATA, preserving the suffix, and
rebuilding the B+tree.

Fix:

- Reworked V2 unwritten conversion to locate the candidate with
  `floor_entry(offset)`, preserving the requirement that the requested range be
  wholly contained in one UNWRITTEN entry.
  suffix entries from `range_scan(end..)`, while preserving prefix/data/suffix
  splitting, `NotFound` behavior, file-size updates, and header accounting.
- Added a fragmented late-entry regression that converts the middle of one late
  UNWRITTEN extent, preserves surrounding entries, keeps allocation bytes

Remaining caveats:

  entries; this removes the extra full input snapshot but not the larger
  page-backed range-replace gap.
- Polymorphic export/promotion/demotion still explicitly asks for whole-map
  collection.

### F-026: Polymorphic No-Op Switch Checks Collected The Whole Active Map

Status: fixed in #6702 for stable V2/V3 no-op switch decisions.

After the direct V2 and V3 mutation input scans were bounded,
`PolymorphicExtentMap::check_and_switch()` still called `collect_entries()`
after every mutation. For stable BTree or MultiLevel maps whose entry count was
nowhere near a promotion or demotion boundary, that cloned the full active
extent map before deciding no representation switch could happen. This quietly
layer after otherwise bounded direct mutations.

Fix:

- Reworked `check_and_switch()` to consult cheap active-representation counters
  before collecting entries.
- Inline maps still collect directly because their entry list is inherently
  bounded.
- BTree maps collect only when they might demote to Inline or promote to V3.
- MultiLevel maps collect only when they might demote to BTree.
- Preserved the existing UNWRITTEN/HOLE demotion guards by collecting entries
  on the candidate demotion paths before switching.
- Added focused stable BTree and MultiLevel no-op switch tests.

Remaining caveats:

- Actual representation switches still need all entries to rebuild the target
  in-memory representation. This fix bounds the common no-switch wrapper path;
  it does not make promotion/demotion itself page-streamed.
- Explicit whole-map export and polymorphic serialization still traverse the
  active representation by design.

### F-027: V2 Serialization Cloned The Whole Extent Map Before Writing Pages


After #6701, direct V2 read queries and mutation input scans no longer cloned
the whole map before doing local work, but `BTreeExtentMap::serialize()` still
called `collect_all()` before handing entries to `serialize_to_pages()`. The
wire format was already page-oriented, so serializing a large fragmented V2 map
kept a full duplicate extent vector in memory before writing one page chunk at a
time.

Fix:

- Reworked V2 serialization to derive `page_count` from the B+tree length
  instead of a collected vector.
- Streamed `range_scan(..)` directly into one leaf-page buffer at a time and
  called `serialize_leaf_page` per page, retaining at most one serialized page's
  entries before writing.
- Preserved the existing `VX22` version-2 wire format: magic, version/flags,
  32-bit page count, 4096-byte leaf pages, and per-page BLAKE3 checksums.
- Added a fragmented multi-page V2 serde regression that checks serialized page
  deserialize.

Remaining caveats:

  after #6706.
- Explicit full-map defrag/export helper paths remain separate review targets.



After #6703, V2 serialization no longer cloned the whole map before writing
checking sortedness, overlap, adjacent-merge, file-size, locator, entry-count,
fragmented V2 map therefore kept a full duplicate extent vector even though the
B+tree already scans entries in key order.

Fix:

  previous entry's comparison fields plus entry-count and allocated-byte
  counters.
- Preserved wrong-version, zero-length, overflow, overlap, adjacent unmerged,
  file-size, locator, entry-count, alloc-byte, and B+tree structural checks.
  UNWRITTEN entries with locators, DATA entries without locators, and
  offset+length overflow.

Remaining caveats:

  after #6706.
- Explicit full-map defrag/export helper paths remain separate review targets.

### F-029: V2 Deserialization Staged Every Decoded Page Entry Before Rebuild


`BTreeExtentMap::deserialize_v2()` still decoded every VX22 leaf page into one
`all_entries` vector and then rebuilt the in-memory B+tree from that duplicate
flat list. A large fragmented V2 map therefore held the final B+tree plus a
full temporary copy during import.

Fix:

- Added `BPlusTree::try_rebuild_compact_from_sorted_unknown_len_iter()` for
  fallible sorted streams that do not know the exact entry count before
  decoding. It builds leaves from the owned stream, rebalances a short final
  leaf with its predecessor to preserve minimum-fill invariants, and returns
  the actual entry count.
- Reworked V2 deserialization to iterate VX22 pages through `V2PageEntries`,
  retaining only one decoded page plus the in-progress B+tree leaf nodes while
  computing header stats.
- Preserved the existing VX22 wire format and corruption behavior: page
  checksum/read errors propagate, key-order violations become corrupt input,
  file-size invariants.
- Added focused regressions for unknown-length B+tree rebuild success,
  unsorted input, source-error propagation, and V2 out-of-order page rejection.

Remaining caveats:

  after #6706.
- Explicit full-map defrag/export helper paths remain separate review targets.

### F-030: Polymorphic V2/V3 Switches Exported Full Maps Before Rebuild

memory.

checks, and direct mutation input scans were bounded, but representation changes
still cloned the entire active map. `PolymorphicExtentMap::check_and_switch()`
called `collect_entries()` before promoting V2 to V3 or demoting V3 to V2, then
rebuilt the destination by reinserting the full slice. A large fragmented file
destination tree during a tier switch.

Fix:

- Added crate-private ordered-entry streams on `BTreeExtentMap` and
  `MultiLevelBTreeExtentMap`.
- Added crate-private unknown-length sorted rebuild helpers for both V2 and V3.
  They feed owned entries directly into
  `BPlusTree::try_rebuild_compact_from_sorted_unknown_len_iter()` while
  computing actual entry count, allocated bytes, file size, depth, and V3 page
  counts.
- Reworked polymorphic V2->V3 promotion to stream from the V2 tree into a new
  V3 tree without staging a full `Vec`.
- Reworked polymorphic V3->V2 demotion to scan V3 entries for UNWRITTEN/hole
  blockers through the iterator, then stream entries into a new V2 tree without
  staging a full `Vec`.
- Kept Inline<->V2 transitions on the existing slice path because those are
  bounded by `PROMOTE_THRESHOLD` / `DEMOTE_THRESHOLD`.
- Added sparse fragmented-map regressions that force V2->V3 and V3->V2
  thresholds with artificial header counts, then verify the destination
  representation uses the actual streamed entry count, preserves file size, and

Remaining caveats:

- `PolymorphicExtentMap::defrag()` still intentionally materializes and merges a
  whole active entry list. That should become an incremental/background defrag
  issue rather than hiding under representation switching.
- `collect_entries()` remains as a bounded inline/test/defrag helper, so future
  production call sites must be audited before using it on V2/V3 maps.

### F-031: Kernel Root-Dir Full-Snapshot Reader Was Production-Visible

Status: fixed in #6707 for the public kernel root-dir reader API surface.

After #6685 added direct storage helpers, production read-only kernel paths
could answer lookup and readdir without retaining a complete sorted directory
snapshot. The older `KernelRootDirReader::new` constructor and snapshot
accessors still remained public in kernel builds, however, which left the
unbounded full-directory reader available to future mounted-kernel call sites
even though `lookup_in_storage` and `readdir_in_storage` cover the read-only
production contract.

Fix:

  snapshot/query accessors compile only under `cfg(test)`.
- Kept `KernelRootDirReader::lookup_in_storage` and
  `KernelRootDirReader::readdir_in_storage` available in kernel builds as the
  production storage-backed APIs.
- Updated the module documentation to state that the legacy full-snapshot
  reader is unit-test-only.
- Verified production greps found `KernelRootDirReader::new` and
  `all_entries` only in `kernel_reader.rs` unit tests before applying the gate.

Remaining caveats:

  kernel-feature checks prove the snapshot reader is no longer production
- Directory mutation/import paths outside `kernel_reader.rs` still need their
  own bounded-structure audits.


indexes.

After #6684, `Namespace::load` rebuilt fallback inode attributes through a
bounded `list_from` window, but it still called `PersistentDirIndex::load` for
directory indexes in `Namespace::dirs`. A namespace with many large directories
directory contents, even when startup only needed to seed inode metadata and
the active working set would touch a small subset.

Fix:

- Added `DirPageIndex::for_each_in_store` and
  `PersistentDirIndex::for_each_in_store`, which scan live persisted directory
  entries one decoded page at a time without building a mutable
  `DirPageIndex`.
- Reworked `Namespace::load` to stream every manifest directory through that
  scanner for fallback inode-table seeding while initially retaining only the
  root directory index.
- Recorded the manifest directory set and object-store root in the loaded
  namespace so directory operations can lazy-load a child directory's mutable
  `PersistentDirIndex` on first touch.
- Updated lookup, resolution, read_dir, create, unlink, link, mknod, and rename
  paths to ensure a persisted directory is loaded before operating on it.
- Added regressions proving import retains only the root index initially,
  lazy-loads only the touched child directory.

Remaining caveats:

- Lazy loading reopens the local object store read-only from its root path using
  default store options. That keeps the import API unchanged, but a future
  owned/read-handle directory store would make the dependency explicit and avoid
  reopen overhead.
- This bounds import retention, not every later namespace mutation working set:
  touched directories remain loaded and mutable until a future eviction/cache
  policy exists.

### F-033: Dir-Index Full-Snapshot Helper APIs Remained Production Visible

Status: fixed in #6709 for residual cursor and persistent snapshot helpers.

After #6681/#6682 moved production readdir callers to `DirCursor::new_window`,
the legacy `DirCursor::new` constructor still remained in the production API
even though repo grep found only `crates/tidefs-dir-index/src/cursor.rs` unit
tests using that exact API. The constructor verifies checksums and then calls
`idx.list()`, retaining a full sorted cursor snapshot before positioning at
the requested offset. `PersistentDirIndex::entry_snapshot` had the same API
shape for persistent directories: it called `self.inner.list()` and returned a
flat full-directory vector of entries and cookies, with no production caller
left in the tree.

Fix:

- Gated `DirCursor::new` behind `#[cfg(test)]` so production dir-index users
  must use `DirCursor::new_window`, which bounds cursor allocation by the
  caller's requested batch.
- Updated cursor module documentation to describe the bounded-window production
  path and identify the full-snapshot constructor as test-only legacy
  coverage.
- Gated `PersistentDirIndex::entry_snapshot` behind `#[cfg(test)]` and added a
  focused unit test covering its legacy sorted-cookie behavior.

Remaining caveats:

- `DirPageIndex::load`, `DirPageIndex::load_with_replicas`, and
  `PersistentDirIndex::load` still intentionally build full mutable directory
  indexes for callers that need mutation. The next dir-index audit should
  focus on reducing production use of those constructors where read-only
  store-backed helpers suffice.
- `DirCursor::new_window` still verifies the full in-memory `DirIndex` before
  returning a bounded window. That preserves current checksum semantics but is
  not yet a page-local verification model for very large on-disk directories.
- Repo-wide grep also finds `DirCursor::new` in `tidefs-kmod-posix-vfs`, but
  those hits are a distinct kernel VFS cursor type, not the dir-index full
  snapshot constructor gated here.

### F-034: Namespace Read-Only Lookup Loaded Cold Persistent Directories

Status: fixed in #6710 for lookup, path resolution, and symlink-entry
inspection.

child directories on first touch. Source inspection showed that read-only
lookup paths counted as a touch: `Namespace::lookup`, `resolve_component`, and
`readlink_at` all called `ensure_persistent_dir_loaded(parent)` before reading
one entry. Looking up a single name in a large persisted child directory
`PersistentDirIndex`.

Fix:

- Added `PersistentDirIndex::lookup_in_store`, a high-level adapter over
  `DirPageIndex::lookup_in_store` that returns `DirMicroEntry` without loading
  the mutable page index.
- Added a namespace lookup helper that checks already-loaded directories first
  and then probes persisted manifest directories through store-backed lookup.
- Rewired `resolve_component`, `Namespace::lookup`, and `readlink_at` through
  that read-only helper while leaving mutation and `read_dir` paths on the
  existing lazy mutable-load path.
- Extended the persistent namespace regression so lookup and full path
  resolution under an unloaded child directory keep the loaded-directory count
  unchanged; `read_dir` still demonstrates the explicit mutable load boundary
  for this slice.

Remaining caveats:

- At #6710 close, `Namespace::read_dir` still lazy-loaded the full mutable
  directory index before returning a positional-cookie page. This specific
  caveat is addressed by F-035/#6711 below.
- Mutations intentionally continue loading mutable directory indexes before
  changing entries. A future eviction/cache policy is still needed so mutated

### F-035: Namespace Read-Dir Loaded Cold Persistent Directories

Status: fixed in #6711 for unloaded manifest directories.

After #6710, `Namespace::read_dir` was the remaining read-only namespace path
that still called `ensure_persistent_dir_loaded(dir_inode)` before returning a
page of entries. Reading one page from a large persisted child directory
though the operation only needed a bounded directory page.

Fix:

- Added `PersistentDirIndex::list_from_store`, a high-level adapter over
  `DirPageIndex::range_scan_in_store` that preserves the current positional
  `DirCookie` contract while avoiding mutable index construction.
- The adapter advances through persisted name-sorted windows. Later positional
  requested read-dir window plus the final skip remainder, not by total
  directory size.
- Rewired `Namespace::read_dir` so loaded directories continue using the
  mutable index, while unloaded manifest directories are served directly from
  the object store.
- Extended the persistent namespace regression to prove lookup, path
  resolution, first-page read-dir, second-page read-dir, and exhaustion under a
  cold child directory keep the loaded-directory count unchanged.

Remaining caveats:

  Positional cookies over the current name-range scanner can rescan persisted
  pages to reach later offsets. A future persistent name/page cookie can remove
  that cost once the API contract is updated deliberately.
- Mutations still intentionally load mutable directory indexes before changing
  policy exists.

### F-036: Namespace Flush Dropped Unloaded Persistent Directories

Status: fixed in #6712 for lazy manifest preservation.

kept cold child directories unloaded, while lookup and read-dir could serve
those children from persisted pages. Source inspection found that
`Namespace::flush` still rebuilt the namespace manifest from
`self.dirs.keys()` only. A flush after lazy import could therefore rewrite the
manifest with just the currently loaded mutable directories and silently drop
unloaded persisted child directories from future imports.

Fix:

  manifest directory inodes and currently loaded mutable directory indexes.
- Kept page flushing scoped to loaded mutable indexes; unloaded directories are
  preserved in the manifest without forcing a full mutable load.
- Updated directory inode cleanup so removed directories are deleted from the
- Added persistent namespace regressions for flush-after-lazy-load preserving
  an unloaded child directory and for removed directories staying absent from
  the rewritten manifest.

Remaining caveats:

- This preserves manifest membership; it does not add a directory-index
  eviction policy for mutable directories that were loaded by mutation.


Status: fixed in #6713 for read-only persistent namespace import.

After #6711/#6712, unloaded child directories could serve lookup and read-dir
from persisted pages and flush could preserve their manifest membership, but
`Namespace::load` still special-cased root with `PersistentDirIndex::load`. A
at import, even when callers only needed root lookup or root read-dir pages.

Fix:

- Removed the persistent root full-load special case from `Namespace::load`.
- Required a persistent namespace manifest to contain `ROOT_INODE` and usable
  root directory pages; malformed manifests now fail instead of silently
  synthesizing a fixed root table as production authority.
  read-dir are served by the store-backed helpers while
  `loaded_dir_count_for_test` remains zero after read-only import.
- Preserved the mutation boundary: creating or otherwise mutating under root
  still lazy-loads the mutable root index through `ensure_persistent_dir_loaded`.
- Added regressions for root lookup/read-dir staying cold, mutation loading only
  root, and malformed manifests missing root or root pages being rejected.

Remaining caveats:

- Root and child mutations intentionally load mutable directory indexes and keep
  memory but can rescan persisted pages for later offsets.
- Import still scans every manifest directory one page at a time to seed fallback
  inode attributes; that avoids retaining directory indexes but is not yet a
  paged inode-attribute authority.

### F-038: Rename Cycle Parent-Chain Checks Loaded Cold Persistent Ancestors

Status: fixed in #6714 for rename cycle detection parent walks.

After #6713, read-only persistent import and root/child lookup could keep all
directory indexes cold until mutation. The rename cycle check was a leftover
read-only path inside a mutating operation: `directory_is_self_or_descendant`
called `ensure_persistent_dir_loaded(current)` for each ancestor while walking
`..` links. Moving a directory under a cold persisted sibling subtree therefore
rename only needed those ancestors' parent entries.

Fix:

- Rewired `directory_is_self_or_descendant` to read `..` through
  `lookup_dir_entry`, which already checks loaded mutable indexes first and then
  falls back to store-backed persisted-page lookup for unloaded manifest
  directories.
- Kept the explicit mutation boundary intact: rename still loads the source
  parent, destination parent, moved directory, and replaced directory when those
  mutable indexes are needed for the operation.
- Added a persistent namespace regression that imports with zero loaded
  directories, moves a root directory under a deep cold sibling subtree, and
  proves the cold ancestor chain is still served from persisted pages while only

Remaining caveats:

- Rename replacement-directory emptiness checks were still loading the cold
  target directory; that caveat is addressed by F-039/#6715.
- Store-backed parent walks still reopen the local object store through the
  reopen overhead.

### F-039: Rename Replacement Emptiness Checks Loaded Cold Target Directories

Status: fixed in #6715 for non-exchange rename replacement checks.

After #6714, rename cycle parent walks were store-backed, but the ordinary
rename/renameat replacement path still called `ensure_persistent_dir_loaded` on
an existing directory destination before planning whether the target was empty.
For cold persisted namespaces, replacing an empty directory or rejecting a
operation only needed to distinguish the standard `.`/`..` entries from real
children.

Fix:

- Added capped live-entry counting on persisted directory pages and surfaced it
  through `PersistentDirIndex::entry_count_in_store`.
- Rewired non-exchange rename target planning to use the capped store-backed
  count when the existing directory destination is cold.
- Preserved the mutation boundary: rename still loads the source parent,
  destination parent, moved directory, and exchange target directory when those
  mutable indexes are edited or their `..` entries may change.
- Added persistent namespace regressions for empty target replacement and
  non-empty target rejection. Both import with zero loaded directories and
  prove the target directory stays cold while the answer is derived from
  persisted pages.

Remaining caveats:

- The capped count scans persisted pages until it sees three live entries or
  checks but can still read multiple pages for a sparse/tombstoned directory.
- Store-backed read-only helpers still reopen the local object store through
  the existing namespace helper.

## Next Source Audit Order

1. `crates/tidefs-dir-index` and `crates/tidefs-namespace`: audit remaining
   production `PersistentDirIndex::load` callers that only need read-only
   access after #6715 removed the known rename replacement-directory emptiness
   case.
2. `crates/tidefs-extent-map`: full-map defrag/export helper paths now that
   deserialization, direct V2/V3 mutation input scans, no-op polymorphic switch
3. `crates/tidefs-inode-table`: mutable open/import behavior, `iter` snapshot
   use, and bounded inode cache assumptions beyond the new read-only helpers.
4. `crates/tidefs-local-object-store` plus locator/relocation crates:
   reallocation, defrag, and device removal live-range inputs.
5. `crates/tidefs-local-filesystem` and `crates/tidefs-reclaim`: live reclaim
   authority and any residual in-memory-only reclaim queues.


- `python3 -m py_compile /root/ai/bin/tidefs-claim`: pass.
- `git -C /root/ai diff --check`: pass before publishing `a5307a2`.
- `~/ai/bin/tidefs-claim status`: pass after #6680 adoption; reports both
  foreground claims and their non-overlapping write sets.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index range_scan_btree --locked`:
  pass, including the new collision-bucket name-index regression test.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index --locked`:
  pass, 373 package tests plus doc-tests; the existing 10k-entry unit test took
  139.48s and completed successfully.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index --test large_directory --test dir_iterator_smoke --locked`:
  pass after the `DirIterator::next_entry` fix.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6681 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6681 edits; reports active #6681
  and #6583 with non-overlapping write sets.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-local-filesystem --lib --locked`:
  pass, with the pre-existing `ContentCompressionPolicy` private-interface
  warning.
- `git diff --check`: pass after #6681 edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index window_ --locked`:
  pass, including the new bounded cursor-window unit tests.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index --test large_directory --test dir_iterator_smoke --locked`:
  pass after #6681 edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-local-filesystem readdir_large_directory_batches_at_cursor_window_limit --locked`:
  pass, with the pre-existing `ContentCompressionPolicy` private-interface
  warning.
- `~/ai/bin/tidefs-claim status`: pass before #6682 edits; reports active #6682
  and #6583 with non-overlapping write sets.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p fuser cursor_drive_large_dir_crosses_internal_cursor_windows --locked`:
  pass.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p fuser cursor_drive --locked`:
  pass.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6683 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6683 edits; reports active
  #6683 and #6583 with non-overlapping write sets.
- `cargo fmt -p tidefs-dir-index`: pass.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index --features persistent-dir-index --locked`:
  pass, 558 package tests plus doc-tests; the existing 10k-entry unit test
  completed successfully.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index --features persistent-dir-index --locked in_store`:
  pass after tightening the store-backed range helper to reject entries outside
  the bounded window before cloning names.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index --features persistent-dir-index --locked list_from_returns_bounded_window_after_large_skip`:
  pass after the same final refinement.
- `git diff --check`: pass after #6683 edits.
- conflict-marker scan over the touched files: no markers found.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6684 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6684 edits; reports active
  #6684 and #6583 with non-overlapping write sets.
- #6684 branch `codex/issue-6684-scale-namespace-load` was pushed before source
  edits so other foreground Codex sessions can see the claimed work.
- `cargo fmt -p tidefs-namespace`: pass.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --features persistent-dir-index --locked persistent_load_rebuilds_inode_attrs_past_first_directory_window`:
  pass.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --features persistent-dir-index --locked`:
  pass, 198 package tests plus doc-tests.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-namespace --locked`:
  pass for the default in-memory feature set.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --features persistent-dir-index --locked persistent_load_rebuilds_inode_attrs_past_first_directory_window`:
  pass after the final import-gating cleanup.
- `git diff --check`: pass after #6684 edits.
- conflict-marker scan over the touched files: no markers found.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6685 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6685 claim; reported active
  #6583 and ready #6685 with non-overlapping write sets.
- #6685 branch `codex/issue-6685-bound-dir-reader` was pushed before source
  edits so other foreground Codex sessions can see the claimed work.
- `cargo fmt -p tidefs-dir-index`: pass.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index --features kernel --locked direct_`:
  pass, including the new direct kernel lookup/readdir tests.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index --features kernel --locked`:
  pass, 209 package tests plus integration tests and doc-tests. The existing
  10k-entry serialization test completed successfully in 298.48s.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-dir-index --no-default-features --features kernel --locked`:
  pass.
- `git diff --check`: pass after #6685 edits.
- conflict-marker scan over the touched files: no markers found.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6686 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6686 claim; reported active
- #6686 branch `codex/issue-6686-bound-inode-read-windows` was pushed before
  source edits so other foreground Codex sessions can see the claimed work.
- `cargo fmt -p tidefs-inode-table`: pass.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-inode-table --locked persisted_`:
  pass, including the new direct persistent lookup/window tests.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-inode-table --locked`:
  pass, 138 package tests, 121 integration tests, and 2 doc-tests.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-inode-table --no-default-features --features kernel --locked`:
  pass.
- `git diff --check`: pass after #6686 edits.
- conflict-marker scan over the touched files: no markers found.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6687 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6687 edits; reports active
  #6687 and #6583 with non-overlapping write sets.
- #6687 branch `codex/issue-6687-bound-extent-lookup` was pushed before source
  edits so other foreground Codex sessions can see the claimed work.
- `cargo fmt -p tidefs-btree -p tidefs-extent-map`: pass.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-btree --locked floor_entry`:
  pass after adding the predecessor helper coverage.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked lookup_range`:
  pass, including the late fragmented lookup and predecessor-spanning
  regressions.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-btree --locked`:
  pass, 221 unit tests, 153 integration tests, 25 proptests, and doc-tests.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked`:
  pass, full package test suite.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-extent-map --no-default-features --features kernel --locked`:
  pass.
- `git diff --check`: pass after #6697 edits.
- anchored conflict-marker scan over the touched files: no markers found.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6690 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6690 claim; reported only
  before source edits so other foreground Codex sessions can see the claimed
  work.
- `rustfmt crates/tidefs-extent-map/src/multi_level.rs`: pass.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked multi_level::serde_tests`:
  pass, covering V3 serialization roundtrips, page-boundary cases, and
  checksum corruption rejection.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked`:
  pass, full package test suite.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-extent-map --no-default-features --features kernel --locked`:
  pass.
- `git diff --check`: pass after #6687 edits.
- conflict-marker scan over the touched files: no markers found.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6688 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6688 claim; reported only active
- #6688 branch `codex/issue-6688-bound-extent-seek-fiemap` was pushed before
  source edits so other foreground Codex sessions can see the claimed work.
- `rustfmt crates/tidefs-extent-map/src/btree.rs`: pass.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked seek_late_fragmented_window_uses_predecessor_and_bounded_scan`:
  pass.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked fiemap_late_window_includes_predecessor_gap_and_next_extent`:
  pass.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked`:
  pass, full package test suite.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-extent-map --no-default-features --features kernel --locked`:
  pass.
- `git diff --check`: pass after #6688 edits.
- conflict-marker scan over the touched files: no markers found.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6689 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6689 edits; reports active
  #6689 and #6583 with non-overlapping write sets.
- #6689 branch `codex/issue-6689-bound-v3-extent-reads` was pushed before
  source edits so other foreground Codex sessions can see the claimed work.
- `rustfmt crates/tidefs-extent-map/src/multi_level.rs`: pass.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked lookup_range_late_small_window_uses_predecessor_and_bounded_scan`:
  pass, including V2 and V3 late-window lookup regressions.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked seek_late_fragmented_window_uses_predecessor_and_bounded_scan`:
  pass, including V2 and V3 late-window seek regressions.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked fiemap_late_window_includes_predecessor_gap_and_next_extent`:
  pass, including V2 and V3 late-window FIEMAP regressions.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked seek_data_and_hole_treat_unwritten_as_data`:
  pass, covering V3 UNWRITTEN-as-data seek behavior.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked`:
  pass, full package test suite.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-extent-map --no-default-features --features kernel --locked`:
  pass.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6691 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6691 claim; reported only
- #6691 branch `codex/issue-6691-stream-v3-deserialize` was pushed before
  source edits so other foreground Codex sessions can see the claimed work.
- `rustfmt crates/tidefs-btree/src/lib.rs crates/tidefs-extent-map/src/multi_level.rs`:
  pass.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-btree rebuild_compact_from_sorted_iter --locked`:
  pass, covering the new sorted bulk rebuild API and fallible-source path.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked multi_level::serde_tests`:
  pass, covering V3 roundtrips plus out-of-order checked-page and count
  mismatch corruption rejection.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-btree --locked`:
  pass, full package suite: 225 unit tests, 153 integration tests, 25
  proptests, and doc-tests.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked`:
  pass, full package test suite.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-extent-map --no-default-features --features kernel --locked`:
  pass.
- `git diff --check`: pass after #6691 edits.
- conflict-marker scan over the touched files: no markers found.
- `rustfmt --check crates/tidefs-extent-map/src/multi_level.rs`: pass.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked truncate_late_tail_preserves_trim_and_freed_types`:
  pass, covering the new late-tail V3 truncate regression.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked`:
  pass, full package test suite.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-extent-map --no-default-features --features kernel --locked`:
  pass.
- `git diff --check`: pass after #6692 edits.
- conflict-marker scan over the touched files: no markers found.
  #6692 and #6583 with non-overlapping write sets.
- `rustfmt --check crates/tidefs-extent-map/src/multi_level.rs`: pass.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked convert_unwritten_late_fragment_preserves_prefix_and_suffix`:
  pass, covering the new late V3 unwritten conversion regression.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked convert_unwritten`:
  pass, covering V1/V2/V3 conversion, split, zero-length, wrong-type, and
  partial-overlap behavior.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked`:
  pass, full package test suite.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-extent-map --no-default-features --features kernel --locked`:
  pass.
- `git diff --check`: pass after #6693 edits.
- conflict-marker scan over the touched files: no markers found.
  #6693 and #6583 with non-overlapping write sets.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6694 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6694 claim; after #6693
  work.
- #6694 branch `codex/issue-6694-stream-v3-punch-hole` was pushed before
  source edits so other foreground Codex sessions can see the claimed work.
- `rustfmt --check crates/tidefs-extent-map/src/multi_level.rs`: pass.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked punch_hole_late_fragmented_preserves_trim_and_freed_types`:
  pass, covering the new late fragmented V3 punch-hole regression.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked punch_hole`:
  pass, covering V1/V2/V3 punch-hole behavior and edge cases.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked`:
  pass, full package test suite.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-extent-map --no-default-features --features kernel --locked`:
  pass.
- `git diff --check`: pass after #6694 edits.
- conflict-marker scan over the touched files: no markers found.
  #6694 and #6583 with non-overlapping write sets.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6695 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6695 claim; reported no active
  claimed/review issues after #6694 and #6583 closeout.
- #6695 branch `codex/issue-6695-stream-v3-collapse-range` was pushed before
  source edits so other foreground Codex sessions can see the claimed work.
- `rustfmt --check crates/tidefs-extent-map/src/multi_level.rs`: pass.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked collapse_range_late_fragmented_preserves_trim_and_shifted_suffix`:
  pass, covering the new late fragmented V3 collapse-range regression.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked collapse_range`:
  pass, covering V1/V2/V3 collapse-range behavior and edge cases.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked`:
  pass, full package test suite.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-extent-map --no-default-features --features kernel --locked`:
  pass.
- `git diff --check`: pass after #6695 edits.
- conflict-marker scan over the touched files: no markers found.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6696 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6696 claim; reported active
- #6696 branch `codex/issue-6696-stream-v3-insert` was pushed before source
  edits so other foreground Codex sessions can see the claimed work.
- `rustfmt --check crates/tidefs-extent-map/src/multi_level.rs`: pass.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map insert_late_fragmented_preserves_trim_and_merge --locked`:
  pass, covering the new late fragmented V3 insert regression.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map insert_batch_replaces_multiple_ranges_in_one_extent --locked`:
  pass, covering the new multi-entry batch replacement regression.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map insert --locked`:
  pass, covering V1/V2/V3 insert behavior and edge cases.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked`:
  pass, full package test suite.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-extent-map --no-default-features --features kernel --locked`:
  pass.
- `git diff --check`: pass after #6696 edits.
- anchored conflict-marker scan over the touched files: no markers found.
- #6696 landed on `master` as `d660d946` and closed. #6697 continues the V2
  extent-map insert cleanup in the current branch/worktree above.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6697 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6697 continuation; reports
- #6697 branch `codex/issue-6697-stream-v2-insert` was pushed before source
  edits so other foreground Codex sessions can see the claimed work.
- `rustfmt --check crates/tidefs-extent-map/src/btree.rs`: pass.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map userspace::btree::tests::insert_late_fragmented_preserves_trim_and_merge --locked`:
  pass, covering the new late fragmented V2 insert regression.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map userspace::btree::tests::insert_batch_replaces_multiple_ranges_in_one_extent --locked`:
  pass, covering the new multi-entry V2 batch replacement regression.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target RUST_BACKTRACE=1 cargo test -p tidefs-extent-map allocate_overflow_offset_plus_length_rejected --locked`:
  pass after adding explicit V2 insert range overflow rejection before rebuild.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map insert --locked`:
  pass, covering V1/V2/V3 insert behavior and edge cases.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked`:
  pass, full package test suite.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-extent-map --no-default-features --features kernel --locked`:
  pass.
- #6697 landed on `master` as `78679463` and closed. #6698 continues the V2
  extent-map truncate cleanup in the current branch/worktree above.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6698 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6698 continuation; reports
- #6698 branch `codex/issue-6698-stream-v2-truncate` was pushed before source
  edits so other foreground Codex sessions can see the claimed work.
- `rustfmt --check crates/tidefs-extent-map/src/btree.rs`: pass.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map userspace::btree::tests::truncate_late_tail_preserves_trim_and_freed_types --locked`:
  pass, covering the new late fragmented V2 truncate regression.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map truncate --locked`:
  pass, covering V1/V2/V3 truncate behavior and edge cases.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked`:
  pass, full package test suite.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-extent-map --no-default-features --features kernel --locked`:
  pass.
- `git diff --check`: pass after #6698 edits.
- anchored conflict-marker scan over the touched files: no markers found.
- #6698 landed on `master` as `0a65059e` and closed. #6699 continues the V2
  extent-map punch-hole cleanup in the current branch/worktree above.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6699 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6699 continuation; reports
- #6699 branch `codex/issue-6699-stream-v2-punch-hole` was pushed before source
  edits so other foreground Codex sessions can see the claimed work.
- `rustfmt --check crates/tidefs-extent-map/src/btree.rs`: pass.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map userspace::btree::tests::punch_hole_late_fragmented_preserves_trim_and_freed_types --locked`:
  pass, covering the new late fragmented V2 punch-hole regression.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map punch_hole --locked`:
  pass, covering V1/V2/V3 punch-hole behavior and edge cases.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked`:
  pass, full package test suite.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-extent-map --no-default-features --features kernel --locked`:
  pass.
- `git diff --check`: pass after #6699 edits.
- anchored conflict-marker scan over the touched files: no markers found.
- #6699 landed on `master` as `e7146008`.
- Post-merge `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map userspace::btree::tests::punch_hole_late_fragmented_preserves_trim_and_freed_types --locked`:
  pass.
  documentation continuation and closed. #6700 continues the V2 extent-map
  collapse-range cleanup in the current branch/worktree above.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6700 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6700 continuation; reports
- #6700 branch `codex/issue-6700-stream-v2-collapse-range` was pushed before
  source edits so other foreground Codex sessions can see the claimed work.
- `rustfmt --check crates/tidefs-extent-map/src/btree.rs`: pass.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map userspace::btree::tests::collapse_range_late_fragmented_preserves_trim_and_shifted_suffix --locked`:
  pass, covering the new late fragmented V2 collapse-range regression.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map collapse_range --locked`:
  pass, covering V1/V2/V3 collapse-range behavior and edge cases.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked`:
  pass, full package test suite.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-extent-map --no-default-features --features kernel --locked`:
  pass.
- `git diff --check`: pass after #6700 edits.
- anchored conflict-marker scan over the touched files: no markers found.
- #6700 landed on `master` as `712ddaf2`.
- Post-merge `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map userspace::btree::tests::collapse_range_late_fragmented_preserves_trim_and_shifted_suffix --locked`:
  pass.
- `rustfmt --check crates/tidefs-extent-map/src/btree.rs`: pass after #6701
  edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map userspace::btree::tests::convert_unwritten_late_fragment_preserves_prefix_and_suffix --locked`:
  pass, covering the new late fragmented V2 unwritten-conversion regression.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map convert_unwritten --locked`:
  pass, covering V1/V2/V3 unwritten conversion behavior and edge cases.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked`:
  pass, full package test suite.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-extent-map --no-default-features --features kernel --locked`:
  pass.
- `git diff --check`: pass after #6701 edits.
- anchored conflict-marker scan over the touched files: no markers found.
- Post-merge `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map userspace::btree::tests::convert_unwritten_late_fragment_preserves_prefix_and_suffix --locked`:
  pass.
- `rustfmt --check crates/tidefs-extent-map/src/polymorphic.rs`: pass after
  #6702 edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map stable_btree_noop_switch_preserves_fragmented_map --locked`:
  pass, covering the new stable BTree no-op switch regression.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map stable_multi_level_noop_switch_preserves_representation --locked`:
  pass, covering the new stable MultiLevel no-op switch regression.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map polymorphic --locked`:
  pass, covering polymorphic switching, serialization, and stress behavior.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked`:
  pass, full package test suite.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-extent-map --no-default-features --features kernel --locked`:
  pass.
- `git diff --check`: pass after #6702 edits.
- anchored conflict-marker scan over the touched files: no markers found.
- Post-merge `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map stable_btree_noop_switch_preserves_fragmented_map --locked`:
  pass.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6703 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6703 edits; reports active #6703
- #6703 branch `codex/issue-6703-stream-v2-serialize` was pushed before source
  edits so other foreground Codex sessions can see the claimed work.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map serde_roundtrip_fragmented_multi_page_preserves_page_count_and_tail --locked`:
  pass, covering the new fragmented multi-page V2 serialization regression.
- `rustfmt --check crates/tidefs-extent-map/src/btree.rs`: pass after #6703
  edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map serde --locked`:
  pass, covering V1/V2/V3/polymorphic serialization tests including the new V2
  fragmented multi-page page-count regression.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked`:
  pass, full package test suite.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-extent-map --no-default-features --features kernel --locked`:
  pass.
- `git diff --check`: pass after #6703 edits.
- anchored conflict-marker scan over the touched files: no markers found.
- #6703 landed on `master` as `df5ef38d`.
- Post-merge `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map serde_roundtrip_fragmented_multi_page_preserves_page_count_and_tail --locked`:
  pass.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6704 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6704 edits; reports active #6704
  edits so other foreground Codex sessions can see the claimed work.
- `rustfmt --check crates/tidefs-extent-map/src/btree.rs`: pass after #6704
  edits.
  unmerged-adjacent, locator-invariant, and offset-overflow regressions.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked`:
  pass, full package test suite.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-extent-map --no-default-features --features kernel --locked`:
  pass.
- `git diff --check`: pass after #6704 edits.
- anchored conflict-marker scan over the touched files: no markers found.
- #6704 source fix landed on `master` as `5ca6ee69`.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6705 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6705 claim; reported active
- #6705 branch `codex/issue-6705-stream-v2-deserialize` was pushed before
  source edits so other foreground Codex sessions can see the claimed work.
- `rustfmt crates/tidefs-btree/src/lib.rs crates/tidefs-extent-map/src/btree.rs`:
  pass after #6705 edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-btree unknown_len --locked`:
  pass, covering the new unknown-length sorted bulk-load success, unsorted
  input, and source-error regressions.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map streamed_deserialize --locked`:
  pass, covering the new V2 out-of-order VX22 page rejection.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map serde --locked`:
  pass, covering V1/V2/V3/polymorphic serialization tests including the
  streamed V2 deserialization path.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-btree rebuild_compact_from_sorted --locked`:
  pass, covering the exact-length and unknown-length sorted bulk-load tests.
- `rustfmt --check crates/tidefs-btree/src/lib.rs crates/tidefs-extent-map/src/btree.rs`:
  pass after #6705 checkpoint.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-btree --locked`:
  pass, full package suite including 228 unit tests, 153 integration tests, 25
  proptests, and doc-tests.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked`:
  pass, full package suite including 433 unit tests plus integration,
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-extent-map --no-default-features --features kernel --locked`:
  pass.
- anchored conflict-marker scan over the touched files: no markers found.
- Post-merge `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map serde_streamed_deserialize_rejects_out_of_order_page_entries --locked`:
  pass after `master` advanced.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6706 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6706 edits; reports active
- #6706 branch `codex/issue-6706-stream-polymorphic-switches` was pushed before
  source edits so other foreground Codex sessions can see the claimed work.
- `rustfmt --check crates/tidefs-extent-map/src/btree.rs crates/tidefs-extent-map/src/multi_level.rs crates/tidefs-extent-map/src/polymorphic.rs`:
  pass after #6706 edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked streaming -- --nocapture`:
  pass, covering the new sparse fragmented V2->V3 promotion and V3->V2
  demotion regressions.
- #6706 source and initial review documentation checkpoint was pushed to the
  issue branch as `d351edc9` so other foreground Codex sessions can inspect the
  work before integration.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked`:
  pass, full package suite including 435 unit tests plus integration,
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-extent-map --no-default-features --features kernel --locked`:
  pass.
- Post-merge `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-extent-map --locked streaming -- --nocapture`:
  pass after `master` advanced, covering the V2->V3 and V3->V2 sparse
  fragmented streaming regressions.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6707 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6707 edits; reports active
- #6707 branch `codex/issue-6707-dir-index-kernel-snapshot-test-only` was
  pushed before source edits so other foreground Codex sessions can see the
  claimed work.
- `rustfmt --check crates/tidefs-dir-index/src/kernel_reader.rs`: pass after
  #6707 edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-dir-index --no-default-features --features kernel --locked`:
  pass after #6707 edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index --no-default-features --features kernel --locked kernel_reader -- --nocapture`:
  pass, 19 kernel_reader tests.
- `git diff --check`: pass after #6707 edits.
- anchored conflict-marker scan over the touched files: no markers found.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index --locked`:
  pass, full package suite including 190 unit tests, integration tests, and
  doc-tests; the existing 10k-entry serialization unit test completed in
  164.26s.
- Post-merge `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index --no-default-features --features kernel --locked kernel_reader -- --nocapture`:
  pass, 19 kernel_reader tests after `master` advanced.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6708 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6708 edits; reports active
- #6708 branch `codex/issue-6708-bound-namespace-import-retention` was pushed
  before source edits so other foreground Codex sessions can see the claimed
  work.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --no-default-features --features persistent-dir-index persistent_load_streams_manifest_dirs_and_lazily_loads_children --locked -- --nocapture`:
  pass, covering the new lazy child-directory import regression.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index --features persistent-dir-index for_each_in_store_visits_live_entries_without_loading_index --locked -- --nocapture`:
  pass, covering the direct persisted-page scanner and tombstone filtering.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --no-default-features --features persistent-dir-index persistent_load --locked -- --nocapture`:
  pass, covering the existing large-root persistent load test plus the new
  lazy child-directory import regression.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-namespace --locked`:
  pass after #6708 edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-namespace --no-default-features --features persistent-dir-index --locked`:
  pass after #6708 edits.
- `rustfmt --check crates/tidefs-dir-index/src/pages.rs crates/tidefs-dir-index/src/persistent.rs crates/tidefs-namespace/src/lib.rs crates/tidefs-namespace/src/local_fs_persist.rs`:
  pass after #6708 edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --no-default-features --features persistent-dir-index --locked`:
  pass, full persistent namespace suite with 199 unit tests plus doc-tests.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index --features persistent-dir-index --locked`:
  pass, full persistent dir-index suite with 312 unit tests plus integration
  tests and doc-tests; the existing 10k-entry serialization unit test
  completed in 122.71s.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --locked`:
  pass, full default namespace suite with 197 unit tests plus doc-tests.
- Post-merge `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --no-default-features --features persistent-dir-index persistent_load --locked -- --nocapture`:
  pass, 2 persistent-load tests after `master` advanced.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6709 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6709 edits; reports active
- #6709 branch `codex/issue-6709-dir-index-snapshot-apis` was pushed before
  source edits so other foreground Codex sessions can see the claimed work.
- `rustfmt --check crates/tidefs-dir-index/src/cursor.rs crates/tidefs-dir-index/src/persistent.rs`:
  pass after #6709 edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-dir-index --locked`:
  pass after #6709 edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-dir-index --features persistent-dir-index --locked`:
  pass after #6709 edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index cursor --locked`:
  pass, covering 33 cursor unit tests plus focused cursor-related integration
  tests after the full-snapshot constructor was gated to tests.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index --features persistent-dir-index entry_snapshot_keeps_legacy_test_cookies --locked`:
  pass, covering the test-only persistent snapshot helper.
- `git diff --check`: pass after #6709 edits.
- anchored conflict-marker scan over the touched files: no markers found.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index --locked`:
  pass, full package suite including 190 unit tests, integration tests, and
  doc-tests; the existing 10k-entry serialization unit test completed in
  175.68s.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index --features persistent-dir-index --locked`:
  pass, full persistent dir-index suite including 313 unit tests, integration
  tests, and doc-tests; the existing 10k-entry serialization unit test
  completed in 114.28s.
- Post-merge `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index --features persistent-dir-index entry_snapshot_keeps_legacy_test_cookies --locked`:
  pass after `master` advanced, covering the test-only persistent snapshot
  helper.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6710 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6710 edits; reports active
- #6710 branch `codex/issue-6710-store-backed-namespace-lookup` was pushed
  before source edits so other foreground Codex sessions can see the claimed
  work.
- `rustfmt --check crates/tidefs-dir-index/src/persistent.rs crates/tidefs-namespace/src/lib.rs`:
  pass after #6710 edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-namespace --locked`:
  pass after #6710 edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-namespace --no-default-features --features persistent-dir-index --locked`:
  pass after #6710 edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index --features persistent-dir-index lookup_in_store_finds_entry_without_loading_index --locked`:
  pass, covering the new persistent adapter helper and existing page-level
  lookup helper.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --no-default-features --features persistent-dir-index persistent_load_streams_manifest_dirs_and_lazily_loads_children --locked -- --nocapture`:
  pass, covering read-only lookup and path resolution under an unloaded
  persisted child directory without retaining its mutable index.
- `git diff --check`: pass after #6710 edits.
- anchored conflict-marker scan over the touched files: no markers found.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --no-default-features --features persistent-dir-index --locked`:
  pass, full persistent namespace suite with 199 unit tests plus doc-tests.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --locked`:
  pass, full default namespace suite with 197 unit tests plus doc-tests.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index --features persistent-dir-index --locked`:
  pass, full persistent dir-index suite including 314 unit tests, integration
  tests, and doc-tests; the existing 10k-entry serialization unit test
  completed in 117.45s.
- Post-merge `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --no-default-features --features persistent-dir-index persistent_load_streams_manifest_dirs_and_lazily_loads_children --locked -- --nocapture`:
  pass after `master` advanced, covering store-backed read-only lookup under
  an unloaded persisted child directory.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6711 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6711 edits; reports active
- #6711 branch `codex/issue-6711-store-backed-read-dir` was pushed before
  source edits so other foreground Codex sessions can see the claimed work.
- `rustfmt --edition 2021 --check crates/tidefs-dir-index/src/persistent.rs crates/tidefs-namespace/src/lib.rs`:
  pass after #6711 edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index --features persistent-dir-index --locked list_from_store_preserves_positional_windows`:
  pass, covering store-backed positional read-dir windows without loading the
  mutable persistent index.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --no-default-features --features persistent-dir-index --locked persistent_load_streams_manifest_dirs_and_lazily_loads_children`:
  pass, covering lookup, resolution, paginated read-dir, and read-dir
  exhaustion under an unloaded persisted child directory without increasing
  the loaded directory count.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-dir-index --features persistent-dir-index --locked`:
  pass after #6711 edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-namespace --no-default-features --features persistent-dir-index --locked`:
  pass after #6711 edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index --features persistent-dir-index --locked`:
  pass, full persistent dir-index suite including 315 unit tests, integration
  tests, and doc-tests; the existing 10k-entry serialization unit test
  completed in 119.01s.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --no-default-features --features persistent-dir-index --locked`:
  pass, full persistent namespace suite with 199 unit tests plus doc-tests.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-dir-index --locked`:
  pass after #6711 edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-namespace --locked`:
  pass after #6711 edits.
- `git diff --check`: pass after #6711 edits.
- anchored conflict-marker scan over the touched files: no markers found.
- Post-merge `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-dir-index --features persistent-dir-index --locked list_from_store_preserves_positional_windows`:
  pass after `master` advanced, covering store-backed positional read-dir
  windows.
- Post-merge `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --no-default-features --features persistent-dir-index --locked persistent_load_streams_manifest_dirs_and_lazily_loads_children`:
  pass after `master` advanced, covering paginated read-dir under an unloaded
  persisted child directory.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6712 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6712 edits; reports active
- #6712 branch `codex/issue-6712-preserve-manifest-flush` was pushed before
  source edits so other foreground Codex sessions can see the claimed work.
- `rustfmt --edition 2021 --check crates/tidefs-namespace/src/lib.rs`:
  pass after #6712 edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --no-default-features --features persistent-dir-index --locked persistent_flush_`:
  pass, covering flush-after-lazy-load manifest preservation and removed
  directory manifest pruning.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-namespace --no-default-features --features persistent-dir-index --locked`:
  pass after #6712 edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --no-default-features --features persistent-dir-index --locked`:
  pass, full persistent namespace suite with 201 unit tests plus doc-tests.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-namespace --locked`:
  pass after #6712 edits.
- `git diff --check`: pass after #6712 edits.
- anchored conflict-marker scan over the touched files: no markers found.
- Post-merge `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --no-default-features --features persistent-dir-index --locked persistent_flush_`:
  pass after `master` advanced, covering manifest preservation for unloaded
  directories and pruning for removed directories.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6713 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6713 edits; reports active #6713
  and #6585 with non-overlapping write sets.
- #6713 branch `codex/issue-6713-lazy-root-namespace` was pushed before source
  edits so other foreground Codex sessions can see the claimed work.
- `cargo fmt -p tidefs-namespace`: pass after #6713 source edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --no-default-features --features persistent-dir-index --locked persistent_load`:
  pass, covering root cold import, root store-backed lookup/read-dir, root
  mutation lazy-load, and malformed root manifest rejection.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --no-default-features --features persistent-dir-index --locked persistent_flush_`:
  pass, covering manifest preservation and removed-directory pruning with the
  root index also left unloaded after import.
- `git diff --check`: pass before publishing source checkpoint `d91ccdd0`.
- #6713 source/test checkpoint `d91ccdd0` was pushed to
  `codex/issue-6713-lazy-root-namespace`.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-namespace --no-default-features --features persistent-dir-index --locked`:
  pass after #6713 documentation checkpoint.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --no-default-features --features persistent-dir-index --locked`:
  pass, full persistent namespace suite with 203 unit tests plus doc-tests.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-namespace --locked`:
  pass for the default namespace feature set.
- Post-merge `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --no-default-features --features persistent-dir-index --locked persistent_load`:
  pass after `master` advanced, covering cold root import, root store-backed
  lookup/read-dir, mutation lazy-load, and malformed root manifest rejection.
- `systemctl is-active tidefs-nexus tidefs-nexus-dashboard || true` and
  `systemctl is-enabled tidefs-nexus tidefs-nexus-dashboard || true`: inactive
  and disabled before #6714 continuation.
- `~/ai/bin/tidefs-claim status`: pass before #6714 edits; reports active #6714
  and #6585 with non-overlapping write sets.
- #6714 branch `codex/issue-6714-store-backed-rename-cycle` was pushed before
  source edits so other foreground Codex sessions can see the claimed work.
- `cargo fmt -p tidefs-namespace`: pass after #6714 source edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --no-default-features --features persistent-dir-index --locked persistent_rename_cycle_check_keeps_cold_ancestors_unloaded`:
  pass, covering a directory rename under a deep cold sibling subtree while the
  cold ancestor chain stays served from persisted pages.
- `git diff --check`: pass before publishing source checkpoint `4a3e7338`.
- #6714 source checkpoint `4a3e7338` was pushed to
  `codex/issue-6714-store-backed-rename-cycle`.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-namespace --no-default-features --features persistent-dir-index --locked`:
  pass after #6714 documentation checkpoint.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --no-default-features --features persistent-dir-index --locked`:
  pass, full persistent namespace suite with 204 unit tests plus doc-tests.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p tidefs-namespace --locked`:
  pass for the default namespace feature set.
- Post-merge `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --no-default-features --features persistent-dir-index --locked persistent_rename_cycle_check_keeps_cold_ancestors_unloaded`:
  pass after `master` advanced, covering store-backed rename cycle parent-chain
  lookup without loading the cold ancestor chain.
- `cargo fmt -p tidefs-dir-index -p tidefs-namespace`: pass after #6715 edits.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --no-default-features --features persistent-dir-index --locked persistent_rename_replace_`:
  pass, covering empty target replacement and non-empty target rejection while
  the cold target directory remains unloaded.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace --no-default-features --features persistent-dir-index --locked`:
  pass, full persistent namespace suite with 206 unit tests plus doc-tests.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target-default cargo check -p tidefs-namespace --locked`:
  pass for the default namespace feature set.
- `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target-dir-index cargo check -p tidefs-dir-index --locked`:
  pass for the direct persisted-page helper surface.
- anchored conflict-marker scan over the touched files: no markers found.
