# tidefs-local-filesystem

Pre-alpha local filesystem engine for TideFS. This crate implements the
namespace, file-content, commit, and reopen path used by the userspace mounted
filesystem. It is not production-ready and does not establish a broader TideFS
product claim.

## Role

The mounted path has this ownership shape:

```text
FUSE daemon
    │
    ▼
VfsLocalFileSystem (`VfsEngine` implementation)
    │
    ▼
LocalFileSystem
    ├── FileSystemState
    ├── CommitGroupStateMachine
    ├── WriteBuffer / DirtySet
    ├── retained IntentLog
    └── page and inode caches
    │
    ▼
Pool
    ├── placement receipts
    └── one or more device LocalObjectStore instances
```

`LocalFileSystem` owns the `Pool`. Transaction metadata and root-selection
records use the raw recovery store where the current on-disk design requires
it. Mounted file-content reads, writes, commit validation, and retained-intent
reconstruction use Pool placement authority; checksum-valid raw-primary bytes
without a current placement receipt are not independently authoritative file
content.

## Commit And Recovery

A commit writes immutable transaction objects, synchronizes every Pool device,
publishes an authenticated root slot, and synchronizes the Pool again. A final
sync failure reports an uncertain publication outcome rather than pretending
that the old or new root is known.

On open, the crate:

1. selects the newest authenticated root whose transaction metadata validates;
2. validates every nonempty file-content object named by that root through the
   current Pool placement path;
3. loads auxiliary mounted state; and
4. validates and replays retained local intent entries against the selected
   Pool-authorized base.

Incomplete or unreadable newer candidates do not become live roots. Replayed
intent entries remain durable until a later full commit publishes the recovered
state and clears them.

The separate `.viflodev` sidecar format has no authenticated LSN watermark in
the committed root and no production writer connected to this mounted engine.
`LocalFileSystem::open` therefore does not treat such files as mounted recovery
authority. The Pool-backed local intent log above is the current mounted replay
path.

This is recovery behavior, not an automatic-repair or release-readiness claim.
`RecoveryAuditReport` and `OnlineVerifierReport` still use a raw-primary/root-slot
diagnostic view; they are not Pool-complete mounted diagnostics. GitHub issue
#2377 owns that bounded follow-up.

## Durability Boundaries

- `fsync_file` flushes buffered data and publishes a full committed root.
- Data-only sync may retain a durable intent until a later full commit.
- Foreground buffer, commit, fsync, and fdatasync boundaries drive mounted
  durability.
- Production open does not start the dormant `WritebackDaemon`; no timer daemon
  is part of the current mounted writeback path.
- Explicit background-service ticks may run compaction, orphan cleanup, and
  receipt-bound reclaim work, but those services do not replace commit or
  intent durability.

## Important Modules

| Module | Current responsibility |
|---|---|
| `lib.rs` | `LocalFileSystem`, mounted mutation, commit, and open orchestration |
| `vfs_engine_impl.rs` | `VfsEngine` adapter used by the FUSE daemon |
| `content.rs` | Pool-authorized content layout/chunk reads and writes |
| `persistence.rs` | transaction-object and authenticated-root publication |
| `recovery.rs` | authenticated-root selection, candidate validation, and retained-intent staging |
| `intent_log.rs` | durable local intent encoding, validation, replay, and trimming |
| `allocation.rs` | mounted content-allocation planning |
| `write_buffer.rs` | coalesced foreground writes |
| `writeback.rs` | dirty-state accounting |
| `page_cache/` | derived read cache and reclaim mechanics |
| `snapshot.rs` | snapshot lifecycle |
| `send_receive.rs` | pre-release send/receive stream implementation |

The repository Product Contract in the top-level `README.md` is the sole
authority for TideFS product shape. Focused source and carrier tests establish
what this crate currently does; live issues own remaining defects and planned
work.
