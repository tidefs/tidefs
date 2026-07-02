# Snapshot Deadlist Reclaim Policy

Status: current pointer for issue #1266; documentation/design only.

This file remains because
`docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md` maps issue #1266 to this path. The
source-backed local snapshot/deadlist authority is still
`docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md` plus the owning reclaim and
capacity source paths.

## Current Authority

- `docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md` section 4 defines the local
  snapshot/clone/deadlist integration model and follow-up map.
- `crates/tidefs-reclaim-queue-core/src/dead_object_queue.rs`,
  `crates/tidefs-local-object-store/src/reclaim_queue.rs`,
  `crates/tidefs-reclaim/src/lib.rs`, and
  `crates/tidefs-segment-cleaner/src/physical_reclaim.rs` own the
  receipt-bound reclaim queue and physical drain mechanics.
- `crates/tidefs-local-filesystem/src/capacity_authority.rs`,
  `space_pressure.rs`, and `statfs.rs` own local capacity/statfs reporting.

## Policy Boundary

The design decision is limited to the policy layer above the dead-object queue:

- background drain is the ordinary path;
- space-pressure escalation may run a bounded synchronous drain before ENOSPC;
- default batch targets remain 1024 entries for background drain and 256
  entries for synchronous pressure drain until source evidence changes them;
- operator reporting should distinguish deadlist debt from physically freed
  capacity;
- allocator-visible free space must come from receipt-bound physical reclaim,
  not from directly trusting an in-memory deadlist.

## Non-Claims

This pointer does not claim snapshot delete, distributed deadlists,
capacity/accounting integration, production allocator behavior, performance, or
release readiness are complete. Any source work that implements or revises this
policy needs its own issue, validation tier, and claim-gate evidence.
