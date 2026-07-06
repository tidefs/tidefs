# Compaction Authority

Maturity: design authority for GitHub issue #749.

This document decides the TideFS compaction authority boundary. It is a
documentation slice only: it does not change compaction, segment-cleaner,
reclaim, checksum-tree, extent-map, or object-store runtime behavior.

## Evidence Reviewed

- `crates/tidefs-compaction/`: planned compaction surface with B-tree page
  compaction, segment merge planning, BLAKE3 rewrite verification, and swap
  manifests.
- `crates/tidefs-segment-cleaner/`: current segment cleaner with pressure
  policy, victim selection, pin-set filtering, cleanup queue, and cleaner
  ledger.
- `crates/tidefs-data-cleaner/`: model reclaim-queue draining surface that is
  not mounted-runtime wiring.
- `crates/tidefs-background-scheduler/` and
  `docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md`: unified tick-driven scheduler
  and priority/budget model.
- `crates/tidefs-reclaim/` and `crates/tidefs-reclaim-queue-core/`: reclaim
  queue, liveness accounting, dead-object handoff, and existing reclaim policy
  surfaces.
- `docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md`: implementation-gated
  snapshot/clone/deadlist boundary.
- `crates/tidefs-spacemap-allocator/`: source-owned allocator surface.
  `docs/SPACEMAP_ALLOCATOR_DESIGN.md` remains historical provenance only.
- `docs/workspace-package-classification.md`: `tidefs-compaction` and
  `tidefs-data-cleaner` are planned authority surfaces requiring follow-up.

## Authority Decision

`crates/tidefs-compaction` is the single compaction authority.

It owns:

- compaction trigger admission;
- partial-segment candidate scoring;
- merge grouping and ordering;
- write-amplification bounds;
- relocation manifest construction;
- verification requirements before a compaction swap may publish.

It does not own:

- scheduler tick timing or cross-service budget fairness;
- refcount-delta processing;
- ordinary stale-extent reclaim;
- fully-dead segment freeing;
- allocator free-map publication;
- checksum-tree or extent-map root ownership.

Those boundaries are delegated below. Other crates may supply signals, durable
inputs, or commit participants, but they must not make independent
partial-segment merge-policy decisions once this authority is implemented.

## Trigger Model

The selected trigger model is a scheduled background pass with space-pressure
escalation. Write amplification is an admission bound, not a trigger.

The background scheduler owns when the compaction service receives a tick and
how much budget the tick may spend. It should register compaction as
BestEffort for ordinary scheduled passes, consistent with the background
service design. The scheduler must not inspect segments, choose merge groups,
or change compaction thresholds.

The segment cleaner and allocator own pressure signals. The segment cleaner's
existing free-space modes are the pressure vocabulary:

- free space at or above 15 percent: deferred pressure, scheduled compaction
  may run only under the normal write-amplification cap;
- free space below 15 percent: auto pressure, compaction may receive a larger
  budget but must keep the pressure cap;
- free space below 5 percent: urgent pressure, cleaner backpressure may
  throttle or reject non-critical writes while compaction still remains
  budgeted and write-amplification bounded.

`crates/tidefs-compaction` owns the admission decision for each tick:

- scheduled ticks admit only candidates with estimated write amplification at
  or below `2.0`;
- pressure ticks admit only candidates with estimated write amplification at
  or below `4.0`;
- candidates with no reclaimable bytes are skipped;
- fully-dead segments are not merge-compaction work and are routed to the
  segment cleaner's fully-dead free path;
- all modes remain subject to `WorkBudget` and a compaction-local maximum
  relocated-bytes budget.

Estimated write amplification uses the segment-cleaner cost vocabulary:

```text
(live_bytes + dead_bytes) / dead_bytes
```

where `dead_bytes` is the expected physical space reclaimed if the source
segment is released. This keeps the current default `liveness_threshold < 0.5`
behavior equivalent to the ordinary `2.0` cap while making the cap explicit.

## Merge Policy

`crates/tidefs-compaction` selects partial-segment merge candidates from
durable liveness inputs supplied by reclaim and segment-cleaner state. A
candidate is eligible only when:

- the source segment is sealed and not still accumulating foreground writes;
- the source segment is not reachable from a pinned traversal root or snapshot
  protection boundary;
- it contains live bytes that must be relocated and dead bytes that can be
  reclaimed;
- its estimated write amplification is within the current trigger cap;
- the total live bytes fit the current target segment grouping budget.

Fully-dead segments are excluded from merge groups. They are cheaper segment
cleaner work and do not require compaction relocation.

Partial candidates are ordered deterministically:

1. lowest estimated write amplification;
2. highest reclaimable bytes;
3. oldest creation or birth commit group;
4. lowest segment id.

Merge groups are built in that order until the configured target segment size
or relocated-bytes budget would be exceeded. A group that cannot make positive
net progress under the cap is skipped and reported as policy-rejected.

This makes write amplification a hard policy guard. Space pressure can increase
the admitted cap from `2.0` to `4.0`, but it cannot authorize unbounded
relocation or hidden foreground write starvation.

## Reclaim And Cleaner Boundary

Compaction dispatch does not own stale-extent reclaim.

The reclaim queue processor owns refcount-delta processing. It turns durable
refcount changes into locator/deadlist/liveness state and leaves underflow or
integrity failures queued for repair rather than silently freeing data.

The data cleaner is a reclaim-drain participant. Its mounted-runtime authority
is to drain durable reclaim work into liveness/deadlist handoff state. It must
not directly own physical segment freeing or partial-segment merge ordering.

The segment cleaner owns:

- free-space watermarks and cleaner backpressure;
- fully-dead segment freeing;
- pin-set filtering for cleaner candidates;
- crash-safe cleanup queue and cleaner ledger state;
- handoff of partial live/dead candidates to the compaction authority.

The compaction authority owns only the partial-live rewrite. After a verified
rewrite, source segments become release candidates. Physical release still goes
through the cleaner/cleanup path and allocator commit boundary; compaction does
not bypass reclaim or return space directly to the allocator.

## Visibility And Commit Ordering

Compaction operates on a committed extent-map and checksum-tree snapshot. Until
publish, readers continue to observe the old extent locations and old checksum
tree entries.

A compaction publish has these ordering requirements:

1. Write target objects or target segment payloads.
2. Verify rewritten bytes and relocation manifests using the compaction
   verification domain.
3. Prepare checksum-tree entries for the new target locations.
4. Prepare extent-map locator swaps from source locations to target locations.
5. Commit target object publication, checksum-tree updates, extent-map swaps,
   compaction relocation receipts, and source-release cleanup entries in one
   recovery-safe commit boundary.
6. Only after that commit boundary may the source segments be processed by the
   cleaner/allocator free path.

Readers may see either the pre-compaction mapping or the post-compaction
mapping. They must never see a target extent without the matching checksum
tree entry, a checksum entry without the matching extent-map locator, or a
source segment returned to the allocator while any visible extent map still
names it.

Crash recovery follows the same boundary:

- crash before publish: target writes are discarded or treated as orphaned
  scratch; source mappings remain authoritative;
- crash during publish: commit-group recovery chooses the old or new root set,
  never a mixed root set;
- crash after publish but before cleanup drain: new mappings are authoritative
  and source release is replayed from the durable cleanup entry.

## Negative Authority

Compaction authority is not:

- a replacement for the reclaim queue;
- a hidden foreground writeback path;
- an allocator free-space authority;
- a checksum-tree root authority;
- an extent-map root authority;
- a scheduler priority override;
- a data-cleaner direct-free authority;
- permission to compact pinned, unsealed, or snapshot-protected segments.

## Follow-Up Issues

The current tree has overlapping or incomplete authority surfaces. The
implementation work is split into non-overlapping GitHub issues:

| Issue | Scope | Expected write set |
|---|---|---|
| #802 | Add the compaction policy facade, trigger admission, deterministic merge ordering, and explicit write-amplification caps. | `crates/tidefs-compaction/` |
| #803 | Route segment-cleaner partial victims through the compaction authority while preserving pressure, fully-dead freeing, pin filtering, and cleaner ledger ownership. | `crates/tidefs-segment-cleaner/` |
| #804 | Make data cleaner drain refcount deltas to durable liveness/deadlist handoff state instead of direct physical free authority. | `crates/tidefs-data-cleaner/` |
| #805 | Align reclaim with refcount/liveness/deadlist publication and remove independent partial-segment compaction policy. | `crates/tidefs-reclaim/`, `crates/tidefs-reclaim-queue-core/` |
| #806 | Register compaction authority ticks through the background scheduler without moving merge policy into scheduler or local-filesystem glue. | `crates/tidefs-background-scheduler/`, `crates/tidefs-local-filesystem/src/background_compaction.rs` |
| #807 | Wire the verified object-store, checksum-tree, extent-map, commit-group, and source-release publish boundary. | `crates/tidefs-local-object-store/`, `crates/tidefs-extent-map/`, `crates/tidefs-checksum-tree/`, `crates/tidefs-commit_group/` |

## Validation For This Slice

This authority record was produced from source and design-doc inspection. The
only repository write authorized by #749 is this file. Validation is
documentation validation plus `git diff --check`; runtime validation belongs
to the follow-up implementation issues above.
