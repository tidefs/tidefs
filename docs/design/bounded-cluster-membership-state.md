# Bounded Cluster Membership State: Anti-Ceph-OSDMap-Explosion Design

Maturity: **design-spec** for bounded membership epoch lifecycle, historical
epoch garbage collection, and the placement-via-locator architecture that
eliminates O(cluster-history) state growth.

This document closes Forgejo issue #1283.

## 1. Motivation: The Ceph OSDMap Anti-Pattern

Ceph's monitor daemons store the entire cluster map (OSDMap) in memory.
The OSDMap grows unboundedly with every OSD addition, removal, weight change,
and PG adjustment. On large, long-lived clusters:

- **Monitor OOM**: OSDMaps exceed 10 GB of in-memory state.
- **Slow restart**: Monitor restart replays every epoch — minutes to hours.
- **Slow OSD join**: New OSDs must receive the full OSDMap history.

The root cause is architectural: Ceph uses OSDMap as both a **placement
function** (CRUSH computes data location from OSDMap) and a **cluster state
log** (every membership change appends a new epoch). Since placement is a
*function* of map state, any node that needs to locate data must replay all
historical maps to determine where data currently resides. The OSDMap grows
with cluster *history*, not cluster *size*.

A tidefs cluster must run for a decade with thousands of node
additions/removals. If membership state grows with history, the system
degrades over time regardless of workload. This is a "design for 10 years"
constraint.

## 2. Design Overview

tidefs avoids the OSDMap trap through three architectural decisions:

| Decision | Mechanism |
|----------|-----------|
| **Placement results, not placement functions** | Extent physical location is stored in the locator table at write time; no re-derivation from epoch history is needed |
| **Compaction, not accumulation** | Only the latest membership epoch is required for normal operation; historical epochs are eligible for GC |
| **Bounded monitor state** | Monitor state is O(current cluster size), not O(cluster history) |

These decisions mean that while epoch history may be logged for
audit/debugging, the *operational* data path never depends on it. The extent
locator (`tidefs-locator-table`) stores physical pointers explicitly. An
extent written during epoch N records `written_at_epoch = N` in its locator
entry, but the *physical location* is an explicit `ReplicaPlacement` vector —
not a function to be recomputed from N.

### 2.1 Contrast with Ceph

```
Ceph:  data_location = CRUSH(extent_id, OSDMap_current)
       → OSDMap_current requires full replay of OSDMap history
       → state = O(cluster history)

tidefs: data_location = locator_table[locator_id].replica_placement
        → locator_id stored in extent map at write time
        → state = O(active extents) = O(cluster size × dataset size factor)
```

## 3. Data Structures

### 3.1 MembershipEpochRecord

Each committed membership epoch is a compact record:

```rust
/// A single committed membership epoch, containing the full membership
/// table for that epoch plus the deterministic placement seed.
pub struct MembershipEpochRecord {
    /// Monotonically increasing epoch identifier.
    pub epoch: EpochId,                     // u64 (from tidefs-membership-epoch)

    /// Full membership table: MemberId → ClusterMemberRecord.
    /// Uses BTreeMap for deterministic iteration order.
    pub members: BTreeMap<MemberId, ClusterMemberRecord>,

    /// Deterministic hash seed for extent placement during this epoch.
    /// All placement decisions within an epoch use this seed to produce
    /// consistent, reproducible replica target selection.
    pub placement_seed: u64,

    /// Pool COMMIT_GROUP at which this epoch was committed. Provides causal
    /// ordering relative to data-plane transactions.
    pub created_at_commit_group: u64,

    /// Config class for this epoch (Bootstrap, Normal, Joint, Quarantined).
    pub config_class: ConfigClass,

    /// The previous epoch this one succeeded, or EpochId::ZERO for
    /// the bootstrap epoch.
    pub predecessor_epoch: EpochId,

    /// Digest of the serialized record for integrity verification.
    pub digest: u64,
}
```

`ClusterMemberRecord` is defined in `tidefs-membership-epoch` and includes:
`member_id`, `member_class` (Voter/Learner/WitnessOnly/DataOnly/ShadowOnly/
Quarantined), `current_membership_epoch_ref`, `log_frontier`, `health`,
`failure_domain_vector`, and `digest`.

### 3.2 Epoch History Store

Historical epochs are stored in a bounded ring buffer with a configurable
retention window:

```rust
/// Bounded store of historical membership epochs.
///
/// The store retains up to `retention_limit` epochs. When the limit is
/// exceeded, the oldest epoch is evaluated for GC eligibility and either
/// deleted or a retention override is logged.
pub struct EpochHistoryStore {
    /// Current (latest) epoch — always present.
    pub current: MembershipEpochRecord,

    /// Historical epochs in descending epoch order (newest first after current).
    /// Bounded to `retention_limit` entries.
    pub history: VecDeque<MembershipEpochRecord>,

    /// Maximum number of historical epochs to retain before GC evaluation.
    pub retention_limit: usize,             // default: 16 (from MEMBERSHIP service)

    pub gc_watermark_epoch: EpochId,
}
```

### 3.3 ExtentLocatorValueV1 Extension: written_at_epoch

The existing `ExtentLocatorValueV1` (in `tidefs-types-locator-table-core`)
gains a `written_at_epoch` field to support GC:

```rust
/// Extends ExtentLocatorValueV1 with epoch tracking for GC.
///
/// Field addition (TLV extension compatible with V1 on-media format):
///   written_at_epoch: u64   // EpochId.0 when this extent was allocated
```

Every `LocatorTableOps::allocate()` call stamps the new locator with the
current epoch. When the GC service evaluates a historical epoch for deletion,
it queries: "do any live extents reference epoch N?" If the minimum
`written_at_epoch` across all live locators is greater than N, epoch N is
safe to delete.

### 3.4 CompactedEpochSummary

epoch records are GC'd:

```rust
pub struct CompactedEpochSummary {
    pub epoch: EpochId,
    pub created_at_commit_group: u64,
    pub member_count: u16,
    pub voter_count: u16,
    pub config_class: ConfigClass,
    pub transition_description: String,    // e.g., "add-node-42 voter"
    pub digest: u64,
}
// Total: ~80 bytes per compacted epoch vs ~4+ KiB per full epoch record
```

~3.65M summaries at ~80 bytes = ~292 MB, trivially manageable.

## 4. Algorithms

### 4.1 Epoch Creation and Compaction

```
algorithm create_next_epoch(current: MembershipEpochRecord,
                             transition: MembershipTransitionRecord)
                             → MembershipEpochRecord

  1. Verify transition is valid under current.config_class and quorum rules.
  2. Apply transition to membership table:
     - Add/remove members, change member classes as specified.
  3. Generate new placement_seed via deterministic RNG seeded from
     current.placement_seed || transition.digest.
  4. Set predecessor_epoch = current.epoch.
  5. Set config_class based on transition type (Joint for voter changes).
  6. Set created_at_commit_group = pool current COMMIT_GROUP.
  7. Compute digest over the serialized record.
  8. Commit the new epoch.
  9. Push current into history; if history.len() > retention_limit,
     enqueue oldest for GC evaluation.
```

### 4.2 Epoch Garbage Collection Eligibility

```
algorithm is_epoch_gc_eligible(epoch: EpochId,
                                locator_table: &dyn LocatorTableOps)
                                → bool

  1. If epoch == EpochHistoryStore.current.epoch:
       return false  // never GC the current epoch

  2. Query locator_table.min_written_at_epoch():
     - If no live locators: return true
     - If min_written_at_epoch > epoch:
         return true  // all live extents written after this epoch
     - Else:
         return false // at least one live extent references this epoch

  3. Additionally, if epoch is predecessor to an epoch still in a Joint
     phase transition not yet committed to Normal: return false.
```

### 4.3 Deterministic Placement Without History

Placement of new extents uses the current epoch's placement seed:

```
algorithm place_extent(extent_id: ExtentId,
                        epoch: MembershipEpochRecord,
                        failure_domain_policy: &PlacementPolicy)
                        → Vec<ReplicaPlacement>

  1. hash_input = epoch.placement_seed || extent_id.0.to_le_bytes()
  2. hash = BLAKE3(hash_input)
  3. Select N replicas from the eligible member set per failure_domain_policy:
     - Filter members by member_class.can_hold_replicas()
     - Use hash to deterministically shuffle and select targets
     - Enforce anti-affinity per FailureDomainClass
  4. Return Vec<ReplicaPlacement> with selected physical locations.
  5. Write the result into the locator table — placement is now STORED,
     not a function to be recomputed later.
```

The critical property: once written, extent placement is *stored* in the
locator table. Neither read nor rebuild needs to replay epoch history to
find where data is. Only recovery verification may consult epoch history
to confirm that placement was lawful — and the verification path can use
compacted summaries or operate within the retention window.

### 4.4 Recovery: Finding Extents Written During an Old Epoch

Recovery of extents written during a specific epoch uses the locator table,
not epoch replays:

```
algorithm recover_extents_from_epoch(epoch: EpochId,
                                      locator_table: &dyn LocatorTableOps,
                                      extent_map: &dyn ExtentMapOps)
                                      → Vec<(ExtentId, ExtentLocatorValueV1)>

  1. Scan locator table for all entries where written_at_epoch == epoch.
  2. For each locator, resolve the extent_id from the extent map
     (or from the locator's stored extent_id if co-located).
  3. Verify each replica's health; rebuild degraded replicas using
     surviving replicas or erasure-coded reconstruction.
  4. Return the set for integrity verification.
```

Since the locator table directly stores physical placement, recovery never
needs to know the full membership table of the epoch — only the physical
device addresses in the `replica_placement` vector.

### 4.5 Background GC Service Integration

The epoch GC evaluator runs as a Stage 4 (Best-effort) `BackgroundService`
per #1179:

```
service EpochGcService:
  name: "epoch-gc"
  priority: Stage4  // Best-effort: compaction, trim

  tick(budget):
    1. Read gc_watermark_epoch from EpochHistoryStore.
    2. Collect epochs in history where epoch <= gc_watermark_epoch.
    3. For each candidate, call is_epoch_gc_eligible().
    4. If eligible:
       a. Emit CompactedEpochSummary to audit log.
       b. Remove full epoch record from history.
       c. Update gc_watermark_epoch to candidate.epoch + 1.
    5. Return TickReport with count of GC'd epochs.

  work_pending():
    return history.contains(|e| e.epoch <= gc_watermark_epoch)
```

### 4.6 Membership Change Protocol: Joint Consensus

Per the P8-02 model, membership transitions that change the voter set pass
through a joint-consensus phase:

```
Normal(c1) → Joint(c2) → Normal(c1)

1. Current config is Normal(c1) with voters {A, B, C}.
2. Proposal to add D as voter.
3. Transition to Joint(c2): config requires quorum from
   both {A, B, C} AND {A, B, C, D} for any decision.
4. During Joint(c2): D catches up on log/state.
5. Once D reaches required frontier, commit Normal(c1)
   with voters {A, B, C, D} and new placement_seed.
```

Each transition creates exactly ONE new epoch. Joint epochs are temporary
and are eligible for GC once their successor Normal epoch is committed and
no extents reference the Joint epoch.

## 5. Bounded State Analysis

### 5.1 Monitor State Budget

| Component | Bound | Rationale |
|-----------|-------|-----------|
| Current epoch record | O(N) where N = cluster members | Full membership table for N ≤ 256 nodes |
| Historical epoch ring | retention_limit × O(N) | Default: 16 epochs; configurable |
| Compacted summaries | O(changes) × 80 bytes | ~292 MB over 10 years; trivial |
| Active leases | O(N) | One per active node |
| In-flight operations | O(W) where W = concurrent ops | Bounded by transport-layer queue limits |

Maximum monitor memory = O(N × retention_limit + changes × 80 + N + W)
= O(N) on a per-epoch basis, with a constant factor from retention_limit.

For a 256-node cluster with retention_limit = 16, a full epoch record is
approximately:
- ClusterMemberRecord: ~160 bytes × 256 = ~41 KiB
- Overhead (BTreeMap, seed, metadata): ~4 KiB
- Total per epoch: ~45 KiB

Maximum monitor memory for epochs: 45 KiB × 16 = ~720 KiB. Compare with
Ceph's 10 GB+ OSDMap — tidefs is ~14,000× smaller.

### 5.2 Monitor Restart Time

- Load current epoch: O(N) = read one record (~45 KiB) → microseconds.
- Replay recent operations from intent log: O(minutes of changes), not
  O(years of history).
- Re-establish leases: one heartbeat round.

Total restart: sub-second, vs. Ceph's minutes-to-hours.

### 5.3 Node Join Time

A new node joining the cluster needs:
- Current epoch record (the membership table).
- Compacted epoch summaries for audit context (optional).
- No historical epoch replay.

Data placement is learned on-demand from the locator table during reads, not
pre-loaded from epoch history.

## 6. Integration Points

### 6.1 With tidefs-membership-epoch (P8-02 model)

`MembershipEpochRecord` wraps the existing `tidefs-membership-epoch` types:
- Uses `EpochId`, `MemberId`, `ClusterMemberRecord`, `ConfigClass`,
  `MemberClass`, `FailureDomainVector` directly.
- Adds `placement_seed` for deterministic placement during the epoch.
- Adds `created_at_commit_group` for causal ordering with the data plane.

### 6.2 With tidefs-locator-table

`ExtentLocatorValueV1` gains `written_at_epoch: u64`. The `LocatorTableOps`
trait gains:

```rust
/// Return the minimum `written_at_epoch` among all non-retired locator
/// entries, or None if the table is empty.
fn min_written_at_epoch(&self) -> Option<EpochId>;

/// Return all locator ids whose `written_at_epoch` matches the given epoch.
fn locators_written_at_epoch(&self, epoch: EpochId) -> Vec<LocatorId>;
```

### 6.3 With tidefs-types-extent-map-core

The `ExtentMapEntryV1` already has `committed_commit_group: u64`. For epoch-aware GC,
the locator table is the authoritative source of `written_at_epoch`. The
extent map can resolve `locator_id → epoch` through the locator table without
duplicating the epoch field.

### 6.4 With Background Scheduler (#1179)

Epoch GC is a Stage 4 `BackgroundService`. It must:
- Declare its priority class and per-tick budget.
- Report `TickReport` with GC'd epoch count.
- Respect the global background-work budget to avoid starving critical
  services (repair, intent-log sync).

### 6.5 With MEMBERSHIP Service (#1209)

The MEMBERSHIP service consumes `MembershipEpochRecord` for:
- `CLUSTER_VIEW` push: includes current epoch + member table.
- `JOIN_ACK`: includes current epoch for new nodes.
- Epoch transitions: initiated by leader, committed via joint consensus.

The service already defines `MAX_EPOCH_HISTORY = 16`, which becomes the
default `retention_limit` for `EpochHistoryStore`.

### 6.6 With Pool Topology Management (#1254)

Pool topology changes (device add/remove, geometry conversion) trigger
membership epoch transitions, which in turn update `placement_seed` for
new allocations. Existing extents are unaffected — their placement is
already stored in the locator table.

## 7. Safety and Liveness

### 7.1 No Silent Data Loss

An epoch must never be GC'd while any live extent references it. The safety
invariant is:

```
Invariant: epoch_not_referenced(E) ⇒
  ∀ locator ∈ locator_table:
    locator.written_at_epoch ≠ E ∨ locator.health = Retired
```

The GC evaluator queries `min_written_at_epoch()` atomically to ensure no
live locator with `written_at_epoch <= E` exists before deleting epoch E.

### 7.2 Placement Reproducibility

Placement during a historical epoch can be *reproduced* for verification
using the epoch's `placement_seed` and the membership table from the epoch
record. This is an audit/debug path, not a normal-operation path. The GC
watermark ensures that if verification needs epoch E, the locator table's
`min_written_at_epoch() <= E` prevents premature deletion.

### 7.3 Split-Brain Safety

Per the P8-02 model, split-brain hazards are detected by
`detect_split_brain_hazard_and_force_hold_or_quarantine()`. Historical epoch
(default 16 epochs) covers the time window needed to detect and resolve
partition scenarios. Compacted summaries provide a longer audit trail.

## 8. GC Liveness: Avoiding Indefinite Retention

An epoch could theoretically be pinned forever if a single extent written
during that epoch never becomes eligible for deletion. This is a normal
property: epochs are pinned by live data, not by a timer.

Mitigations:
- Online defrag (#1265) can relocate extents from old epochs, updating their
  `written_at_epoch` to the current epoch.
- Segment retirement and tier migration both update `written_at_epoch`.
- The operator has visibility into which epochs are pinned and by how many
  extents via `truth_view` surfaces.

## 9. Failure Modes and Recovery

| Failure mode | Impact | Recovery |
|-------------|--------|----------|
| GC deletes an epoch still referenced by a locator | Data integrity violation | Safety invariant prevents this |
| Epoch history ring overflows before GC runs | Oldest epoch evicted with compacted summary | Locator table still has physical placement; read path unaffected |
| Leader crash during joint consensus transition | Joint epoch may be abandoned | New leader re-proposes or rolls back per P8-02 rules |
| Corrupted epoch record | Digest mismatch detected on load | Reconstruct from surviving peers' current epoch; fall back to compacted summaries |
| placement_seed collision | Two epochs with same seed produce identical placement | Seed is derived from predecessor seed || transition digest; collision probability negligible |

## 10. Performance Characteristics

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| Create new epoch | O(N log N) | N = members; BTreeMap insertion + digest |
| Push to history ring | O(1) amortized | VecDeque push; GC eval is async |
| GC eligibility check | O(1) | Single query to locator table |
| Placement of new extent | O(M × D) | M = eligible members, D = replica count |
| Node join (read current epoch) | O(N) | Deserialize one MembershipEpochRecord |
| Locate extent (read) | O(log L) | L = locators in table; B-tree lookup |
| Recover extents from epoch E | O(K) | K = locators with written_at_epoch = E |

## 11. Open Questions

1. **Should compacted summaries be stored in a purpose-built audit log rather
   than in-memory?** The current design keeps them in-memory (~292 MB/decade).
   A spill-to-disk strategy could reduce memory further for clusters that
   change membership very frequently. Recommendation: in-memory for v1;
   spill-to-disk when compacted summaries exceed 64 MiB.

2. **Should epoch GC be triggered by a size threshold in addition to the ring
   buffer limit?** The current design uses a count-based retention limit.
   A byte-size threshold would provide more predictable memory usage.
   Recommendation: count-based for v1 (simpler); add byte-size threshold as
   a configurable option.

3. **Can the retention window be reduced for read-only epochs?** If an epoch
   is known to have no extents allocated during it (a purely administrative
   transition), it could be GC'd immediately after its successor is committed.
   Recommendation: defer to post-v1 optimization; treat all epochs uniformly
   for initial implementation.

## 12. Non-claims (Explicit Boundaries)

- Actual Rust implementation of `MembershipEpochRecord` and `EpochHistoryStore`
  is deferred to an implementation issue following this design.
- The `written_at_epoch` field on `ExtentLocatorValueV1` is specified here but
  implemented in the locator table implementation issue.
- Multi-leader membership sharding (beyond 256 nodes) is deferred per #1209.
- Audit-log design for compacted summaries is deferred to the observability
  workstream.
- Online defrag interacting with epoch GC is deferred to #1265.

## 13. References

- [#1283] This design spec
- [P8-02] `docs/MEMBERSHIP_PLACEMENT_FAILURE_DOMAIN_MODEL_P8-02.md`
- [#1209] MEMBERSHIP service design
- [#1249] CRUSH-like placement model
- [#1191] Extent management architecture: extent_id indirection
- [#1179] Background service framework
- [#1254] Pool topology management
- [#1265] Online defrag / BPR
- [#1285] Extent maps and locator tables design
- [#1279] ZFS/Ceph design mistake coverage matrix
- `crates/tidefs-membership-epoch/` — deterministic membership model
- `crates/tidefs-membership-live/` — membership runtime
- `crates/tidefs-locator-table/` — V1 locator table implementation
- `crates/tidefs-types-extent-map-core/` — ExtentId, LocatorId, ExtentMapEntryV1
- `crates/tidefs-types-locator-table-core/` — ExtentLocatorValueV1, LocatorTableOps
- `docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md`
- `docs/EXTENT_MAPS_LOCATOR_TABLES_DESIGN.md`
- `docs/ZFS_CEPH_DESIGN_MISTAKE_COVERAGE_MATRIX.md`
