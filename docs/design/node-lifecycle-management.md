# Node Lifecycle Management: Staged Drain, Graceful Decommission, Forced Fencing, and Cluster Rebalance Orchestration

**Issue**: [#1260](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1260)
**Kind**: Design / Specification
**Status**: Design delivered (awaiting implementation phases)
**Version**: 1.0
**Last updated**: 2026-05-03

---

## 1. Motivation and Scope

### 1.1 Prior-Art Pressures

ZFS and Ceph are prior-art inputs for this node lifecycle design, not evidence
for a current TideFS operational-superiority claim. ZFS is single-system, while
Ceph has OSD drain/decommission workflows with multiple operator-visible steps
such as reweighting, waiting for backfill, and marking OSDs out.

The TideFS design target is a unified node lifecycle that:
- Is a single `tidefsctl node drain <node>` command
- Supports cancellation and progress reporting
- Integrates with the resource governor to throttle impact
- Drains all resources (leases, data, cache, admin role) in one coordinated flow

### 1.2 Scope

This design covers:
- Node state machine (5 states)
- Staged drain protocol (5 stages)
- Drain cancellation semantics
- Forced fencing for node failures
- Optional cluster rebalance after topology changes
- Observability surface (CLI commands, events, metrics)
- Error handling and crash resilience
- Integration with companion issues

Out of scope:
- Device-level drain (#1254, independent concern)
- Pool topology reconfiguration
- Client mount migration (clients reconnect naturally)

---

## 2. Node State Machine

### 2.1 States

```
NodeStateV1:
  ACTIVE          # fully participating in the cluster
  DRAINING        # graceful drain in progress, no new work accepted
  DRAINED         # drain complete, safe to shut down
  DECOMMISSIONED  # permanently removed from cluster
  FENCED          # forcibly removed (failure, partition)
```

### 2.2 State Transitions

```
         ┌──────────────────────────────────────────────┐
         │                                              │
         ▼                                              │
     ┌────────┐    drain start     ┌──────────┐        │
     │ ACTIVE │──────────────────▶│ DRAINING  │        │
     └────────┘                    └──────────┘        │
         ▲                              │               │
         │                              │ drain complete│
         │    cancel drain              ▼               │
         │                        ┌──────────┐         │
         │◄───────────────────────│ DRAINED  │         │
         │                        └──────────┘         │
         │                              │               │
         │                              │ decommission  │
         │                              ▼               │
         │                        ┌───────────────┐     │
         │                        │ DECOMMISSIONED│     │
         │                        └───────────────┘     │
         │                                              │
     ┌────────┐    heartbeat timeout / explicit fence   │
     │ FENCED │◄────────────────────────────────────────┘
     └────────┘
```

### 2.3 State invariants

| State | Accepts work | Holds leases | In membership | Recoverable |
|-------|-------------|-------------|---------------|-------------|
| ACTIVE | Yes | Yes | Yes | N/A |
| DRAINING | No (rejects new) | Yes (transferring) | Yes | Yes (cancel) |
| DRAINED | No | No | Yes (observer) | No |
| DECOMMISSIONED | No | No | No | No |
| FENCED | No | No (revoked) | No (evicted) | Yes (rejoin) |

---

## 3. Staged Drain Protocol

The drain protocol executes in five sequential stages. Each stage must complete (or be skipped if no applicable resources) before advancing to the next.

### 3.1 Stage 1: Reject New Work

**Scope**: Prevent the node from taking on new responsibilities while existing work continues.

Actions:
- Stop accepting new **writer lease grants** (respond with `DRAINING` status to lease requests)
- Stop accepting **admin mutation proxying** (redirect clients to other ADMIN-capable nodes)
- Stop accepting new **client mounts** (return `DRAINING` to mount requests)
- Stop accepting new **block volume exports**
- Existing leases and mounts continue operating normally

Gate: All new-work rejection hooks are armed. Existing load is unaffected.

### 3.2 Stage 2: Hand Off Leases

**Scope**: Transfer all held leases to healthy peers.

For each dataset with **EXCLUSIVE writer lease** on this node:
1. Select target node (least-loaded, or admin-specified via `--target-node`)
2. Flush all dirty state (intent log drain, commit_group commit)
3. Transfer lease to target node via LOCK service (#1248)
4. Target node takes over writer role and acknowledges

For each **SHARED reader lease**: simply drop the lease (readers are stateless).

Progress model:
- Lease transfer per dataset, reported via ADMIN job model (#1243)
- Cursor-driven per #1239: `(dataset_count, current_dataset_uuid, lease_type)`

Gate: Zero leases held on the draining node.

### 3.3 Stage 3: Evacuate Pinned Resources

**Scope**: Relocate resources that are pinned to this node to peers.

Resources to evacuate:
- **DDT shards** (#1255): reassign ownership to peers. Any in-flight dedup hits are lost but acceptable.
- **FlashTier contents** (#1256): optionally bulk-transfer to peers (admin choice via `--flash_tier-policy=[transfer|discard]`). Default: discard.
- **Derived view refresh responsibility** (#1240): reassign refresh scheduling to other nodes.

Progress model:
- Per-resource evacuation, cursor-driven per #1239
- DDT: `(shard_count, current_shard_id, target_node)`
- FlashTier: `(bytes_total, bytes_transferred)` or `(bytes_discarded)`
- Derived views: `(view_count, current_view_id)`

### 3.4 Stage 4: Verify Quorum Safety

**Scope**: Ensure cluster remains healthy after this node departs.

Checks:
1. Remaining nodes form a valid quorum (majority of configured cluster size - 1)
2. All datasets have at least one readable copy accessible from remaining nodes
3. No data loss: all extent shards are accessible from remaining nodes
4. Redundancy check per #1249: if redundancy is configured, verify rebuild capacity

If quorum would be lost:
- Drain is **blocked**
- Requires admin override: `--force` flag skips quorum check (⚠️ risk of split-brain)
- Admin is warned about reduced fault tolerance

Gate: All four checks pass, or `--force` flag is set.

### 3.5 Stage 5: Final State Commit

**Scope**: Persist the DRAINED state to cluster membership.

Actions:
1. Node state committed to cluster membership (#1209) as `DRAINED`
2. All remaining nodes acknowledge the state change (quorum write)
3. ADMIN event emitted: `DRAIN_COMPLETE`
4. Draining node may now shut down gracefully

Gate: Raft-backed membership write acknowledged by quorum.

---

## 4. Drain Cancellation

### 4.1 Semantics

- Admin can cancel drain at **any stage** before `DECOMMISSIONED`
- Leases are **NOT** automatically transferred back (would be disruptive to new owners)
- Cancel just stops the drain process; node returns to `ACTIVE`
- Already-transferred leases stay with their new owners
- Node re-enters scheduler rotation and starts accepting new work again

### 4.2 Cancellation flow

```
tidefsctl node drain-cancel <node>
  → ADMIN job cancelled (#1243)
  → In-progress stage aborted at next safe checkpoint
  → Node state: DRAINING → ACTIVE
  → ADMIN event: DRAIN_CANCELLED
```

### 4.3 Partial drain state

After cancellation, the node may have fewer leases/resources than before drain started. This is expected and acceptable. The node functions normally with whatever resources remain assigned to it. If admin wants to rebalance leases back, they use `tidefsctl cluster rebalance`.

---

## 5. Forced Fencing

### 5.1 Trigger conditions

A node is forcibly fenced when:
- **Heartbeat timeout**: Node misses N consecutive heartbeats (configurable, default N=3, interval=2s → 6s timeout)
- **Explicit fence**: Admin issues `tidefsctl node fence <node>` (emergency override)
- **Partition detected**: Membership layer detects split-brain risk and fences minority partition

### 5.2 Fencing sequence

1. Membership marks node as `FENCED` in cluster state (#1209)
2. FENCING event emitted on ADMIN stream
3. All leases held by fenced node are **revoked** (LOCK service #1248 issues lease revocation)
4. Fenced node's DDT shards are reassigned to peers (may lose some dedup state — acceptable tradeoff)
5. Extent availability assessment:
   - If **redundancy available** (#1249): dataset becomes `DEGRADED`, background rebuild starts immediately
   - If **no redundancy**: dataset becomes `READONLY` or `UNAVAILABLE`
6. Background rebuild starts per #1249 recovery loops

### 5.3 Fenced node recovery

A fenced node may rejoin:
1. Node restarts and discovers it was fenced (membership state check)
2. Node performs full state reset (discards stale leases, DDT shards, cache)
3. Node rejoins as a new member (fresh join protocol per #1209)
4. Node enters `ACTIVE` state and participates normally

### 5.4 Safety properties

- Fencing is **irreversible at the fencing node**: once FENCED, the node's state is discarded
- Fencing is **committed by quorum**: at least majority of remaining nodes must agree
- Fencing cannot be accidentally triggered by transient network blips (heartbeat grace period)
- Two nodes cannot simultaneously fence each other (epoch-based tie-breaking per #1209)

---

## 6. Cluster Rebalance

### 6.1 When rebalancing is needed

Node drain/decommission can trigger rebalancing when:
- Data distribution becomes uneven after a node departs
- Capacity imbalance exceeds threshold (default: 20% deviation from mean)
- Admin explicitly requests rebalance: `tidefsctl cluster rebalance`

### 6.2 Rebalancing constraints

- Rebalancing is **optional**, not required for drain to complete
- Runs in **BACKGROUND lane** (#1241) to avoid impacting foreground I/O
- Uses **BULK plane** (#1229) for data movement
- **Cursor-driven** per #1239 for bounded, resumable operation

### 6.3 Rebalance algorithm (high-level)

1. Calculate per-node capacity utilization across the cluster
2. Identify over-utilized and under-utilized nodes
3. Generate extent migration plan (source → destination)
4. Execute migrations in BULK plane with rate limiting
5. Update extent locator tables (#1287) after each migration batch
6. Repeat until balance is within threshold

### 6.4 Progress and cancellation

- ADMIN job model (#1243): `tidefsctl cluster rebalance-status`
- Cursor tracks: `(total_extents, migrated_count, current_extent_id)`
- ETA computed from migration rate and remaining extent count
- Cancellable at any cursor checkpoint

---

## 7. Integration with Companion Issues

| Issue | Relationship |
|-------|-------------|
| #1209 (Membership) | State machine commit target; node registration and mount tracking |
| #1248 (Distributed Lock Service) | Lease transfer target; lease revocation on fence |
| #1243 (ADMIN job model) | Drain/fence/rebalance operations initiated via ADMIN; job progress reporting |
| #1239 (Cursor framework) | Staged progress tracking for drain/rebalance |
| #1241 (Scheduling lanes) | Drain in CONTROL lane; rebalance in BACKGROUND lane |
| #1229 (BULK plane) | Lease state transfer; data movement for rebalance |
| #1249 (Redundancy/rebuild) | Automatic rebuild after fencing |
| #1254 (Pool topology) | Independent device-level management |
| #1255 (DDT shards) | DDT ownership reassignment during drain/fence |
| #1256 (FlashTier) | Cache transfer/discard policy during drain |
| #1240 (Derived views) | Refresh responsibility reassignment |
| #1287 (Checksum/extent locators) | Extent locator updates during rebalance |
| #1174 (Trace oracle) | Observability events for lifecycle transitions |

---

## 8. Observability

### 8.1 CLI Commands

```
tidefsctl node status [<node>]          # state, drain progress, held leases
tidefsctl node drain <node> [--target-node <n>] [--flash_tier-policy transfer|discard] [--force]
tidefsctl node drain-status <node>      # per-stage progress, ETA
tidefsctl node drain-cancel <node>      # cancel in-progress drain
tidefsctl node fence <node>             # emergency forced fencing
tidefsctl node decommission <node>      # finalize drained node removal
tidefsctl cluster rebalance [--threshold <pct>]
tidefsctl cluster rebalance-status
```

### 8.2 ADMIN Events (emitted on event stream per #1243)

| Event | Stage trigger | Payload |
|-------|--------------|---------|
| `DRAIN_STARTED` | Stage 1 begins | `{node_id, target_node, flash_tier_policy, force}` |
| `STAGE_PROGRESS` | Per-stage advancement | `{node_id, stage, progress_cursor}` |
| `LEASE_TRANSFERRED` | Each lease handoff | `{node_id, dataset_uuid, target_node, lease_type}` |
| `RESOURCE_EVACUATED` | Each resource type done | `{node_id, resource_type, count}` |
| `DRAIN_COMPLETE` | Stage 5 committed | `{node_id, total_duration_ms, leases_transferred, resources_evacuated}` |
| `DRAIN_CANCELLED` | Cancellation complete | `{node_id, stage_reached, leases_transferred}` |
| `DRAIN_BLOCKED` | Quorum check failed | `{node_id, reason, remaining_nodes_count}` |
| `FENCING_STARTED` | Fence triggered | `{node_id, trigger}` |
| `FENCING_COMPLETE` | Fence committed | `{node_id, leases_revoked, rebuild_required}` |
| `FENCED_NODE_REJOIN` | Fenced node rejoins | `{node_id, new_member_id}` |
| `REBALANCE_STARTED` | Rebalance begins | `{threshold, total_extents}` |
| `REBALANCE_BATCH` | Each migration batch | `{batch_id, extents_migrated, bytes_moved}` |
| `REBALANCE_COMPLETE` | Rebalance finishes | `{total_extents_migrated, total_bytes_moved, duration_ms}` |

### 8.3 Metrics

Prometheus-style metrics exposed on the node metrics endpoint:

| Metric | Type | Description |
|--------|------|-------------|
| `tidefs_node_state` | Gauge | Current node state (enum: 0=ACTIVE, 1=DRAINING, 2=DRAINED, 3=DECOMMISSIONED, 4=FENCED) |
| `tidefs_drain_leases_remaining` | Gauge | Leases still held during drain |
| `tidefs_drain_stage` | Gauge | Current drain stage (1-5) |
| `tidefs_drain_progress_pct` | Gauge | Overall drain progress (0.0-1.0) |
| `tidefs_rebalance_extents_remaining` | Gauge | Extents remaining to migrate |
| `tidefs_rebalance_bytes_total` | Counter | Total bytes migrated during rebalance |
| `tidefs_fencing_events_total` | Counter | Total fencing events (by trigger type) |

---

## 9. Error Handling

### 9.1 Error codes

| Code | Name | Description |
|------|------|-------------|
| `NLC001` | `DRAIN_IN_PROGRESS` | Cannot start drain; another drain is active on this node |
| `NLC002` | `NOT_ACTIVE` | Node is not in ACTIVE state; cannot drain |
| `NLC003` | `QUORUM_LOSS_RISK` | Drain would cause quorum loss; use `--force` to override |
| `NLC004` | `DATA_LOSS_RISK` | Drain would cause data loss; additional redundancy needed |
| `NLC005` | `LEASE_TRANSFER_FAILED` | A lease transfer failed; drain blocked at Stage 2 |
| `NLC006` | `TARGET_NODE_UNHEALTHY` | Specified target node is not healthy |
| `NLC007` | `FENCING_ALREADY_IN_PROGRESS` | Cannot fence; another fencing operation is active |
| `NLC008` | `REBALANCE_IN_PROGRESS` | Cannot start rebalance; another rebalance is active |
| `NLC009` | `NODE_NOT_FOUND` | Specified node is not a known member |
| `NLC010` | `CANCEL_NOT_DRAINING` | Cannot cancel; node is not in DRAINING state |

### 9.2 Crash resilience

If the draining node crashes mid-drain:
- Membership layer detects node failure (heartbeat timeout)
- Remaining nodes see the node transition from `DRAINING` → `FENCED` (crash = implicit fence)
- Fencing sequence triggers automatically
- Any leases that were not yet transferred are revoked
- In-progress drain state is lost; admin must restart drain on node rejoin or decommission the fenced node

If a target node (lease recipient) crashes during Stage 2:
- Lease transfer to that target is aborted
- Alternative target is selected
- Overall drain continues

---

## 10. Tradeoffs

### 10.1 Lease non-reversibility on cancel
**Tradeoff**: Drain cancellation leaves leases on new owners, creating asymmetry.
**Rationale**: Transferring leases back would require a second flush-and-transfer cycle, doubling the disruption. Nodes already handling the lease can continue doing so. If balance matters, admin runs rebalance.

### 10.2 DDT partial-loss on fence
**Tradeoff**: Forced fencing may lose in-flight DDT state.
**Rationale**: Replicating every DDT write synchronously to peers would add write latency. DDT is a dedup hint, not a correctness dependency. Lost DDT state means some blocks may be stored non-deduplicated temporarily. Acceptable for failure scenarios.

### 10.3 FlashTier discard default
**Tradeoff**: Default FlashTier policy is `discard`, not `transfer`.
**Rationale**: FlashTier is read cache, not durable data. Bulk-transferring cache contents over the network may cause more load than simply repopulating from primary storage. Admin can opt-in to transfer for large, slow-to-warm caches.

### 10.4 Synchronous quorum check
**Tradeoff**: Quorum safety check (Stage 4) is synchronous and can block drain.
**Rationale**: Allowing drain that breaks quorum would compromise cluster safety. The `--force` flag provides an escape hatch for informed operators who accept the risk.

---

## 11. Implementation Plan

### 11.1 Phase breakdown

| Phase | Description | Depends on | Testing gate |
|-------|-------------|-----------|--------------|
| 1 | `NodeStateV1` type + membership integration | #1209 | Unit tests on state transitions |
| 2 | Stage 1 (Reject new work) | Phase 1, #1248 | Integration: drain start blocks new leases |
| 3 | Stage 2 (Hand off leases) | Phase 2, #1248, #1229 | Integration: lease transfer completes without data loss |
| 4 | Stages 3-5 (Evacuate, Verify, Commit) | Phase 3, #1255, #1256, #1240, #1239 | Full drain integration test |
| 5 | Forced fencing | Phase 1, #1248, #1249 | Chaos: kill node, verify rebuild |
| 6 | Drain cancellation | Phase 4 | Integration: cancel mid-drain, verify node recovers |
| 7 | Cluster rebalance | #1229, #1241, #1239, #1287 | Integration: rebalance after 3→2 node drain |
| 8 | CLI + observability | All phases | End-to-end: tidefsctl drain → status → complete |

### 11.2 Testing strategy

- **Unit tests**: State machine transitions, drain stage logic, error mapping
- **Integration tests**: Two-node drain, three-node drain with quorum, cancellation
- **Chaos tests**: Kill node mid-drain, verify automatic fencing + rebuild
- **Performance tests**: Drain duration vs dataset count, lease count
- **Regression tests**: Drain must not affect I/O to non-draining nodes

---

## 12. Data Structures

### 12.1 NodeStateV1 (in `tidefs-types-membership-core`)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum NodeStateV1 {
    Active = 0,
    Draining = 1,
    Drained = 2,
    Decommissioned = 3,
    Fenced = 4,
}
```

### 12.2 DrainJobV1 (in `tidefs-types-admin-service-core`)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrainJobV1 {
    pub node_id: NodeId,
    pub target_node: Option<NodeId>,
    pub flash_tier_policy: FlashTierPolicy,
    pub force: bool,
    pub started_at: Timestamp,
    pub current_stage: DrainStage,
    pub progress: DrainProgress,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DrainStage {
    RejectingWork,
    HandingOffLeases,
    EvacuatingResources,
    VerifyingQuorum,
    Committing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrainProgress {
    pub leases_total: u32,
    pub leases_transferred: u32,
    pub ddt_shards_total: u32,
    pub ddt_shards_evacuated: u32,
    pub flash_tier_bytes_total: u64,
    pub flash_tier_bytes_evacuated: u64,
    pub views_total: u32,
    pub views_reassigned: u32,
}
```

### 12.3 FlashTierPolicy

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlashTierPolicy {
    Discard,   // Default: drop cache contents
    Transfer,  // Bulk-transfer to peers
}
```

---

## 13. Wire Protocol Extensions

### 13.1 ADMIN method additions (per #1243)

```
AdminMethod:
  // existing...
  NODE_DRAIN            = 0x20  // DrainJobV1
  NODE_DRAIN_STATUS     = 0x21  // NodeId → DrainStatus
  NODE_DRAIN_CANCEL     = 0x22  // NodeId
  NODE_FENCE            = 0x23  // NodeId
  NODE_DECOMMISSION     = 0x24  // NodeId
  CLUSTER_REBALANCE     = 0x25  // RebalanceRequestV1
  CLUSTER_REBALANCE_STATUS = 0x26  // → RebalanceStatusV1
```

### 13.2 LOCK service additions (per #1248)

```
LockMethod:
  // existing...
  LEASE_TRANSFER_PREPARE = 0x10  // Prepare target for lease takeover
  LEASE_TRANSFER_COMMIT  = 0x11  // Commit lease transfer
  LEASE_TRANSFER_ABORT   = 0x12  // Abort in-progress transfer
  LEASE_REVOKE_ALL       = 0x13  // Revoke all leases for fenced node
```

---

## 14. Safety and Liveness

### 14.1 Safety properties

- **No two nodes hold same writer lease**: Lease transfer is atomic via #1248 two-phase commit
- **Quorum integrity**: Stage 4 blocks unless quorum is preserved (or `--force`)
- **Fencing is committed**: Fence state is written by quorum before revocation
- **No silent data loss**: Redundancy check in Stage 4 catches missing extent replicas

### 14.2 Liveness properties

- **Drain always makes progress or fails clearly**: Each stage has bounded work (finite leases, finite resources)
- **Drain is not stuck on unreachable target**: Failed lease transfers select alternative targets
- **Fencing has bounded latency**: Heartbeat timeout drives automatic fencing (default ~6s)
- **Rebalance is optional and bounded**: Cursor-driven; can be cancelled; no impact on foreground I/O

### 14.3 Failure mode summary

| Failure | Behavior | Recovery |
|---------|----------|----------|
| Draining node crashes | Auto-fence → revoke leases → rebuild | Admin drains remaining node or lets it rejoin |
| Target node crashes during Stage 2 | Alternative target selected | Drain continues |
| Network partition during drain | Heartbeat loss → fence minority side | Partition heals → fenced nodes rejoin |
| Quorum loss risk detected | Stage 4 blocks with error | Admin must add nodes or use `--force` |
| All nodes drain simultaneously | Last draining node cannot pass Stage 4 | Blocked; admin must add nodes or cancel some drains |

---

## 15. Documentation and Closeout

### 15.1 Affected documentation

The imported delivery plan originally targeted deleted status/matrix docs.
Treat those targets as historical residue, not current closeout instructions:

- Historical plan residue: `docs/STATUS.md` design-delivery entry and
  `docs/FEATURE_MATRIX.md` node-lifecycle row were old closeout targets and
  must not be recreated or updated for this design.
- Current coordination and evidence surfaces: GitHub issues and pull requests
  record implementation follow-up and validation evidence. Broader TFR-019
  documentation-authority classification belongs in
  `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`, not this design closeout note.

### 15.2 Residual risk

This is a design-only deliverable; no runtime risk. Implementation risks:
- DDT partial-loss semantic during fencing needs careful verification (Phase 5)
- FlashTier transfer policy may cause unexpected network load if misused
- `--force` flag can cause data loss if used without redundancy (#1249) configured

### 15.3 Future design extensions

Not in scope for this design but noted for future:
- Staged drain with graceful workload shedding (throttle I/O before full rejection)
- Node hibernation (preserve state without active participation)
- Automated drain on predictive failure (SMART thresholds)
- Multi-node simultaneous drain orchestration

---

## References

- #1209: Cluster membership and node registration
- #1248: Distributed lock service (leases)
- #1243: ADMIN service and job model
- #1239: Cursor framework
- #1241: Scheduling lanes (CONTROL, BACKGROUND)
- #1229: BULK plane
- #1249: Redundancy and rebuild
- #1254: Pool topology (device-level management)
- #1255: DDT shards
- #1256: FlashTier
- #1240: Derived views
- #1287: Checksum architecture and extent locators
- #1174: Trace oracle (observability)
