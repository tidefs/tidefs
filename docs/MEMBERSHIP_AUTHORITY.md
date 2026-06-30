# Membership Authority

**Status**: Decision record
**Issue**: [#750](https://github.com/tidefs/tidefs/issues/750)
**Date**: 2026-06-21
**TFR link**: TFR-017 (transport/cluster authority), TFR-019 (documentation authority)

## Purpose

Multiple membership and quorum crates exist (`tidefs-membership-epoch`,
`tidefs-membership-live`, `tidefs-membership-types`, `tidefs-quorum-write`,
`tidefs-quorum-write-runtime`, `tidefs-witness-set`) and design docs
(`docs/MEMBERSHIP_SERVICE_DESIGN.md`,
`docs/MEMBERSHIP_CONFIG_QUORUM_SET_IDENTITY_OW302B.md`,
`docs/MEMBERSHIP_PLACEMENT_FAILURE_DOMAIN_MODEL_P8-02.md`), but no single
document names the authority owner for membership epoch identity,
quorum-write dispatch, witness-set evidence, and the cluster join/leave
lifecycle.

This record decides the single membership epoch authority owner, the
quorum-write dispatch model, the node-join and node-drain lifecycle
integration with membership epoch and witness-set, and the
membership/transport boundary. It names the single membership authority
owner and maps follow-up implementation issues with expected write sets.

## Evidence reviewed

- `docs/MEMBERSHIP_SERVICE_DESIGN.md` — membership service design
- `docs/MEMBERSHIP_CONFIG_QUORUM_SET_IDENTITY_OW302B.md` — quorum-set
  identity spec
- `docs/MEMBERSHIP_PLACEMENT_FAILURE_DOMAIN_MODEL_P8-02.md` — membership,
  placement, and failure-domain law
- Deleted transport boundedness lineage — historical input in git history
- `docs/TRANSPORT_CLUSTER_AUTHORITY.md` and #672 (closed) — transport/cluster
  authority boundary decision
- `docs/REVIEW_TODO_REGISTER.md` TFR-017 and TFR-019 entries
- #913 / PR #840 storage-intent evidence-query snapshot dependency note:
  downstream storage-intent consumers need membership evidence producer,
  freshness, source-index, snapshot, and refusal refs for replayable evidence
  cuts
- `crates/tidefs-membership-epoch/` — deterministic membership model (5971
  line lib.rs): defines `EpochId`, `EpochCounter`, `MembershipEpoch`,
  `EpochStateMachine`, `EpochTransitionBarrier`, `EpochToken`,
  `DatasetMountIdentity`, `AuthorityDomainId`, membership config epoch
  synthesis, cohort population, authority-home derivation, and transition
  evaluation
- `crates/tidefs-membership-live/` — live membership runtime: SWIM failure
  detection, 3-phase epoch transitions, heartbeat protocol, epoch fence
  enforcement, coordinator promotion
- `crates/tidefs-membership-types/` — wire protocol types for service 0x02:
  `no_std` binary encode/decode with CRC32C checksums
- `crates/tidefs-quorum-write/` — deterministic 4-phase quorum write model:
  PREPARE-TRANSFER-COMMIT-WITNESS with 3 durability modes
- `crates/tidefs-quorum-write-runtime/` — runtime quorum-write coordinator:
  integrates TDMA slot allocation, epoch-gated lease acquisition, and
  BLAKE3-verified quorum dispatch
- `crates/tidefs-witness-set/` — deterministic witness set for quorum ack
  tracking: epoch-scoped, quorum-threshold gating
- `crates/tidefs-cluster/` — cluster membership lease authority: slot
  assignment and grant/nack decisions keyed by `EpochId`
- `crates/tidefs-node-join/` — staged join promotion (`Idle →
  JoinRequested → Bootstrapping → CatchingUp → Joining → Joined`) with
  epoch-bound `JoinToken`
- `crates/tidefs-node-drain/` — staged node drain (`DrainRequested →
  DrainingLeases → DrainingData → DrainingCache → DrainingAdmin → Drained`)
  with forced fencing

## Decision

### 1. Membership epoch authority owner: `tidefs-membership-epoch`

`tidefs-membership-epoch` is the single authority owner for membership epoch
identity. It **issues** (`EpochId`, `EpochCounter::new`), **increments**
(`EpochCounter::epoch_advance`, `EpochStateMachine::join`/`leave`/
`increment`), and **validates** (`EpochCounter::validate_token`,
`is_lease_valid`, `EpochTransitionBarrier::acquire`) epoch identity.

The deterministic epoch grammar lives here:
- `EpochId` (opaque monotonic u64)
- `EpochCounter` (monotonic with generation-based fencing via `EpochToken`)
- `MembershipEpoch` (epoch + member set, with BLAKE3-verified `propose`/
  `advance`)
- `EpochStateMachine` (deterministic join/leave state machine, strictly
  monotonic epoch IDs, never reused)
- `EpochTransitionBarrier` (blocks lease acquisition during transitions)
- `DatasetMountIdentity` (binds lease lifecycle to epoch)

Other crates consume epoch identity from `tidefs-membership-epoch` through
`EpochId` values and `EpochToken` proofs; they never generate epoch
identifiers independently.

`tidefs-membership-live` is the **networked runtime driver**, not the
authority origin. It drives epoch transitions over the wire (SWIM failure
detection, heartbeat protocol, 3-phase transitions), but the epoch model
it operates on is owned by `tidefs-membership-epoch`. When
`tidefs-membership-live` needs to fence a departed peer, it calls
`tidefs-membership-epoch` to advance the epoch; it does not invent epoch
semantics locally.

`tidefs-cluster::LeaseAuthority` consumes `EpochId` for lease grant/nack
decisions and rejects cross-epoch requests, but it originates neither
epoch identity nor epoch-fencing policy.

### 2. Quorum-write dispatch model

The quorum-write dispatch follows a layered ownership model:

**Quorum-set decision** is owned by `tidefs-membership-epoch`. The quorum
set for a write is the alive voters in the current committed membership
epoch. `tidefs-quorum-write-runtime::QuorumWriteCoordinator` receives
the alive voter list via `sync_targets_from_membership(&mut self,
alive_voters: &[MemberId])` and passes target node IDs into the
`tidefs-quorum-write` protocol. The coordinator does not independently
decide which nodes constitute a quorum.

**Witness-set evidence** gates quorum satisfaction through
`tidefs-witness-set`. The `WitnessSet` tracks per-operation
acknowledgments scoped to the current epoch (`advance_epoch` clears all
pending acks, preventing stale-epoch acks from satisfying quorum). The
`QuorumThreshold` configuration (`StrictMajority`, `SuperMajority`, or
`Exact`) determines when enough witnesses have acknowledged. The
witness-set is consulted after quorum dispatch to decide whether the
operation reached quorum (`WitnessSet::has_quorum`). The write
coordinator integrates this:
1. Acquire TDMA slot (epoch-gated)
2. Validate slot grant (BLAKE3 token, staleness, epoch match)
3. Acquire write lease (epoch-gated)
4. Dispatch quorum write via `QuorumWriteRuntime::execute_write`
5. Collect acks into witness-set
6. Gate commit/abort on `WitnessSet::has_quorum`

The `tidefs-witness-set` crate is the authority for witness-set
membership and quorum-satisfaction gating. The write coordinator is the
integration point that wires epoch identity, quorum dispatch, and
witness-set evidence together.

**Witness-set membership** is derived from the current membership epoch:
only voter-class members are eligible witnesses. The witness-set
consumes `tidefs-membership-epoch` for the epoch-scoped member list.

### 3. Node-join and node-drain lifecycle integration

**Node-join** (`tidefs-node-join`) integrates with membership epoch as
follows:
- `JoinToken` carries an `Option<EpochId>` binding so stale tokens from
  prior epochs cannot authorize join into the current epoch
- `NodeJoinState::Joining` proposes a membership epoch transition
  (`EpochStateMachine::join`) to include the new node as a learner
- After catch-up, a second epoch transition promotes the learner to
  voter through a joint-consensus config epoch (`c2.joint` in the P8-02
  model)
- The join lifecycle consumes epoch identity from
  `tidefs-membership-epoch`; it does not issue epochs

**Node-drain** (`tidefs-node-drain`) integrates with membership epoch as
follows:
- `DrainStage` transitions through lease release, data migration, cache
  invalidation, and admin-role transfer
- Forced fencing (`forced_fencing.rs`) advances the epoch to evict the
  drained node, using `tidefs-membership-epoch`'s epoch-advance
  mechanism
- The epoch gate (`epoch_gate.rs`) ensures drain operations complete
  before the epoch advances past the draining node's membership window
- The drain lifecycle consumes `tidefs-membership-epoch` for epoch
  identity and fencing; it does not issue epochs

Both `tidefs-node-join` and `tidefs-node-drain` depend on
`tidefs-membership-epoch` in their `Cargo.toml`. The membership epoch is
the central authority that both join and drain integrate with, not a
peer they negotiate with.

### 4. Membership/transport boundary

The membership/transport boundary was decided in #672
(`docs/TRANSPORT_CLUSTER_AUTHORITY.md`). This document reaffirms that
boundary and extends it with the membership-side ownership decided here.

**Transport** (`tidefs-transport`) owns:
- Session admission mechanics (`connection_admission`,
  `peer_admission`): accepting or rejecting inbound connections
- Send backpressure mechanics (`send_backpressure`, `send_scheduler`):
  per-priority watermarks, queue-depth accounting, weighted-fair-queue
  scheduling
- Frame-level accounting, dedup, per-connection bounds

**Membership** (authority: `tidefs-membership-epoch`; runtime:
`tidefs-membership-live`) owns:
- Epoch generation and monotonic advancement
- Committed roster membership (which nodes are voters, learners,
  witnesses, or quarantined)
- Fencing decisions: which peers are evicted, drained, or failed
- Session admission gate: whether a connecting peer is in the current
  roster (transport enforces mechanically via `AdmissionGate`)

Transport enforces membership decisions through narrow typed interfaces:
- `AdmissionGate` (rejects connections from non-members)
- `EpochFence` (re-evaluates active connections after epoch advance)
- `EpochBarrier` (stamps outbound messages with epoch; rejects stale
  inbound)
- `MembershipSessionGuard` (tears down sessions to departed peers)
- `SendGate` (blocks outbound sends to non-roster peers)

Transport never originates roster, epoch, or fencing choices.

### 5. Single membership authority owner

`tidefs-membership-epoch` is the single membership authority owner. Its
responsibilities span:

| Surface | Mechanism |
|---------|-----------|
| Epoch identity issuance | `EpochId::new`, `EpochCounter::new` |
| Epoch increment | `EpochCounter::epoch_advance`, `EpochStateMachine::join`/`leave`/`increment` |
| Epoch validation | `EpochCounter::validate_token`, `is_lease_valid` |
| Membership config epoch synthesis | `synthesize_membership_config_epoch_and_quorum_sets` |
| Cohort population | `populate_transport_session_cohorts_from_membership_epoch` |
| Authority-home derivation | `derive_authority_home_and_failover_successor_candidates` |
| Transition evaluation | `evaluate_transition_catchup_and_readiness` (via `MembershipEpochDriver`) |
| Split-brain hazard law | `SplitBrainHazardRecord` and `MembershipPlacementVerdictRecord` |
| Quorum-set definition | `MembershipConfigRecord` with old-voter/new-voter quorum sets |
| Fence epoch enforcement | `EpochTransitionBarrier`, `EpochAdvanceError` |
| Lease-epoch gating | `is_lease_valid`, `DatasetMountIdentity` |

All other crates that touch membership are consumers: `tidefs-cluster`
consumes `EpochId` for lease decisions; `tidefs-quorum-write-runtime`
consumes `EpochId` and `MemberId` for write dispatch; `tidefs-witness-set`
consumes epoch-scoped member lists; `tidefs-node-join` and
`tidefs-node-drain` consume epoch identity for lifecycle transitions;
`tidefs-transport` enforces epoch-fence decisions mechanically without
originating them.

### Storage-intent and recovery evidence boundary

Storage-intent policy (#839 / PR #840) and recovery/degradation policy (#900)
consume membership evidence from this authority record. They must not recompute
membership, infer a parallel quorum set, or treat transport/session success as
membership proof.

The membership authority exports the following decision boundaries for
downstream records and predicates:

- `membership_epoch_ref`: the committed `EpochId` plus `EpochToken` proof from
  `tidefs-membership-epoch`.
- `committed_roster_identity`: the `MembershipEpoch`/`MembershipConfigRecord`
  roster that classifies voters, learners, witnesses, quarantined peers,
  draining peers, and fenced peers.
- `failure_domain_binding`: the membership/failure-domain binding from the
  committed epoch model and P8-02 placement law.
- `quorum_set_identity`: the old-voter/new-voter quorum sets in
  `MembershipConfigRecord`, reduced for a write to alive voters in the
  committed epoch.
- `participant_role`: whether a peer is eligible as a voter witness, a learner,
  a witness-only participant, a data-bearing storage participant, quarantined,
  draining, or fenced. Storage-intent consumers must not count witness-only,
  quarantined, fenced, or draining peers as durable data/intent replicas.
- `join_drain_fence_state`: epoch-scoped join, drain, and fence state, including
  `JoinToken` epoch binding and `EpochTransitionBarrier`-guarded drain fencing.
- `epoch_freshness_state`: stale, future, forked, or missing epoch evidence.
  These states fail closed unless the consuming storage policy explicitly
  produces a degraded-visible refusal or degraded-visible read state.
- `split_brain_hazard_state`: `SplitBrainHazardRecord` and
  `MembershipPlacementVerdictRecord` evidence for partition or topology drift.
- `receipt_epoch_binding`: the epoch/quorum-set evidence a storage receipt
  claims to have satisfied. Membership supplies the epoch/quorum/fence proof;
  storage-intent and receipt authority decide whether the receipt satisfies the
  requested policy.

When recovery or degraded reads lack current membership epoch, quorum-set,
participant-role, fence/drain, or split-brain evidence, the consuming policy
must return a typed refusal or degraded-visible state. It must not convert stale,
under-width, partition-ambiguous, witness-only, fenced, or draining evidence
into ordinary durable success.

### Storage-intent evidence-query snapshot boundary

Storage-intent evidence-query snapshots (#913 / PR #840) are downstream
consumers of membership evidence. Membership authority does not originate the
storage-intent query snapshot; it exports membership-family refs that #913 can
include in a bounded, replayable evidence cut:

- `membership_evidence_producer_ref`: the membership evidence producer identity,
  including `tidefs-membership-epoch` and the current producer generation for
  epoch, roster, quorum-set, fence, drain, and split-brain evidence.
- `membership_evidence_source_index_ref`: the source index or catalog frontier
  that supplied the membership evidence, so a consumer can replay, audit, or
  invalidate the exact roster/quorum/fence cut it used.
- `membership_evidence_freshness_frontier`: freshness and staleness bounds for
  membership epoch, roster, quorum-set, participant-role, fence/drain, and
  split-brain evidence, including missing, stale, forked, superseded, refused,
  or contradictory evidence states.
- `membership_evidence_snapshot_ref`: the membership-family refs carried inside
  a `StorageIntentEvidenceQuerySnapshot` or its typed query refusal.

Storage-intent consumers must treat a missing, refused, stale, contradictory,
or incomplete #913 snapshot/refusal ref as blocked, refused, unknown-evidence,
or degraded-visible according to the compiled policy. They must not rebuild a
membership cut from live scans, cache-local state, mixed-policy indexes, or
transport session state. If future membership-side logic consumes
storage-intent evidence, it must carry the #913 snapshot/refusal ref into its
decision instead of treating current storage-intent records as ambient truth.

### Policy-rollout and tenant-isolation evidence boundary

Storage-intent policy rollout (#901) and tenant/budget isolation (#902) are
downstream consumers of this membership authority decision. They own policy
revision publication, staged rollout, rollback/re-entry, convergence,
budget-owner identity, resource-vector budgets, noisy-neighbor state, and typed
throttle/refusal evidence. Membership authority does not originate or reinterpret
those records.

This record preserves the membership side of their evidence boundary:

- Policy rollout must carry `membership_epoch_ref`, `quorum_set_identity`,
  `participant_role`, `join_drain_fence_state`, `split_brain_hazard_state`, and
  `receipt_epoch_binding` alongside policy-revision evidence whenever a policy
  change affects writes, reads, repair, rebuild, relocation, geo catch-up,
  receipt retirement, operator explanation, validation, or claims. A rollout
  must not reinterpret an old receipt by looking only at the current policy or
  current membership roster.
- Tenant isolation must carry `committed_roster_identity`,
  `failure_domain_binding`, `participant_role`, `join_drain_fence_state`,
  `epoch_freshness_state`, and `split_brain_hazard_state` alongside
  budget-owner and resource-pressure evidence whenever admission, throttling,
  borrowing, donation, repair, relocation, geo backlog, transport pressure, wear,
  or operator-money budgets can affect another policy owner. Aggregate spare
  capacity or local lane state must not hide a protected tenant, dataset, sync,
  repair, or degraded-read budget violation.
- Policy-rollout and isolation predicates must fail closed or surface visible
  refusal/degraded state when membership evidence is stale, missing, forked,
  witness-only, fenced, draining, partition-ambiguous, or bound to a different
  receipt epoch than the policy decision being evaluated.

Open #901 and #902 are not prerequisites for this docs-only authority record to
land: they remain focused storage-intent follow-up slices with their own write
sets and validation. They consume and preserve the membership refs above instead
of requiring this PR to implement storage-intent rollout or budget-isolation
records.

## Follow-up implementation issues

This decision enables the following focused implementation issues. Each
names a non-overlapping expected write set and does not edit this
authority record except to update the follow-up list.

### 1. membership-epoch: wire epoch-token validation into quorum-write dispatch

Currently `QuorumWriteCoordinator::validate_slot_epoch` checks epoch
match against the slot grant, but the coordinator's own epoch tracking
(`current_epoch`) is set locally via `advance_epoch` without consuming
an `EpochToken` from `tidefs-membership-epoch`. The coordinator should
validate that its epoch was witnessed through the token mechanism.

Write set: `crates/tidefs-quorum-write-runtime/src/quorum_write_coordinator.rs`,
`crates/tidefs-quorum-write-runtime/src/config.rs`.

### 2. witness-set: bind witness membership to membership-epoch voter class

Currently `WitnessSet::add_witness` accepts any `u64` node ID without
classification. It should consume voter-class membership from
`tidefs-membership-epoch` and reject non-voter witnesses.

Write set: `crates/tidefs-witness-set/src/witness_set.rs`,
`crates/tidefs-witness-set/src/types.rs`,
`crates/tidefs-witness-set/Cargo.toml`.

### 3. node-join: require epoch-bound JoinToken with epoch validation

`JoinToken` already has an `Option<EpochId>` field and `with_epoch`
builder, but the join lifecycle does not enforce that the token's epoch
matches the current membership epoch before proceeding to
`Bootstrapping`. The join state machine should validate the token's epoch
against `tidefs-membership-epoch`'s current epoch and reject stale tokens
before bootstrap.

Write set: `crates/tidefs-node-join/src/join_lifecycle.rs`,
`crates/tidefs-node-join/src/handshake.rs`.

### 4. node-drain: gate forced fencing on EpochTransitionBarrier

`forced_fencing.rs` executes drain-fence epoch advance directly. It
should acquire `EpochTransitionBarrier` from `tidefs-membership-epoch`
before advancing the epoch, ensuring no concurrent lease acquisition
during the drain transition window.

Write set: `crates/tidefs-node-drain/src/forced_fencing.rs`,
`crates/tidefs-node-drain/src/epoch_gate.rs`.

### 5. membership-live: epoch-coordinator consumes membership-epoch authority

`tidefs-membership-live/src/epoch_coordinator.rs` currently manages epoch
transitions over the network. It should consume
`tidefs-membership-epoch::EpochStateMachine` (instead of duplicating
epoch logic) so the deterministic model is the single source of truth
for epoch identity and member-set state during live transitions.

Write set: `crates/tidefs-membership-live/src/epoch_coordinator.rs`,
`crates/tidefs-membership-live/src/epoch_fence.rs`.

### 6. membership-types: add epoch-gated wire proofs for membership authority

`tidefs-membership-types` defines CRC32C-checksummed wire types for
service 0x02. `JoinRequestV1` carries an advisory `highest_epoch_seen`
counter and `JoinResponseV1`/`ClusterViewV1` carry epoch fields, but
the join and heartbeat messages do not carry a committed epoch binding
or epoch-token proof from `tidefs-membership-epoch`. Add epoch-gated
wire fields or proof types so receivers can reject stale-epoch messages
at the wire layer.

Write set: `crates/tidefs-membership-types/src/lib.rs`.

## What this decision does not close

- This decision does not close TFR-017. The transport/cluster authority
  gaps named in the register (cross-replica scrub comparison, repair
  authority, distributed transaction authority, cluster pool
  CLI/orchestrator alignment, RDMA hardware validation) remain open and
  are mapped in `docs/TRANSPORT_CLUSTER_AUTHORITY.md`.
- This decision does not implement any of the follow-up issues above;
  each requires its own GitHub issue with acceptance criteria and
  validation evidence.
- This decision does not edit membership, quorum, witness, or transport
  runtime source; it is a documentation/design authority record only.
- This decision does not create present-tense product claims about
  end-to-end quorum correctness, distributed locking, or cluster drain.
  Those claims require the follow-up implementation issues to be
  completed with runtime validation evidence.
