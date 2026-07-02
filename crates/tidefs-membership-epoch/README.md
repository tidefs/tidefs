# tidefs-membership-epoch

Deterministic membership_placement_0 epoch model and failure/rejoin tests.

This README is a crate-local source map. System-wide membership authority,
runtime boundaries, and publishing-facing claim limits live in
[`docs/MEMBERSHIP_AUTHORITY.md`](../../docs/MEMBERSHIP_AUTHORITY.md) and
[`docs/CLAIMS_GATE_POLICY.md`](../../docs/CLAIMS_GATE_POLICY.md); this file is
not evidence for distributed membership availability or persistence.

## Epoch Commit Subscriber Dispatch

The `epoch_commit_subscriber` module provides a multi-subscriber notification bus
so transport subsystems receive structured epoch-transition events without polling.

### Types

- **`EpochCommitSubscriber`** — Trait (`Send + Sync`) with a single method
  `on_epoch_committed(&self, notification: &EpochCommitNotification)`. Transport
  consumers implement this trait to react to roster epoch transitions.

- **`EpochCommitBus`** — Registry supporting `register`, `unregister`, and
  `dispatch_commit`. Uses `RefCell` interior mutability for single-threaded
  use within the epoch-commit path. Subscribers receive every dispatch.

- **`CommittedRoster`** — A committed membership roster with epoch, sorted
  member ids, and a deterministic BLAKE3-256 roster hash for consumer-side
  deduplication.

- **`EpochCommitNotification`** — Dispatch payload carrying epoch, roster hash,
  member set, and a monotonic commit index. Consumers store the last-seen
  index to suppress replayed notifications.

- **`SubscriberId`** — Opaque handle returned by `register` and consumed by
  `unregister`.

### Integration

1. Transport creates an `EpochCommitBus` and registers `EpochCommitSubscriber`
   implementations during initialization.
2. The epoch-commit authority calls `EpochCommitBus::dispatch_commit(epoch, member_ids)`
   when a roster epoch transitions.
3. Each subscriber receives the `EpochCommitNotification` and can react
   (update epoch-gate, adjust admission state, etc.) without polling or
   indirect side-channel signals.

### Intended Consumers

- Transport epoch-gate enforcement can reject stale-epoch connection
  messages by comparing current epoch against the latest notification.
- Transport connection admission control can admit or reject new
  connections based on authoritative roster membership.

## Epoch Agreement Protocol

The `agreement` module implements the wire-level peer-to-peer epoch-agreement
protocol: a coordinator proposes a new epoch, collects peer acknowledgments over
transport, and commits the epoch once a configurable acknowledgement threshold
is reached.

### Types in `tidefs-membership-types`

- **`EpochAgreementProposal`** — A proposal to advance the epoch, carrying
  `epoch_id`, a sorted `view` of member node ids, and the `coordinator_id`.
  No BLAKE3 or MAC overfit: integrity belongs at the transport security
  boundary.

- **`EpochAgreementAck`** — A peer's response to a proposal. Carries `epoch_id`,
  `peer_id`, and an `accepted` flag. Both approvals and rejections are tracked.

- **`EpochAgreementCommit`** — Notification emitted when quorum is reached.
  Carries the committed `epoch_id`.

### MembershipEpochAgreement State Machine

`MembershipEpochAgreement` coordinates the multi-node lifecycle:

1. **Idle** — ready for a new proposal.
2. **Proposing** — `propose()` creates the proposal. In the single-node
   degenerate case (peer_count = 0), commits immediately.
3. **AwaitingAcks** — `broadcast()` signals dispatch to peers. Acks arrive
   via `receive_ack()`. Duplicate acks and wrong-epoch acks are rejected.
4. **Committed** — reached when acceptances meet the quorum threshold.
   `reset()` returns to Idle for the next round.

### Quorum Modes

- **SimpleMajority** — `floor(N/2) + 1` acceptances required (default).
- **Unanimous** — all N peers must accept.
- **Fixed(N)** — exact count of acceptances required.

### Timeout

When `timeout_ms > 0`, `broadcast()` sets a wall-clock deadline. Callers poll
`check_timeout()` and call `abort()` to cancel a stale proposal and return to
Idle.

### Commit Bus Integration

Attach an `EpochCommitBus` via `set_commit_bus()`. On commit, each registered
`EpochCommitSubscriber` receives an `EpochCommitNotification` that transport
consumers can use for epoch-gate enforcement and admission control.

### Protocol Guarantees

- Duplicate proposals (same coordinator_id + epoch_id) are detected and
  rejected.
- Acks targeting the wrong epoch_id are rejected.
- Duplicate acks from the same peer are rejected.
- Timeout aborts return to Idle for retry.

## Epoch Durable Persistence

The `epoch_persistence` module defines pluggable epoch-state persistence with
restart recovery and epoch-chain integrity verification.

### Types

- **`DurableEpochStore`** — Pluggable storage backend trait (`Send + Sync`) with
  `write_epoch`, `read_epoch`, `list_epochs`, and `clear`. This crate provides
  the trait and an `InMemoryDurableStore` for tests; callers provide any
  object-store, intent-log, or other backend outside this crate.

- **`EpochStateStore`** — Persists committed `CommittedRoster` views keyed by
  monotonic epoch number. Exposes `persist_epoch()` to write a roster and
  `load_chain()` to read all rosters in sorted epoch order.

- **`EpochChainLoader`** — Loads the complete epoch chain on restart and
  validates each transition through `EpochChainVerifier`.
  Rejects truncated chains, non-monotonic sequences, gaps, and corrupt
  roster hashes. Returns an empty chain for first-start/bootstrap.

- **`EpochPersistenceHandle`** — Implements `EpochCommitSubscriber` to bridge
  `EpochCommitBus` commit events to writes against the configured store. Every
  committed epoch is passed to the store without caller coordination.
  Persistence failures are logged but non-blocking.

### Serialized Record

Each epoch is stored as a serialized JSON record of `CommittedRoster`:

- **Key**: epoch number (`u64`, monotonic)
- **Value**: `CommittedRoster` with `epoch`, `member_ids` (sorted `Vec<u64>`),
  and `roster_hash` ([u8; 32] BLAKE3-256)

### Restart Recovery Flow

1. `EpochChainLoader::load_and_verify()` calls `EpochStateStore::load_chain()`
   to read all persisted rosters in epoch order.
2. Each roster's internal hash is verified via `CommittedRoster::verify()`.
3. Each consecutive transition is validated through `EpochChainVerifier`,
   ensuring monotonic, gap-free chain integrity.
4. An empty chain (bootstrap) is returned when no rosters exist.
5. After recovery, new epoch commits are automatically persisted by
   `EpochPersistenceHandle` registered with the `EpochCommitBus`.

### Integration

```ignore
use tidefs_membership_epoch::epoch_persistence::{
    EpochStateStore, EpochChainLoader, EpochPersistenceHandle,
    InMemoryDurableStore,
};
use tidefs_membership_epoch::epoch_commit_subscriber::EpochCommitBus;

// Bootstrap
let store = InMemoryDurableStore::new();
let state = EpochStateStore::new(store);
let mut loader = EpochChainLoader::new();
let chain = loader.load_and_verify(&state).unwrap();
assert!(chain.is_empty()); // first start

// Wire persistence to the commit bus
let bus = EpochCommitBus::new();
bus.register(Box::new(EpochPersistenceHandle::new(
    std::sync::Arc::new(state),
)));
```

## Roster Change Validation

The `roster_validation` module provides pre-quorum well-formedness checking for
roster-change proposals, preventing malformed transitions from consuming quorum
rounds and risking partition.

### Types

- **`RosterChangeProposal`** — A proposed roster delta with `added` and
  `removed` peer identifier sets. Duplicates within each set are tolerated
  at construction but flagged by the validator.

- **`RosterChangeValidationRule`** — Enum of six well-formedness rules:
  `AddPeerPresent`, `RemoveAbsentPeer`, `RemoveLastMember`, `EmptyProposal`,
  `DuplicateEntry`, `AddAndRemoveSamePeer`.

- **`RosterChangeValidationError`** — Carries the violated `rule` and
  the triggering `peer_id` (`None` for `EmptyProposal` and `RemoveLastMember`).

### Entry Point

- **`validate_roster_change(proposal, current_members)`** — Returns
  `Ok(())` when the proposal is well-formed or `Err(Vec<RosterChangeValidationError>)`
  with all violations collected. Pure function, O(N+M) time.

### Pre-Quorum Contract

The epoch-advance coordinator in `tidefs-membership-live` calls
`validate_roster_change` before feeding a proposal into quorum collection.
Rejected proposals never enter a quorum round.


## Roster Constraints

The `roster_constraints` module provides structural constraint validation for
membership roster changes, ensuring proposals respect peer-count bounds and
quorum requirements before the coordinator records a transition journal entry
or solicits quorum votes.

### Types

- **`RosterConstraints`** — Configuration struct with `max_peers` (default 64)
  and `min_peers_for_quorum` (default 1). Use `new(max, min)` for custom bounds.

- **`ConstraintValidationError`** — Enum of five structural violations:
  `QuorumLost` (removal drops below quorum floor), `TooManyPeers` (addition
  exceeds peer ceiling), `DuplicatePeer` (invariant: roster contains duplicate
  ids), `PeerNotFound` (removal targets absent peer), `PeerAlreadyPresent`
  (addition targets peer already in roster). Implements `Display` for
  human-readable error messages.

### Validation Functions

- **`validate_add_peer(current_roster, new_peer, constraints)`** —
  Checks `PeerAlreadyPresent` and `TooManyPeers`.
  Returns `Ok(())` or `Err(ConstraintValidationError)`.

- **`validate_remove_peer(current_roster, departing_peer_id, constraints)`** —
  Checks `PeerNotFound` and `QuorumLost`.
  Returns `Ok(())` or `Err(ConstraintValidationError)`.

- **`validate_roster_invariants(roster, constraints)`** —
  Checks `DuplicatePeer`, `TooManyPeers`, and `QuorumLost`.
  Returns `Ok(())` or `Err(ConstraintValidationError)`.

### Journal Integration

`MembershipTransitionJournal::record_prepare_with_constraints` wraps constraint
validation before recording a transition. For a `Join` kind it calls
`validate_add_peer`; for a `Leave` kind it calls `validate_remove_peer`. After
the operation-specific check, it validates the resulting roster invariants.
On failure, returns the `ConstraintValidationError` without recording a journal
entry.

### Interaction with Roster Change Validation

`roster_constraints` complements `roster_validation`: the former enforces
structural bounds (how many peers, quorum floor), while the latter enforces
well-formedness (no duplicate deltas, no self-contradictory proposals). Both
run before quorum collection to prevent invalid configurations from consuming
a quorum round.

## Leave Coordination

The `leave_coordinator` module provides graceful peer departure validation
and notification payload construction.

### Types in `tidefs-membership-epoch`

- **`LeaveReason`** — Enum of departure reasons: `Voluntary` (0), `Maintenance` (1),
  `Draining` (2). Each variant has a stable wire discriminant and a
  human-readable label.

- **`LeaveOutcome`** — Result classification: `Accepted` (0), `Rejected` (1),
  `AlreadyDeparted` (2). `AlreadyDeparted` is returned when the peer has
  already been removed from the roster (idempotent).

- **`LeaveNotificationPayload`** — Serializable payload carrying
  `departing_member`, `departure_epoch`, `successor_epoch`, and
  `reason`. This payload is embedded into
  `MembershipOutboundMessage::LeaveNotification` for broadcast to remaining
  peers.

### LeaveCoordinator

`LeaveCoordinator` validates leave requests against the current roster and
produces a `LeaveResult`:

1. **Transition-in-flight guard** — rejects leave when another epoch
   transition is already pending, preventing conflicting concurrent
   proposals.
2. **Membership check** — rejects leave when the departing peer is not in
   the current member set.
3. **Last-member guard** — rejects leave when the cluster would be left
   with zero members.
4. **Success** — computes the successor epoch (`current + 1`), removes the
   departing member from the set, and constructs a
   `LeaveNotificationPayload` for broadcast.

### Entry Point

- **`LeaveCoordinator::validate_leave(member_id, reason) -> LeaveResult`** —
  Runs all validation rules and returns the outcome, successor epoch,
  updated member set, and optional notification payload. Pure function
  (no side effects), suitable for both userspace and kernel contexts.

### Integration

After `LeaveCoordinator` accepts a leave, the caller (membership-live)
broadcasts the `LeaveNotificationPayload` to all remaining active peers
via `RosterLeaveNotifier`. The broadcast reuses the existing
`MembershipOutboundDispatch` → `SendDispatcher` transport pipeline,
ensuring partial-failure tolerance: an unreachable peer does not block
delivery to the rest.



## Coordinator Promotion

The `coordinator_promotion` module provides deterministic coordinator
succession using `MemberId` sort order.

### Design

The coordinator is the member with the lowest `MemberId` in the current
roster. This is a deterministic, stateless computation that requires no
leader election protocol or external coordination:

- **`CoordinatorPromotion`** — Stateless coordinator promotion logic.
  `current_coordinator(roster)` returns the lowest-`MemberId` member;
  `promote_on_departure(roster, departed)` returns the successor
  when the departing member was the current coordinator, or `None`
  when a non-coordinator departs.

- **`CoordinatorChanged`** — Payload carrying `old` and `new`
  `MemberId` values produced when a coordinator departure triggers
  promotion.

### Integration with LeaveCoordinator

`LeaveCoordinator` now carries an optional `current_coordinator` field
(auto-computed from the member set on construction). When a leave is
accepted and the departing member is the current coordinator,
`LeaveCoordinator::validate_leave` computes the successor via
`CoordinatorPromotion::promote_on_departure` and includes the
`CoordinatorChanged` payload in `LeaveResult`.

The `EpochEvent::CoordinatorChanged { old, new }` variant records
coordinator transitions in the epoch history for persistence and
replay.

### Deterministic Priority Model

- Priority is determined solely by `MemberId` ordering (lowest = highest priority).
- When the coordinator departs, the next-lowest `MemberId` in the
  roster becomes the new coordinator.
- No leadership election protocol is needed — any member can compute
  the expected coordinator from the roster.
- Promotion only occurs when the departing member is the current
  coordinator; non-coordinator departures produce no
  `CoordinatorChanged` event.

### Entry Points

- **`CoordinatorPromotion::current_coordinator(&[MemberId]) -> Option<MemberId>`** —
  Returns the lowest-`MemberId` member.
- **`CoordinatorPromotion::promote_on_departure(&[MemberId], MemberId) -> Option<CoordinatorChanged>`** —
  Returns the successor coordinator when the coordinator departs.
- **`LeaveResult::coordinator_changed: Option<CoordinatorChanged>`** —
  Carries the promotion payload out of `LeaveCoordinator::validate_leave`.


## Coordinator Promotion

The `coordinator_promotion` module provides deterministic coordinator
succession using `MemberId` sort order.

### Design

The coordinator is the member with the lowest `MemberId` in the current
roster. This is a deterministic, stateless computation that requires no
leader election protocol or external coordination:

- **`CoordinatorPromotion`** — Stateless coordinator promotion logic.
  `current_coordinator(roster)` returns the lowest-`MemberId` member;
  `promote_on_departure(roster, departed)` returns the successor
  when the departing member was the current coordinator, or `None`
  when a non-coordinator departs.

- **`CoordinatorChanged`** — Payload carrying `old` and `new`
  `MemberId` values produced when a coordinator departure triggers
  promotion.

### Integration with LeaveCoordinator

`LeaveCoordinator` now carries an optional `current_coordinator` field
(auto-computed from the member set on construction). When a leave is
accepted and the departing member is the current coordinator,
`LeaveCoordinator::validate_leave` computes the successor via
`CoordinatorPromotion::promote_on_departure` and includes the
`CoordinatorChanged` payload in `LeaveResult`.

The `EpochEvent::CoordinatorChanged { old, new }` variant records
coordinator transitions in the epoch history for persistence and
replay.

### Deterministic Priority Model

- Priority is determined solely by `MemberId` ordering (lowest = highest priority).
- When the coordinator departs, the next-lowest `MemberId` in the
  roster becomes the new coordinator.
- No leadership election protocol is needed — any member can compute
  the expected coordinator from the roster.
- Promotion only occurs when the departing member is the current
  coordinator; non-coordinator departures produce no
  `CoordinatorChanged` event.

### Entry Points

- **`CoordinatorPromotion::current_coordinator(&[MemberId]) -> Option<MemberId>`** —
  Returns the lowest-`MemberId` member.
- **`CoordinatorPromotion::promote_on_departure(&[MemberId], MemberId) -> Option<CoordinatorChanged>`** —
  Returns the successor coordinator when the coordinator departs.
- **`LeaveResult::coordinator_changed: Option<CoordinatorChanged>`** —
  Carries the promotion payload out of `LeaveCoordinator::validate_leave`.

## Transition Journal

The `transition_journal` module provides a coordinator-local crash-recovery
journal for in-flight membership transitions (join, leave).

### Design

Each transition is recorded with a prepare-then-commit lifecycle:

1. **Prepare** — `record_prepare()` assigns a monotonically increasing
   `TransitionId` and records the intent before any side effects.
2. **Commit** — `record_commit()` marks the transition as completed after
   broadcast to peers.
3. **Abort** — `record_abort()` finalises a rejected or failed transition.

On coordinator promotion after a crash, the new coordinator replays the
journal via `replay_pending(timeout_ms)`: committed transitions are
re-yielded for re-broadcast to ensure all members converge; prepared
transitions older than the staleness timeout are auto-aborted; fresh
prepared transitions are yielded for caller resolution.

### Types

- **`TransitionId`** — Monotonically increasing identifier (`u64`). Zero is
  the null sentinel.
- **`TransitionKind`** — `Join { peer_id, epoch }` or
  `Leave { peer_id, epoch, reason }`.
- **`TransitionStatus`** — `Prepared`, `Committed`, or `Aborted`.
- **`TransitionRecord`** — Full journal entry: id, kind, status,
  `prepared_at_millis`, `finalised_at_millis`.
- **`MembershipTransitionJournal`** — Append-only `VecDeque`-backed log
  with `record_prepare`, `record_commit`, `record_abort`,
  `replay_pending`, `get`, `iter`, and `clear`.
- **`ReplayAction`** — `ReBroadcastCommitted { record }` or
  `ResolvePrepared { record }`, yielded by the replay iterator.

### Integration

The journal is held in `MembershipRuntime` (`tidefs-membership-live`) as
`Arc<Mutex<MembershipTransitionJournal>>` and wired into:
- **Join path** — `PeerJoinHandshake::process_peer_join` records prepare
  before validation and commit after acceptance.
- **Leave path** — `RosterLeaveNotifier::notify_leave` records prepare
  before fan-out and commit after broadcast.
- **Replay** — `MembershipRuntime::replay_transition_journal` replays on
  coordinator promotion, re-broadcasting committed transitions and
  auto-aborting stale prepared ones.

### Entry Points

- **`MembershipTransitionJournal::record_prepare(kind, now_ms) -> TransitionId`** —
  Record a prepared transition intent.
- **`MembershipTransitionJournal::record_commit(id, now_ms) -> bool`** —
  Mark a transition as committed.
- **`MembershipTransitionJournal::record_abort(id, now_ms) -> bool`** —
  Mark a transition as aborted.
- **`MembershipTransitionJournal::replay_pending(now_ms, timeout_ms) -> ReplayIter`** —
  Iterate pending records for crash-recovery replay.
- **`current_time_millis() -> u64`** — Wall-clock time in milliseconds for
  timestamping journal records.

### Module Inventory

| Source File | Description |
|-------------|-------------|
| `roster_validation.rs` | Proposal well-formedness validation rules |
| `epoch_chain.rs` | Epoch-chain integrity verification |
| `quorum.rs` | Quorum-based proposal/vote/commit lifecycle |
| `epoch_proposal.rs` | Wire types for epoch proposal and ack messages |
| `epoch_commit_subscriber.rs` | Commit subscriber dispatch registry |
| `epoch_persistence.rs` | Durable epoch-state persistence and restart recovery |
| `roster_push.rs` | Committed-roster transport push for peer synchronization |
| `session_binding.rs` | Transport-session to membership-roster binding |
| `leave_coordinator.rs` | Graceful peer departure validation and notification payload construction |
| `transition_journal.rs` | Coordinator-local transition journal for crash-recovery replay |
| `coordinator_promotion.rs` | Deterministic coordinator promotion with MemberId sort order |
| `membership_quorum_tracker.rs` | Quorum-based proposal-vote lifecycle for roster changes |

## Roster Change Quorum Protocol

The `membership_quorum_tracker` module implements a two-phase proposal-vote
protocol for roster changes (join and leave). Instead of unilateral
coordinator-driven epoch advancement, the coordinator broadcasts a
`RosterChangeProposal` to all current members, collects `RosterChangeVote`
responses, and commits the change only when a simple-majority quorum
of accept votes is reached.

### Message Flow

```
Coordinator                         Members
    |                                   |
    |-- RosterChangeProposal ---------->|  (broadcast to all)
    |                                   |
    |<-- RosterChangeVote (accept) -----|  (each member validates + votes)
    |<-- RosterChangeVote (reject) -----|
    |                                   |
    |       [quorum reached]            |
    |-- epoch advance + commit -------->|
```

### Types in `tidefs-membership-types`

- **`RosterChangeProposal`** — Carries `proposal_id`, `coordinator_id`,
  `current_epoch`, `added`/`removed` member sets, and `created_at_millis`.
  Serialized over transport for broadcast.

- **`RosterChangeVote`** — Carries `proposal_id`, `voter_id`, `accepted` flag,
  optional `reject_reason`, and `voted_at_millis`. Binary wire format with
  CRC32C checksum via `MembershipCodec`.

### Quorum Calculation

Simple majority: `floor(N / 2) + 1` where N is the number of current members.
For a single-member cluster (N=1), the threshold is 1. An empty member set
thresholds to 0 (degenerate case).

### Timeout Behavior

Each proposal carries a configurable `timeout_ms` (default 5 seconds).
When a timeout fires:

- Remaining uncast votes are treated as implicit rejections.
- If the maximum mathematically reachable approvals (cast approvals +
  remaining members) falls below the quorum threshold, the proposal is
  aborted early with a `QuorumOutcome::Rejected`.
- Otherwise the tracker stays `Pending`, waiting for late votes.

A `timeout_ms` of 0 disables timeout entirely.

### Coordinator-Side: MembershipQuorumTracker

`MembershipQuorumTracker` wraps a proposal and collects votes. Lifecycle:

1. **create(proposal)** -> `AwaitingVotes`
2. **receive_vote(vote)** for each member response — deduplicates, validates
   voter membership, and checks for quorum.
3. **check_timeout(now_millis)** — fires timeout logic.
4. **quorum reached** -> `Committed` outcome.
5. **timeout or abort** -> `Rejected` outcome.

Errors: `AlreadyCommitted`, `AlreadyAborted`, `ProposalIdMismatch`,
`DuplicateVote`, `VoterNotMember`.

### Member-Side: MembershipVoteHandler

`MembershipVoteHandler` (in `tidefs-membership-live`) validates incoming
proposals:

1. Coordinator matches the expected coordinator (lowest `MemberId`).
2. Proposal epoch matches the member's current committed epoch.
3. The add/remove delta passes well-formedness rules (no duplicate joins,
   no removal of non-members, no empty proposals, etc.) via
   `roster_validation::validate_roster_change`.

Valid proposals receive an accept vote; invalid proposals receive a
reject vote with a structured `RejectReason` code.

### Failure Modes

| Scenario | Behavior |
|---|---|
| Coordinator proposes with wrong epoch | Members reject with `epoch_mismatch` |
| Coordinator is not the expected coordinator | Members reject with `wrong_coordinator` |
| Duplicate join (peer already in roster) | Members reject with `duplicate_join` |
| Removal of non-member | Members reject with `remove_non_member` |
| Quorum unreachable (split vote) | Proposal stays pending; timeout aborts |
| Coordinator crashes mid-proposal | New coordinator (via promotion) aborts stale proposals |

## Epoch Snapshot Persistence

The `snapshot` module provides durable membership epoch snapshot persistence so
a restarting coordinator can reconstruct the current membership roster from the
latest snapshot plus incremental transition-journal replay, avoiding full
sequential journal replay for long-running clusters.

### Design

1. **Snapshot creation**: After a quorum-confirmed roster change (via
   `membership_quorum_tracker`), a `MembershipEpochSnapshot` is written before
   advancing the in-memory epoch. Each snapshot carries a monotonically
   increasing sequence number for ordering.

2. **Recovery**: On coordinator restart, `recover_roster` loads the latest
   snapshot (highest sequence number) and replays only committed transition
   journal entries whose epoch is strictly greater than the snapshot epoch.
   Prepared-but-uncommitted entries are skipped.

3. **Empty fallback**: When no snapshot exists (first start or clean store),
   `load_latest_snapshot` returns `None` and `recover_roster` replays all
   committed journal entries from an empty starting state.

### Types

- **`MembershipEpochSnapshot`** — The serialized snapshot carrying:
  `sequence_number` (monotonic u64), `epoch` (EpochId), `coordinator`
  (MemberId), and `roster` (sorted Vec of (MemberId, TransportAddress) pairs).
  Encoded/decoded via bincode for deterministic binary representation.

- **`TransportAddress`** — A host:port string for reaching a member node.

- **`EpochSnapshotStore`** — Pluggable storage backend trait (Send + Sync) with
  `write_snapshot`, `read_snapshot`, `list_snapshots`, and `clear`. This crate
  provides the trait and an `InMemorySnapshotStore` for tests; callers provide
  the storage backend used by their runtime.

- **`RecoveredRoster`** — Result of recovery: sorted `member_ids`, current
  `epoch`, and deterministic `coordinator` (lowest MemberId).

### Entry Points

- **`MembershipEpochSnapshot::new(seq, epoch, coordinator, roster)`** —
  Creates a snapshot with the roster automatically sorted by MemberId.

- **`MembershipEpochSnapshot::encode()` / `decode(data)`** —
  Binary serialization via bincode.

- **`write_epoch_snapshot(store, snapshot)`** —
  Encodes and persists a snapshot through the store backend.

- **`load_latest_snapshot(store)`** —
  Returns the snapshot with the highest sequence number, or `None`.

- **`recover_roster(store, journal)`** —
  Loads the latest snapshot, replays committed journal entries with higher
  epochs, and returns the reconstructed roster.

### Interaction Contract with Transition Journal

- The snapshot captures the full roster at a specific epoch.  Recovery replays
  only committed journal entries whose epoch is strictly greater than the
  snapshot epoch.
- Prepared (in-flight) journal entries are never replayed during recovery
  because they have not been committed and may be stale.
- If no snapshot exists, all committed journal entries are replayed from an
  empty starting state (epoch 0).
- `recover_roster` returns `EpochSnapshotError::NoState` when both the store
  and journal are empty, signalling genesis bootstrap to the caller.

## Proposal Idempotency

The `proposal_idempotency` module prevents duplicate membership epoch proposals
from being committed when a subsystem safely resubmits after a coordinator
transition.

### Types

- **`ProposalIdempotencyKey`** — Opaque newtype wrapping `[u8; 32]`. Callers
  generate a deterministic key for each logical proposal intent (e.g. BLAKE3
  hash of the proposal payload). `Copy + Eq + Hash` for tracker lookup.

- **`IdempotencyConfig`** — Configuration with `retention_epochs` (default 8,
  number of epochs to retain keys before pruning) and `max_tracked_keys`
  (default 4096, LRU capacity).

- **`ProposalOutcome`** — `PassThrough` (new key, proceed to quorum) or
  `AlreadyCommitted { epoch }` (duplicate, skip quorum).

- **`IdempotencyTracker`** — Bounded-LRU state machine keyed by
  `(proposer_id, ProposalIdempotencyKey)`. On `check_and_insert`:
  1. prunes entries older than the retention window, 2. checks for duplicate,
  3. inserts the key, 4. evicts the oldest entry when LRU capacity is exceeded.

### Caller Contract

Before entering a quorum round, the caller generates a deterministic
`ProposalIdempotencyKey` for the proposal intent and consults
`IdempotencyTracker::check_and_insert`. A `ProposalOutcome::AlreadyCommitted`
result means the caller must skip quorum and treat the proposal as complete.
This eliminates duplicate transport fan-out and quorum-round churn during
coordinator failover.

### Entry Points

- **`IdempotencyTracker::check_and_insert(proposer_id, key, current_epoch) -> ProposalOutcome`** —
  Deduplicate and insert.
- **`IdempotencyTracker::record_commit(proposer_id, key, committed_epoch)`** —
  Update the recorded epoch after successful commit.
- **`IdempotencyTracker::clear()`** — Remove all tracked entries.

## Checkpoint Management

The `checkpoint` module builds on the snapshot persistence layer to provide
a high-level `CheckpointManager` for bounded-replay crash recovery.

### Design

1. **CheckpointManager** wraps an `EpochSnapshotStore` and tracks a monotonic
   sequence number, ensuring each new checkpoint supersedes the previous one.
2. **create_checkpoint(epoch, coordinator, incarnation, roster)** encodes the
   current membership state as a `MembershipEpochSnapshot` and persists it
   through the underlying store.
3. **latest_checkpoint()** returns the snapshot with the highest sequence
   number, or `None` when no checkpoint has been persisted.

### Integration

- Call `create_checkpoint` after each quorum-confirmed epoch advancement to
  bound future journal replay to only post-checkpoint entries.
- On restart, call `latest_checkpoint` to reconstruct pre-crash state, then
  replay only transition journal entries whose epoch is strictly greater than
  the checkpoint epoch.
- `CheckpointManager::new(store)` automatically scans for the latest persisted
  checkpoint and initializes its sequence counter one past it.

### Types

- **`CheckpointManager`** — High-level checkpoint manager providing
  `create_checkpoint`, `latest_checkpoint`, and `next_sequence_number`.
- Uses `MembershipEpochSnapshot` from the `snapshot` module for serialization.
- Storage backends implement `EpochSnapshotStore` (also from `snapshot`).

### Crate Integration

This crate does not define a runtime checkpoint backend. Runtime callers that
need checkpoint storage provide an `EpochSnapshotStore` implementation and use
`CheckpointManager` only to create and load `MembershipEpochSnapshot` records.
System-level runtime and claim boundaries remain owned by
`docs/MEMBERSHIP_AUTHORITY.md`.
