# tidefs-membership-live

Live membership runtime: SWIM failure detection, 3-phase epoch transitions,
heartbeat protocol, and membership event notification.

## Capabilities

- SWIM-style failure detection with indirect ping relay, gossip batching, and epidemic fan-out broadcast
- 3-phase epoch transition engine with quorum-acknowledged advancement
- Fencing watchdog for unresponsive-node forced ejection
- Node drain state machine with verified drain-request validation
- BLAKE3-verified membership event notification bridge


## Gossip Dissemination

The gossip module (`gossip` module) disseminates membership liveness
observations cluster-wide via two complementary mechanisms:

- **Rumor-mongering** — a `RumorMongerer` maintains a bounded
  `VecDeque<GossipMessage>` rumor queue. On each outgoing transport
  message, up to `piggyback_limit` rumors (default 3) are selected
  by state-change priority (Failed > Suspected > Alive), with TTL-based
  expiration and duplicate suppression.

- **Anti-entropy exchange** — an `AntiEntropyRound` drives periodic
  full-state digest exchange with a randomly selected peer. Identical
  digests produce no data transfer; divergent entries are exchanged
  incrementally.

Together they provide eventual-consistency membership state propagation
without requiring a central coordinator, closing the gap between suspicion
accumulation (#5683) and roster maintenance (#5694).

### Core Types

- `GossipMessage` — BLAKE3-256 domain-separated wire type
  (`tidefs-membership-gossip-v1`) covering member_id, incarnation, state,
  lamport clock, originator; `verify_full()` tamper detection.
- `GossipState` — per-member tracking of last known incarnation, state,
  lamport clock, and hop count for loop detection.
- `DisseminationConfig` — builder-pattern configuration with defaults:
  piggyback_limit=3, anti_entropy_interval_ms=1000, rumor_ttl=10,
  max_rumor_queue=256.

### Supersede Logic

Incoming gossip messages are merged by Lamport clock ordering:
higher incarnation always wins; equal incarnation + higher clock wins;
equal clock + Failed > Suspected > Alive. Hop counts accumulate on each
successful application; rumors with hop count >= `rumor_ttl` are dropped
to prevent infinite loops.

### Epidemic Broadcast

The `GossipBroadcastEngine` provides proactive fan-out of membership state
changes to a random subset of peers, achieving O(log N) dissemination
rounds with high probability.

- `GossipConfig` -- epidemic broadcast configuration with defaults:
  fanout=3, retry_count=2, ttl=10, seen_set_capacity=1024.
- `GossipBroadcastEngine` -- maintains a bounded LRU seen-message set
  for deduplication, selects `fanout` random peers from the cluster
  (deterministic with seeded RNG), and builds gossip messages from
  `MembershipEvent` variants via `build_from_event()`.

Unlike rumor-mongering which passively piggybacks on outbound transport,
the broadcast engine is designed for active dissemination of epoch
transition notifications and peer state deltas (join/drain/fail).
Messages are sent over the transport layer via
`MembershipWireMessage::GossipBroadcast`.

When an incoming gossip message arrives, `accept_message()` verifies
BLAKE3 digest integrity, checks the seen-set for deduplication, and
enforces TTL-based maximum age before marking the message as seen.

## Event Bridge

The event bridge (`event_bridge` module) publishes typed membership
state-change notifications for consumption by transport, placement, and
other subsystems. It decouples SWIM failure-detection internals from
connection-lifecycle management.

### MembershipEvent

Four event variants, each carrying member identity, incarnation number,
and a BLAKE3-256 domain-separated digest (domain
`tidefs-membership-event-v1`) for tamper detection:

- `MemberJoined` -- new peer confirmed in the membership roster.
- `MemberSuspected` -- peer health transitioned to Suspect.
- `MemberFailed` -- peer declared Down after suspicion timeout.
- `MemberLeft` -- graceful departure (drain complete or removal).

Use the factory constructors (`member_joined`, `member_suspected`,
`member_failed`, `member_left`) to create events with correct digests.
Call `verify_event_digest()` to detect tampered or corrupted events
before acting on them.

### MembershipEventSubscriber trait

Implement `MembershipEventSubscriber` (single method:
`on_membership_event(&self, event: &MembershipEvent)`) to receive
notifications. Implementations must be non-blocking and fast; spawn
async work for long-running I/O or blocking operations.

```
impl MembershipEventSubscriber for MyPeerManager {
    fn on_membership_event(&self, event: &MembershipEvent) {
        match event {
            MembershipEvent::MemberJoined { member_id, .. } => {
                self.establish_session(*member_id);
            }
            MembershipEvent::MemberFailed { member_id, .. } => {
                self.teardown_session(*member_id);
            }
            _ => {}
        }
    }
}
```

### MembershipEventPublisher lifecycle

- `subscribe(Box<dyn MembershipEventSubscriber>) -> SubscriberId`
- `unsubscribe(SubscriberId) -> bool`
- `publish(&MembershipEvent) -> bool` -- returns `false` when suppressed
  as a duplicate of the last published event kind for that member.
- `clear_dedup(MemberId)` -- reset dedup state for re-publishing after
  recovery.

The publisher suppresses consecutive identical event kinds per member
(e.g., re-suspicion of an already-suspected member does not fire a second
event). Call `clear_dedup` when a member recovers to allow future
suspicion events.

### Integration guidance for transport consumers

The transport peer manager (#5671) is the primary consumer. Recommended
actions per event:

- `MemberJoined`: establish transport session, add to connection pool.
- `MemberSuspected`: mark sessions suspect, throttle, do not teardown yet.
- `MemberFailed`: teardown sessions, cancel in-flight transfers.
- `MemberLeft`: drain and teardown (node-initiated departure).

The publisher lives on `MembershipRuntime::event_publisher`. Subscribe
during transport initialization and keep the subscriber alive for the
lifetime of the runtime. Events are delivered synchronously within
`MembershipRuntime::tick()`; subscribers must not block the SWIM loop.

### Thread safety

The publisher uses `&mut self` methods and is intended for
single-threaded use within the runtime tick loop. Wrap in `Mutex` or
`RwLock` for multi-threaded subscribers.

## Escalation Pipeline

The escalation pipeline (`escalation` module) bridges the suspicion accumulator
(#5683) to the epoch proposal constructor (#5727).  It polls the accumulator
on a configurable interval, applies consecutive-interval gating and cooldown
enforcement, and emits `EscalationProposalRequest`s when a member is confirmed
Failed — closing the gap between failure detection and membership
reconfiguration.

### Threshold Model

- `suspect_score_ceiling` (default 30): minimum accumulator score before the
  engine begins tracking toward Suspected.
- `failed_score_ceiling` (default 100): minimum accumulator score to finalize
  Failed.
- `consecutive_intervals` (default 3): number of consecutive polls the score
  must remain above the ceiling before the state transition is committed.
- `cooldown_ticks` (default 10): ticks a member stays in cooldown after
  de-escalation before re-escalation is permitted.

### State Machine

- `BelowThreshold` → `PendingEscalation` when score crosses a ceiling.
- `PendingEscalation` → `EscalatedToSuspected` after consecutive confirmations
  above suspect ceiling.
- `PendingEscalation` → `EscalatedToFailed` after consecutive confirmations
  above failed ceiling (emits `EscalationProposalRequest`).
- `EscalatedToSuspected` → `EscalatedToFailed` after consecutive failed-ceiling
  confirmations.
- De-escalation drops to `BelowThreshold` with cooldown enforcement.

### BLAKE3 Domain

The state digest uses domain `tidefs-membership-escalation-v1`, covering all
per-member states, cooldowns, the config hash, and the engine tick.

### Integration

`EscalationEngine::poll()` consumes the `SuspicionAccumulator` and
`MembershipRoster`.  Generated `EscalationProposalRequest`s carry the member
to remove and the current member snapshot for direct use with
`EpochProposalConstructor`.  The engine is designed to feed into the epoch
transition state machine (#5666) once it lands.

## Session Binding

The session binding module (`session_binding` module) provides a
membership-side type surface for transport session lifecycle policy.
It enables the transport layer to bind established sessions to
membership peer identities and query "what is the current policy for
this peer's sessions?" as membership state evolves.

### Core Types

- `PeerSessionBinding` — opaque handle associating a transport session
  identifier (`SessionId`) with a membership peer identity (`MemberId`),
  created at admission time and held by transport.
- `SessionPolicy` — lifecycle directive enum with four variants:
  `Admit` (allow new connection), `Route` (normal operation),
  `Drain` (graceful shutdown), `Close` (immediate teardown).
- `SessionBindingTable` — BTreeMap-indexed collection of active bindings
  with O(log n) lookup by peer ID and session ID, supporting batch
  epoch refresh, insert, remove, and per-peer removal.

### Policy Derivation

`binding_policy(state)` maps `MemberState` to `SessionPolicy`:

| MemberState | SessionPolicy | Transport Action |
|-------------|---------------|------------------|
| Alive       | Route         | Route traffic normally |
| Suspected   | Drain         | Stop new work, drain in-flight |
| Failed      | Close         | Tear down immediately |

`admission_policy()` returns `SessionPolicy::Admit` for pre-membership
peer admission, separate from the bound-session policy path.

### Transport Integration

The module is a pure membership type surface: it does not import
`tidefs-transport` or open a dependency edge toward transport.
Transport creates a `PeerSessionBinding` at admission time and inserts
it into a shared `SessionBindingTable`. When membership events arrive
(epoch advance, peer failure, drain notification), transport calls
`binding_policy()` with the peer's current `MemberState` and applies
the returned policy to all sessions bound to that peer.

`SessionBindingTable::refresh_epoch()` supports batch policy refresh on
epoch advance, updating the epoch field on all bindings matching a
predicate and returning the set of affected peer IDs.

### Security Model

No per-message BLAKE3/MAC/auth-token layers are added. Peer authenticity
and message integrity remain at the transport session boundary per the
TideFS crypto guardrails. This module only provides the membership-to-
transport policy bridge for session lifecycle decisions.

## Protocol-Level Liveness Tracking

The [`LivenessTracker`](src/liveness.rs) provides protocol-level heartbeat
expectations independent of transport-layer TCP keepalive. A peer with an
active TCP connection may still be unresponsive at the application layer. The
liveness tracker records the most recent authenticated protocol message
timestamp for each member and detects failures when the grace period expires.

### LivenessConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `heartbeat_interval` | `Duration` | 500ms | Expected interval between protocol messages |
| `failure_threshold` | `u32` | 5 | Missed intervals before declaring failure (>= 1) |
| `min_peers_for_liveness` | `usize` | 2 | Minimum peers before failure signals are emitted |

The failure grace period is `heartbeat_interval * failure_threshold`. If a
member sends no authenticated protocol message within this window, it is
declared failed.

### LivenessTracker

- `register_member(id)` — begin tracking a peer with current-time initial
  timestamp.
- `record_activity(id)` — update last-seen timestamp on receipt of any
  authenticated membership protocol message (ping, ack, gossip, epoch
  proposal). If the member was previously failed, this clears the failure
  flag (recovery).
- `poll_failures()` — returns an iterator of `MemberId`s that exceeded the
  grace period. Each failed member is emitted at most once; subsequent polls
  skip already-emitted failures until `record_activity` clears the flag.
- `is_failed(id)` / `last_seen(id)` — query individual member state.
- `remove_member(id)` — stop tracking a departed member.
- `reset_failures()` — clear all failure flags (e.g. after epoch transition).

Failures are suppressed when the tracked member count is below
`min_peers_for_liveness`, avoiding false positives in single-node or
very small clusters.

### Integration

`LivenessTracker::poll_failures()` is consumed by the epoch state machine
(`tidefs-membership-epoch`) to trigger reconfiguration when a member stops
responding. Each failed `MemberId` feeds into an `EpochProposal` with
`MembershipDelta::NodeFailed`, driving the propose → accept → commit
lifecycle to remove the unresponsive peer from the member set.

## Backend Disclosure

The `backend_disclosure` module provides the `BackendDisclosure` enum — a
single authority type shared by the storage-node, transport, membership,
placement, and replication subsystems.

### Variants

| Variant | `is_live()` | Purpose |
|---|---|---|
| `Rdma(addr)` | yes | Network backend disclosure for an RDMA address or device string; enum state only, not proof of an executable RDMA path |
| `Tcp(addr)` | yes | Network backend disclosure for TCP bound to a socket address |
| `Loopback` | no | In-process loopback for single-node deterministic testing |
| `DeterministicInMemory` | no | Fully deterministic in-memory for unit/validation harnesses |
| `NotRun` | no | Authority spine constructed, no transport active |

### Usage

The storage-node constructs a `BackendDisclosure` from CLI flags and
passes it to `RuntimeAuthority::build()`. Every subsystem queries
`authority.backend()` to learn which backend is active. The `is_live()`
predicate distinguishes live-network disclosures from harness/test modes
without subsystem-specific backend inspection.

`BackendDisclosure` is intentionally a pure data type with no
dependencies on transport, replication, or placement internals.
The storage-node binary owns the wiring that maps a disclosure to
concrete subsystem initialization.

## Inbound Message Dispatch

The dispatch router (`dispatch_router` module) routes decoded membership
protocol messages arriving from transport channels to the correct subsystem
handler. It closes the inbound dispatch gap so that multi-node membership
protocol messages produce concrete state transitions instead of being dropped.

### MembershipMessage

A 15-variant enum covering the membership protocol surface:

| Variant | Discriminant | Target Subsystem |
|---------|-------------|------------------|
| JoinRequest | 0 | Join handshake |
| JoinResponse | 1 | Join handshake |
| LeaveNotification | 2 | Roster / epoch |
| EpochProposal | 3 | Epoch state machine |
| EpochAccept | 4 | Epoch state machine |
| LeaseGrant | 5 | Lease manager |
| LeaseRenew | 6 | Lease manager |
| LeaseRevoke | 7 | Lease manager |
| HealthReport | 8 | Liveness tracker |
| GossipDigest | 9 | Gossip engine |
| GossipDelta | 10 | Gossip engine |
| DrainRequest | 11 | Drain verifier |
| DrainComplete | 12 | Drain verifier |
| LeaseAcknowledge | 13 | Lease manager |
| LeaseExpire | 14 | Lease manager |

### MembershipMessageHandler Trait

The `MembershipMessageHandler` trait provides one method per message
variant, each with a default no-op implementation returning `Ok(())`.
Subsystems implement this trait and override only the methods for the
message variants they handle.

```
impl MembershipMessageHandler for MyLivenessHandler {
    fn handle_health_report(&self, msg: &MembershipMessage) -> Result<(), MembershipDispatchError> {
        // update liveness tracking with the received health report
        Ok(())
    }
}
```

### MembershipDispatchRouter

The `MembershipDispatchRouter` stores a `HashMap<u8, Box<dyn MembershipMessageHandler>>`
keyed by message discriminant. Registration replaces any existing handler for
the same discriminant.

- `router.register(discriminant, handler)` — register a boxed handler for a discriminant.
- `router.route(&msg)` — match the message variant, look up the handler by discriminant,
  and call the appropriate typed handler method.
- `router.unregister(discriminant)` — remove the handler for a discriminant.
- `router.has_handler(discriminant)` — check if a handler is registered.

### Integration

The transport receive path decodes incoming membership protocol messages
from transport channels and calls `MembershipDispatchRouter::route()` to
deliver them to the registered subsystem handler. Subsystems register
their handlers during initialization and begin receiving protocol messages
without depending on transport internals.

## Membership Outbound Dispatch

The outbound dispatch module (`membership_outbound_dispatch`) bridges
subsystem-generated membership protocol messages to the transport per-connection
send pipeline provided by `SendDispatcher` (#5829).

### MembershipOutboundMessage

A 14-variant enum covering the outbound membership protocol surface:

| Variant | Purpose |
|---------|---------|
| LeaseGrant | Grant write-authority lease to a member |
| LeaseRenew | Renew an existing lease |
| LeaseRevoke | Revoke a member's lease |
| EpochProposal | Propose a new membership epoch |
| EpochAccept | Accept a proposed epoch |
| EpochCommit | Commit an epoch after quorum |
| HealthReport | Liveness heartbeat health report |
| GossipDigest | Anti-entropy digest for gossip |
| GossipDelta | Incremental gossip state delta |
| DrainRequest | Request graceful node drain |
| DrainComplete | Drain operation completed |
| JoinRequest | Request to join the cluster |
| JoinResponse | Response to a join request |
| LeaveNotification | Graceful leave notification |

All messages serialize through bincode and carry
`MessageFamily::PublicationProgress` (m4).

### MembershipOutboundDispatch

The `MembershipOutboundDispatch` struct holds references to the transport
`SendDispatcher` and the membership `MembershipRoster`. It provides two
routing modes:

- **Unicast** (`send_to_peer`): resolves the target `MemberId` against the
  roster snapshot, serializes the message, and enqueues through the transport
  send pipeline. Returns `OutboundDispatchError` on roster miss, serialization
  failure, backpressure, queue-not-found, or shutdown.

- **Broadcast** (`broadcast`): iterates all `Active` members in the roster
  snapshot, cloning the message per peer, and enqueues to each. Returns a
  `BroadcastResult` with success count and per-peer error details. Non-active
  peers (Suspected, Failed, Left) are skipped.

### MemberId to PeerId Mapping

MemberId and PeerId are both `u64` newtypes. The dispatch layer uses a direct
mapping (`member_id.0 as PeerId`), relying on the transport layer to maintain
the connection-to-peer binding.

### Backpressure Propagation

When the transport `SendQueue` is at capacity, `SendError::Backpressure` is
converted to `OutboundDispatchError::Backpressure` carrying the member_id,
peer_id, current queue depth, and byte depth. Callers should inspect this
error and decide whether to delay, drop, or shed.

### Integration

The membership runtime creates a `MembershipOutboundDispatch` during
initialization and passes references to subsystem message producers.
Together with the inbound `MembershipDispatchRouter` (#5836), this
completes the bidirectional membership message flow through the
transport layer, enabling end-to-end multi-node protocol operation.


## Lease Message Construction

The lease message construction layer (`lease_messages` module) provides
typed builder functions that construct `MembershipMessage` variants for
the lease lifecycle. Each function accepts domain parameters and returns
a correctly-formed protocol message.

### Domain Types

- `LeaseId(u64)` — unique lease identifier, scoped within an epoch.
  Stable across renewals; a new epoch receives a fresh lease-id namespace.
- `LeaseTerm(u64)` — monotonic lease term counter, incremented on each
  grant and renewal to detect stale or replayed lease messages.

### Builder Functions

| Function | Inputs | Output Variant | Role |
|----------|--------|---------------|------|
| `build_lease_grant` | member_id, lease_id, epoch, term, ttl | `LeaseGrant` | Grant write authority to a member |
| `build_lease_renew` | member_id, lease_id, epoch, term, ttl | `LeaseRenew` | Extend an existing lease before expiry |
| `build_lease_revoke` | member_id, lease_id, epoch | `LeaseRevoke` | Strip write authority from a member |
| `build_lease_acknowledge` | member_id, lease_id, epoch, accepted | `LeaseAcknowledge` | Confirm or reject a lease grant |
| `build_lease_expire` | member_id, lease_id, epoch | `LeaseExpire` | Notify that a lease's TTL has elapsed |

Each builder has a corresponding `_at()` variant (e.g. `build_lease_grant_at`)
that accepts an explicit millisecond clock value, enabling deterministic or
simulated clock injection for validation harnesses.

### Lease Lifecycle

```text
  Grant ──> Renew ──> Revoke
    │         │
    └──> Expire (if TTL elapses without renewal)
    │
    └──> Acknowledge (lease-holder confirms grant)
```

### Integration

Lease protocol code in `tidefs-membership-live` calls these builders to
construct `MembershipMessage` variants suitable for outbound dispatch
through existing dispatch pipelines. Each builder populates millisecond
timestamps from a caller-provided clock value, keeping the construction
layer free of ambient time dependencies.
## Drain Orchestration Protocol

The `DrainOrchestrator` coordinates graceful node departure across the membership protocol. It bridges drain lifecycle messages through the existing inbound (`MembershipDispatchRouter`) and outbound (`MembershipOutboundDispatch`) dispatch pipelines.

### State Machine

```text
Idle ──► Draining ──► DrainingLocally ──► Drained ──► Removed
```

- **Idle**: No drain operation in progress.
- **Draining**: A drain has been initiated; `DrainRequest` broadcast sent to all active peers. Waiting for peer acknowledgments.
- **DrainingLocally**: The local node is preparing for drain (lease handoff, in-flight operation completion).
- **Drained**: All peers have confirmed drain completion; node is safe to remove from the roster.
- **Removed**: Node has been removed from the roster. Terminal state.

### Message Flow

1. **Initiation**: `initiate_drain(member_id)` broadcasts `DrainRequest` to all active roster members and transitions the target to `Draining`.
2. **Self-drain**: If the target is the local node, the orchestrator additionally transitions to `DrainingLocally` and sends a `DrainComplete` ack.
3. **Peer ack**: `on_drain_request(from, target)` processes inbound drain requests. For remote targets, it records the in-progress drain. For local targets, it transitions to `DrainingLocally` and sends a `DrainComplete` acknowledgment.
4. **Completion**: `on_drain_complete(from, target)` records peer confirmations. When the quorum threshold is met (all active peers excluding the target have acknowledged), the state advances to `Drained`.
5. **Removal**: `commit_removal(member_id)` transitions the orchestrator state to `Removed`. The roster transition (`Active -> Left`) is performed externally through `MembershipRoster::transition_state`.
6. **Abort**: `abort_drain(member_id)` resets the member's drain state to `Idle` on timeout or rejection.

### Configuration

`DrainConfig` controls protocol behavior:
- `drain_timeout_ms` (default 30,000): Maximum milliseconds a drain may remain in `Draining` before being eligible for abort via `check_timeouts`.
- `quorum_threshold` (default 2): Number of peer `DrainComplete` confirmations required before the orchestrator transitions to `Drained`.

### Dispatch Integration

`DrainOrchestrator` implements `MembershipMessageHandler` for `DrainRequest` (discriminant 11) and `DrainComplete` (discriminant 12). Register the orchestrator with `MembershipDispatchRouter` to route inbound drain protocol messages. Outbound messages flow through `MembershipOutboundDispatch`.

## Connection Teardown

The `EpochTeardownSubscriber` bridges membership epoch transitions to transport connection lifecycle by automatically draining and closing transport connections to peers removed from the cluster roster.

### Triggering

Teardown is triggered through two paths:

1. **Event-driven**: The subscriber implements `MembershipEventSubscriber` and listens for `MemberLeft`, `MemberFailed`, and `MemberDrained` events. On each departure event, the associated transport connection is torn down immediately.

2. **Roster-sync**: `sync_roster(new_roster, action)` diffs the cached known-peer set against a new committed roster and tears down connections for every removed peer. This is the primary entry point for epoch-commit-driven teardown.

### Teardown Actions

| MembershipEvent | TeardownAction | Behavior |
|-----------------|---------------|----------|
| `MemberFailed` | `Close` | Immediate disconnect — no point draining a dead link |
| `MemberDrained` | `Close` | Immediate disconnect — state transfer already complete |
| `MemberLeft` | `Drain` | Graceful drain — allow in-flight work to complete before close |

### Integration Surface

```
MembershipEventPublisher
       │
       ▼
EpochTeardownSubscriber
       │
       ├──► ConnectionRegistry (lookup/remove by peer ID)
       ├──► SessionBindingTable (remove_all_for_peer)
       └──► TeardownCallback (user-provided: bridges to ConnectionManager)
                │
                ▼
         ConnectionManager::drain / disconnect
```

The `TeardownCallback` is a `Box<dyn Fn(SocketAddr, TeardownAction) + Send + Sync>` provided by the transport runtime. It bridges the sync membership event callback to the async `ConnectionManager` by spawning a tokio task for each teardown.

### Idempotency

- If a peer is not found in `ConnectionRegistry` (already removed or never admitted), teardown is a no-op.
- A second teardown request for an already-removed peer produces no additional callback invocation.
- The cached known-peer set prevents duplicate roster-sync teardowns.


## Peer Eviction

The `EvictionExecutor` bridges epoch-commit subscriber dispatch to transport
connection teardown and session cleanup. When the `EpochAdvanceCoordinator`
commits a new `EpochView` that removes a dead peer, the executor tears down
the associated transport connections, releases session bindings, and emits
`EvictionOutcome` records for downstream subsystem notification. This closes
the action-execution gap between membership view changes and the runtime
consequences those changes demand.

### Membership Lifecycle Pipeline

```text
liveness detection (#5958)
       │
       ▼
epoch-advance coordinator (#5962)
       │
       ▼
epoch-agreement protocol (#5965)
       │
       ▼
epoch commit dispatch (#5900)
       │
       ▼
eviction execution (#5986)
       │
       ▼
transport teardown + session cleanup
```

### Triggering

Eviction is driven by epoch commits. The executor implements
`EpochCommitSubscriber` and is registered with the
`EpochAdvanceCoordinator` via `subscribe()`. On each committed epoch
view, the executor:

1. Diffs the new member set against the cached prior roster.
2. Identifies removed peers via set difference.
3. For each removed peer, evicts the transport connection and releases
   session bindings.
4. Returns `EvictionOutcome` records for observability and downstream
   notification.

### EvictionAction

| Variant | Use Case |
|---------|----------|
| `Close` | Dead peers — immediate teardown; no point draining a dead link. |
| `Drain` | Graceful departures — allow in-flight work to complete before close. |

### EvictionOutcome

Each `EvictionOutcome` carries:
- `peer_id`: the evicted peer.
- `action`: the action taken (`Drain` or `Close`).
- `connections_closed`: number of transport connections closed (0 or 1).
- `sessions_released`: number of session bindings released.

### Integration Surface

```text
EpochAdvanceCoordinator
       │
       ▼ on_epoch_committed(view)
EvictionExecutor
       │
       ├──► ConnectionRegistry (lookup/remove by peer ID)
       ├──► SessionBindingTable (remove_all_for_peer)
       └──► EvictionCallback (bridges to ConnectionManager)
                │
                ▼
         ConnectionManager::drain / disconnect
```

The `EvictionCallback` is a `Box<dyn Fn(SocketAddr, EvictionAction) + Send + Sync>`
provided by the transport runtime. It bridges the sync epoch-commit callback
to the async `ConnectionManager` by spawning a tokio task for each eviction.

### Live Runtime Wiring

The eviction executor is wired into the production `MembershipRuntime`
via `wire_eviction_executor()`. Call this method once during startup
after initial peers have been registered and transport resources are
available:

```rust
let mut runtime = MembershipRuntime::new(config, my_id, class, domain);
runtime.add_peer(peer2_id, MemberClass::Voter, 2);
// ... register remaining peers ...

let registry = Arc::new(ConnectionRegistry::new());
let bindings = Arc::new(Mutex::new(SessionBindingTable::new()));

runtime.wire_eviction_executor(
    registry,
    bindings,
    Box::new(move |addr, action| {
        let mgr = conn_manager.clone();
        tokio::runtime::Handle::current().spawn(async move {
            match action {
                EvictionAction::Drain => { let _ = mgr.drain(addr).await; }
                EvictionAction::Close => { let _ = mgr.disconnect(addr).await; }
            }
        });
    }),
);
```

After wiring, the runtime feeds heartbeat-driven `MemberFailed` events
into the `EpochAdvanceCoordinator` as `PeerLivenessChange::Dead`
transitions. The coordinator commits a new epoch view removing the dead
peer, and the eviction executor subscriber tears down the associated
transport connection and releases session bindings.

New peers added via `add_peer()` are fed into the coordinator as
`PeerLivenessChange::Alive`, ensuring the coordinator's member set
stays in sync with the roster.

Use `has_eviction_wired()` to check whether the eviction pipeline is
active. The `EpochAdvanceCoordinator` is publicly accessible via the
`epoch_coordinator` field for direct liveness-change injection in tests
and recovery paths.

### Idempotency

- If a peer is not found in `ConnectionRegistry` (already evicted or never
  admitted), connection teardown is a no-op and `connections_closed` is 0.
- Session bindings for an already-cleared peer return an empty list.
- The prior-roster cache prevents duplicate evictions for the same epoch
  transition.


## Connection Establishment

The `ConnectionEstablishmentSubscriber` is the symmetric counterpart to
`EpochTeardownSubscriber`. It bridges membership epoch transitions to
transport connection establishment when new peers appear in the cluster
roster.

### Triggering

Establishment is triggered through two paths:

1. **Event-driven**: The subscriber implements `MembershipEventSubscriber`
   and listens for `MemberJoined` events. On each join event, a connection
   establishment callback is invoked if the peer is not already known.

2. **Roster-sync**: `sync_roster(new_roster)` diffs the cached known-peer
   set against a new committed roster and triggers establishment for every
   newly added peer. This is the primary entry point for epoch-commit-driven
   establishment.

### EstablishCallback

The `EstablishCallback` (`Box<dyn Fn(MemberId) + Send + Sync>`) is a
caller-provided closure that bridges to transport's connect API. The callback
receives a `MemberId`; the caller is responsible for resolving the member ID
to a network endpoint and initiating the transport connection.

```
impl ConnectionEstablishmentSubscriber {
    pub fn new(
        config: ConnectionEstablishmentConfig,
        connection_registry: Arc<ConnectionRegistry>,
        establish: EstablishCallback,
        initial_peers: BTreeSet<MemberId>,
    ) -> Self { ... }

    pub fn sync_roster(&self, new_roster: &BTreeSet<MemberId>) -> usize { ... }
    pub fn config(&self) -> &ConnectionEstablishmentConfig { ... }
    pub fn known_peer_count(&self) -> usize { ... }
}
```

The subscriber is non-blocking: the callback should spawn async work for
I/O-based connection establishment.

### ConnectionEstablishmentConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_attempts` | `u32` | 3 | Max connect attempts before giving up |
| `backoff_ms` | `u64` | 500 | Backoff in ms between retry attempts |

The subscriber exposes the config so the callback can read retry policy,
but the subscriber itself does not perform retries — that belongs to
the callback's internal async logic.

### Idempotency

- If a peer already has a connection entry in `ConnectionRegistry`,
  establishment is skipped.
- If a peer is already in the cached known-peer set, establishment is
  skipped.
- A second `MemberJoined` event for the same peer is a no-op.

### Relationship to connection_teardown

| Direction | Module | Trigger | Action |
|-----------|--------|---------|--------|
| Peer addition (event) | `connection_establishment` | `MemberJoined`, `sync_roster` diff | Invoke `EstablishCallback` |
| Peer addition (epoch) | `peer_add_connector` | Roster diff on epoch commit | Invoke `PeerAddCallback`, emit `PeerConnected` |
| Peer removal | `connection_teardown` | `MemberLeft`/`Failed`/`Drained`, `sync_roster` diff | Invoke `TeardownCallback` |
| Peer join (first-time) | `peer_join` | Inbound transport connect (unknown peer) | Verify identity, push epoch state, queue for roster |

The three modules share the same `ConnectionRegistry` and operate on
complementary roster transitions. Establishment only adds new peers;
teardown only removes departed peers. Together they keep the transport
connection set aligned with the committed membership roster.

## Roster Session Bridge

The `roster_session_bridge` module provides a unified handle
([`RosterSessionHandle`]) that bridges membership roster changes
(peer addition and removal) to transport session establish/teardown,
with per-peer notification channels so membership subsystems can
await session readiness before sending protocol messages.

### TransportSessionOps Trait

The [`TransportSessionOps`] trait abstracts per-peer transport session
lifecycle operations:

- `establish(peer_id, addresses)` — initiate transport session establishment
  to the peer. The implementation spawns async connect work and, on success,
  calls [`RosterSessionHandle::notify_session_ready`].
- `teardown(peer_id, graceful)` — initiate transport session teardown.
  `graceful=true` drains in-flight messages before closing (via the #6097
  session-drain infrastructure); `graceful=false` closes immediately. On
  completion, the implementation calls
  [`RosterSessionHandle::notify_session_lost`].

The trait is the membership-side abstraction; `tidefs-transport` provides
the production implementation.

### RosterSessionHandle

The [`RosterSessionHandle`] is the public API for other membership
subsystems. It implements [`MembershipEventSubscriber`] and delegates
roster events to [`TransportSessionOps`]:

| Event | Action |
|-------|--------|
| `MemberJoined` | `establish(peer_id, addresses)` |
| `MemberLeft` | `teardown(peer_id, graceful=true)` |
| `MemberFailed` | `teardown(peer_id, graceful=false)` |
| `MemberDrained` | `teardown(peer_id, graceful=false)` |
| `MemberSuspected`, `MemberDraining` | ignored |

#### Bidirectional Mapping

The handle maintains [`MemberId`]↔[`SessionId`] bidirectional mapping,
updated through notification callbacks from the transport layer:

- `notify_session_ready(peer_id, session_id)` — called after successful
  session establishment; updates the mapping and wakes waiters.
- `notify_session_lost(peer_id)` — called after session teardown; removes
  the mapping.

Query methods:

- `session_of(peer_id) -> Option<SessionId>`
- `peer_of(session_id) -> Option<MemberId>`
- `has_session(peer_id) -> bool`
- `session_count() -> usize`

#### Notification Channels

Subsystems call `session_ready(peer_id)` to obtain a [`SessionReady`]
future. If the peer already has an active session, the future resolves
immediately. Otherwise, it waits until `notify_session_ready` is called
for that peer.

```rust
// Subsystem usage:
let ready = handle.session_ready(peer_id);
tokio::spawn(async move {
    ready.wait().await;
    // Session is now established; safe to send protocol messages.
});
```

Multiple callers can wait on the same peer; a single
`notify_session_ready` wakes all waiters.

### Thread Safety

The handle is `Clone` (interior `Arc`). Clones share the same mapping
and notification channels. The handle is designed for single-threaded use
within `MembershipRuntime::tick()` for event delivery, consistent with
other membership event subscribers.

### Idempotency

- A second `MemberJoined` event for a peer with an already-registered
  session is a no-op.
- A `MemberLeft`/`MemberFailed`/`MemberDrained` for a peer without a
  registered session is a no-op.
- `notify_session_ready` for an already-mapped peer replaces the old
  mapping (reconnect).
- `notify_session_lost` cleans up any pending `SessionReady` notifier.

## Peer Address Registry

The `peer_address_registry` module provides a membership-owned lookup structure
mapping peer [`MemberId`]s to [`TransportAddr`] vectors, giving outbound
dispatch (#6093), session establishment (#6122), and eviction (#6097)
a single authority for peer endpoint resolution.

### PeerAddressRegistry

A shared, thread-safe registry backed by `RwLock<HashMap>`. Reads for
dispatch and session establishment are concurrent; writes for roster
changes acquire exclusive access.

```ignore
use tidefs_membership_live::peer_address_registry::PeerAddressRegistry;
use tidefs_membership_epoch::MemberId;
use tidefs_transport::addr::TransportAddr;

let reg = PeerAddressRegistry::new();
let peer = MemberId(1);
let addr: TransportAddr = "tcp://10.0.0.1:9100".parse().unwrap();
reg.register(peer, vec![addr]);
assert!(reg.contains(peer));
```

### API Surface

| Method | Description |
|---|---|
| `register(peer_id, addresses)` | Register or replace addresses for a peer |
| `deregister(peer_id)` | Remove a peer from the registry |
| `update(peer_id, addresses)` | Atomic replace for known-peer address changes |
| `resolve(peer_id) -> Option<Vec<TransportAddr>>` | Lookup all addresses |
| `resolve_first(peer_id) -> Option<TransportAddr>` | Lookup first address of any carrier |
| `resolve_one(peer_id) -> Option<SocketAddr>` | Lookup first TCP socket address, if any |
| `contains(peer_id) -> bool` | Check registration status |
| `len() -> usize` | Number of registered peers |
| `is_empty() -> bool` | True if no peers registered |

### Integration

The [`RosterSessionHandle`] calls `register` on peer addition and
`deregister` on peer removal or eviction. [`MembershipOutboundDispatch`]
calls `resolve` to obtain peer transport addresses before sending protocol
messages. Transport session establishment uses `resolve` to select
connection endpoints.

### Design Notes

- No per-message crypto, BLAKE3, or auth tokens — the registry is a plain
  address-index data structure.
- Carrier-agnostic: stores full [`TransportAddr`] enum values, including TCP,
  RDMA, and Unix variants. This is address bookkeeping, not a carrier
  readiness claim.
- `resolve_one` is a convenience for callers that only operate over TCP
  and want a bare `SocketAddr`.


## Transport Bridge

The `transport_bridge` module provides a bidirectional epoch-driven bridge
from committed membership epoch views to transport session lifecycle
management. Unlike the event-driven [`RosterSessionHandle`] which reacts
to individual member state transitions, [`MembershipTransportBridge`]
operates on whole-epoch diffs: every committed epoch advance produces a
set-difference between the previous and current member sets, and the
bridge dispatches the resulting additions and removals to the transport
layer through the [`TransportSessionManager`] trait.

### TransportSessionManager Trait

The [`TransportSessionManager`] trait is defined in membership-live and
implemented in `tidefs-transport`, keeping the dependency direction clean
(membership defines the interface, transport provides the implementation):

- `register_peer(peer_id, addresses)` — called when a peer is added to
  the committed epoch member set. The transport layer registers the peer
  in the cohort graph and initiates proactive outbound session
  establishment.
- `close_peer_sessions(peer_id)` — called when a peer is removed from
  the committed epoch member set. The transport layer tears down all
  sessions associated with that peer, draining in-flight messages before
  closing with `SessionCloseReason::PeerRemoved`.

### MembershipTransportBridge

[`MembershipTransportBridge`] implements [`EpochCommitSubscriber`] and is
registered with the [`EpochAdvanceCoordinator`]. On each epoch commit:

1. The new member set is extracted from the [`EpochView`].
2. The difference between the previous member set (stored internally) and
   the new member set is computed via `BTreeSet::difference`.
3. **Removed peers** (present in previous, absent in current) dispatch
   `close_peer_sessions` — session teardown with graceful drain.
4. **Added peers** (absent in previous, present in current) dispatch
   `register_peer` with resolved addresses from the shared
   [`PeerAddressRegistry`].
5. The previous member set is updated for the next diff.

#### Bidirectional Contract

| Direction | Trigger | Transport Action |
|-----------|---------|------------------|
| Roster addition | Peer appears in new epoch, absent from previous | `register_peer` → connect + handshake |
| Roster removal | Peer absent from new epoch, present in previous | `close_peer_sessions` → drain + close |

#### Edge Cases

- **Empty diff** (no membership change): no calls are dispatched.
- **First epoch after bridge construction**: the bridge treats the entire
  member set as additions; call [`set_initial_member_set`] to seed the
  previous set and suppress false additions.
- **Duplicate removals** (peer re-removed): idempotent — the session
  registry entry is removed on the first call, returning an empty list
  on subsequent calls.
- **Self-removal** (local node evicted from roster): the bridge calls
  `close_peer_sessions` for the local peer ID; the transport layer is
  responsible for coordinating with the local shutdown path.

### Integration with RosterSessionHandle

[`MembershipTransportBridge`] and [`RosterSessionHandle`] operate at
different granularities: the bridge processes whole-epoch set diffs
(batch additions/removals), while the handle reacts to individual
`MemberJoined`/`MemberLeft`/`MemberFailed` events. Both consume roster
changes and drive transport session lifecycle; they are complementary
paths within the membership-to-transport bridge surface.

## Join Response Dispatch and Handling

The `join_response` module completes the membership join handshake by
delivering join acceptance or rejection decisions to joining peers over
transport, and processing inbound join responses on the joiner side.

### JoinOutcome

The `JoinOutcome` enum represents the result of a join-request evaluation:

- `Accepted { member_id, epoch, roster }` — join request accepted, carrying
  the assigned `MemberId`, cluster `Epoch` at acceptance, and the current
  roster member set.
- `Rejected { reason }` — join request rejected with a human-readable reason.

### JoinResponseDispatcher

The `JoinResponseDispatcher` constructs `MembershipOutboundMessage::JoinResponse`
messages and dispatches them through the existing outbound transport pipeline
via `MembershipOutboundDispatch`. It provides two methods:

- `send_acceptance(request_member_id, assigned_epoch)` — sends an acceptance
  join response with the assigned epoch.
- `send_rejection(request_member_id, reason)` — sends a rejection join
  response with the reason.

The dispatcher is called by the epoch coordinator after evaluating a join
request to deliver the outcome to the joining peer.

### JoinResponseHandler

The `JoinResponseHandler` implements `MembershipMessageHandler`, overriding
`handle_join_response` to process inbound join responses. It can be registered
via `HandlerSet::with_join_response_handler()` at discriminant slot 1.

Features:

- **Idempotent re-delivery**: Tracks processed `(member_id, epoch)` pairs
  and silently drops duplicates, ensuring safe retransmission handling.
- **Acceptance callback**: Fires on accepted responses, delivering the
  `JoinOutcome::Accepted` payload so the runtime can trigger roster state
  sync (#6140), session establishment, and epoch catch-up.
- **Rejection callback**: Fires on rejected responses, delivering the
  rejection reason for operator visibility or retry logic.
- **No-op when unconfigured**: If no callbacks are set, the handler records
  idempotency state and returns silently.

### Integration

```text
EpochCoordinator accepts join request
      |
      v
JoinResponseDispatcher::send_acceptance(peer_id, epoch)
      |
      v
Transport send pipeline  -->  Joining peer receives JoinResponse
                                    |
                                    v
                            MembershipInboundDispatch (slot 1)
                                    |
                                    v
                            JoinResponseHandler::handle_join_response()
                                    |
                                    +-- idempotency check
                                    +-- fire acceptance/rejection callback
```

The `JoinResponse` wire format carries the acceptance decision and assigned
epoch. Full roster state synchronization is handled by the roster state sync
module (#6140), which the acceptance callback should trigger.

## Join Initiator State Machine

The `join_initiator` module drives the joining peer's side of the membership
join handshake. It is a pure-logic state machine with no I/O: callers feed
events (transport connection, response arrival, timeout, disconnect) and the
state machine transitions, returning actions the caller must execute.

### State Machine

```
Idle ──► Connecting ──► RequestSent ──► Accepted ──► Active
  ▲          │                │              │
  │          │ (timeout or    │ (reject      │
  │          │  disconnect)   │  with retry) │
  └──────────┴────────────────┴──────────────┘
               Rejected (retries exhausted)
```

| State | Description |
|-------|-------------|
| `Idle` | No join in progress. Ready to initiate. |
| `Connecting` | Transport session to coordinator being established. |
| `RequestSent` | JoinRequest dispatched, awaiting response. |
| `Accepted` | JoinResponse::Accepted received; roster installation pending. |
| `Rejected` | Permanently rejected (retries exhausted or fatal rejection). |
| `Active` | Roster installed and local member is operational. |

### Core Types

- `JoinInitiatorConfig` — configuration with `coordinator_member_id`,
  `request_timeout_ms` (default 15s), `max_retries` (default 5), and
  `backoff_base_ms` (default 1s). All config is immutable after construction.
- `JoinInitiatorState` — the six states listed above.
- `JoinResult` — outcome of each transition call: `InProgress`, `Accepted`,
  `Rejected` (with `retries_exhausted` flag), or `Active`.

### JoinInitiator API

The state machine is driven through a sequence of transition methods, each
validating the current state before progressing:

- `initiate()` — `Idle → Connecting`. Records initiation timestamp.
  Returns `Err` if called from a non-`Idle` state (double-join prevention).
- `on_connected()` — `Connecting → RequestSent`. Caller must serialize and
  dispatch a `JoinRequest` over transport. Records request timestamp.
- `on_response(outcome)` — `RequestSent → Accepted` or `RequestSent → Idle`
  (retry) or `RequestSent → Rejected` (exhausted). Processes the coordinator's
  `JoinOutcome`: on `Accepted`, stores the assigned `MemberId`, `EpochId`, and
  roster; on `Rejected`, applies backoff and retry or signals permanent
  failure.
- `install_roster(roster)` — `Accepted → Active`. Writes all members from the
  accepted roster into the local `MembershipRoster` and verifies the assigned
  member is present. Returns `Err` if not in `Accepted` or if the assigned
  member ID is missing.
- `on_timeout()` — `RequestSent → Idle` or `RequestSent → Rejected`.
  Request deadline expired; retries or exhausts.
- `on_disconnect()` — `Connecting | RequestSent → Idle` or `→ Rejected`.
  Transport disconnect during handshake; retries or exhausts. No-op when
  `Idle`; error from `Accepted`, `Rejected`, or `Active`.

Callers can poll `is_timed_out(now_ms)` and `backoff_delay_ms()` to implement
deadline detection and exponential-backoff sleep before re-initiating.

### Integration

The joining peer side of the handshake consumes `JoinResponse` messages
dispatched by the coordinator's `JoinResponseDispatcher` (#6147) and received
via the `JoinResponseHandler`. After acceptance, roster state is synchronized
by the roster sync module (#6140). The initiator's `install_roster` writes the
received member set into the local `MembershipRoster` before transitioning to
`Active`.

```text
Joining peer initiates via JoinInitiator
      |
      v
Transport connect to coordinator
      |
      v
JoinRequest dispatched over transport
      |
      v
Coordinator evaluates → JoinResponse dispatched
      |
      v
JoinResponseHandler → JoinInitiator::on_response()
      |
      +-- Accepted → install_roster() → Active
      +-- Rejected → backoff → retry or permanent Rejected
```

### Error Modes

- Double-join prevention: `initiate()` returns `Err` from non-`Idle` states.
- Wrong-state calls: all transition methods return `Err` with the unexpected
  state name when called out of sequence.
- Roster installation failure: `install_roster` returns `Err` if the assigned
  member is not found in the roster after writing (consistency guard).
- Retry exhaustion: when `max_retries` (or timeout/disconnect equivalents)
  is reached, the state machine transitions to terminal `Rejected`.

### Caller Contract

The caller (e.g., daemon bootstrap or node-join driver) is responsible for:

1. Establishing the transport session to the coordinator when the machine
   enters `Connecting`.
2. Serializing and dispatching the `JoinRequest` message after `on_connected`.
3. Delivering received `JoinOutcome` variants to `on_response`.
4. Sleeping for `backoff_delay_ms()` before re-calling `initiate()` on
   retryable rejections.
5. Calling `install_roster` with the live `MembershipRoster` when the
   machine enters `Accepted`.


## Heartbeat Protocol

The heartbeat module (`heartbeat` module) provides deadline-based peer
liveness detection that bridges transport-level health signals into
membership events for autonomous failure recovery.

### State Machine

```
  Alive --(deadline expires)--> Suspected --(deadline expires)--> Failed
    ^                               |
    +---(heartbeat received)--------+
```

### Core Types

- `HeartbeatConfig` — interval (how often to send), deadline (when to mark
  Suspected), and max_missed_count (consecutive missed intervals before
  declaring Failed). Validates that deadline >= interval and all values
  are non-zero.
- `LivenessStatus` — Alive, Suspected, or Failed with PartialOrd ordering.
- `PeerLiveness` — per-peer record tracking last_heard_ms, missed_count,
  and current status.
- `HeartbeatTransmitter` — periodic transmitter that builds
  `MembershipOutboundMessage::HealthReport` messages for every known peer
  via the outbound dispatch pipeline (#5841). Skips self and enforces the
  configured transmit interval.
- `PeerLivenessTracker` — deadline-checking loop that transitions peers
  through Suspected to Failed, publishing `MembershipEvent::MemberSuspected`
  and `MembershipEvent::MemberFailed` through the `MembershipEventPublisher`.

### Integration Points

- `HeartbeatTransmitter` uses `MembershipOutboundDispatch` to send
  `HealthReport` messages to all known peers at the configured interval.
- `PeerLivenessTracker` uses `MembershipEventPublisher` to emit liveness
  events consumed by connection teardown (#5854) and connection
  establishment (#5867) subscribers for autonomous peer lifecycle
  management.
- The heartbeat protocol operates independently of the SWIM-style
  failure detector; both can coexist for layered liveness assurance.

### Configuration Knobs

| Parameter | Default | Description |
|-----------|---------|-------------|
| interval | 500ms | Time between transmitted HealthReport messages |
| deadline | 1500ms | Time without a heartbeat before marking Suspected |
| max_missed_count | 3 | Consecutive missed deadlines before declaring Failed |


## Peer Unreachability Tracking


The `PeerUnreachableTracker` detects peer unreachability driven by transport

session disconnect events, bridging the `RosterSessionHandle` session lifecycle

notifications (#6122) into automatic roster removal proposals via the

`EpochAdvanceCoordinator` (#5900). This enables autonomous cluster

reconfiguration around failed nodes without operator intervention.



### State Machine



```text

  Connected --(session lost)--> Disconnected --(grace expires)--> Unreachable

      ^                          |                                   |

      +---(session ready)--------+-----------------------------------+

```



### Core Types



- `PeerUnreachableConfig` — builder-pattern configuration with a single

  parameter `unreachable_grace_ms` (default 30_000 ms). A peer is only

  considered unreachable after its transport session has been down for

  at least this duration.

- `PeerUnreachableStatus` — per-peer queryable status: `Connected`,

  `Disconnected { since_ms }`, or `Unreachable { since_ms, removal_proposed }`.

  Exposed for operator visibility (e.g., `tidefsctl membership status`).

- `PeerUnreachableTracker` — multi-peer tracker managing per-peer connectivity

  state and producing `PeerLivenessChange` events on grace expiry.



### Integration



1. `MembershipRuntime` holds a `PeerUnreachableTracker` and calls `tick()` in

   its main event loop.

2. `RosterSessionHandle` (or the transport layer) calls

   `MembershipRuntime::notify_session_connected()` and

   `notify_session_disconnected()` when transport sessions are established or

   lost.

3. On disconnect, the tracker starts a per-peer grace timer. If the session

   is re-established before the grace expires, the timer resets and no action

   is taken.

4. When the grace period expires, the tracker produces a `PeerLivenessChange`

   (Alive -> Dead) which is fed into the `EpochAdvanceCoordinator` to propose

   automatic roster removal.

5. Subscribers to committed epoch views (e.g., `EvictionExecutor`) then

   execute the removal, tearing down any remaining transport resources.



### Grace Duration



| Parameter | Default | Description |

|-----------|---------|-------------|

| unreachable_grace_ms | 30_000 | Disconnect duration before proposing removal |


## Epoch Advance Coordinator

The `EpochAdvanceCoordinator` bridges peer liveness detection (#5958) to
committed epoch views (#5900). When the liveness state machine reports a
peer transition to Dead or Alive, the coordinator evaluates whether the
change warrants a membership view update and, if so, produces a new
committed `EpochView` and notifies registered `EpochCommitSubscriber`s.

### Input Contract

Liveness changes arrive as `PeerLivenessChange` values: a member id,
previous status, new status, and timestamp. The coordinator tracks the
current `EpochView` (member set + epoch number) and advances it when a
transition changes the member set.

### Output Contract

When a new epoch view is committed, every registered `EpochCommitSubscriber`
receives the callback. The committed view is available via `current_view()`.

### Idempotency

Repeated liveness changes with the same `previous_status` and `new_status`
for a given member are suppressed: the coordinator records the last change
per member and does not produce duplicate epoch advances.

### Quorum Guard

The coordinator will not produce an epoch view whose member set drops below
the configured `min_members`, preventing single-node clusters from losing
their only member through a liveness event.

### Integration Points

- `PeerLivenessTracker`: source of liveness changes (Alive, Suspected, Failed).
- `EpochCommitSubscriber`: subscriber dispatch that epoch views flow into for
  transport notification.
- Transport epoch-gate enforcement (#5889): downstream consumer of committed
  epoch views for stale-epoch rejection.

### Lifecycle

1. Construct via `EpochAdvanceCoordinator::new(min_members)`.
2. Call `initialize(members, now_ms)` with the initial member set.
3. Register subscribers via `subscribe(Box<dyn EpochCommitSubscriber>)`.
4. Feed liveness changes via `on_liveness_change(change)`.
5. Committed epoch views flow to subscribers automatically.


## Liveness Trigger Dispatch

The `LivenessTriggerDispatcher` bridges health-score-driven peer liveness
transitions from the [`HealthScoreLivenessTracker`] (#6035) to the
[`EpochAdvanceCoordinator`] (#5962).  It detects 3-state
(Alive/Suspect/Dead) transitions and maps them to binary
`PeerLivenessChange` events that drive epoch-advance proposals.

### Pipeline Position

```text
HealthScoreLivenessTracker (health scorer, #6035)
       │
       ▼  PeerLivenessState transitions
LivenessTriggerDispatcher (this module)
       │
       ▼  PeerLivenessChange events
EpochAdvanceCoordinator (epoch-advance, #5962)
       │
       ▼  committed EpochView
EvictionExecutor (#5999) / PeerAddConnector (#6017) (transport actions)
```

### Transition Mapping

| Health Scorer Transition | Binary Liveness Change  | Proposal         |
|--------------------------|-------------------------|------------------|
| Unknown → Alive          | no-op                   | none             |
| Alive → Suspect          | no-op (pass-through)    | none             |
| Suspect → Dead           | Alive → Dead            | removal          |
| Alive → Dead (direct)    | Alive → Dead            | removal          |
| Suspect → Alive          | Dead → Alive            | reinstatement    |
| Dead → Alive             | Dead → Alive            | reinstatement    |

Suspected transitions (Alive→Suspect) are passed through without generating
a proposal.  A Suspected peer is still a member and should not be removed
until confirmed Dead.

### LivenessTriggerConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `cooldown_ms` | `u64` | 5_000 | Cooldown after a proposal before the same peer can trigger another |
| `enable_reinstatement` | `bool` | `true` | Whether Suspect/Dead→Alive recovery generates reinstatement proposals |

### LivenessTriggerDispatcher

- `new(config)` — create with explicit configuration.
- `with_defaults()` — create with default config (5s cooldown, reinstatement on).
- `process_tracker(tracker, coordinator, now_ms)` — poll all tracked peers
  from `HealthScoreLivenessTracker`, detect transitions, and feed proposals
  into `EpochAdvanceCoordinator`.  Returns a `Vec<TriggerOutcome>`.
- `process_single(member_id, prev, current, coordinator, now_ms)` — inject a
  single state transition explicitly (for testing and external events).
- `reset_peer(member_id)` / `reset_all()` — clear tracking state.
- `in_cooldown(member_id, now_ms)` — query whether a peer is in the debounce window.
- `config()` — access the configuration.

### TriggerOutcome

- `Suppressed` — no proposal (no-op transition, cooldown, or not tracked).
- `RemovalProposed { member_id }` — removal proposal forwarded to coordinator.
- `ReinstatementProposed { member_id }` — reinstatement proposal forwarded.

Outcomes are pure state-transition records with no new wire types or
protocol layers.  The existing transport/session security boundary applies.

### Cooldown / Debounce

Each peer enters a configurable cooldown window after a proposal is
generated.  Any transition within the window is suppressed, preventing
proposal flapping on rapid health-score oscillation.  The cooldown
resets on each new proposal for that peer.

### Integration

During each membership runtime tick, the dispatcher's `process_tracker`
is called with the shared `HealthScoreLivenessTracker` and
`EpochAdvanceCoordinator`.  Generated proposals flow through the
coordinator as `PeerLivenessChange` events, which produce committed
`EpochView`s delivered to registered `EpochCommitSubscriber`s
(eviction executor, peer-add connector, session binding table).

## Deterministic Testing

The `TransportEventRecorder` and `DeterministicReplayHarness` enable
deterministic epoch-transition integration testing without a live transport
stack.

### TransportEventRecorder

Records transport-to-membership bridge events into a thread-safe,
serializable log for later replay.

- `TransportEventRecorder::new()` creates a recorder (starts recording).
- `recorder.record(event)` captures a `MembershipTransportEvent`.
- `recorder.drain_events()` returns the recorded `EventLog` and clears it.
- `recorder.export_json()` serializes the log for bug-reproduction sharing.
- The recorder uses `Arc<RwLock<EventLog>>` for concurrent use alongside live
  transport.

Six event kinds are captured:

- `PeerConnected` / `PeerDisconnected` — transport session lifecycle.
- `HealthScoreChanged` — peer health score in [0.0, 1.0].
- `MessageReceived` — a membership protocol message arrived over transport.
- `MessageSendCompleted` — a message was successfully sent (tracking only).
- `ConnectionError` — a transport-level error was observed.

### DeterministicReplayHarness

Wraps a `MembershipRuntime` and replays recorded `EventLog`s with
configurable inter-event delays.

```rust
use tidefs_membership_live::{TransportEventRecorder, DeterministicReplayHarness, EventLog};

// Record events alongside live transport
let recorder = TransportEventRecorder::new();
recorder.record(MembershipTransportEvent::PeerConnected {
    peer_id: MemberId::new(2),
    label: "peer-2".into(),
});
let log = recorder.drain_events();

// Replay deterministically
let mut harness = DeterministicReplayHarness::new_zero_delay(1, log);
harness.generate_peer_key(MemberId::new(2));
let outcome = harness.replay_all();
assert_eq!(outcome.events_replayed, 1);
```

Key methods:

- `replay_all()` — replays every event and returns a `ReplayOutcome`.
- `replay_until_epoch(target)` — replays until reaching a target epoch.
- `step()` — replays one event at a time for step-by-step debugging.
- `inject_fault(fault)` — injects drop, duplicate, reorder, or delay faults.
- `reset(self_id)` — resets the harness for a fresh replay from the beginning.

Fault injection variants:

- `ReplayFault::Drop { index }` — skip an event.
- `ReplayFault::Duplicate { index }` — deliver an event twice.
- `ReplayFault::Reorder { i, j }` — swap two events.
- `ReplayFault::Delay { index, extra_ticks }` — add tick delay before an event.

### Why deterministic replay matters

Live transport events are asynchronous and timing-dependent, making
epoch-transition logic inherently non-deterministic in tests. By recording
real transport events and replaying them through the harness, the same
event sequence produces identical membership state every time, enabling
regression tests, bug reproduction, and chaos-style fault injection without
a running transport stack.

## Transition Journal Replay

The coordinator maintains a `MembershipTransitionJournal` for crash-recovery
of in-flight join and leave transitions. On coordinator promotion after a
crash, the new coordinator replays the journal to resolve pending transitions
without external intervention.

### Lifecycle

1. **Prepare** — Before validating a join or leave, `record_prepare()` writes
   the intent to the journal.
2. **Commit** — After successful broadcast, `record_commit()` marks the
   transition complete.
3. **Abort** — On validation failure or rejection, `record_abort()` finalises
   the transition.

### Replay on Promotion

When a new coordinator is promoted (detected via lowest-`MemberId` check in
`MembershipRuntime::tick()`), `replay_transition_journal()` replays the
journal:

- **Committed transitions** are re-broadcast via outbound dispatch (`PeerJoined`
  for joins, `LeaveNotification` for leaves) to ensure all members converge.
- **Stale prepared transitions** (older than 30s by default) are auto-aborted.

Replay is idempotent: committed records are re-broadcast every replay cycle,
so late-joining or recovering peers eventually receive the transition result.

### Integration Points

- `MembershipRuntime::transition_journal` — `Arc<Mutex<MembershipTransitionJournal>>`
  owned by the runtime, wired into join and leave paths.
- `PeerJoinHandshake::set_journal()` — attaches the journal to the join handshake.
- `RosterLeaveNotifier::with_journal()` — attaches the journal to leave notification.
- `MembershipRuntime::replay_transition_journal()` — replays on coordinator
  promotion, called from `tick()` when the local node is the current coordinator
  and `journal_needs_replay` is true.
- `coordinator_promotion::replay_transition_journal()` — standalone function
  performing the replay and returning a `TransitionJournalReplayResult`.

## Join Request Handling and Admission Lifecycle

The `join_request` module implements the coordinator-side entry point for
the join protocol: receiving join requests from transport, validating
admission constraints, tracking join state through the admission lifecycle,
initiating quorum proposals, and delivering outcomes to the joining peer.

### AdmissionState

The `AdmissionState` enum defines the lifecycle states for a join request:

| State | Description |
|-------|-------------|
| `Pending` | Join request received and validated; awaiting proposal initiation |
| `Proposed` | A quorum proposal has been initiated for this join |
| `Accepted` | The quorum has accepted the join |
| `Rejected` | The join was rejected (validation failure, quorum rejection, or timeout) |
| `Committed` | The join has been committed to the epoch and the peer is now a member |

Terminal states are `Rejected` and `Committed`. Once terminal, the join is
eligible for removal from the active tracking set.

### PendingJoin

`PendingJoin` tracks a single in-flight join request through the admission
lifecycle, recording the member id, join epoch, timestamps, and current
state. It provides state-transition methods (`mark_proposed`, `mark_accepted`,
`mark_rejected`, `mark_committed`) and timeout detection via `is_expired`.

### JoinRequestHandler

`JoinRequestHandler` implements `MembershipMessageHandler`, overriding
`handle_join_request` to process inbound `MembershipMessage::JoinRequest`
messages. It can be registered via `HandlerSet::with_join_request_handler()`
at discriminant slot 0.

**Validation rules:**

- **Already member**: rejects if the peer is already in the roster
- **Cluster full**: rejects if the roster has reached `max_members`
- **Duplicate pending**: rejects if a non-terminal join is already in progress
  for the same peer

**Admission lifecycle:**

1. Validates admission constraints on receipt
2. Creates a `PendingJoin` in `Pending` state
3. Transitions to `Proposed` and invokes the `on_propose` callback, which
   the runtime wires to broadcast a `ProposalSubmission` through the quorum
   system (#6176)
4. The runtime calls `accept()` or `reject()` when quorum outcomes arrive
5. The `on_outcome` callback fires on acceptance or rejection, which the
   runtime wires to `JoinResponseDispatcher` to deliver the result to the
   joining peer (#6147)
6. Once committed to the epoch, the runtime calls `commit()` to finalize

**Timeout handling:**

- `reap_expired(now_millis)` transitions any join in `Pending` or `Proposed`
  state older than `join_timeout_ms` to `Rejected` and fires the outcome
  callback
- `purge_terminal()` removes completed (terminal) joins from the active set
- The runtime should call both periodically in its tick loop

**Callback architecture:**

- `set_on_propose(cb)`: sets the proposal initiation callback. The callback
  receives a `&PendingJoin` and should broadcast a
  `MembershipOutboundMessage::ProposalSubmission` to the quorum system.
- `set_on_outcome(cb)`: sets the outcome delivery callback. The callback
  receives a `PendingJoin` in terminal state (Accepted or Rejected) and
  should deliver the result via `JoinResponseDispatcher`.
- `set_roster(roster)`: provides the authoritative membership roster for
  duplicate-member and capacity checks.

### Integration

```text
Transport receive path
    |
    v
MembershipInboundDispatch (slot 0)
    |
    v
JoinRequestHandler::handle_join_request()
    |
    +-- validate_admission()
    |     +-- roster.lookup() -> already member?
    |     +-- roster.len() >= max_members?
    |     +-- duplicate pending join?
    |
    +-- create PendingJoin (state = Pending -> Proposed)
    |
    +-- on_propose callback -> broadcast ProposalSubmission (#6176)
    |
    ... (quorum voting) ...
    |
    +-- runtime calls accept() or reject()
          |
          +-- on_outcome callback -> JoinResponseDispatcher (#6147)
                |
                v
          Joining peer receives JoinResponse
```


## Coordinator-Side JoinHandler (Pure Logic)

The `join_handler` module provides the coordinator-side pure-logic validator for
inbound join requests. While `JoinRequestHandler` manages the admission lifecycle
(proposal initiation, timeout, outcome delivery), `JoinHandler` validates the
join request against coordinator authority, roster constraints, and incarnation
freshness before the admission lifecycle begins.

### Role

Sits between the transport receive path and the admission lifecycle. Inbound
join requests arrive at the coordinator, pass through `JoinHandler` for
validation, and only valid requests proceed to `JoinRequestHandler` for
proposal and commitment.

### Validation Gates

1. **Invalid member ID**: rejects `MemberId::ZERO` (reserved).
2. **Coordinator authority**: rejects if self is not the current coordinator.
3. **Incarnation freshness**: rejects messages carrying an incarnation below
   the coordinator's current incarnation (stale-message guard, via
   `IncarnationTracker` from #6208).
4. **Already member**: rejects if the peer is in the committed roster.
5. **Join in progress**: rejects if a pending join for this peer already exists.
6. **Roster constraints**: runs `validate_add_peer` from
   `tidefs-membership-epoch::roster_constraints` (#6214) rejecting on
   `PeerAlreadyPresent` or `TooManyPeers`.

### Types

- `JoinHandler` -- pure-logic validator struct holding self identity, coordinator
  flag, roster, constraints, incarnation tracker, and pending-join set.
- `JoinHandlerResult` -- outcome enum: `Accepted(JoinProposal)` or
  `Rejected(JoinRejectionReason)`.
- `JoinProposal` -- payload carrying the joining peer, target epoch, and
  idempotency key.
- `JoinRejectionReason` -- structured rejection causes with `Display`
  formatting for wire delivery.
- `JoinIdempotencyKey` -- deterministic key derived from peer identity and
  epoch for safe coordinator retransmission after failover (#6239).

### Idempotency

`handle_join_request_idempotent()` returns the same `JoinProposal` for a
previously accepted peer, enabling the coordinator to safely retransmit after
a brief network partition without double-committing the roster addition.
The idempotency key is deterministic across retransmissions and expires
naturally when the epoch advances.

### Mutable Helpers

- `set_coordinator(bool)` -- toggle coordinator authority after election.
- `set_roster(roster)` -- replace the roster after epoch advance.
- `set_incarnation_tracker(tracker)` -- update the incarnation reference.
- `complete_join(peer)` -- release a completed join's pending slot.
- `clear_pending()` -- reset all pending-join state.

### Integration

```text
Transport receive path
    |
    v
JoinHandler::handle_join_request()  [PURE LOGIC -- this module]
    |
    +-- coordinator check
    +-- incarnation validation (#6208)
    +-- roster already-member check
    +-- duplicate-in-flight check
    +-- validate_add_peer (#6214)
    |
    v
JoinHandlerResult::Accepted(JoinProposal)
    |
    v
JoinRequestHandler (admission lifecycle -- join_request module)
    |
    v
Proposal commit path / JoinResponseDispatcher
```

### Runtime Wiring

`MembershipRuntime` owns a `JoinHandler` field initialised at construction and
kept in sync during each `tick()` call: coordinator authority, active roster
members, and incarnation tracker are refreshed from the runtime's current state.
Callers can use `runtime.join_handler.handle_join_request()` to validate
inbound join requests before feeding the result into the admission lifecycle.
## Coordinator Epoch Lease

Prevents split-brain coordinator operation during network partitions by requiring the active coordinator to periodically confirm majority connectivity through transport heartbeats.

### Lease Lifecycle

1. **Activation**: When a node becomes coordinator (promotion via `CoordinatorPromotion` #6160), `CoordinatorLease::activate()` starts the lease machinery.
2. **Heartbeat Rounds**: Every `heartbeat_interval/3` (the tick interval), the coordinator sends a `CoordinatorHeartbeat` to every roster member with a monotonic `lease_nonce`.
3. **Ack Collection**: During the collection window (one tick), peers reply with `CoordinatorHeartbeatAck`. Acks with a stale nonce are silently dropped.
4. **Evaluation**: At the end of each collection window, the coordinator evaluates whether it received acks from a majority of roster members (`floor(N/2) + 1`). If yes, the lease is renewed for another `lease_duration`. If not, the round is recorded as lost.
5. **Expiration**: If no successful renewal occurs within `lease_duration`, the lease transitions to `LeaseStatus::Lost`. The coordinator must step down.
6. **Deactivation**: `CoordinatorLease::deactivate()` stops heartbeat emission and clears collection state.

### Peer-Side Handling

`handle_inbound_heartbeat()` processes incoming `CoordinatorHeartbeat` messages:
- **Matching epoch**: Reply with `CoordinatorHeartbeatAck` immediately.
- **Stale epoch** (heartbeat < local): Reply with ack, no side effect.
- **Future epoch** (heartbeat > local): Reply with ack and signal epoch catch-up via `AckWithCatchUp`.

### Types

- `CoordinatorLeaseConfig`: Configures `lease_duration` (default 30s) and `heartbeat_interval` (default 10s, tick fires at 3.33s).
- `CoordinatorLease`: Tick-driven state machine. Callers invoke `tick(now_ms, roster_members)` periodically.
- `CoordinatorHeartbeatRequest`: Pending heartbeat to send via transport.
- `LeaseStatus::Held` / `LeaseStatus::Lost`: Outcome of lease evaluation.
- `HeartbeatResponse`: Peer-side response classification (Ack, AckStale, AckWithCatchUp).

### Integration

- Activated on coordinator promotion (#6160).
- On `LeaseStatus::Lost`, the stepdown callback notifies the coordinator promotion subsystem to trigger failover.
- Complements the quorum-confirmed roster change protocol (#6176) and membership liveness tracking (#5794).

## Bootstrap Discovery

The `seed_discovery` module provides cold-start cluster bootstrap: a node
with no prior membership state discovers an existing cluster by probing a
configured list of seed addresses.

### Flow

1. The operator supplies a list of seed addresses as `"host:port"` strings
   (e.g., `"seed1.tidefs.local:9100"` or `"10.0.0.1:9100"`).
2. [`SeedDiscovery`] resolves DNS for each seed, tries transport connections
   in order with per-seed timeouts, and stops at the first successful
   connection.
3. On success, the resolved address is registered in the
   [`PeerAddressRegistry`] under a temporary [`MemberId`], and the transport
   session handle is returned for handoff to [`JoinInitiator`] for the join
   handshake.
4. On failure (all seeds exhausted), [`SeedDiscoveryError`] carries
   per-seed failure detail for operator diagnosis.

### Configuration

- `seeds` — ordered list of `"host:port"` strings.
- `per_seed_connect_timeout` — connection deadline per seed (default 10 s).

### Temporary node IDs

Since the real [`MemberId`] of a seed peer is not known before the join
handshake, each probe assigns a temporary node ID from a high range
(`u64::MAX - probe_index`). After [`JoinInitiator`] completes, callers
update the registry with the real identity.

### Integration

- Wraps a shared `Arc<Mutex<Transport>>` for outbound connections.
- Feeds the discovered session into [`JoinInitiator`] for the join
  handshake.
- Purely synchronous; DNS resolution uses [`std::net::ToSocketAddrs`].

## Checkpoint Persistence

The `checkpoint_persistence` module provides durable epoch checkpoint
persistence backed by `LocalObjectStore` for bounded-replay crash recovery.

### Architecture

1. **`CheckpointPersistence`** implements `EpochSnapshotStore` from
   `tidefs_membership_epoch::snapshot`, storing each checkpoint as a named
   object under the local object store root directory.
2. **Named objects** use the key format `__membership_checkpoint_{seq:020}`
   for individual snapshots, with a `__membership_checkpoint_head` sentinel
   tracking the latest sequence number as a little-endian u64.
3. **Write path**: The checkpoint object is written first, then the head
   sentinel is updated.  This provides crash safety: on recovery, the head
   always points to a complete checkpoint.
4. **Read path**: The head sentinel is consulted first, then the
   corresponding checkpoint object is fetched and deserialized.

### Lifecycle

- **Open**: `CheckpointPersistence::open(root)` creates or opens a
  `LocalObjectStore` under the given directory, ready for checkpoint
  read/write operations.
- **Write**: When a `CheckpointManager` calls `write_snapshot`, the
  encoded bytes and head sentinel are persisted atomically.
- **Read**: `read_snapshot(seq)` retrieves a specific checkpoint by
  sequence number; `list_snapshots` returns at most the latest sequence
  via the head sentinel.
- **Clear**: Resets the head sentinel to signal no checkpoints.

### Integration with MembershipRuntime

The `MembershipRuntime::set_checkpoint_store(store)` method accepts any
`Box<dyn EpochSnapshotStore>` and installs a `CheckpointManager`.  After
each quorum-confirmed epoch advancement in `fire_transition_callbacks`,
the runtime captures the current roster (with transport addresses from
the peer address registry), the coordinator identity (lowest active
member ID), and the current incarnation, then persists a checkpoint
through the manager.  On restart, the checkpoint is loaded before
transition journal replay to bound replay to only post-checkpoint entries.
