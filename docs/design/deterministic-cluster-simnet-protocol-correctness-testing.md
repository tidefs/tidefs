# Deterministic Cluster Simnet for Protocol Correctness Testing

**Issue**: [#1175](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1175)
**Kind**: Design / Specification
**Status**: design-spec
**Priority**: P2
**Complements**: #882 (distributed runtime gaps), #903 (network partition reconciliation), #1174 (trace oracle)

---

## 1. Motivation

Current distributed protocol testing uses real TCP/TLS transport via `tidefs-transport`. Real-network testing is essential for integration but carries two
well-known costs:

- **Non-determinism**: socket scheduling, OS timer jitter, and thread
  interleaving make reproducing protocol bugs difficult and prevent use as a
  regression oracle.
- **Slowness**: each integration test spawns threads, binds ports, and pays
  real network overhead. A full cluster scenario can take seconds.

deterministic simulator (`simnet.py`, `cluster_api.py`, `scenarios_suite.py`).
That approach caught raft-like consensus bugs, lease bugs, and replication
ordering bugs before they reached the network. The Rust codebase currently has
no equivalent.

This design describes `tidefs-simnet`: a deterministic, in-process,
no-RNG cluster simulator that exercises the same transport trait and
replication model as production, produces fully reproducible JSONL traces, and
serves as a CI regression oracle.

---

## 2. Core Invariants

| Invariant | Mechanism |
|-----------|-----------|
| No RNG | All scheduling decisions use round/cycle counters; pseudo-randomness seeded from a fixed seed and drawn from a deterministic PRNG (ChaCha20) with sequenced calls. |
| No real networking | Messages delivered in-process through channels; `SimTransport` implements the same trait surface as the production transport. |
| No wall-clock time | Virtual ticks advance only when all nodes are idle or at explicit yield points. |
| Fully reproducible | Same seed + same scenario → same execution trace (JSONL), same per-node state fingerprint (BLAKE3). |
| Same trait surface | `SimTransport` implements the `TransportBackend` trait from `tidefs-transport`, so replication-model and membership-live consumers see no difference. |

---

## 3. Crate Structure

```
crates/tidefs-simnet/
├── Cargo.toml
└── src/
    ├── lib.rs              # public API, re-exports
    ├── clock.rs            # SimClock: virtual tick counter
    ├── transport.rs        # SimTransport: in-process channel transport
    ├── network.rs          # SimNetwork: topology model, per-link behavior
    ├── harness.rs          # ClusterHarness: multi-node orchestration
    ├── scenarios.rs        # Scenario definitions (Churn, Failover, etc.)
    ├── trace.rs            # JSONL trace output + fingerprint computation
    ├── lane.rs             # Lane model (CONTROL, METADATA, DATA, BULK)
    ├── error.rs            # SimnetError type
    └── tests/
        └── integration.rs  # Scenario integration tests
```

### 3.1 Dependencies

- `tidefs-local-filesystem` — LocalFileSystem per node
- `tidefs-local-object-store` — LocalObjectStore per node
- `tidefs-transport` — TransportBackend trait (SimTransport implements it)
- `tidefs-replication-model` — ReplicatedWritePlan, ReplicatedReadPlan, etc.
- `tidefs-membership-epoch` — EpochId, MemberId, MembershipConfigRecord
- `tidefs-flow-commit-coordinator` — FlowCommitCoordinator (opt-in per scenario)
- `tidefs-membership-live` — MembershipRuntime (opt-in per scenario)
- `rand_chacha` — Deterministic ChaCha20 RNG
- `blake3` — State fingerprinting
- `serde` / `serde_json` — JSONL trace serialization

---

## 4. SimClock: Virtual Tick Counter

```rust
/// A virtual clock that advances in discrete ticks.
/// No relationship to wall-clock time.
#[derive(Debug, Clone)]
pub struct SimClock {
    /// Current tick number, monotonically increasing.
    pub tick: u64,
    /// Per-tick event budget: maximum deliveries/actions per tick.
    pub max_deliveries_per_tick: u64,
}

impl SimClock {
    pub fn new() -> Self { Self { tick: 0, max_deliveries_per_tick: 256 } }

    /// Advance one tick. Returns Some(remaining_budget) or None if budget exhausted.
    pub fn advance(&mut self) { self.tick = self.tick.wrapping_add(1); }

    /// Whether the clock has reached a given tick threshold.
    pub fn after(&self, threshold: u64) -> bool { self.tick >= threshold }
}
```

### 4.1 Tick Semantics

A "tick" represents one synchronous round of the discrete-event simulation:

1. **Deliver pending messages**: each in-flight message whose target tick has
   arrived is delivered to its destination node.
2. **Run node step**: each node processes its inbound queue for one "step"
   (process at most `max_deliveries_per_tick` messages, then yield).
3. **Check quiescence**: if no node has pending messages, the simnet is
   quiescent and the scenario can advance to the next phase.

---

## 5. SimNetwork: Topology Model

```rust
/// Identifies a node in the simulated cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SimNodeId(pub u64);

/// Per-link configuration for SimNetwork.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimLinkConfig {
    /// Whether the link is currently paused (partitioned).
    pub paused: bool,
    /// Deterministic loss: message N is dropped when N % loss_period == 0.
    /// (0 means no loss.)
    pub loss_period: u64,
    /// Deterministic reorder: the delivery order is rotated by this offset.
    /// (0 means no reorder.)
    pub reorder_depth: usize,
    /// Tick delay added to every message on this link.
    pub latency_ticks: u64,
    /// Maximum inflight bytes on this link before backpressure.
    pub inflight_byte_cap: u64,
}

/// The full network topology: |N|×|N| matrix of link configurations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimNetwork {
    /// Nodes in the topology.
    pub nodes: BTreeSet<SimNodeId>,
    /// Per-direction link config: (src, dst) → SimLinkConfig.
    pub links: BTreeMap<(SimNodeId, SimNodeId), SimLinkConfig>,
    /// Messages currently in flight, keyed by delivery tick.
    pub inflight: BTreeMap<u64, Vec<SimMessage>>,
    /// Message counter for deterministic loss computation.
    msg_counters: BTreeMap<(SimNodeId, SimNodeId), u64>,
    /// RNG for deterministic behavior.
    pub rng: ChaCha20Rng,
}
```

### 5.1 Link Operations

```rust
impl SimNetwork {
    /// Pause/resume a unidirectional link.
    pub fn set_link_paused(&mut self, src: SimNodeId, dst: SimNodeId, paused: bool);

    /// Enqueue a message. Returns None if the link's inflight cap would be exceeded.
    pub fn try_enqueue(&mut self, msg: SimMessage) -> Option<SimMessage>;

    /// Deliver all messages scheduled for the current tick.
    pub fn deliver_tick(&mut self, tick: u64) -> Vec<(SimNodeId, SimMessage)>;

    /// Check whether any inflight messages remain.
    pub fn has_pending(&self) -> bool;
}
```

---

## 6. SimTransport: In-Process Channel Transport

SimTransport implements `tidefs_transport::backend::TransportBackend`. Every
node gets its own `SimTransport` instance wired to the shared `SimNetwork`.

```rust
/// A transport backend that routes messages through the deterministic SimNetwork.
pub struct SimTransport {
    /// This node's identity.
    pub node_id: SimNodeId,
    /// Shared reference to the simulation network.
    pub network: Arc<Mutex<SimNetwork>>,
    /// Inbound message queue for this node (delivered messages).
    pub inbox: VecDeque<SimMessage>,
    /// Outbound message queue (buffered before being injected into network).
    pub outbox: VecDeque<SimMessage>,
    /// Per-lane sequence counters.
    pub seq_counters: BTreeMap<LaneClass, u64>,
    /// Consensus round counter (drives leader election determinism).
    pub consensus_round: u64,
}
```

### 6.1 TransportBackend Implementation

`SimTransport` implements `TransportBackend` by:

- **connect(peer)**: registers the link in `SimNetwork.links` (no actual
  connection — just model setup).
- **send(session, lane, payload)**: builds a `SimMessage`, increments the
  per-lane sequence counter, and calls `SimNetwork.try_enqueue()`. If the
  lane has priority preemption (CONTROL), it always succeeds; other lanes
  respect inflight caps.
- **recv()**: pops from `self.inbox`; non-blocking (returns None when empty).
- **close(session)**: removes the session's links from the network.

### 6.2 Message Delivery Logic

```
┌──────────────┐   enqueue    ┌──────────────┐   deliver     ┌──────────────┐
│  SimTransport │────────────▶│  SimNetwork   │─────────────▶│  SimTransport │
│  (sender)     │             │  (inflight)   │              │  (receiver)   │
└──────────────┘              └──────────────┘              └──────────────┘
                                     │
                              ┌──────┴──────┐
                              │ Link config │
                              │ loss/reorder│
                              │ latency     │
                              └─────────────┘
```

When `SimTransport::send()` is called:
1. The per-link message counter increments.
2. If `counter % loss_period == 0`, the message is dropped (no delivery).
3. Otherwise, the message is assigned a delivery tick = `current_tick + latency_ticks`.
4. The message is inserted into `SimNetwork.inflight[delivery_tick]`.
5. If `reorder_depth > 0`, the inflight queue at that tick is shuffled
   deterministically using the PRNG seeded with tick + link counter.

When `SimNetwork::deliver_tick(tick)` is called:
1. All messages in `inflight[tick]` are dequeued into their destination
   nodes' `inbox` queues.
2. If a link's inflight byte cap is exceeded when enqueuing, the sender's
   `try_enqueue()` returns the message back (backpressure).

### 6.3 Lane Model

The lane model mirrors the old Python `simnet.py` design:

| Lane | Priority | Purpose | Budget (default) | Behavior |
|------|----------|---------|-------------------|----------|
| CONTROL | 0 (highest) | Leader election, votes, acks | Unlimited | Never backpressured; preempts all other lanes; always succeeds on send |
| METADATA | 1 | Log replication proposals, commit notifications, lease grants/recalls | Per-link inflight byte cap (default: 64 KiB) | Backpressured when inflight cap exceeded; sender retries next tick |
| DATA | 2 | Extent payload, chunk shipping, torrent rate-limited | Per-link inflight byte cap (default: 4 MiB), per-flow rate limit | Torrent-style rate limiter; sender throttles when cap or rate limit hit |
| BULK | 3 (lowest) | Background rebuild, relocation, rebalance, state-transfer snapshots | Per-link inflight byte cap (default: 16 MiB) | Processed only when no CONTROL/METADATA/DATA pending; lowest scheduling priority |

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SimLane {
    Control = 0,
    Metadata = 1,
    Data = 2,
    Bulk = 3,
}
```



### 6.4 Lane Scheduling and Preemption

The simnet lane scheduler processes lanes in strict priority order each tick:

1. **CONTROL messages**: delivered first, always. No cap. Preempts all other lanes.
   This ensures leader election messages, votes, and acks are never delayed
   by bulk traffic.
2. **METADATA messages**: delivered second, subject to per-link inflight byte
   cap. If a link's inflight matches the cap, the sender's `try_enqueue()`
   returns false (backpressure) and the message is retried next tick.
3. **DATA messages**: delivered third, subject to per-link inflight byte cap
   AND a per-flow rate limiter. The torrent-style rate limiter tracks bytes
   sent per flow per tick epoch and throttles when the rate budget is
   exhausted. This models real network bandwidth without nondeterministic
   socket scheduling.
4. **BULK messages**: delivered last, only when no CONTROL, METADATA, or DATA
   messages remain in the inflight queue for this tick. Background traffic
   never interferes with foreground operations.

### 6.5 Per-Link Configuration

Each directed link `(src, dst)` in `SimNetwork` carries its own lane budget
and fault model:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimLinkConfig {
    /// Loss: drop every Nth message (0 = no loss).
    pub loss_period: u64,
    /// Latency: deliver message after this many ticks.
    pub latency_ticks: u64,
    /// Reorder depth: shuffle the last N messages before delivery (0 = no reorder).
    pub reorder_depth: u64,
    /// Per-lane inflight byte caps.
    pub lane_budgets: BTreeMap<SimLane, u64>,
    /// Whether the link is currently partitioned (paused).
    pub paused: bool,
}

impl Default for SimLinkConfig {
    fn default() -> Self {
        let mut lane_budgets = BTreeMap::new();
        lane_budgets.insert(SimLane::Control, u64::MAX);       // unlimited
        lane_budgets.insert(SimLane::Metadata, 64 * 1024);      // 64 KiB
        lane_budgets.insert(SimLane::Data, 4 * 1024 * 1024);    // 4 MiB
        lane_budgets.insert(SimLane::Bulk, 16 * 1024 * 1024);   // 16 MiB
        Self {
            loss_period: 0,
            latency_ticks: 1,
            reorder_depth: 0,
            lane_budgets,
            paused: false,
        }
    }
}
```
The lane model maps to the existing production transport in
`tidefs_types_transport_session::LaneClass` (Control, Metadata, Demand,
Speculative, Background) with a simnet-specific grouping.

---


---

## 6a. Lease Semantics (Signal-Driven Recall + Epoch Fencing)

The simnet exercises the distributed lease protocol with deterministic
control of recall timing, epoch advancement, and fencing enforcement.
Leases in the cluster grant either shared (read) or exclusive (write)
access to datasets, with deterministic lease state transitions driven
by the simnet tick clock rather than wall-clock timeouts.

### 6a.1 Lease Lifecycle

```
  [No Lease]
      │
      │ request_shared_lease(node, dataset)
      ▼
  [Shared Hold] ◄────── others request shared ──────┐
      │                                               │
      │ request_exclusive_lease (via leader)          │
      ▼                                               │
  [Recall Pending] ──► recall all shared holders ──► [Exclusive Grant]
      │                                               │
      │ stale epoch write                             │
      ▼                                               │
  [Epoch Fenced: Write Rejected] ──► re-acquire ──► [Exclusive Grant]
```

### 6a.2 Signal-Driven Recall

When a node requests an exclusive lease, the lease service issues a
**recall signal** on the CONTROL lane to all current shared holders.
This is not a timeout — the simnet deterministically:

1. Injects the recall signal into the destination node's inbox at the
   next tick boundary.
2. The receiving node processes the recall: flushes any pending writes,
   releases the shared hold, and sends a **recall-complete** ack.
3. Only after all shared holders have acked does the exclusive grant
   proceed.
4. If a shared holder is crashed or partitioned, the recall times out
   after a configurable tick threshold (`recall_timeout_ticks`), and
   the grant proceeds with the crashed node's lease revoked.

### 6a.3 Epoch Fencing

Epoch fencing prevents split-brain writes after lease expiry or
leadership change:

- Each lease grant carries a monotonically increasing **lease epoch**
  (tracked in `SimNodeState.epoch`).
- Every write operation includes the lease epoch in its metadata.
- The replication layer checks: if the write's epoch is less than the
  current committed epoch, the write is **rejected** (fenced).
- Even the current exclusive holder can be fenced if its epoch is
  stale — e.g., after a leader change increments the epoch.
- After a fenced write rejection, the node must re-acquire a new lease
  (bumping its epoch) before proceeding.

### 6a.4 Simnet Lease Harness API

```rust
impl ClusterHarness {
    /// Request a shared (read) lease on a dataset for a node.
    pub fn request_shared_lease(
        &mut self,
        node: SimNodeId,
        dataset: DatasetId,
    ) -> Result<LeaseGrant, SimnetError>;

    /// Request an exclusive (write) lease. Triggers recall of all
    /// shared holders before granting.
    pub fn request_exclusive_lease(
        &mut self,
        node: SimNodeId,
        dataset: DatasetId,
    ) -> Result<LeaseGrant, SimnetError>;

    /// Release a lease held by a node.
    pub fn release_lease(&mut self, node: SimNodeId, dataset: DatasetId);

    /// Get the current lease epoch for a dataset.
    pub fn lease_epoch(&self, dataset: DatasetId) -> u64;
}
```

### 6a.5 Lease Scenario Example

The `leases` scenario exercises:

1. Node A acquires shared read lease on dataset D.
2. Node B acquires shared read lease on dataset D (compatible).
3. Node C requests exclusive write lease → recall signals sent to A and B.
4. A and B ack recall → exclusive lease granted to C.
5. C writes data with lease epoch E.
6. Leader crashes, new leader increments epoch to E+1.
7. C attempts another write with epoch E → **fenced**, write rejected.
8. C re-acquires exclusive lease with epoch E+1 → write succeeds.
9. Verify all nodes' state fingerprints match after lease resolution.

## 7. ClusterHarness: Multi-Node Orchestration

```rust
/// The top-level cluster simulation harness.
pub struct ClusterHarness {
    /// Simulation clock.
    pub clock: SimClock,
    /// Network topology + inflight messages.
    pub network: Arc<Mutex<SimNetwork>>,
    /// Per-node filesystem instances.
    pub nodes: BTreeMap<SimNodeId, SimNodeState>,
    /// Per-node transport instances.
    pub transports: BTreeMap<SimNodeId, Arc<Mutex<SimTransport>>>,
    /// Current leader node (None if no election yet).
    pub leader: Option<SimNodeId>,
    /// RNG for scenario randomization.
    pub rng: ChaCha20Rng,
    /// Scenario configuration.
    pub config: SimClusterConfig,
    /// Trace recorder.
    pub tracer: SimTracer,
}

pub struct SimNodeState {
    pub fs: LocalFileSystem,
    pub object_store: LocalObjectStore,
    pub epoch: EpochId,
    pub member_id: MemberId,
    pub crashed: bool,
    pub state_fingerprint: Option<[u8; 32]>,
}
```

### 7.1 Harness Lifecycle

```rust
impl ClusterHarness {
    /// Create a cluster of `node_count` nodes, each with its own
    /// LocalFileSystem in a temp directory. All nodes share the same
    /// SimNetwork and SimClock.
    pub fn create(config: SimClusterConfig) -> Result<Self, SimnetError>;

    /// Advance one tick: deliver messages, step each node, record trace.
    pub fn run_tick(&mut self, max_deliveries: u64) -> Result<TickReport, SimnetError>;

    /// Run until quiescence or timeout.
    pub fn run_until_quiescent(&mut self, timeout_ticks: u64) -> Result<Vec<TickReport>, SimnetError>;

    /// Submit an operation through the leader.
    pub fn submit(&mut self, op: SimOperation, timeout_ticks: u64) -> Result<SimOpResult, SimnetError>;

    /// Submit from a specific node.
    pub fn submit_from(&mut self, node_id: SimNodeId, op: SimOperation) -> Result<SimOpResult, SimnetError>;

    // --- Node lifecycle ---
    pub fn crash_node(&mut self, id: SimNodeId);
    pub fn restart_node(&mut self, id: SimNodeId) -> Result<(), SimnetError>;
    pub fn add_node(&mut self, id: SimNodeId) -> Result<(), SimnetError>;
    pub fn remove_node(&mut self, id: SimNodeId);

    // --- Network manipulation ---
    pub fn pause_link(&mut self, a: SimNodeId, b: SimNodeId, paused: bool);

    // --- Membership ---
    pub fn elect_leader(&mut self, node_id: SimNodeId);
    pub fn add_learner(&mut self, id: SimNodeId) -> Result<(), SimnetError>;
    pub fn promote_learner_to_voter(&mut self, id: SimNodeId) -> Result<(), SimnetError>;
    pub fn remove_voter(&mut self, id: SimNodeId);
    pub fn remove_learner(&mut self, id: SimNodeId);

    // --- Verification ---
    pub fn fingerprints(&self) -> BTreeMap<SimNodeId, [u8; 32]>;
    pub fn assert_all_equal_fingerprints(&self) -> Result<(), SimnetError>;
    pub fn assert_all_equal_fingerprints_r(&self) -> Result<(), SimnetError>;

    // --- Trace ---
    pub fn trace_path(&self) -> &Path;
    pub fn flush_trace(&mut self) -> Result<(), SimnetError>;
}
```

### 7.2 Tick Execution

Each `run_tick()` executes:

```
1. SimNetwork::deliver_tick(clock.tick)
2. For each non-crashed node:
   a. Process inbound messages up to max_deliveries
   b. Advance membership state machine (if enabled)
   c. Run pending replication operations (if any)
   d. Compute new state fingerprint (BLAKE3 over all committed state)
   e. Record trace event: {tick, node_id, events: [...], fingerprint}
3. SimClock::advance()
4. Return TickReport
```

---



### 7.3 Membership Change Protocols

The simnet exercises the full membership lifecycle with deterministic
control of configuration transitions. These protocols port the v0.262
L1 cluster test suite behaviors (`test_l1_cluster_membership.py`).

#### Add Learner

A new node joins the cluster as a non-voting **learner**:

1. `add_learner(new_node_id)` registers the node in the membership
   config with `voter=false`.
2. The new node catches up via log replication and/or state transfer
   (snapshot install) from the leader.
3. During catchup, the learner:
   - Receives log entries but does NOT vote in elections.
   - Applies committed log entries to its local state.
   - Emits progress acks so the leader tracks catchup state.
4. The simnet advances ticks until the learner's match index equals
   the leader's commit index.

#### Promote Learner to Voter

Once a learner is caught up, it is promoted to full voting member:

1. `promote_learner_to_voter(node_id)` initiates a joint-consensus
   transition (old config + new config both active during transition).
2. The new config (with the learner now `voter=true`) is replicated
   as a committed log entry.
3. Once the joint-consensus entry commits, the transition completes
   and the node becomes a full voter.
4. **Quorum recalculation**: the quorum size increases. For example,
   a 3-node cluster (quorum=2) adding a voter becomes 4-node (quorum=3).

#### Remove Voter

A voting node is removed from the cluster:

1. `remove_voter(node_id)` initiates a joint-consensus transition
   to a config without the node.
2. The removed node stops receiving log entries and stops voting.
3. **Quorum recalculation**: quorum size decreases. A 4-node cluster
   (quorum=3) removing 1 voter becomes 3-node (quorum=2) — can now
   survive 2 crashes instead of 1.
4. Removed nodes cannot become leader.

#### Remove Learner

A non-voting learner is removed:

1. `remove_learner(node_id)` removes the learner from the membership
   config without a joint-consensus transition (learners don't vote).
2. Replication to the learner stops immediately.
3. The learner stops applying log operations.
4. Voting members are unaffected.

#### Membership Scenario Example

The `membership` scenario exercises:

1. Bootstrap: 3 nodes, all voters, quorum=2.
2. Add learner (node 4) → catchup via log replication.
3. Promote learner 4 to voter → quorum becomes 3.
4. Submit 10 writes through leader → all 4 nodes commit.
5. Remove voter (node 3) → quorum becomes 2.
6. Crash node 2 (voter) → quorum still satisfied (node 1 + node 4).
7. Submit 10 more writes → committed with 2 surviving voters.
8. Remove learner (node 5, previously added but not promoted).
9. Verify fingerprints match across all surviving nodes.

## 8. Scenario Definitions

Each scenario is a function that takes a `ClusterHarness` reference and a
scenario seed, drives a deterministic sequence of operations, and returns a
`ScenarioResult` with per-node fingerprints and trace.

```rust
pub trait Scenario: Send + Sync {
    fn name(&self) -> &'static str;
    fn run(&self, harness: &mut ClusterHarness) -> Result<ScenarioResult, SimnetError>;
    fn seed(&self) -> u64;
}

pub struct ScenarioResult {
    pub scenario_name: String,
    pub seed: u64,
    pub total_ticks: u64,
    pub fingerprints: BTreeMap<SimNodeId, [u8; 32]>,
    pub trace_path: PathBuf,
    pub passed: bool,
    pub error: Option<String>,
}
```

### 8.1 Scenario Coverage Matrix (from v0.262 L1 Cluster Test Suite)

| Scenario | Test file (Python) | Node count | Ticks | Key protocol behavior |
|----------|---------------------|------------|-------|----------------------|
| `churn` | `test_l1_cluster_churn.py` | 5 | 500 | Continuous join/leave with concurrent writes; verifies no data loss during membership flux |
| `failover` | `test_l1_cluster_failover.py` | 3 | 300 | Leader crash → auto-election → catchup → verify; tests log continuity across leadership change |
| `election` | `test_l1_cluster_election.py` | 5 | 400 | Minority partition + tail truncation; tests that truncated entries are not recommitted |
| `loss_sync` | `test_l1_cluster_loss_sync.py` | 3 | 500 | Message loss (every Nth message dropped) + eventual consistency; verifies all nodes converge |
| `reorder` | `test_l1_cluster_reorder.py` | 3 | 400 | Message reorder + commit ordering invariance; verifies total order despite network reordering |
| `leases` | `test_l1_cluster_leases.py` | 3 | 350 | Shared→exclusive lease recall, epoch fencing, stale write rejection |
| `membership` | `test_l1_cluster_membership.py` | 3→5 | 450 | Learner add/promote, voter remove, quorum recalculation, learner remove |
| `restart` | `test_l1_cluster_restart.py` | 3 | 300 | Follower restart while behind leader; catchup via log replay |
| `state_transfer` | `test_l1_cluster_state_transfer.py` | 3 | 500 | Snapshot install when log too far behind for incremental catchup |
| `commit_group` | `test_l1_cluster_commit_group.py` | 3 | 200 | Transaction group batching: multiple writes batched into a single commit across cluster |
| `auto_election` | `test_l1_cluster_auto_election.py` | 5 | 400 | Automatic leader election with pre-vote phase; tests split-vote prevention |
| `catchup` | `test_l1_cluster_catchup.py` | 3 | 300 | Log catchup after varying gap sizes (1, 10, 100 entries behind) |

### 8.2 Scenario: Churn (example specification)

```
seed: fixed u64
node_count: 5
duration_ticks: 500
operations_per_tick: 2

Phase 1 (ticks 0-100): bootstrap — elect leader, establish quorum
Phase 2 (ticks 101-300): churn — every 20 ticks, randomly (from seed) add or
                         remove a node; concurrently submit writes through leader
Phase 3 (ticks 301-400): stabilize — stop churn, let cluster converge
Phase 4 (ticks 401-500): verify — assert all nodes have identical fingerprints;
                         replay log and verify commit ordering is total
```

### 8.3 Scenario: Failover (example specification)

```
seed: fixed u64
node_count: 3
duration_ticks: 300

Phase 1 (ticks 0-50): bootstrap
Phase 2 (ticks 51-100): write — submit 20 writes through leader
Phase 3 (tick 101): crash leader
Phase 4 (ticks 102-200): election — remaining nodes elect new leader
Phase 5 (ticks 201-250): catchup — new leader replicates missing entries
Phase 6 (ticks 251-300): verify — fingerprints match, no data loss
```

---

## 9. Trace Output and Fingerprinting

### 9.1 JSONL Trace Format

Every tick event is a single JSON line:

```json
{"tick":42,"node_id":0,"events":[{"kind":"deliver","lane":"CONTROL","from":2,"bytes":72},{"kind":"commit","commit_group_id":3}],"fingerprint":"a1b2c3d4e5f6..."}
```

Trace events include:

| Event kind | Fields |
|------------|--------|
| `deliver` | `lane`, `from`, `bytes`, `seq` |
| `drop` | `lane`, `from`, `reason` (loss/reorder/cap) |
| `commit` | `commit_group_id`, `subject_count` |
| `elect` | `new_leader`, `term` |
| `membership_change` | `delta`, `epoch` |
| `lease_grant` | `dataset`, `mode` (shared/exclusive), `epoch` |
| `lease_recall` | `dataset`, `reason` |
| `write` | `path`, `bytes`, `offset` |
| `fingerprint_mismatch` | `node_a`, `node_b`, `fp_a`, `fp_b` |

### 9.2 State Fingerprint

The per-node BLAKE3-256 fingerprint is computed from a canonical traversal of
committed state:

1. All inodes sorted by `InodeId`, with `st_size`, `st_nlink`, `st_mode`, and
   data tree root hashes.
2. All directory entries sorted by `(parent, name)`, with `(name, inode_id)`
   pairs.
3. All snapshots sorted by snapshot id, with catalog entries.
4. CommitGroup counter and epoch.

The fingerprint is computed in a streaming fashion and compared across nodes.

### 9.3 Trace Replay and Minimization

The trace output integrates with the trace oracle (#1174):

- Traces emitted by simnet scenarios use the same JSONL protocol format as
  `tidefs-trace-oracle`.
- A failing scenario trace can be replayed through the trace oracle's
  `replay_trace()` to isolate the minimal failing sequence.
- The `tidefs-trace-oracle::minimize` module can reduce a multi-hundred-tick
  trace to the few key operations that cause divergence.

---

## 10. xtask Integration

A new xtask subcommand drives simnet scenarios:

```
cargo xtask run-scenarios --scenario churn,failover,election --seed 42
```

```rust
// xtask/src/simnet.rs (new module)
pub fn run_scenarios(
    scenarios: Vec<String>,
    seed: u64,
    output_dir: Option<PathBuf>,
) -> Result<(), anyhow::Error> {
    let harness_config = SimClusterConfig {
        seed,
        node_count: 5,
        device_count: 1,
        device_size_bytes: 64 * 1024 * 1024, // 64 MiB per node
    };

    for name in &scenarios {
        let scenario = load_scenario(name)?;
        let mut harness = ClusterHarness::create(harness_config.clone())?;
        let result = scenario.run(&mut harness)?;
        println!("{}: {}", name, if result.passed { "PASS" } else { "FAIL" });
        if !result.passed {
            eprintln!("  trace: {}", result.trace_path.display());
            anyhow::bail!("scenario {} failed", name);
        }
    }
    Ok(())
}
```

---

## 11. Implementation Plan

Phase-gated implementation matching the old Python → Rust port order:

### Phase 1: Core infrastructure
1. Create `crates/tidefs-simnet` with `Cargo.toml`.
2. Implement `SimClock` (virtual tick counter).
3. Implement `SimNetwork` (topology, link config, inflight queue, loss/reorder).
4. Implement `SimTransport` implementing `TransportBackend`.

### Phase 2: Cluster harness
5. Implement `ClusterHarness` creating `LocalFileSystem` per node.
6. Wire `SimTransport` into the harness.
7. Implement `run_tick()`, `run_until_quiescent()`.
8. Implement `submit()`, `submit_from()`.
9. Implement node lifecycle: `crash_node()`, `restart_node()`, `add/remove`.

### Phase 3: Scenarios
10. Port the 12 scenarios from old Python test suite.
11. Implement `SimTracer` + JSONL output.
12. Implement state fingerprinting with BLAKE3.
13. Add `assert_all_equal_fingerprints_r()`.

### Phase 4: xtask integration
14. Add `xtask/src/simnet.rs` with `run-scenarios` subcommand.
15. Wire into `xtask/src/main.rs`.

17. Run all scenarios with fixed seeds; capture golden fingerprints.
18. Add golden-file regression tests (compare fingerprint against committed
    golden values).
19. Document scenario coverage matrix in `docs/FEATURE_MATRIX.md`.

---

## 12. Key Data Structures

### 12.1 SimMessage

```rust
/// A simulated network message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimMessage {
    pub src: SimNodeId,
    pub dst: SimNodeId,
    pub lane: SimLane,
    pub session_id: u64,
    pub seq: u64,
    pub payload: Vec<u8>,
    pub enqueued_at_tick: u64,
    pub deliver_at_tick: u64,
}
```

### 12.2 SimClusterConfig

```rust
/// Configuration for setting up a cluster harness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimClusterConfig {
    pub seed: u64,
    pub node_count: usize,
    pub device_count: usize,
    pub device_size_bytes: u64,
    pub default_link_config: SimLinkConfig,
    pub max_ticks: u64,
    pub trace_dir: PathBuf,
    pub enable_membership: bool,      // wire MembershipRuntime?
    pub enable_flow_coordinator: bool, // wire FlowCommitCoordinator?
}
```

### 12.3 SimOperation

```rust
/// A simulated filesystem operation submitted to the cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SimOperation {
    CreateFile { path: String, mode: u32 },
    WriteFile { path: String, offset: u64, data: Vec<u8> },
    ReadFile { path: String, offset: u64, len: u64 },
    Unlink { path: String },
    Rename { from: String, to: String, replace: bool },
    Mkdir { path: String, mode: u32 },
    Rmdir { path: String },
    CreateSnapshot { name: String },
    DestroySnapshot { name: String },
    Truncate { path: String, len: u64 },
    Link { src: String, dst: String },
    Fsync { path: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimOpResult {
    pub ok: bool,
    pub error: Option<String>,
    pub bytes_written: Option<u64>,
    pub bytes_read: Option<Vec<u8>>,
    pub commit_tick: u64,
}
```

### 12.4 TickReport

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TickReport {
    pub tick: u64,
    pub messages_delivered: u64,
    pub messages_dropped: u64,
    pub ops_committed: u64,
    pub nodes_idle: bool,
    pub per_node: BTreeMap<SimNodeId, NodeTickReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeTickReport {
    pub events: Vec<SimEvent>,
    pub fingerprint: Option<[u8; 32]>,
    pub fingerprint_changed: bool,
    pub crashed: bool,
}
```

---

## 13. Determinism Contract

### 13.1 Sources of Determinism

| Source | Guarantee |
|--------|-----------|
| ChaCha20 PRNG with fixed seed | Same PRNG call sequence → same bytes. No system entropy. |
| SimClock tick counter | No wall-clock sources. No `Instant::now()`. |
| SimNetwork inflight queues | Strict BTreeMap ordering by (tick, seq). No scheduler nondeterminism. |
| In-process channels | No OS scheduler. Messages delivered in deterministic order. |
| BLAKE3 state hashing | Deterministic hash of canonical state traversal. |
| Memfd / tmpfs for node storage | No disk I/O nondeterminism. Node filesystems live in `/tmp`. |

### 13.2 Nondeterminism Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| HashMap iteration order | Use `BTreeMap` for all collections that affect message ordering. |
| Thread scheduling | Single-threaded simulation; no `tokio` or async. |
| Filesystem timestamps | All `st_mtime`/`st_ctime` set from `SimClock.tick`, not real time. |
| `Instant::now()` in dependencies | Audit `LocalFileSystem` for wall-clock calls; simulate or stub them. |

---

## 14. Relationship to Existing Infrastructure

| Component | Relationship |
|-----------|-------------|
| `tidefs-transport` | SimTransport implements `TransportBackend` trait; production send/recv path is reused. |
| `tidefs-replication-model` | ReplicatedWritePlan / ReplicatedReadPlan used directly; simnet exercises the model. |
| `tidefs-membership-epoch` | Epoch model used directly; membership transitions driven by simnet. |
| `tidefs-flow-commit-coordinator` | Optional integration; scenarios can wire it to test commit flow under loss/reorder. |
| `tidefs-local-filesystem` | One instance per node; state fingerprint covers all committed state. |
| Real-transport tests (#1060, #1143) | NOT replaced — complemented. Simnet for fast deterministic regression; real transport for network-level integration. |

---

## 15. Tradeoffs and Alternatives Considered

| Decision | Rationale |
|----------|-----------|
| In-process vs. process-per-node | In-process avoids serialization overhead and process management. BTreeMap ordering gives deterministic scheduling. Process-per-node would require deterministic OS scheduling — impractical. |
| SimClock ticks vs. event-driven simulation | Ticks are simpler to reason about and make quiescence detection trivial. Event-driven (DES) is more efficient but harder to integrate with the existing trait-based architecture. The tick cost is negligible for the target cluster sizes (3–7 nodes). |
| Trait-based transport vs. new sim-specific API | Trait-based (implementing `TransportBackend`) means simnet exercises the same code paths as production. If the trait surface changes, simnet breaks at compile time. A sim-specific API would drift. |
| ChaCha20 vs. `StdRng` | ChaCha20 is deterministic and seedable without any OS entropy. `StdRng` (HC-128) is also deterministic but ChaCha20 has better understood determinism guarantees and a simpler API. |
| BLAKE3 vs. SHA-256 for fingerprints | BLAKE3 is faster in software and produces equivalent security. No need for cryptographic security in simnet hashes — the hash is for regression comparison only. |
| Temp directories vs. in-memory storage | Temp directories (`/tmp`) backed by tmpfs give realistic filesystem behavior (real kernel VFS, real page cache) while being fast and clean per-test. In-memory storage would require mocking the kernel filesystem layer. |

---

## 16. Open Questions

1. **MembershipRuntime integration**: Should `ClusterHarness` wire
   `tidefs_membership_live::MembershipRuntime` by default, or should it use a
   simpler deterministic membership mock? The runtime has real timers and
   async — using it would break determinism. Likely resolution: a
   `SimMembership` adapter that wraps the same epoch-transition logic without
   real timers or I/O.

2. **QuorumObjectStore integration**: Should the simnet use
   `QuorumObjectStore` (distributed write path) or just `LocalObjectStore`
   per node? If each node has its own `QuorumObjectStore`, the actual quorum
   logic is exercised. Likely resolution: yes, use QuorumObjectStore per node
   wired to the SimTransport to exercise the full distributed path.

3. **FUSE daemon integration**: Can we mount a simulated node via FUSE for
   interactive debugging? Likely resolution: out of scope for v1; traces and
   fingerprints are the debugging surface.

4. **Golden file strategy**: Should golden fingerprints be committed to the
   one file per scenario+seed combination.

---

## 17. Success Criteria

- [ ] `cargo xtask run-scenarios --scenario all` completes deterministically.
- [ ] Same seed → same fingerprints across any two CI runs.
- [ ] At least one scenario per protocol behavior category (churn, failover,
  election, loss, reorder, leases, membership, restart, state_transfer, commit_group,
  auto_election, catchup).
- [ ] A failure in any scenario produces a trace that can be replayed through
  `tidefs-trace-oracle`.
- [ ] Regression test: changing a protocol implementation (e.g., commit order)
  changes at least one scenario fingerprint and is caught at CI time.
