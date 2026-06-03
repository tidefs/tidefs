# tidefs-node-drain

Staged node drain with resource migration, forced fencing, and decommission
for TideFS distributed clusters.

## Architecture

The node drain protocol safely removes a storage node from the cluster in
five ordered stages:

```
DrainRequested -> DrainingLeases -> DrainingData -> DrainingCache -> DrainingAdmin -> Drained
```

Each stage must complete before the next begins. Progress is tracked per-stage
through `DrainProgress`, and the entire drain is bounded by a configurable
timeout.

### Modules

- **`drain`** — Core types: `NodeState`, `DrainStage`, `DrainProgress`,
  `NodeDrain` (state machine), `DrainHandle` (read-only observer), and
  `DrainError`.

- **`executor`** — `DrainExecutor` drives the drain through each stage by
  calling `DrainOps` trait methods. `LockTableDrainOps` is a production
  implementation backed by the lease lock table.

- **`forced_fencing`** — `ForcedFencing` handles unresponsive nodes: monotonic
  `FenceToken` per node, `FencingStats` tracking, and `FenceExclusionProposal`
  metadata for membership epoch transitions. Configurable max consecutive
  fences before operator intervention.

- **`epoch_gate`** — `EpochGate` coordinates the membership epoch transition
  that excludes a draining node. Uses a 3-phase protocol (propose,
  accept-collect, commit) via the `EpochGateOps` trait.

- **`migration`** — `MigrationDriver` orchestrates object-store enumeration,
  placement-target assignment, send-stream transfers, and BLAKE3 checksum
  verification via the `MigrationOps` trait.

- **`health_verify`** — `DrainHealthVerifier` validates that zero replicas
  remain on the draining node after evacuation and that every object meets
  its durability requirements. Uses the `HealthVerifyOps` trait.

- **`pool_label`** — `DrainPoolLabelUpdater` removes the drained node's
  devices from pool labels via the `PoolLabelOps` trait, ensuring subsequent
  pool imports do not rediscover evacuated devices.

- **`orchestrator`** — Top-level `drain_node()` entry point composing all
  phases: drain executor, data migration, replication health verification,
  epoch gate transition, and drain completion. Configured via
  `NodeDrainConfig` with result in `DrainNodeOutcome`.

## Public API

```rust
// Top-level entry point
let outcome = tidefs_node_drain::drain_node(
    &config,
    &mut drain_ops,
    &mut migration_ops,
    &health_verify_ops,
    &mut gate_ops,
)?;

// Individual components
let (mut drain, handle) = NodeDrain::drain(node_id);
let (mut executor, handle) = DrainExecutor::start(node_id);
let mut migration = MigrationDriver::new(node_id);
let mut gate = EpochGate::new(node_id, EpochGateConfig::default());
let mut verifier = DrainHealthVerifier::new(node_id);
let mut updater = DrainPoolLabelUpdater::new(node_id);
```

## Protocol-level state machine

The `DrainProtocolMachine` tracks the cluster-coordination drain lifecycle
in five phases, each producing a BLAKE3-256 domain-separated state digest
(domain: `tidefs-membership-drain-state-v1`):

```
Idle → DrainAnnounced → Draining → DrainComplete → Drained
```

- **Idle**: No drain in progress.
- **DrainAnnounced**: Drain intent broadcast to peers; awaiting acks.
- **Draining**: State transfer underway (leases, data, cache offloaded).
- **DrainComplete**: Transfer finished; epoch gate pending.
- **Drained**: Terminal — node excluded from roster.

Cancellation is supported from any non-terminal state back to Idle.
`Drained → Drained` is idempotent for retry safety.

```rust
use tidefs_node_drain::state_machine::{DrainProtocolMachine, DrainProtocolState};

let mut machine = DrainProtocolMachine::new();
let snap = machine.announce_drain(node_id, epoch_id, 5)?;
// Collect acks from peers...
while !snap.all_acks_received() {
    machine.record_ack()?;
}
machine.start_draining()?;
// Execute state transfers...
machine.complete_draining()?;
machine.finalize_drain()?;
assert_eq!(machine.state(), DrainProtocolState::Drained);
```

## Wire protocol messages

Five BLAKE3-verified message types (domain: `tidefs-membership-drain-v1`):

| Message | Direction | Purpose |
|---|---|---|
| `DrainAnnounce` | Initiator → peers | Broadcast drain intent |
| `DrainAck` | Peer → initiator | Accept or reject the drain |
| `StateTransferRequest` | Peer → initiator | Request state handoff |
| `StateTransferChunk` | Initiator → peer | Transfer a chunk of state |
| `DrainComplete` | Initiator → peers | Confirm drain finalization |

All messages implement `DrainWireMessage` with `verify_full()` for
cryptographic integrity verification.

## Runtime integration

`DrainRuntime<O: DrainRuntimeOps>` orchestrates the full protocol:

1. Broadcast `DrainAnnounce` to all peers.
2. Collect `DrainAck` responses (with configurable timeout).
3. Execute state transfer chunks via `StateTransferChunk`.
4. Remove the drained node from the membership roster.
5. Signal transport peer manager drain → teardown.
6. Broadcast `DrainComplete`.

The `DrainRuntimeOps` trait abstracts external services (messaging,
roster, transport, event bridge). The membership-live runtime bridges
`DrainRuntimeEvent` variants into `MembershipEvent::{Draining, Drained}`
so that subscribers (transport peer manager, epoch transition engine)
react to drain lifecycle progress.

```rust
use tidefs_node_drain::config::DrainConfig;
use tidefs_node_drain::runtime::{DrainRuntime, DrainRuntimeOps};

let config = DrainConfig::default(); // 30s timeout, batch=64, concurrent=4
let mut runtime = DrainRuntime::new(config, my_ops);
runtime.start_drain(node_id, "maintenance window".into())?;
// ... collect acks, transfer state ...
runtime.begin_state_transfer()?;
runtime.transfer_chunk(target, 0, 0, payload)?;
runtime.complete_state_transfer()?;
runtime.finalize_drain()?;
```

## Testing

```bash
cargo test -p tidefs-node-drain
```

251 unit tests covering the full drain protocol: state machine transitions,
BLAKE3 wire-message integrity, config validation, runtime orchestration,
multi-peer ack collection, state transfer, timeout enforcement, roster
integration, transport signaling, and concurrent drain serialization.
