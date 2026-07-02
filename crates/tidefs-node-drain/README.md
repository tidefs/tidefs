# tidefs-node-drain

Crate-local staged node-drain state machines, message types, and trait-driven
orchestration helpers.

This crate models drain progress for a node that is leaving membership duties.
It does not by itself prove live multi-node behavior, roster updates, transport
teardown, pool-wide data movement, or release-facing operator behavior. Those
claims require the membership authority, claim registry, issue-owned source
follow-ups, and current CI/runtime artifacts named below.

## Current Boundary

The crate contains source-level building blocks:

- drain stages and progress counters;
- BLAKE3-verified protocol snapshots and drain message structs;
- forced-fence tokens and epoch-gate helpers;
- migration, health verification, pool-label, and runtime drivers behind
  caller-supplied traits;
- unit tests and mock-driven runtime/orchestrator paths.

The crate does not currently supply end-to-end evidence for:

- a live membership roster transition across running nodes;
- transport session admission or teardown in a deployed topology;
- real object rebuild/relocation over an operator pool;
- a final public operator command surface for node removal;
- release-readiness, successor/comparator, or product-safety wording.

Membership truth is owned by `docs/MEMBERSHIP_AUTHORITY.md`. That document
classifies `tidefs-node-drain` as a consumer of membership epoch identity and
records the remaining source work for epoch-transition-barrier fencing. It also
states that cluster drain claims require the follow-up issues and runtime
validation evidence.

Publishing-facing capability wording is governed by
`docs/CLAIMS_GATE_POLICY.md`, `validation/claims.toml`, and generated
`docs/CLAIM_REGISTRY.md`. Validation artifacts, not this README, decide whether
any future distributed-storage or operator-facing claim is admissible.

## Modules

- `drain` - Core types: `NodeState`, `DrainStage`, `DrainProgress`,
  `NodeDrain`, `DrainHandle`, and `DrainError`.

- `executor` - `DrainExecutor` advances the local drain stages by calling
  `DrainOps` trait methods. The current lease-lock-table adapter can enumerate
  and release leases; data, cache, and admin-role hooks remain service
  integration points until their runtime owners are wired.

- `forced_fencing` - `ForcedFencing`, monotonic `FenceToken` values per node,
  `FencingStats`, and fence-exclusion proposal metadata for membership epoch
  transitions.

- `epoch_gate` - `EpochGate` models the membership epoch transition that
  excludes a draining node through `EpochGateOps`. Its state machine covers
  proposal, accept collection, commit, timeout, failure, and cancellation.

- `drain_state` - `DrainStateMachine` validates `DrainRequest` values against
  `MembershipVerificationOps` and placement evidence before admitting a local
  drain transition.

- `state_machine` - `DrainProtocolMachine` tracks the protocol-level states
  `Idle -> DrainAnnounced -> Draining -> DrainComplete -> Drained`, producing
  BLAKE3-256 domain-separated state digests.

- `protocol` - BLAKE3-verified drain messages: `DrainAnnounce`, `DrainAck`,
  `StateTransferRequest`, `StateTransferChunk`, and `DrainComplete`. Each
  message implements `DrainWireMessage::verify_full()`.

- `config` - `DrainConfig` validates drain timeouts, transfer batch size, and
  concurrency limits.

- `runtime` - `DrainRuntime<O: DrainRuntimeOps>` drives announce, ack
  collection, state-transfer messages, roster-removal callbacks,
  transport-drain callbacks, and completion broadcasts through caller-provided
  operations.

- `migration` - `MigrationDriver` builds and executes object-transfer plans
  through `MigrationOps`, including placement targets and checksum fields.

- `health_verify` - `DrainHealthVerifier` asks `HealthVerifyOps` for remaining
  replicas and durability status before a drain can be treated as complete.

- `pool_label` - `DrainPoolLabelUpdater` calls `PoolLabelOps` to update the
  drained node's device entries in pool-label metadata.

- `orchestrator` - `drain_node()` composes request validation, lease-stage
  execution, migration, health verification, epoch-gate commit, pool-label
  update, and final state completion using caller-supplied implementations.

## Public API Shape

The top-level entry point is trait-backed. The caller supplies the live or test
operations; the crate supplies the ordering and state checks.

```rust
let outcome = tidefs_node_drain::drain_node(
    &config,
    &mut drain_ops,
    &mut migration_ops,
    &health_verify_ops,
    &mut gate_ops,
    &verify_ops,
    &placement_verifier,
)?;
```

Individual state-machine components can be exercised separately:

```rust
let (mut drain, _drain_handle) = NodeDrain::drain(node_id);
let (mut executor, _executor_handle) = DrainExecutor::start(node_id);
let mut migration = MigrationDriver::new(node_id);
let mut gate = EpochGate::new(node_id, EpochGateConfig::default());
let mut verifier = DrainHealthVerifier::new(node_id);
let mut updater = DrainPoolLabelUpdater::new(node_id);
```

Protocol-level state can also be advanced directly in tests or model-style
source checks:

```rust
use tidefs_node_drain::state_machine::{DrainProtocolMachine, DrainProtocolState};

let mut machine = DrainProtocolMachine::new();
machine.announce_drain(node_id, epoch_id, 5)?;
while machine.acks_received() < machine.acks_expected() {
    machine.record_ack()?;
}
machine.start_draining()?;
machine.complete_draining()?;
machine.finalize_drain()?;
assert_eq!(machine.state(), DrainProtocolState::Drained);
```

## Testing

```bash
cargo test -p tidefs-node-drain
```

The crate tests cover module-local state transitions, BLAKE3 message integrity,
configuration validation, mock runtime/orchestrator paths, state-transfer
messages, timeout handling, roster-callback hooks, transport-callback hooks,
and concurrent-drain serialization. They are source and unit-test evidence, not
live multi-node validation.
