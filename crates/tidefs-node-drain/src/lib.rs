#![forbid(unsafe_code)]

//! Staged node drain with resource migration, forced fencing, and decommission.
//!
//! Implements the node lifecycle management design for TideFS distributed
//! clusters: graceful staged drain (leases -> data -> cache -> admin -> done),
//! forced fencing for unresponsive nodes, and fence tokens for safe rejoin.
//!
//! ## Architecture
//!
//! - [`drain`]: Types for the drain state machine -- [`NodeState`], [`DrainStage`],
//!   [`DrainProgress`], [`NodeDrain`], and [`DrainHandle`].
//! - [`executor`]: The [`DrainExecutor`] orchestration loop wiring the drain
//!   state machine to live cluster services via the [`DrainOps`] trait.
//! - [`forced_fencing`]: [`ForcedFencing`] for fencing unresponsive nodes,
//!   [`FenceToken`] monotonically increasing per-node counter, and
//!   [`FencingStats`] tracking nodes_fenced, fence_triggers, rebuilds_triggered.
//! - [`epoch_gate`]: [`EpochGate`] coordinates the membership epoch transition
//!   that excludes a draining node via the [`EpochGateOps`] trait, gating drain
//!   completion on a committed epoch boundary.
//! - [`drain_state`]: [`DrainStateMachine`] processes BLAKE3-verified
//!   [`DrainRequest`]s validated against the live membership view via
//!   [`MembershipVerificationOps`], with idempotent retry and epoch coordination.
//! - [`state_machine`]: [`DrainProtocolMachine`] is a BLAKE3-verified
//!   protocol-level state machine with five states (Idle, DrainAnnounced,
//!   Draining, DrainComplete, Drained) tracking the drain lifecycle at the
//!   cluster-coordination layer, with [`DrainProtocolSnapshot`] providing
//!   attested state snapshots.
//! - [`protocol`]: BLAKE3-verified drain wire messages — [`DrainAnnounce`],
//!   [`DrainAck`], [`StateTransferRequest`], [`StateTransferChunk`], and
//!   [`DrainComplete`] — each with [`DrainWireMessage::verify_full`].
//! - [`config`]: [`DrainConfig`] bundles drain protocol tunables with
//!   validated bounds checking (drain timeout, batch size, concurrency).
//! - [`runtime`]: [`DrainRuntime`] orchestrates the full drain protocol —
//!   announce, collect acks, state transfer, roster removal, transport
//!   teardown, and DrainComplete broadcast — via [`DrainRuntimeOps`].
//! - [`migration`]: [`MigrationDriver`] orchestrates object-store enumeration,
//!   placement-target assignment, send-stream transfers, and BLAKE3 checksum
//!   verification via the [`MigrationOps`] trait.
//! - [`health_verify`]: [`DrainHealthVerifier`] validates zero replicas remain
//!   on the draining node after evacuation and every object meets durability
//!   requirements via the [`HealthVerifyOps`] trait.
//! - [`pool_label`]: [`DrainPoolLabelUpdater`] removes the drained node's
//!   devices from pool labels via the [`PoolLabelOps`] trait.
//! - [`orchestrator`]: [`drain_node()`] is the top-level public entry point
//!   that composes the drain executor, migration driver, and epoch gate into
//!   a single deterministic node drain pipeline. Use [`NodeDrainConfig`] to
//!   configure the drain and inspect [`DrainNodeOutcome`] for the result.

pub mod config;
pub mod drain;
pub mod drain_state;
pub mod epoch_gate;
pub mod executor;
pub mod forced_fencing;
pub mod health_verify;
pub mod migration;
pub mod orchestrator;
pub mod pool_label;
pub mod protocol;
pub mod runtime;
pub mod state_machine;

pub use config::*;
pub use drain::*;
pub use drain_state::*;
pub use epoch_gate::*;
pub use executor::*;
pub use forced_fencing::*;
pub use health_verify::*;
pub use migration::*;
pub use orchestrator::*;
pub use pool_label::*;
pub use protocol::*;
pub use runtime::*;
pub use state_machine::*;
