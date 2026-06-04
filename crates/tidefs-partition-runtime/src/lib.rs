#![forbid(unsafe_code)]

//! P8-02 partition runtime for TideFS.
//!
//! Detects, prevents, and recovers from network partitions in the distributed
//! cluster. Integrates SWIM-based failure detection with epoch fencing to
//! guarantee split-brain safety at runtime.
//!
//! ## Architecture
//!
//! - [`types`]: Hazard classes, partition states, reachability matrix,
//!   reconciliation types, audit records, and drift-adaptive config.
//! - [`partition_detector`]: Monitors the SWIM failure detector, builds a
//!   reachability matrix from peer observations, and identifies connected
//!   components (partition sides).
//! - [`split_brain_guard`]: Membership-epoch-gated quorum checking,
//!   witness-vouche verification for tie-breaking, minority-side freeze,
//!   and split-brain hazard emission.
//! - [`publication_gate`]: Epoch-gated publication admission during
//!   partition; freezes publication on the minority side and admits
//!   under new epoch on the quorum side.
//! - [`partition_healing`]: C2 joint config creation, receipt frontier
//!   exchange, divergence classification, and reconciliation strategy
//!   selection.
//! - [`post_heal_placement`]: Post-heal placement recomputation,
//!   anti-entropy scan trigger, and replica rebuild coordination.
//! - [`partition_runtime`]: The main `PartitionRuntime` service coordinating
//!   all components in a long-running loop.
//! - [`partition_audit`]: Records partition events for operator audit
//!   through the operator audit system (#898).
//!
//! ## Integration
//!
//! The partition runtime integrates with:
//! - [`tidefs-membership-live`]: SWIM failure detector for liveness tracking
//!   and peer reachability.
//! - [`tidefs-membership-epoch`]: Deterministic epoch model — split-brain
//!   hazards, verict classes, and member state.
//! - [`tidefs-witness-set`]: Witness-vouche verification for breaking ties
//!   in ambiguous (even-split) partitions.
//! - Transport (#883): Session disconnection feeds partition detection.
//! - Transfer orchestrator (#901): Reconciliation shipment after heal.
//! - Publication pipeline (#915): Epoch-gated publication during partition.
//! - Operator audit (#898): Operator audit trail.

pub mod partition_audit;
pub mod partition_detector;
pub mod partition_healing;
pub mod partition_runtime;
pub mod post_heal_placement;
pub mod publication_gate;
pub mod single_writer_fence;
pub mod split_brain_guard;
pub mod types;

// Re-exports
pub use partition_audit::PartitionAuditRecorder;
pub use partition_detector::PartitionDetector;
pub use partition_healing::PartitionHealingProtocol;
pub use partition_runtime::{PartitionRuntime, PartitionTickResult};
pub use post_heal_placement::{PostHealPending, PostHealPlacementRecompute};
pub use publication_gate::{PublicationGateResult, PublicationPipelineEpochGate};
pub use single_writer_fence::SingleWriterFence;
pub use split_brain_guard::SplitBrainGuard;
pub use types::{
    DivergenceClass, PartitionDetectionConfig, PartitionEvent, PartitionEventClass, PartitionFence,
    PartitionHazardClass, PartitionState, PartitionSuspect, ReachabilityEntry, ReachabilityMatrix,
    ReceiptFrontier, ReconciliationStrategy,
};
