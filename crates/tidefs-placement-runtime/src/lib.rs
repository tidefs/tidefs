// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Placement runtime engine.
//!
//! Executes deterministic placement plans across nodes. The deterministic
//! placement model (OW-303) produces verdicts about which nodes SHOULD
//! hold which chunks.  The placement runtime is the engine that actually
//! executes them: reserving target capacity, placing objects on nodes,
//! tracking placement state, and feeding the transfer orchestrator
//! with the work needed to make verdicts reality.
//!
//! ## Runtime model
//!
//! Each node executes deterministic plan-registry entries by reserving target
//! capacity, tracking placement state, and dispatching transfer work.
//! Lease-protected budget reservations keep concurrent placement plans
//! conflict-aware.

mod budget;
mod dispatch;
mod health;
mod plan_registry;
mod planner;
mod rebalance;
mod runtime;
mod shard_dispatch;
mod throttle;
mod types;

pub use budget::*;
pub use dispatch::*;
pub use health::*;
pub use plan_registry::*;
pub use planner::*;
pub use rebalance::*;
pub use runtime::*;
pub use shard_dispatch::*;
pub use throttle::*;
pub use types::*;

/// Gate constant for the placement runtime.
pub const PLACEMENT_RUNTIME_GATE: &str =
    "source-owned placement runtime executes deterministic placement plans across nodes with 5-phase lifecycle, budget tracking, and plan conflict resolution";
