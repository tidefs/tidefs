// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! tidefs-tdma-scheduler: Per-object TDMA time-slot scheduler.
//!
//! Implements the TDMA (Time-Division Multiple Access) coordination strategy
//! for per-object write scheduling. Provides fair round-robin slot allocation
//! across contending nodes with configurable slot duration, starvation
//! detection, epoch fencing, and integration with the
//! [`CoordinationStrategy::TDMA`] variant in [`tidefs_coordination_strategy`].
//!
//! # Architecture
//!
//! The scheduler maintains per-object state:
//! - Round-robin position tracking for fair allocation
//! - Active slot with start/end times and state machine
//! - Per-node starvation counters for escalation detection
//! - Epoch fencing for safe [`StrategyTransition`] integration
//!
//! Several modules provide epoch-bound slot coordination for multi-node
//! write-path scheduling:
//!
//! - [`slot_ring`]: A circular buffer of epoch-bound time slots with
//!   deterministic round-robin allocation, node-ID-to-slot mapping,
//!   stale-slot expiry, and epoch-advance drain.
//! - [`slot_grant`]: BLAKE3-authenticated slot grant tokens carrying
//!   (slot_index, epoch, grantee_node_id, issued_at_txg) with tamper
//!   detection, staleness checks, and domain-separated canonical encoding.
//!
//! The [`slot_allocator`] module provides epoch-gated deterministic
//! slot assignment with collision-free linear probing. The
//! [`slot_integrity`] module produces BLAKE3-256 domain-separated
//! integrity hashes under the `"TdmaSlot"` domain tag. The [`slot_table`]
//! module manages active-slot lifecycle with insert, lookup, and
//! epoch/time-gated expiry.
//!
//! Use the [`TdmaSchedule`] trait to consume a unified slot-scheduling
//! interface without depending on specific module paths.
//!
//! [`CoordinationStrategy::TDMA`]: tidefs_coordination_strategy::CoordinationStrategy::TDMA
//! [`StrategyTransition`]: tidefs_coordination_strategy::StrategyTransition

pub mod allocator;
pub mod clock_sync;
pub mod config;
pub mod credit;
pub mod frame;
pub mod request_queue;
pub mod scheduler;
pub mod slot;
pub mod slot_allocator;
pub mod slot_grant;
pub mod slot_integrity;
pub mod slot_ring;
pub mod slot_table;

#[cfg(test)]
mod tests;

pub use allocator::{TdmaSlotAllocator, TransmitWindow};
pub use clock_sync::TdmaClockSync;
pub use config::{TdmaConfig, TdmaConfigError};
pub use credit::{
    BandwidthSlot, CreditAccount, CreditScheduler, CreditSchedulerError, SlotAllocator, SlotTable,
};
pub use frame::{
    arbitrate_slot, FrameScheduler, FrameSchedulerError, TdmaFrame, TdmaSlotAssignment,
};
pub use request_queue::{BackpressureSignal, QueueFull, SlotRequest, SlotRequestQueue};
pub use scheduler::{
    BandwidthEnforcer, SchedulerStats, SlotAssignment, TdmaRoundConfig, TdmaRoundScheduler,
    TdmaScheduler, TdmaSchedulerConfig, TdmaSchedulerError,
};
pub use slot::{
    SlotAllocation, SlotState, TdmaSlot, TransportSlot, TransportSlotError, TransportSlotState,
    TransportSlotTable,
};
pub use slot_grant::SlotGrant;
pub use slot_ring::{SlotRing, SlotRingConfig, SlotRingError};

// ---------------------------------------------------------------------------
// TdmaSchedule trait
// ---------------------------------------------------------------------------

use tidefs_membership_epoch::EpochId;

/// Unified TDMA scheduling interface for write-path coordination.
///
/// Implementations provide deterministic slot assignment via epoch-gated
/// allocation, BLAKE3-verified slot integrity, and active-slot lifecycle
/// tracking. Callers use [`allocate_slot`](Self::allocate_slot) to obtain
/// a collision-free slot and [`lookup_slot`](Self::lookup_slot) to verify
/// slot validity during write dispatch.
pub trait TdmaSchedule {
    /// The slot-assignment type.
    type Slot;

    /// Error type for schedule operations.
    type Error;

    /// Allocate a deterministic, collision-free slot for the given
    /// (epoch, node_id, write_txg) triple.
    fn allocate_slot(
        &mut self,
        epoch: EpochId,
        node_id: u64,
        write_txg: u64,
    ) -> Result<Self::Slot, Self::Error>;

    /// Look up an allocated slot by (node_id, write_txg) key.
    fn lookup_slot(&self, node_id: u64, write_txg: u64) -> Option<Self::Slot>;

    /// Release a previously allocated slot.
    fn release_slot(&mut self, node_id: u64, write_txg: u64) -> bool;

    /// Maximum number of active slots this scheduler supports.
    fn max_slots(&self) -> usize;

    /// Number of currently allocated slots.
    fn allocated_count(&self) -> usize;
}
