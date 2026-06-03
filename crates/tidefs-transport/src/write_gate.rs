//! Write-gate for single-writer fencing.
//!
//! The [`WriteGate`] is the transport-layer enforcement point for the
//! single-writer fence mechanism defined in `tidefs-cluster::write_fence`.
//! Before any write request is dispatched to the storage layer, the
//! transport dispatch path calls [`WriteGate::check_fence`] to verify
//! that the write carries the current active fence token.
//!
//! Writes carrying a stale fence (from a prior lease holder) are rejected
//! with [`StaleFence`], preventing split ownership in the multi-node
//! write path.
//!
//! ## Architecture
//!
//! - [`WriteGate`]: holds a [`FenceValidator`] obtained from the cluster
//!   lease runtime. The validator is an `Arc`-backed read-only view of
//!   the active fence.
//! - [`check_fence`](WriteGate::check_fence): the single validation entry
//!   point. Takes a [`WriteFence`] from the inbound write and returns
//!   `Ok(())` or `Err(StaleFence)`.
//!
//! ## Integration
//!
//! The [`WriteGate`] is constructed with a [`FenceValidator`] obtained
//! from [`ClusterLeaseRuntime::fence_validator`]. It is consulted in the
//! transport message dispatch path before forwarding writes to the
//! storage layer.
//!
//! ## Relationship to EpochFence
//!
//! [`EpochFence`](crate::epoch_fence) gates connection-level access
//! (departed peers get their connections drained). [`WriteGate`] gates
//! write-level access within an active connection (writes from a prior
//! lease holder are rejected even if the connection is still alive).
//! Together, they provide defense-in-depth against split-ownership
//! scenarios.

use tidefs_cluster::write_fence::{FenceValidator, StaleFence, WriteFence};

/// Transport-layer enforcement point for single-writer fencing.
///
/// Wraps a [`FenceValidator`] and provides a type-erased validation
/// interface suitable for the transport dispatch path.
///
/// # Thread safety
///
/// [`WriteGate`] is `Send + Sync` and cheap to clone. All clones share
/// the same underlying validator and see fence updates immediately.
#[derive(Clone, Debug)]
pub struct WriteGate {
    validator: FenceValidator,
}

impl WriteGate {
    /// Create a new write gate from a [`FenceValidator`].
    pub fn new(validator: FenceValidator) -> Self {
        Self { validator }
    }

    /// Check whether a write carrying `fence` is authorized under the
    /// current single-writer lease.
    ///
    /// Returns `Ok(())` if the write is current.
    /// Returns `Err(StaleFence)` if the write carries a fence from a
    /// prior lease holder (or if no active fence exists).
    pub fn check_fence(&self, fence: WriteFence) -> Result<(), StaleFence> {
        self.validator.validate(fence)
    }

    /// Return the currently active fence, if any.
    pub fn active_fence(&self) -> Option<WriteFence> {
        self.validator.active_fence()
    }
}
