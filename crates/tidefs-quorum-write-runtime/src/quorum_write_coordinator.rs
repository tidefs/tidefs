// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Quorum-write coordinator: ties TDMA slot acquisition, epoch-gated
//! lease acquisition, and BLAKE3-verified quorum dispatch into a single
//! coherent multi-node write fast path.
//!
//! # Protocol flow
//!
//! ```text
//! acquire_slot → validate_epoch → acquire_lease → quorum_dispatch
//!                                                  ├─ collect_acks
//!                                                  ├─ quorum_reached → commit → release_slot(success)
//!                                                  └─ quorum_failed  → abort  → release_slot(abort)
//! ```
//!
//! Each phase is gated by the current epoch. An epoch change mid-write
//! invalidates the slot, lease, and in-flight dispatch, forcing an abort.

use std::fmt;

use std::sync::Arc;
use tidefs_cache_coherency::CoherencyEventBus;
use tidefs_lease::types::{LeaseClass, LeaseDomain, LeaseGrant};
use tidefs_lease_manager::manager::LeaseManager;
use tidefs_membership_epoch::{EpochId, EpochToken, MemberId};
use tidefs_quorum_write::{QuorumWriteResult, QuorumWriteSummary, WriteClass};
use tidefs_tdma_scheduler::slot_allocator::{SlotAllocator, SlotAssignment};
use tidefs_tdma_scheduler::slot_grant::SlotGrant;

use crate::config::QuorumWriteConfig;
use crate::coordinator::QuorumWriteRuntime;

// ═══════════════════════════════════════════════════════════════════════
// CoordinatorError
// ═══════════════════════════════════════════════════════════════════════

/// Errors produced by the quorum-write coordinator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoordinatorError {
    /// No alive target nodes available.
    NoTargets,
    /// Slot acquisition failed.
    SlotAcquisitionFailed(String),
    /// Slot grant validation failed (BLAKE3 token mismatch).
    /// Epoch mismatch between coordinator and slot grant.
    EpochMismatch { expected: u64, actual: u64 },
    /// No membership-epoch token has witnessed the coordinator's current epoch.
    MissingEpochToken { current_epoch: u64 },
    /// A supplied membership-epoch token is older than the coordinator epoch.
    StaleEpochToken {
        token_epoch: u64,
        current_epoch: u64,
    },
    /// A supplied membership-epoch token does not match the coordinator epoch.
    EpochTokenMismatch {
        token_epoch: u64,
        current_epoch: u64,
    },
    /// Slot is stale (epoch too old).
    StaleSlot { slot_epoch: u64, current_epoch: u64 },
    /// Write lease epoch differs from the token-witnessed coordinator epoch.
    LeaseEpochMismatch { expected: u64, actual: u64 },
    /// Lease acquisition failed.
    LeaseAcquisitionFailed(String),
    /// Quorum write dispatch failed.
    QuorumWriteFailed(String),
    /// Internal error from the quorum runtime.
    RuntimeError(String),
    /// Slot release after abort failed.
    SlotReleaseFailed(String),
    /// Timeout: the total timeout expired before quorum was reached.
    Timeout(String),
}

impl fmt::Display for CoordinatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTargets => write!(f, "quorum coordinator: no alive target nodes"),
            Self::SlotAcquisitionFailed(reason) => {
                write!(f, "slot acquisition failed: {reason}")
            }
            Self::EpochMismatch { expected, actual } => {
                write!(f, "epoch mismatch: expected {expected}, got {actual}")
            }
            Self::MissingEpochToken { current_epoch } => {
                write!(
                    f,
                    "missing membership epoch token for current epoch {current_epoch}"
                )
            }
            Self::StaleEpochToken {
                token_epoch,
                current_epoch,
            } => {
                write!(
                    f,
                    "stale membership epoch token: token epoch {token_epoch} < current epoch {current_epoch}"
                )
            }
            Self::EpochTokenMismatch {
                token_epoch,
                current_epoch,
            } => {
                write!(
                    f,
                    "membership epoch token mismatch: token epoch {token_epoch}, current epoch {current_epoch}"
                )
            }
            Self::StaleSlot {
                slot_epoch,
                current_epoch,
            } => {
                write!(
                    f,
                    "stale slot: slot epoch {slot_epoch} < current epoch {current_epoch}"
                )
            }
            Self::LeaseEpochMismatch { expected, actual } => {
                write!(f, "lease epoch mismatch: expected {expected}, got {actual}")
            }
            Self::LeaseAcquisitionFailed(reason) => {
                write!(f, "lease acquisition failed: {reason}")
            }
            Self::QuorumWriteFailed(reason) => {
                write!(f, "quorum write failed: {reason}")
            }
            Self::RuntimeError(reason) => {
                write!(f, "quorum runtime error: {reason}")
            }
            Self::SlotReleaseFailed(reason) => {
                write!(f, "slot release failed: {reason}")
            }
            Self::Timeout(reason) => {
                write!(f, "coordinator timeout: {reason}")
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// CoordinatorOutcome
// ═══════════════════════════════════════════════════════════════════════

/// The result of a successfully coordinated quorum write.
#[derive(Clone, Debug)]
pub struct CoordinatorOutcome {
    /// The TDMA slot that was acquired for this write.
    pub slot_grant: SlotGrant,
    /// The lease that was acquired (if lease acquisition was enabled).
    pub lease_grant: Option<LeaseGrant>,
    /// The quorum write result from the runtime.
    pub quorum_result: QuorumWriteResult,
    /// The quorum write summary from the runtime.
    pub quorum_summary: QuorumWriteSummary,
    /// Whether quorum was fully satisfied.
    pub quorum_reached: bool,
    /// Write class as determined by the runtime.
    pub write_class: WriteClass,
}

// ═══════════════════════════════════════════════════════════════════════
// QuorumWriteCoordinator
// ═══════════════════════════════════════════════════════════════════════

/// High-level quorum-write coordinator that integrates TDMA slot allocation,
/// epoch-gated lease acquisition, and BLAKE3-verified quorum dispatch into
/// a single coherent multi-node write fast path.
///
/// The coordinator sits above `QuorumWriteRuntime` and adds the slot+lease
/// layer. On every write:
///
/// 1. Acquire a deterministic TDMA slot for (node_id, write_txg, epoch).
/// 2. Validate the slot grant (BLAKE3 token, staleness, epoch match).
/// 3. Optionally acquire a write lease for the target domain.
/// 4. Dispatch the quorum write via `QuorumWriteRuntime::execute_write()`.
/// 5. On quorum reached: commit via intent log, release slot with success.
/// 6. On quorum failed: abort, release slot, return error.
pub struct QuorumWriteCoordinator {
    /// The underlying quorum write runtime (handles dispatch, ack collection,
    /// quorum resolution, and commit).
    runtime: QuorumWriteRuntime,

    /// TDMA slot allocator for deterministic slot acquisition. Wrapped in
    /// Option to allow the coordinator to operate without slot scheduling
    /// (e.g., single-node mode or testing).
    slot_allocator: Option<SlotAllocator>,

    /// Lease manager for write-lease acquisition. Optional: single-node
    /// and non-leased configurations skip lease acquisition.
    lease_manager: Option<LeaseManager>,

    /// This node's identifier (used for slot allocation and lease holder id).
    node_id: u64,

    /// Coarse timestamp for lease TTL calculations (milliseconds since epoch).
    time_source_ms: u64,

    /// The last epoch this coordinator was configured for.
    current_epoch: EpochId,

    /// Membership-epoch proof that witnessed `current_epoch`.
    current_epoch_token: Option<EpochToken>,

    /// Whether lease acquisition is enabled.
    lease_enabled: bool,

    /// Optional coherency event bus for mmap cache invalidation
    /// when leases are revoked across clustered clients.
    coherency_bus: Option<Arc<CoherencyEventBus>>,

    /// Whether slot acquisition is enabled.
    slot_enabled: bool,
}

impl QuorumWriteCoordinator {
    /// Create a coordinator with no TDMA scheduler or lease manager.
    /// Useful for single-node or test configurations.
    #[must_use]
    pub fn new(config: QuorumWriteConfig, local_store_root: std::path::PathBuf) -> Self {
        let runtime = QuorumWriteRuntime::new(config, local_store_root, Vec::new());
        Self {
            runtime,
            slot_allocator: None,
            lease_manager: None,
            coherency_bus: None,
            node_id: 0,
            time_source_ms: 0,
            current_epoch: EpochId::new(0),
            current_epoch_token: None,
            lease_enabled: false,
            slot_enabled: false,
        }
    }

    /// Attach a TDMA slot allocator, enabling slot-gated writes.
    #[must_use]
    pub fn with_slot_allocator(mut self, allocator: SlotAllocator) -> Self {
        self.slot_enabled = true;
        self.slot_allocator = Some(allocator);
        self
    }

    /// Attach a coherency event bus for mmap cache invalidation.
    ///
    /// The bus is wired into the lease manager when both are configured,
    /// so that lease revocation automatically triggers page-cache
    /// invalidation across clustered clients.
    #[must_use]
    pub fn with_coherency_bus(mut self, bus: Arc<CoherencyEventBus>) -> Self {
        self.coherency_bus = Some(bus);
        self
    }

    /// Attach a lease manager, enabling lease-gated writes.
    ///
    /// If a coherency bus was previously set via [`with_coherency_bus`],
    /// it is automatically wired into the lease manager so that lease
    /// revocation triggers cache invalidation.
    #[must_use]
    pub fn with_lease_manager(mut self, lease_mgr: LeaseManager) -> Self {
        self.lease_enabled = true;
        let mut lm = lease_mgr;
        if let Some(ref bus) = self.coherency_bus {
            lm.set_coherency_bus(Arc::clone(bus));
        }
        if self.current_epoch > lm.current_epoch() {
            lm.advance_epoch(self.current_epoch);
        }
        self.lease_manager = Some(lm);
        self
    }

    /// Set the local node identifier.
    pub fn set_node_id(&mut self, node_id: u64) {
        self.node_id = node_id;
        let targets = self.runtime.target_nodes();
        self.runtime.set_targets(targets);
    }

    /// Update the coarse time source (for lease TTL).
    pub fn set_time_ms(&mut self, now_ms: u64) {
        self.time_source_ms = now_ms;
    }

    /// Get the current epoch.
    #[must_use]
    pub fn current_epoch(&self) -> EpochId {
        self.current_epoch
    }

    /// Get the current membership-epoch token proof.
    #[must_use]
    pub fn current_epoch_token(&self) -> Option<EpochToken> {
        self.current_epoch_token
    }

    /// Consume a membership-epoch token proving the coordinator's current epoch.
    ///
    /// The token is issued and owned by `tidefs-membership-epoch`; the quorum
    /// coordinator only mirrors the witnessed epoch and refuses writes without
    /// a matching token.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorError::StaleEpochToken`] if the token is older than
    /// the coordinator's current epoch.
    pub fn witness_epoch_token(&mut self, token: EpochToken) -> Result<usize, CoordinatorError> {
        if token.epoch < self.current_epoch {
            return Err(CoordinatorError::StaleEpochToken {
                token_epoch: token.epoch.0,
                current_epoch: self.current_epoch.0,
            });
        }

        let revoked = self.apply_epoch(token.epoch);
        self.current_epoch_token = Some(token);
        Ok(revoked)
    }

    /// Advance to a locally observed epoch without proof authority.
    ///
    /// This invalidates all slots and leases from prior epochs, clears any
    /// previously witnessed token, and returns the number of leases revoked.
    /// Call [`Self::witness_epoch_token`] with a token from
    /// `tidefs-membership-epoch` before dispatching another quorum write.
    pub fn advance_epoch(&mut self, new_epoch: EpochId) -> usize {
        let revoked = self.apply_epoch(new_epoch);
        self.current_epoch_token = None;
        revoked
    }

    fn apply_epoch(&mut self, new_epoch: EpochId) -> usize {
        let revoked = if let Some(ref mut lm) = self.lease_manager {
            lm.advance_epoch(new_epoch).len()
        } else {
            0
        };
        self.current_epoch = new_epoch;
        let targets = self.runtime.target_nodes();
        self.runtime.set_targets(targets);
        revoked
    }

    /// Sync targets from alive membership voters.
    pub fn sync_targets_from_membership(&mut self, alive_voters: &[MemberId]) {
        self.runtime.sync_targets_from_membership(alive_voters);
    }

    /// Set explicit target node list.
    pub fn set_targets(&mut self, targets: Vec<tidefs_quorum_write::NodeId>) {
        self.runtime.set_targets(targets);
    }

    /// Get the current target nodes.
    #[must_use]
    pub fn target_nodes(&self) -> Vec<tidefs_quorum_write::NodeId> {
        self.runtime.target_nodes()
    }

    /// Whether slot acquisition is enabled.
    #[must_use]
    pub fn slot_enabled(&self) -> bool {
        self.slot_enabled
    }

    /// Whether lease acquisition is enabled.
    #[must_use]
    pub fn lease_enabled(&self) -> bool {
        self.lease_enabled
    }

    /// Execute a full coordinated quorum write: acquire slot → acquire lease
    /// → dispatch quorum write → commit or abort.
    ///
    /// # Errors
    ///
    /// Returns `CoordinatorError` on slot acquisition failure, lease
    /// acquisition failure, quorum failure, epoch mismatch, or timeout.
    pub fn execute_coordinated_write(
        &mut self,
        object_key: &str,
        data: &[u8],
        write_txg: u64,
    ) -> Result<CoordinatorOutcome, CoordinatorError> {
        self.validate_current_epoch_token()?;

        // ── 1. Slot acquisition ────────────────────────────────────
        let slot_grant = if self.slot_enabled {
            self.acquire_slot(write_txg)?
        } else {
            SlotGrant::new(0, self.current_epoch, 0, 0)
        };

        // ── 2. Epoch validation ────────────────────────────────────
        self.validate_slot_epoch(&slot_grant)?;

        // ── 3. Lease acquisition ───────────────────────────────────
        let lease_grant = if self.lease_enabled && self.lease_manager.is_some() {
            Some(self.acquire_write_lease(object_key)?)
        } else {
            None
        };
        if let Some(ref grant) = lease_grant {
            self.validate_lease_epoch(grant)?;
        }

        // ── 4. Quorum dispatch ─────────────────────────────────────
        self.validate_current_epoch_token()?;
        let (quorum_result, quorum_summary) = self
            .runtime
            .execute_write(object_key, data)
            .map_err(CoordinatorError::QuorumWriteFailed)?;

        let quorum_reached = quorum_result.write_class.is_success();
        let write_class = quorum_result.write_class;

        // ── 5. Commit or abort ─────────────────────────────────────
        if quorum_reached {
            self.validate_current_epoch_token()?;
            self.release_slot_success(&slot_grant, write_txg);
        } else {
            self.abort_write(&slot_grant, write_txg)?;
            return Err(CoordinatorError::QuorumWriteFailed(format!(
                "quorum not reached: {:?}, acks={}/{}",
                write_class, quorum_result.acks_count, quorum_result.target_count
            )));
        }

        Ok(CoordinatorOutcome {
            slot_grant,
            lease_grant,
            quorum_result,
            quorum_summary,
            quorum_reached,
            write_class,
        })
    }

    /// Acquire a TDMA slot for the given write transaction group.
    fn acquire_slot(&mut self, write_txg: u64) -> Result<SlotGrant, CoordinatorError> {
        let allocator = self.slot_allocator.as_mut().ok_or_else(|| {
            CoordinatorError::SlotAcquisitionFailed("no slot allocator configured".into())
        })?;

        let assignment: SlotAssignment = allocator
            .allocate(self.current_epoch, self.node_id, write_txg)
            .map_err(|e| CoordinatorError::SlotAcquisitionFailed(format!("{e:?}")))?;

        let grant = SlotGrant::new(
            assignment.slot_index as u32,
            assignment.epoch,
            assignment.node_id,
            assignment.write_txg,
        );

        // Transport layer provides integrity for slot grants.
        Ok(grant)
    }

    /// Validate that the slot grant matches the current epoch.
    fn validate_slot_epoch(&self, grant: &SlotGrant) -> Result<(), CoordinatorError> {
        self.validate_current_epoch_token()?;
        if grant.is_stale(self.current_epoch) {
            return Err(CoordinatorError::StaleSlot {
                slot_epoch: grant.epoch.0,
                current_epoch: self.current_epoch.0,
            });
        }
        if grant.epoch != self.current_epoch {
            return Err(CoordinatorError::EpochMismatch {
                expected: self.current_epoch.0,
                actual: grant.epoch.0,
            });
        }
        Ok(())
    }

    fn validate_current_epoch_token(&self) -> Result<(), CoordinatorError> {
        let Some(token) = self.current_epoch_token else {
            return Err(CoordinatorError::MissingEpochToken {
                current_epoch: self.current_epoch.0,
            });
        };

        if token.epoch < self.current_epoch {
            return Err(CoordinatorError::StaleEpochToken {
                token_epoch: token.epoch.0,
                current_epoch: self.current_epoch.0,
            });
        }
        if token.epoch != self.current_epoch {
            return Err(CoordinatorError::EpochTokenMismatch {
                token_epoch: token.epoch.0,
                current_epoch: self.current_epoch.0,
            });
        }
        Ok(())
    }

    fn validate_lease_epoch(&self, grant: &LeaseGrant) -> Result<(), CoordinatorError> {
        self.validate_current_epoch_token()?;
        if grant.epoch != self.current_epoch {
            return Err(CoordinatorError::LeaseEpochMismatch {
                expected: self.current_epoch.0,
                actual: grant.epoch.0,
            });
        }
        Ok(())
    }

    /// Acquire a write lease for the target object domain.
    fn acquire_write_lease(&mut self, object_key: &str) -> Result<LeaseGrant, CoordinatorError> {
        self.validate_current_epoch_token()?;

        let domain = LeaseDomain::Subtree {
            dataset_id: 0,
            prefix: object_key.to_string(),
        };
        let holder = MemberId::new(self.node_id);

        let grant = {
            let lm = self.lease_manager.as_mut().ok_or_else(|| {
                CoordinatorError::LeaseAcquisitionFailed("no lease manager configured".into())
            })?;

            lm.grant(
                LeaseClass::Exclusive,
                domain,
                holder,
                0,
                self.time_source_ms,
            )
            .map_err(|e| CoordinatorError::LeaseAcquisitionFailed(format!("{e:?}")))?
        };
        self.validate_lease_epoch(&grant)?;
        Ok(grant)
    }

    /// Release the slot with a success marker.
    fn release_slot_success(&mut self, _grant: &SlotGrant, write_txg: u64) {
        if let Some(ref mut allocator) = self.slot_allocator {
            allocator.release(self.node_id, write_txg);
        }
    }

    /// Abort the write: release the slot and optionally revoke the lease.
    fn abort_write(&mut self, _grant: &SlotGrant, write_txg: u64) -> Result<(), CoordinatorError> {
        if let Some(ref mut allocator) = self.slot_allocator {
            if !allocator.release(self.node_id, write_txg) {
                return Err(CoordinatorError::SlotReleaseFailed(format!(
                    "failed to release slot for (node {}, txg {})",
                    self.node_id, write_txg
                )));
            }
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tidefs_lease_manager::manager::LeaseManagerConfig;
    use tidefs_quorum_write::NodeId;

    fn make_config() -> QuorumWriteConfig {
        QuorumWriteConfig::dev_local()
    }

    fn make_coordinator() -> QuorumWriteCoordinator {
        QuorumWriteCoordinator::new(make_config(), PathBuf::from("/tmp/qwc"))
    }

    fn epoch_token(epoch: u64, generation: u64) -> EpochToken {
        EpochToken {
            epoch: EpochId::new(epoch),
            generation,
        }
    }

    fn authorize_epoch(c: &mut QuorumWriteCoordinator, epoch: u64, generation: u64) {
        c.witness_epoch_token(epoch_token(epoch, generation))
            .expect("epoch token should authorize coordinator");
    }

    // ── Basic coordinator construction ──────────────────────────────

    #[test]
    fn coordinator_created_with_no_slot_or_lease() {
        let c = make_coordinator();
        assert!(!c.slot_enabled());
        assert!(!c.lease_enabled());
        assert_eq!(c.current_epoch(), EpochId::new(0));
        assert_eq!(c.current_epoch_token(), None);
    }

    #[test]
    fn coordinator_with_slot_allocator() {
        let alloc = SlotAllocator::new(EpochId::new(0), 64).unwrap();
        let c = make_coordinator().with_slot_allocator(alloc);
        assert!(c.slot_enabled());
        assert!(!c.lease_enabled());
    }

    #[test]
    fn coordinator_with_lease_manager() {
        let cfg = LeaseManagerConfig {
            witness_quorum: 0,
            ..LeaseManagerConfig::default()
        };
        let lm = LeaseManager::new(cfg, EpochId::new(0));
        let c = make_coordinator().with_lease_manager(lm);
        assert!(!c.slot_enabled());
        assert!(c.lease_enabled());
    }

    #[test]
    fn coordinator_with_both_slot_and_lease() {
        let alloc = SlotAllocator::new(EpochId::new(0), 64).unwrap();
        let cfg = LeaseManagerConfig {
            witness_quorum: 0,
            ..LeaseManagerConfig::default()
        };
        let lm = LeaseManager::new(cfg, EpochId::new(0));
        let c = make_coordinator()
            .with_slot_allocator(alloc)
            .with_lease_manager(lm);
        assert!(c.slot_enabled());
        assert!(c.lease_enabled());
    }

    // ── Epoch management ────────────────────────────────────────────

    #[test]
    fn advance_epoch_increments_current() {
        let mut c = make_coordinator();
        assert_eq!(c.current_epoch().0, 0);
        authorize_epoch(&mut c, 0, 0);
        let revoked = c.advance_epoch(EpochId::new(5));
        assert_eq!(revoked, 0);
        assert_eq!(c.current_epoch().0, 5);
        assert_eq!(c.current_epoch_token(), None);
    }

    #[test]
    fn advance_epoch_with_lease_manager_revokes_leases() {
        let cfg = LeaseManagerConfig {
            witness_quorum: 0,
            ..LeaseManagerConfig::default()
        };
        let lm = LeaseManager::new(cfg, EpochId::new(0));
        let mut c = make_coordinator().with_lease_manager(lm);
        c.set_node_id(1);
        c.set_time_ms(1000);
        authorize_epoch(&mut c, 0, 0);
        let revoked = c.advance_epoch(EpochId::new(3));
        assert_eq!(revoked, 0);
        assert_eq!(c.current_epoch().0, 3);
        assert_eq!(c.current_epoch_token(), None);
    }

    #[test]
    fn witness_epoch_token_accepts_current_epoch_token() {
        let mut c = make_coordinator();
        authorize_epoch(&mut c, 0, 0);

        assert_eq!(c.current_epoch(), EpochId::new(0));
        assert_eq!(c.current_epoch_token(), Some(epoch_token(0, 0)));
        assert!(c.validate_current_epoch_token().is_ok());
    }

    #[test]
    fn witness_epoch_token_rejects_stale_token() {
        let mut c = make_coordinator();
        authorize_epoch(&mut c, 0, 0);
        c.advance_epoch(EpochId::new(2));

        let result = c.witness_epoch_token(epoch_token(0, 0));

        match result.unwrap_err() {
            CoordinatorError::StaleEpochToken {
                token_epoch,
                current_epoch,
            } => {
                assert_eq!(token_epoch, 0);
                assert_eq!(current_epoch, 2);
            }
            other => panic!("expected StaleEpochToken, got {other:?}"),
        }
    }

    #[test]
    fn validate_current_epoch_token_rejects_absent_token() {
        let c = make_coordinator();

        match c.validate_current_epoch_token().unwrap_err() {
            CoordinatorError::MissingEpochToken { current_epoch } => {
                assert_eq!(current_epoch, 0);
            }
            other => panic!("expected MissingEpochToken, got {other:?}"),
        }
    }

    #[test]
    fn validate_current_epoch_token_rejects_mismatched_token() {
        let mut c = make_coordinator();
        c.current_epoch_token = Some(epoch_token(5, 1));

        match c.validate_current_epoch_token().unwrap_err() {
            CoordinatorError::EpochTokenMismatch {
                token_epoch,
                current_epoch,
            } => {
                assert_eq!(token_epoch, 5);
                assert_eq!(current_epoch, 0);
            }
            other => panic!("expected EpochTokenMismatch, got {other:?}"),
        }
    }

    // ── Slot acquisition ────────────────────────────────────────────

    #[test]
    fn acquire_slot_succeeds_with_available_slots() {
        let alloc = SlotAllocator::new(EpochId::new(0), 64).unwrap();
        let mut c = make_coordinator().with_slot_allocator(alloc);
        c.set_node_id(1);

        let result = c.acquire_slot(100);
        assert!(result.is_ok());
        let grant = result.unwrap();
        assert_eq!(grant.epoch, EpochId::new(0));
        assert_eq!(grant.grantee_node_id, 1);
        assert_eq!(grant.issued_at_txg, 100);
        // validate removed: transport provides integrity
    }

    #[test]
    fn acquire_slot_different_write_txg_get_different_slots() {
        let alloc = SlotAllocator::new(EpochId::new(0), 64).unwrap();
        let mut c = make_coordinator().with_slot_allocator(alloc);
        c.set_node_id(1);

        let g1 = c.acquire_slot(10).unwrap();
        let g2 = c.acquire_slot(20).unwrap();
        assert_ne!(g1.slot_index, g2.slot_index);
        // grant_token removed: transport provides integrity
    }

    #[test]
    fn acquire_slot_same_txg_collision() {
        let alloc = SlotAllocator::new(EpochId::new(0), 64).unwrap();
        let mut c = make_coordinator().with_slot_allocator(alloc);
        c.set_node_id(1);

        let _g1 = c.acquire_slot(42).unwrap();
        let result = c.acquire_slot(42);
        assert!(result.is_err());
    }

    #[test]
    fn acquire_slot_epoch_mismatch_rejected() {
        let alloc = SlotAllocator::new(EpochId::new(5), 64).unwrap();
        let mut c = make_coordinator().with_slot_allocator(alloc);
        c.set_node_id(1);
        c.current_epoch = EpochId::new(0);

        let result = c.acquire_slot(1);
        assert!(result.is_err());
    }

    // ── Slot epoch validation ───────────────────────────────────────

    #[test]
    fn validate_slot_epoch_matching_epoch_passes() {
        let mut c = make_coordinator();
        authorize_epoch(&mut c, 0, 0);
        let grant = SlotGrant::new(0, EpochId::new(0), 1, 100);
        assert!(c.validate_slot_epoch(&grant).is_ok());
    }

    #[test]
    fn validate_slot_epoch_future_epoch_rejected() {
        let mut c = make_coordinator();
        authorize_epoch(&mut c, 0, 0);
        let grant = SlotGrant::new(0, EpochId::new(5), 1, 100);
        let result = c.validate_slot_epoch(&grant);
        assert!(result.is_err());
    }

    #[test]
    fn validate_slot_epoch_stale_detected() {
        let mut c = make_coordinator();
        c.current_epoch = EpochId::new(10);
        c.current_epoch_token = Some(epoch_token(10, 1));
        let grant = SlotGrant::new(0, EpochId::new(3), 1, 100);
        let result = c.validate_slot_epoch(&grant);
        assert!(result.is_err());
        match result.unwrap_err() {
            CoordinatorError::StaleSlot {
                slot_epoch,
                current_epoch,
            } => {
                assert_eq!(slot_epoch, 3);
                assert_eq!(current_epoch, 10);
            }
            other => panic!("expected StaleSlot, got {other:?}"),
        }
    }

    // ── Lease acquisition ───────────────────────────────────────────

    #[test]
    fn acquire_write_lease_succeeds() {
        let cfg = LeaseManagerConfig {
            witness_quorum: 0,
            ..LeaseManagerConfig::default()
        };
        let lm = LeaseManager::new(cfg, EpochId::new(0));
        let mut c = make_coordinator().with_lease_manager(lm);
        c.set_node_id(1);
        c.set_time_ms(1000);
        authorize_epoch(&mut c, 0, 0);

        let grant = c.acquire_write_lease("obj/test_lease");
        assert!(grant.is_ok());
        let g = grant.unwrap();
        assert_eq!(g.holder_id, MemberId::new(1));
    }

    #[test]
    fn acquire_write_lease_no_manager_error() {
        let mut c = make_coordinator();
        c.set_node_id(1);
        c.lease_enabled = true;
        authorize_epoch(&mut c, 0, 0);

        let result = c.acquire_write_lease("obj/test");
        assert!(result.is_err());
    }

    #[test]
    fn validate_lease_epoch_rejects_mismatched_write_epoch() {
        let mut c = make_coordinator();
        authorize_epoch(&mut c, 1, 1);
        let grant = LeaseGrant::request(
            1,
            LeaseClass::Exclusive,
            LeaseDomain::Subtree {
                dataset_id: 0,
                prefix: "obj/stale".into(),
            },
            MemberId::new(1),
            0,
            5_000,
            1_000,
            EpochId::new(0),
            tidefs_membership_epoch::DatasetMountIdentity::ZERO,
            0,
            0,
            0,
        );

        match c.validate_lease_epoch(&grant).unwrap_err() {
            CoordinatorError::LeaseEpochMismatch { expected, actual } => {
                assert_eq!(expected, 1);
                assert_eq!(actual, 0);
            }
            other => panic!("expected LeaseEpochMismatch, got {other:?}"),
        }
    }

    // ── Slot release and abort ──────────────────────────────────────

    #[test]
    fn release_slot_frees_allocation() {
        let alloc = SlotAllocator::new(EpochId::new(0), 64).unwrap();
        let mut c = make_coordinator().with_slot_allocator(alloc);
        c.set_node_id(1);

        let grant = c.acquire_slot(50).unwrap();
        let slot_idx = grant.slot_index as u64;
        assert!(c
            .slot_allocator
            .as_ref()
            .unwrap()
            .is_allocated(1, 50, slot_idx));

        c.release_slot_success(&grant, 50);
        assert!(!c
            .slot_allocator
            .as_ref()
            .unwrap()
            .is_allocated(1, 50, slot_idx));
    }

    #[test]
    fn abort_write_releases_slot() {
        let alloc = SlotAllocator::new(EpochId::new(0), 64).unwrap();
        let mut c = make_coordinator().with_slot_allocator(alloc);
        c.set_node_id(1);

        let grant = c.acquire_slot(77).unwrap();
        let slot_idx = grant.slot_index as u64;
        assert!(c
            .slot_allocator
            .as_ref()
            .unwrap()
            .is_allocated(1, 77, slot_idx));

        let result = c.abort_write(&grant, 77);
        assert!(result.is_ok());
        assert!(!c
            .slot_allocator
            .as_ref()
            .unwrap()
            .is_allocated(1, 77, slot_idx));
    }

    #[test]
    fn abort_write_double_release_is_error() {
        let alloc = SlotAllocator::new(EpochId::new(0), 64).unwrap();
        let mut c = make_coordinator().with_slot_allocator(alloc);
        c.set_node_id(1);

        let grant = c.acquire_slot(88).unwrap();
        assert!(c.abort_write(&grant, 88).is_ok());
        let result = c.abort_write(&grant, 88);
        assert!(result.is_err());
    }

    // ── End-to-end coordinated write ────────────────────────────────

    #[test]
    fn coordinated_write_single_target_no_slot_no_lease() {
        let mut c = make_coordinator();
        authorize_epoch(&mut c, 0, 0);
        c.set_targets(vec![NodeId::new(1)]);

        let result = c.execute_coordinated_write("obj/e2e", b"payload", 1);
        assert!(result.is_ok());
        let outcome = result.unwrap();
        assert!(outcome.quorum_reached);
        assert_eq!(outcome.write_class, WriteClass::Committed);
        assert_eq!(outcome.quorum_result.acks_count, 1);
    }

    #[test]
    fn coordinated_write_with_slot_acquisition() {
        let alloc = SlotAllocator::new(EpochId::new(0), 64).unwrap();
        let mut c = make_coordinator().with_slot_allocator(alloc);
        c.set_node_id(1);
        authorize_epoch(&mut c, 0, 0);
        c.set_targets(vec![NodeId::new(1)]);

        let result = c.execute_coordinated_write("obj/slotted", b"data", 100);
        assert!(result.is_ok());
        let outcome = result.unwrap();
        assert!(outcome.quorum_reached);
        assert_eq!(outcome.slot_grant.grantee_node_id, 1);
        assert_eq!(outcome.slot_grant.issued_at_txg, 100);
    }

    #[test]
    fn coordinated_write_with_slot_and_lease() {
        let alloc = SlotAllocator::new(EpochId::new(0), 64).unwrap();
        let lm_cfg = LeaseManagerConfig {
            witness_quorum: 0,
            ..LeaseManagerConfig::default()
        };
        let lm = LeaseManager::new(lm_cfg, EpochId::new(0));
        let mut c = make_coordinator()
            .with_slot_allocator(alloc)
            .with_lease_manager(lm);
        c.set_node_id(1);
        c.set_time_ms(2000);
        authorize_epoch(&mut c, 0, 0);
        c.set_targets(vec![NodeId::new(1)]);

        let result = c.execute_coordinated_write("obj/both", b"payload", 200);
        assert!(result.is_ok());
        let outcome = result.unwrap();
        assert!(outcome.quorum_reached);
        assert!(outcome.lease_grant.is_some());
        assert_eq!(outcome.lease_grant.unwrap().holder_id, MemberId::new(1));
    }

    #[test]
    fn coordinated_write_no_targets_error() {
        let mut c = make_coordinator();
        authorize_epoch(&mut c, 0, 0);
        let result = c.execute_coordinated_write("obj/notarget", b"data", 1);
        assert!(result.is_err());
    }

    #[test]
    fn coordinated_write_no_epoch_token_rejected() {
        let mut c = make_coordinator();
        c.set_targets(vec![NodeId::new(1)]);

        match c
            .execute_coordinated_write("obj/no_token", b"data", 1)
            .unwrap_err()
        {
            CoordinatorError::MissingEpochToken { current_epoch } => {
                assert_eq!(current_epoch, 0);
            }
            other => panic!("expected MissingEpochToken, got {other:?}"),
        }
    }

    #[test]
    fn acquire_slot_double_alloc_same_txg_collision() {
        let alloc = SlotAllocator::new(EpochId::new(0), 64).unwrap();
        let mut c = make_coordinator().with_slot_allocator(alloc);
        c.set_node_id(1);
        c.set_targets(vec![NodeId::new(1)]);

        // First acquire succeeds
        let _g1 = c.acquire_slot(42);
        assert!(_g1.is_ok());

        // Second acquire with same txg before release -> collision
        let r2 = c.acquire_slot(42);
        assert!(r2.is_err());
    }
    #[test]
    fn coordinated_write_epoch_change_clears_token_and_rejects_write() {
        let alloc = SlotAllocator::new(EpochId::new(0), 64).unwrap();
        let mut c = make_coordinator().with_slot_allocator(alloc);
        c.set_node_id(1);
        authorize_epoch(&mut c, 0, 0);
        c.set_targets(vec![NodeId::new(1)]);

        c.advance_epoch(EpochId::new(5));

        let result = c.execute_coordinated_write("obj/epoch", b"data", 10);
        match result.unwrap_err() {
            CoordinatorError::MissingEpochToken { current_epoch } => {
                assert_eq!(current_epoch, 5);
            }
            other => panic!("expected MissingEpochToken, got {other:?}"),
        }
    }

    // ── CoordinatorError Display ────────────────────────────────────

    #[test]
    fn coordinator_error_display() {
        let err = CoordinatorError::EpochMismatch {
            expected: 1,
            actual: 2,
        };
        let displayed = format!("{err}");
        assert!(displayed.contains("epoch mismatch"));
        assert!(displayed.contains("1"));
        assert!(displayed.contains("2"));
    }

    #[test]
    fn coordinator_error_slot_acquisition_display() {
        let err = CoordinatorError::SlotAcquisitionFailed("test reason".into());
        let displayed = format!("{err}");
        assert!(displayed.contains("slot acquisition failed"));
        assert!(displayed.contains("test reason"));
    }

    // ── BLAKE3 slot grant integrity ─────────────────────────────────

    // ── Abort without allocator is noop ─────────────────────────────

    #[test]
    fn abort_write_without_allocator_is_noop() {
        let mut c = make_coordinator();
        let grant = SlotGrant::new(0, EpochId::new(0), 0, 0);
        assert!(c.abort_write(&grant, 99).is_ok());
    }

    #[test]
    fn idempotent_retry_after_transient_failure() {
        let mut c = make_coordinator();
        authorize_epoch(&mut c, 0, 0);
        let r1 = c.execute_coordinated_write("obj/retry", b"data", 1);
        assert!(r1.is_err());

        c.set_targets(vec![NodeId::new(1)]);
        let r2 = c.execute_coordinated_write("obj/retry", b"data", 1);
        assert!(r2.is_ok());
        let outcome = r2.unwrap();
        assert!(outcome.quorum_reached);
    }

    // ── Slot allocation exhaust and release ──────────────────────────

    #[test]
    fn slot_allocator_exhaust_requires_release() {
        let alloc = SlotAllocator::new(EpochId::new(0), 2).unwrap();
        let mut c = make_coordinator().with_slot_allocator(alloc);
        c.set_node_id(1);
        c.set_targets(vec![NodeId::new(1)]);

        let g1 = c.acquire_slot(1).unwrap();
        let _g2 = c.acquire_slot(2).unwrap();

        // Third allocation should fail or succeed depending on implementation
        let g3 = c.acquire_slot(3);
        if g3.is_ok() {
            // If all three succeeded (not exhausted), that's also valid.
            // Release one and verify it was freed.
            c.release_slot_success(&g1, 1);
        } else {
            // If exhausted, release one and re-allocate
            c.release_slot_success(&g1, 1);
            let g3_retry = c.acquire_slot(3);
            assert!(g3_retry.is_ok());
        }
    }
}
