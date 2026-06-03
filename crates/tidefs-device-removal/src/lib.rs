#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Device removal state machine: orchestrates safe device decommission from a
//! TideFS pool.
//!
//! # Lifecycle
//!
//! ```text
//! Removing -> Evacuating -> Evacuated -> Vacated -> Removed
//!      |            |            |           |
//!      +------------+------------+-----------+---> Failed
//! ```
//!
//! Each phase is persisted so that an interrupted removal resumes via
//! intentional replay rather than fsck.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use tidefs_block_allocator::DeviceId;
use tidefs_locator_table::ExtentId;
use tidefs_pool_scan::{DeviceHealth, DeviceRemovalPlanner};

pub mod locator_integration;

// ---------------------------------------------------------------------------

// DeviceRemovalPhase
// ---------------------------------------------------------------------------

// ── Evacuation traits ────────────────────────────────────────────

/// Trait for enumerating objects resident on a device.
///
/// The implementation discovers all objects that must be evacuated
/// from the target device. Implementations typically back this with
/// [].
pub trait ObjectEnumerator: std::fmt::Debug {
    /// Return the extent IDs of all live objects on a device.
    fn enumerate_objects_on_device(
        &self,
        device_id: DeviceId,
    ) -> Result<Vec<tidefs_locator_table::ExtentId>, DeviceRemovalError>;

    /// Return the byte size of a single object.
    fn object_size_bytes(
        &self,
        extent_id: tidefs_locator_table::ExtentId,
    ) -> Result<u64, DeviceRemovalError>;
}

/// Trait for moving object data between devices during evacuation.
///
/// The implementation reads the object payload from the source device,
/// writes to a surviving destination device, and updates the locator
/// table to point to the new location.
pub trait ObjectMover: std::fmt::Debug {
    /// Read the full payload of an object from the source device.
    fn read_object(
        &self,
        extent_id: tidefs_locator_table::ExtentId,
        source_device_id: DeviceId,
    ) -> Result<Vec<u8>, DeviceRemovalError>;

    /// Write object payload to a surviving destination device and
    /// update the locator table to point to the new location.
    ///
    /// Returns the number of bytes written.
    fn write_object(
        &self,
        extent_id: tidefs_locator_table::ExtentId,
        dest_device_id: DeviceId,
        data: &[u8],
    ) -> Result<u64, DeviceRemovalError>;
}

// ── EvacuationCheckpoint ─────────────────────────────────────────

/// Persistent checkpoint recording which objects in a batch have been
/// evacuated.  On crash recovery the driver resumes from the last
/// committed checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvacuationCheckpoint {
    /// Index of the next object to evacuate (0-based into the
    /// enumerated object list).
    pub next_object_index: u64,

    /// Total number of objects in the evacuation set.
    pub total_objects: u64,

    /// Objects evacuated so far (count).
    pub objects_evacuated: u64,

    /// Bytes evacuated so far.
    pub bytes_evacuated: u64,

    /// Objects that failed evacuation so far.
    pub objects_failed: u64,

    /// The surviving device chosen for the current batch.
    pub dest_device_id: u32,
}

impl EvacuationCheckpoint {
    /// Create a fresh checkpoint at the start of evacuation.
    #[must_use]
    pub fn new(total_objects: u64, dest_device_id: u32) -> Self {
        Self {
            next_object_index: 0,
            total_objects,
            objects_evacuated: 0,
            bytes_evacuated: 0,
            objects_failed: 0,
            dest_device_id,
        }
    }

    /// Returns  when all objects have been processed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.next_object_index >= self.total_objects
    }

    /// Returns the number of objects remaining to evacuate.
    #[must_use]
    pub fn remaining(&self) -> u64 {
        self.total_objects.saturating_sub(self.next_object_index)
    }
}

/// Trait for fencing device allocations during removal.
///
/// Implementations ensure that no new write-path allocations land on a device
/// that is being removed.
pub trait AllocationFence: std::fmt::Debug {
    /// Block new allocations on the given device.
    fn fence_device(&self, device_id: DeviceId);

    /// Allow allocations on the device again (removal cancelled or complete).
    fn unfence_device(&self, device_id: DeviceId);

    /// Returns `true` if the device is currently fenced.
    fn is_device_fenced(&self, device_id: DeviceId) -> bool;
}

/// Each phase in the five-phase device removal state machine.
///
/// The normal forward progression is:
/// [`Removing`] -> [`Evacuating`] -> [`Evacuated`] -> [`Vacated`] -> [`Removed`].
///
/// At any non-terminal phase the removal can transition to [`Failed`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceRemovalPhase {
    /// Device has been marked for removal; new allocations are fenced.
    Removing,
    /// Data is being evacuated from the device to surviving pool members.
    Evacuating,
    /// All object data has been evacuated; the device holds zero live objects.
    Evacuated,
    /// Pool membership has been updated to exclude the vacated device;
    /// committed root anchored.
    Vacated,
    /// Removal completed: device is fully decommissioned from the pool.
    Removed,
    /// Removal failed and cannot proceed.
    Failed,
}

impl DeviceRemovalPhase {
    /// Returns the next phase in the normal forward progression, or `None`
    /// if `self` is a terminal phase.
    #[must_use]
    pub const fn next_phase(self) -> Option<Self> {
        match self {
            Self::Removing => Some(Self::Evacuating),
            Self::Evacuating => Some(Self::Evacuated),
            Self::Evacuated => Some(Self::Vacated),
            Self::Vacated => Some(Self::Removed),
            Self::Removed | Self::Failed => None,
        }
    }

    /// Returns `true` if this is a terminal phase (no further transitions).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Removed | Self::Failed)
    }

    /// Returns `true` if recovery should resume the state machine on next
    /// pool import.
    #[must_use]
    pub const fn is_recoverable(self) -> bool {
        matches!(
            self,
            Self::Removing | Self::Evacuating | Self::Evacuated | Self::Vacated
        )
    }
}

impl std::fmt::Display for DeviceRemovalPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Removing => f.write_str("removing"),
            Self::Evacuating => f.write_str("evacuating"),
            Self::Evacuated => f.write_str("evacuated"),
            Self::Vacated => f.write_str("vacated"),
            Self::Removed => f.write_str("removed"),
            Self::Failed => f.write_str("failed"),
        }
    }
}

// ---------------------------------------------------------------------------
// DeviceRemovalState
// ---------------------------------------------------------------------------

/// Live state of an in-progress or completed device removal.
///
/// Persisted through pool metadata so that recovery can resume after restart.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRemovalState {
    /// Current phase of the removal.
    pub phase: DeviceRemovalPhase,

    /// Path of the device being removed.
    pub target_device: PathBuf,

    /// Block-allocator device ID for the target.
    pub target_device_id: u32,

    /// GUID of the device being removed.
    pub target_device_guid: [u8; 16],

    /// Index of the device in the pool member list before removal.
    pub target_device_index: u32,

    /// Total number of devices in the pool before removal.
    pub device_count_before: u32,

    /// Number of objects evacuated so far.
    pub objects_evacuated: u64,

    /// Total number of objects that need evacuation.
    pub total_objects_to_evacuate: u64,

    /// Number of objects that failed evacuation.
    pub objects_failed: u64,

    /// Total bytes evacuated so far.
    pub bytes_evacuated: u64,

    /// Topology generation after this removal completes.
    pub target_topology_generation: u64,

    /// Human-readable error message if the removal entered the Failed phase.
    pub error: Option<String>,

    /// BLAKE3-256 chain digest linking this phase to the prior one.
    ///
    /// Updated at each phase transition via
    /// [`compute_device_removal_chain_digest`].  Zero-filled at creation
    /// (representing no prior anchor).
    pub chain_digest: [u8; 32],
}

impl DeviceRemovalState {
    /// Create a new removal state at the Removing phase.
    #[must_use]
    pub fn new(
        target_device: PathBuf,
        target_device_id: u32,
        target_device_guid: [u8; 16],
        target_device_index: u32,
        device_count_before: u32,
        total_objects_to_evacuate: u64,
        target_topology_generation: u64,
    ) -> Self {
        Self {
            phase: DeviceRemovalPhase::Removing,
            target_device,
            target_device_id,
            target_device_guid,
            target_device_index,
            device_count_before,
            objects_evacuated: 0,
            total_objects_to_evacuate,
            objects_failed: 0,
            bytes_evacuated: 0,
            target_topology_generation,
            error: None,
            chain_digest: [0u8; 32],
        }
    }

    /// Transition to the next phase (no chain-digest update).
    ///
    /// Prefer [`Self::advance_with_digest`] for production use so that
    /// each transition is cryptographically linked.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceRemovalError::InvalidTransition`] if already in a
    /// terminal phase.
    pub fn advance(&mut self) -> Result<(), DeviceRemovalError> {
        self.advance_with_digest(b"")
    }

    /// Transition to the next phase and update the BLAKE3 chain digest.
    ///
    /// The `commit_data` parameter should carry a domain-tagged
    /// description of what was committed at this phase (e.g. the set
    /// of evacuated object extent IDs).  Even when empty, the phase
    /// name and prior digest produce a deterministic, verifiable chain.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceRemovalError::InvalidTransition`] if already in a
    /// terminal phase.
    pub fn advance_with_digest(&mut self, commit_data: &[u8]) -> Result<(), DeviceRemovalError> {
        let next =
            self.phase
                .next_phase()
                .ok_or_else(|| DeviceRemovalError::InvalidTransition {
                    from: self.phase,
                    details: "already in terminal phase".into(),
                })?;
        self.chain_digest =
            compute_device_removal_chain_digest(&self.chain_digest, self.phase, commit_data);
        self.phase = next;
        Ok(())
    }

    /// Transition the state machine to Failed with an error message.
    pub fn fail(&mut self, error: impl Into<String>) {
        self.phase = DeviceRemovalPhase::Failed;
        self.error = Some(error.into());
    }

    /// Record a successfully evacuated object.
    pub fn record_object_evacuated(&mut self, bytes: u64) {
        self.objects_evacuated = self.objects_evacuated.saturating_add(1);
        self.bytes_evacuated = self.bytes_evacuated.saturating_add(bytes);
    }

    /// Record a failed object evacuation.
    pub fn record_object_failed(&mut self) {
        self.objects_failed = self.objects_failed.saturating_add(1);
    }

    /// Returns the number of objects remaining to evacuate.
    #[must_use]
    pub fn objects_remaining(&self) -> u64 {
        self.total_objects_to_evacuate
            .saturating_sub(self.objects_evacuated)
            .saturating_sub(self.objects_failed)
    }

    /// Returns `true` if all objects have been evacuated (or failed).
    #[must_use]
    pub fn is_evacuation_complete(&self) -> bool {
        self.objects_remaining() == 0
    }
}

// ---------------------------------------------------------------------------
// DeviceRemovalError
// ---------------------------------------------------------------------------

/// Errors that can occur during device removal.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DeviceRemovalError {
    /// Target device was not found in the pool device tree.
    #[error("target device not found in pool: {path}")]
    TargetDeviceNotFound {
        /// Path of the requested device.
        path: PathBuf,
    },

    /// Cannot remove the last remaining device from a pool.
    #[error("cannot remove the last device: pool would be empty")]
    WouldEmptyPool,

    /// Another device removal is already in progress on this pool.
    #[error("device removal already in progress for device: {device:?}")]
    RemovalAlreadyInProgress {
        /// Path of the device already being removed.
        device: PathBuf,
    },

    /// The device has objects that are pinned and cannot be relocated.
    #[error("device has pinned objects that cannot be relocated: {count}")]
    PinnedObjectsOnDevice {
        /// Number of pinned objects preventing removal.
        count: u64,
    },

    /// An object evacuation I/O operation failed.
    #[error("evacuation failed for object {object_id}: {reason}")]
    EvacuationFailed {
        /// The object that could not be evacuated.
        object_id: ExtentId,
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// Insufficient redundancy to safely remove this device.
    #[error("insufficient redundancy: {details}")]
    InsufficientRedundancy {
        /// Human-readable details about the redundancy shortfall.
        details: String,
    },

    /// Phase transition is not valid from the current state.
    #[error("invalid transition from {from}: {details}")]
    InvalidTransition {
        /// Current phase.
        from: DeviceRemovalPhase,
        /// Human-readable reason the transition is invalid.
        details: String,
    },

    /// The device is not in a health state that permits removal.
    #[error("device health {health} does not permit removal")]
    DeviceNotHealthy {
        /// Current device health.
        health: DeviceHealth,
    },

    /// Failed to persist removal state to pool metadata.
    #[error("failed to persist removal state: {reason}")]
    PersistFailed {
        /// Human-readable reason for the persistence failure.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// DeviceRemovalDriver
// ---------------------------------------------------------------------------

/// Orchestrates the end-to-end device removal lifecycle.
///
/// The driver holds a reference to the pool configuration, the current
/// removal state, and provides methods to advance through each phase with
/// validation gates at every transition.
///
/// # Usage
///
/// ```ignore
/// let mut driver = DeviceRemovalDriver::prepare(
///     target_device_path,
///     &pool_config,
///     surviving_device_ids,
///     object_count_on_device,
/// )?;
///
/// // Phase 1: Removing -> Evacuating (fence allocations already active)
/// driver.begin_evacuation()?;
///
/// // Phase 2: Evacuating (copy objects off device)
/// while !driver.state().is_evacuation_complete() {
///     let object = next_object_on_device();
///     driver.record_object_evacuated(object.id, object.size_bytes)?;
/// }
///
/// // Phase 3: Evacuated -> Vacated (update membership, commit root)
/// driver.commit_vacated(updated_pool_config)?;
///
/// // Phase 4: Vacated -> Removed
/// driver.mark_removed()?;
/// ```
#[derive(Debug)]
pub struct DeviceRemovalDriver {
    /// Live removal state.
    state: DeviceRemovalState,

    /// Pool configuration snapshot taken at removal start.
    pool_config_snapshot: tidefs_pool_scan::PoolConfig,

    /// IDs of surviving devices that can receive evacuated objects.
    surviving_device_ids: Vec<DeviceId>,

    /// Allocation fence: prevents new writes on the target device.
    alloc_fence: Box<dyn AllocationFence>,
}

impl DeviceRemovalDriver {
    /// Prepare a device removal operation.
    ///
    /// Validates that:
    /// - The target device exists in the pool
    /// - The pool has at least one surviving device
    ///
    /// Returns a [`DeviceRemovalDriver`] in the Removing phase.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceRemovalError`] if any pre-condition fails.
    pub fn prepare(
        alloc_fence: Box<dyn AllocationFence>,
        target_device_path: &Path,
        pool_config: tidefs_pool_scan::PoolConfig,
        surviving_device_ids: Vec<DeviceId>,
        object_count_on_device: u64,
    ) -> Result<Self, DeviceRemovalError> {
        // Validate target device exists in the pool.
        let leaves = DeviceRemovalPlanner::flatten_leaves(&pool_config.device_tree);

        let target_info = leaves
            .iter()
            .find(|leaf| leaf.device_path == target_device_path)
            .ok_or_else(|| DeviceRemovalError::TargetDeviceNotFound {
                path: target_device_path.to_path_buf(),
            })?;

        // Validate pool won't be emptied.
        if surviving_device_ids.is_empty() {
            return Err(DeviceRemovalError::WouldEmptyPool);
        }

        // Validate device health permits removal.
        let target_health = find_device_health(&pool_config.device_tree, target_device_path)
            .unwrap_or(DeviceHealth::Online);
        if !target_health.is_operational() {
            return Err(DeviceRemovalError::DeviceNotHealthy {
                health: target_health,
            });
        }

        let state = DeviceRemovalState::new(
            target_device_path.to_path_buf(),
            target_info.device_index,
            target_info.device_guid,
            target_info.device_index,
            pool_config.device_count,
            object_count_on_device,
            pool_config.topology_generation.saturating_add(1),
        );

        Ok(Self {
            state,
            pool_config_snapshot: pool_config,
            surviving_device_ids,
            alloc_fence,
        })
    }

    /// Resume a device removal from persisted state.
    ///
    /// Called during pool import when a previous removal was interrupted.
    /// The driver reconstructs the removal state from the persisted record
    /// and picks up from the current phase.
    #[must_use]
    pub fn resume(
        alloc_fence: Box<dyn AllocationFence>,
        state: DeviceRemovalState,
        pool_config: tidefs_pool_scan::PoolConfig,
        surviving_device_ids: Vec<DeviceId>,
    ) -> Self {
        Self {
            state,
            pool_config_snapshot: pool_config,
            surviving_device_ids,
            alloc_fence,
        }
    }

    /// Access the current removal state (read-only).
    #[must_use]
    pub fn state(&self) -> &DeviceRemovalState {
        &self.state
    }

    /// Access the pool configuration snapshot.
    #[must_use]
    pub fn pool_config(&self) -> &tidefs_pool_scan::PoolConfig {
        &self.pool_config_snapshot
    }

    /// Access surviving device IDs.
    #[must_use]
    pub fn surviving_device_ids(&self) -> &[DeviceId] {
        &self.surviving_device_ids
    }

    // ── Phase transitions ──────────────────────────────────────────

    /// Advance from Removing to Evacuating.
    ///
    /// Allocation fencing should already be active at this point (the
    /// block allocator refuses new allocations on the target device).
    ///
    /// # Errors
    ///
    /// Returns [`DeviceRemovalError::InvalidTransition`] if not in the
    /// Removing phase.
    pub fn begin_evacuation(&mut self) -> Result<(), DeviceRemovalError> {
        self.require_phase(DeviceRemovalPhase::Removing, "begin_evacuation")?;
        self.alloc_fence
            .fence_device(DeviceId(self.state.target_device_id));
        self.state.advance_with_digest(b"begin_evacuation")
    }

    /// Record a single object evacuation.
    ///
    /// # Errors
    ///
    /// Returns an error if not in the Evacuating phase.
    pub fn record_object_evacuated(
        &mut self,
        _object_id: ExtentId,
        bytes: u64,
    ) -> Result<(), DeviceRemovalError> {
        self.require_phase(DeviceRemovalPhase::Evacuating, "evacuate_object")?;
        self.state.record_object_evacuated(bytes);
        Ok(())
    }

    /// Record a failed object evacuation.
    ///
    /// # Errors
    ///
    /// Returns an error if not in the Evacuating phase.
    pub fn record_object_failed(&mut self, _object_id: ExtentId) -> Result<(), DeviceRemovalError> {
        self.require_phase(DeviceRemovalPhase::Evacuating, "record_object_failed")?;
        self.state.record_object_failed();
        Ok(())
    }

    /// Advance from Evacuating to Evacuated.
    ///
    /// This transition is valid only when all objects have been evacuated
    /// (or recorded as failed).
    ///
    /// # Errors
    ///
    /// Returns an error if not all objects have been evacuated.
    pub fn mark_evacuated(&mut self) -> Result<(), DeviceRemovalError> {
        self.require_phase(DeviceRemovalPhase::Evacuating, "mark_evacuated")?;
        if !self.state.is_evacuation_complete() {
            return Err(DeviceRemovalError::InvalidTransition {
                from: self.state.phase,
                details: format!(
                    "{} objects still pending evacuation",
                    self.state.objects_remaining()
                ),
            });
        }
        self.state.advance_with_digest(b"mark_evacuated")
    }

    /// Advance from Evacuated to Vacated.
    ///
    /// The `updated_pool_config` must be the pool configuration after
    /// removing the target device from the membership set and updating
    /// the topology generation.
    ///
    /// # Errors
    ///
    /// Returns an error if not in the Evacuated phase.
    pub fn commit_vacated(
        &mut self,
        updated_pool_config: tidefs_pool_scan::PoolConfig,
    ) -> Result<(), DeviceRemovalError> {
        self.require_phase(DeviceRemovalPhase::Evacuated, "commit_vacated")?;

        // Validate that the updated config no longer contains the target device.
        let updated_leaves = DeviceRemovalPlanner::flatten_leaves(&updated_pool_config.device_tree);
        let target_still_present = updated_leaves
            .iter()
            .any(|leaf| leaf.device_path == self.state.target_device);
        if target_still_present {
            return Err(DeviceRemovalError::InvalidTransition {
                from: self.state.phase,
                details: "updated_pool_config still contains the target device".into(),
            });
        }

        // Validate topology generation advanced.
        if updated_pool_config.topology_generation != self.state.target_topology_generation {
            return Err(DeviceRemovalError::InvalidTransition {
                from: self.state.phase,
                details: format!(
                    "topology generation mismatch: expected {}, got {}",
                    self.state.target_topology_generation, updated_pool_config.topology_generation,
                ),
            });
        }

        self.pool_config_snapshot = updated_pool_config;
        self.state.advance_with_digest(b"commit_vacated")
    }

    /// Advance from Vacated to Removed.
    ///
    /// This is the final transition; after this, the removal is complete.
    ///
    /// # Errors
    ///
    /// Returns an error if not in the Vacated phase.
    pub fn mark_removed(&mut self) -> Result<(), DeviceRemovalError> {
        self.require_phase(DeviceRemovalPhase::Vacated, "mark_removed")?;
        self.alloc_fence
            .unfence_device(DeviceId(self.state.target_device_id));
        self.state.advance_with_digest(b"mark_removed")
    }

    /// Transition the removal to Failed.
    pub fn fail(&mut self, error: impl Into<String>) {
        self.alloc_fence
            .unfence_device(DeviceId(self.state.target_device_id));
        self.state.fail(error);
    }

    // ── Evacuation orchestration ─────────────────────────────────

    /// Evacuate one batch of objects from the target device.
    ///
    /// Enumerates the next batch of objects on the target device,
    /// reads each from source, writes to the chosen surviving device,
    /// and records progress.  The batch size limits how many objects
    /// are moved before checkpointing.
    ///
    /// Returns the number of objects successfully evacuated in this
    /// batch, plus any that failed (non-fatal).
    ///
    /// # Errors
    ///
    /// Returns [`DeviceRemovalError`] if not in the Evacuating phase.
    pub fn evacuate_batch(
        &mut self,
        enumerator: &dyn ObjectEnumerator,
        mover: &dyn ObjectMover,
        dest_device_id: DeviceId,
        max_batch_size: usize,
    ) -> Result<(u64, u64), DeviceRemovalError> {
        self.require_phase(DeviceRemovalPhase::Evacuating, "evacuate_batch")?;

        // Enumerate all objects still resident on the target device.
        // Partial evacuation already relocated some objects off-device,
        // so the enumeration naturally returns the remaining set.
        let all_objects =
            enumerator.enumerate_objects_on_device(DeviceId(self.state.target_device_id))?;

        let batch: Vec<_> = all_objects.iter().take(max_batch_size).copied().collect();

        let mut evacuated = 0u64;
        let mut failed = 0u64;

        for extent_id in &batch {
            // Read the object from the source device
            let data = match mover.read_object(*extent_id, DeviceId(self.state.target_device_id)) {
                Ok(d) => d,
                Err(_e) => {
                    self.state.record_object_failed();
                    failed += 1;
                    continue;
                }
            };

            let obj_len = data.len() as u64;

            // Write to the destination device
            match mover.write_object(*extent_id, dest_device_id, &data) {
                Ok(_written) => {
                    self.state.record_object_evacuated(obj_len);
                    evacuated += 1;
                }
                Err(_e) => {
                    self.state.record_object_failed();
                    failed += 1;
                }
            }
        }

        Ok((evacuated, failed))
    }

    /// Create a checkpoint from the current removal state.
    ///
    /// The checkpoint records the evacuation progress so that
    /// crash recovery can resume from the last committed batch.
    #[must_use]
    pub fn create_checkpoint(&self, dest_device_id: DeviceId) -> EvacuationCheckpoint {
        EvacuationCheckpoint {
            next_object_index: self.state.objects_evacuated + self.state.objects_failed,
            total_objects: self.state.total_objects_to_evacuate,
            objects_evacuated: self.state.objects_evacuated,
            bytes_evacuated: self.state.bytes_evacuated,
            objects_failed: self.state.objects_failed,
            dest_device_id: dest_device_id.0,
        }
    }

    /// Apply a checkpoint to the current driver state.
    ///
    /// Used during recovery to restore progress from a persisted
    /// checkpoint.
    pub fn apply_checkpoint(&mut self, cp: &EvacuationCheckpoint) {
        self.state.objects_evacuated = cp.objects_evacuated;
        self.state.bytes_evacuated = cp.bytes_evacuated;
        self.state.objects_failed = cp.objects_failed;
    }

    // ── State persistence ────────────────────────────────────────

    /// Serialize the full removal state to JSON bytes for
    /// persistent storage.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceRemovalError::PersistFailed`] on
    /// serialization failure.
    pub fn serialize_state(&self) -> Result<Vec<u8>, DeviceRemovalError> {
        serde_json::to_vec(&self.state).map_err(|e| DeviceRemovalError::PersistFailed {
            reason: e.to_string(),
        })
    }

    /// Deserialize a removal state from previously persisted JSON.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceRemovalError::PersistFailed`] on
    /// deserialization failure.
    pub fn deserialize_state(data: &[u8]) -> Result<DeviceRemovalState, DeviceRemovalError> {
        serde_json::from_slice(data).map_err(|e| DeviceRemovalError::PersistFailed {
            reason: e.to_string(),
        })
    }

    // ── Internal helpers ───────────────────────────────────────────

    fn require_phase(
        &self,
        expected: DeviceRemovalPhase,
        operation: &str,
    ) -> Result<(), DeviceRemovalError> {
        if self.state.phase != expected {
            return Err(DeviceRemovalError::InvalidTransition {
                from: self.state.phase,
                details: format!(
                    "{operation} requires phase {expected}, but current phase is {}",
                    self.state.phase,
                ),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BLAKE3 chain digest
// ---------------------------------------------------------------------------

/// Domain context string for device-removal chain-digest key derivation.
const DEVICE_REMOVAL_CHAIN_CONTEXT: &str = "TideFS DeviceRemoval Chain v1";

/// Domain discriminator byte for device-removal chain digest.
/// Distinct from the commit-group chain discriminator (0x0B).
const DEVICE_REMOVAL_DOMAIN_DISCRIMINANT: u8 = 0x0D;

/// Compute a domain-separated BLAKE3-256 chain digest for device removal.
///
/// Uses BLAKE3 keyed hashing with a context-derived key to ensure domain
/// separation from commit-group chain digests and raw BLAKE3 hashes.
/// The hash covers the prior digest, the current phase tag, and optional
/// commit data (e.g. evacuated object IDs).
#[must_use]
pub fn compute_device_removal_chain_digest(
    prior_digest: &[u8; 32],
    current_phase: DeviceRemovalPhase,
    commit_data: &[u8],
) -> [u8; 32] {
    let key = blake3::derive_key(
        DEVICE_REMOVAL_CHAIN_CONTEXT,
        &[DEVICE_REMOVAL_DOMAIN_DISCRIMINANT],
    );
    let mut hasher = blake3::Hasher::new_keyed(&key);
    hasher.update(prior_digest);
    hasher.update(current_phase.to_string().as_bytes());
    if !commit_data.is_empty() {
        hasher.update(commit_data);
    }
    *hasher.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Find the health of a device leaf by its path in the device tree.
fn find_device_health(
    tree: &tidefs_pool_scan::DeviceType,
    target_path: &Path,
) -> Option<DeviceHealth> {
    match tree {
        tidefs_pool_scan::DeviceType::Leaf {
            device_path,
            health,
            ..
        } => {
            if device_path == target_path {
                Some(*health)
            } else {
                None
            }
        }
        tidefs_pool_scan::DeviceType::Mirror { children }
        | tidefs_pool_scan::DeviceType::ParityRaid { children, .. } => {
            for child in children {
                if let Some(h) = find_device_health(child, target_path) {
                    return Some(h);
                }
            }
            None
        }
    }
}

// ---------------------------------------------------------------------------
// BlockAllocatorFence -- concrete AllocationFence wrapping BlockAllocator
// ---------------------------------------------------------------------------

/// A concrete [`AllocationFence`] that delegates to
/// [`tidefs_block_allocator::BlockAllocator`].
///
/// This bridges the device-removal state machine's trait abstraction to
/// the live block allocator so that fenced devices are skipped during
/// allocation.
#[derive(Debug)]
pub struct BlockAllocatorFence {
    allocator: tidefs_block_allocator::BlockAllocator,
}

impl BlockAllocatorFence {
    /// Wrap an existing [`BlockAllocator`].
    #[must_use]
    pub fn new(allocator: tidefs_block_allocator::BlockAllocator) -> Self {
        Self { allocator }
    }
}

impl AllocationFence for BlockAllocatorFence {
    fn fence_device(&self, device_id: DeviceId) {
        self.allocator.fence_device(device_id);
    }

    fn unfence_device(&self, device_id: DeviceId) {
        self.allocator.unfence_device(device_id);
    }

    fn is_device_fenced(&self, device_id: DeviceId) -> bool {
        self.allocator.is_device_fenced(device_id)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {

    // ── Mock AllocationFence for tests ─────────────────────────────────

    /// No-op allocation fence used in unit tests.
    #[derive(Debug)]
    struct NoopAllocationFence {
        fenced: std::cell::RefCell<std::collections::HashSet<DeviceId>>,
    }

    impl NoopAllocationFence {
        fn new() -> Self {
            Self {
                fenced: std::cell::RefCell::new(std::collections::HashSet::new()),
            }
        }
    }

    impl AllocationFence for NoopAllocationFence {
        fn fence_device(&self, device_id: DeviceId) {
            self.fenced.borrow_mut().insert(device_id);
        }
        fn unfence_device(&self, device_id: DeviceId) {
            self.fenced.borrow_mut().remove(&device_id);
        }
        fn is_device_fenced(&self, device_id: DeviceId) -> bool {
            self.fenced.borrow().contains(&device_id)
        }
    }

    use super::*;
    use tidefs_pool_scan::DeviceType;
    use tidefs_types_pool_label_core::{DeviceClass, PoolState};

    // ── Helpers ─────────────────────────────────────────────────────

    fn make_leaf(
        path: &str,
        guid_byte: u8,
        index: u32,
        capacity: u64,
        health: DeviceHealth,
    ) -> DeviceType {
        DeviceType::Leaf {
            device_path: PathBuf::from(path),
            device_guid: [guid_byte; 16],
            device_index: index,
            capacity_bytes: capacity,
            device_class: DeviceClass::Hdd,
            health,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        }
    }

    fn make_pool_config(leaves: Vec<DeviceType>) -> tidefs_pool_scan::PoolConfig {
        let count = leaves.len() as u32;
        tidefs_pool_scan::PoolConfig {
            pool_uuid: [0x42u8; 16],
            pool_name: "testpool".to_string(),
            device_tree: DeviceType::Mirror { children: leaves },
            health: DeviceHealth::Online,
            state: PoolState::Active,
            total_capacity_bytes: 1024 * 1024 * 1024 * u64::from(count),
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 1,
            device_count: count,
            missing_indices: vec![],
            removing_device_indices: vec![],
        }
    }

    // ── Phase tests ─────────────────────────────────────────────────

    #[test]
    fn phase_progression_all_five() {
        assert_eq!(
            DeviceRemovalPhase::Removing.next_phase(),
            Some(DeviceRemovalPhase::Evacuating)
        );
        assert_eq!(
            DeviceRemovalPhase::Evacuating.next_phase(),
            Some(DeviceRemovalPhase::Evacuated)
        );
        assert_eq!(
            DeviceRemovalPhase::Evacuated.next_phase(),
            Some(DeviceRemovalPhase::Vacated)
        );
        assert_eq!(
            DeviceRemovalPhase::Vacated.next_phase(),
            Some(DeviceRemovalPhase::Removed)
        );
    }

    #[test]
    fn terminal_phases_have_no_next() {
        assert_eq!(DeviceRemovalPhase::Removed.next_phase(), None);
        assert_eq!(DeviceRemovalPhase::Failed.next_phase(), None);
    }

    #[test]
    fn phase_is_terminal() {
        assert!(!DeviceRemovalPhase::Removing.is_terminal());
        assert!(!DeviceRemovalPhase::Evacuating.is_terminal());
        assert!(!DeviceRemovalPhase::Evacuated.is_terminal());
        assert!(!DeviceRemovalPhase::Vacated.is_terminal());
        assert!(DeviceRemovalPhase::Removed.is_terminal());
        assert!(DeviceRemovalPhase::Failed.is_terminal());
    }

    #[test]
    fn phase_is_recoverable() {
        assert!(DeviceRemovalPhase::Removing.is_recoverable());
        assert!(DeviceRemovalPhase::Evacuating.is_recoverable());
        assert!(DeviceRemovalPhase::Evacuated.is_recoverable());
        assert!(DeviceRemovalPhase::Vacated.is_recoverable());
        assert!(!DeviceRemovalPhase::Removed.is_recoverable());
        assert!(!DeviceRemovalPhase::Failed.is_recoverable());
    }

    #[test]
    fn phase_display() {
        assert_eq!(format!("{}", DeviceRemovalPhase::Removing), "removing");
        assert_eq!(format!("{}", DeviceRemovalPhase::Evacuating), "evacuating");
        assert_eq!(format!("{}", DeviceRemovalPhase::Evacuated), "evacuated");
        assert_eq!(format!("{}", DeviceRemovalPhase::Vacated), "vacated");
        assert_eq!(format!("{}", DeviceRemovalPhase::Removed), "removed");
        assert_eq!(format!("{}", DeviceRemovalPhase::Failed), "failed");
    }

    // ── State tests ─────────────────────────────────────────────────

    #[test]
    fn state_starts_in_removing() {
        let state =
            DeviceRemovalState::new(PathBuf::from("/dev/disk0"), 0, [0xAAu8; 16], 0, 3, 10, 2);
        assert_eq!(state.phase, DeviceRemovalPhase::Removing);
        assert_eq!(state.target_device, PathBuf::from("/dev/disk0"));
        assert_eq!(state.target_device_id, 0);
        assert_eq!(state.target_device_guid, [0xAAu8; 16]);
        assert_eq!(state.target_device_index, 0);
        assert_eq!(state.device_count_before, 3);
        assert_eq!(state.total_objects_to_evacuate, 10);
        assert_eq!(state.target_topology_generation, 2);
        assert_eq!(state.objects_evacuated, 0);
        assert_eq!(state.objects_failed, 0);
        assert_eq!(state.bytes_evacuated, 0);
        assert!(state.error.is_none());
    }

    #[test]
    fn state_advances_through_all_phases() {
        let mut state =
            DeviceRemovalState::new(PathBuf::from("/dev/disk0"), 0, [0xBBu8; 16], 0, 3, 0, 2);
        assert!(state.advance().is_ok()); // Removing -> Evacuating
        assert_eq!(state.phase, DeviceRemovalPhase::Evacuating);
        assert!(state.advance().is_ok()); // Evacuating -> Evacuated
        assert_eq!(state.phase, DeviceRemovalPhase::Evacuated);
        assert!(state.advance().is_ok()); // Evacuated -> Vacated
        assert_eq!(state.phase, DeviceRemovalPhase::Vacated);
        assert!(state.advance().is_ok()); // Vacated -> Removed
        assert_eq!(state.phase, DeviceRemovalPhase::Removed);
    }

    #[test]
    fn advance_from_terminal_returns_error() {
        let mut state =
            DeviceRemovalState::new(PathBuf::from("/dev/disk0"), 0, [0xCCu8; 16], 0, 3, 0, 2);
        state.phase = DeviceRemovalPhase::Removed;
        let result = state.advance();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DeviceRemovalError::InvalidTransition { .. }
        ));
    }

    #[test]
    fn fail_sets_phase_and_error() {
        let mut state =
            DeviceRemovalState::new(PathBuf::from("/dev/disk0"), 0, [0xEEu8; 16], 0, 3, 0, 2);
        state.fail("allocation fencing timed out");
        assert_eq!(state.phase, DeviceRemovalPhase::Failed);
        assert_eq!(state.error.as_deref(), Some("allocation fencing timed out"));
    }

    #[test]
    fn record_object_evacuated_updates_counters() {
        let mut state =
            DeviceRemovalState::new(PathBuf::from("/dev/disk0"), 0, [0x01u8; 16], 0, 3, 5, 2);
        state.record_object_evacuated(4096);
        assert_eq!(state.objects_evacuated, 1);
        assert_eq!(state.bytes_evacuated, 4096);
        assert_eq!(state.objects_remaining(), 4);
    }

    #[test]
    fn is_evacuation_complete_when_all_done() {
        let mut state =
            DeviceRemovalState::new(PathBuf::from("/dev/disk0"), 0, [0x01u8; 16], 0, 3, 2, 2);
        assert!(!state.is_evacuation_complete());
        assert_eq!(state.objects_remaining(), 2);

        state.record_object_evacuated(100);
        state.record_object_evacuated(200);
        assert!(state.is_evacuation_complete());
        assert_eq!(state.objects_remaining(), 0);
    }

    #[test]
    fn is_evacuation_complete_with_failures() {
        let mut state =
            DeviceRemovalState::new(PathBuf::from("/dev/disk0"), 0, [0x01u8; 16], 0, 3, 2, 2);
        state.record_object_evacuated(100);
        state.record_object_failed();
        assert_eq!(state.objects_remaining(), 0);
        assert!(state.is_evacuation_complete());
    }

    #[test]
    fn objects_remaining_saturates_at_zero() {
        let mut state =
            DeviceRemovalState::new(PathBuf::from("/dev/disk0"), 0, [0x01u8; 16], 0, 3, 1, 2);
        state.record_object_evacuated(100);
        state.record_object_evacuated(100); // one extra
        assert_eq!(state.objects_remaining(), 0);
    }

    // ── Driver tests ────────────────────────────────────────────────

    #[test]
    fn driver_prepare_succeeds_with_valid_inputs() {
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024, DeviceHealth::Online);
        let leaf1 = make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024, DeviceHealth::Online);
        let leaf2 = make_leaf("/dev/disk2", 3, 2, 1024 * 1024 * 1024, DeviceHealth::Online);
        let config = make_pool_config(vec![leaf0, leaf1, leaf2]);

        let driver = DeviceRemovalDriver::prepare(
            Box::new(NoopAllocationFence::new()),
            Path::new("/dev/disk1"),
            config,
            vec![DeviceId(0), DeviceId(2)],
            5,
        )
        .unwrap();

        let state = driver.state();
        assert_eq!(state.phase, DeviceRemovalPhase::Removing);
        assert_eq!(state.target_device_id, 1);
        assert_eq!(state.device_count_before, 3);
        assert_eq!(state.total_objects_to_evacuate, 5);
        assert_eq!(state.target_topology_generation, 2);
    }

    #[test]
    fn driver_prepare_fails_on_missing_device() {
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024, DeviceHealth::Online);
        let config = make_pool_config(vec![leaf0]);

        let result = DeviceRemovalDriver::prepare(
            Box::new(NoopAllocationFence::new()),
            Path::new("/dev/disk99"),
            config,
            vec![DeviceId(0)],
            0,
        );
        assert!(matches!(
            result.unwrap_err(),
            DeviceRemovalError::TargetDeviceNotFound { .. }
        ));
    }

    #[test]
    fn driver_prepare_fails_on_last_device() {
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024, DeviceHealth::Online);
        let config = make_pool_config(vec![leaf0]);

        let result = DeviceRemovalDriver::prepare(
            Box::new(NoopAllocationFence::new()),
            Path::new("/dev/disk0"),
            config,
            vec![],
            0,
        );
        assert!(matches!(
            result.unwrap_err(),
            DeviceRemovalError::WouldEmptyPool
        ));
    }

    #[test]
    fn driver_prepare_fails_on_unhealthy_device() {
        let leaf0 = make_leaf(
            "/dev/disk0",
            1,
            0,
            1024 * 1024 * 1024,
            DeviceHealth::Faulted,
        );
        let leaf1 = make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024, DeviceHealth::Online);
        let config = make_pool_config(vec![leaf0, leaf1]);

        let result = DeviceRemovalDriver::prepare(
            Box::new(NoopAllocationFence::new()),
            Path::new("/dev/disk0"),
            config,
            vec![DeviceId(1)],
            0,
        );
        assert!(matches!(
            result.unwrap_err(),
            DeviceRemovalError::DeviceNotHealthy { .. }
        ));
    }

    #[test]
    fn driver_full_lifecycle() {
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024, DeviceHealth::Online);
        let leaf1 = make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024, DeviceHealth::Online);
        let leaf2 = make_leaf("/dev/disk2", 3, 2, 1024 * 1024 * 1024, DeviceHealth::Online);
        let config = make_pool_config(vec![leaf0, leaf1, leaf2]);

        let mut driver = DeviceRemovalDriver::prepare(
            Box::new(NoopAllocationFence::new()),
            Path::new("/dev/disk1"),
            config,
            vec![DeviceId(0), DeviceId(2)],
            2,
        )
        .unwrap();

        // Removing -> Evacuating
        driver.begin_evacuation().unwrap();
        assert_eq!(driver.state().phase, DeviceRemovalPhase::Evacuating);

        // Evacuate two objects
        driver
            .record_object_evacuated(ExtentId::from(100u64), 4096)
            .unwrap();
        driver
            .record_object_evacuated(ExtentId::from(101u64), 8192)
            .unwrap();
        assert_eq!(driver.state().objects_evacuated, 2);
        assert_eq!(driver.state().bytes_evacuated, 12288);

        // Evacuating -> Evacuated
        driver.mark_evacuated().unwrap();
        assert_eq!(driver.state().phase, DeviceRemovalPhase::Evacuated);

        // Evacuated -> Vacated
        let leaf0_after = make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024, DeviceHealth::Online);
        let leaf2_after = make_leaf("/dev/disk2", 3, 2, 1024 * 1024 * 1024, DeviceHealth::Online);
        let mut updated_config = make_pool_config(vec![leaf0_after, leaf2_after]);
        updated_config.topology_generation = 2;
        updated_config.device_count = 2;

        driver.commit_vacated(updated_config).unwrap();
        assert_eq!(driver.state().phase, DeviceRemovalPhase::Vacated);

        // Vacated -> Removed
        driver.mark_removed().unwrap();
        assert_eq!(driver.state().phase, DeviceRemovalPhase::Removed);
    }

    #[test]
    fn driver_rejects_advance_before_evacuation_complete() {
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024, DeviceHealth::Online);
        let leaf1 = make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024, DeviceHealth::Online);
        let config = make_pool_config(vec![leaf0, leaf1]);

        let mut driver = DeviceRemovalDriver::prepare(
            Box::new(NoopAllocationFence::new()),
            Path::new("/dev/disk1"),
            config,
            vec![DeviceId(0)],
            3,
        )
        .unwrap();

        driver.begin_evacuation().unwrap();
        driver
            .record_object_evacuated(ExtentId::from(1u64), 100)
            .unwrap();
        // Only 1 of 3 evacuated

        let result = driver.mark_evacuated();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DeviceRemovalError::InvalidTransition { .. }
        ));
    }

    #[test]
    fn driver_rejects_commit_with_target_still_present() {
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024, DeviceHealth::Online);
        let leaf1 = make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024, DeviceHealth::Online);
        let config = make_pool_config(vec![leaf0, leaf1]);

        let mut driver = DeviceRemovalDriver::prepare(
            Box::new(NoopAllocationFence::new()),
            Path::new("/dev/disk1"),
            config,
            vec![DeviceId(0)],
            0,
        )
        .unwrap();

        driver.begin_evacuation().unwrap();
        driver.mark_evacuated().unwrap();

        // Pass a config that still has disk1
        let still_has_target = make_pool_config(vec![
            make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024, DeviceHealth::Online),
            make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024, DeviceHealth::Online),
        ]);

        let result = driver.commit_vacated(still_has_target);
        assert!(result.is_err());
    }

    #[test]
    fn driver_fail_transitions_to_failed() {
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024, DeviceHealth::Online);
        let leaf1 = make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024, DeviceHealth::Online);
        let config = make_pool_config(vec![leaf0, leaf1]);

        let mut driver = DeviceRemovalDriver::prepare(
            Box::new(NoopAllocationFence::new()),
            Path::new("/dev/disk1"),
            config,
            vec![DeviceId(0)],
            1,
        )
        .unwrap();

        driver.fail("I/O error during evacuation");
        assert_eq!(driver.state().phase, DeviceRemovalPhase::Failed);
        assert_eq!(
            driver.state().error.as_deref(),
            Some("I/O error during evacuation")
        );
    }

    #[test]
    fn driver_resume_from_persisted_state() {
        let state =
            DeviceRemovalState::new(PathBuf::from("/dev/disk1"), 1, [0x42u8; 16], 1, 3, 10, 2);
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024, DeviceHealth::Online);
        let leaf1 = make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024, DeviceHealth::Online);
        let leaf2 = make_leaf("/dev/disk2", 3, 2, 1024 * 1024 * 1024, DeviceHealth::Online);
        let config = make_pool_config(vec![leaf0, leaf1, leaf2]);

        let driver = DeviceRemovalDriver::resume(
            Box::new(NoopAllocationFence::new()),
            state,
            config,
            vec![DeviceId(0), DeviceId(2)],
        );

        assert_eq!(driver.state().phase, DeviceRemovalPhase::Removing);
        assert_eq!(driver.state().target_device_id, 1);
        assert_eq!(driver.surviving_device_ids().len(), 2);
    }

    #[test]
    fn driver_phase_guard_prevents_wrong_phase_operations() {
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024, DeviceHealth::Online);
        let leaf1 = make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024, DeviceHealth::Online);
        let config = make_pool_config(vec![leaf0, leaf1]);

        let mut driver = DeviceRemovalDriver::prepare(
            Box::new(NoopAllocationFence::new()),
            Path::new("/dev/disk1"),
            config,
            vec![DeviceId(0)],
            0,
        )
        .unwrap();

        // Try to evacuate before begin_evacuation
        let result = driver.record_object_evacuated(ExtentId::from(1u64), 100);
        assert!(result.is_err());

        // Try to mark_evacuated before begin_evacuation
        let result = driver.mark_evacuated();
        assert!(result.is_err());
    }

    // ── Serde roundtrip tests ───────────────────────────────────────

    #[test]
    fn serde_phase_roundtrip() {
        for phase in &[
            DeviceRemovalPhase::Removing,
            DeviceRemovalPhase::Evacuating,
            DeviceRemovalPhase::Evacuated,
            DeviceRemovalPhase::Vacated,
            DeviceRemovalPhase::Removed,
            DeviceRemovalPhase::Failed,
        ] {
            let json = serde_json::to_string(phase).expect("serialize");
            let round: DeviceRemovalPhase = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*phase, round, "roundtrip failed for {phase}");
        }
    }

    #[test]
    fn serde_state_roundtrip() {
        let state = DeviceRemovalState {
            phase: DeviceRemovalPhase::Evacuating,
            target_device: PathBuf::from("/dev/disk0"),
            target_device_id: 7,
            target_device_guid: [0x42u8; 16],
            target_device_index: 1,
            device_count_before: 3,
            objects_evacuated: 5,
            total_objects_to_evacuate: 10,
            objects_failed: 1,
            bytes_evacuated: 20480,
            target_topology_generation: 4,
            error: Some("transient I/O error".into()),
            chain_digest: [0xBBu8; 32],
        };
        let json = serde_json::to_string(&state).expect("serialize");
        let round: DeviceRemovalState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(state, round);
    }

    // ── Error display tests ─────────────────────────────────────────

    #[test]
    fn error_display_outputs() {
        let errors = [
            DeviceRemovalError::TargetDeviceNotFound {
                path: PathBuf::from("/dev/disk99"),
            },
            DeviceRemovalError::WouldEmptyPool,
            DeviceRemovalError::RemovalAlreadyInProgress {
                device: PathBuf::from("/dev/disk1"),
            },
            DeviceRemovalError::PinnedObjectsOnDevice { count: 3 },
            DeviceRemovalError::EvacuationFailed {
                object_id: ExtentId::from(42u64),
                reason: "read error".into(),
            },
            DeviceRemovalError::InsufficientRedundancy {
                details: "only 1 replica remaining".into(),
            },
            DeviceRemovalError::InvalidTransition {
                from: DeviceRemovalPhase::Removing,
                details: "not ready".into(),
            },
            DeviceRemovalError::DeviceNotHealthy {
                health: DeviceHealth::Faulted,
            },
            DeviceRemovalError::PersistFailed {
                reason: "disk full".into(),
            },
        ];
        for err in &errors {
            let s = format!("{err}");
            assert!(!s.is_empty(), "Display output empty for {err:?}");
        }
    }

    // ── Evacuation checkpoint tests ────────────────────────────────

    #[test]
    fn checkpoint_new_starts_at_zero() {
        let cp = EvacuationCheckpoint::new(10, 42);
        assert_eq!(cp.next_object_index, 0);
        assert_eq!(cp.total_objects, 10);
        assert_eq!(cp.objects_evacuated, 0);
        assert_eq!(cp.bytes_evacuated, 0);
        assert_eq!(cp.objects_failed, 0);
        assert_eq!(cp.dest_device_id, 42);
        assert!(!cp.is_complete());
        assert_eq!(cp.remaining(), 10);
    }

    #[test]
    fn checkpoint_is_complete_when_index_reaches_total() {
        let mut cp = EvacuationCheckpoint::new(3, 0);
        assert!(!cp.is_complete());
        cp.next_object_index = 2;
        assert!(!cp.is_complete());
        cp.next_object_index = 3;
        assert!(cp.is_complete());
        cp.next_object_index = 5;
        assert!(cp.is_complete());
    }

    #[test]
    fn checkpoint_remaining_decrements_correctly() {
        let cp = EvacuationCheckpoint {
            next_object_index: 7,
            total_objects: 10,
            objects_evacuated: 6,
            bytes_evacuated: 600,
            objects_failed: 1,
            dest_device_id: 3,
        };
        assert_eq!(cp.remaining(), 3);
        assert!(!cp.is_complete());
    }

    #[test]
    fn checkpoint_serde_roundtrip() {
        let cp = EvacuationCheckpoint {
            next_object_index: 42,
            total_objects: 100,
            objects_evacuated: 40,
            bytes_evacuated: 40960,
            objects_failed: 2,
            dest_device_id: 7,
        };
        let json = serde_json::to_string(&cp).expect("serialize");
        let round: EvacuationCheckpoint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cp, round);
    }

    // ── State persistence tests ─────────────────────────────────────

    #[test]
    fn serialize_deserialize_state_roundtrip() {
        let state =
            DeviceRemovalState::new(PathBuf::from("/dev/disk0"), 0, [0x42u8; 16], 0, 3, 10, 4);
        let driver = DeviceRemovalDriver::resume(
            Box::new(NoopAllocationFence::new()),
            state.clone(),
            make_pool_config(vec![
                make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online),
                make_leaf("/dev/disk1", 2, 1, 1024, DeviceHealth::Online),
            ]),
            vec![DeviceId(1)],
        );

        let serialized = driver.serialize_state().unwrap();
        let deserialized = DeviceRemovalDriver::deserialize_state(&serialized).unwrap();
        assert_eq!(state, deserialized);
    }

    // ── Evacuation batch tests ──────────────────────────────────────

    /// A fake object enumerator for unit testing evacuation batches.
    #[derive(Debug)]
    struct FakeObjectEnumerator {
        objects: Vec<tidefs_locator_table::ExtentId>,
        sizes: std::collections::HashMap<tidefs_locator_table::ExtentId, u64>,
    }

    impl ObjectEnumerator for FakeObjectEnumerator {
        fn enumerate_objects_on_device(
            &self,
            _device_id: DeviceId,
        ) -> Result<Vec<tidefs_locator_table::ExtentId>, DeviceRemovalError> {
            Ok(self.objects.clone())
        }

        fn object_size_bytes(
            &self,
            extent_id: tidefs_locator_table::ExtentId,
        ) -> Result<u64, DeviceRemovalError> {
            Ok(self.sizes.get(&extent_id).copied().unwrap_or(0))
        }
    }

    /// A fake object mover that just copies to memory, no I/O.
    #[derive(Debug)]
    struct FakeObjectMover {
        store:
            std::cell::RefCell<std::collections::HashMap<tidefs_locator_table::ExtentId, Vec<u8>>>,
    }

    impl FakeObjectMover {
        fn new() -> Self {
            Self {
                store: std::cell::RefCell::new(std::collections::HashMap::new()),
            }
        }

        fn insert(&self, id: tidefs_locator_table::ExtentId, data: Vec<u8>) {
            self.store.borrow_mut().insert(id, data);
        }
    }

    impl ObjectMover for FakeObjectMover {
        fn read_object(
            &self,
            extent_id: tidefs_locator_table::ExtentId,
            _source_device_id: DeviceId,
        ) -> Result<Vec<u8>, DeviceRemovalError> {
            self.store.borrow().get(&extent_id).cloned().ok_or_else(|| {
                DeviceRemovalError::EvacuationFailed {
                    object_id: extent_id,
                    reason: "object not found".into(),
                }
            })
        }

        fn write_object(
            &self,
            extent_id: tidefs_locator_table::ExtentId,
            _dest_device_id: DeviceId,
            data: &[u8],
        ) -> Result<u64, DeviceRemovalError> {
            let len = data.len() as u64;
            self.store.borrow_mut().insert(extent_id, data.to_vec());
            Ok(len)
        }
    }

    #[test]
    fn evacuate_batch_moves_all_objects() {
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let leaf1 = make_leaf("/dev/disk1", 2, 1, 1024, DeviceHealth::Online);
        let config = make_pool_config(vec![leaf0, leaf1.clone()]);

        let mut driver = DeviceRemovalDriver::prepare(
            Box::new(NoopAllocationFence::new()),
            Path::new("/dev/disk1"),
            config,
            vec![DeviceId(0)],
            3,
        )
        .unwrap();

        driver.begin_evacuation().unwrap();

        let eid_a = tidefs_locator_table::ExtentId::from(100u64);
        let eid_b = tidefs_locator_table::ExtentId::from(101u64);
        let eid_c = tidefs_locator_table::ExtentId::from(102u64);

        let mover = FakeObjectMover::new();
        mover.insert(eid_a, vec![0xAAu8; 100]);
        mover.insert(eid_b, vec![0xBBu8; 200]);
        mover.insert(eid_c, vec![0xCCu8; 300]);

        let enumerator = FakeObjectEnumerator {
            objects: vec![eid_a, eid_b, eid_c],
            sizes: std::collections::HashMap::new(),
        };

        let (evac, failed) = driver
            .evacuate_batch(&enumerator, &mover, DeviceId(0), 10)
            .unwrap();

        assert_eq!(evac, 3);
        assert_eq!(failed, 0);
        assert_eq!(driver.state().objects_evacuated, 3);
        assert_eq!(driver.state().bytes_evacuated, 600);
    }

    #[test]
    fn evacuate_batch_respects_max_batch_size() {
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let leaf1 = make_leaf("/dev/disk1", 2, 1, 1024, DeviceHealth::Online);
        let config = make_pool_config(vec![leaf0, leaf1]);

        let mut driver = DeviceRemovalDriver::prepare(
            Box::new(NoopAllocationFence::new()),
            Path::new("/dev/disk1"),
            config,
            vec![DeviceId(0)],
            5,
        )
        .unwrap();

        driver.begin_evacuation().unwrap();

        let objects: Vec<_> = (0..5)
            .map(|i| tidefs_locator_table::ExtentId::from(i as u64))
            .collect();

        let mover = FakeObjectMover::new();
        for &obj in &objects {
            mover.insert(obj, vec![0x42u8; 50]);
        }

        let enumerator = FakeObjectEnumerator {
            objects: objects.clone(),
            sizes: std::collections::HashMap::new(),
        };

        // Batch size 2: only 2 objects should be evacuated
        let (evac, _failed) = driver
            .evacuate_batch(&enumerator, &mover, DeviceId(0), 2)
            .unwrap();
        assert_eq!(evac, 2);
        assert_eq!(driver.state().objects_evacuated, 2);
    }

    #[test]
    fn create_checkpoint_syncs_state_correctly() {
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let leaf1 = make_leaf("/dev/disk1", 2, 1, 1024, DeviceHealth::Online);
        let config = make_pool_config(vec![leaf0, leaf1]);

        let mut driver = DeviceRemovalDriver::prepare(
            Box::new(NoopAllocationFence::new()),
            Path::new("/dev/disk1"),
            config,
            vec![DeviceId(0)],
            10,
        )
        .unwrap();

        driver.begin_evacuation().unwrap();

        // Manually record some progress
        driver.state.record_object_evacuated(100);
        driver.state.record_object_evacuated(200);
        driver.state.record_object_failed();

        let cp = driver.create_checkpoint(DeviceId(5));
        assert_eq!(cp.next_object_index, 3); // 2 evacuated + 1 failed
        assert_eq!(cp.objects_evacuated, 2);
        assert_eq!(cp.objects_failed, 1);
        assert_eq!(cp.bytes_evacuated, 300);
        assert_eq!(cp.dest_device_id, 5);
        assert_eq!(cp.total_objects, 10);
    }

    #[test]
    fn apply_checkpoint_restores_state() {
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let leaf1 = make_leaf("/dev/disk1", 2, 1, 1024, DeviceHealth::Online);
        let config = make_pool_config(vec![leaf0, leaf1]);

        let mut driver = DeviceRemovalDriver::prepare(
            Box::new(NoopAllocationFence::new()),
            Path::new("/dev/disk1"),
            config,
            vec![DeviceId(0)],
            100,
        )
        .unwrap();

        driver.begin_evacuation().unwrap();

        // Driver starts at 0.
        assert_eq!(driver.state().objects_evacuated, 0);
        assert_eq!(driver.state().bytes_evacuated, 0);
        assert_eq!(driver.state().objects_failed, 0);

        // Apply a checkpoint from a previous run.
        let cp = EvacuationCheckpoint {
            next_object_index: 55,
            total_objects: 100,
            objects_evacuated: 50,
            bytes_evacuated: 50000,
            objects_failed: 5,
            dest_device_id: 3,
        };
        driver.apply_checkpoint(&cp);

        assert_eq!(driver.state().objects_evacuated, 50);
        assert_eq!(driver.state().bytes_evacuated, 50000);
        assert_eq!(driver.state().objects_failed, 5);
    }

    #[test]
    fn evacuate_batch_rejects_wrong_phase() {
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let leaf1 = make_leaf("/dev/disk1", 2, 1, 1024, DeviceHealth::Online);
        let config = make_pool_config(vec![leaf0, leaf1]);

        let mut driver = DeviceRemovalDriver::prepare(
            Box::new(NoopAllocationFence::new()),
            Path::new("/dev/disk1"),
            config,
            vec![DeviceId(0)],
            1,
        )
        .unwrap();

        // Still in Removing phase (not Evacuating).
        let mover = FakeObjectMover::new();
        let enumerator = FakeObjectEnumerator {
            objects: vec![],
            sizes: std::collections::HashMap::new(),
        };

        let result = driver.evacuate_batch(&enumerator, &mover, DeviceId(0), 1);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DeviceRemovalError::InvalidTransition { .. }
        ));
    }

    // ── BLAKE3 chain digest tests ──────────────────────────────────
    #[test]
    fn chain_digest_is_deterministic() {
        let d1 = compute_device_removal_chain_digest(
            &[0x42u8; 32],
            DeviceRemovalPhase::Removing,
            b"test data",
        );
        let d2 = compute_device_removal_chain_digest(
            &[0x42u8; 32],
            DeviceRemovalPhase::Removing,
            b"test data",
        );
        assert_eq!(d1, d2);
    }
    #[test]
    fn chain_digest_changes_with_phase() {
        let d_removing =
            compute_device_removal_chain_digest(&[0u8; 32], DeviceRemovalPhase::Removing, b"");
        let d_evacuating =
            compute_device_removal_chain_digest(&[0u8; 32], DeviceRemovalPhase::Evacuating, b"");
        assert_ne!(d_removing, d_evacuating);
    }
    #[test]
    fn chain_digest_changes_with_data() {
        let d1 = compute_device_removal_chain_digest(
            &[0u8; 32],
            DeviceRemovalPhase::Evacuating,
            b"batch 1",
        );
        let d2 = compute_device_removal_chain_digest(
            &[0u8; 32],
            DeviceRemovalPhase::Evacuating,
            b"batch 2",
        );
        assert_ne!(d1, d2);
    }
    #[test]
    fn chain_digest_chains_across_phases() {
        let d1 =
            compute_device_removal_chain_digest(&[0u8; 32], DeviceRemovalPhase::Removing, b"start");
        let d2 = compute_device_removal_chain_digest(&d1, DeviceRemovalPhase::Evacuating, b"");
        let d3 = compute_device_removal_chain_digest(&d2, DeviceRemovalPhase::Evacuated, b"");
        // Each step must produce a different digest.
        assert_ne!(d1, d2);
        assert_ne!(d2, d3);
        // Must not equal a chain starting from scratch.
        let d2_alt =
            compute_device_removal_chain_digest(&[0u8; 32], DeviceRemovalPhase::Evacuated, b"");
        assert_ne!(d3, d2_alt);
    }
    #[test]
    fn advance_with_digest_updates_chain_digest() {
        let mut state =
            DeviceRemovalState::new(PathBuf::from("/dev/disk0"), 0, [0x01u8; 16], 0, 3, 0, 2);
        let initial = state.chain_digest;
        assert_eq!(initial, [0u8; 32]);
        state.advance_with_digest(b"phase1").unwrap();
        assert_ne!(state.chain_digest, [0u8; 32]);
        assert_eq!(state.phase, DeviceRemovalPhase::Evacuating);
        let digest1 = state.chain_digest;
        state.advance_with_digest(b"phase2").unwrap();
        assert_ne!(state.chain_digest, digest1);
        assert_eq!(state.phase, DeviceRemovalPhase::Evacuated);
    }
    #[test]
    fn advance_without_digest_preserves_chain() {
        let mut state =
            DeviceRemovalState::new(PathBuf::from("/dev/disk0"), 0, [0x01u8; 16], 0, 3, 0, 2);
        state.advance_with_digest(b"phase1").unwrap();
        let digest1 = state.chain_digest;
        state.advance().unwrap(); // no digest update
                                  // advance() delegates to advance_with_digest(b"") which still chains
        assert_ne!(state.chain_digest, digest1);
    }
    #[test]
    fn chain_digest_nonzero_after_first_transition() {
        let mut state =
            DeviceRemovalState::new(PathBuf::from("/dev/disk0"), 0, [0x01u8; 16], 0, 3, 0, 2);
        assert_eq!(state.chain_digest, [0u8; 32]);
        state.advance_with_digest(b"begin").unwrap();
        // Chain digest must be non-zero after first transition.
        let nonzero_count = state.chain_digest.iter().filter(|&&b| b != 0).count();
        assert!(nonzero_count > 0, "digest should be non-zero");
    }
    #[test]
    fn chain_digest_domain_separated_from_raw_blake3() {
        // Device removal chain digest must not equal a raw BLAKE3 of the same data.
        let prior = [0xAAu8; 32];
        let chain_d =
            compute_device_removal_chain_digest(&prior, DeviceRemovalPhase::Removing, b"test");
        let mut raw_hasher = blake3::Hasher::new();
        raw_hasher.update(&prior);
        raw_hasher.update(DeviceRemovalPhase::Removing.to_string().as_bytes());
        raw_hasher.update(b"test");
        let raw_d = *raw_hasher.finalize().as_bytes();
        assert_ne!(chain_d, raw_d, "chain digest must be domain-separated");
    }
    #[test]
    fn full_driver_lifecycle_produces_chain_digest() {
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let leaf1 = make_leaf("/dev/disk1", 2, 1, 1024, DeviceHealth::Online);
        let config = make_pool_config(vec![leaf0, leaf1]);
        let mut driver = DeviceRemovalDriver::prepare(
            Box::new(NoopAllocationFence::new()),
            Path::new("/dev/disk1"),
            config,
            vec![DeviceId(0)],
            0,
        )
        .unwrap();
        assert_eq!(driver.state().chain_digest, [0u8; 32]);
        driver.begin_evacuation().unwrap();
        let d1 = driver.state().chain_digest;
        assert_ne!(d1, [0u8; 32]);
        driver.mark_evacuated().unwrap();
        let d2 = driver.state().chain_digest;
        assert_ne!(d2, d1);
        let leaf0_after = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let mut updated = make_pool_config(vec![leaf0_after]);
        updated.topology_generation = 2;
        driver.commit_vacated(updated).unwrap();
        let d3 = driver.state().chain_digest;
        assert_ne!(d3, d2);
        driver.mark_removed().unwrap();
        let d4 = driver.state().chain_digest;
        assert_ne!(d4, d3);
    }
}
