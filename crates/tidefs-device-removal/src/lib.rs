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
use tidefs_pool_scan::{
    DeviceHealth, DeviceRemovalPlanner, DeviceRemovalRefusal, DeviceRemovalRefusalClass,
};

use tidefs_replication_model::PlacementReceiptRef;

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
    /// Block-allocator device ID for the target being removed.
    pub target_device_id: u32,

    /// GUID of the target device being removed.
    pub target_device_guid: [u8; 16],

    /// Topology generation that this removal is expected to commit.
    pub target_topology_generation: u64,

    /// Digest binding the enumerated evacuation set identity.
    pub evacuation_set_digest: [u8; 32],

    /// Removal phase-chain digest observed when the checkpoint was created.
    pub removal_chain_digest: [u8; 32],

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
            target_device_id: 0,
            target_device_guid: [0u8; 16],
            target_topology_generation: 0,
            evacuation_set_digest: [0u8; 32],
            removal_chain_digest: [0u8; 32],
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

// ---------------------------------------------------------------------------
// EvacuationReceipt
// ---------------------------------------------------------------------------

/// Committed evidence that all placement receipts referencing a device have been
/// relocated during evacuation.
///
/// An [`EvacuationReceipt`] binds the target device identity, the evacuation
/// completion generation, and the set of placement receipt refs that relocated
/// data off the device.  Device removal must possess a committed
/// [`EvacuationReceipt`] before the target device can be vacated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvacuationReceipt {
    /// GUID of the target device that was evacuated.
    pub target_device_guid: [u8; 16],

    /// Topology generation against which this evacuation completed.
    pub topology_generation: u64,

    /// Digest binding the enumerated evacuation set identity.
    pub evacuation_set_digest: [u8; 32],

    /// The completion generation that was produced when evacuation finished.
    pub completion_generation: EvacuationCompletionGeneration,

    /// Placement receipt refs that relocated data off the target device.
    /// Empty means the device had no placement receipts referencing it
    /// (e.g., a new device with no data placed yet).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub placement_receipt_refs: Vec<PlacementReceiptRef>,

    /// Monotonic receipt identifier.
    pub receipt_id: u64,

    /// BLAKE3 digest of the committed receipt payload (excluding this field).
    pub receipt_digest: [u8; 32],
}

impl EvacuationReceipt {
    /// Create an evacuation receipt from the completion generation and
    /// the set of placement receipt refs that were relocated.
    #[must_use]
    pub fn new(
        completion_generation: EvacuationCompletionGeneration,
        placement_receipt_refs: Vec<PlacementReceiptRef>,
        receipt_id: u64,
    ) -> Self {
        let mut receipt = Self {
            target_device_guid: completion_generation.target_device_guid,
            topology_generation: completion_generation.target_topology_generation,
            evacuation_set_digest: completion_generation.evacuation_set_digest,
            completion_generation,
            placement_receipt_refs,
            receipt_id,
            receipt_digest: [0u8; 32],
        };
        receipt.receipt_digest = receipt.compute_digest();
        receipt
    }

    /// Compute the BLAKE3 digest of the committed receipt payload.
    #[must_use]
    pub fn compute_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.target_device_guid);
        hasher.update(&self.topology_generation.to_le_bytes());
        hasher.update(&self.evacuation_set_digest);
        hasher.update(&self.completion_generation.removal_chain_digest);
        hasher.update(&self.receipt_id.to_le_bytes());
        for pr in &self.placement_receipt_refs {
            hasher.update(&pr.object_id.to_le_bytes());
            hasher.update(&pr.object_key);
            hasher.update(&pr.receipt_epoch.0.to_le_bytes());
            hasher.update(&pr.receipt_generation.to_le_bytes());
            match pr.redundancy_policy {
                tidefs_replication_model::ReceiptRedundancyPolicy::Replicated { copies } => {
                    hasher.update(&[0]);
                    hasher.update(&[copies]);
                }
                tidefs_replication_model::ReceiptRedundancyPolicy::Erasure {
                    data_shards,
                    parity_shards,
                } => {
                    hasher.update(&[1]);
                    hasher.update(&[data_shards]);
                    hasher.update(&[parity_shards]);
                }
            }
            hasher.update(&pr.payload_len.to_le_bytes());
            hasher.update(&pr.payload_digest);
            hasher.update(&pr.target_count.to_le_bytes());
        }
        hasher.finalize().into()
    }

    /// Verify the receipt digest matches the computed digest.
    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.receipt_digest == self.compute_digest()
    }

    /// Create a [`tidefs_pool_scan::CompletedEvacuation`] record from this receipt.
    ///
    /// The returned evidence can be stored in [`tidefs_pool_scan::PoolConfig`]
    /// so that post-removal pool scans surface the committed evacuation receipt.
    #[must_use]
    pub fn to_completed_evacuation(&self) -> tidefs_pool_scan::CompletedEvacuation {
        tidefs_pool_scan::CompletedEvacuation {
            target_device_guid: self.target_device_guid,
            topology_generation: self.topology_generation,
            receipt_digest: self.receipt_digest,
            receipt_id: self.receipt_id,
        }
    }

    /// Verify this evacuation receipt against the current removal state.
    ///
    /// Returns `None` on success, or a human-readable mismatch reason.
    #[must_use]
    pub fn verify(
        &self,
        state: &DeviceRemovalState,
        expected_set_digest: [u8; 32],
    ) -> Option<String> {
        if self.target_device_guid != state.target_device_guid {
            return Some(format!(
                "evacuation receipt target guid {:x?} does not match state {:x?}",
                self.target_device_guid, state.target_device_guid
            ));
        }
        if self.topology_generation != state.target_topology_generation {
            return Some(format!(
                "evacuation receipt topology {} does not match state topology {}",
                self.topology_generation, state.target_topology_generation
            ));
        }
        if self.evacuation_set_digest != expected_set_digest {
            return Some("evacuation receipt evacuation set digest does not match".to_string());
        }
        if !self.verify_digest() {
            return Some("evacuation receipt digest verification failed".to_string());
        }
        None
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

// ---------------------------------------------------------------------------
// PlacementReceiptChecker
// ---------------------------------------------------------------------------

/// Trait for checking whether placement receipts reference a device.
///
/// Implementations consult the placement runtime to determine whether
/// any committed placement receipt still references the device being
/// removed.  The removal gate uses this to fail closed when receipts
/// still reference the device.
pub trait PlacementReceiptChecker: std::fmt::Debug {
    /// Return placement receipt refs that reference any of the given extents.
    ///
    /// An empty `Vec` means no placement receipts still reference the
    /// device and the evacuation receipt can be committed.
    fn receipts_referencing_extents(
        &self,
        extent_ids: &[ExtentId],
    ) -> Result<Vec<PlacementReceiptRef>, DeviceRemovalError>;

    /// Returns `true` if any placement receipt references the given extents.
    fn has_receipts_referencing_extents(&self, extent_ids: &[ExtentId]) -> bool {
        self.receipts_referencing_extents(extent_ids)
            .map(|v| !v.is_empty())
            .unwrap_or(true) // fail closed
    }
}

// ---------------------------------------------------------------------------
// EvacuationCompletionGeneration
// ---------------------------------------------------------------------------

/// Durable evidence that evacuation completed for a specific device removal.
///
/// Binds the target device GUID, the topology generation, the evacuation-set
/// digest, and the removal phase-chain digest at the point evacuation finished.
/// Stored durably before pool-label retirement so that crash replay can verify
/// completion rather than relying on in-memory state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvacuationCompletionGeneration {
    /// GUID of the target device that was evacuated.
    pub target_device_guid: [u8; 16],

    /// Topology generation against which this evacuation completed.
    pub target_topology_generation: u64,

    /// Digest binding the enumerated evacuation set identity.
    pub evacuation_set_digest: [u8; 32],

    /// Removal phase-chain digest at the point evacuation completed.
    pub removal_chain_digest: [u8; 32],
}

impl EvacuationCompletionGeneration {
    /// Create a completion generation from the current removal state.
    #[must_use]
    pub fn from_state(state: &DeviceRemovalState, set_digest: [u8; 32]) -> Self {
        Self {
            target_device_guid: state.target_device_guid,
            target_topology_generation: state.target_topology_generation,
            evacuation_set_digest: set_digest,
            removal_chain_digest: state.chain_digest,
        }
    }

    /// Verify this completion generation against the current removal state.
    ///
    /// Returns `None` on success, or a human-readable mismatch reason.
    #[must_use]
    pub fn verify(
        &self,
        state: &DeviceRemovalState,
        expected_set_digest: [u8; 32],
    ) -> Option<String> {
        if self.target_device_guid != state.target_device_guid {
            return Some(format!(
                "completion generation target guid {:x?} does not match state {:x?}",
                self.target_device_guid, state.target_device_guid
            ));
        }
        if self.target_topology_generation != state.target_topology_generation {
            return Some(format!(
                "completion generation topology {} does not match state topology {}",
                self.target_topology_generation, state.target_topology_generation
            ));
        }
        if self.evacuation_set_digest != expected_set_digest {
            return Some("completion generation evacuation set digest does not match".to_string());
        }
        None
    }

    /// Verify the completion generation against the given chain digest.
    ///
    /// Unlike [`Self::verify`], this also checks that the completion
    /// generation was created at the same chain-digest point.  Use this
    /// for intra-phase verification (e.g., during crash replay) where the
    /// chain digest should not have advanced.
    #[must_use]
    pub fn verify_chain(&self, expected_chain_digest: &[u8; 32]) -> Option<String> {
        if self.removal_chain_digest != *expected_chain_digest {
            return Some(format!(
                "completion generation chain digest {:x?} does not match expected {:x?}",
                self.removal_chain_digest, expected_chain_digest
            ));
        }
        None
    }
}
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
// DeviceRemovalStatus
// ---------------------------------------------------------------------------

/// Operator-visible removal status for progress reporting and
/// crash-replay gating.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeviceRemovalStatus {
    /// Object evacuation is in progress; some live objects remain on the device.
    EvacuationInProgress,
    /// Evacuation finished in memory but the completion generation has not been
    /// durably recorded.  Crash before persistence rolls back to evacuation.
    CompletionNotDurable,
    /// The topology generation has changed since evacuation completed.
    TopologyMismatch,
    /// Evacuation completion is durable and topology matches; label retirement
    /// or final removal can proceed.
    LabelRetirementReady,
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

    /// Typed refusal/failure evidence if the removal entered the Failed phase.
    pub failure_evidence: Option<DeviceRemovalRefusal>,

    /// BLAKE3-256 chain digest linking this phase to the prior one.
    ///
    /// Updated at each phase transition via
    /// [`compute_device_removal_chain_digest`].  Zero-filled at creation
    /// (representing no prior anchor).
    pub chain_digest: [u8; 32],

    /// Evacuation completion generation evidence.
    ///
    /// Populated in memory after [`DeviceRemovalPhase::Evacuated`] is reached.
    /// Durable recording happens at [`DeviceRemovalPhase::Vacated`] commit.
    /// `None` until evacuation completes; `Some` afterwards.
    pub evacuation_completion_generation: Option<EvacuationCompletionGeneration>,

    /// Committed evacuation receipt binding placement receipts to this evacuation.
    ///
    /// Populated when the placement receipt checker confirms no live extent
    /// references the device.  `None` until the evacuation receipt is committed;
    /// `Some` afterwards.
    pub evacuation_receipt: Option<EvacuationReceipt>,

    /// Extent IDs that were evacuated from the target device.
    ///
    /// Populated during evacuation; used by the placement receipt checker
    /// during commit to verify no receipt still references these extents.
    /// Not serialized because ExtentId does not implement serde traits;
    /// the evacuation receipt carries the canonical durable evidence.
    #[serde(skip)]
    pub evacuated_extent_ids: Vec<ExtentId>,
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
            failure_evidence: None,
            chain_digest: [0u8; 32],
            evacuation_completion_generation: None,
            evacuation_receipt: None,
            evacuated_extent_ids: Vec::new(),
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

    /// Transition the state machine to Failed with typed durable evidence.
    pub fn fail_with_evidence(&mut self, evidence: DeviceRemovalRefusal) {
        self.phase = DeviceRemovalPhase::Failed;
        self.error = Some(evidence.details.clone());
        self.failure_evidence = Some(evidence);
    }

    /// Record a successfully evacuated object.
    pub fn record_object_evacuated(&mut self, extent_id: ExtentId, bytes: u64) {
        self.objects_evacuated = self.objects_evacuated.saturating_add(1);
        self.bytes_evacuated = self.bytes_evacuated.saturating_add(bytes);
        self.evacuated_extent_ids.push(extent_id);
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
    }

    /// Returns `true` if all live objects have been evacuated with no failures.
    #[must_use]
    pub fn is_evacuation_complete(&self) -> bool {
        self.objects_failed == 0 && self.objects_remaining() == 0
    }

    /// Record the evacuation completion generation from the current state.
    ///
    /// Captures the target device GUID, topology generation, evacuation-set
    /// digest, and removal phase-chain digest at the point evacuation finished.
    /// This is an in-memory recording; durability comes at Vacated commit.
    pub fn record_evacuation_completion(&mut self, set_digest: [u8; 32]) {
        self.evacuation_completion_generation =
            Some(EvacuationCompletionGeneration::from_state(self, set_digest));
    }

    /// Record the committed evacuation receipt.
    ///
    /// Creates and stores an [`EvacuationReceipt`] that binds the evacuation
    /// completion to the set of placement receipt refs that relocated data off
    /// the target device.  Must be called after [`Self::record_evacuation_completion`]
    /// and after the placement receipt checker confirms no live extent references
    /// the device.
    ///
    /// # Panics
    ///
    /// Panics if `record_evacuation_completion` has not been called first.
    pub fn record_evacuation_receipt(
        &mut self,
        placement_receipt_refs: Vec<PlacementReceiptRef>,
        receipt_id: u64,
    ) {
        let completion = self
            .evacuation_completion_generation
            .as_ref()
            .expect("evacuation completion generation must be recorded before evacuation receipt");
        self.evacuation_receipt = Some(EvacuationReceipt::new(
            completion.clone(),
            placement_receipt_refs,
            receipt_id,
        ));
    }

    /// Return a reference to the evacuation completion generation, if recorded.
    #[must_use]
    pub fn evacuation_completion_generation(&self) -> Option<&EvacuationCompletionGeneration> {
        self.evacuation_completion_generation.as_ref()
    }

    /// Returns `true` if the evacuation completion generation is recorded
    /// (non-`None`).  Note that this does not imply durability — use
    /// [`Self::completion_status`] for the full picture.
    #[must_use]
    pub fn is_completion_recorded(&self) -> bool {
        self.evacuation_completion_generation.is_some()
    }

    /// Operator-visible status for progress reporting and crash-replay gating.
    ///
    /// Consults the current phase, completion generation, and pool config
    /// to determine whether evacuation is done, durable, and topology-matched.
    #[must_use]
    pub fn completion_status(
        &self,
        pool_config: &tidefs_pool_scan::PoolConfig,
    ) -> DeviceRemovalStatus {
        match self.phase {
            DeviceRemovalPhase::Removing | DeviceRemovalPhase::Evacuating => {
                DeviceRemovalStatus::EvacuationInProgress
            }
            DeviceRemovalPhase::Evacuated => {
                if self.evacuation_completion_generation.is_some() {
                    DeviceRemovalStatus::CompletionNotDurable
                } else {
                    DeviceRemovalStatus::EvacuationInProgress
                }
            }
            DeviceRemovalPhase::Vacated | DeviceRemovalPhase::Removed => {
                let Some(ref gen) = self.evacuation_completion_generation else {
                    return DeviceRemovalStatus::CompletionNotDurable;
                };
                if gen.target_topology_generation != pool_config.topology_generation {
                    return DeviceRemovalStatus::TopologyMismatch;
                }
                DeviceRemovalStatus::LabelRetirementReady
            }
            DeviceRemovalPhase::Failed => DeviceRemovalStatus::EvacuationInProgress,
        }
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

    /// Removal was refused or failed with typed durable evidence.
    #[error("device removal refused: {evidence}")]
    RemovalRefused {
        /// Typed refusal/failure evidence.
        evidence: DeviceRemovalRefusal,
    },

    /// Failed to persist removal state to pool metadata.
    #[error("failed to persist removal state: {reason}")]
    PersistFailed {
        /// Human-readable reason for the persistence failure.
        reason: String,
    },
}

impl DeviceRemovalError {
    /// Return typed refusal evidence when this error carries it directly.
    #[must_use]
    pub const fn refusal_evidence(&self) -> Option<&DeviceRemovalRefusal> {
        match self {
            Self::RemovalRefused { evidence } => Some(evidence),
            _ => None,
        }
    }

    /// Return the stable refusal class when this error carries direct evidence.
    #[must_use]
    pub const fn refusal_class(&self) -> Option<DeviceRemovalRefusalClass> {
        match self {
            Self::RemovalRefused { evidence } => Some(evidence.class),
            _ => None,
        }
    }
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

    /// Placement receipt checker: verifies no placement receipt references
    /// the target device before finalizing removal. Missing checker authority
    /// fails the removal closed.
    placement_receipt_checker: Option<Box<dyn PlacementReceiptChecker>>,
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
        let expected_topology_generation = pool_config.topology_generation;
        Self::prepare_with_expected_topology_generation(
            alloc_fence,
            target_device_path,
            pool_config,
            surviving_device_ids,
            object_count_on_device,
            expected_topology_generation,
        )
    }

    /// Prepare a device removal operation against an expected topology
    /// generation.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceRemovalError::RemovalRefused`] with typed evidence if
    /// preflight rejects the target, topology, health, or redundancy state.
    pub fn prepare_with_expected_topology_generation(
        alloc_fence: Box<dyn AllocationFence>,
        target_device_path: &Path,
        pool_config: tidefs_pool_scan::PoolConfig,
        surviving_device_ids: Vec<DeviceId>,
        object_count_on_device: u64,
        expected_topology_generation: u64,
    ) -> Result<Self, DeviceRemovalError> {
        if pool_config.topology_generation != expected_topology_generation {
            return Err(DeviceRemovalError::RemovalRefused {
                evidence: DeviceRemovalRefusal::new(
                    DeviceRemovalRefusalClass::StaleTopologyGeneration,
                    target_device_path.to_path_buf(),
                    "pool topology generation changed before removal preflight",
                )
                .with_topology_generations(
                    expected_topology_generation,
                    pool_config.topology_generation,
                ),
            });
        }

        if !pool_config.redundancy_policy.is_well_formed() {
            return Err(DeviceRemovalError::RemovalRefused {
                evidence: DeviceRemovalRefusal::new(
                    DeviceRemovalRefusalClass::DomainConstraintViolation,
                    target_device_path.to_path_buf(),
                    format!(
                        "pool redundancy policy {} is not well formed",
                        pool_config.redundancy_policy
                    ),
                ),
            });
        }

        // Validate target device exists in the pool.
        let leaves = DeviceRemovalPlanner::flatten_leaves(&pool_config.device_tree);

        let target_info = leaves
            .iter()
            .find(|leaf| leaf.device_path == target_device_path)
            .ok_or_else(|| DeviceRemovalError::RemovalRefused {
                evidence: DeviceRemovalRefusal::new(
                    DeviceRemovalRefusalClass::TargetNotFound,
                    target_device_path.to_path_buf(),
                    "target device is not present in the pool topology",
                ),
            })?;

        // Validate pool won't be emptied.
        if surviving_device_ids.is_empty() {
            return Err(DeviceRemovalError::RemovalRefused {
                evidence: DeviceRemovalRefusal::new(
                    DeviceRemovalRefusalClass::WouldEmptyPool,
                    target_device_path.to_path_buf(),
                    "removal would leave the pool with zero surviving devices",
                )
                .with_surviving_topology(0, 1),
            });
        }

        // Validate device health permits removal.
        let target_health = find_device_health(&pool_config.device_tree, target_device_path)
            .unwrap_or(DeviceHealth::Online);
        if !target_health.is_operational() {
            return Err(DeviceRemovalError::RemovalRefused {
                evidence: DeviceRemovalRefusal::new(
                    DeviceRemovalRefusalClass::UnhealthyTarget,
                    target_device_path.to_path_buf(),
                    format!("target health is {target_health}"),
                ),
            });
        }

        let required_survivors = u32::from(pool_config.redundancy_policy.target_width());
        if (surviving_device_ids.len() as u32) < required_survivors {
            return Err(DeviceRemovalError::RemovalRefused {
                evidence: DeviceRemovalRefusal::new(
                    DeviceRemovalRefusalClass::InsufficientSurvivingTopology,
                    target_device_path.to_path_buf(),
                    format!(
                        "removal would leave {} surviving device(s), but policy {} requires {}",
                        surviving_device_ids.len(),
                        pool_config.redundancy_policy,
                        required_survivors
                    ),
                )
                .with_surviving_topology(surviving_device_ids.len() as u32, required_survivors),
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
            placement_receipt_checker: None,
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
            placement_receipt_checker: None,
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

    /// Return the operator-visible removal status.
    ///
    /// Distinguishes evacuation-in-progress, completion-not-durable,
    /// topology-mismatch, and label-retirement-ready outcomes.
    #[must_use]
    pub fn status(&self) -> DeviceRemovalStatus {
        self.state.completion_status(&self.pool_config_snapshot)
    }

    /// Attach a placement receipt checker for evacuation gating.
    ///
    /// Without a checker, [`Self::commit_vacated`] and [`Self::mark_removed`]
    /// refuse removal because receipt completeness cannot be proven.
    pub fn set_placement_receipt_checker(&mut self, checker: Box<dyn PlacementReceiptChecker>) {
        self.placement_receipt_checker = Some(checker);
    }

    /// Record the committed evacuation receipt.
    ///
    /// Delegates to [`DeviceRemovalState::record_evacuation_receipt`].
    /// Must be called after evacuation completes and the placement
    /// receipt checker confirms no live extent references the device.
    pub fn record_evacuation_receipt(
        &mut self,
        placement_receipt_refs: Vec<PlacementReceiptRef>,
        receipt_id: u64,
    ) {
        self.state
            .record_evacuation_receipt(placement_receipt_refs, receipt_id);
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
        self.state
            .advance_with_digest(&begin_evacuation_digest_data(&self.state))
    }

    /// Record a single object evacuation.
    ///
    /// # Errors
    ///
    /// Returns an error if not in the Evacuating phase.
    pub fn record_object_evacuated(
        &mut self,
        object_id: ExtentId,
        bytes: u64,
    ) -> Result<(), DeviceRemovalError> {
        self.require_phase(DeviceRemovalPhase::Evacuating, "evacuate_object")?;
        self.state.record_object_evacuated(object_id, bytes);
        Ok(())
    }

    /// Record a failed object evacuation.
    ///
    /// # Errors
    ///
    /// Returns an error if not in the Evacuating phase.
    pub fn record_object_failed(&mut self, object_id: ExtentId) -> Result<(), DeviceRemovalError> {
        self.require_phase(DeviceRemovalPhase::Evacuating, "record_object_failed")?;
        self.state.record_object_failed();
        let evidence = DeviceRemovalRefusal::new(
            DeviceRemovalRefusalClass::EvacuationFailed,
            self.state.target_device.clone(),
            format!("evacuation failed for object {object_id}"),
        );
        Err(self.transition_to_failed(evidence))
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
        if self.state.objects_failed > 0 {
            let evidence = DeviceRemovalRefusal::new(
                DeviceRemovalRefusalClass::EvacuationFailed,
                self.state.target_device.clone(),
                format!(
                    "{} object(s) failed during evacuation",
                    self.state.objects_failed
                ),
            );
            return Err(self.transition_to_failed(evidence));
        }
        if self.state.objects_remaining() > 0 {
            let evidence = DeviceRemovalRefusal::new(
                DeviceRemovalRefusalClass::EvacuationIncomplete,
                self.state.target_device.clone(),
                format!(
                    "{} live object(s) remain un-evacuated",
                    self.state.objects_remaining()
                ),
            );
            return Err(self.transition_to_failed(evidence));
        }
        self.state
            .advance_with_digest(&evacuation_success_digest_data(&self.state))?;

        // Record the evacuation completion generation so that subsequent
        // transitions (commit_vacated, mark_removed) can verify durable
        // completion evidence rather than in-memory state alone.
        let set_digest = evacuation_set_digest(&self.state);
        self.state.record_evacuation_completion(set_digest);
        Ok(())
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

        // Verify that evacuation completion generation is recorded and matches.
        let set_digest = evacuation_set_digest(&self.state);
        let Some(ref completion) = self.state.evacuation_completion_generation else {
            let evidence = DeviceRemovalRefusal::new(
                DeviceRemovalRefusalClass::EvacuationCompletionNotDurable,
                self.state.target_device.clone(),
                "evacuation completion generation is missing; commit requires durable evidence",
            );
            return Err(self.transition_to_failed(evidence));
        };
        if let Some(reason) = completion.verify(&self.state, set_digest) {
            let evidence = DeviceRemovalRefusal::new(
                DeviceRemovalRefusalClass::EvacuationCompletionMismatch,
                self.state.target_device.clone(),
                reason,
            );
            return Err(self.transition_to_failed(evidence));
        }

        // Verify that the evacuation receipt is recorded and placement receipts
        // no longer reference the target device.
        let Some(ref evac_receipt) = self.state.evacuation_receipt else {
            let evidence = DeviceRemovalRefusal::new(
                DeviceRemovalRefusalClass::EvacuationCompletionNotDurable,
                self.state.target_device.clone(),
                "evacuation receipt is missing; commit requires committed placement receipt evidence",
            );
            return Err(self.transition_to_failed(evidence));
        };
        if let Some(reason) = evac_receipt.verify(&self.state, set_digest) {
            let evidence = DeviceRemovalRefusal::new(
                DeviceRemovalRefusalClass::EvacuationCompletionMismatch,
                self.state.target_device.clone(),
                reason,
            );
            return Err(self.transition_to_failed(evidence));
        }
        self.require_no_placement_receipts_reference_target("commit_vacated")?;

        // Validate that the updated config no longer contains the target device.
        let updated_leaves = DeviceRemovalPlanner::flatten_leaves(&updated_pool_config.device_tree);
        let target_still_present = updated_leaves
            .iter()
            .any(|leaf| leaf.device_path == self.state.target_device);
        if target_still_present {
            let evidence = DeviceRemovalRefusal::new(
                DeviceRemovalRefusalClass::CommittedTopologyMismatch,
                self.state.target_device.clone(),
                "updated_pool_config still contains the target device",
            );
            return Err(self.transition_to_failed(evidence));
        }

        // Validate topology generation advanced.
        if updated_pool_config.topology_generation != self.state.target_topology_generation {
            let evidence = DeviceRemovalRefusal::new(
                DeviceRemovalRefusalClass::CommittedTopologyMismatch,
                self.state.target_device.clone(),
                format!(
                    "topology generation mismatch: expected {}, got {}",
                    self.state.target_topology_generation, updated_pool_config.topology_generation,
                ),
            )
            .with_topology_generations(
                self.state.target_topology_generation,
                updated_pool_config.topology_generation,
            );
            return Err(self.transition_to_failed(evidence));
        }

        let digest_data = committed_topology_digest_data(&self.state, &updated_pool_config);
        self.pool_config_snapshot = updated_pool_config;
        self.state.advance_with_digest(&digest_data)
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

        // Verify durable evacuation completion before final removal.
        // The completion generation must be present and match the current state;
        // a missing or mismatched completion means the evacuation was never
        // durably recorded and the removal cannot be finalized.
        let set_digest = evacuation_set_digest(&self.state);
        let Some(ref completion) = self.state.evacuation_completion_generation else {
            let evidence = DeviceRemovalRefusal::new(
                DeviceRemovalRefusalClass::EvacuationCompletionNotDurable,
                self.state.target_device.clone(),
                "evacuation completion generation is missing; removal requires durable evidence",
            );
            return Err(self.transition_to_failed(evidence));
        };
        if let Some(reason) = completion.verify(&self.state, set_digest) {
            let evidence = DeviceRemovalRefusal::new(
                DeviceRemovalRefusalClass::EvacuationCompletionMismatch,
                self.state.target_device.clone(),
                reason,
            );
            return Err(self.transition_to_failed(evidence));
        }

        // Verify that the evacuation receipt is recorded and placement receipts
        // no longer reference the target device.
        let Some(ref evac_receipt) = self.state.evacuation_receipt else {
            let evidence = DeviceRemovalRefusal::new(
                DeviceRemovalRefusalClass::EvacuationCompletionNotDurable,
                self.state.target_device.clone(),
                "evacuation receipt is missing; removal requires committed placement receipt evidence",
            );
            return Err(self.transition_to_failed(evidence));
        };
        if let Some(reason) = evac_receipt.verify(&self.state, set_digest) {
            let evidence = DeviceRemovalRefusal::new(
                DeviceRemovalRefusalClass::EvacuationCompletionMismatch,
                self.state.target_device.clone(),
                reason,
            );
            return Err(self.transition_to_failed(evidence));
        }
        self.require_no_placement_receipts_reference_target("mark_removed")?;

        self.state
            .advance_with_digest(&removed_digest_data(&self.state))
    }
    /// Transition the removal to Failed.
    pub fn fail(&mut self, error: impl Into<String>) {
        let evidence = DeviceRemovalRefusal::new(
            DeviceRemovalRefusalClass::DomainConstraintViolation,
            self.state.target_device.clone(),
            error.into(),
        );
        let _ = self.transition_to_failed(evidence);
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
    /// batch. Any object failure fails the removal closed.
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
        for extent_id in &batch {
            // Read the object from the source device
            let data = match mover.read_object(*extent_id, DeviceId(self.state.target_device_id)) {
                Ok(d) => d,
                Err(e) => {
                    self.state.record_object_failed();
                    let evidence = DeviceRemovalRefusal::new(
                        DeviceRemovalRefusalClass::EvacuationFailed,
                        self.state.target_device.clone(),
                        format!("read failed for object {extent_id}: {e}"),
                    );
                    return Err(self.transition_to_failed(evidence));
                }
            };

            let obj_len = data.len() as u64;

            // Write to the destination device
            match mover.write_object(*extent_id, dest_device_id, &data) {
                Ok(_written) => {
                    self.state.record_object_evacuated(*extent_id, obj_len);
                    evacuated += 1;
                }
                Err(e) => {
                    self.state.record_object_failed();
                    let evidence = DeviceRemovalRefusal::new(
                        DeviceRemovalRefusalClass::EvacuationFailed,
                        self.state.target_device.clone(),
                        format!("write failed for object {extent_id}: {e}"),
                    );
                    return Err(self.transition_to_failed(evidence));
                }
            }
        }

        Ok((evacuated, 0))
    }

    /// Create a checkpoint from the current removal state.
    ///
    /// The checkpoint records the evacuation progress so that
    /// crash recovery can resume from the last committed batch.
    #[must_use]
    pub fn create_checkpoint(&self, dest_device_id: DeviceId) -> EvacuationCheckpoint {
        EvacuationCheckpoint {
            target_device_id: self.state.target_device_id,
            target_device_guid: self.state.target_device_guid,
            target_topology_generation: self.state.target_topology_generation,
            evacuation_set_digest: evacuation_set_digest(&self.state),
            removal_chain_digest: self.state.chain_digest,
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
    ///
    /// # Errors
    ///
    /// Returns [`DeviceRemovalError::RemovalRefused`] if the checkpoint
    /// identity does not match this removal.
    pub fn apply_checkpoint(
        &mut self,
        cp: &EvacuationCheckpoint,
    ) -> Result<(), DeviceRemovalError> {
        self.apply_checkpoint_for_destination(cp, DeviceId(cp.dest_device_id))
    }

    /// Apply a checkpoint while proving it belongs to an expected destination.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceRemovalError::RemovalRefused`] if the checkpoint was
    /// created for a different target, destination, object count, topology
    /// generation, or phase-chain digest.
    pub fn apply_checkpoint_for_destination(
        &mut self,
        cp: &EvacuationCheckpoint,
        expected_dest_device_id: DeviceId,
    ) -> Result<(), DeviceRemovalError> {
        self.require_phase(DeviceRemovalPhase::Evacuating, "apply_checkpoint")?;
        if let Some(evidence) = self.checkpoint_replay_refusal(cp, expected_dest_device_id) {
            return Err(self.transition_to_failed(evidence));
        }
        self.state.objects_evacuated = cp.objects_evacuated;
        self.state.bytes_evacuated = cp.bytes_evacuated;
        self.state.objects_failed = cp.objects_failed;
        Ok(())
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

    fn checkpoint_replay_refusal(
        &self,
        cp: &EvacuationCheckpoint,
        expected_dest_device_id: DeviceId,
    ) -> Option<DeviceRemovalRefusal> {
        let class = DeviceRemovalRefusalClass::CheckpointReplayRejected;
        let target = self.state.target_device.clone();
        let expected_set_digest = evacuation_set_digest(&self.state);
        let expected_next_index = cp.objects_evacuated.saturating_add(cp.objects_failed);

        let details = if cp.target_device_id != self.state.target_device_id {
            Some(format!(
                "checkpoint target device id {} does not match {}",
                cp.target_device_id, self.state.target_device_id
            ))
        } else if cp.target_device_guid != self.state.target_device_guid {
            Some("checkpoint target device guid does not match removal target".to_string())
        } else if cp.dest_device_id != expected_dest_device_id.0 {
            Some(format!(
                "checkpoint destination device {} does not match expected {}",
                cp.dest_device_id, expected_dest_device_id.0
            ))
        } else if !self
            .surviving_device_ids
            .iter()
            .any(|device_id| device_id.0 == cp.dest_device_id)
        {
            Some(format!(
                "checkpoint destination device {} is not a surviving device",
                cp.dest_device_id
            ))
        } else if cp.total_objects != self.state.total_objects_to_evacuate {
            Some(format!(
                "checkpoint object count {} does not match removal object count {}",
                cp.total_objects, self.state.total_objects_to_evacuate
            ))
        } else if cp.target_topology_generation != self.state.target_topology_generation {
            Some(format!(
                "checkpoint topology generation {} does not match {}",
                cp.target_topology_generation, self.state.target_topology_generation
            ))
        } else if cp.evacuation_set_digest != expected_set_digest {
            Some("checkpoint evacuation set digest does not match removal identity".to_string())
        } else if cp.removal_chain_digest != self.state.chain_digest {
            Some("checkpoint removal chain digest does not match current phase chain".to_string())
        } else if cp.objects_failed > 0 {
            Some(format!(
                "checkpoint records {} failed object(s)",
                cp.objects_failed
            ))
        } else if cp.next_object_index != expected_next_index {
            Some(format!(
                "checkpoint next object index {} does not equal processed object count {}",
                cp.next_object_index, expected_next_index
            ))
        } else if cp.objects_evacuated > cp.total_objects {
            Some(format!(
                "checkpoint evacuated count {} exceeds object count {}",
                cp.objects_evacuated, cp.total_objects
            ))
        } else {
            None
        };

        details.map(|details| DeviceRemovalRefusal::new(class, target, details))
    }

    fn require_no_placement_receipts_reference_target(
        &mut self,
        operation: &str,
    ) -> Result<(), DeviceRemovalError> {
        let details = match self.placement_receipt_checker.as_ref() {
            Some(checker) => match self.placement_receipt_check_extent_ids() {
                Ok(extent_ids) => match checker.receipts_referencing_extents(&extent_ids) {
                    Ok(refs) if refs.is_empty() => return Ok(()),
                    Ok(refs) => format!(
                        "placement receipts still reference the target device: {} receipt ref(s)",
                        refs.len()
                    ),
                    Err(err) => {
                        format!("placement receipt checker failed during {operation}: {err}")
                    }
                },
                Err(details) => details,
            },
            None => format!(
                "placement receipt checker is missing; {operation} requires committed placement receipt verification"
            ),
        };

        let evidence = DeviceRemovalRefusal::new(
            DeviceRemovalRefusalClass::PlacementReceiptsStillReferenceDevice,
            self.state.target_device.clone(),
            details,
        );
        Err(self.transition_to_failed(evidence))
    }

    fn placement_receipt_check_extent_ids(&self) -> Result<Vec<ExtentId>, String> {
        if !self.state.evacuated_extent_ids.is_empty() {
            return Ok(self.state.evacuated_extent_ids.clone());
        }

        let mut recovered_extent_ids: Vec<ExtentId> = self
            .state
            .evacuation_receipt
            .as_ref()
            .map(|receipt| {
                receipt
                    .placement_receipt_refs
                    .iter()
                    .map(|receipt_ref| ExtentId(receipt_ref.object_id))
                    .collect()
            })
            .unwrap_or_default();
        recovered_extent_ids.sort_unstable();
        recovered_extent_ids.dedup();

        if recovered_extent_ids.is_empty() && self.state.objects_evacuated > 0 {
            return Err(
                "evacuated extent identity is missing after replay; placement receipt verification cannot be proven"
                    .to_string(),
            );
        }

        Ok(recovered_extent_ids)
    }

    fn transition_to_failed(&mut self, evidence: DeviceRemovalRefusal) -> DeviceRemovalError {
        self.alloc_fence
            .unfence_device(DeviceId(self.state.target_device_id));
        let digest_data = refusal_digest_data(&evidence);
        self.state.chain_digest = compute_device_removal_chain_digest(
            &self.state.chain_digest,
            self.state.phase,
            &digest_data,
        );
        self.state.fail_with_evidence(evidence.clone());
        DeviceRemovalError::RemovalRefused { evidence }
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
    append_hash_field(&mut hasher, b"prior-digest", prior_digest);
    append_hash_field(&mut hasher, b"phase", current_phase.to_string().as_bytes());
    append_hash_field(&mut hasher, b"removal-evidence", commit_data);
    *hasher.finalize().as_bytes()
}

fn begin_evacuation_digest_data(state: &DeviceRemovalState) -> Vec<u8> {
    let mut data = removal_state_digest_data(b"begin-evacuation", state);
    append_u64_field(
        &mut data,
        b"planned-object-count",
        state.total_objects_to_evacuate,
    );
    data
}

fn evacuation_success_digest_data(state: &DeviceRemovalState) -> Vec<u8> {
    let mut data = removal_state_digest_data(b"evacuation-success", state);
    let outcome = if state.total_objects_to_evacuate == 0 {
        b"empty-evacuation-success".as_slice()
    } else {
        b"all-live-objects-evacuated".as_slice()
    };
    append_vec_field(&mut data, b"evacuation-outcome", outcome);
    append_u64_field(&mut data, b"objects-evacuated", state.objects_evacuated);
    append_u64_field(&mut data, b"objects-failed", state.objects_failed);
    append_u64_field(&mut data, b"bytes-evacuated", state.bytes_evacuated);
    data
}

fn committed_topology_digest_data(
    state: &DeviceRemovalState,
    updated_pool_config: &tidefs_pool_scan::PoolConfig,
) -> Vec<u8> {
    let mut data = removal_state_digest_data(b"committed-topology", state);
    append_u64_field(
        &mut data,
        b"committed-topology-generation",
        updated_pool_config.topology_generation,
    );
    append_u32_field(
        &mut data,
        b"committed-device-count",
        updated_pool_config.device_count,
    );
    append_vec_field(
        &mut data,
        b"committed-topology-root",
        &topology_root_digest(updated_pool_config),
    );
    data
}

fn removed_digest_data(state: &DeviceRemovalState) -> Vec<u8> {
    let mut data = removal_state_digest_data(b"removed", state);
    append_u64_field(&mut data, b"objects-evacuated", state.objects_evacuated);
    append_u64_field(&mut data, b"bytes-evacuated", state.bytes_evacuated);
    data
}

fn refusal_digest_data(evidence: &DeviceRemovalRefusal) -> Vec<u8> {
    let mut data = Vec::new();
    append_vec_field(&mut data, b"evidence-kind", b"removal-refusal");
    append_vec_field(
        &mut data,
        b"failure-class",
        evidence.class.to_string().as_bytes(),
    );
    append_vec_field(
        &mut data,
        b"target-device",
        evidence.target_device.to_string_lossy().as_bytes(),
    );
    append_vec_field(&mut data, b"details", evidence.details.as_bytes());
    if let Some(expected) = evidence.expected_topology_generation {
        append_u64_field(&mut data, b"expected-topology-generation", expected);
    }
    if let Some(observed) = evidence.observed_topology_generation {
        append_u64_field(&mut data, b"observed-topology-generation", observed);
    }
    if let Some(surviving) = evidence.surviving_devices {
        append_u32_field(&mut data, b"surviving-devices", surviving);
    }
    if let Some(required) = evidence.required_surviving_devices {
        append_u32_field(&mut data, b"required-surviving-devices", required);
    }
    data
}

fn removal_state_digest_data(tag: &[u8], state: &DeviceRemovalState) -> Vec<u8> {
    let mut data = Vec::new();
    append_vec_field(&mut data, b"evidence-kind", tag);
    append_vec_field(
        &mut data,
        b"target-device",
        state.target_device.to_string_lossy().as_bytes(),
    );
    append_u32_field(&mut data, b"target-device-id", state.target_device_id);
    append_vec_field(&mut data, b"target-device-guid", &state.target_device_guid);
    append_u32_field(&mut data, b"target-device-index", state.target_device_index);
    append_u32_field(&mut data, b"device-count-before", state.device_count_before);
    append_u64_field(
        &mut data,
        b"target-topology-generation",
        state.target_topology_generation,
    );
    append_vec_field(&mut data, b"evacuation-set", &evacuation_set_digest(state));
    data
}

fn evacuation_set_digest(state: &DeviceRemovalState) -> [u8; 32] {
    let key = blake3::derive_key(
        "TideFS DeviceRemoval Evacuation Set v1",
        &[DEVICE_REMOVAL_DOMAIN_DISCRIMINANT],
    );
    let mut hasher = blake3::Hasher::new_keyed(&key);
    append_hash_field(
        &mut hasher,
        b"target-device-id",
        &state.target_device_id.to_le_bytes(),
    );
    append_hash_field(
        &mut hasher,
        b"target-device-guid",
        &state.target_device_guid,
    );
    append_hash_field(
        &mut hasher,
        b"total-objects",
        &state.total_objects_to_evacuate.to_le_bytes(),
    );
    append_hash_field(
        &mut hasher,
        b"target-topology-generation",
        &state.target_topology_generation.to_le_bytes(),
    );
    *hasher.finalize().as_bytes()
}

fn topology_root_digest(config: &tidefs_pool_scan::PoolConfig) -> [u8; 32] {
    let key = blake3::derive_key(
        "TideFS DeviceRemoval Committed Topology Root v1",
        &[DEVICE_REMOVAL_DOMAIN_DISCRIMINANT],
    );
    let mut hasher = blake3::Hasher::new_keyed(&key);
    append_hash_field(
        &mut hasher,
        b"topology-generation",
        &config.topology_generation.to_le_bytes(),
    );
    append_hash_field(
        &mut hasher,
        b"device-count",
        &config.device_count.to_le_bytes(),
    );
    for leaf in DeviceRemovalPlanner::flatten_leaves(&config.device_tree) {
        append_hash_field(
            &mut hasher,
            b"leaf-path",
            leaf.device_path.to_string_lossy().as_bytes(),
        );
        append_hash_field(&mut hasher, b"leaf-guid", &leaf.device_guid);
        append_hash_field(&mut hasher, b"leaf-index", &leaf.device_index.to_le_bytes());
        append_hash_field(
            &mut hasher,
            b"leaf-capacity",
            &leaf.capacity_bytes.to_le_bytes(),
        );
    }
    *hasher.finalize().as_bytes()
}

fn append_vec_field(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.extend_from_slice(&(name.len() as u64).to_le_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&(value.len() as u64).to_le_bytes());
    out.extend_from_slice(value);
}

fn append_u32_field(out: &mut Vec<u8>, name: &[u8], value: u32) {
    append_vec_field(out, name, &value.to_le_bytes());
}

fn append_u64_field(out: &mut Vec<u8>, name: &[u8], value: u64) {
    append_vec_field(out, name, &value.to_le_bytes());
}

fn append_hash_field(hasher: &mut blake3::Hasher, name: &[u8], value: &[u8]) {
    hasher.update(&(name.len() as u64).to_le_bytes());
    hasher.update(name);
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
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
        tidefs_pool_scan::DeviceType::PoolWideData { children }
        | tidefs_pool_scan::DeviceType::Mirror { children }
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
            redundancy_policy: tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(1),
            device_tree: DeviceType::PoolWideData { children: leaves },
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

    fn assert_refusal_class(
        error: DeviceRemovalError,
        expected: DeviceRemovalRefusalClass,
    ) -> DeviceRemovalRefusal {
        match error {
            DeviceRemovalError::RemovalRefused { evidence } => {
                assert_eq!(evidence.class, expected);
                evidence
            }
            other => panic!("expected {expected} refusal, got {other:?}"),
        }
    }

    /// Mock [`PlacementReceiptChecker`] that returns a fixed set of refs.
    #[derive(Debug)]
    struct MockPlacementReceiptChecker {
        refs: Vec<PlacementReceiptRef>,
    }

    impl PlacementReceiptChecker for MockPlacementReceiptChecker {
        fn receipts_referencing_extents(
            &self,
            _extent_ids: &[ExtentId],
        ) -> Result<Vec<PlacementReceiptRef>, DeviceRemovalError> {
            Ok(self.refs.clone())
        }
    }

    #[derive(Debug)]
    struct ExpectingPlacementReceiptChecker {
        expected_extent_ids: Vec<ExtentId>,
        refs: Vec<PlacementReceiptRef>,
    }

    impl PlacementReceiptChecker for ExpectingPlacementReceiptChecker {
        fn receipts_referencing_extents(
            &self,
            extent_ids: &[ExtentId],
        ) -> Result<Vec<PlacementReceiptRef>, DeviceRemovalError> {
            assert_eq!(extent_ids, self.expected_extent_ids.as_slice());
            Ok(self.refs.clone())
        }
    }

    fn placement_receipt_ref(object_id: u64) -> PlacementReceiptRef {
        PlacementReceiptRef {
            object_id,
            object_key: [object_id as u8; 32],
            receipt_epoch: tidefs_membership_epoch::EpochId(0),
            receipt_generation: object_id.saturating_add(1),
            redundancy_policy: tidefs_replication_model::ReceiptRedundancyPolicy::Replicated {
                copies: 2,
            },
            payload_len: 0,
            payload_digest: [0u8; 32],
            target_count: 0,
        }
    }

    fn attach_empty_receipt_checker(driver: &mut DeviceRemovalDriver) {
        driver
            .set_placement_receipt_checker(Box::new(MockPlacementReceiptChecker { refs: vec![] }));
    }

    fn make_evacuating_driver(total_objects: u64) -> DeviceRemovalDriver {
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let leaf1 = make_leaf("/dev/disk1", 2, 1, 1024, DeviceHealth::Online);
        let config = make_pool_config(vec![leaf0, leaf1]);
        let mut driver = DeviceRemovalDriver::prepare(
            Box::new(NoopAllocationFence::new()),
            Path::new("/dev/disk1"),
            config,
            vec![DeviceId(0)],
            total_objects,
        )
        .unwrap();
        driver.begin_evacuation().unwrap();
        driver
    }

    fn assert_checkpoint_rejected(
        mut driver: DeviceRemovalDriver,
        checkpoint: &EvacuationCheckpoint,
        expected_dest_device_id: DeviceId,
    ) -> DeviceRemovalRefusal {
        let err = driver
            .apply_checkpoint_for_destination(checkpoint, expected_dest_device_id)
            .unwrap_err();
        let evidence =
            assert_refusal_class(err, DeviceRemovalRefusalClass::CheckpointReplayRejected);
        assert_eq!(driver.state().phase, DeviceRemovalPhase::Failed);
        assert_eq!(
            driver.state().failure_evidence.as_ref().map(|e| e.class),
            Some(DeviceRemovalRefusalClass::CheckpointReplayRejected)
        );
        evidence
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
        assert!(state.failure_evidence.is_none());
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
        state.record_object_evacuated(ExtentId::from(1u64), 4096);
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

        state.record_object_evacuated(ExtentId::from(1u64), 100);
        state.record_object_evacuated(ExtentId::from(2u64), 200);
        assert!(state.is_evacuation_complete());
        assert_eq!(state.objects_remaining(), 0);
    }

    #[test]
    fn is_evacuation_complete_with_failures() {
        let mut state =
            DeviceRemovalState::new(PathBuf::from("/dev/disk0"), 0, [0x01u8; 16], 0, 3, 2, 2);
        state.record_object_evacuated(ExtentId::from(1u64), 100);
        state.record_object_failed();
        assert_eq!(state.objects_remaining(), 1);
        assert!(!state.is_evacuation_complete());
    }

    #[test]
    fn objects_remaining_saturates_at_zero() {
        let mut state =
            DeviceRemovalState::new(PathBuf::from("/dev/disk0"), 0, [0x01u8; 16], 0, 3, 1, 2);
        state.record_object_evacuated(ExtentId::from(1u64), 100);
        state.record_object_evacuated(ExtentId::from(1u64), 100); // one extra
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
        let evidence = assert_refusal_class(
            result.unwrap_err(),
            DeviceRemovalRefusalClass::TargetNotFound,
        );
        assert_eq!(evidence.target_device, PathBuf::from("/dev/disk99"));
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
        let evidence = assert_refusal_class(
            result.unwrap_err(),
            DeviceRemovalRefusalClass::WouldEmptyPool,
        );
        assert_eq!(evidence.surviving_devices, Some(0));
        assert_eq!(evidence.required_surviving_devices, Some(1));
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
        let evidence = assert_refusal_class(
            result.unwrap_err(),
            DeviceRemovalRefusalClass::UnhealthyTarget,
        );
        assert_eq!(evidence.target_device, PathBuf::from("/dev/disk0"));
    }

    #[test]
    fn driver_prepare_fails_on_insufficient_surviving_topology() {
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024, DeviceHealth::Online);
        let leaf1 = make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024, DeviceHealth::Online);
        let leaf2 = make_leaf("/dev/disk2", 3, 2, 1024 * 1024 * 1024, DeviceHealth::Online);
        let mut config = make_pool_config(vec![leaf0, leaf1, leaf2]);
        config.redundancy_policy =
            tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(2);

        let result = DeviceRemovalDriver::prepare(
            Box::new(NoopAllocationFence::new()),
            Path::new("/dev/disk1"),
            config,
            vec![DeviceId(0)],
            0,
        );
        let evidence = assert_refusal_class(
            result.unwrap_err(),
            DeviceRemovalRefusalClass::InsufficientSurvivingTopology,
        );
        assert_eq!(evidence.surviving_devices, Some(1));
        assert_eq!(evidence.required_surviving_devices, Some(2));
    }

    #[test]
    fn driver_prepare_fails_on_bad_redundancy_policy() {
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024, DeviceHealth::Online);
        let leaf1 = make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024, DeviceHealth::Online);
        let mut config = make_pool_config(vec![leaf0, leaf1]);
        config.redundancy_policy =
            tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(0);

        let result = DeviceRemovalDriver::prepare(
            Box::new(NoopAllocationFence::new()),
            Path::new("/dev/disk1"),
            config,
            vec![DeviceId(0)],
            0,
        );
        assert_refusal_class(
            result.unwrap_err(),
            DeviceRemovalRefusalClass::DomainConstraintViolation,
        );
    }

    #[test]
    fn driver_prepare_fails_on_stale_topology_generation() {
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024, DeviceHealth::Online);
        let leaf1 = make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024, DeviceHealth::Online);
        let mut config = make_pool_config(vec![leaf0, leaf1]);
        config.topology_generation = 5;

        let result = DeviceRemovalDriver::prepare_with_expected_topology_generation(
            Box::new(NoopAllocationFence::new()),
            Path::new("/dev/disk1"),
            config,
            vec![DeviceId(0)],
            0,
            4,
        );
        let evidence = assert_refusal_class(
            result.unwrap_err(),
            DeviceRemovalRefusalClass::StaleTopologyGeneration,
        );
        assert_eq!(evidence.expected_topology_generation, Some(4));
        assert_eq!(evidence.observed_topology_generation, Some(5));
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
        driver.record_evacuation_receipt(vec![], 0);
        attach_empty_receipt_checker(&mut driver);
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
        assert_refusal_class(
            result.unwrap_err(),
            DeviceRemovalRefusalClass::EvacuationIncomplete,
        );
        assert_eq!(driver.state().phase, DeviceRemovalPhase::Failed);
        assert_eq!(
            driver.state().failure_evidence.as_ref().map(|e| e.class),
            Some(DeviceRemovalRefusalClass::EvacuationIncomplete)
        );
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
        driver.record_evacuation_receipt(vec![], 0);
        attach_empty_receipt_checker(&mut driver);

        // Pass a config that still has disk1
        let still_has_target = make_pool_config(vec![
            make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024, DeviceHealth::Online),
            make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024, DeviceHealth::Online),
        ]);

        let result = driver.commit_vacated(still_has_target);
        assert_refusal_class(
            result.unwrap_err(),
            DeviceRemovalRefusalClass::CommittedTopologyMismatch,
        );
        assert_eq!(driver.state().phase, DeviceRemovalPhase::Failed);
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
        assert_eq!(
            driver.state().failure_evidence.as_ref().map(|e| e.class),
            Some(DeviceRemovalRefusalClass::DomainConstraintViolation)
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
            failure_evidence: None,
            chain_digest: [0xBBu8; 32],
            evacuation_completion_generation: None,
            evacuation_receipt: None,
            evacuated_extent_ids: Vec::new(),
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
            DeviceRemovalError::RemovalRefused {
                evidence: DeviceRemovalRefusal::new(
                    DeviceRemovalRefusalClass::WouldEmptyPool,
                    PathBuf::from("/dev/disk0"),
                    "removal would leave no data device",
                ),
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
            target_device_id: 1,
            target_device_guid: [0x11u8; 16],
            target_topology_generation: 2,
            evacuation_set_digest: [0x22u8; 32],
            removal_chain_digest: [0x33u8; 32],
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
            target_device_id: 7,
            target_device_guid: [0x44u8; 16],
            target_topology_generation: 9,
            evacuation_set_digest: [0x55u8; 32],
            removal_chain_digest: [0x66u8; 32],
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
        driver
            .state
            .record_object_evacuated(ExtentId::from(1u64), 100);
        driver
            .state
            .record_object_evacuated(ExtentId::from(2u64), 200);
        driver.state.record_object_failed();

        let cp = driver.create_checkpoint(DeviceId(5));
        assert_eq!(cp.next_object_index, 3); // 2 evacuated + 1 failed
        assert_eq!(cp.objects_evacuated, 2);
        assert_eq!(cp.objects_failed, 1);
        assert_eq!(cp.bytes_evacuated, 300);
        assert_eq!(cp.dest_device_id, 5);
        assert_eq!(cp.total_objects, 10);
        assert_eq!(cp.target_device_id, 1);
        assert_eq!(cp.target_device_guid, [2u8; 16]);
        assert_eq!(cp.target_topology_generation, 2);
        assert_eq!(
            cp.evacuation_set_digest,
            evacuation_set_digest(driver.state())
        );
        assert_eq!(cp.removal_chain_digest, driver.state().chain_digest);
    }

    #[test]
    fn apply_checkpoint_restores_state() {
        let mut source = make_evacuating_driver(100);
        source
            .state
            .record_object_evacuated(ExtentId::from(1u64), 400);
        source
            .state
            .record_object_evacuated(ExtentId::from(2u64), 600);
        let cp = source.create_checkpoint(DeviceId(0));

        let mut recovered = make_evacuating_driver(100);
        assert_eq!(recovered.state().objects_evacuated, 0);
        assert_eq!(recovered.state().bytes_evacuated, 0);
        assert_eq!(recovered.state().objects_failed, 0);

        recovered.apply_checkpoint(&cp).unwrap();

        assert_eq!(recovered.state().objects_evacuated, 2);
        assert_eq!(recovered.state().bytes_evacuated, 1000);
        assert_eq!(recovered.state().objects_failed, 0);
    }

    #[test]
    fn apply_checkpoint_rejects_failed_progress() {
        let mut source = make_evacuating_driver(100);
        source
            .state
            .record_object_evacuated(ExtentId::from(1u64), 100);
        let mut cp = source.create_checkpoint(DeviceId(0));
        cp.objects_failed = 5;
        cp.next_object_index = cp.objects_evacuated + cp.objects_failed;

        let evidence = assert_checkpoint_rejected(make_evacuating_driver(100), &cp, DeviceId(0));
        assert!(evidence.details.contains("failed object"));
    }

    #[test]
    fn checkpoint_replay_rejects_tampered_identity() {
        let mut source = make_evacuating_driver(10);
        source
            .state
            .record_object_evacuated(ExtentId::from(1u64), 100);
        let base = source.create_checkpoint(DeviceId(0));

        let mut cp = base.clone();
        cp.target_device_id = 99;
        assert_checkpoint_rejected(make_evacuating_driver(10), &cp, DeviceId(0));

        let mut cp = base.clone();
        cp.target_device_guid = [0x99u8; 16];
        assert_checkpoint_rejected(make_evacuating_driver(10), &cp, DeviceId(0));

        let evidence = assert_checkpoint_rejected(make_evacuating_driver(10), &base, DeviceId(1));
        assert!(evidence.details.contains("destination"));

        let mut cp = base.clone();
        cp.total_objects = 11;
        assert_checkpoint_rejected(make_evacuating_driver(10), &cp, DeviceId(0));

        let mut cp = base.clone();
        cp.target_topology_generation += 1;
        assert_checkpoint_rejected(make_evacuating_driver(10), &cp, DeviceId(0));

        let mut cp = base.clone();
        cp.evacuation_set_digest[0] ^= 0x01;
        assert_checkpoint_rejected(make_evacuating_driver(10), &cp, DeviceId(0));

        let mut cp = base.clone();
        cp.removal_chain_digest[0] ^= 0x01;
        assert_checkpoint_rejected(make_evacuating_driver(10), &cp, DeviceId(0));

        let mut cp = base.clone();
        cp.next_object_index += 1;
        assert_checkpoint_rejected(make_evacuating_driver(10), &cp, DeviceId(0));

        let mut cp = base;
        cp.objects_evacuated = cp.total_objects + 1;
        cp.next_object_index = cp.objects_evacuated;
        assert_checkpoint_rejected(make_evacuating_driver(10), &cp, DeviceId(0));
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
        driver.record_evacuation_receipt(vec![], 0);
        attach_empty_receipt_checker(&mut driver);
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

    // ── Evacuation completion generation tests ──────────────────────

    #[test]
    fn completion_generation_recorded_after_evacuation() {
        let mut driver = make_evacuating_driver(2);
        // Evacuate objects.
        driver
            .record_object_evacuated(ExtentId::from(1u64), 100)
            .unwrap();
        driver
            .record_object_evacuated(ExtentId::from(2u64), 200)
            .unwrap();
        assert!(driver.state().is_evacuation_complete());

        // mark_evacuated should record the completion generation.
        driver.mark_evacuated().unwrap();
        assert_eq!(driver.state().phase, DeviceRemovalPhase::Evacuated);

        let completion = driver
            .state()
            .evacuation_completion_generation()
            .expect("completion generation must be recorded");
        assert_eq!(
            completion.target_device_guid,
            driver.state().target_device_guid
        );
        assert_eq!(
            completion.target_topology_generation,
            driver.state().target_topology_generation
        );
        // The completion should have a non-zero chain digest.
        let nonzero = completion.removal_chain_digest.iter().any(|&b| b != 0);
        assert!(nonzero, "chain digest must be non-zero");

        // Status should be CompletionNotDurable (not yet committed).
        assert_eq!(driver.status(), DeviceRemovalStatus::CompletionNotDurable);
    }

    #[test]
    fn commit_vacated_rejects_missing_completion() {
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
        driver.begin_evacuation().unwrap();
        driver.mark_evacuated().unwrap();
        driver.record_evacuation_receipt(vec![], 0);

        // Manually clear the completion generation to simulate
        // a state that was deserialized without it (pre-this-issue data).
        driver.state.evacuation_completion_generation = None;

        let leaf0_after = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let mut updated = make_pool_config(vec![leaf0_after]);
        updated.topology_generation = 2;

        let err = driver.commit_vacated(updated).unwrap_err();
        let evidence = assert_refusal_class(
            err,
            DeviceRemovalRefusalClass::EvacuationCompletionNotDurable,
        );
        assert!(
            evidence
                .details
                .contains("completion generation is missing"),
            "details must mention missing completion"
        );
        assert_eq!(driver.state().phase, DeviceRemovalPhase::Failed);
    }

    #[test]
    fn mark_removed_rejects_missing_completion() {
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
        driver.begin_evacuation().unwrap();
        driver.mark_evacuated().unwrap();
        driver.record_evacuation_receipt(vec![], 0);
        attach_empty_receipt_checker(&mut driver);

        let leaf0_after = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let mut updated = make_pool_config(vec![leaf0_after]);
        updated.topology_generation = 2;
        driver.commit_vacated(updated).unwrap();

        // Clear the completion generation to simulate deserialized
        // state without durable evidence.
        driver.state.evacuation_completion_generation = None;

        let err = driver.mark_removed().unwrap_err();
        let evidence = assert_refusal_class(
            err,
            DeviceRemovalRefusalClass::EvacuationCompletionNotDurable,
        );
        assert!(
            evidence
                .details
                .contains("completion generation is missing"),
            "details must mention missing completion"
        );
        assert_eq!(driver.state().phase, DeviceRemovalPhase::Failed);
    }

    #[test]
    fn completion_mismatched_evacuation_set_rejected() {
        let mut driver = make_evacuating_driver(1);
        driver
            .record_object_evacuated(ExtentId::from(1u64), 100)
            .unwrap();
        driver.mark_evacuated().unwrap();
        driver.record_evacuation_receipt(vec![], 0);

        // Tamper with the completion generation set digest.
        if let Some(ref mut completion) = driver.state.evacuation_completion_generation {
            completion.evacuation_set_digest = [0xFFu8; 32];
        }

        let leaf0_after = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let mut updated = make_pool_config(vec![leaf0_after]);
        updated.topology_generation = 2;

        let err = driver.commit_vacated(updated).unwrap_err();
        let evidence =
            assert_refusal_class(err, DeviceRemovalRefusalClass::EvacuationCompletionMismatch);
        assert!(
            evidence
                .details
                .contains("evacuation set digest does not match"),
            "details must mention set digest mismatch"
        );
        assert_eq!(driver.state().phase, DeviceRemovalPhase::Failed);
    }

    #[test]
    fn completion_stale_topology_rejected_in_mark_removed() {
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
        driver.begin_evacuation().unwrap();
        driver.mark_evacuated().unwrap();
        driver.record_evacuation_receipt(vec![], 0);
        attach_empty_receipt_checker(&mut driver);

        let leaf0_after = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let mut updated = make_pool_config(vec![leaf0_after]);
        updated.topology_generation = 2;
        driver.commit_vacated(updated).unwrap();

        // Tamper with the completion generation topology.
        if let Some(ref mut completion) = driver.state.evacuation_completion_generation {
            completion.target_topology_generation = 99;
        }

        let err = driver.mark_removed().unwrap_err();
        let evidence =
            assert_refusal_class(err, DeviceRemovalRefusalClass::EvacuationCompletionMismatch);
        assert!(
            evidence.details.contains("topology"),
            "details must mention topology mismatch"
        );
        assert_eq!(driver.state().phase, DeviceRemovalPhase::Failed);
    }

    #[test]
    fn completion_status_transitions_through_phases() {
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

        // Removing phase: evacuation in progress.
        assert_eq!(driver.status(), DeviceRemovalStatus::EvacuationInProgress);

        driver.begin_evacuation().unwrap();
        // Evacuating phase: still in progress.
        assert_eq!(driver.status(), DeviceRemovalStatus::EvacuationInProgress);

        driver
            .record_object_evacuated(ExtentId::from(1u64), 100)
            .unwrap();
        driver.mark_evacuated().unwrap();
        driver.record_evacuation_receipt(vec![], 0);
        attach_empty_receipt_checker(&mut driver);
        // Evacuated phase: not yet durable.
        assert_eq!(driver.status(), DeviceRemovalStatus::CompletionNotDurable);

        let leaf0_after = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let mut updated = make_pool_config(vec![leaf0_after]);
        updated.topology_generation = 2;
        driver.commit_vacated(updated).unwrap();
        // Vacated phase with matching topology: ready for retirement.
        assert_eq!(driver.status(), DeviceRemovalStatus::LabelRetirementReady);

        driver.mark_removed().unwrap();
        // Removed phase: still LabelRetirementReady.
        assert_eq!(driver.status(), DeviceRemovalStatus::LabelRetirementReady);
    }

    #[test]
    fn replay_after_evacuation_recovers_completion() {
        // Simulate crash after mark_evacuated but before commit_vacated.
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let leaf1 = make_leaf("/dev/disk1", 2, 1, 1024, DeviceHealth::Online);
        let config = make_pool_config(vec![leaf0, leaf1]);
        let mut driver = DeviceRemovalDriver::prepare(
            Box::new(NoopAllocationFence::new()),
            Path::new("/dev/disk1"),
            config.clone(),
            vec![DeviceId(0)],
            0,
        )
        .unwrap();
        driver.begin_evacuation().unwrap();
        driver.mark_evacuated().unwrap();

        // Serialize state (simulating persistence).
        let serialized = driver.serialize_state().unwrap();

        // Deserialize into a new state (simulating pool import after crash).
        let recovered_state = DeviceRemovalDriver::deserialize_state(&serialized).unwrap();
        assert_eq!(recovered_state.phase, DeviceRemovalPhase::Evacuated);
        assert!(
            recovered_state.evacuation_completion_generation.is_some(),
            "completion generation must survive serialization roundtrip"
        );

        // Resume the driver from the recovered state.
        let mut resumed = DeviceRemovalDriver::resume(
            Box::new(NoopAllocationFence::new()),
            recovered_state,
            config,
            vec![DeviceId(0)],
        );

        // Status should be CompletionNotDurable (in Evacuated phase).
        assert_eq!(resumed.status(), DeviceRemovalStatus::CompletionNotDurable);

        // The resumed driver can continue to commit_vacated.
        let leaf0_after = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let mut updated = make_pool_config(vec![leaf0_after]);
        updated.topology_generation = 2;
        resumed.record_evacuation_receipt(vec![], 0);
        attach_empty_receipt_checker(&mut resumed);
        resumed.commit_vacated(updated).unwrap();
        assert_eq!(resumed.state().phase, DeviceRemovalPhase::Vacated);

        resumed.mark_removed().unwrap();
        assert_eq!(resumed.state().phase, DeviceRemovalPhase::Removed);
    }

    #[test]
    fn replay_uses_receipt_refs_for_placement_check_extent_ids() {
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let leaf1 = make_leaf("/dev/disk1", 2, 1, 1024, DeviceHealth::Online);
        let config = make_pool_config(vec![leaf0, leaf1]);
        let mut driver = DeviceRemovalDriver::prepare(
            Box::new(NoopAllocationFence::new()),
            Path::new("/dev/disk1"),
            config.clone(),
            vec![DeviceId(0)],
            1,
        )
        .unwrap();
        driver.begin_evacuation().unwrap();
        driver
            .record_object_evacuated(ExtentId::from(42u64), 4096)
            .unwrap();
        driver.mark_evacuated().unwrap();

        let serialized = driver.serialize_state().unwrap();
        let recovered_state = DeviceRemovalDriver::deserialize_state(&serialized).unwrap();
        assert!(
            recovered_state.evacuated_extent_ids.is_empty(),
            "serialized recovery intentionally drops in-memory extent ids"
        );

        let mut resumed = DeviceRemovalDriver::resume(
            Box::new(NoopAllocationFence::new()),
            recovered_state,
            config,
            vec![DeviceId(0)],
        );
        resumed.record_evacuation_receipt(vec![placement_receipt_ref(42)], 7);
        resumed.set_placement_receipt_checker(Box::new(ExpectingPlacementReceiptChecker {
            expected_extent_ids: vec![ExtentId::from(42u64)],
            refs: vec![],
        }));

        let leaf0_after = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let mut updated = make_pool_config(vec![leaf0_after]);
        updated.topology_generation = 2;
        resumed.commit_vacated(updated).unwrap();
        assert_eq!(resumed.state().phase, DeviceRemovalPhase::Vacated);
    }

    #[test]
    fn replay_rejects_missing_checkable_extent_identity() {
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let leaf1 = make_leaf("/dev/disk1", 2, 1, 1024, DeviceHealth::Online);
        let config = make_pool_config(vec![leaf0, leaf1]);
        let mut driver = DeviceRemovalDriver::prepare(
            Box::new(NoopAllocationFence::new()),
            Path::new("/dev/disk1"),
            config.clone(),
            vec![DeviceId(0)],
            1,
        )
        .unwrap();
        driver.begin_evacuation().unwrap();
        driver
            .record_object_evacuated(ExtentId::from(42u64), 4096)
            .unwrap();
        driver.mark_evacuated().unwrap();

        let serialized = driver.serialize_state().unwrap();
        let recovered_state = DeviceRemovalDriver::deserialize_state(&serialized).unwrap();
        let mut resumed = DeviceRemovalDriver::resume(
            Box::new(NoopAllocationFence::new()),
            recovered_state,
            config,
            vec![DeviceId(0)],
        );
        resumed.record_evacuation_receipt(vec![], 7);
        attach_empty_receipt_checker(&mut resumed);

        let leaf0_after = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let mut updated = make_pool_config(vec![leaf0_after]);
        updated.topology_generation = 2;
        let err = resumed.commit_vacated(updated).unwrap_err();
        let evidence = assert_refusal_class(
            err,
            DeviceRemovalRefusalClass::PlacementReceiptsStillReferenceDevice,
        );
        assert!(
            evidence
                .details
                .contains("evacuated extent identity is missing after replay"),
            "details must mention missing replay extent identity"
        );
        assert_eq!(resumed.state().phase, DeviceRemovalPhase::Failed);
    }
    // ── Evacuation receipt gating tests ─────────────────────────────

    #[test]
    fn evacuation_receipt_digest_verifies() {
        let completion = EvacuationCompletionGeneration {
            target_device_guid: [0xAAu8; 16],
            target_topology_generation: 7,
            evacuation_set_digest: [0xBBu8; 32],
            removal_chain_digest: [0xCCu8; 32],
        };
        let receipt = EvacuationReceipt::new(completion.clone(), vec![], 1);
        assert!(
            receipt.verify_digest(),
            "fresh receipt must verify its own digest"
        );

        // Tamper with the receipt_id and check that the digest no longer matches.
        let mut tampered = receipt.clone();
        tampered.receipt_id = 42;
        assert!(
            !tampered.verify_digest(),
            "tampered receipt_id must invalidate digest"
        );

        // Tamper with placement_receipt_refs.
        let mut tampered2 = receipt.clone();
        tampered2.placement_receipt_refs = vec![PlacementReceiptRef {
            object_id: 1,
            object_key: [0x01u8; 32],
            receipt_epoch: tidefs_membership_epoch::EpochId(0),
            receipt_generation: 1,
            redundancy_policy: tidefs_replication_model::ReceiptRedundancyPolicy::Replicated {
                copies: 2,
            },
            payload_len: 0,
            payload_digest: [0u8; 32],
            target_count: 0,
        }];
        assert!(
            !tampered2.verify_digest(),
            "tampered placement_receipt_refs must invalidate digest"
        );

        let receipt_with_ref =
            EvacuationReceipt::new(completion, vec![placement_receipt_ref(9)], 2);
        let mut tampered_object_id = receipt_with_ref.clone();
        tampered_object_id.placement_receipt_refs[0].object_id = 10;
        assert!(
            !tampered_object_id.verify_digest(),
            "tampered placement receipt object_id must invalidate digest"
        );
    }

    #[test]
    fn commit_vacated_rejects_missing_evacuation_receipt() {
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
        driver.begin_evacuation().unwrap();
        driver.mark_evacuated().unwrap();
        // Completion generation is recorded by mark_evacuated, but we do NOT
        // call record_evacuation_receipt — receipt is intentionally missing.

        let leaf0_after = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let mut updated = make_pool_config(vec![leaf0_after]);
        updated.topology_generation = 2;

        let err = driver.commit_vacated(updated).unwrap_err();
        let evidence = assert_refusal_class(
            err,
            DeviceRemovalRefusalClass::EvacuationCompletionNotDurable,
        );
        assert!(
            evidence.details.contains("evacuation receipt is missing"),
            "details must mention missing evacuation receipt"
        );
        assert_eq!(driver.state().phase, DeviceRemovalPhase::Failed);
    }

    #[test]
    fn mark_removed_rejects_missing_evacuation_receipt() {
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
        driver.begin_evacuation().unwrap();
        driver.mark_evacuated().unwrap();
        driver.record_evacuation_receipt(vec![], 0);
        attach_empty_receipt_checker(&mut driver);

        let leaf0_after = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let mut updated = make_pool_config(vec![leaf0_after]);
        updated.topology_generation = 2;
        driver.commit_vacated(updated).unwrap();

        // Clear the evacuation receipt to simulate state where it was lost.
        driver.state.evacuation_receipt = None;

        let err = driver.mark_removed().unwrap_err();
        let evidence = assert_refusal_class(
            err,
            DeviceRemovalRefusalClass::EvacuationCompletionNotDurable,
        );
        assert!(
            evidence.details.contains("evacuation receipt is missing"),
            "details must mention missing evacuation receipt"
        );
        assert_eq!(driver.state().phase, DeviceRemovalPhase::Failed);
    }

    #[test]
    fn commit_vacated_rejects_missing_placement_receipt_checker() {
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
        driver.begin_evacuation().unwrap();
        driver.mark_evacuated().unwrap();
        driver.record_evacuation_receipt(vec![], 0);

        let leaf0_after = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let mut updated = make_pool_config(vec![leaf0_after]);
        updated.topology_generation = 2;

        let err = driver.commit_vacated(updated).unwrap_err();
        let evidence = assert_refusal_class(
            err,
            DeviceRemovalRefusalClass::PlacementReceiptsStillReferenceDevice,
        );
        assert!(
            evidence
                .details
                .contains("placement receipt checker is missing"),
            "details must mention missing placement checker"
        );
        assert_eq!(driver.state().phase, DeviceRemovalPhase::Failed);
    }

    #[test]
    fn mark_removed_rejects_missing_placement_receipt_checker() {
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
        driver.begin_evacuation().unwrap();
        driver.mark_evacuated().unwrap();
        driver.record_evacuation_receipt(vec![], 0);
        attach_empty_receipt_checker(&mut driver);

        let leaf0_after = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let mut updated = make_pool_config(vec![leaf0_after]);
        updated.topology_generation = 2;
        driver.commit_vacated(updated).unwrap();

        driver.placement_receipt_checker = None;

        let err = driver.mark_removed().unwrap_err();
        let evidence = assert_refusal_class(
            err,
            DeviceRemovalRefusalClass::PlacementReceiptsStillReferenceDevice,
        );
        assert!(
            evidence
                .details
                .contains("placement receipt checker is missing"),
            "details must mention missing placement checker"
        );
        assert_eq!(driver.state().phase, DeviceRemovalPhase::Failed);
    }

    #[test]
    fn placement_receipt_checker_blocks_commit_vacated() {
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
        driver.begin_evacuation().unwrap();
        driver.mark_evacuated().unwrap();
        driver.record_evacuation_receipt(vec![], 0);

        // Install a checker that reports references still exist.
        driver.set_placement_receipt_checker(Box::new(MockPlacementReceiptChecker {
            refs: vec![PlacementReceiptRef {
                object_id: 1,
                object_key: [0x01u8; 32],
                receipt_epoch: tidefs_membership_epoch::EpochId(0),
                receipt_generation: 1,
                redundancy_policy: tidefs_replication_model::ReceiptRedundancyPolicy::Replicated {
                    copies: 2,
                },
                payload_len: 0,
                payload_digest: [0u8; 32],
                target_count: 0,
            }],
        }));

        let leaf0_after = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let mut updated = make_pool_config(vec![leaf0_after]);
        updated.topology_generation = 2;

        let err = driver.commit_vacated(updated).unwrap_err();
        let evidence = assert_refusal_class(
            err,
            DeviceRemovalRefusalClass::PlacementReceiptsStillReferenceDevice,
        );
        assert!(
            evidence
                .details
                .contains("placement receipts still reference the target device"),
            "details must mention placement receipts still referencing device"
        );
        assert_eq!(driver.state().phase, DeviceRemovalPhase::Failed);
    }

    #[test]
    fn placement_receipt_checker_blocks_mark_removed() {
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
        driver.begin_evacuation().unwrap();
        driver.mark_evacuated().unwrap();
        driver.record_evacuation_receipt(vec![], 0);
        attach_empty_receipt_checker(&mut driver);

        let leaf0_after = make_leaf("/dev/disk0", 1, 0, 1024, DeviceHealth::Online);
        let mut updated = make_pool_config(vec![leaf0_after]);
        updated.topology_generation = 2;
        driver.commit_vacated(updated).unwrap();

        // Install a checker that reports references still exist.
        driver.set_placement_receipt_checker(Box::new(MockPlacementReceiptChecker {
            refs: vec![PlacementReceiptRef {
                object_id: 1,
                object_key: [0x01u8; 32],
                receipt_epoch: tidefs_membership_epoch::EpochId(0),
                receipt_generation: 1,
                redundancy_policy: tidefs_replication_model::ReceiptRedundancyPolicy::Replicated {
                    copies: 2,
                },
                payload_len: 0,
                payload_digest: [0u8; 32],
                target_count: 0,
            }],
        }));

        let err = driver.mark_removed().unwrap_err();
        let evidence = assert_refusal_class(
            err,
            DeviceRemovalRefusalClass::PlacementReceiptsStillReferenceDevice,
        );
        assert!(
            evidence
                .details
                .contains("placement receipts still reference the target device"),
            "details must mention placement receipts still referencing device"
        );
        assert_eq!(driver.state().phase, DeviceRemovalPhase::Failed);
    }
}
