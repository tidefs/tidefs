// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Dataset lifecycle runtime state machine.
//!
//! Wraps [`tidefs_types_dataset_lifecycle_core::DatasetStateV1`] with
//! validated state transitions, mount-time gating, foundational poison
//! primitives, GC pin-set integration, and destroy job tracking.
//! Implements Phases 2 (runtime state machine) and 4 (pinned traversal
//! roots) from the canonical
//! design spec at [`docs/design/dataset-lifecycle-state-machine.md`],
//! closing Forgejo issues #1431, #1439, #1452, and #1454.
//!
//! Phases 5 (destroy worker block traversal) and
//! 7 (cluster consensus integration) are deferred to wire-up issues per
//! [#1938](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1938).
//!
//! # Comparison to ZFS / Ceph
//!
//! - **ZFS**: Destroy is immediate via `zfs destroy` — blocks commit_group commit
//!   pipeline, no abort capability, no tombstone phase.
//! - **Ceph**: Pool deletion is a monitor flag; no explicit state machine.
//!
//! TideFS separates lifecycle from space reclamation with an explicit
//! ACTIVE → DESTROYING → TOMBSTONE state machine, poison gating, and
//! admin abort recovery.
//!
//! Foundational destroy worker tracking types (`DestroyJobRecordV1`)
//! are defined in `tidefs-types-dataset-lifecycle-core` and integrated
//! here. The full async destroy worker runtime (Phase 5) is deferred to
//! a wire-up issue.
//!
//! [`docs/design/dataset-lifecycle-state-machine.md`]:
//!     https://forgejo/forgeadmin/tidefs/docs/design/dataset-lifecycle-state-machine.md

use core::fmt;

#[cfg(feature = "alloc")]
extern crate alloc;

use tidefs_types_dataset_lifecycle_core::{
    validate_transition as core_validate_transition, DatasetOpenResult, DatasetStateV1,
    DestroyFlags, DestroyJobRecordV1, ReapEligibility, TombstoneReaperPolicy,
    DEFAULT_DESTROY_GRACE_SECS, DEFAULT_TOMBSTONE_MIN_AGE_COMMIT_GROUPS,
};

pub use tidefs_types_dataset_lifecycle_core::{
    BlockPointer, PoisonReason, PoisonState, TraversalRoot, TraversalRootType,
};

pub use tidefs_dataset_catalog::{
    CatalogError, DatasetCatalog, DatasetFlags, DatasetId, DatasetType, SyncGuarantee,
};

#[cfg(feature = "alloc")]
use tidefs_derived_catalog::DerivedCatalog;

// ---------------------------------------------------------------------------
// LifecycleError — transition and precondition errors
// ---------------------------------------------------------------------------

// Re-export PoisonNotification when alloc is available.
#[cfg(feature = "alloc")]
pub use notification::PoisonNotification;
#[cfg(feature = "alloc")]
pub mod consensus;
#[cfg(feature = "alloc")]
pub mod destroy_worker;

#[cfg(feature = "alloc")]
pub use tidefs_gc_pin_set::GcPinSet;
use tidefs_types_dataset_lifecycle_core::MAX_TRAVERSAL_ROOTS;

#[cfg(feature = "alloc")]
pub type DatasetChildEntry = (
    alloc::string::String,
    DatasetId,
    DatasetType,
    u64,
    DatasetFlags,
);

#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotAnchorCreate {
    pub clone_dataset_id: DatasetId,
    pub origin_dataset_id: DatasetId,
    pub snapshot_name: alloc::string::String,
    pub committed_root_txg: u64,
    pub root_handle: u64,
    pub creation_commit_group: u64,
    pub created_at_secs: u64,
}

/// Errors from lifecycle state transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleError {
    /// The requested transition is structurally invalid per the state
    /// machine rules (e.g., Active → Tombstone, Tombstone → Destroying).
    InvalidTransition {
        from: DatasetStateV1,
        to: DatasetStateV1,
    },
    /// Dataset is already in the requested target state (idempotent check).
    AlreadyInState { state: DatasetStateV1 },
    /// A precondition was not satisfied (e.g., dataset has clone children
    /// pointing at it as origin).
    PreconditionFailed {
        from: DatasetStateV1,
        to: DatasetStateV1,
        reason: &'static str,
    },
    /// The dataset has been poisoned and cannot accept state transitions
    /// until the poison is cleared.
    Poisoned { poison: PoisonState },
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LifecycleError::InvalidTransition { from, to } => {
                write!(
                    f,
                    "invalid lifecycle transition {} -> {}",
                    from.label(),
                    to.label()
                )
            }
            LifecycleError::AlreadyInState { state } => {
                write!(f, "dataset already in {} state", state.label())
            }
            LifecycleError::PreconditionFailed { from, to, reason } => {
                write!(
                    f,
                    "precondition failed for {} -> {}: {}",
                    from.label(),
                    to.label(),
                    reason
                )
            }
            LifecycleError::Poisoned { poison } => {
                write!(f, "dataset is poisoned ({poison})")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BackgroundService — identifies a background service for pin attribution
// ---------------------------------------------------------------------------

/// Identifies a background service for pin attribution and statistics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum BackgroundService {
    /// Dataset destroy worker traversing object graphs.
    Destroy = 0x01,
    /// Data cleaner reclaiming dead extents.
    Cleanup = 0x02,
    /// Scrub worker verifying object integrity.
    Scrub = 0x03,
    /// Compaction service rewriting derived catalogs.
    Compaction = 0x04,
    /// View builder constructing derived catalog views.
    ViewBuilder = 0x05,
    /// Defragmentation service relocating extents.
    Defrag = 0x06,
    /// Rebuild/backfill service restoring redundancy.
    Rebuild = 0x07,
}

impl fmt::Display for BackgroundService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackgroundService::Destroy => write!(f, "destroy"),
            BackgroundService::Cleanup => write!(f, "cleanup"),
            BackgroundService::Scrub => write!(f, "scrub"),
            BackgroundService::Compaction => write!(f, "compaction"),
            BackgroundService::ViewBuilder => write!(f, "view-builder"),
            BackgroundService::Defrag => write!(f, "defrag"),
            BackgroundService::Rebuild => write!(f, "rebuild"),
        }
    }
}

// ---------------------------------------------------------------------------
// DatasetLifecycleStats — pin and lifecycle statistics
// ---------------------------------------------------------------------------

/// Statistics for the dataset lifecycle, including active pins.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DatasetLifecycleStats {
    /// Current lifecycle state.
    pub state: DatasetStateV1,
    /// Current poison state.
    pub poison: PoisonState,
    /// Number of active pins across all roots and services.
    pub active_pins: usize,
    /// Number of distinct root types with at least one active pin.
    pub distinct_pinned_roots: usize,
    /// Per-root pin counts, indexed by TraversalRootType discriminant (1-6).
    pub per_root_pins: [u32; 7],
    /// Whether a destroy job is in progress.
    pub destroy_in_progress: bool,
    /// Destroy progress in parts-per-million (0-1,000,000).
    pub destroy_progress_ppm: u64,
}

// ---------------------------------------------------------------------------
// PinnedRoot — handle returned by pin_root_for_service
// ---------------------------------------------------------------------------

/// A pinned traversal root handle.
///
/// Created by [`DatasetLifecycle::pin_root_for_service()`].
/// Callers **must** call [`DatasetLifecycle::release_pin()`] to release
/// the pin when traversal is complete; the handle does NOT auto-release on
/// drop (explicit release gives the caller control over pin lifetime and
/// avoids lifetime coupling between the handle and the lifecycle).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinnedRoot {
    root: TraversalRoot,
    service: BackgroundService,
}

impl PinnedRoot {
    /// The full traversal root this pin protects.
    #[must_use]
    pub fn root(&self) -> TraversalRoot {
        self.root
    }

    /// The root type this pin protects.
    #[must_use]
    pub fn root_type(&self) -> TraversalRootType {
        self.root.root_type
    }

    /// The service that acquired this pin.
    #[must_use]
    pub fn service(&self) -> BackgroundService {
        self.service
    }
}

// ---------------------------------------------------------------------------
// DatasetLifecycle — runtime state machine
// ---------------------------------------------------------------------------

/// Runtime wrapper around [`DatasetStateV1`] that enforces the lifecycle
/// state machine and manages poison state for in-flight mounts.
///
/// # State machine
///
/// ```text
/// Active ──► Destroying ──► Tombstone
///   ▲             │              │
///   │   abort     │              │ recovery
///   └─────────────┘              │
///                                ▼
///                            (deleted by reaper)
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatasetLifecycle {
    state: DatasetStateV1,
    poison: PoisonState,
    grace_secs: u32,
    #[cfg(feature = "alloc")]
    notification: PoisonNotification,
    #[cfg(feature = "alloc")]
    gc_pin_set: GcPinSet<MAX_TRAVERSAL_ROOTS>,
    /// Destroy job state — only valid when in DESTROYING or just-entered TOMBSTONE.
    destroy_job: Option<DestroyJobRecordV1>,
    /// Tombstone reaper configuration.
    reaper_policy: TombstoneReaperPolicy,
    tombstone_consensus_granted: bool,
    /// Derived-catalog for clone/origin registration (issue #5215).
    #[cfg(feature = "alloc")]
    derived_catalog: DerivedCatalog,
    /// Whether the dataset is frozen for consistent snapshot capture.
    /// When frozen, writes are rejected and the committed root is stable
    /// for snapshot anchoring.
    frozen: bool,
}

// ---------------------------------------------------------------------------
// DatasetHandle --- returned by DatasetLifecycle::create()
// ---------------------------------------------------------------------------

/// Handle returned when a new dataset is created.
///
/// Carries the stable [`DatasetId`] plus the initial lifecycle state so
/// callers can immediately mount or configure the new dataset without a
/// second catalog lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatasetHandle {
    /// Stable dataset identifier (UUID).
    pub dataset_id: DatasetId,
    /// Full hierarchical path in the catalog.
    pub path: alloc::string::String,
    /// Dataset class.
    pub dataset_type: DatasetType,
    /// Creation transaction group.
    pub creation_commit_group: u64,
    /// Initial lifecycle state (always `Active`).
    pub lifecycle: DatasetLifecycle,
}

impl DatasetLifecycle {
    /// Create a new lifecycle in Active state with MountOk poison.
    #[must_use]
    pub fn new() -> Self {
        DatasetLifecycle {
            state: DatasetStateV1::Active,
            poison: PoisonState::MountOk,
            grace_secs: DEFAULT_DESTROY_GRACE_SECS,
            #[cfg(feature = "alloc")]
            notification: PoisonNotification::new(),
            #[cfg(feature = "alloc")]
            gc_pin_set: GcPinSet::<MAX_TRAVERSAL_ROOTS>::default(),
            destroy_job: None,
            reaper_policy: TombstoneReaperPolicy::default(),
            tombstone_consensus_granted: false,
            #[cfg(feature = "alloc")]
            derived_catalog: DerivedCatalog::new(),
            frozen: false,
        }
    }

    /// Create a lifecycle from an existing state and poison state.
    /// Used for recovery: restore from on-disk state after crash.
    #[must_use]
    pub fn from_parts(state: DatasetStateV1, poison: PoisonState) -> Self {
        DatasetLifecycle {
            state,
            poison,
            grace_secs: DEFAULT_DESTROY_GRACE_SECS,
            #[cfg(feature = "alloc")]
            notification: PoisonNotification::with_state(poison),
            #[cfg(feature = "alloc")]
            gc_pin_set: GcPinSet::<MAX_TRAVERSAL_ROOTS>::default(),
            destroy_job: None,
            reaper_policy: TombstoneReaperPolicy::default(),
            tombstone_consensus_granted: false,
            #[cfg(feature = "alloc")]
            derived_catalog: DerivedCatalog::new(),
            frozen: false,
        }
    }

    /// Set the poison grace period in seconds.
    #[must_use]
    pub const fn with_grace_secs(mut self, secs: u32) -> Self {
        self.grace_secs = secs;
        self
    }

    // -- Accessors --

    /// Current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> DatasetStateV1 {
        self.state
    }

    /// Current poison state.
    #[must_use]
    pub const fn poison_state(&self) -> PoisonState {
        self.poison
    }

    /// Grace period in seconds.
    #[must_use]
    pub const fn grace_secs(&self) -> u32 {
        self.grace_secs
    }

    // -- Reaper policy (Phase 6) --

    /// Get the reaper policy.
    #[must_use]
    pub const fn reaper_policy(&self) -> &TombstoneReaperPolicy {
        &self.reaper_policy
    }

    /// Set the reaper policy.
    pub fn set_reaper_policy(&mut self, policy: TombstoneReaperPolicy) {
        self.reaper_policy = policy;
    }

    /// Check whether this tombstone dataset is eligible for reaping.
    #[must_use]
    pub fn is_reap_eligible(&self, current_commit_group: u64) -> ReapEligibility {
        if !self.state.is_terminal() {
            return ReapEligibility::Eligible;
        }
        if let Some(ref job) = self.destroy_job {
            if job.is_completed() {
                let age_commit_groups =
                    current_commit_group.saturating_sub(job.completion_commit_group);
                if age_commit_groups < DEFAULT_TOMBSTONE_MIN_AGE_COMMIT_GROUPS {
                    return ReapEligibility::TooYoung {
                        age_commit_groups,
                        required: DEFAULT_TOMBSTONE_MIN_AGE_COMMIT_GROUPS,
                    };
                }
                if !self.cluster_consensus_granted() {
                    return ReapEligibility::ConsensusPending;
                }
                return ReapEligibility::Eligible;
            }
            return ReapEligibility::TooYoung {
                age_commit_groups: 0,
                required: DEFAULT_TOMBSTONE_MIN_AGE_COMMIT_GROUPS,
            };
        }
        ReapEligibility::Eligible
    }

    /// Mark that cluster consensus has been granted for this tombstone.
    /// Called by the cluster GC layer once a quorum of cohort members
    /// acknowledges the tombstone.
    pub fn set_cluster_consensus_granted(&mut self) {
        self.tombstone_consensus_granted = true;
    }

    /// Whether cluster consensus has been granted for this tombstone.
    #[must_use]
    pub fn cluster_consensus_granted(&self) -> bool {
        self.tombstone_consensus_granted
    }

    /// Reap the tombstone: clear the destroy job and prepare for catalog removal.
    ///
    /// # Errors
    /// -  if the dataset is not in Tombstone state.
    pub fn reap_tombstone(
        &mut self,
    ) -> Result<(), tidefs_types_dataset_lifecycle_core::LifecycleError> {
        use tidefs_types_dataset_lifecycle_core::LifecycleError as CoreError;
        if self.state != DatasetStateV1::Tombstone {
            return Err(CoreError::NotTombstone { actual: self.state });
        }
        self.destroy_job = None;
        Ok(())
    }

    // -- Destroy job state (Phase 5) --

    /// Accessor for the current destroy job record, if any.
    ///
    /// Returns `None` if no destroy job has been initialised or if the
    /// dataset is in Active state.
    #[must_use]
    pub fn destroy_job(&self) -> Option<&DestroyJobRecordV1> {
        self.destroy_job.as_ref()
    }

    /// Initialise the destroy job record with pinned traversal roots and
    /// object count. Must be called after `transition_to_destroying()` with the same `pinned_roots` slice
    /// (while in DESTROYING state) and before the destroy worker begins
    /// walking.
    ///
    /// Returns `None` if the dataset is not in DESTROYING state or if
    /// the pinned roots array exceeds [`MAX_TRAVERSAL_ROOTS`].
    #[must_use]
    pub fn init_destroy_job(
        &mut self,
        job_id: u64,
        commit_group: u64,
        flags: DestroyFlags,
        pinned_roots: &[TraversalRoot],
        objects_total: u64,
    ) -> Option<&DestroyJobRecordV1> {
        if self.state != DatasetStateV1::Destroying {
            return None;
        }
        let job =
            DestroyJobRecordV1::new(job_id, commit_group, flags, pinned_roots, objects_total)?;
        self.destroy_job = Some(job);
        self.destroy_job.as_ref()
    }

    /// Update destroy progress with the number of objects and bytes
    /// reclaimed so far. Called periodically by the destroy worker.
    ///
    /// Returns `true` if the job is now complete (all objects reclaimed).
    #[must_use]
    pub fn update_destroy_progress(
        &mut self,
        objects_reclaimed: u64,
        bytes_reclaimed: u64,
    ) -> bool {
        if let Some(ref mut job) = self.destroy_job {
            job.objects_reclaimed = objects_reclaimed;
            job.bytes_reclaimed = bytes_reclaimed;
            if objects_reclaimed >= job.objects_total && job.objects_total > 0 {
                job.completion_commit_group = job.destroy_commit_group;
                return true;
            }
        }
        false
    }

    /// Returns the destroy progress in parts-per-million (0–1,000,000).
    ///
    /// 0 = no progress, 1,000,000 = complete.
    /// Returns 0 if no destroy job exists.
    #[must_use]
    pub fn destroy_progress_ppm(&self) -> u64 {
        self.destroy_job
            .as_ref()
            .map_or(0, |job| job.progress_ppm())
    }

    /// Whether all pinned traversal roots have been marked as walked.
    ///
    /// This is a coarse completion signal: the destroy worker pins each
    /// root, walks it, and calls `unpin_root()` when done. When all
    /// roots are unpinned, traversal is complete.
    #[must_use]
    #[cfg(feature = "alloc")]
    pub fn all_roots_processed(&self) -> bool {
        self.gc_pin_set.is_empty()
    }

    /// Returns the number of roots still pinned (i.e., not yet fully walked).
    #[must_use]
    #[cfg(feature = "alloc")]
    pub fn roots_remaining(&self) -> usize {
        self.gc_pin_set.count()
    }

    /// Mark the destroy job as complete with final stats.
    /// Auto-called by `transition_to_tombstone()`.
    fn complete_destroy_job(&mut self, completion_commit_group: u64) {
        if let Some(ref mut job) = self.destroy_job {
            if !job.is_completed() {
                job.completion_commit_group = completion_commit_group;
                job.objects_reclaimed = job.objects_total;
            }
        }
    }
    // -- GC pin set (alloc feature) --

    /// Accessor for the GC pin set.
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn gc_pin_set(&self) -> &GcPinSet<MAX_TRAVERSAL_ROOTS> {
        &self.gc_pin_set
    }

    /// Pin a traversal root for a background service.
    ///
    /// Returns a [`PinnedRoot`] handle. Call [`release_pin()`](Self::release_pin)
    /// to release the pin when traversal is complete.
    ///
    /// Multiple services may pin the same root type concurrently; the pin
    /// count is reference-counted and the root remains GC-protected until
    /// all pins for that root type are released.
    ///
    /// # Errors
    /// - [`GcPinError::Full`] if the pin set is at capacity and the root
    ///   type is not already present.
    #[cfg(feature = "alloc")]
    pub fn pin_root_for_service(
        &mut self,
        root: TraversalRoot,
        service: BackgroundService,
    ) -> Result<PinnedRoot, tidefs_gc_pin_set::GcPinError> {
        self.gc_pin_set.pin(root)?;
        Ok(PinnedRoot { root, service })
    }

    /// Release a pin acquired by [`pin_root_for_service()`](Self::pin_root_for_service).
    ///
    /// Decrements the reference count for the pinned root type. When the
    /// count reaches zero, the root is no longer GC-protected for that
    /// particular pin (other pins on the same root type may still hold it).
    ///
    /// # Errors
    /// - [`GcPinError::NotFound`] if the root type is not currently pinned.
    #[cfg(feature = "alloc")]
    pub fn release_pin(&mut self, pin: PinnedRoot) -> Result<(), tidefs_gc_pin_set::GcPinError> {
        self.gc_pin_set.unpin(pin.root())
    }

    /// Legacy pin method: pin a root without a service attribution.
    /// Prefer [`pin_root_for_service()`](Self::pin_root_for_service).
    ///
    /// # Errors
    /// - [`GcPinError::Full`] if the pin set is at capacity.
    #[cfg(feature = "alloc")]
    pub fn pin_root(
        &mut self,
        root: tidefs_types_dataset_lifecycle_core::TraversalRoot,
    ) -> Result<(), tidefs_gc_pin_set::GcPinError> {
        self.gc_pin_set.pin(root)
    }

    /// Unpin a single root by exact identity. Called when the destroy worker
    /// finishes processing that root or when a snapshot is deleted.
    #[cfg(feature = "alloc")]
    pub fn unpin_root(&mut self, root: tidefs_types_dataset_lifecycle_core::TraversalRoot) {
        let _ = self.gc_pin_set.unpin(root);
    }

    /// Unpin a single root by type (convenience wrapper for legacy callers).
    /// Prefer [`unpin_root()`](Self::unpin_root) with the full root.
    #[cfg(feature = "alloc")]
    pub fn unpin_root_by_type(
        &mut self,
        root_type: tidefs_types_dataset_lifecycle_core::TraversalRootType,
    ) {
        let _ = self.gc_pin_set.unpin_by_type(root_type);
    }

    /// Repin roots from a persisted [`DestroyJobRecordV1`] after crash recovery.
    #[cfg(feature = "alloc")]
    pub fn repin_from_destroy_job(&mut self, job: &DestroyJobRecordV1) {
        self.gc_pin_set.repin_from_destroy_job(job);
    }

    /// Destroy a snapshot by unpinning its object graph from the GC pin set,
    /// clearing related metadata, and deregistering the clone→origin entry
    /// from the derived catalog (issue #5215).
    ///
    /// Returns an error if the snapshot root is not currently pinned.
    #[cfg(feature = "alloc")]
    pub fn destroy_snapshot(
        &mut self,
        root: tidefs_types_dataset_lifecycle_core::TraversalRoot,
        clone_dataset_id: &DatasetId,
    ) -> Result<(), tidefs_gc_pin_set::GcPinError> {
        self.gc_pin_set.force_unpin(root)?;
        self.derived_catalog.remove_clone(clone_dataset_id);
        Ok(())
    }

    /// Destroy a snapshot for backward compat (by type only).
    /// Prefer [`destroy_snapshot()`](Self::destroy_snapshot) with the full root.
    #[cfg(feature = "alloc")]
    pub fn destroy_snapshot_by_type(
        &mut self,
        clone_dataset_id: &DatasetId,
    ) -> Result<(), tidefs_gc_pin_set::GcPinError> {
        self.gc_pin_set.force_unpin_by_type(
            tidefs_types_dataset_lifecycle_core::TraversalRootType::SnapshotCatalog,
        )?;
        self.derived_catalog.remove_clone(clone_dataset_id);
        Ok(())
    }
    // ------------------------------------------------------------------
    // Pool-level create / destroy / list (catalog-backed, alloc only)
    // ------------------------------------------------------------------

    /// Create a new dataset in the catalog and return a handle.
    ///
    /// Validates that `name` is unique under `parent_path`, allocates a
    /// fresh [`DatasetId`], inserts a catalog entry, and returns a
    /// [`DatasetHandle`] with the new lifecycle initialised in `Active`
    /// state.
    #[cfg(feature = "alloc")]
    pub fn create(
        catalog: &mut DatasetCatalog,
        parent_path: &str,
        name: &str,
        dataset_type: DatasetType,
        creation_commit_group: u64,
        properties: alloc::vec::Vec<u8>,
        flags: DatasetFlags,
        sync_guarantee: SyncGuarantee,
    ) -> Result<DatasetHandle, CatalogError> {
        let full_path = if parent_path.is_empty() {
            alloc::string::String::from(name)
        } else {
            alloc::format!("{parent_path}/{name}")
        };

        // Allocate a deterministic dataset id from path + commit_group
        let mut id_bytes = [0u8; 16];
        let seed = full_path.as_bytes();
        for (i, &b) in seed.iter().enumerate() {
            id_bytes[i % 16] ^= b;
        }
        let txg_bytes = creation_commit_group.to_le_bytes();
        for (i, &b) in txg_bytes.iter().enumerate() {
            id_bytes[i % 16] ^= b;
        }
        id_bytes[0] ^= dataset_type.to_u8();
        let dataset_id = DatasetId::from_bytes(id_bytes);

        catalog.create(
            &full_path,
            dataset_id,
            dataset_type,
            creation_commit_group,
            properties,
            flags,
            sync_guarantee,
        )?;

        let lifecycle = DatasetLifecycle::new();

        Ok(DatasetHandle {
            dataset_id,
            path: full_path,
            dataset_type,
            creation_commit_group,
            lifecycle,
        })
    }

    /// Destroy the dataset at `path`.
    ///
    /// Refuses if children exist. Transitions lifecycle to Destroying
    /// and removes the catalog entry.
    #[cfg(feature = "alloc")]
    pub fn destroy(
        catalog: &mut DatasetCatalog,
        path: &str,
    ) -> Result<DatasetLifecycle, CatalogError> {
        // Verify path exists
        let _ = catalog.lookup(path).map_err(|_| CatalogError::NotFound)?;

        // Refuse if children exist
        let children = catalog.list_children(path)?;
        if !children.is_empty() {
            return Err(CatalogError::HasChildren);
        }

        let mut lc = DatasetLifecycle::new();
        let _ = lc
            .transition_to_destroying(tidefs_types_dataset_lifecycle_core::DestroyFlags::NONE, &[]);

        catalog.destroy(path)?;

        Ok(lc)
    }

    /// List the direct children of a dataset.
    #[cfg(feature = "alloc")]
    pub fn list(
        catalog: &DatasetCatalog,
        parent_path: &str,
    ) -> Result<alloc::vec::Vec<DatasetChildEntry>, CatalogError> {
        catalog.list_children_detailed(parent_path)
    }

    // ------------------------------------------------------------------
    // Freeze / unfreeze (issue #5226)
    // ------------------------------------------------------------------

    /// Freeze the dataset for consistent snapshot capture.
    ///
    /// While frozen, writes are rejected and the committed root is stable.
    /// A frozen dataset must be unfrozen before normal operation resumes.
    ///
    /// # Errors
    ///
    /// Returns  if the dataset is already
    /// frozen.
    pub fn freeze(&mut self) -> Result<(), LifecycleError> {
        if self.frozen {
            return Err(LifecycleError::AlreadyInState { state: self.state });
        }
        self.frozen = true;
        Ok(())
    }

    /// Unfreeze the dataset, resuming normal write operation.
    ///
    /// Idempotent: unfreezing an already-unfrozen dataset is a no-op.
    pub fn unfreeze(&mut self) {
        self.frozen = false;
    }

    /// Returns  if the dataset is currently frozen.
    #[must_use]
    pub fn is_frozen(&self) -> bool {
        self.frozen
    }

    /// Create a full snapshot with freeze/anchor/unfreeze bracketing.
    ///
    /// Freezes the dataset, records a [] in the derived
    /// catalog, registers the clone→origin relationship, pins the GC root,
    /// and unfreezes. This is the primary snapshot-creation path that
    /// ensures the committed root is captured atomically with respect to
    /// commit_group commits.
    ///
    /// # Errors
    ///
    /// Returns  if the dataset is already frozen, or
    ///  if the GC pin set is at capacity.
    #[cfg(feature = "alloc")]
    pub fn create_snapshot_with_anchor(
        &mut self,
        request: SnapshotAnchorCreate,
    ) -> Result<tidefs_derived_catalog::SnapshotAnchor, LifecycleError> {
        use tidefs_gc_pin_set::GcPinError;
        let SnapshotAnchorCreate {
            clone_dataset_id,
            origin_dataset_id,
            snapshot_name,
            committed_root_txg,
            root_handle,
            creation_commit_group,
            created_at_secs,
        } = request;

        self.freeze()?;

        // Register clone→origin in derived catalog
        self.derived_catalog.insert_clone(
            origin_dataset_id,
            clone_dataset_id,
            creation_commit_group,
        );

        // Create the snapshot anchor
        let anchor = self.derived_catalog.create_snapshot_anchor(
            clone_dataset_id,
            snapshot_name,
            committed_root_txg,
            root_handle,
            creation_commit_group,
            created_at_secs,
        );

        // Pin the snapshot catalog root for GC safety
        let root = tidefs_types_dataset_lifecycle_core::TraversalRoot::new(
            tidefs_types_dataset_lifecycle_core::TraversalRootType::SnapshotCatalog,
            tidefs_types_dataset_lifecycle_core::BlockPointer(0),
            0,
        );
        if let Err(e) = self.gc_pin_set.pin(root) {
            self.unfreeze();
            return Err(LifecycleError::PreconditionFailed {
                from: self.state,
                to: self.state,
                reason: match e {
                    GcPinError::Full { .. } => "GC pin set full",
                    _ => "pin error",
                },
            });
        }

        self.unfreeze();
        Ok(anchor)
    }

    /// Record that a snapshot was created for this dataset.
    ///
    /// Pins the `SnapshotCatalog` traversal root in the GC pin set so the
    /// snapshot's object graph is protected from garbage collection while
    /// the snapshot exists. Registers the clone→origin relationship in the
    /// derived catalog (issue #5215).
    ///
    /// # Errors
    ///
    /// Returns `GcPinError::Full` if the pin set is at capacity.
    #[cfg(feature = "alloc")]
    pub fn create_snapshot(
        &mut self,
        clone_dataset_id: DatasetId,
        origin_dataset_id: DatasetId,
        creation_commit_group: u64,
    ) -> Result<(), tidefs_gc_pin_set::GcPinError> {
        let root = tidefs_types_dataset_lifecycle_core::TraversalRoot::new(
            tidefs_types_dataset_lifecycle_core::TraversalRootType::SnapshotCatalog,
            tidefs_types_dataset_lifecycle_core::BlockPointer(0),
            0,
        );
        self.gc_pin_set.pin(root)?;
        self.derived_catalog.insert_clone(
            origin_dataset_id,
            clone_dataset_id,
            creation_commit_group,
        );
        Ok(())
    }

    // -- Binary persistence (issue #5215) --

    /// Encode the lifecycle state and derived catalog to a binary blob.
    ///
    /// Layout:
    /// - state discriminant (1 byte, u8)
    /// - poison discriminant (1 byte, u8)
    /// - grace_secs (4 bytes, u32 LE)
    /// - derived_catalog (count-prefixed, variable)
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn encode(&self) -> alloc::vec::Vec<u8> {
        let cat_encoded = self.derived_catalog.encode();
        let mut buf = alloc::vec::Vec::with_capacity(6 + cat_encoded.len());
        buf.push(self.state.to_u8());
        buf.push(self.poison.to_u8());
        buf.extend_from_slice(&self.grace_secs.to_le_bytes());
        buf.extend_from_slice(&cat_encoded);
        buf
    }

    /// Decode a lifecycle from a binary blob produced by [`encode()`](Self::encode).
    ///
    /// Returns `None` if the data is malformed or truncated.
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 6 {
            return None;
        }
        let state = DatasetStateV1::from_u8(data[0])?;
        let poison = PoisonState::from_u8(data[1]);
        let grace_secs = u32::from_le_bytes(data[2..6].try_into().ok()?);
        let derived_catalog = DerivedCatalog::decode(&data[6..])?;
        Some(DatasetLifecycle {
            state,
            poison,
            grace_secs,
            #[cfg(feature = "alloc")]
            notification: PoisonNotification::with_state(poison),
            #[cfg(feature = "alloc")]
            gc_pin_set: GcPinSet::<MAX_TRAVERSAL_ROOTS>::default(),
            destroy_job: None,
            reaper_policy: TombstoneReaperPolicy::default(),
            tombstone_consensus_granted: false,
            #[cfg(feature = "alloc")]
            derived_catalog,
            frozen: false,
        })
    }

    /// Reset pin set to empty. Used on abort or tombstone transition.
    #[cfg(feature = "alloc")]
    fn reset_pinned_roots(&mut self) {
        self.gc_pin_set = GcPinSet::<MAX_TRAVERSAL_ROOTS>::new();
    }

    // -- Statistics (Phase 4) --

    /// Access the derived catalog for clone/origin lookups.
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn derived_catalog(&self) -> &DerivedCatalog {
        &self.derived_catalog
    }

    /// Mutable access to the derived catalog.
    #[cfg(feature = "alloc")]
    pub fn derived_catalog_mut(&mut self) -> &mut DerivedCatalog {
        &mut self.derived_catalog
    }

    /// Collect lifecycle statistics including pin status.
    #[must_use]
    pub fn stats(&self) -> DatasetLifecycleStats {
        let mut per_root_pins = [0u32; 7];
        for root in self.gc_pin_set.pinned_roots() {
            let idx = root.root_type.to_u8() as usize;
            if idx < 7 {
                per_root_pins[idx] = self.gc_pin_set.pin_count_by_type(root.root_type);
            }
        }
        DatasetLifecycleStats {
            state: self.state,
            poison: self.poison,
            active_pins: self.gc_pin_set.total_pins(),
            distinct_pinned_roots: self.gc_pin_set.count(),
            per_root_pins,
            destroy_in_progress: self.state == DatasetStateV1::Destroying,
            destroy_progress_ppm: self.destroy_progress_ppm(),
        }
    }

    /// Whether the dataset is mountable.
    #[must_use]
    pub const fn is_mountable(&self) -> bool {
        self.state.is_mountable() && self.poison.is_healthy()
    }

    /// Whether writes are currently accepted.
    #[must_use]
    pub const fn accepts_writes(&self) -> bool {
        self.state.accepts_writes() && self.poison.is_healthy()
    }

    /// Get a clone of the shared poison notification handle.
    ///
    /// Available only when the `alloc` feature is enabled.
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn poison_notification(&self) -> PoisonNotification {
        self.notification.clone()
    }

    /// Check mount eligibility with feature gate integration.
    #[must_use = "check mount eligibility before proceeding with open"]
    pub fn check_mount(
        &self,
        _dataset_name: &'static str,
    ) -> Result<DatasetOpenResult, LifecycleError> {
        // State check first: Destroying/Tombstone refuse mount regardless of poison.
        match self.state {
            DatasetStateV1::Active => {
                if !self.poison.is_healthy() {
                    return Err(LifecycleError::Poisoned {
                        poison: self.poison,
                    });
                }
                Ok(DatasetOpenResult::ReadWrite)
            }
            DatasetStateV1::Destroying => Err(LifecycleError::InvalidTransition {
                from: DatasetStateV1::Destroying,
                to: DatasetStateV1::Destroying,
            }),
            DatasetStateV1::Tombstone => Err(LifecycleError::InvalidTransition {
                from: DatasetStateV1::Tombstone,
                to: DatasetStateV1::Tombstone,
            }),
        }
    }

    // -- Transitions --

    /// Transition Active → Destroying.
    ///
    /// Sets poison to [`PoisonState::PoisonPending`], fencing new operations
    /// while allowing in-flight ops to drain within the grace period.
    ///
    /// # Errors
    /// - `AlreadyInState` if already Destroying or Tombstone
    /// - `InvalidTransition` if not Active
    /// - `Poisoned` if mount is already poisoned
    pub fn transition_to_destroying(
        &mut self,
        flags: DestroyFlags,
        pinned_roots: &[TraversalRoot],
    ) -> Result<(), LifecycleError> {
        if self.state == DatasetStateV1::Destroying || self.state == DatasetStateV1::Tombstone {
            return Err(LifecycleError::AlreadyInState { state: self.state });
        }
        if self.state != DatasetStateV1::Active {
            return Err(LifecycleError::InvalidTransition {
                from: self.state,
                to: DatasetStateV1::Destroying,
            });
        }
        // Validate the transition against the core state machine.
        core_validate_transition(self.state, DatasetStateV1::Destroying).map_err(|_e| {
            LifecycleError::InvalidTransition {
                from: self.state,
                to: DatasetStateV1::Destroying,
            }
        })?;

        // With FORCE_UNMOUNT, skip the grace period: poison immediately active.
        let initial_poison = if flags.force_unmount() {
            PoisonState::PoisonActive
        } else {
            PoisonState::PoisonPending
        };
        self.state = DatasetStateV1::Destroying;
        self.poison = initial_poison;
        #[cfg(feature = "alloc")]
        {
            for root in pinned_roots {
                let _ = self.gc_pin_set.pin(*root);
            }
        }
        #[cfg(feature = "alloc")]
        self.notification.set(initial_poison);
        Ok(())
    }

    /// Transition Destroying → Tombstone.
    ///
    /// Finalises the destroy after the destroy worker completes all reclamation.
    /// Sets poison to [`PoisonState::MountDead`].
    ///
    /// # Errors
    /// - `AlreadyInState` if already Tombstone
    /// - `InvalidTransition` if not Destroying
    pub fn transition_to_tombstone(&mut self) -> Result<(), LifecycleError> {
        if self.state == DatasetStateV1::Tombstone {
            return Err(LifecycleError::AlreadyInState { state: self.state });
        }
        if self.state != DatasetStateV1::Destroying {
            return Err(LifecycleError::InvalidTransition {
                from: self.state,
                to: DatasetStateV1::Tombstone,
            });
        }
        core_validate_transition(self.state, DatasetStateV1::Tombstone).map_err(|_e| {
            LifecycleError::InvalidTransition {
                from: self.state,
                to: DatasetStateV1::Tombstone,
            }
        })?;

        self.state = DatasetStateV1::Tombstone;
        self.poison = PoisonState::MountDead;
        #[cfg(feature = "alloc")]
        self.notification.set(PoisonState::MountDead);
        // Mark the destroy job complete if one exists.
        self.complete_destroy_job(u64::MAX); // u64::MAX = "complete, commit_group unknown"
        self.reset_pinned_roots();
        Ok(())
    }

    /// Abort: transition Destroying → Active.
    ///
    /// Admin recovery path. Clears poison to MountOk. Already-reclaimed
    /// blocks are not recovered.
    ///
    /// # Errors
    /// - `AlreadyInState` if already Active
    /// - `InvalidTransition` if not Destroying
    pub fn abort_destroy(&mut self) -> Result<(), LifecycleError> {
        if self.state == DatasetStateV1::Active {
            return Err(LifecycleError::AlreadyInState { state: self.state });
        }
        if self.state != DatasetStateV1::Destroying {
            return Err(LifecycleError::InvalidTransition {
                from: self.state,
                to: DatasetStateV1::Active,
            });
        }
        core_validate_transition(self.state, DatasetStateV1::Active).map_err(|_e| {
            LifecycleError::InvalidTransition {
                from: self.state,
                to: DatasetStateV1::Active,
            }
        })?;

        self.state = DatasetStateV1::Active;
        self.poison = PoisonState::MountOk;
        #[cfg(feature = "alloc")]
        self.notification.set(PoisonState::MountOk);
        // Clear destroy job — partial reclamation is not rolled back.
        self.destroy_job = None;
        self.reset_pinned_roots();
        Ok(())
    }

    /// Recovery: transition Tombstone → Active.
    ///
    /// Disaster-recovery path. Clears poison to MountOk. Data already
    /// reclaimed is permanently lost; only the dataset namespace is
    /// recovered.
    ///
    /// # Errors
    /// - `AlreadyInState` if already Active
    /// - `InvalidTransition` if not Tombstone
    pub fn recover_tombstone(&mut self) -> Result<(), LifecycleError> {
        if self.state == DatasetStateV1::Active {
            return Err(LifecycleError::AlreadyInState { state: self.state });
        }
        if self.state != DatasetStateV1::Tombstone {
            return Err(LifecycleError::InvalidTransition {
                from: self.state,
                to: DatasetStateV1::Active,
            });
        }
        core_validate_transition(self.state, DatasetStateV1::Active).map_err(|_e| {
            LifecycleError::InvalidTransition {
                from: self.state,
                to: DatasetStateV1::Active,
            }
        })?;

        self.state = DatasetStateV1::Active;
        self.poison = PoisonState::MountOk;
        #[cfg(feature = "alloc")]
        self.notification.set(PoisonState::MountOk);
        self.destroy_job = None;
        self.reset_pinned_roots();
        Ok(())
    }

    // -- Poison management --

    /// Transition poison from PoisonPending → PoisonActive.
    ///
    /// Called when the grace period expires or FORCE_UNMOUNT is set.
    /// All outstanding operations are cancelled.
    pub fn escalate_poison(&mut self) {
        if self.poison == PoisonState::PoisonPending {
            self.poison = PoisonState::PoisonActive;
            #[cfg(feature = "alloc")]
            self.notification.set(PoisonState::PoisonActive);
        }
    }

    /// Transition poison to MountDead.
    ///
    /// Called when the FUSE session is fully torn down.
    pub fn kill_mount(&mut self) {
        self.poison = PoisonState::MountDead;
        #[cfg(feature = "alloc")]
        self.notification.set(PoisonState::MountDead);
    }

    /// Restore poison to MountOk (abort/recovery path).
    pub fn clear_poison(&mut self) {
        self.poison = PoisonState::MountOk;
        #[cfg(feature = "alloc")]
        self.notification.set(PoisonState::MountOk);
    }

    /// Convenience: validate a proposed transition without mutating.
    #[must_use = "validate transition before applying state change"]
    pub fn validate_transition(&self, to: DatasetStateV1) -> Result<(), LifecycleError> {
        if self.state == to {
            return Err(LifecycleError::AlreadyInState { state: self.state });
        }
        core_validate_transition(self.state, to).map_err(|_e| {
            LifecycleError::InvalidTransition {
                from: self.state,
                to,
            }
        })?;
        Ok(())
    }
}

impl Default for DatasetLifecycle {
    fn default() -> Self {
        DatasetLifecycle::new()
    }
}

impl fmt::Display for DatasetLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DatasetLifecycle(state={}, poison={})",
            self.state.label(),
            self.poison.label()
        )?;
        #[cfg(feature = "alloc")]
        if self.gc_pin_set.total_pins() > 0 {
            write!(
                f,
                " [pins: {} total / {} types]",
                self.gc_pin_set.total_pins(),
                self.gc_pin_set.count()
            )?;
        }
        if let Some(ref job) = self.destroy_job {
            write!(
                f,
                " destroy(job_id={} commit_group={} progress={}/{} reclaimed={} {})",
                job.destroy_job_id,
                job.destroy_commit_group,
                job.objects_reclaimed,
                job.objects_total,
                job.bytes_reclaimed,
                if job.is_completed() {
                    "completed"
                } else {
                    "in-progress"
                }
            )?;
        }
        if self.state.is_terminal() {
            let eligibility = self.is_reap_eligible(u64::MAX);
            write!(
                f,
                " reaper({})",
                match eligibility {
                    ReapEligibility::Eligible => "eligible",
                    ReapEligibility::TooYoung { .. } => "too-young",
                    ReapEligibility::ConsensusPending => "consensus-pending",
                }
            )?;
        }
        Ok(())
    }
}
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// PoisonNotification -- thread-safe poison state handle
// ---------------------------------------------------------------------------

#[cfg(feature = "alloc")]
pub mod notification {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU8, Ordering};

    use tidefs_types_dataset_lifecycle_core::{PoisonReason, PoisonState};

    /// Shared poison notification handle, safe to clone and share across threads.
    #[derive(Clone, Debug)]
    pub struct PoisonNotification {
        state: Arc<AtomicU8>,
        reason: Arc<AtomicU8>,
    }

    impl PoisonNotification {
        #[must_use]
        pub fn new() -> Self {
            PoisonNotification {
                state: Arc::new(AtomicU8::new(PoisonState::MountOk as u8)),
                reason: Arc::new(AtomicU8::new(0)), // PoisonReason::None
            }
        }

        #[must_use]
        pub fn with_state(initial: PoisonState) -> Self {
            PoisonNotification {
                state: Arc::new(AtomicU8::new(initial as u8)),
                reason: Arc::new(AtomicU8::new(0)), // PoisonReason::None
            }
        }
        /// Create a notification with a specific state and reason.
        #[must_use]
        pub fn with_state_and_reason(initial: PoisonState, reason: PoisonReason) -> Self {
            PoisonNotification {
                state: Arc::new(AtomicU8::new(initial as u8)),
                reason: Arc::new(AtomicU8::new(reason as u8)),
            }
        }

        #[must_use]
        pub fn get(&self) -> PoisonState {
            let raw = self.state.load(Ordering::Acquire);
            PoisonState::from_u8(raw)
        }

        pub fn advance(&self) -> PoisonState {
            loop {
                let current_raw = self.state.load(Ordering::Acquire);
                let current = PoisonState::from_u8(current_raw);
                let next = match current {
                    PoisonState::MountOk => PoisonState::PoisonPending,
                    PoisonState::PoisonPending => PoisonState::PoisonActive,
                    PoisonState::PoisonActive | PoisonState::MountDead => {
                        return current;
                    }
                };
                if self
                    .state
                    .compare_exchange(current_raw, next as u8, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return next;
                }
            }
        }

        pub fn set(&self, target: PoisonState) -> PoisonState {
            let old_raw = self.state.swap(target as u8, Ordering::AcqRel);
            PoisonState::from_u8(old_raw)
        }

        /// Get the current poison reason.
        #[must_use]
        pub fn get_reason(&self) -> PoisonReason {
            let raw = self.reason.load(Ordering::Acquire);
            PoisonReason::from_u8(raw)
        }

        /// Set the poison reason. Returns the previous reason.
        pub fn set_reason(&self, target: PoisonReason) -> PoisonReason {
            let old_raw = self.reason.swap(target as u8, Ordering::AcqRel);
            PoisonReason::from_u8(old_raw)
        }

        /// Set both state and reason (best-effort).
        pub fn set_both(&self, state: PoisonState, reason: PoisonReason) {
            self.set(state);
            self.set_reason(reason);
        }

        /// Whether the dataset should reject new operations.
        #[must_use]
        pub fn should_reject_new_ops(&self) -> bool {
            self.get().should_reject_new_ops()
        }
    }

    impl Default for PoisonNotification {
        fn default() -> Self {
            Self::new()
        }
    }

    impl PartialEq for PoisonNotification {
        fn eq(&self, other: &Self) -> bool {
            self.get() == other.get()
        }
    }

    impl Eq for PoisonNotification {}
}
// ---------------------------------------------------------------------------
// PoisonGuard -- checked at FUSE dispatch entry before any operation
// ---------------------------------------------------------------------------

/// Error returned when an operation is attempted on a poisoned dataset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoisonError {
    /// Why the dataset was poisoned.
    pub reason: PoisonReason,
    /// Current poison state.
    pub state: PoisonState,
}

impl PoisonError {
    /// POSIX errno for this error (always EIO for active poison).
    #[must_use]
    pub const fn errno(self) -> i32 {
        self.reason.errno()
    }
}

impl fmt::Display for PoisonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "dataset poisoned (state={}, reason={})",
            self.state.label(),
            self.reason.label()
        )
    }
}

/// A poison guard checked at FUSE dispatch entry.
///
/// Before any FUSE operation on a dataset, the guard must be checked.
/// If the dataset is poisoned, the guard returns a [`PoisonError`] with
/// the reason, and the FUSE daemon replies with EIO.
///
/// The guard is cheap to clone (shared atomic state) and can be held
/// by every dispatch worker.
#[derive(Clone, Debug)]
pub struct PoisonGuard {
    notification: PoisonNotification,
}

impl PoisonGuard {
    /// Create a poison guard from a poison notification handle.
    #[must_use]
    pub fn new(notification: PoisonNotification) -> Self {
        PoisonGuard { notification }
    }

    /// Check whether operations are allowed on this dataset.
    ///
    /// Returns `Ok(())` if the dataset is healthy, or `Err(PoisonError)`
    /// if the dataset is poisoned and new operations must be rejected.
    pub fn check(&self) -> Result<(), PoisonError> {
        let state = self.notification.get();
        if state.is_healthy() {
            return Ok(());
        }
        let reason = self.notification.get_reason();
        Err(PoisonError { reason, state })
    }

    /// Whether this dataset should reject new operations.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.notification.should_reject_new_ops()
    }

    /// Get the current poison state.
    #[must_use]
    pub fn poison_state(&self) -> PoisonState {
        self.notification.get()
    }

    /// Get the current poison reason.
    #[must_use]
    pub fn poison_reason(&self) -> PoisonReason {
        self.notification.get_reason()
    }

    /// Access the underlying notification handle.
    #[must_use]
    pub fn notification(&self) -> &PoisonNotification {
        &self.notification
    }
}

// ---------------------------------------------------------------------------
// DrainInFlight -- tracks in-flight operations during poison drain
// ---------------------------------------------------------------------------

/// Tracks in-flight FUSE operations on a dataset.
///
/// When a dataset enters the POISONED state, new operations are rejected
/// and in-flight operations must drain before the dataset can transition
/// to DESTROYING. This counter tracks those in-flight operations.
#[derive(Clone, Debug)]
pub struct DrainInFlight {
    notification: PoisonNotification,
    inflight: alloc::sync::Arc<core::sync::atomic::AtomicU64>,
}

impl DrainInFlight {
    /// Create a drain tracker from a poison notification handle.
    #[must_use]
    pub fn new(notification: PoisonNotification) -> Self {
        DrainInFlight {
            notification,
            inflight: alloc::sync::Arc::new(core::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Try to enter a new in-flight operation.
    ///
    /// Returns `true` if the operation may proceed (dataset is healthy
    /// and the operation was registered). Returns `false` if the dataset
    /// is poisoned — new operations must not start.
    ///
    /// Caller MUST call [`leave`](Self::leave) when the operation
    /// completes if this method returned `true`.
    #[must_use]
    pub fn enter(&self) -> bool {
        let state = self.notification.get();
        if state.should_reject_new_ops() {
            return false;
        }
        self.inflight
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        // Double-check after increment: poison may have been set
        let state_after = self.notification.get();
        if state_after.should_reject_new_ops() {
            self.inflight
                .fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
            return false;
        }
        true
    }

    /// Mark an in-flight operation as complete.
    pub fn leave(&self) {
        self.inflight
            .fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
    }

    /// Whether all in-flight operations have drained.
    #[must_use]
    pub fn is_drained(&self) -> bool {
        self.inflight.load(core::sync::atomic::Ordering::Acquire) == 0
    }

    /// Current count of in-flight operations.
    #[must_use]
    pub fn inflight_count(&self) -> u64 {
        self.inflight.load(core::sync::atomic::Ordering::Acquire)
    }
}

#[cfg(feature = "poison-gating")]
pub mod poison_dispatch {
    //! Poison dispatch gate for the FUSE daemon main loop.
    //!
    //! This module provides [`PoisonDispatchGate`], a composite gate that
    //! combines poison checking with in-flight operation tracking.  FUSE
    //! dispatch loops call [`PoisonDispatchGate::enter`] before servicing
    //! a request and [`PoisonDispatchGate::leave`] after completion.
    //! When the dataset is poisoned, `enter` returns a [`PoisonError`]
    //! and the daemon replies with `EIO`.

    use crate::notification::PoisonNotification;
    use crate::{DrainInFlight, PoisonError, PoisonGuard, PoisonReason, PoisonState};

    /// Composite dispatch gate for a single dataset.
    ///
    /// Combines a [`PoisonGuard`] (for poison state check) with
    /// [`DrainInFlight`] (for in-flight operation tracking).
    ///
    /// Cheap to clone — underlying state is shared via `Arc`.
    #[derive(Clone, Debug)]
    pub struct PoisonDispatchGate {
        guard: PoisonGuard,
        drain: DrainInFlight,
    }

    impl PoisonDispatchGate {
        /// Create a dispatch gate from a poison notification handle.
        #[must_use]
        pub fn new(notification: PoisonNotification) -> Self {
            PoisonDispatchGate {
                guard: PoisonGuard::new(notification.clone()),
                drain: DrainInFlight::new(notification),
            }
        }

        /// Enter a new dispatch operation.
        ///
        /// Returns `Ok(())` if the operation may proceed (dataset is healthy
        /// and the inflight counter was incremented).
        ///
        /// Returns `Err(PoisonError)` if the dataset is poisoned — the
        /// FUSE daemon must reply with `EIO` (errno 5).
        ///
        /// The caller **must** call [`leave`](Self::leave) after the
        /// operation completes when this returns `Ok(())`.
        #[must_use]
        pub fn enter(&self) -> Result<(), PoisonError> {
            // Fast path: check poison state before touching the counter.
            if let Err(e) = self.guard.check() {
                return Err(e);
            }
            // Attempt to register the inflight operation.
            if !self.drain.enter() {
                // Poison was set between check and register; re-check guard.
                return self.guard.check();
            }
            Ok(())
        }

        /// Mark an in-flight operation as complete.
        ///
        /// Must be called exactly once for each successful [`enter`](Self::enter).
        pub fn leave(&self) {
            self.drain.leave();
        }

        /// Whether all in-flight operations have drained.
        ///
        /// Poll this after setting poison to determine when it is safe
        /// to proceed with the destroy transition.
        #[must_use]
        pub fn is_drained(&self) -> bool {
            self.drain.is_drained()
        }

        /// Current in-flight operation count.
        #[must_use]
        pub fn inflight_count(&self) -> u64 {
            self.drain.inflight_count()
        }

        /// Poison the dataset with a reason.
        ///
        /// Sets the poison state and reason on the underlying notification.
        /// After this call, all future [`enter`](Self::enter) calls will
        /// return `Err(PoisonError)`.
        pub fn poison(&self, state: PoisonState, reason: PoisonReason) {
            self.guard.notification().set_both(state, reason);
        }

        /// Current poison state.
        #[must_use]
        pub fn poison_state(&self) -> PoisonState {
            self.guard.poison_state()
        }

        /// Current poison reason.
        #[must_use]
        pub fn poison_reason(&self) -> PoisonReason {
            self.guard.poison_reason()
        }
    }

    // ── Integration tests ─────────────────────────────────────────

    #[cfg(test)]
    mod integration_tests {
        use super::*;

        /// Simulates: mount → poison dataset → attempt open/read/write → all return EIO → drain.
        #[test]
        fn poison_dispatch_gate_full_sequence() {
            let notif = PoisonNotification::new();
            let gate = PoisonDispatchGate::new(notif);

            // Phase 1: dataset is healthy — operations proceed.
            for _ in 0..3 {
                assert!(gate.enter().is_ok(), "healthy dataset should allow ops");
            }
            assert_eq!(gate.inflight_count(), 3);

            // Phase 2: poison the dataset (simulates corruption detection).
            gate.poison(PoisonState::PoisonActive, PoisonReason::CorruptionDetected);

            // Phase 3: new operations are rejected with EIO.
            for op in ["open", "read", "write", "getattr", "readdir"] {
                let err = gate.enter().unwrap_err();
                assert_eq!(err.errno(), 5, "{op} should return EIO");
                assert_eq!(err.reason, PoisonReason::CorruptionDetected);
                assert_eq!(err.state, PoisonState::PoisonActive);
            }

            // Phase 4: existing in-flight operations drain.
            assert!(!gate.is_drained());
            for _ in 0..3 {
                gate.leave();
            }
            assert!(gate.is_drained());
            assert_eq!(gate.inflight_count(), 0);
        }

        /// PoisonPending still rejects new operations.
        #[test]
        fn poison_pending_rejects_new_ops() {
            let notif = PoisonNotification::new();
            let gate = PoisonDispatchGate::new(notif);

            gate.poison(PoisonState::PoisonPending, PoisonReason::AdminAction);
            let err = gate.enter().unwrap_err();
            assert_eq!(err.errno(), 5);
            assert_eq!(err.state, PoisonState::PoisonPending);
        }

        /// Multiple gates from the same notification share poison state.
        #[test]
        fn multiple_gates_share_poison_state() {
            let notif = PoisonNotification::new();
            let gate1 = PoisonDispatchGate::new(notif.clone());
            let gate2 = PoisonDispatchGate::new(notif.clone());

            assert!(gate1.enter().is_ok());
            assert!(gate2.enter().is_ok());

            // Poison via gate1 — gate2 sees it immediately.
            gate1.poison(PoisonState::PoisonActive, PoisonReason::FatalIOError);
            assert!(gate2.enter().is_err());
            assert!(gate1.enter().is_err());

            // Drain both.
            gate1.leave();
            gate2.leave();
            assert!(gate1.is_drained());
            // Each gate has its own drain counter; both drained after their
            assert!(gate2.is_drained());
        }

        /// Drain correctly handles concurrent enter/leave across clones.
        #[test]
        fn drain_handles_concurrent_entries() {
            let notif = PoisonNotification::new();
            let gate = PoisonDispatchGate::new(notif);

            for _ in 0..10 {
                assert!(gate.enter().is_ok());
            }
            assert_eq!(gate.inflight_count(), 10);

            gate.poison(PoisonState::PoisonPending, PoisonReason::AdminAction);
            // New ops rejected.
            assert!(gate.enter().is_err());
            // Still 10 inflight.
            assert_eq!(gate.inflight_count(), 10);

            for _ in 0..10 {
                gate.leave();
            }
            assert!(gate.is_drained());
        }

        /// MountDead terminal state rejects everything.
        #[test]
        fn mount_dead_rejects_and_eventually_drains() {
            let notif = PoisonNotification::with_state_and_reason(
                PoisonState::MountDead,
                PoisonReason::ClusterConsensusLost,
            );
            let gate = PoisonDispatchGate::new(notif);

            let err = gate.enter().unwrap_err();
            assert_eq!(err.state, PoisonState::MountDead);
            assert_eq!(err.reason, PoisonReason::ClusterConsensusLost);
            assert_eq!(gate.inflight_count(), 0);
            assert!(gate.is_drained());
        }

        /// Poison state and reason accessors work through gate.
        #[test]
        fn gate_accessors_reflect_notification() {
            let notif = PoisonNotification::new();
            let gate = PoisonDispatchGate::new(notif);

            assert_eq!(gate.poison_state(), PoisonState::MountOk);
            assert_eq!(gate.poison_reason(), PoisonReason::None);

            gate.poison(
                PoisonState::PoisonActive,
                PoisonReason::MetadataInconsistency,
            );
            assert_eq!(gate.poison_state(), PoisonState::PoisonActive);
            assert_eq!(gate.poison_reason(), PoisonReason::MetadataInconsistency);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a DatasetId from a single byte pattern.
    fn did(n: u8) -> DatasetId {
        let mut bytes = [0u8; 16];
        bytes[0] = n;
        bytes[1] = n;
        bytes[2] = n;
        bytes[3] = n;
        bytes[4] = n;
        bytes[5] = n;
        bytes[6] = n;
        bytes[7] = n;
        bytes[8] = n;
        bytes[9] = n;
        bytes[10] = n;
        bytes[11] = n;
        bytes[12] = n;
        bytes[13] = n;
        bytes[14] = n;
        bytes[15] = n;
        DatasetId::from_bytes(bytes)
    }

    use tidefs_derived_catalog::SnapshotId;
    use tidefs_types_dataset_lifecycle_core::{BlockPointer, TraversalRoot, TraversalRootType};

    // ── Construction ──────────────────────────────────────────────

    #[test]
    fn new_starts_active() {
        let lc = DatasetLifecycle::new();
        assert_eq!(lc.state(), DatasetStateV1::Active);
        assert_eq!(lc.poison_state(), PoisonState::MountOk);
        assert!(lc.is_mountable());
        assert!(lc.accepts_writes());
    }

    #[test]
    fn default_is_new() {
        assert_eq!(DatasetLifecycle::default(), DatasetLifecycle::new());
    }

    #[test]
    fn from_parts_preserves() {
        let lc =
            DatasetLifecycle::from_parts(DatasetStateV1::Destroying, PoisonState::PoisonPending);
        assert_eq!(lc.state(), DatasetStateV1::Destroying);
        assert_eq!(lc.poison_state(), PoisonState::PoisonPending);
        assert!(!lc.is_mountable());
    }

    #[test]
    fn with_grace_secs() {
        let lc = DatasetLifecycle::new().with_grace_secs(60);
        assert_eq!(lc.grace_secs(), 60);
    }

    // ── transition_to_destroying ──────────────────────────────────

    #[test]
    fn active_to_destroying_success() {
        let mut lc = DatasetLifecycle::new();
        assert!(lc.transition_to_destroying(DestroyFlags::NONE, &[]).is_ok());
        assert_eq!(lc.state(), DatasetStateV1::Destroying);
        assert_eq!(lc.poison_state(), PoisonState::PoisonPending);
        assert!(!lc.is_mountable());
        assert!(!lc.accepts_writes());
    }

    #[test]
    fn active_to_destroying_with_force_unmount() {
        let mut lc = DatasetLifecycle::new();
        assert!(lc
            .transition_to_destroying(DestroyFlags::FORCE_UNMOUNT, &[])
            .is_ok());
        assert_eq!(lc.state(), DatasetStateV1::Destroying);
        // FORCE_UNMOUNT skips the grace period: poison is immediately active.
        assert_eq!(lc.poison_state(), PoisonState::PoisonActive);
        // Verify notification handle tracks the forced state.
        #[cfg(feature = "alloc")]
        {
            assert_eq!(lc.poison_notification().get(), PoisonState::PoisonActive);
        }
    }

    #[test]
    fn already_destroying_refuses() {
        let mut lc = DatasetLifecycle::new();
        lc.transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap();
        let err = lc
            .transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap_err();
        assert!(matches!(
            err,
            LifecycleError::AlreadyInState {
                state: DatasetStateV1::Destroying
            }
        ));
    }

    #[test]
    fn tombstone_refuses_destroy() {
        let mut lc = DatasetLifecycle::new();
        lc.transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap();
        lc.transition_to_tombstone().unwrap();
        let err = lc
            .transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap_err();
        assert!(matches!(
            err,
            LifecycleError::AlreadyInState {
                state: DatasetStateV1::Tombstone
            }
        ));
    }

    // ── transition_to_tombstone ───────────────────────────────────

    #[test]
    fn destroying_to_tombstone_success() {
        let mut lc = DatasetLifecycle::new();
        lc.transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap();
        assert!(lc.transition_to_tombstone().is_ok());
        assert_eq!(lc.state(), DatasetStateV1::Tombstone);
        assert_eq!(lc.poison_state(), PoisonState::MountDead);
        assert!(!lc.is_mountable());
    }

    #[test]
    fn active_refuses_tombstone() {
        let mut lc = DatasetLifecycle::new();
        let err = lc.transition_to_tombstone().unwrap_err();
        assert!(matches!(
            err,
            LifecycleError::InvalidTransition {
                from: DatasetStateV1::Active,
                to: DatasetStateV1::Tombstone,
            }
        ));
    }

    #[test]
    fn already_tombstone_refuses() {
        let mut lc = DatasetLifecycle::new();
        lc.transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap();
        lc.transition_to_tombstone().unwrap();
        let err = lc.transition_to_tombstone().unwrap_err();
        assert!(matches!(
            err,
            LifecycleError::AlreadyInState {
                state: DatasetStateV1::Tombstone
            }
        ));
    }

    // ── abort_destroy ─────────────────────────────────────────────

    #[test]
    fn abort_destroy_success() {
        let mut lc = DatasetLifecycle::new();
        lc.transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap();
        assert!(lc.abort_destroy().is_ok());
        assert_eq!(lc.state(), DatasetStateV1::Active);
        assert_eq!(lc.poison_state(), PoisonState::MountOk);
        assert!(lc.is_mountable());
        assert!(lc.accepts_writes());
    }

    #[test]
    fn abort_active_refuses() {
        let mut lc = DatasetLifecycle::new();
        let err = lc.abort_destroy().unwrap_err();
        assert!(matches!(
            err,
            LifecycleError::AlreadyInState {
                state: DatasetStateV1::Active
            }
        ));
    }

    #[test]
    fn abort_tombstone_refuses() {
        let mut lc = DatasetLifecycle::new();
        lc.transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap();
        lc.transition_to_tombstone().unwrap();
        let err = lc.abort_destroy().unwrap_err();
        assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
    }

    // ── recover_tombstone ─────────────────────────────────────────

    #[test]
    fn recover_tombstone_success() {
        let mut lc = DatasetLifecycle::new();
        lc.transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap();
        lc.transition_to_tombstone().unwrap();
        assert!(lc.recover_tombstone().is_ok());
        assert_eq!(lc.state(), DatasetStateV1::Active);
        assert_eq!(lc.poison_state(), PoisonState::MountOk);
        assert!(lc.is_mountable());
    }

    #[test]
    fn recover_active_refuses() {
        let mut lc = DatasetLifecycle::new();
        let err = lc.recover_tombstone().unwrap_err();
        assert!(matches!(
            err,
            LifecycleError::AlreadyInState {
                state: DatasetStateV1::Active
            }
        ));
    }

    #[test]
    fn recover_destroying_refuses() {
        let mut lc = DatasetLifecycle::new();
        lc.transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap();
        let err = lc.recover_tombstone().unwrap_err();
        assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
    }

    // ── Poison management ─────────────────────────────────────────

    #[test]
    fn escalate_poison_progression() {
        let mut lc = DatasetLifecycle::new();
        lc.transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap();
        assert_eq!(lc.poison_state(), PoisonState::PoisonPending);
        lc.escalate_poison();
        assert_eq!(lc.poison_state(), PoisonState::PoisonActive);
        lc.kill_mount();
        assert_eq!(lc.poison_state(), PoisonState::MountDead);
    }

    #[test]
    fn escalate_poison_from_active_noop() {
        let mut lc = DatasetLifecycle::new();
        lc.escalate_poison();
        assert_eq!(lc.poison_state(), PoisonState::MountOk);
    }

    #[test]
    fn escalate_poison_from_dead_noop() {
        let mut lc = DatasetLifecycle::new();
        lc.kill_mount();
        assert_eq!(lc.poison_state(), PoisonState::MountDead);
        lc.escalate_poison();
        assert_eq!(lc.poison_state(), PoisonState::MountDead);
    }

    #[test]
    fn clear_poison_restores() {
        let mut lc = DatasetLifecycle::new();
        lc.transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap();
        lc.escalate_poison();
        lc.kill_mount();
        assert_eq!(lc.poison_state(), PoisonState::MountDead);
        lc.clear_poison();
        assert_eq!(lc.poison_state(), PoisonState::MountOk);
    }

    // ── is_mountable / accepts_writes ─────────────────────────────

    #[test]
    fn mountable_with_poison_pending() {
        let mut lc = DatasetLifecycle::new();
        lc.transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap();
        assert!(!lc.is_mountable());
        assert!(!lc.accepts_writes());
    }

    #[test]
    fn mountable_active_healthy() {
        let lc = DatasetLifecycle::new();
        assert!(lc.is_mountable());
        assert!(lc.accepts_writes());
    }

    // ── validate_transition ───────────────────────────────────────

    #[test]
    fn validate_legal_transition() {
        let lc = DatasetLifecycle::new();
        assert!(lc.validate_transition(DatasetStateV1::Destroying).is_ok());
    }

    #[test]
    fn validate_same_state_error() {
        let lc = DatasetLifecycle::new();
        let err = lc.validate_transition(DatasetStateV1::Active).unwrap_err();
        assert!(matches!(err, LifecycleError::AlreadyInState { .. }));
    }

    #[test]
    fn validate_illegal_transition() {
        let lc = DatasetLifecycle::new();
        let err = lc
            .validate_transition(DatasetStateV1::Tombstone)
            .unwrap_err();
        assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
    }

    // ── check_mount ───────────────────────────────────────────────

    #[test]
    fn check_mount_active_healthy() {
        let lc = DatasetLifecycle::new();
        let result = lc.check_mount("testds");
        assert!(result.is_ok());
        assert!(!result.unwrap().is_read_only());
    }

    #[test]
    fn check_mount_destroying_rejected() {
        let mut lc = DatasetLifecycle::new();
        lc.transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap();
        let err = lc.check_mount("testds").unwrap_err();
        assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
    }

    #[test]
    fn check_mount_tombstone_rejected() {
        let mut lc = DatasetLifecycle::new();
        lc.transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap();
        lc.transition_to_tombstone().unwrap();
        let err = lc.check_mount("testds").unwrap_err();
        assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
    }

    // ── Display ───────────────────────────────────────────────────

    #[test]
    fn display_nonempty() {
        let lc = DatasetLifecycle::new();
        let s = format!("{lc}");
        assert!(s.contains("active"));
        assert!(s.contains("MOUNT_OK"));
    }

    #[test]
    fn display_poisoned() {
        let mut lc = DatasetLifecycle::new();
        lc.transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap();
        let s = format!("{lc}");
        assert!(s.contains("destroying"));
        assert!(s.contains("POISON_PENDING"));
    }

    // ── LifecycleError Display ────────────────────────────────────

    #[test]
    fn lifecycle_error_display_invalid() {
        let e = LifecycleError::InvalidTransition {
            from: DatasetStateV1::Active,
            to: DatasetStateV1::Tombstone,
        };
        let s = format!("{e}");
        assert!(s.contains("active"));
        assert!(s.contains("tombstone"));
    }

    #[test]
    fn lifecycle_error_display_already() {
        let e = LifecycleError::AlreadyInState {
            state: DatasetStateV1::Destroying,
        };
        let s = format!("{e}");
        assert!(s.contains("destroying"));
    }

    #[test]
    fn lifecycle_error_display_precond() {
        let e = LifecycleError::PreconditionFailed {
            from: DatasetStateV1::Active,
            to: DatasetStateV1::Destroying,
            reason: "clone children exist",
        };
        let s = format!("{e}");
        assert!(s.contains("clone children exist"));
    }

    #[test]
    fn lifecycle_error_display_poisoned() {
        let e = LifecycleError::Poisoned {
            poison: PoisonState::PoisonActive,
        };
        let s = format!("{e}");
        assert!(s.contains("POISON_ACTIVE"));
    }

    // ── Full lifecycle integration ────────────────────────────────

    #[test]
    fn full_lifecycle_active_to_tombstone_and_back() {
        let mut lc = DatasetLifecycle::new();

        // Active state
        assert!(lc.is_mountable());
        assert_eq!(lc.state(), DatasetStateV1::Active);
        assert_eq!(lc.poison_state(), PoisonState::MountOk);

        // Transition to Destroying
        assert!(lc.transition_to_destroying(DestroyFlags::NONE, &[]).is_ok());
        assert!(!lc.is_mountable());
        assert_eq!(lc.state(), DatasetStateV1::Destroying);
        assert_eq!(lc.poison_state(), PoisonState::PoisonPending);

        // Escalate poison after grace period
        lc.escalate_poison();
        assert_eq!(lc.poison_state(), PoisonState::PoisonActive);

        // Transition to Tombstone
        assert!(lc.transition_to_tombstone().is_ok());
        assert_eq!(lc.state(), DatasetStateV1::Tombstone);
        assert_eq!(lc.poison_state(), PoisonState::MountDead);

        // Recover from tombstone
        assert!(lc.recover_tombstone().is_ok());
        assert!(lc.is_mountable());
        assert_eq!(lc.state(), DatasetStateV1::Active);
        assert_eq!(lc.poison_state(), PoisonState::MountOk);
    }

    #[test]
    fn abort_during_destroy() {
        let mut lc = DatasetLifecycle::new();
        lc.transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap();
        lc.escalate_poison();
        // Abort before tombstone
        assert!(lc.abort_destroy().is_ok());
        assert!(lc.is_mountable());
        assert_eq!(lc.state(), DatasetStateV1::Active);
        assert_eq!(lc.poison_state(), PoisonState::MountOk);
    }

    // ── GC pin set integration (gc-pin feature) ──────────────────

    #[cfg(feature = "alloc")]
    #[test]
    fn pin_roots_for_destroy_registers_all() {
        let mut lc = DatasetLifecycle::new();
        let roots = [
            TraversalRoot::new(TraversalRootType::InodeTable, BlockPointer(100), 500),
            TraversalRoot::new(TraversalRootType::ExtentMap, BlockPointer(200), 300),
            TraversalRoot::new(TraversalRootType::DirectoryIndex, BlockPointer(300), 200),
        ];
        lc.transition_to_destroying(DestroyFlags::NONE, &roots)
            .unwrap();
        assert_eq!(lc.gc_pin_set().count(), 3);
        assert!(lc
            .gc_pin_set()
            .is_pinned_by_type(TraversalRootType::InodeTable));
        assert!(lc
            .gc_pin_set()
            .is_pinned_by_type(TraversalRootType::ExtentMap));
        assert!(lc
            .gc_pin_set()
            .is_pinned_by_type(TraversalRootType::DirectoryIndex));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn unpin_root_removes_one() {
        let mut lc = DatasetLifecycle::new();
        let roots = [
            TraversalRoot::new(TraversalRootType::InodeTable, BlockPointer(100), 500),
            TraversalRoot::new(TraversalRootType::ExtentMap, BlockPointer(200), 300),
        ];
        lc.transition_to_destroying(DestroyFlags::NONE, &roots)
            .unwrap();
        assert_eq!(lc.gc_pin_set().count(), 2);
        lc.unpin_root_by_type(TraversalRootType::InodeTable);
        assert_eq!(lc.gc_pin_set().count(), 1);
        assert!(!lc
            .gc_pin_set()
            .is_pinned_by_type(TraversalRootType::InodeTable));
        assert!(lc
            .gc_pin_set()
            .is_pinned_by_type(TraversalRootType::ExtentMap));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn tombstone_clears_pin_set() {
        use tidefs_types_dataset_lifecycle_core::BlockPointer as BP;
        use tidefs_types_dataset_lifecycle_core::TraversalRoot as TR;
        use tidefs_types_dataset_lifecycle_core::TraversalRootType as TRT;

        let mut lc = DatasetLifecycle::new();
        let roots = [TR::new(TRT::InodeTable, BP(100), 500)];
        lc.transition_to_destroying(DestroyFlags::NONE, &roots)
            .unwrap();
        assert_eq!(lc.gc_pin_set().count(), 1);

        lc.escalate_poison();
        lc.transition_to_tombstone().unwrap();

        assert!(lc.gc_pin_set().is_empty());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn abort_clears_pin_set() {
        use tidefs_types_dataset_lifecycle_core::BlockPointer as BP;
        use tidefs_types_dataset_lifecycle_core::TraversalRoot as TR;
        use tidefs_types_dataset_lifecycle_core::TraversalRootType as TRT;

        let mut lc = DatasetLifecycle::new();
        let roots = [TR::new(TRT::InodeTable, BP(100), 500)];
        lc.transition_to_destroying(DestroyFlags::NONE, &roots)
            .unwrap();
        assert_eq!(lc.gc_pin_set().count(), 1);

        lc.abort_destroy().unwrap();

        assert!(lc.gc_pin_set().is_empty());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn repin_from_job_restores_roots() {
        let roots = [
            TraversalRoot::new(TraversalRootType::InodeTable, BlockPointer(100), 500),
            TraversalRoot::new(TraversalRootType::ExtentMap, BlockPointer(200), 300),
        ];
        let job = DestroyJobRecordV1::new(1, 1000, DestroyFlags::NONE, &roots, 800).unwrap();

        let mut lc = DatasetLifecycle::new();
        lc.transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap();

        lc.repin_from_destroy_job(&job);
        assert_eq!(lc.gc_pin_set().count(), 2);
        assert!(lc
            .gc_pin_set()
            .is_pinned_by_type(TraversalRootType::InodeTable));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn recover_tombstone_clears_pin_set() {
        use tidefs_types_dataset_lifecycle_core::BlockPointer as BP;
        use tidefs_types_dataset_lifecycle_core::TraversalRoot as TR;
        use tidefs_types_dataset_lifecycle_core::TraversalRootType as TRT;

        let mut lc = DatasetLifecycle::new();
        let roots = [TR::new(TRT::InodeTable, BP(100), 500)];
        lc.transition_to_destroying(DestroyFlags::NONE, &roots)
            .unwrap();
        lc.escalate_poison();
        lc.transition_to_tombstone().unwrap();
        assert!(lc.gc_pin_set().is_empty());

        lc.recover_tombstone().unwrap();
        assert!(lc.gc_pin_set().is_empty()); // still clear after recovery
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn pin_set_clone_equality() {
        let mut lc = DatasetLifecycle::new();
        let roots = [TraversalRoot::new(
            TraversalRootType::InodeTable,
            BlockPointer(100),
            500,
        )];
        lc.transition_to_destroying(DestroyFlags::NONE, &roots)
            .unwrap();

        let cloned = lc.clone();
        assert_eq!(lc, cloned);
        assert_eq!(lc.gc_pin_set(), cloned.gc_pin_set());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn pin_set_debug_format_includes_state() {
        let lc = DatasetLifecycle::new();
        let d = format!("{lc:?}");
        // Should include pin set info
        assert!(d.contains("gc_pin_set") || d.contains("GcPinSet") || d.contains("len:"));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn all_roots_processed_true_when_empty() {
        let lc = DatasetLifecycle::new();
        assert!(lc.all_roots_processed());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn all_roots_processed_false_when_pinned() {
        let mut lc = DatasetLifecycle::new();
        let roots = [TraversalRoot::new(
            TraversalRootType::InodeTable,
            BlockPointer(100),
            500,
        )];
        lc.transition_to_destroying(DestroyFlags::NONE, &roots)
            .unwrap();
        assert!(!lc.all_roots_processed());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn roots_remaining_counts_pinned_roots() {
        let mut lc = DatasetLifecycle::new();
        let roots = [
            TraversalRoot::new(TraversalRootType::InodeTable, BlockPointer(100), 500),
            TraversalRoot::new(TraversalRootType::ExtentMap, BlockPointer(200), 300),
        ];
        lc.transition_to_destroying(DestroyFlags::NONE, &roots)
            .unwrap();
        assert_eq!(lc.roots_remaining(), 2);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn all_roots_processed_after_unpin_all() {
        let mut lc = DatasetLifecycle::new();
        let roots = [TraversalRoot::new(
            TraversalRootType::InodeTable,
            BlockPointer(100),
            500,
        )];
        lc.transition_to_destroying(DestroyFlags::NONE, &roots)
            .unwrap();
        assert!(!lc.all_roots_processed());
        assert_eq!(lc.roots_remaining(), 1);
        lc.unpin_root_by_type(TraversalRootType::InodeTable);
        assert!(lc.all_roots_processed());
        assert_eq!(lc.roots_remaining(), 0);
    }

    #[test]
    fn states_are_exhaustive() {
        // Ensure all three states are covered by tests
        let states = [
            DatasetStateV1::Active,
            DatasetStateV1::Destroying,
            DatasetStateV1::Tombstone,
        ];
        for &s in &states {
            let lc = DatasetLifecycle::from_parts(s, PoisonState::MountOk);
            assert_eq!(lc.state(), s);
        }
    }

    #[test]
    fn validate_transition_after_recovery_is_idempotent() {
        let mut lc = DatasetLifecycle::new();
        lc.transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap();
        lc.transition_to_tombstone().unwrap();
        lc.recover_tombstone().unwrap();

        // After recovery, can destroy again.
        assert!(lc.validate_transition(DatasetStateV1::Destroying).is_ok());
        assert!(lc.transition_to_destroying(DestroyFlags::NONE, &[]).is_ok());
    }

    // ── Phase 5: destroy worker progress tracking ─────────────────

    #[test]
    fn init_destroy_job_tracks_state() {
        let roots = [
            TraversalRoot::new(TraversalRootType::InodeTable, BlockPointer(100), 500),
            TraversalRoot::new(TraversalRootType::ExtentMap, BlockPointer(200), 300),
        ];
        let mut lc = DatasetLifecycle::new();
        lc.transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap();

        let job = lc.init_destroy_job(42, 1000, DestroyFlags::NONE, &roots, 800);
        assert!(job.is_some());
        let job = job.unwrap();
        assert_eq!(job.destroy_job_id, 42);
        assert_eq!(job.destroy_commit_group, 1000);
        assert_eq!(job.objects_total, 800);
        assert_eq!(job.objects_reclaimed, 0);
        assert!(!job.is_completed());
    }

    #[test]
    fn init_destroy_job_refuses_when_not_destroying() {
        let roots = [TraversalRoot::new(
            TraversalRootType::InodeTable,
            BlockPointer(100),
            500,
        )];
        let mut lc = DatasetLifecycle::new(); // Active state
        let result = lc.init_destroy_job(42, 1000, DestroyFlags::NONE, &roots, 500);
        assert!(result.is_none());
    }

    #[test]
    fn update_destroy_progress_tracks_reclamation() {
        let roots = [TraversalRoot::new(
            TraversalRootType::InodeTable,
            BlockPointer(100),
            1000,
        )];
        let mut lc = DatasetLifecycle::new();
        lc.transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap();
        let _job = lc.init_destroy_job(1, 1, DestroyFlags::NONE, &roots, 1000);

        // Partial progress
        let done = lc.update_destroy_progress(500, 1024 * 1024);
        assert!(!done);
        let job = lc.destroy_job().unwrap();
        assert_eq!(job.objects_reclaimed, 500);
        assert_eq!(job.bytes_reclaimed, 1024 * 1024);
        assert_eq!(lc.destroy_progress_ppm(), 500_000);

        // Complete
        let done = lc.update_destroy_progress(1000, 2 * 1024 * 1024);
        assert!(done);
        assert!(lc.destroy_job().unwrap().is_completed());
        assert_eq!(lc.destroy_progress_ppm(), 1_000_000);
    }

    #[test]
    fn destroy_progress_ppm_zero_without_job() {
        let lc = DatasetLifecycle::new();
        assert_eq!(lc.destroy_progress_ppm(), 0);
    }

    #[test]
    fn destroy_job_none_after_abort() {
        let roots = [TraversalRoot::new(
            TraversalRootType::InodeTable,
            BlockPointer(100),
            500,
        )];
        let mut lc = DatasetLifecycle::new();
        lc.transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap();
        let _job = lc.init_destroy_job(1, 100, DestroyFlags::NONE, &roots, 500);
        assert!(lc.destroy_job().is_some());

        lc.abort_destroy().unwrap();
        assert!(lc.destroy_job().is_none());
        assert_eq!(lc.destroy_progress_ppm(), 0);
    }

    #[test]
    fn destroy_job_completed_after_tombstone() {
        let roots = [TraversalRoot::new(
            TraversalRootType::InodeTable,
            BlockPointer(100),
            1000,
        )];
        let mut lc = DatasetLifecycle::new();
        lc.transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap();
        let _job = lc.init_destroy_job(1, 100, DestroyFlags::NONE, &roots, 1000);
        let _done = lc.update_destroy_progress(500, 5000);

        lc.escalate_poison();
        lc.transition_to_tombstone().unwrap();

        let job = lc.destroy_job().unwrap();
        assert!(job.is_completed());
        assert_eq!(job.objects_reclaimed, 1000); // completed auto-sets total
        assert_eq!(lc.destroy_progress_ppm(), 1_000_000);
    }

    #[test]
    fn display_includes_destroy_job() {
        let roots = [TraversalRoot::new(
            TraversalRootType::InodeTable,
            BlockPointer(100),
            500,
        )];
        let mut lc = DatasetLifecycle::new();
        lc.transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap();
        let _job = lc.init_destroy_job(42, 1000, DestroyFlags::NONE, &roots, 500);
        let s = format!("{lc}");
        assert!(s.contains("destroying"));
        assert!(s.contains("job_id=42"));
        assert!(s.contains("in-progress"));
    }
    // ── Tombstone reaper (Phase 6) ────────────────────────────────

    #[test]
    fn reaper_policy_default_values() {
        let lc = DatasetLifecycle::new();
        let p = lc.reaper_policy();
        assert_eq!(p.min_age_secs, 86_400);
        assert_eq!(p.max_per_scan, 128);
        assert_eq!(p.scan_interval_secs, 60);
    }

    #[test]
    fn reaper_policy_set_and_get() {
        let mut lc = DatasetLifecycle::new();
        let policy = TombstoneReaperPolicy::new(3600, 50, 10);
        lc.set_reaper_policy(policy);
        let p = lc.reaper_policy();
        assert_eq!(p.min_age_secs, 3600);
        assert_eq!(p.max_per_scan, 50);
        assert_eq!(p.scan_interval_secs, 10);
    }

    #[test]
    fn is_reap_eligible_too_young() {
        let mut lc = DatasetLifecycle::new();
        let roots = [TraversalRoot::new(
            TraversalRootType::InodeTable,
            BlockPointer(100),
            500,
        )];
        lc.transition_to_destroying(DestroyFlags::NONE, &roots)
            .unwrap();
        let _job = lc.init_destroy_job(1, 100, DestroyFlags::NONE, &roots, 500);
        lc.transition_to_tombstone().unwrap();
        // completion_commit_group == u64::MAX; age at commit_group=100 is 0 < 100 -> TooYoung
        let eligibility = lc.is_reap_eligible(100);
        assert!(matches!(
            eligibility,
            ReapEligibility::TooYoung {
                age_commit_groups: 0,
                required: 100
            }
        ));
    }

    #[test]
    fn is_reap_eligible_eligible() {
        let mut lc = DatasetLifecycle::new();
        let roots = [TraversalRoot::new(
            TraversalRootType::InodeTable,
            BlockPointer(100),
            500,
        )];
        lc.transition_to_destroying(DestroyFlags::NONE, &roots)
            .unwrap();
        let _job = lc.init_destroy_job(1, 100, DestroyFlags::NONE, &roots, 500);
        // Manually mark complete at commit_group 100, then check at commit_group 300 (age=200 >= 100)
        if let Some(ref mut job) = lc.destroy_job {
            job.mark_complete(100, 5000, 500);
        }
        lc.state = DatasetStateV1::Tombstone;
        lc.set_cluster_consensus_granted();
        let eligibility = lc.is_reap_eligible(300);
        assert_eq!(eligibility, ReapEligibility::Eligible);
    }

    #[test]
    fn is_reap_eligible_non_terminal() {
        let lc = DatasetLifecycle::new();
        assert_eq!(lc.is_reap_eligible(0), ReapEligibility::Eligible);
        let mut lc2 = DatasetLifecycle::new();
        let roots: [TraversalRoot; 0] = [];
        lc2.transition_to_destroying(DestroyFlags::NONE, &roots)
            .unwrap();
        assert_eq!(lc2.is_reap_eligible(0), ReapEligibility::Eligible);
    }

    #[test]
    fn is_reap_eligible_no_destroy_job() {
        let mut lc = DatasetLifecycle::new();
        lc.state = DatasetStateV1::Tombstone;
        // No destroy_job -> returns Eligible
        assert_eq!(lc.is_reap_eligible(0), ReapEligibility::Eligible);
    }

    #[test]
    fn reap_tombstone_from_tombstone() {
        let mut lc = DatasetLifecycle::new();
        let roots = [TraversalRoot::new(
            TraversalRootType::InodeTable,
            BlockPointer(100),
            500,
        )];
        lc.transition_to_destroying(DestroyFlags::NONE, &roots)
            .unwrap();
        let _job = lc.init_destroy_job(1, 100, DestroyFlags::NONE, &roots, 500);
        lc.transition_to_tombstone().unwrap();
        assert!(lc.reap_tombstone().is_ok());
        assert!(lc.destroy_job().is_none());
    }

    #[test]
    fn reap_tombstone_from_active() {
        let mut lc = DatasetLifecycle::new();
        let err = lc.reap_tombstone().unwrap_err();
        assert!(matches!(
            err,
            tidefs_types_dataset_lifecycle_core::LifecycleError::NotTombstone { .. }
        ));
    }

    #[test]
    fn reap_tombstone_from_destroying() {
        let mut lc = DatasetLifecycle::new();
        let roots: [TraversalRoot; 0] = [];
        lc.transition_to_destroying(DestroyFlags::NONE, &roots)
            .unwrap();
        let err = lc.reap_tombstone().unwrap_err();
        assert!(matches!(
            err,
            tidefs_types_dataset_lifecycle_core::LifecycleError::NotTombstone { .. }
        ));
    }

    #[test]
    fn reap_tombstone_idempotent() {
        let mut lc = DatasetLifecycle::new();
        let roots = [TraversalRoot::new(
            TraversalRootType::InodeTable,
            BlockPointer(100),
            500,
        )];
        lc.transition_to_destroying(DestroyFlags::NONE, &roots)
            .unwrap();
        let _job = lc.init_destroy_job(1, 100, DestroyFlags::NONE, &roots, 500);
        lc.transition_to_tombstone().unwrap();
        assert!(lc.reap_tombstone().is_ok());
        // Second reap is Ok (destroy_job already None)
        assert!(lc.reap_tombstone().is_ok());
    }

    #[test]
    fn display_includes_reaper_info() {
        let mut lc = DatasetLifecycle::new();
        let roots = [TraversalRoot::new(
            TraversalRootType::InodeTable,
            BlockPointer(100),
            500,
        )];
        lc.transition_to_destroying(DestroyFlags::NONE, &roots)
            .unwrap();
        let _job = lc.init_destroy_job(1, 100, DestroyFlags::NONE, &roots, 500);
        lc.transition_to_tombstone().unwrap();
        let s = format!("{lc}");
        assert!(
            s.contains("reaper("),
            "display should contain reaper info: {s}"
        );
    }

    // ── pin_root (GC pin-set integration) ───────────────────────

    #[test]
    fn pin_root_adds_to_pin_set() {
        let mut lc = DatasetLifecycle::new();
        let root = TraversalRoot::new(TraversalRootType::SnapshotCatalog, BlockPointer(42), 100);
        assert!(lc.gc_pin_set().is_empty());
        lc.pin_root(root).unwrap();
        assert_eq!(lc.gc_pin_set().count(), 1);
        assert!(lc
            .gc_pin_set()
            .is_pinned_by_type(TraversalRootType::SnapshotCatalog));
    }

    #[test]
    fn distinct_snapshot_roots_get_separate_slots() {
        let mut lc = DatasetLifecycle::new();
        let r1 = TraversalRoot::new(TraversalRootType::SnapshotCatalog, BlockPointer(10), 50);
        let r2 = TraversalRoot::new(TraversalRootType::SnapshotCatalog, BlockPointer(20), 100);
        lc.pin_root(r1).unwrap();
        // With identity-based pinning, different block pointers → separate slots.
        lc.pin_root(r2).unwrap();
        // Two distinct slots, one pin each.
        assert_eq!(lc.gc_pin_set().count(), 2);
        assert_eq!(lc.gc_pin_set().total_pins(), 2);
        assert_eq!(lc.gc_pin_set().pin_count(r1), 1);
        assert_eq!(lc.gc_pin_set().pin_count(r2), 1);
        assert_eq!(
            lc.gc_pin_set()
                .pin_count_by_type(TraversalRootType::SnapshotCatalog),
            2
        );
    }

    #[test]
    fn pin_root_then_unpin_via_destroy_snapshot() {
        let mut lc = DatasetLifecycle::new();
        let root = TraversalRoot::new(TraversalRootType::SnapshotCatalog, BlockPointer(99), 200);
        lc.pin_root(root).unwrap();
        assert_eq!(lc.gc_pin_set().count(), 1);

        // destroy_snapshot unpins the SnapshotCatalog root
        lc.destroy_snapshot_by_type(&did(1)).unwrap();
        assert!(lc.gc_pin_set().is_empty());
    }

    #[test]
    fn pin_root_multiple_types() {
        let mut lc = DatasetLifecycle::new();
        let snap_root = TraversalRoot::new(TraversalRootType::SnapshotCatalog, BlockPointer(1), 10);
        let inode_root = TraversalRoot::new(TraversalRootType::InodeTable, BlockPointer(2), 20);
        lc.pin_root(snap_root).unwrap();
        lc.pin_root(inode_root).unwrap();
        assert_eq!(lc.gc_pin_set().count(), 2);
        assert!(lc
            .gc_pin_set()
            .is_pinned_by_type(TraversalRootType::SnapshotCatalog));
        assert!(lc
            .gc_pin_set()
            .is_pinned_by_type(TraversalRootType::InodeTable));
    }

    // ── destroy_snapshot (GC pin-set integration) ────────────────

    #[test]
    fn destroy_snapshot_unpins_snapshot_catalog_root() {
        let mut lc = DatasetLifecycle::new();
        let roots = [TraversalRoot::new(
            TraversalRootType::SnapshotCatalog,
            BlockPointer(42),
            1000,
        )];
        lc.transition_to_destroying(DestroyFlags::NONE, &roots)
            .unwrap();
        // SnapshotCatalog is now pinned
        assert!(lc
            .gc_pin_set()
            .is_pinned_by_type(TraversalRootType::SnapshotCatalog));
        assert_eq!(lc.gc_pin_set().count(), 1);

        // destroy_snapshot unpins the SnapshotCatalog root
        lc.destroy_snapshot_by_type(&did(1)).unwrap();
        assert!(!lc
            .gc_pin_set()
            .is_pinned_by_type(TraversalRootType::SnapshotCatalog));
        assert_eq!(lc.gc_pin_set().count(), 0);
    }

    #[test]
    fn destroy_snapshot_when_not_pinned_returns_not_found() {
        let mut lc = DatasetLifecycle::new();
        // No roots pinned — SnapshotCatalog not present
        let err = lc.destroy_snapshot_by_type(&did(1)).unwrap_err();
        assert_eq!(
            err,
            tidefs_gc_pin_set::GcPinError::NotFound {
                root_type: TraversalRootType::SnapshotCatalog
            }
        );
    }

    #[test]
    fn destroy_snapshot_does_not_affect_other_pinned_roots() {
        let mut lc = DatasetLifecycle::new();
        let roots = [
            TraversalRoot::new(TraversalRootType::InodeTable, BlockPointer(10), 500),
            TraversalRoot::new(TraversalRootType::SnapshotCatalog, BlockPointer(20), 300),
            TraversalRoot::new(TraversalRootType::ExtentMap, BlockPointer(30), 400),
        ];
        lc.transition_to_destroying(DestroyFlags::NONE, &roots)
            .unwrap();
        assert_eq!(lc.gc_pin_set().count(), 3);

        lc.destroy_snapshot_by_type(&did(1)).unwrap();

        assert_eq!(lc.gc_pin_set().count(), 2);
        assert!(lc
            .gc_pin_set()
            .is_pinned_by_type(TraversalRootType::InodeTable));
        assert!(!lc
            .gc_pin_set()
            .is_pinned_by_type(TraversalRootType::SnapshotCatalog));
        assert!(lc
            .gc_pin_set()
            .is_pinned_by_type(TraversalRootType::ExtentMap));
    }

    // ── create_snapshot pinning ─────────────────────────────────

    #[cfg(feature = "alloc")]
    #[test]
    fn create_snapshot_pins_snapshot_catalog_root() {
        let mut lc = DatasetLifecycle::new();
        assert!(lc.gc_pin_set().is_empty());

        lc.create_snapshot(did(1), did(2), 100).unwrap();

        assert!(lc
            .gc_pin_set()
            .is_pinned_by_type(TraversalRootType::SnapshotCatalog));
        assert_eq!(lc.gc_pin_set().count(), 1);
        assert_eq!(lc.gc_pin_set().total_pins(), 1);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn create_multiple_snapshots_increments_pin_count() {
        let mut lc = DatasetLifecycle::new();

        lc.create_snapshot(did(10), did(20), 100).unwrap();
        lc.create_snapshot(did(11), did(21), 101).unwrap();
        lc.create_snapshot(did(12), did(22), 102).unwrap();

        // Each create_snapshot pins the same root type (SnapshotCatalog)
        // so the count is 1 (one root type) but total_pins = 3
        assert_eq!(lc.gc_pin_set().count(), 1);
        assert_eq!(lc.gc_pin_set().total_pins(), 3);
        assert_eq!(
            lc.gc_pin_set()
                .pin_count_by_type(TraversalRootType::SnapshotCatalog),
            3
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn create_then_destroy_snapshot_balances_pins() {
        let mut lc = DatasetLifecycle::new();

        lc.create_snapshot(did(30), did(40), 200).unwrap();
        assert_eq!(lc.gc_pin_set().total_pins(), 1);

        lc.destroy_snapshot_by_type(&did(30)).unwrap();
        assert!(lc.gc_pin_set().is_empty());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn create_snapshot_idempotent_pin() {
        let mut lc = DatasetLifecycle::new();

        lc.create_snapshot(did(50), did(60), 300).unwrap();
        lc.create_snapshot(did(50), did(60), 300).unwrap();

        assert_eq!(lc.gc_pin_set().total_pins(), 2);
        // destroy_snapshot uses force_unpin which removes the root
        // entirely regardless of pin count.
        lc.destroy_snapshot_by_type(&did(50)).unwrap();
        assert!(lc.gc_pin_set().is_empty());
    }

    // ── Phase 4: pin_root_for_service + release_pin ─────────────

    #[cfg(feature = "alloc")]
    #[test]
    fn pin_root_for_service_adds_pin() {
        let mut lc = DatasetLifecycle::new();
        let root = TraversalRoot::new(TraversalRootType::InodeTable, BlockPointer(42), 100);
        let pin = lc
            .pin_root_for_service(root, BackgroundService::Scrub)
            .unwrap();
        assert_eq!(pin.root_type(), TraversalRootType::InodeTable);
        assert_eq!(pin.service(), BackgroundService::Scrub);
        assert!(lc
            .gc_pin_set()
            .is_pinned_by_type(TraversalRootType::InodeTable));
        assert_eq!(lc.gc_pin_set().count(), 1);
        assert_eq!(lc.gc_pin_set().total_pins(), 1);
        // Release explicitly.
        lc.release_pin(pin).unwrap();
        assert!(!lc
            .gc_pin_set()
            .is_pinned_by_type(TraversalRootType::InodeTable));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn multi_service_pin_same_root_refcounts() {
        let mut lc = DatasetLifecycle::new();
        let root = TraversalRoot::new(TraversalRootType::SnapshotCatalog, BlockPointer(10), 50);
        // Two services pin the same exact root (same type + same block pointer)
        let pin1 = lc
            .pin_root_for_service(root, BackgroundService::Cleanup)
            .unwrap();
        let pin2 = lc
            .pin_root_for_service(root, BackgroundService::Scrub)
            .unwrap();
        // One slot, two pins on same root.
        assert_eq!(lc.gc_pin_set().count(), 1);
        assert_eq!(lc.gc_pin_set().total_pins(), 2);
        assert_eq!(lc.gc_pin_set().pin_count(root), 2);
        assert_eq!(
            lc.gc_pin_set()
                .pin_count_by_type(TraversalRootType::SnapshotCatalog),
            2
        );
        lc.release_pin(pin1).unwrap();
        assert_eq!(lc.gc_pin_set().total_pins(), 1);
        assert_eq!(lc.gc_pin_set().pin_count(root), 1);
        lc.release_pin(pin2).unwrap();
        assert_eq!(lc.gc_pin_set().count(), 0);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn gc_skips_pinned_root_via_is_pinned() {
        let mut lc = DatasetLifecycle::new();
        let root = TraversalRoot::new(TraversalRootType::ExtentMap, BlockPointer(300), 1000);
        let pin = lc
            .pin_root_for_service(root, BackgroundService::Destroy)
            .unwrap();
        // GC would call is_pinned() before freeing — if pinned, skip.
        assert!(lc
            .gc_pin_set()
            .is_pinned_by_type(TraversalRootType::ExtentMap));
        assert!(
            lc.gc_pin_set()
                .pin_count_by_type(TraversalRootType::ExtentMap)
                > 0
        );
        lc.release_pin(pin).unwrap();
        assert!(!lc
            .gc_pin_set()
            .is_pinned_by_type(TraversalRootType::ExtentMap));
    }

    // ── Phase 4: Stats ──────────────────────────────────────────

    #[cfg(feature = "alloc")]
    #[test]
    fn stats_reports_active_pins() {
        let mut lc = DatasetLifecycle::new();
        let root = TraversalRoot::new(TraversalRootType::InodeTable, BlockPointer(42), 100);
        let _pin = lc
            .pin_root_for_service(root, BackgroundService::Cleanup)
            .unwrap();
        let stats = lc.stats();
        assert_eq!(stats.state, DatasetStateV1::Active);
        assert_eq!(stats.active_pins, 1);
        assert_eq!(stats.distinct_pinned_roots, 1);
        assert_eq!(
            stats.per_root_pins[TraversalRootType::InodeTable as u8 as usize],
            1
        );
        assert!(!stats.destroy_in_progress);
        assert_eq!(stats.destroy_progress_ppm, 0);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn stats_reflects_multi_pin() {
        let mut lc = DatasetLifecycle::new();
        let r1 = TraversalRoot::new(TraversalRootType::InodeTable, BlockPointer(1), 10);
        let r2 = TraversalRoot::new(TraversalRootType::ExtentMap, BlockPointer(2), 20);
        let _pin1 = lc
            .pin_root_for_service(r1, BackgroundService::Cleanup)
            .unwrap();
        let _pin2 = lc
            .pin_root_for_service(r2, BackgroundService::Scrub)
            .unwrap();
        let _pin3 = lc
            .pin_root_for_service(r1, BackgroundService::Destroy)
            .unwrap();
        let stats = lc.stats();
        assert_eq!(stats.active_pins, 3);
        assert_eq!(stats.distinct_pinned_roots, 2);
        assert_eq!(
            stats.per_root_pins[TraversalRootType::InodeTable as u8 as usize],
            2
        );
        assert_eq!(
            stats.per_root_pins[TraversalRootType::ExtentMap as u8 as usize],
            1
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn stats_empty_when_no_pins() {
        let lc = DatasetLifecycle::new();
        let stats = lc.stats();
        assert_eq!(stats.active_pins, 0);
        assert_eq!(stats.distinct_pinned_roots, 0);
        for i in 0..7 {
            assert_eq!(stats.per_root_pins[i], 0);
        }
    }

    // ── BackgroundService display ───────────────────────────────

    #[test]
    fn background_service_display() {
        assert_eq!(BackgroundService::Destroy.to_string(), "destroy");
        assert_eq!(BackgroundService::Cleanup.to_string(), "cleanup");
        assert_eq!(BackgroundService::Scrub.to_string(), "scrub");
        assert_eq!(BackgroundService::Compaction.to_string(), "compaction");
        assert_eq!(BackgroundService::ViewBuilder.to_string(), "view-builder");
        assert_eq!(BackgroundService::Defrag.to_string(), "defrag");
        assert_eq!(BackgroundService::Rebuild.to_string(), "rebuild");
    }

    // ── PinnedRoot Debug ────────────────────────────────────────

    #[cfg(feature = "alloc")]
    #[test]
    fn pinned_root_debug_includes_service() {
        let mut lc = DatasetLifecycle::new();
        let root = TraversalRoot::new(TraversalRootType::InodeTable, BlockPointer(1), 10);
        let pin = lc
            .pin_root_for_service(root, BackgroundService::Destroy)
            .unwrap();
        let debug_str = format!("{pin:?}");
        assert!(debug_str.contains("InodeTable"));
    }

    // ── PoisonGuard and PoisonError ────────────────────────────────

    #[test]
    fn poison_guard_check_ok_when_healthy() {
        let notif = PoisonNotification::new();
        let guard = PoisonGuard::new(notif);
        assert!(guard.check().is_ok());
        assert!(!guard.is_poisoned());
    }

    #[test]
    fn poison_guard_check_err_when_poisoned() {
        let notif = PoisonNotification::with_state_and_reason(
            PoisonState::PoisonActive,
            PoisonReason::CorruptionDetected,
        );
        let guard = PoisonGuard::new(notif);
        let err = guard.check().unwrap_err();
        assert_eq!(err.reason, PoisonReason::CorruptionDetected);
        assert_eq!(err.state, PoisonState::PoisonActive);
        assert_eq!(err.errno(), 5);
        assert!(guard.is_poisoned());
    }

    #[test]
    fn poison_guard_check_err_on_pending() {
        let notif = PoisonNotification::with_state_and_reason(
            PoisonState::PoisonPending,
            PoisonReason::AdminAction,
        );
        let guard = PoisonGuard::new(notif);
        assert!(guard.check().is_err());
        assert!(guard.is_poisoned());
    }

    #[test]
    fn poison_guard_poison_state_and_reason_accessors() {
        let notif = PoisonNotification::with_state_and_reason(
            PoisonState::PoisonActive,
            PoisonReason::FatalIOError,
        );
        let guard = PoisonGuard::new(notif);
        assert_eq!(guard.poison_state(), PoisonState::PoisonActive);
        assert_eq!(guard.poison_reason(), PoisonReason::FatalIOError);
    }

    #[test]
    fn poison_guard_clone_shares_state() {
        let notif = PoisonNotification::new();
        let guard1 = PoisonGuard::new(notif.clone());
        let guard2 = guard1.clone();
        assert!(guard1.check().is_ok());
        assert!(guard2.check().is_ok());
        notif.set_both(PoisonState::PoisonActive, PoisonReason::AdminAction);
        assert!(guard1.check().is_err());
        assert!(guard2.check().is_err());
    }

    #[test]
    fn poison_error_display_includes_state_and_reason() {
        let err = PoisonError {
            reason: PoisonReason::CorruptionDetected,
            state: PoisonState::PoisonActive,
        };
        let s = format!("{err}");
        assert!(s.contains("poisoned"));
        assert!(s.contains("POISON_ACTIVE"));
        assert!(s.contains("CORRUPTION_DETECTED"));
    }

    #[test]
    fn poison_error_errno_is_eio() {
        let err = PoisonError {
            reason: PoisonReason::FatalIOError,
            state: PoisonState::PoisonActive,
        };
        assert_eq!(err.errno(), 5);
    }

    // ── DrainInFlight ──────────────────────────────────────────────

    #[test]
    fn drain_inflight_enter_when_healthy() {
        let notif = PoisonNotification::new();
        let drain = DrainInFlight::new(notif);
        assert!(drain.enter());
        assert_eq!(drain.inflight_count(), 1);
    }

    #[test]
    fn drain_inflight_rejects_when_poisoned() {
        let notif = PoisonNotification::with_state_and_reason(
            PoisonState::PoisonActive,
            PoisonReason::AdminAction,
        );
        let drain = DrainInFlight::new(notif);
        assert!(!drain.enter());
        assert_eq!(drain.inflight_count(), 0);
    }

    #[test]
    fn drain_inflight_rejects_when_poison_pending() {
        let notif = PoisonNotification::with_state_and_reason(
            PoisonState::PoisonPending,
            PoisonReason::CorruptionDetected,
        );
        let drain = DrainInFlight::new(notif);
        assert!(!drain.enter());
    }

    #[test]
    fn drain_inflight_enter_leave_sequence() {
        let notif = PoisonNotification::new();
        let drain = DrainInFlight::new(notif);
        assert!(drain.enter());
        assert_eq!(drain.inflight_count(), 1);
        assert!(!drain.is_drained());
        drain.leave();
        assert_eq!(drain.inflight_count(), 0);
        assert!(drain.is_drained());
    }

    #[test]
    fn drain_inflight_multiple_concurrent() {
        let notif = PoisonNotification::new();
        let drain = DrainInFlight::new(notif);
        for _ in 0..5 {
            assert!(drain.enter());
        }
        assert_eq!(drain.inflight_count(), 5);
        for _ in 0..5 {
            drain.leave();
        }
        assert_eq!(drain.inflight_count(), 0);
        assert!(drain.is_drained());
    }

    #[test]
    fn drain_inflight_is_drained_initially() {
        let notif = PoisonNotification::new();
        let drain = DrainInFlight::new(notif);
        assert!(drain.is_drained());
        assert_eq!(drain.inflight_count(), 0);
    }

    #[test]
    fn drain_inflight_atomic_visibility() {
        let notif1 = PoisonNotification::new();
        let notif2 = notif1.clone(); // same shared state
        let drain1 = DrainInFlight::new(notif1);
        let drain2 = DrainInFlight::new(notif2);
        // DrainInFlight itself doesn't share inflight across clones,
        // but notification is shared — opaque sanity:
        assert!(drain1.enter());
        // drain2 has its own inflight counter (0)
        assert_eq!(drain2.inflight_count(), 0);
        drain1.leave();
        assert!(drain1.is_drained());
    }

    #[test]
    fn notification_reason_tracking() {
        let notif = PoisonNotification::new();
        assert_eq!(notif.get_reason(), PoisonReason::None);
        let old = notif.set_reason(PoisonReason::CorruptionDetected);
        assert_eq!(old, PoisonReason::None);
        assert_eq!(notif.get_reason(), PoisonReason::CorruptionDetected);
    }

    #[test]
    fn notification_set_both() {
        let notif = PoisonNotification::new();
        notif.set_both(PoisonState::PoisonActive, PoisonReason::FatalIOError);
        assert_eq!(notif.get(), PoisonState::PoisonActive);
        assert_eq!(notif.get_reason(), PoisonReason::FatalIOError);
    }

    #[test]
    fn notification_with_state_and_reason() {
        let notif = PoisonNotification::with_state_and_reason(
            PoisonState::PoisonPending,
            PoisonReason::MetadataInconsistency,
        );
        assert_eq!(notif.get(), PoisonState::PoisonPending);
        assert_eq!(notif.get_reason(), PoisonReason::MetadataInconsistency);
    }

    #[test]
    fn notification_should_reject_new_ops() {
        let healthy = PoisonNotification::new();
        assert!(!healthy.should_reject_new_ops());

        let pending = PoisonNotification::with_state_and_reason(
            PoisonState::PoisonPending,
            PoisonReason::AdminAction,
        );
        assert!(pending.should_reject_new_ops());

        let active = PoisonNotification::with_state_and_reason(
            PoisonState::PoisonActive,
            PoisonReason::CorruptionDetected,
        );
        assert!(active.should_reject_new_ops());

        let dead = PoisonNotification::with_state_and_reason(
            PoisonState::MountDead,
            PoisonReason::ClusterConsensusLost,
        );
        assert!(dead.should_reject_new_ops());
    }
    // ── DerivedCatalog integration (issue #5215) ──────────────────

    #[test]
    fn create_snapshot_registers_in_derived_catalog() {
        let mut lc = DatasetLifecycle::new();
        let clone_id = did(10);
        let origin_id = did(20);

        lc.create_snapshot(clone_id, origin_id, 100).unwrap();

        let cat = lc.derived_catalog();
        assert_eq!(cat.len(), 1);
        assert!(cat.is_derived(&clone_id));
        // The clone's origin should be the origin dataset (converted to SnapshotId)
        let origin_snap = cat.lookup_origin(&clone_id);
        assert!(origin_snap.is_some());
        // origin_id as SnapshotId should have clone_id in its clone list
        let snap_id = SnapshotId::from(origin_id);
        assert!(cat.has_clones(&snap_id));
        let clones = cat.lookup_clones(&snap_id);
        assert_eq!(clones.len(), 1);
        assert_eq!(clones[0], clone_id);
    }

    #[test]
    fn destroy_snapshot_deregisters_from_derived_catalog() {
        let mut lc = DatasetLifecycle::new();
        let clone_id = did(30);

        lc.create_snapshot(clone_id, did(40), 200).unwrap();
        assert_eq!(lc.derived_catalog().len(), 1);

        lc.destroy_snapshot_by_type(&clone_id).unwrap();

        assert!(lc.derived_catalog().is_empty());
        assert!(!lc.derived_catalog().is_derived(&clone_id));
    }

    #[test]
    fn destroy_snapshot_leaves_unrelated_entries() {
        let mut lc = DatasetLifecycle::new();
        let clone_a = did(10);
        let clone_b = did(20);

        lc.create_snapshot(clone_a, did(100), 100).unwrap();
        lc.create_snapshot(clone_b, did(200), 200).unwrap();
        assert_eq!(lc.derived_catalog().len(), 2);

        lc.destroy_snapshot_by_type(&clone_a).unwrap();

        assert_eq!(lc.derived_catalog().len(), 1);
        assert!(!lc.derived_catalog().is_derived(&clone_a));
        assert!(lc.derived_catalog().is_derived(&clone_b));
    }

    #[test]
    fn encode_decode_roundtrip_preserves_catalog() {
        let mut lc = DatasetLifecycle::new();
        lc.create_snapshot(did(1), did(10), 100).unwrap();
        lc.create_snapshot(did(2), did(20), 200).unwrap();
        lc.create_snapshot(did(3), did(10), 300).unwrap();

        let encoded = lc.encode();
        let decoded = DatasetLifecycle::decode(&encoded).unwrap();

        assert_eq!(decoded.state(), lc.state());
        assert_eq!(decoded.poison_state(), lc.poison_state());
        assert_eq!(decoded.grace_secs(), lc.grace_secs());
        assert_eq!(decoded.derived_catalog().len(), 3);
        assert!(decoded.derived_catalog().is_derived(&did(1)));
        assert!(decoded.derived_catalog().is_derived(&did(2)));
        assert!(decoded.derived_catalog().is_derived(&did(3)));

        // Verify clone index is preserved
        let snap10 = SnapshotId::from(did(10));
        let clones = decoded.derived_catalog().lookup_clones(&snap10);
        assert_eq!(clones.len(), 2);
        assert!(clones.contains(&did(1)));
        assert!(clones.contains(&did(3)));
    }

    #[test]
    fn encode_decode_empty_catalog() {
        let lc = DatasetLifecycle::new();
        let encoded = lc.encode();
        let decoded = DatasetLifecycle::decode(&encoded).unwrap();
        assert!(decoded.derived_catalog().is_empty());
        assert_eq!(decoded.state(), DatasetStateV1::Active);
    }

    #[test]
    fn create_duplicate_clone_replaces_origin() {
        let mut lc = DatasetLifecycle::new();
        let clone_id = did(50);

        // First creation: clone of origin A
        lc.create_snapshot(clone_id, did(100), 100).unwrap();
        assert_eq!(lc.derived_catalog().len(), 1);
        let snap100 = SnapshotId::from(did(100));
        assert!(lc.derived_catalog().has_clones(&snap100));

        // Second creation: same clone but different origin B
        lc.create_snapshot(clone_id, did(200), 200).unwrap();
        assert_eq!(lc.derived_catalog().len(), 1); // still 1 entry (replaced)

        // Origin A should no longer have this clone
        assert!(!lc.derived_catalog().has_clones(&snap100));

        // Origin B should now have this clone
        let snap200 = SnapshotId::from(did(200));
        assert!(lc.derived_catalog().has_clones(&snap200));
        assert_eq!(
            lc.derived_catalog().lookup_origin(&clone_id).unwrap(),
            snap200
        );
    }

    #[test]
    fn derived_catalog_mut_allows_direct_manipulation() {
        let mut lc = DatasetLifecycle::new();
        lc.create_snapshot(did(1), did(10), 100).unwrap();

        // Direct manipulation through mutable accessor
        lc.derived_catalog_mut().clear();
        assert!(lc.derived_catalog().is_empty());
    }

    #[test]
    fn decode_malformed_data_returns_none() {
        // Too short
        assert!(DatasetLifecycle::decode(&[]).is_none());
        assert!(DatasetLifecycle::decode(&[0u8; 5]).is_none());

        // Invalid state discriminant
        let mut data = vec![0xFFu8, 0x00, 0x00, 0x00, 0x00, 0x00];
        data.extend_from_slice(&[0u8; 4]); // empty catalog
        assert!(DatasetLifecycle::decode(&data).is_none());

        // Invalid poison discriminant
        let mut data2 = vec![0x00u8, 0xFF, 0x00, 0x00, 0x00, 0x00];
        data2.extend_from_slice(&[0u8; 4]); // empty catalog
        assert!(DatasetLifecycle::decode(&data2).is_none());
    }

    // ── Freeze / unfreeze (issue #5226) ───────────────────────────────

    #[test]
    fn freeze_sets_frozen_flag() {
        let mut lc = DatasetLifecycle::new();
        assert!(!lc.is_frozen());
        lc.freeze().unwrap();
        assert!(lc.is_frozen());
    }

    #[test]
    fn freeze_when_already_frozen_returns_error() {
        let mut lc = DatasetLifecycle::new();
        lc.freeze().unwrap();
        assert!(lc.freeze().is_err());
    }

    #[test]
    fn unfreeze_clears_frozen_flag() {
        let mut lc = DatasetLifecycle::new();
        lc.freeze().unwrap();
        assert!(lc.is_frozen());
        lc.unfreeze();
        assert!(!lc.is_frozen());
    }

    #[test]
    fn unfreeze_when_not_frozen_is_noop() {
        let mut lc = DatasetLifecycle::new();
        assert!(!lc.is_frozen());
        lc.unfreeze();
        assert!(!lc.is_frozen());
    }

    #[test]
    fn freeze_unfreeze_roundtrip() {
        let mut lc = DatasetLifecycle::new();
        for _ in 0..5 {
            lc.freeze().unwrap();
            assert!(lc.is_frozen());
            lc.unfreeze();
            assert!(!lc.is_frozen());
        }
    }

    // ── create_snapshot_with_anchor (issue #5226) ─────────────────────

    fn snapshot_anchor_create(
        clone_dataset_id: DatasetId,
        origin_dataset_id: DatasetId,
        snapshot_name: &str,
        committed_root_txg: u64,
        root_handle: u64,
        creation_commit_group: u64,
        created_at_secs: u64,
    ) -> SnapshotAnchorCreate {
        SnapshotAnchorCreate {
            clone_dataset_id,
            origin_dataset_id,
            snapshot_name: snapshot_name.into(),
            committed_root_txg,
            root_handle,
            creation_commit_group,
            created_at_secs,
        }
    }

    #[test]
    fn create_snapshot_with_anchor_persists_entry() {
        let mut lc = DatasetLifecycle::new();
        let clone_id = did(10);
        let origin_id = did(100);

        let anchor = lc
            .create_snapshot_with_anchor(snapshot_anchor_create(
                clone_id,
                origin_id,
                "snap-2025",
                42,
                7,
                42,
                1715000000,
            ))
            .unwrap();

        assert_eq!(anchor.dataset_id, clone_id);
        assert_eq!(anchor.name, "snap-2025");
        assert_eq!(anchor.committed_root_txg, 42);
        assert_eq!(anchor.root_handle, 7);
        assert_eq!(anchor.creation_commit_group, 42);
        assert_eq!(anchor.created_at_secs, 1715000000);
    }

    #[test]
    fn create_snapshot_with_anchor_registers_in_derived_catalog() {
        let mut lc = DatasetLifecycle::new();
        let clone_id = did(10);
        let origin_id = did(100);

        lc.create_snapshot_with_anchor(snapshot_anchor_create(
            clone_id, origin_id, "snap-a", 100, 1, 100, 1000,
        ))
        .unwrap();

        // Clone registered in derived catalog
        assert!(lc.derived_catalog().is_derived(&clone_id));
        let snap100 = SnapshotId::from(origin_id);
        assert!(lc.derived_catalog().has_clones(&snap100));
    }

    #[test]
    fn create_snapshot_with_anchor_pins_gc_root() {
        let mut lc = DatasetLifecycle::new();

        lc.create_snapshot_with_anchor(snapshot_anchor_create(
            did(1),
            did(10),
            "snap",
            10,
            1,
            10,
            100,
        ))
        .unwrap();

        // GC pin set should have the snapshot catalog root pinned
        assert!(lc.gc_pin_set().total_pins() >= 1);
    }

    #[test]
    fn create_snapshot_with_anchor_unfreezes_after_success() {
        let mut lc = DatasetLifecycle::new();

        lc.create_snapshot_with_anchor(snapshot_anchor_create(
            did(1),
            did(10),
            "snap",
            10,
            1,
            10,
            100,
        ))
        .unwrap();

        // Dataset should be unfrozen after successful snapshot creation
        assert!(!lc.is_frozen());
    }

    #[test]
    fn create_snapshot_with_anchor_unfreezes_after_pin_error() {
        let mut lc = DatasetLifecycle::new();

        // Fill the GC pin set to capacity so pin fails on the 7th pin.
        // MAX_TRAVERSAL_ROOTS is 6, so pinning 6 distinct root types fills it.
        for i in 0..6u8 {
            let root = TraversalRoot::new(
                TraversalRootType::from_u8(i + 1).unwrap(),
                BlockPointer(i as u64 + 1),
                1,
            );
            let _ = lc.pin_root_for_service(root, BackgroundService::Scrub);
        }

        // pin set is full; create_snapshot_with_anchor should fail
        // but still unfreeze
        let _ = lc.create_snapshot_with_anchor(snapshot_anchor_create(
            did(1),
            did(10),
            "snap",
            10,
            1,
            10,
            100,
        ));

        // Verify the contract: whether it succeeds or fails, unfreeze happens.
        assert!(!lc.is_frozen());
    }

    #[test]
    fn create_snapshot_with_anchor_fails_when_already_frozen() {
        let mut lc = DatasetLifecycle::new();
        lc.freeze().unwrap();

        let result = lc.create_snapshot_with_anchor(snapshot_anchor_create(
            did(1),
            did(10),
            "snap",
            10,
            1,
            10,
            100,
        ));
        assert!(result.is_err());
    }

    #[test]
    fn snapshot_anchor_survives_encode_decode_roundtrip() {
        let mut lc = DatasetLifecycle::new();

        lc.create_snapshot_with_anchor(snapshot_anchor_create(
            did(42),
            did(100),
            "my-snapshot",
            500,
            3,
            500,
            1715000000,
        ))
        .unwrap();

        let encoded = lc.encode();
        let decoded = DatasetLifecycle::decode(&encoded).unwrap();

        // Verify snapshot anchor is preserved
        assert!(decoded
            .derived_catalog()
            .has_snapshot_anchor(&did(42), "my-snapshot"));
        let anchors = decoded.derived_catalog().list_snapshot_anchors(&did(42));
        assert_eq!(anchors.len(), 1);
        assert_eq!(anchors[0].committed_root_txg, 500);
        assert_eq!(anchors[0].root_handle, 3);
    }

    #[test]
    fn multiple_snapshot_anchors_survive_roundtrip() {
        let mut lc = DatasetLifecycle::new();

        lc.create_snapshot_with_anchor(snapshot_anchor_create(
            did(1),
            did(10),
            "s1",
            100,
            1,
            100,
            1000,
        ))
        .unwrap();
        lc.create_snapshot_with_anchor(snapshot_anchor_create(
            did(1),
            did(10),
            "s2",
            200,
            2,
            200,
            2000,
        ))
        .unwrap();

        let encoded = lc.encode();
        let decoded = DatasetLifecycle::decode(&encoded).unwrap();

        let anchors = decoded.derived_catalog().list_snapshot_anchors(&did(1));
        assert_eq!(anchors.len(), 2);
        assert_eq!(anchors[0].name, "s1");
        assert_eq!(anchors[1].name, "s2");
    }
}
