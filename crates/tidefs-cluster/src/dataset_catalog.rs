// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Cluster dataset-catalog wrapper gated by lease/fence ownership.
//!
//! Wraps [`tidefs_dataset_catalog::DatasetCatalog`] and gates catalog
//! mutations on the active write fence.
//!
//! ## Authority
//!
//! This module is **not** a second catalog authority. It delegates catalog
//! lookups and mutations to [`tidefs_dataset_catalog::DatasetCatalog`] and
//! adds lease-gate state plus catalog-delta preparation and application.
//!
//! ## Replication model
//!
//! The wrapper's contained catalog and its encode/decode helpers are local
//! mechanisms for callers. They are not evidence of clustered dataset
//! readiness, failover, complete fencing, recovery, or product admission.
//!
//! ## Integration
//!
//! ```ignore
//! use tidefs_cluster::dataset_catalog::ClusterDatasetCatalog;
//! use tidefs_cluster::write_fence::WriteFence;
//!
//! let mut cat = ClusterDatasetCatalog::new();
//! cat.on_lease_acquired(WriteFence::new(epoch, 1));
//! cat.create("pool/fs1", dataset_id, dataset_type, 42, vec![], flags)?;
//! let encoded = cat.encode();
//! cat.on_lease_lost();
//! ```

use serde::{Deserialize, Serialize};

use tidefs_dataset_catalog::{
    CatalogError, DatasetCatalog, DatasetChildDetails, DatasetFlags, DatasetId, DatasetType,
    LifecycleState, SyncGuarantee,
};

use crate::write_fence::WriteFence;

// ---------------------------------------------------------------------------
// ClusterCatalogError
// ---------------------------------------------------------------------------

/// Errors returned by cluster-gated catalog operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClusterCatalogError {
    /// The operation requires lease-holder authority but this node does not
    /// hold the write lease.
    NotLeaseHolder,
    /// A fence mismatch was detected: the operation's fence does not
    /// match the active fence.
    FenceMismatch,
    /// The underlying catalog operation failed.
    Catalog(CatalogError),
}

impl core::fmt::Display for ClusterCatalogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ClusterCatalogError::NotLeaseHolder => {
                f.write_str("not the lease holder; catalog mutations require write-lease authority")
            }
            ClusterCatalogError::FenceMismatch => {
                f.write_str("write fence mismatch; catalog mutation rejected")
            }
            ClusterCatalogError::Catalog(e) => write!(f, "catalog error: {e}"),
        }
    }
}

impl From<CatalogError> for ClusterCatalogError {
    fn from(e: CatalogError) -> Self {
        ClusterCatalogError::Catalog(e)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatasetCreateRequest {
    pub path: String,
    pub dataset_id: DatasetId,
    pub dataset_type: DatasetType,
    pub creation_txg: u64,
    pub properties: Vec<u8>,
    pub flags: DatasetFlags,
}

// ---------------------------------------------------------------------------
// CatalogDelta — serializable catalog mutation for cluster proposal/commit
// ---------------------------------------------------------------------------

/// A serializable dataset catalog mutation for cluster epoch proposals.
///
/// The lease holder prepares a [`CatalogDelta`] that describes the desired
/// catalog mutation. The delta is serialized and included in a cluster
/// epoch proposal via `MembershipMessage::ProposalSubmission`.
/// Peers validate and ack the delta; upon commit, all nodes apply it
/// via [`ClusterDatasetCatalog::apply_delta`].
///
/// Deltas are applied in epoch order; applying a delta does NOT check
/// the lease gate (the epoch commit already represents quorum consensus).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CatalogDelta {
    /// Create a new dataset in the catalog.
    Create {
        /// Full hierarchical path (e.g. `"pool/fs1"`).
        path: String,
        /// Stable dataset identifier (UUID v4, 16 bytes).
        dataset_id_bytes: Vec<u8>,
        /// Dataset class discriminant (see [`DatasetType`] for values).
        dataset_type_u8: u8,
        /// Commit-group number at creation time.
        creation_txg: u64,
        /// Opaque property blob (serialized key/value pairs).
        properties: Vec<u8>,
        /// Per-dataset creation flags bitmask.
        flags_u16: u16,
    },
    /// Destroy a dataset, removing its catalog entry.
    Destroy {
        /// Full hierarchical path to remove.
        path: String,
    },
    /// Rename a dataset, preserving its stable [`DatasetId`].
    Rename {
        /// Current path.
        old_path: String,
        /// Target path.
        new_path: String,
    },
    /// Transition a dataset to the Destroying lifecycle state.
    TransitionToDestroying { path: String },
    /// Transition a dataset to the Destroyed lifecycle state.
    TransitionToDestroyed { path: String },
}

impl CatalogDelta {
    /// Returns a human-readable description of this delta.
    pub fn description(&self) -> String {
        match self {
            CatalogDelta::Create { path, .. } => format!("create dataset '{path}'"),
            CatalogDelta::Destroy { path } => format!("destroy dataset '{path}'"),
            CatalogDelta::Rename { old_path, new_path } => {
                format!("rename dataset '{old_path}' -> '{new_path}'")
            }
            CatalogDelta::TransitionToDestroying { path } => {
                format!("transition dataset '{path}' to destroying")
            }
            CatalogDelta::TransitionToDestroyed { path } => {
                format!("transition dataset '{path}' to destroyed")
            }
        }
    }

    /// Validate the delta's internal data without modifying any catalog.
    ///
    /// Returns `Ok(())` if the delta is structurally valid, or an
    /// appropriate error. This allows peers to reject malformed deltas
    /// before voting on a proposal.
    pub fn validate(&self) -> Result<(), ClusterCatalogError> {
        match self {
            CatalogDelta::Create {
                dataset_id_bytes,
                dataset_type_u8,
                ..
            } => {
                if dataset_id_bytes.len() != 16 {
                    return Err(ClusterCatalogError::Catalog(CatalogError::InvalidPath));
                }
                if DatasetType::from_u8(*dataset_type_u8).is_none() {
                    return Err(ClusterCatalogError::Catalog(CatalogError::InvalidPath));
                }
                Ok(())
            }
            CatalogDelta::Destroy { .. }
            | CatalogDelta::Rename { .. }
            | CatalogDelta::TransitionToDestroying { .. }
            | CatalogDelta::TransitionToDestroyed { .. } => Ok(()),
        }
    }

    // -- Conversion helpers (used by prepare/apply) --

    fn create_dataset_id(bytes: &[u8]) -> Option<DatasetId> {
        if bytes.len() != 16 {
            return None;
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(bytes);
        Some(DatasetId::from_bytes(arr))
    }

    fn dataset_id_to_bytes(id: &DatasetId) -> Vec<u8> {
        id.as_bytes().to_vec()
    }
}

// ---------------------------------------------------------------------------
// CatalogDelta methods on ClusterDatasetCatalog
// ---------------------------------------------------------------------------

impl ClusterDatasetCatalog {
    /// Prepare a [`CatalogDelta`] for a create operation.
    ///
    /// Validates the mutation against the lease gate and catalog rules,
    /// but does NOT apply it. The returned delta is intended for cluster
    /// proposal; apply with [`Self::apply_delta`] once committed.
    pub fn prepare_create_delta(
        &self,
        fence: &WriteFence,
        request: DatasetCreateRequest,
    ) -> Result<CatalogDelta, ClusterCatalogError> {
        self.check_mutation_gate_readonly(fence)?;
        // Pre-validate: path must not already exist, parent must exist.
        // We check against a clone to avoid mutating self.
        let mut check = self.catalog.clone();
        check.create(
            &request.path,
            request.dataset_id,
            request.dataset_type,
            request.creation_txg,
            request.properties.clone(),
            request.flags,
            SyncGuarantee::default(),
        )?;
        Ok(CatalogDelta::Create {
            path: request.path,
            dataset_id_bytes: CatalogDelta::dataset_id_to_bytes(&request.dataset_id),
            dataset_type_u8: request.dataset_type.to_u8(),
            creation_txg: request.creation_txg,
            properties: request.properties,
            flags_u16: request.flags.bits(),
        })
    }

    /// Prepare a [`CatalogDelta`] for a destroy operation.
    pub fn prepare_destroy_delta(
        &self,
        fence: &WriteFence,
        path: &str,
    ) -> Result<CatalogDelta, ClusterCatalogError> {
        self.check_mutation_gate_readonly(fence)?;
        let mut check = self.catalog.clone();
        check.destroy(path)?;
        Ok(CatalogDelta::Destroy {
            path: path.to_string(),
        })
    }

    /// Prepare a [`CatalogDelta`] for a rename operation.
    pub fn prepare_rename_delta(
        &self,
        fence: &WriteFence,
        old_path: &str,
        new_path: &str,
    ) -> Result<CatalogDelta, ClusterCatalogError> {
        self.check_mutation_gate_readonly(fence)?;
        let mut check = self.catalog.clone();
        check.rename(old_path, new_path)?;
        Ok(CatalogDelta::Rename {
            old_path: old_path.to_string(),
            new_path: new_path.to_string(),
        })
    }

    /// Prepare a [`CatalogDelta`] for a transition-to-destroying operation.
    pub fn prepare_transition_to_destroying_delta(
        &self,
        fence: &WriteFence,
        path: &str,
    ) -> Result<CatalogDelta, ClusterCatalogError> {
        self.check_mutation_gate_readonly(fence)?;
        let mut check = self.catalog.clone();
        check.transition_to_destroying(path)?;
        Ok(CatalogDelta::TransitionToDestroying {
            path: path.to_string(),
        })
    }

    /// Prepare a [`CatalogDelta`] for a transition-to-destroyed operation.
    pub fn prepare_transition_to_destroyed_delta(
        &self,
        fence: &WriteFence,
        path: &str,
    ) -> Result<CatalogDelta, ClusterCatalogError> {
        self.check_mutation_gate_readonly(fence)?;
        let mut check = self.catalog.clone();
        check.transition_to_destroyed(path)?;
        Ok(CatalogDelta::TransitionToDestroyed {
            path: path.to_string(),
        })
    }

    /// Apply a committed [`CatalogDelta`] to the catalog.
    ///
    /// Does NOT check the lease gate — the delta has already been committed
    /// by cluster quorum. This is the mechanism by which all nodes converge
    /// to a single authoritative catalog state.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] if the delta cannot be applied (e.g. path
    /// collision from a racing delta). Callers should log and continue;
    /// the catalog will be repaired via full state sync if divergence
    /// is detected.
    pub fn apply_delta(&mut self, delta: &CatalogDelta) -> Result<(), CatalogError> {
        match delta {
            CatalogDelta::Create {
                path,
                dataset_id_bytes,
                dataset_type_u8,
                creation_txg,
                properties,
                flags_u16,
            } => {
                let dataset_id = CatalogDelta::create_dataset_id(dataset_id_bytes)
                    .ok_or(CatalogError::CorruptEncoding)?;
                let dataset_type =
                    DatasetType::from_u8(*dataset_type_u8).ok_or(CatalogError::CorruptEncoding)?;
                let flags = DatasetFlags::from_bits(*flags_u16);
                self.catalog.create(
                    path,
                    dataset_id,
                    dataset_type,
                    *creation_txg,
                    properties.clone(),
                    flags,
                    SyncGuarantee::default(),
                )
            }
            CatalogDelta::Destroy { path } => self.catalog.destroy(path),
            CatalogDelta::Rename { old_path, new_path } => self.catalog.rename(old_path, new_path),
            CatalogDelta::TransitionToDestroying { path } => {
                self.catalog.transition_to_destroying(path)
            }
            CatalogDelta::TransitionToDestroyed { path } => {
                self.catalog.transition_to_destroyed(path)
            }
        }
    }

    // ------------------------------------------------------------------
    // Gate check (read-only variant for delta preparation)
    // ------------------------------------------------------------------

    /// Verify lease gate without mutable access.
    fn check_mutation_gate_readonly(&self, fence: &WriteFence) -> Result<(), ClusterCatalogError> {
        if !self.is_lease_holder {
            return Err(ClusterCatalogError::NotLeaseHolder);
        }
        match &self.active_fence {
            Some(active) if active == fence => Ok(()),
            Some(_active) => Err(ClusterCatalogError::FenceMismatch),
            None => Err(ClusterCatalogError::NotLeaseHolder),
        }
    }
}

// ---------------------------------------------------------------------------
// ClusterDatasetCatalog
// ---------------------------------------------------------------------------

/// Cluster-aware wrapper around the canonical [`DatasetCatalog`].
///
/// Read operations (lookup, contains, list_children, entries, lifecycle_state)
/// are always available. Mutation operations (create, destroy, rename,
/// lifecycle transitions) require the active write fence, ensuring only
/// the current lease holder can modify the catalog.
///
/// # Lease lifecycle
///
/// ```text
/// on_lease_acquired(fence)  →  mutations enabled
/// on_lease_lost()           →  mutations disabled
/// ```
#[derive(Clone, Debug)]
pub struct ClusterDatasetCatalog {
    /// The dataset catalog wrapped by this cluster gate.
    catalog: DatasetCatalog,
    /// Whether this node currently holds the write lease.
    is_lease_holder: bool,
    /// The active write fence token for this lease period.
    /// `None` when no lease is held.
    active_fence: Option<WriteFence>,
}

impl ClusterDatasetCatalog {
    /// Create an empty cluster-gated dataset catalog.
    pub fn new() -> Self {
        Self {
            catalog: DatasetCatalog::new(),
            is_lease_holder: false,
            active_fence: None,
        }
    }

    /// Create from an existing [`DatasetCatalog`].
    ///
    /// Used during recovery: load the catalog from the committed root and
    /// wrap it for cluster-gated operation.
    pub fn from_catalog(catalog: DatasetCatalog) -> Self {
        Self {
            catalog,
            is_lease_holder: false,
            active_fence: None,
        }
    }

    // ------------------------------------------------------------------
    // Lease management
    // ------------------------------------------------------------------

    /// Called when this node acquires the write lease.
    ///
    /// After this call, mutation operations are permitted. The active fence
    /// is recorded for fence validation.
    pub fn on_lease_acquired(&mut self, fence: WriteFence) {
        self.is_lease_holder = true;
        self.active_fence = Some(fence);
    }

    /// Called when this node loses the write lease.
    ///
    /// After this call, mutation operations are rejected until the lease is
    /// re-acquired. Read operations continue to work.
    pub fn on_lease_lost(&mut self) {
        self.is_lease_holder = false;
        self.active_fence = None;
    }

    /// Returns `true` if this node currently holds the write lease.
    pub fn is_lease_holder(&self) -> bool {
        self.is_lease_holder
    }

    /// Returns the active write fence, if any.
    pub fn active_fence(&self) -> Option<&WriteFence> {
        self.active_fence.as_ref()
    }

    // ------------------------------------------------------------------
    // Authority access (used for mount/import path resolution)
    // ------------------------------------------------------------------

    /// Returns a reference to the underlying canonical catalog.
    ///
    /// Used for read-only access from mount/import path resolution,
    /// snapshot listing, and client-facing queries that do not require
    /// lease authority.
    pub fn catalog(&self) -> &DatasetCatalog {
        &self.catalog
    }

    /// Consume this wrapper and return the underlying [`DatasetCatalog`].
    pub fn into_inner(self) -> DatasetCatalog {
        self.catalog
    }

    // ------------------------------------------------------------------
    // Gate check helper
    // ------------------------------------------------------------------

    /// Verify that this node holds the lease and the provided fence matches.
    ///
    /// Returns `Ok(())` when the mutation is authorized, or an appropriate
    /// error when the lease is absent or the fence is stale.
    fn check_mutation_gate(&self, fence: &WriteFence) -> Result<(), ClusterCatalogError> {
        if !self.is_lease_holder {
            return Err(ClusterCatalogError::NotLeaseHolder);
        }
        match &self.active_fence {
            Some(active) if active == fence => Ok(()),
            Some(_active) => Err(ClusterCatalogError::FenceMismatch),
            None => Err(ClusterCatalogError::NotLeaseHolder),
        }
    }

    // ------------------------------------------------------------------
    // Read operations (always available, no gate)
    // ------------------------------------------------------------------

    /// Returns the number of datasets in the catalog.
    pub fn len(&self) -> usize {
        self.catalog.len()
    }

    /// Returns `true` if the catalog is empty.
    pub fn is_empty(&self) -> bool {
        self.catalog.is_empty()
    }

    /// Look up a dataset by its full path.
    pub fn lookup(&self, path: &str) -> Result<DatasetId, CatalogError> {
        self.catalog.lookup(path)
    }

    /// Resolve a mount path to the dataset ID.
    pub fn mount_lookup(&self, path: &str) -> Result<DatasetId, CatalogError> {
        self.catalog.mount_lookup(path)
    }

    /// Returns `true` if a dataset exists at the given path.
    pub fn contains(&self, path: &str) -> bool {
        self.catalog.contains(path)
    }

    /// List the direct children of a dataset.
    pub fn list_children(
        &self,
        parent_path: &str,
    ) -> Result<Vec<(String, DatasetId)>, CatalogError> {
        self.catalog.list_children(parent_path)
    }

    /// List the direct children of a dataset with full entry details.
    pub fn list_children_detailed(
        &self,
        parent_path: &str,
    ) -> Result<Vec<DatasetChildDetails>, CatalogError> {
        self.catalog.list_children_detailed(parent_path)
    }

    /// Return all entries in the catalog.
    pub fn entries(&self) -> Vec<(String, DatasetId)> {
        self.catalog.entries()
    }

    /// Return all entries with full details.
    pub fn list_all(
        &self,
    ) -> Vec<(
        String,
        DatasetId,
        DatasetType,
        u64,
        DatasetFlags,
        LifecycleState,
    )> {
        self.catalog.list_all()
    }

    /// Look up a dataset by its stable ID.
    pub fn get_by_id(
        &self,
        id: &DatasetId,
    ) -> Option<(
        String,
        Option<String>,
        DatasetType,
        u64,
        DatasetFlags,
        LifecycleState,
    )> {
        self.catalog.get_by_id(id)
    }

    /// Look up a dataset by its name component under a parent.
    pub fn get_by_name(&self, parent_path: &str, name: &str) -> Option<DatasetId> {
        self.catalog.get_by_name(parent_path, name)
    }

    /// Get the lifecycle state of a dataset.
    pub fn lifecycle_state(&self, path: &str) -> Result<LifecycleState, CatalogError> {
        self.catalog.lifecycle_state(path)
    }

    // ------------------------------------------------------------------
    // Mutation operations (require lease + fence)
    // ------------------------------------------------------------------

    /// Create a new dataset in the catalog.
    ///
    /// Requires lease-holder authority. The `fence` must match the active
    /// write fence recorded from the most recent [`Self::on_lease_acquired`].
    pub fn create(
        &mut self,
        fence: &WriteFence,
        request: DatasetCreateRequest,
    ) -> Result<(), ClusterCatalogError> {
        self.check_mutation_gate(fence)?;
        self.catalog.create(
            &request.path,
            request.dataset_id,
            request.dataset_type,
            request.creation_txg,
            request.properties,
            request.flags,
            SyncGuarantee::default(),
        )?;
        Ok(())
    }

    /// Destroy a dataset from the catalog.
    ///
    /// Requires lease-holder authority. Fails if the dataset has children.
    pub fn destroy(&mut self, fence: &WriteFence, path: &str) -> Result<(), ClusterCatalogError> {
        self.check_mutation_gate(fence)?;
        self.catalog.destroy(path)?;
        Ok(())
    }

    /// Rename a dataset, preserving its stable [`DatasetId`].
    ///
    /// Requires lease-holder authority. The new path must not exist and
    /// the rename must not create a cycle.
    pub fn rename(
        &mut self,
        fence: &WriteFence,
        old_path: &str,
        new_path: &str,
    ) -> Result<(), ClusterCatalogError> {
        self.check_mutation_gate(fence)?;
        self.catalog.rename(old_path, new_path)?;
        Ok(())
    }

    /// Transition a dataset to the Destroying lifecycle state.
    pub fn transition_to_destroying(
        &mut self,
        fence: &WriteFence,
        path: &str,
    ) -> Result<(), ClusterCatalogError> {
        self.check_mutation_gate(fence)?;
        self.catalog.transition_to_destroying(path)?;
        Ok(())
    }

    /// Transition a dataset to the Destroyed lifecycle state.
    pub fn transition_to_destroyed(
        &mut self,
        fence: &WriteFence,
        path: &str,
    ) -> Result<(), ClusterCatalogError> {
        self.check_mutation_gate(fence)?;
        self.catalog.transition_to_destroyed(path)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Serialization for cluster-state replication
    // ------------------------------------------------------------------

    /// Encode the catalog for cluster-state replication.
    ///
    /// Delegates to [`DatasetCatalog::encode`] which produces a
    /// BLAKE3-verified binary blob suitable for inclusion in committed
    /// epoch transitions and transport-level state transfer.
    pub fn encode(&self) -> Vec<u8> {
        self.catalog.encode()
    }

    /// Decode a catalog from a replicated blob.
    ///
    /// Delegates to [`DatasetCatalog::decode`] which verifies the
    /// BLAKE3 checksum and rejects corrupt or tampered data.
    pub fn decode(data: &[u8]) -> Result<Self, CatalogError> {
        let catalog = DatasetCatalog::decode(data)?;
        Ok(Self::from_catalog(catalog))
    }
}

impl Default for ClusterDatasetCatalog {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ClusterPoolCatalog — pool-scoped catalog for cluster committed state
// ---------------------------------------------------------------------------

/// A dataset catalog bound to a specific pool in a cluster.
///
/// Combines pool identity with a [`ClusterDatasetCatalog`] so the catalog
/// can be included in the cluster's committed state. On each committed
/// epoch, the catalog snapshot is encoded and persisted through the pool's
/// object store. After failover or restart, the catalog is recovered from
/// the committed root and re-converged via delta replay.
///
/// # Lifecycle
///
/// ```text
/// create    → ClusterPoolCatalog::new(pool_name, pool_uuid)
/// operate   → catalog().create(...) / apply_delta(...)
/// snapshot  → encode() → persisted as part of committed epoch
/// recover   → decode() → wrapped in ClusterPoolCatalog
/// ```
///
/// # Authority
///
/// This is **not** a second catalog authority. It binds a
/// [`ClusterDatasetCatalog`] that wraps [`DatasetCatalog`] to a pool identity.
#[derive(Clone, Debug)]
pub struct ClusterPoolCatalog {
    /// Pool name (e.g. "tank").
    pool_name: String,
    /// Pool UUID (16 bytes).
    pool_uuid: [u8; 16],
    /// The cluster-gated dataset catalog for this pool.
    catalog: ClusterDatasetCatalog,
    /// Monotonically increasing catalog version counter.
    /// Incremented on each committed catalog mutation.
    version: u64,
}

impl ClusterPoolCatalog {
    /// Create a new pool-scoped catalog.
    ///
    /// The catalog starts empty and unleased. Call
    /// [`ClusterDatasetCatalog::on_lease_acquired`] on the inner catalog
    /// once the cluster lease is held.
    pub fn new(pool_name: &str, pool_uuid: [u8; 16]) -> Self {
        Self {
            pool_name: pool_name.to_string(),
            pool_uuid,
            catalog: ClusterDatasetCatalog::new(),
            version: 0,
        }
    }

    /// Create from an existing [`ClusterDatasetCatalog`].
    ///
    /// Used during recovery: load the catalog from committed state and
    /// bind it to pool identity.
    pub fn from_parts(
        pool_name: &str,
        pool_uuid: [u8; 16],
        catalog: ClusterDatasetCatalog,
        version: u64,
    ) -> Self {
        Self {
            pool_name: pool_name.to_string(),
            pool_uuid,
            catalog,
            version,
        }
    }

    /// Pool name.
    pub fn pool_name(&self) -> &str {
        &self.pool_name
    }

    /// Pool UUID.
    pub fn pool_uuid(&self) -> &[u8; 16] {
        &self.pool_uuid
    }

    /// Current catalog version.
    ///
    /// Incremented on each committed delta application. Used by peers to
    /// detect divergence and by catch-up to request missed deltas.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Reference to the inner cluster-gated catalog.
    pub fn catalog(&self) -> &ClusterDatasetCatalog {
        &self.catalog
    }

    /// Mutable reference to the inner cluster-gated catalog.
    pub fn catalog_mut(&mut self) -> &mut ClusterDatasetCatalog {
        &mut self.catalog
    }
    // ── Lease lifecycle delegation (to inner ClusterDatasetCatalog) ──

    /// Returns `true` if the inner catalog is currently lease-gated.
    pub fn is_lease_holder(&self) -> bool {
        self.catalog.is_lease_holder()
    }

    /// Returns the active write fence from the inner catalog, if any.
    pub fn active_fence(&self) -> Option<&WriteFence> {
        self.catalog.active_fence()
    }

    /// Notify the inner catalog that the write lease has been acquired.
    pub fn on_lease_acquired(&mut self, fence: WriteFence) {
        self.catalog.on_lease_acquired(fence);
    }

    /// Notify the inner catalog that the write lease has been lost.
    pub fn on_lease_lost(&mut self) {
        self.catalog.on_lease_lost();
    }

    // ── Delta preparation delegation (to inner ClusterDatasetCatalog) ──

    /// Prepare a create-dataset delta for cluster proposal.
    pub fn prepare_create_delta(
        &self,
        fence: &WriteFence,
        request: DatasetCreateRequest,
    ) -> Result<CatalogDelta, ClusterCatalogError> {
        self.catalog.prepare_create_delta(fence, request)
    }

    /// Prepare a destroy-dataset delta for cluster proposal.
    pub fn prepare_destroy_delta(
        &self,
        fence: &WriteFence,
        path: &str,
    ) -> Result<CatalogDelta, ClusterCatalogError> {
        self.catalog.prepare_destroy_delta(fence, path)
    }

    /// Prepare a rename-dataset delta for cluster proposal.
    pub fn prepare_rename_delta(
        &self,
        fence: &WriteFence,
        old_path: &str,
        new_path: &str,
    ) -> Result<CatalogDelta, ClusterCatalogError> {
        self.catalog.prepare_rename_delta(fence, old_path, new_path)
    }

    /// Apply a committed [`CatalogDelta`] and bump the version counter.
    ///
    /// This is the primary ingress point for committed catalog deltas
    /// arriving through the cluster's epoch commit path. The version
    /// counter lets peers detect when they need catch-up.
    pub fn apply_committed_delta(&mut self, delta: &CatalogDelta) -> Result<u64, CatalogError> {
        self.catalog.apply_delta(delta)?;
        self.version = self.version.wrapping_add(1);
        Ok(self.version)
    }

    /// Apply a sequence of committed deltas in order.
    ///
    /// Returns the final version after all deltas are applied.
    pub fn apply_committed_deltas(&mut self, deltas: &[CatalogDelta]) -> Result<u64, CatalogError> {
        for delta in deltas {
            self.catalog.apply_delta(delta)?;
            self.version = self.version.wrapping_add(1);
        }
        Ok(self.version)
    }

    /// Return the number of datasets in the catalog.
    pub fn len(&self) -> usize {
        self.catalog.len()
    }

    /// Returns `true` if the catalog is empty.
    pub fn is_empty(&self) -> bool {
        self.catalog.is_empty()
    }

    // ------------------------------------------------------------------
    // Persistence: encode/decode for committed state
    // ------------------------------------------------------------------

    /// Encode the full catalog state for inclusion in committed pool state.
    ///
    /// The encoded blob includes pool identity, version, and the BLAKE3-verified
    /// catalog bytes. Used when persisting the committed epoch state.
    pub fn encode_committed_state(&self) -> Vec<u8> {
        let catalog_bytes = self.catalog.encode();
        let mut out = Vec::with_capacity(16 + 8 + catalog_bytes.len());
        // Pool UUID (16 bytes)
        out.extend_from_slice(&self.pool_uuid);
        // Version (8 bytes LE)
        out.extend_from_slice(&self.version.to_le_bytes());
        // Catalog bytes (BLAKE3-verified by DatasetCatalog::encode)
        out.extend_from_slice(&catalog_bytes);
        out
    }

    /// Decode committed pool catalog state.
    ///
    /// Returns `None` if the blob is too short or the catalog data is corrupt.
    pub fn decode_committed_state(pool_name: &str, data: &[u8]) -> Option<Self> {
        if data.len() < 24 {
            // Minimum: 16 (uuid) + 8 (version) + 0 (empty catalog)
            return None;
        }
        let mut pool_uuid = [0u8; 16];
        pool_uuid.copy_from_slice(&data[0..16]);
        let version = u64::from_le_bytes([
            data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
        ]);
        let catalog_bytes = &data[24..];
        let catalog = ClusterDatasetCatalog::decode(catalog_bytes).ok()?;
        Some(Self::from_parts(pool_name, pool_uuid, catalog, version))
    }

    /// Compute a BLAKE3 digest of the committed state for cross-node verification.
    ///
    /// Two nodes with the same committed state produce identical digests.
    /// Used during epoch commit to verify that all peers converged to the
    /// same catalog state, and during catch-up to detect divergence.
    pub fn committed_state_digest(&self) -> [u8; 32] {
        let state = self.encode_committed_state();
        let domain_tag = b"tidefs-cluster-pool-catalog-committed-v1";
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain_tag);
        hasher.update(&state);
        *hasher.finalize().as_bytes()
    }

    /// Consume and return the inner catalog, dropping pool identity.
    pub fn into_inner(self) -> ClusterDatasetCatalog {
        self.catalog
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::EpochId;

    fn did(n: u8) -> DatasetId {
        let mut bytes = [0u8; 16];
        bytes[0] = n;
        DatasetId::from_bytes(bytes)
    }

    fn fence(epoch_seq: u64, gen: u64) -> WriteFence {
        WriteFence::new(EpochId(epoch_seq), gen)
    }

    fn empty_props() -> Vec<u8> {
        vec![]
    }

    fn create_req(
        path: &str,
        dataset_id: DatasetId,
        dataset_type: DatasetType,
        creation_txg: u64,
        properties: Vec<u8>,
        flags: DatasetFlags,
    ) -> DatasetCreateRequest {
        DatasetCreateRequest {
            path: path.into(),
            dataset_id,
            dataset_type,
            creation_txg,
            properties,
            flags,
        }
    }

    // ── Creation ───────────────────────────────────────────────────

    #[test]
    fn new_catalog_is_empty() {
        let cat = ClusterDatasetCatalog::new();
        assert!(cat.is_empty());
        assert_eq!(cat.len(), 0);
        assert!(!cat.is_lease_holder());
    }

    #[test]
    fn from_catalog_preserves_entries() {
        let mut base = DatasetCatalog::new();
        let root_id = did(0);
        base.create(
            "pool",
            root_id,
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        let cat = ClusterDatasetCatalog::from_catalog(base);
        assert!(cat.contains("pool"));
        assert_eq!(cat.lookup("pool").unwrap(), root_id);
        assert!(!cat.is_lease_holder());
    }

    // ── Lease lifecycle ────────────────────────────────────────────

    #[test]
    fn lease_acquired_enables_mutations() {
        let mut cat = ClusterDatasetCatalog::new();
        assert!(!cat.is_lease_holder());
        cat.on_lease_acquired(fence(1, 1));
        assert!(cat.is_lease_holder());
        assert_eq!(cat.active_fence(), Some(&fence(1, 1)));
    }

    #[test]
    fn lease_lost_disables_mutations() {
        let mut cat = ClusterDatasetCatalog::new();
        cat.on_lease_acquired(fence(1, 1));
        assert!(cat.is_lease_holder());
        cat.on_lease_lost();
        assert!(!cat.is_lease_holder());
        assert!(cat.active_fence().is_none());
    }

    // ── Mutation gating ────────────────────────────────────────────

    #[test]
    fn create_rejected_without_lease() {
        let mut cat = ClusterDatasetCatalog::new();
        // Seed the catalog with a pool entry so create can succeed (parent check)
        // We can't even seed without lease — test that no-lease rejects.
        let result = cat.create(
            &fence(1, 1),
            create_req(
                "pool/fs1",
                did(10),
                DatasetType::Filesystem,
                42,
                empty_props(),
                DatasetFlags::default_create(),
            ),
        );
        assert_eq!(result, Err(ClusterCatalogError::NotLeaseHolder));
    }

    #[test]
    fn create_rejected_with_wrong_fence() {
        let mut cat = ClusterDatasetCatalog::new();
        cat.on_lease_acquired(fence(1, 5));
        let result = cat.create(
            &fence(1, 99),
            create_req(
                "pool/fs1",
                did(10),
                DatasetType::Filesystem,
                42,
                empty_props(),
                DatasetFlags::default_create(),
            ),
        );
        assert_eq!(result, Err(ClusterCatalogError::FenceMismatch));
    }

    #[test]
    fn create_rejected_after_lease_lost() {
        let mut cat = ClusterDatasetCatalog::new();
        cat.on_lease_acquired(fence(1, 1));
        cat.on_lease_lost();
        let result = cat.create(
            &fence(1, 1),
            create_req(
                "pool/fs1",
                did(10),
                DatasetType::Filesystem,
                42,
                empty_props(),
                DatasetFlags::default_create(),
            ),
        );
        assert_eq!(result, Err(ClusterCatalogError::NotLeaseHolder));
    }

    // ── Mutation with valid lease ──────────────────────────────────

    fn seeded_catalog() -> ClusterDatasetCatalog {
        let mut cat = ClusterDatasetCatalog::new();
        // Must acquire lease to seed
        cat.on_lease_acquired(fence(1, 1));
        cat.create(
            &fence(1, 1),
            create_req(
                "pool",
                did(0),
                DatasetType::Filesystem,
                1,
                empty_props(),
                DatasetFlags::NONE,
            ),
        )
        .unwrap();
        cat.on_lease_lost();
        cat
    }

    #[test]
    fn create_with_valid_lease_succeeds() {
        let mut cat = seeded_catalog();
        cat.on_lease_acquired(fence(2, 1));
        let f = fence(2, 1);
        cat.create(
            &f,
            create_req(
                "pool/fs1",
                did(10),
                DatasetType::Filesystem,
                100,
                empty_props(),
                DatasetFlags::default_create(),
            ),
        )
        .unwrap();
        assert!(cat.contains("pool/fs1"));
        assert_eq!(cat.lookup("pool/fs1").unwrap(), did(10));
    }

    #[test]
    fn destroy_with_valid_lease_succeeds() {
        let mut cat = seeded_catalog();
        cat.on_lease_acquired(fence(2, 1));
        let f = fence(2, 1);
        cat.create(
            &f,
            create_req(
                "pool/leaf",
                did(20),
                DatasetType::Filesystem,
                200,
                empty_props(),
                DatasetFlags::NONE,
            ),
        )
        .unwrap();
        assert!(cat.contains("pool/leaf"));
        cat.destroy(&f, "pool/leaf").unwrap();
        assert!(!cat.contains("pool/leaf"));
    }

    #[test]
    fn destroy_with_children_fails() {
        let mut cat = seeded_catalog();
        cat.on_lease_acquired(fence(2, 1));
        let f = fence(2, 1);
        cat.create(
            &f,
            create_req(
                "pool/parent",
                did(30),
                DatasetType::Filesystem,
                300,
                empty_props(),
                DatasetFlags::NONE,
            ),
        )
        .unwrap();
        cat.create(
            &f,
            create_req(
                "pool/parent/child",
                did(31),
                DatasetType::Filesystem,
                301,
                empty_props(),
                DatasetFlags::NONE,
            ),
        )
        .unwrap();
        let result = cat.destroy(&f, "pool/parent");
        assert_eq!(
            result,
            Err(ClusterCatalogError::Catalog(CatalogError::HasChildren))
        );
        // Parent still exists
        assert!(cat.contains("pool/parent"));
        assert!(cat.contains("pool/parent/child"));
    }

    #[test]
    fn rename_with_valid_lease_succeeds() {
        let mut cat = seeded_catalog();
        cat.on_lease_acquired(fence(2, 1));
        let f = fence(2, 1);
        cat.create(
            &f,
            create_req(
                "pool/orig",
                did(40),
                DatasetType::Filesystem,
                400,
                empty_props(),
                DatasetFlags::NONE,
            ),
        )
        .unwrap();
        cat.rename(&f, "pool/orig", "pool/renamed").unwrap();
        assert!(!cat.contains("pool/orig"));
        assert!(cat.contains("pool/renamed"));
        // Dataset ID preserved across rename
        assert_eq!(cat.lookup("pool/renamed").unwrap(), did(40));
    }

    #[test]
    fn rename_destination_exists_fails() {
        let mut cat = seeded_catalog();
        cat.on_lease_acquired(fence(2, 1));
        let f = fence(2, 1);
        cat.create(
            &f,
            create_req(
                "pool/a",
                did(50),
                DatasetType::Filesystem,
                500,
                empty_props(),
                DatasetFlags::NONE,
            ),
        )
        .unwrap();
        cat.create(
            &f,
            create_req(
                "pool/b",
                did(51),
                DatasetType::Filesystem,
                501,
                empty_props(),
                DatasetFlags::NONE,
            ),
        )
        .unwrap();
        let result = cat.rename(&f, "pool/a", "pool/b");
        assert_eq!(
            result,
            Err(ClusterCatalogError::Catalog(CatalogError::AlreadyExists))
        );
    }

    // ── Lifecycle transitions ──────────────────────────────────────

    #[test]
    fn lifecycle_transition_to_destroying_with_lease() {
        let mut cat = seeded_catalog();
        cat.on_lease_acquired(fence(2, 1));
        let f = fence(2, 1);
        cat.create(
            &f,
            create_req(
                "pool/ds",
                did(60),
                DatasetType::Filesystem,
                600,
                empty_props(),
                DatasetFlags::NONE,
            ),
        )
        .unwrap();
        cat.transition_to_destroying(&f, "pool/ds").unwrap();
        assert_eq!(
            cat.lifecycle_state("pool/ds").unwrap(),
            LifecycleState::Destroying
        );
    }

    #[test]
    fn lifecycle_transition_to_destroyed_with_lease() {
        let mut cat = seeded_catalog();
        cat.on_lease_acquired(fence(2, 1));
        let f = fence(2, 1);
        cat.create(
            &f,
            create_req(
                "pool/ds2",
                did(70),
                DatasetType::Filesystem,
                700,
                empty_props(),
                DatasetFlags::NONE,
            ),
        )
        .unwrap();
        cat.transition_to_destroying(&f, "pool/ds2").unwrap();
        cat.transition_to_destroyed(&f, "pool/ds2").unwrap();
        assert_eq!(
            cat.lifecycle_state("pool/ds2").unwrap(),
            LifecycleState::Destroyed
        );
    }

    // ── Read operations without lease ──────────────────────────────

    #[test]
    fn reads_work_without_lease() {
        let cat = seeded_catalog(); // lease was released after seeding
        assert!(!cat.is_lease_holder());
        assert!(cat.contains("pool"));
        assert_eq!(cat.lookup("pool").unwrap(), did(0));
        assert_eq!(cat.len(), 1);
    }

    #[test]
    fn list_children_works_without_lease() {
        let mut cat = seeded_catalog();
        cat.on_lease_acquired(fence(2, 1));
        let f = fence(2, 1);
        cat.create(
            &f,
            create_req(
                "pool/a",
                did(10),
                DatasetType::Filesystem,
                100,
                empty_props(),
                DatasetFlags::NONE,
            ),
        )
        .unwrap();
        cat.create(
            &f,
            create_req(
                "pool/b",
                did(11),
                DatasetType::Filesystem,
                101,
                empty_props(),
                DatasetFlags::NONE,
            ),
        )
        .unwrap();
        cat.on_lease_lost();

        let children = cat.list_children("pool").unwrap();
        assert_eq!(children.len(), 2);
        let names: Vec<&str> = children.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));
    }

    // ── Encode/decode round-trip ───────────────────────────────────

    #[test]
    fn encode_decode_roundtrip() {
        let mut cat = seeded_catalog();
        cat.on_lease_acquired(fence(2, 1));
        let f = fence(2, 1);
        cat.create(
            &f,
            create_req(
                "pool/fs1",
                did(80),
                DatasetType::Filesystem,
                800,
                empty_props(),
                DatasetFlags::default_create(),
            ),
        )
        .unwrap();
        cat.create(
            &f,
            create_req(
                "pool/vol1",
                did(81),
                DatasetType::Volume,
                801,
                empty_props(),
                DatasetFlags::READONLY,
            ),
        )
        .unwrap();
        cat.transition_to_destroying(&f, "pool/fs1").unwrap();
        cat.on_lease_lost();

        let encoded = cat.encode();
        let decoded = ClusterDatasetCatalog::decode(&encoded).unwrap();

        assert_eq!(decoded.len(), cat.len());
        assert!(decoded.contains("pool"));
        assert!(decoded.contains("pool/fs1"));
        assert!(decoded.contains("pool/vol1"));
        assert_eq!(decoded.lookup("pool/fs1").unwrap(), did(80));
        assert_eq!(decoded.lookup("pool/vol1").unwrap(), did(81));
        assert_eq!(
            decoded.lifecycle_state("pool/fs1").unwrap(),
            LifecycleState::Destroying
        );
        assert!(!decoded.is_lease_holder()); // lease state is NOT persisted
    }

    #[test]
    fn decode_empty_catalog() {
        let cat = ClusterDatasetCatalog::new();
        let encoded = cat.encode();
        let decoded = ClusterDatasetCatalog::decode(&encoded).unwrap();
        assert!(decoded.is_empty());
        assert!(!decoded.is_lease_holder());
    }

    // ── into_inner ─────────────────────────────────────────────────

    #[test]
    fn into_inner_returns_catalog() {
        let cat = seeded_catalog();
        let inner = cat.into_inner();
        assert!(inner.contains("pool"));
        assert_eq!(inner.lookup("pool").unwrap(), did(0));
    }

    // ── Error display ──────────────────────────────────────────────

    #[test]
    fn error_display() {
        assert_eq!(
            ClusterCatalogError::NotLeaseHolder.to_string(),
            "not the lease holder; catalog mutations require write-lease authority"
        );
        assert_eq!(
            ClusterCatalogError::FenceMismatch.to_string(),
            "write fence mismatch; catalog mutation rejected"
        );
        assert_eq!(
            ClusterCatalogError::Catalog(CatalogError::NotFound).to_string(),
            "catalog error: dataset not found in catalog"
        );
    }

    #[test]
    fn error_from_catalog_error() {
        let e: ClusterCatalogError = CatalogError::AlreadyExists.into();
        assert_eq!(e, ClusterCatalogError::Catalog(CatalogError::AlreadyExists));
    }

    // ── CatalogDelta operations ───────────────────────────────────

    #[test]
    fn delta_create_roundtrip() {
        let mut cat = seeded_catalog();
        cat.on_lease_acquired(fence(2, 1));
        let f = fence(2, 1);

        // Prepare a create delta
        let delta = cat
            .prepare_create_delta(
                &f,
                create_req(
                    "pool/fs1",
                    did(10),
                    DatasetType::Filesystem,
                    100,
                    vec![1, 2, 3],
                    DatasetFlags::default_create(),
                ),
            )
            .unwrap();

        assert_eq!(delta.description(), "create dataset 'pool/fs1'");
        assert!(delta.validate().is_ok());

        // Apply the delta
        cat.apply_delta(&delta).unwrap();
        assert!(cat.contains("pool/fs1"));
        assert_eq!(cat.lookup("pool/fs1").unwrap(), did(10));
    }

    #[test]
    fn delta_destroy_roundtrip() {
        let mut cat = seeded_catalog();
        cat.on_lease_acquired(fence(2, 1));
        let f = fence(2, 1);
        cat.create(
            &f,
            create_req(
                "pool/leaf",
                did(20),
                DatasetType::Filesystem,
                200,
                empty_props(),
                DatasetFlags::NONE,
            ),
        )
        .unwrap();

        let delta = cat.prepare_destroy_delta(&f, "pool/leaf").unwrap();
        assert_eq!(delta.description(), "destroy dataset 'pool/leaf'");

        cat.apply_delta(&delta).unwrap();
        assert!(!cat.contains("pool/leaf"));
    }

    #[test]
    fn delta_rename_roundtrip() {
        let mut cat = seeded_catalog();
        cat.on_lease_acquired(fence(2, 1));
        let f = fence(2, 1);
        cat.create(
            &f,
            create_req(
                "pool/orig",
                did(30),
                DatasetType::Filesystem,
                300,
                empty_props(),
                DatasetFlags::NONE,
            ),
        )
        .unwrap();

        let delta = cat
            .prepare_rename_delta(&f, "pool/orig", "pool/renamed")
            .unwrap();
        assert_eq!(
            delta.description(),
            "rename dataset 'pool/orig' -> 'pool/renamed'"
        );

        cat.apply_delta(&delta).unwrap();
        assert!(!cat.contains("pool/orig"));
        assert!(cat.contains("pool/renamed"));
        assert_eq!(cat.lookup("pool/renamed").unwrap(), did(30));
    }

    #[test]
    fn delta_lifecycle_transitions() {
        let mut cat = seeded_catalog();
        cat.on_lease_acquired(fence(2, 1));
        let f = fence(2, 1);
        cat.create(
            &f,
            create_req(
                "pool/ds",
                did(40),
                DatasetType::Filesystem,
                400,
                empty_props(),
                DatasetFlags::NONE,
            ),
        )
        .unwrap();

        let d1 = cat
            .prepare_transition_to_destroying_delta(&f, "pool/ds")
            .unwrap();
        assert!(d1.description().contains("destroying"));
        cat.apply_delta(&d1).unwrap();
        assert_eq!(
            cat.lifecycle_state("pool/ds").unwrap(),
            LifecycleState::Destroying
        );

        let d2 = cat
            .prepare_transition_to_destroyed_delta(&f, "pool/ds")
            .unwrap();
        assert!(d2.description().contains("destroyed"));
        cat.apply_delta(&d2).unwrap();
        assert_eq!(
            cat.lifecycle_state("pool/ds").unwrap(),
            LifecycleState::Destroyed
        );
    }

    #[test]
    fn delta_validation_rejects_bad_type() {
        let delta = CatalogDelta::Create {
            path: "pool/fs1".into(),
            dataset_id_bytes: vec![0u8; 16],
            dataset_type_u8: 99, // invalid
            creation_txg: 1,
            properties: vec![],
            flags_u16: 0,
        };
        assert!(delta.validate().is_err());
    }

    #[test]
    fn delta_validation_rejects_wrong_id_length() {
        let delta = CatalogDelta::Create {
            path: "pool/fs1".into(),
            dataset_id_bytes: vec![1, 2, 3], // too short
            dataset_type_u8: 1,
            creation_txg: 1,
            properties: vec![],
            flags_u16: 0,
        };
        assert!(delta.validate().is_err());
    }

    #[test]
    fn delta_apply_without_lease_succeeds() {
        // Applying a committed delta does not require lease authority
        let mut cat = seeded_catalog();
        assert!(!cat.is_lease_holder());

        let delta = CatalogDelta::Create {
            path: "pool/postcommit".into(),
            dataset_id_bytes: vec![0xAAu8; 16],
            dataset_type_u8: DatasetType::Filesystem.to_u8(),
            creation_txg: 500,
            properties: vec![],
            flags_u16: DatasetFlags::default_create().bits(),
        };

        cat.apply_delta(&delta).unwrap();
        assert!(cat.contains("pool/postcommit"));
    }

    #[test]
    fn delta_prepare_rejected_without_lease() {
        let cat = seeded_catalog(); // lease released
        assert!(!cat.is_lease_holder());

        let result = cat.prepare_create_delta(
            &fence(1, 1),
            create_req(
                "pool/nope",
                did(99),
                DatasetType::Filesystem,
                1,
                vec![],
                DatasetFlags::NONE,
            ),
        );
        assert_eq!(result, Err(ClusterCatalogError::NotLeaseHolder));
    }

    #[test]
    fn delta_prepare_rejected_wrong_fence() {
        let mut cat = seeded_catalog();
        cat.on_lease_acquired(fence(3, 7));

        let result = cat.prepare_create_delta(
            &fence(3, 99),
            create_req(
                "pool/nope",
                did(99),
                DatasetType::Filesystem,
                1,
                vec![],
                DatasetFlags::NONE,
            ),
        );
        assert_eq!(result, Err(ClusterCatalogError::FenceMismatch));
    }

    #[test]
    fn delta_serialize_deserialize_bincode() {
        let delta = CatalogDelta::Create {
            path: "pool/testds".into(),
            dataset_id_bytes: vec![0x11u8; 16],
            dataset_type_u8: DatasetType::Filesystem.to_u8(),
            creation_txg: 42,
            properties: b"compression=zstd".to_vec(),
            flags_u16: DatasetFlags::COMPRESSION.bits(),
        };

        let encoded = bincode::serialize(&delta).unwrap();
        let decoded: CatalogDelta = bincode::deserialize(&encoded).unwrap();

        assert_eq!(decoded, delta);
    }

    #[test]
    fn delta_rename_serialize_deserialize() {
        let delta = CatalogDelta::Rename {
            old_path: "pool/a".into(),
            new_path: "pool/b".into(),
        };
        let encoded = bincode::serialize(&delta).unwrap();
        let decoded: CatalogDelta = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded, delta);
    }

    #[test]
    fn delta_description_all_variants() {
        let deltas = vec![
            (
                CatalogDelta::Create {
                    path: "p/a".into(),
                    dataset_id_bytes: vec![0; 16],
                    dataset_type_u8: 1,
                    creation_txg: 0,
                    properties: vec![],
                    flags_u16: 0,
                },
                "create dataset 'p/a'",
            ),
            (
                CatalogDelta::Destroy { path: "p/a".into() },
                "destroy dataset 'p/a'",
            ),
            (
                CatalogDelta::Rename {
                    old_path: "p/a".into(),
                    new_path: "p/b".into(),
                },
                "rename dataset 'p/a' -> 'p/b'",
            ),
            (
                CatalogDelta::TransitionToDestroying { path: "p/a".into() },
                "transition dataset 'p/a' to destroying",
            ),
            (
                CatalogDelta::TransitionToDestroyed { path: "p/a".into() },
                "transition dataset 'p/a' to destroyed",
            ),
        ];
        for (delta, expected) in deltas {
            assert_eq!(delta.description(), expected);
        }
    }

    #[test]
    fn apply_many_deltas_converges_state() {
        // Simulate two nodes starting from the same base catalog and applying
        // the same sequence of deltas — they must converge.
        let base = seeded_catalog();
        let mut node_a = base.clone();
        let mut node_b = base.clone();

        let deltas: Vec<CatalogDelta> = vec![
            CatalogDelta::Create {
                path: "pool/a".into(),
                dataset_id_bytes: vec![1u8; 16],
                dataset_type_u8: DatasetType::Filesystem.to_u8(),
                creation_txg: 10,
                properties: vec![],
                flags_u16: 0,
            },
            CatalogDelta::Create {
                path: "pool/b".into(),
                dataset_id_bytes: vec![2u8; 16],
                dataset_type_u8: DatasetType::Volume.to_u8(),
                creation_txg: 20,
                properties: vec![],
                flags_u16: DatasetFlags::READONLY.bits(),
            },
            CatalogDelta::Rename {
                old_path: "pool/a".into(),
                new_path: "pool/a_renamed".into(),
            },
            CatalogDelta::TransitionToDestroying {
                path: "pool/b".into(),
            },
            CatalogDelta::TransitionToDestroyed {
                path: "pool/b".into(),
            },
        ];

        for delta in &deltas {
            node_a.apply_delta(delta).unwrap();
            node_b.apply_delta(delta).unwrap();
        }

        // Both nodes must have identical catalog state
        assert_eq!(node_a.encode(), node_b.encode());
        assert!(node_a.contains("pool/a_renamed"));
        assert!(!node_a.contains("pool/a"));
        assert_eq!(
            node_a.lifecycle_state("pool/b").unwrap(),
            LifecycleState::Destroyed
        );
        assert_eq!(
            node_b.lifecycle_state("pool/b").unwrap(),
            LifecycleState::Destroyed
        );
    }

    // ── ClusterPoolCatalog tests ──────────────────────────────────

    fn pool_uuid() -> [u8; 16] {
        [
            0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
            0x0A, 0x0B,
        ]
    }

    #[test]
    fn pool_catalog_new_is_empty() {
        let pc = ClusterPoolCatalog::new("tank", pool_uuid());
        assert_eq!(pc.pool_name(), "tank");
        assert_eq!(pc.pool_uuid(), &pool_uuid());
        assert_eq!(pc.version(), 0);
        assert!(pc.is_empty());
        assert_eq!(pc.len(), 0);
    }

    #[test]
    fn pool_catalog_from_parts() {
        let mut cat = seeded_catalog();
        cat.on_lease_acquired(fence(2, 1));
        // seeded_catalog() has "pool" as root path; create under that
        cat.create(
            &fence(2, 1),
            create_req(
                "pool/a",
                did(10),
                DatasetType::Filesystem,
                100,
                empty_props(),
                DatasetFlags::NONE,
            ),
        )
        .unwrap();
        cat.on_lease_lost();

        let pc = ClusterPoolCatalog::from_parts("pool", pool_uuid(), cat, 42);
        assert_eq!(pc.pool_name(), "pool");
        assert_eq!(pc.version(), 42);
        assert!(pc.catalog().contains("pool/a"));
    }

    #[test]
    fn pool_catalog_apply_committed_delta_bumps_version() {
        let mut pc = ClusterPoolCatalog::new("tank", pool_uuid());
        assert_eq!(pc.version(), 0);

        // First we need a root entry. Apply a create delta via the inner catalog directly.
        let root_delta = CatalogDelta::Create {
            path: "tank".into(),
            dataset_id_bytes: vec![0u8; 16],
            dataset_type_u8: DatasetType::Filesystem.to_u8(),
            creation_txg: 1,
            properties: vec![],
            flags_u16: 0,
        };
        let v = pc.apply_committed_delta(&root_delta).unwrap();
        assert_eq!(v, 1);

        let create_delta = CatalogDelta::Create {
            path: "tank/fs1".into(),
            dataset_id_bytes: vec![1u8; 16],
            dataset_type_u8: DatasetType::Filesystem.to_u8(),
            creation_txg: 100,
            properties: vec![],
            flags_u16: DatasetFlags::default_create().bits(),
        };
        let v = pc.apply_committed_delta(&create_delta).unwrap();
        assert_eq!(v, 2);
        assert!(pc.catalog().contains("tank/fs1"));
    }

    #[test]
    fn pool_catalog_apply_committed_deltas_batch() {
        let mut pc = ClusterPoolCatalog::new("tank", pool_uuid());

        let deltas = vec![
            CatalogDelta::Create {
                path: "tank".into(),
                dataset_id_bytes: vec![0u8; 16],
                dataset_type_u8: DatasetType::Filesystem.to_u8(),
                creation_txg: 1,
                properties: vec![],
                flags_u16: 0,
            },
            CatalogDelta::Create {
                path: "tank/a".into(),
                dataset_id_bytes: vec![1u8; 16],
                dataset_type_u8: DatasetType::Filesystem.to_u8(),
                creation_txg: 10,
                properties: vec![],
                flags_u16: 0,
            },
            CatalogDelta::Create {
                path: "tank/b".into(),
                dataset_id_bytes: vec![2u8; 16],
                dataset_type_u8: DatasetType::Volume.to_u8(),
                creation_txg: 20,
                properties: vec![],
                flags_u16: DatasetFlags::READONLY.bits(),
            },
        ];

        let v = pc.apply_committed_deltas(&deltas).unwrap();
        assert_eq!(v, 3);
        assert_eq!(pc.len(), 3);
    }

    #[test]
    fn pool_catalog_encode_decode_roundtrip() {
        let mut pc = ClusterPoolCatalog::new("tank", pool_uuid());

        // Apply some deltas to build state
        let deltas = vec![
            CatalogDelta::Create {
                path: "tank".into(),
                dataset_id_bytes: vec![0u8; 16],
                dataset_type_u8: DatasetType::Filesystem.to_u8(),
                creation_txg: 1,
                properties: vec![],
                flags_u16: 0,
            },
            CatalogDelta::Create {
                path: "tank/vol1".into(),
                dataset_id_bytes: vec![0xAAu8; 16],
                dataset_type_u8: DatasetType::Volume.to_u8(),
                creation_txg: 500,
                properties: b"size=10G".to_vec(),
                flags_u16: DatasetFlags::READONLY.bits(),
            },
        ];
        pc.apply_committed_deltas(&deltas).unwrap();

        let encoded = pc.encode_committed_state();
        let decoded = ClusterPoolCatalog::decode_committed_state("tank", &encoded).unwrap();

        assert_eq!(decoded.pool_name(), "tank");
        assert_eq!(decoded.pool_uuid(), &pool_uuid());
        assert_eq!(decoded.version(), pc.version());
        assert_eq!(decoded.len(), pc.len());
        assert!(decoded.catalog().contains("tank/vol1"));
    }

    #[test]
    fn pool_catalog_decode_too_short() {
        assert!(ClusterPoolCatalog::decode_committed_state("tank", &[]).is_none());
        assert!(ClusterPoolCatalog::decode_committed_state("tank", &[0u8; 10]).is_none());
        assert!(ClusterPoolCatalog::decode_committed_state("tank", &[0u8; 23]).is_none());
    }

    #[test]
    fn pool_catalog_decode_corrupt_catalog_data() {
        // Valid header but corrupt catalog payload
        let mut data = vec![0u8; 24]; // uuid + version
        data.extend_from_slice(&[0xFFu8; 50]); // garbage catalog
        assert!(ClusterPoolCatalog::decode_committed_state("tank", &data).is_none());
    }

    #[test]
    fn pool_catalog_into_inner() {
        let mut pc = ClusterPoolCatalog::new("tank", pool_uuid());
        pc.apply_committed_delta(&CatalogDelta::Create {
            path: "tank".into(),
            dataset_id_bytes: vec![0u8; 16],
            dataset_type_u8: DatasetType::Filesystem.to_u8(),
            creation_txg: 1,
            properties: vec![],
            flags_u16: 0,
        })
        .unwrap();

        let inner = pc.into_inner();
        assert!(inner.contains("tank"));
    }

    #[test]
    fn pool_catalog_version_monotonic() {
        let mut pc = ClusterPoolCatalog::new("tank", pool_uuid());

        // First create the root entry "tank" so child entries have a parent
        let root = CatalogDelta::Create {
            path: "tank".into(),
            dataset_id_bytes: vec![255u8; 16],
            dataset_type_u8: DatasetType::Filesystem.to_u8(),
            creation_txg: 0,
            properties: vec![],
            flags_u16: 0,
        };
        pc.apply_committed_delta(&root).unwrap();

        for i in 0..10 {
            let delta = CatalogDelta::Create {
                path: format!("tank/ds{i}"),
                dataset_id_bytes: vec![i as u8; 16],
                dataset_type_u8: DatasetType::Filesystem.to_u8(),
                creation_txg: i + 1,
                properties: vec![],
                flags_u16: 0,
            };
            let v = pc.apply_committed_delta(&delta).unwrap();
            assert_eq!(v, i + 2); // version: 1 (root) + child index + 1
        }
        assert_eq!(pc.version(), 11); // 1 root + 10 children
    }

    #[test]
    fn pool_catalog_convergence_across_nodes() {
        // Two nodes start with empty catalogs for the same pool,
        // apply the same sequence of deltas, and converge.
        let uuid = pool_uuid();
        let mut node_a = ClusterPoolCatalog::new("tank", uuid);
        let mut node_b = ClusterPoolCatalog::new("tank", uuid);

        let deltas: Vec<CatalogDelta> = vec![
            CatalogDelta::Create {
                path: "tank".into(),
                dataset_id_bytes: vec![0u8; 16],
                dataset_type_u8: DatasetType::Filesystem.to_u8(),
                creation_txg: 1,
                properties: vec![],
                flags_u16: 0,
            },
            CatalogDelta::Create {
                path: "tank/fs1".into(),
                dataset_id_bytes: vec![10u8; 16],
                dataset_type_u8: DatasetType::Filesystem.to_u8(),
                creation_txg: 100,
                properties: vec![],
                flags_u16: DatasetFlags::default_create().bits(),
            },
            CatalogDelta::Rename {
                old_path: "tank/fs1".into(),
                new_path: "tank/fs1_renamed".into(),
            },
            CatalogDelta::TransitionToDestroying {
                path: "tank/fs1_renamed".into(),
            },
        ];

        for delta in &deltas {
            node_a.apply_committed_delta(delta).unwrap();
            node_b.apply_committed_delta(delta).unwrap();
        }

        // Both nodes must have identical committed state
        assert_eq!(
            node_a.encode_committed_state(),
            node_b.encode_committed_state()
        );
        assert_eq!(node_a.version(), node_b.version());
        assert!(node_a.catalog().contains("tank/fs1_renamed"));
        assert_eq!(
            node_a
                .catalog()
                .lifecycle_state("tank/fs1_renamed")
                .unwrap(),
            LifecycleState::Destroying,
        );
    }

    #[test]
    fn committed_state_digest_matches_across_replicas() {
        let uuid = pool_uuid();
        let mut node_a = ClusterPoolCatalog::new("tank", uuid);
        let mut node_b = ClusterPoolCatalog::new("tank", uuid);

        // Same deltas → same digest
        let deltas: Vec<CatalogDelta> = vec![
            CatalogDelta::Create {
                path: "tank".into(),
                dataset_id_bytes: vec![0u8; 16],
                dataset_type_u8: DatasetType::Filesystem.to_u8(),
                creation_txg: 1,
                properties: vec![],
                flags_u16: 0,
            },
            CatalogDelta::Create {
                path: "tank/fs1".into(),
                dataset_id_bytes: vec![10u8; 16],
                dataset_type_u8: DatasetType::Filesystem.to_u8(),
                creation_txg: 10,
                properties: b"compression=zstd".to_vec(),
                flags_u16: DatasetFlags::default_create().bits(),
            },
        ];
        for delta in &deltas {
            node_a.apply_committed_delta(delta).unwrap();
            node_b.apply_committed_delta(delta).unwrap();
        }

        assert_eq!(
            node_a.committed_state_digest(),
            node_b.committed_state_digest()
        );

        // Different deltas → different digest
        node_a
            .apply_committed_delta(&CatalogDelta::Rename {
                old_path: "tank/fs1".into(),
                new_path: "tank/fs1_v2".into(),
            })
            .unwrap();

        assert_ne!(
            node_a.committed_state_digest(),
            node_b.committed_state_digest()
        );

        // Catch up node B → digest matches again
        node_b
            .apply_committed_delta(&CatalogDelta::Rename {
                old_path: "tank/fs1".into(),
                new_path: "tank/fs1_v2".into(),
            })
            .unwrap();

        assert_eq!(
            node_a.committed_state_digest(),
            node_b.committed_state_digest()
        );
    }

    #[test]
    fn committed_state_digest_is_deterministic() {
        let uuid = pool_uuid();
        let mut pc = ClusterPoolCatalog::new("tank", uuid);
        pc.apply_committed_delta(&CatalogDelta::Create {
            path: "tank".into(),
            dataset_id_bytes: vec![0u8; 16],
            dataset_type_u8: DatasetType::Filesystem.to_u8(),
            creation_txg: 1,
            properties: vec![],
            flags_u16: 0,
        })
        .unwrap();

        let d1 = pc.committed_state_digest();
        let d2 = pc.committed_state_digest();
        assert_eq!(d1, d2); // Same state, same digest
        assert_eq!(d1.len(), 32);
        assert_ne!(d1, [0u8; 32]); // Not zero
    }

    #[test]
    fn recovery_roundtrip_commit_and_restore() {
        // Simulate: node creates catalog state, commits it, crashes,
        // recovers from committed state blob.
        let uuid = pool_uuid();
        let mut original = ClusterPoolCatalog::new("tank", uuid);

        // Build some state
        original
            .apply_committed_deltas(&[
                CatalogDelta::Create {
                    path: "tank".into(),
                    dataset_id_bytes: vec![0u8; 16],
                    dataset_type_u8: DatasetType::Filesystem.to_u8(),
                    creation_txg: 1,
                    properties: vec![],
                    flags_u16: 0,
                },
                CatalogDelta::Create {
                    path: "tank/a".into(),
                    dataset_id_bytes: vec![1u8; 16],
                    dataset_type_u8: DatasetType::Filesystem.to_u8(),
                    creation_txg: 10,
                    properties: vec![],
                    flags_u16: 0,
                },
                CatalogDelta::Create {
                    path: "tank/b".into(),
                    dataset_id_bytes: vec![2u8; 16],
                    dataset_type_u8: DatasetType::Volume.to_u8(),
                    creation_txg: 20,
                    properties: b"size=10G".to_vec(),
                    flags_u16: DatasetFlags::READONLY.bits(),
                },
            ])
            .unwrap();

        // Commit: encode the state
        let committed_blob = original.encode_committed_state();
        let committed_digest = original.committed_state_digest();

        // "Crash" — drop the original
        drop(original);

        // Recover from committed blob
        let recovered = ClusterPoolCatalog::decode_committed_state("tank", &committed_blob)
            .expect("recovery should succeed");

        assert_eq!(recovered.pool_name(), "tank");
        assert_eq!(recovered.pool_uuid(), &uuid);
        assert_eq!(recovered.version(), 3);
        assert_eq!(recovered.committed_state_digest(), committed_digest);
        assert!(recovered.catalog().contains("tank/a"));
        assert!(recovered.catalog().contains("tank/b"));
        assert_eq!(
            recovered.catalog().lifecycle_state("tank/b").unwrap(),
            LifecycleState::Active,
        );
    }
}
