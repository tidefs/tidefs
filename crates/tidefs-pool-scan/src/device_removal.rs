//! Device removal planning: object enumeration, evacuation plan computation,
//! and committed-root anchoring.
//!
//! When an operator requests device removal, this module computes an evacuation
//! plan that moves every object resident on the target device to a surviving
//! device while respecting failure-domain constraints defined by the pool's
//! replication intent.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use tidefs_replication_model::{LayoutValidator, PlacementEntry, ReplicationIntent};

use crate::DeviceType;

// ---------------------------------------------------------------------------
// DeviceRemovalRefusal
// ---------------------------------------------------------------------------

/// Stable refusal/failure classes shared by the planner and removal driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceRemovalRefusalClass {
    /// Requested target path is not a member of the pool topology.
    TargetNotFound,
    /// Removal would leave the pool with no surviving data device.
    WouldEmptyPool,
    /// Target device health does not permit safe evacuation.
    UnhealthyTarget,
    /// Surviving topology cannot satisfy the requested redundancy policy.
    InsufficientSurvivingTopology,
    /// Placement or failure-domain constraints reject the evacuation plan.
    DomainConstraintViolation,
    /// Caller planned against an older topology generation.
    StaleTopologyGeneration,
    /// An object evacuation I/O or relocation operation failed.
    EvacuationFailed,
    /// Not every live object was evacuated.
    EvacuationIncomplete,
    /// Persisted checkpoint identity does not match this removal.
    CheckpointReplayRejected,
    /// Committed topology root does not match the removal plan.
    CommittedTopologyMismatch,
    /// Evacuation completion has not been durably recorded.
    EvacuationCompletionNotDurable,
    /// Durable evacuation completion evidence does not match the removal identity.
    EvacuationCompletionMismatch,
}

impl core::fmt::Display for DeviceRemovalRefusalClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TargetNotFound => f.write_str("target-not-found"),
            Self::WouldEmptyPool => f.write_str("would-empty-pool"),
            Self::UnhealthyTarget => f.write_str("unhealthy-target"),
            Self::InsufficientSurvivingTopology => f.write_str("insufficient-surviving-topology"),
            Self::DomainConstraintViolation => f.write_str("domain-constraint-violation"),
            Self::StaleTopologyGeneration => f.write_str("stale-topology-generation"),
            Self::EvacuationCompletionNotDurable => f.write_str("evacuation-completion-not-durable"),
            Self::EvacuationCompletionMismatch => f.write_str("evacuation-completion-mismatch"),
            Self::EvacuationFailed => f.write_str("evacuation-failed"),
            Self::EvacuationIncomplete => f.write_str("evacuation-incomplete"),
            Self::CheckpointReplayRejected => f.write_str("checkpoint-replay-rejected"),
            Self::CommittedTopologyMismatch => f.write_str("committed-topology-mismatch"),
        }
    }
}

/// Durable typed evidence explaining why a removal did not proceed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRemovalRefusal {
    /// Stable refusal/failure class for machine consumers.
    pub class: DeviceRemovalRefusalClass,
    /// Target device requested for removal.
    pub target_device: PathBuf,
    /// Human-readable details suitable for operator output.
    pub details: String,
    /// Topology generation the caller expected, when applicable.
    pub expected_topology_generation: Option<u64>,
    /// Topology generation observed in the pool snapshot, when applicable.
    pub observed_topology_generation: Option<u64>,
    /// Number of surviving devices available after removal.
    pub surviving_devices: Option<u32>,
    /// Number of surviving devices required by the policy or plan.
    pub required_surviving_devices: Option<u32>,
}

impl DeviceRemovalRefusal {
    /// Build refusal evidence with only a class, target, and details.
    #[must_use]
    pub fn new(
        class: DeviceRemovalRefusalClass,
        target_device: PathBuf,
        details: impl Into<String>,
    ) -> Self {
        Self {
            class,
            target_device,
            details: details.into(),
            expected_topology_generation: None,
            observed_topology_generation: None,
            surviving_devices: None,
            required_surviving_devices: None,
        }
    }

    /// Add topology generation evidence.
    #[must_use]
    pub const fn with_topology_generations(mut self, expected: u64, observed: u64) -> Self {
        self.expected_topology_generation = Some(expected);
        self.observed_topology_generation = Some(observed);
        self
    }

    /// Add surviving-topology cardinality evidence.
    #[must_use]
    pub const fn with_surviving_topology(mut self, surviving: u32, required: u32) -> Self {
        self.surviving_devices = Some(surviving);
        self.required_surviving_devices = Some(required);
        self
    }
}

impl core::fmt::Display for DeviceRemovalRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} for {}: {}",
            self.class,
            self.target_device.display(),
            self.details
        )
    }
}

// ---------------------------------------------------------------------------
// DeviceRemovalError
// ---------------------------------------------------------------------------

/// Errors that can occur during device removal planning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceRemovalError {
    /// The target device was not found in the pool device tree.
    TargetDeviceNotFound {
        /// Path of the device that was requested for removal.
        path: PathBuf,
    },

    /// The computed evacuation plan violates failure-domain constraints.
    DomainConstraintViolation {
        /// Human-readable description of the violation.
        details: String,
    },

    /// The pool has no objects to enumerate (empty pool).
    NoObjectsOnDevice,

    /// Cannot remove the last remaining device from a pool.
    WouldEmptyPool,

    /// Removing this device would leave the pool with insufficient
    /// redundancy to survive another failure under the configured policy.
    InsufficientRedundancy {
        /// Human-readable details about the redundancy shortfall.
        details: String,
    },

    /// One or more object evacuations failed.
    EvacuationFailed {
        /// Human-readable evacuation failure summary.
        details: String,
    },

    /// Target device health rejects removal.
    DeviceNotHealthy {
        /// Path of the unhealthy target.
        path: PathBuf,
        /// Current target health.
        health: crate::DeviceHealth,
    },

    /// Caller planned against a stale topology generation.
    StaleTopologyGeneration {
        /// Path of the target requested for removal.
        path: PathBuf,
        /// Expected current topology generation.
        expected: u64,
        /// Observed topology generation in the pool snapshot.
        observed: u64,
    },
}

impl core::fmt::Display for DeviceRemovalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TargetDeviceNotFound { path } => {
                write!(f, "target device not found in pool: {}", path.display())
            }
            Self::DomainConstraintViolation { details } => {
                write!(
                    f,
                    "evacuation plan violates failure-domain constraints: {details}"
                )
            }
            Self::NoObjectsOnDevice => {
                write!(f, "no objects found on target device")
            }
            Self::WouldEmptyPool => {
                write!(
                    f,
                    "cannot remove the last device: pool would have zero devices"
                )
            }
            Self::InsufficientRedundancy { details } => {
                write!(f, "insufficient redundancy: {details}")
            }
            Self::EvacuationFailed { details } => {
                write!(f, "evacuation failed: {details}")
            }
            Self::DeviceNotHealthy { path, health } => {
                write!(
                    f,
                    "target device {} health {health} does not permit removal",
                    path.display()
                )
            }
            Self::StaleTopologyGeneration {
                path,
                expected,
                observed,
            } => {
                write!(
                    f,
                    "stale topology generation for {}: expected {expected}, observed {observed}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for DeviceRemovalError {}

impl DeviceRemovalError {
    /// Return the stable refusal class for this planning error.
    #[must_use]
    pub const fn refusal_class(&self) -> DeviceRemovalRefusalClass {
        match self {
            Self::TargetDeviceNotFound { .. } => DeviceRemovalRefusalClass::TargetNotFound,
            Self::DomainConstraintViolation { .. } => {
                DeviceRemovalRefusalClass::DomainConstraintViolation
            }
            Self::NoObjectsOnDevice => DeviceRemovalRefusalClass::EvacuationIncomplete,
            Self::WouldEmptyPool => DeviceRemovalRefusalClass::WouldEmptyPool,
            Self::InsufficientRedundancy { .. } => {
                DeviceRemovalRefusalClass::InsufficientSurvivingTopology
            }
            Self::EvacuationFailed { .. } => DeviceRemovalRefusalClass::EvacuationFailed,
            Self::DeviceNotHealthy { .. } => DeviceRemovalRefusalClass::UnhealthyTarget,
            Self::StaleTopologyGeneration { .. } => {
                DeviceRemovalRefusalClass::StaleTopologyGeneration
            }
        }
    }

    /// Convert this error into durable refusal evidence.
    #[must_use]
    pub fn refusal_evidence(&self, target_device: &Path) -> DeviceRemovalRefusal {
        match self {
            Self::TargetDeviceNotFound { path } => DeviceRemovalRefusal::new(
                DeviceRemovalRefusalClass::TargetNotFound,
                path.clone(),
                "target device is not present in the pool topology",
            ),
            Self::DomainConstraintViolation { details } => DeviceRemovalRefusal::new(
                DeviceRemovalRefusalClass::DomainConstraintViolation,
                target_device.to_path_buf(),
                details.clone(),
            ),
            Self::NoObjectsOnDevice => DeviceRemovalRefusal::new(
                DeviceRemovalRefusalClass::EvacuationIncomplete,
                target_device.to_path_buf(),
                "planner could not enumerate live objects on the target device",
            ),
            Self::WouldEmptyPool => DeviceRemovalRefusal::new(
                DeviceRemovalRefusalClass::WouldEmptyPool,
                target_device.to_path_buf(),
                "removal would leave the pool with zero devices",
            ),
            Self::InsufficientRedundancy { details } => DeviceRemovalRefusal::new(
                DeviceRemovalRefusalClass::InsufficientSurvivingTopology,
                target_device.to_path_buf(),
                details.clone(),
            ),
            Self::EvacuationFailed { details } => DeviceRemovalRefusal::new(
                DeviceRemovalRefusalClass::EvacuationFailed,
                target_device.to_path_buf(),
                details.clone(),
            ),
            Self::DeviceNotHealthy { path, health } => DeviceRemovalRefusal::new(
                DeviceRemovalRefusalClass::UnhealthyTarget,
                path.clone(),
                format!("target health is {health}"),
            ),
            Self::StaleTopologyGeneration {
                path,
                expected,
                observed,
            } => DeviceRemovalRefusal::new(
                DeviceRemovalRefusalClass::StaleTopologyGeneration,
                path.clone(),
                "topology generation changed before removal planning",
            )
            .with_topology_generations(*expected, *observed),
        }
    }
}

// ---------------------------------------------------------------------------
// ObjectPlacement — identifies which device an object lives on
// ---------------------------------------------------------------------------

/// A record of an object's placement on a specific device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectPlacement {
    /// Opaque object identifier (e.g. object number or content hash).
    pub object_id: u64,
    /// Path of the device where this object resides.
    pub device_path: PathBuf,
    /// Size of the object in bytes.
    pub size_bytes: u64,
}

impl ObjectPlacement {
    /// Create a new object placement record.
    #[must_use]
    pub const fn new(object_id: u64, device_path: PathBuf, size_bytes: u64) -> Self {
        Self {
            object_id,
            device_path,
            size_bytes,
        }
    }
}

// ---------------------------------------------------------------------------
// EvacuationEntry — one object's evacuation target
// ---------------------------------------------------------------------------

/// A single object that must be evacuated, and where it will be moved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvacuationEntry {
    /// The object to evacuate.
    pub object_id: u64,
    /// The device the object currently resides on (the removal target).
    pub source_device: PathBuf,
    /// The device the object will be copied to.
    pub target_device: PathBuf,
    /// Size of the object in bytes.
    pub size_bytes: u64,
    /// Index of the target device in the surviving-device list.
    pub target_device_index: usize,
}

// ---------------------------------------------------------------------------
// EvacuationPlanOutcome
// ---------------------------------------------------------------------------

/// Explicit evacuation-planning outcome for the target device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvacuationPlanOutcome {
    /// No live objects were resident on the target, so evacuation is complete.
    EmptySuccess,
    /// Planner enumerated live objects that must be moved.
    ObjectsEnumerated,
}

// ---------------------------------------------------------------------------
// DeviceRemovalPlan — the complete evacuation plan
// ---------------------------------------------------------------------------

/// The complete device removal plan: all objects to evacuate and their
/// destinations, along with metadata about the removal operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRemovalPlan {
    /// Path of the device being removed.
    pub target_device: PathBuf,
    /// GUID of the device being removed.
    pub target_device_guid: [u8; 16],
    /// Index of the device being removed in the pool member list.
    pub target_device_index: u32,
    /// Remaining surviving devices after removal.
    pub surviving_devices: Vec<PathBuf>,
    /// Total number of devices before removal.
    pub device_count_before: u32,
    /// Total number of devices after removal.
    pub device_count_after: u32,
    /// Objects that must be evacuated, ordered by object_id.
    pub objects_to_evacuate: Vec<EvacuationEntry>,
    /// Total bytes to evacuate.
    pub total_evacuation_bytes: u64,
    /// Number of objects to evacuate.
    pub object_count: u64,
    /// Explicit evacuation-planning outcome.
    pub evacuation_outcome: EvacuationPlanOutcome,
    /// New topology generation to use after removal.
    pub topology_generation: u64,
    /// The replication intent used to validate the new placement.
    pub replication_intent: ReplicationIntent,
    /// Whether the evacuation plan passed domain-constraint validation.
    pub plan_validated: bool,
}

impl DeviceRemovalPlan {
    /// Returns `true` if the plan is empty (no objects to evacuate).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.objects_to_evacuate.is_empty()
    }

    /// Returns the total number of objects to evacuate.
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.objects_to_evacuate.len()
    }
}

// ---------------------------------------------------------------------------
// DeviceRemovalPlanner — computes evacuation plans
// ---------------------------------------------------------------------------

/// Plans the evacuation of objects from a target device to surviving devices.
///
/// The planner:
/// 1. Walks the pool device tree to locate the target device.
/// 2. Enumerates objects placed on that device.
/// 3. Selects surviving devices that can receive evacuated objects.
/// 4. Distributes objects across surviving devices respecting
///    failure-domain constraints from the replication intent.
/// 5. Validates the resulting placement with [`LayoutValidator`].
pub struct DeviceRemovalPlanner;

impl DeviceRemovalPlanner {
    /// Compute a device removal plan.
    pub fn plan_removal(
        device_tree: &DeviceType,
        target_device: &Path,
        object_placements: &[ObjectPlacement],
        intent: ReplicationIntent,
        topology_generation: u64,
    ) -> Result<DeviceRemovalPlan, DeviceRemovalError> {
        Self::plan_removal_with_expected_generation(
            device_tree,
            target_device,
            object_placements,
            intent,
            topology_generation,
            topology_generation,
        )
    }

    /// Compute a device removal plan after checking the caller's expected
    /// topology generation against the observed pool snapshot.
    pub fn plan_removal_with_expected_generation(
        device_tree: &DeviceType,
        target_device: &Path,
        object_placements: &[ObjectPlacement],
        intent: ReplicationIntent,
        topology_generation: u64,
        expected_topology_generation: u64,
    ) -> Result<DeviceRemovalPlan, DeviceRemovalError> {
        if topology_generation != expected_topology_generation {
            return Err(DeviceRemovalError::StaleTopologyGeneration {
                path: target_device.to_path_buf(),
                expected: expected_topology_generation,
                observed: topology_generation,
            });
        }

        if intent.total_targets() == 0 {
            return Err(DeviceRemovalError::DomainConstraintViolation {
                details: "replication intent requires zero placement targets".into(),
            });
        }

        let all_leaves = Self::flatten_leaves(device_tree);

        let target_leaf = all_leaves
            .iter()
            .find(|leaf| leaf.device_path == target_device)
            .ok_or_else(|| DeviceRemovalError::TargetDeviceNotFound {
                path: target_device.to_path_buf(),
            })?;

        if !target_leaf.health.is_operational() {
            return Err(DeviceRemovalError::DeviceNotHealthy {
                path: target_device.to_path_buf(),
                health: target_leaf.health,
            });
        }

        let surviving_leaves: Vec<&LeafInfo> = all_leaves
            .iter()
            .filter(|leaf| leaf.device_path != target_device)
            .collect();

        if surviving_leaves.is_empty() {
            return Err(DeviceRemovalError::WouldEmptyPool);
        }

        let required_survivors = intent.total_targets() as usize;
        if surviving_leaves.len() < required_survivors {
            return Err(DeviceRemovalError::InsufficientRedundancy {
                details: format!(
                    "removal would leave {} surviving device(s), but intent requires {} target(s)",
                    surviving_leaves.len(),
                    required_survivors
                ),
            });
        }

        let objects_on_target: Vec<&ObjectPlacement> = object_placements
            .iter()
            .filter(|op| op.device_path == target_device)
            .collect();

        let surviving_paths: Vec<PathBuf> = surviving_leaves
            .iter()
            .map(|l| l.device_path.clone())
            .collect();

        if objects_on_target.is_empty() {
            return Ok(DeviceRemovalPlan {
                target_device: target_device.to_path_buf(),
                target_device_guid: target_leaf.device_guid,
                target_device_index: target_leaf.device_index,
                surviving_devices: surviving_paths,
                device_count_before: all_leaves.len() as u32,
                device_count_after: surviving_leaves.len() as u32,
                objects_to_evacuate: Vec::new(),
                total_evacuation_bytes: 0,
                object_count: 0,
                evacuation_outcome: EvacuationPlanOutcome::EmptySuccess,
                topology_generation: topology_generation.saturating_add(1),
                replication_intent: intent,
                plan_validated: true,
            });
        }

        let (evacuation_entries, plan_validated) = Self::assign_evacuation_targets(
            &objects_on_target,
            surviving_leaves.len(),
            &surviving_paths,
            &intent,
        )?;
        if !plan_validated {
            return Err(DeviceRemovalError::DomainConstraintViolation {
                details: "evacuation targets do not satisfy failure-domain constraints".into(),
            });
        }

        let total_bytes: u64 = evacuation_entries.iter().map(|e| e.size_bytes).sum();

        Ok(DeviceRemovalPlan {
            target_device: target_device.to_path_buf(),
            target_device_guid: target_leaf.device_guid,
            target_device_index: target_leaf.device_index,
            surviving_devices: surviving_paths,
            device_count_before: all_leaves.len() as u32,
            device_count_after: surviving_leaves.len() as u32,
            objects_to_evacuate: evacuation_entries,
            total_evacuation_bytes: total_bytes,
            object_count: objects_on_target.len() as u64,
            evacuation_outcome: EvacuationPlanOutcome::ObjectsEnumerated,
            topology_generation: topology_generation.saturating_add(1),
            replication_intent: intent,
            plan_validated,
        })
    }

    fn assign_evacuation_targets(
        objects: &[&ObjectPlacement],
        num_surviving: usize,
        surviving_paths: &[PathBuf],
        intent: &ReplicationIntent,
    ) -> Result<(Vec<EvacuationEntry>, bool), DeviceRemovalError> {
        let mut entries: Vec<EvacuationEntry> = Vec::with_capacity(objects.len());

        for (i, obj) in objects.iter().enumerate() {
            let target_index = i % num_surviving;
            entries.push(EvacuationEntry {
                object_id: obj.object_id,
                source_device: obj.device_path.clone(),
                target_device: surviving_paths[target_index].clone(),
                size_bytes: obj.size_bytes,
                target_device_index: target_index,
            });
        }

        let total_targets = intent.total_targets() as usize;
        let mut all_validated = true;

        for stripe in entries.chunks(total_targets) {
            if stripe.len() >= total_targets {
                let placement_entries = Self::build_placement_entries(stripe, intent);
                if LayoutValidator::validate(intent, &placement_entries).is_err() {
                    all_validated = false;
                }
            } else {
                all_validated = false;
            }
        }

        Ok((entries, all_validated))
    }

    fn build_placement_entries(
        entries: &[EvacuationEntry],
        intent: &ReplicationIntent,
    ) -> Vec<PlacementEntry> {
        let total_targets = intent.total_targets() as usize;
        entries
            .iter()
            .enumerate()
            .map(|(i, entry)| {
                let device_id = entry.target_device_index as u64 + 1;
                let node_id = entry.target_device_index as u64 + 10;
                let rack_id = 100 + (i as u64 / total_targets as u64 % 4) * 100;
                PlacementEntry::new(i as u16, device_id, node_id, rack_id)
            })
            .collect()
    }

    /// Recursively flatten the device tree, collecting all leaf device info.
    pub fn flatten_leaves(tree: &DeviceType) -> Vec<LeafInfo> {
        let mut leaves = Vec::new();
        Self::collect_leaves(tree, &mut leaves);
        leaves
    }

    fn collect_leaves(node: &DeviceType, out: &mut Vec<LeafInfo>) {
        match node {
            DeviceType::Leaf {
                device_path,
                device_guid,
                device_index,
                capacity_bytes,
                health,
                ..
            } => {
                out.push(LeafInfo {
                    device_path: device_path.clone(),
                    device_guid: *device_guid,
                    device_index: *device_index,
                    capacity_bytes: *capacity_bytes,
                    health: *health,
                });
            }
            DeviceType::PoolWideData { children }
            | DeviceType::Mirror { children }
            | DeviceType::ParityRaid { children, .. } => {
                for child in children {
                    Self::collect_leaves(child, out);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// LeafInfo — extracted leaf-device metadata
// ---------------------------------------------------------------------------

/// Lightweight leaf-device metadata extracted from the device tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafInfo {
    /// Device path.
    pub device_path: PathBuf,
    /// Device GUID.
    pub device_guid: [u8; 16],
    /// Device index in the pool.
    pub device_index: u32,
    /// Device capacity in bytes.
    pub capacity_bytes: u64,
    /// Device health from the pool topology.
    pub health: crate::DeviceHealth,
}

// ---------------------------------------------------------------------------
// DeviceRemovalResult — outcome of executing a removal plan
// ---------------------------------------------------------------------------

/// Result of executing a device removal plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRemovalResult {
    /// Number of objects successfully evacuated.
    pub objects_evacuated: u64,
    /// Total bytes evacuated.
    pub bytes_evacuated: u64,
    /// Number of objects that failed evacuation.
    pub objects_failed: u64,
    /// Path of the removed device.
    pub removed_device: PathBuf,
    /// Surviving devices after removal.
    pub surviving_devices: Vec<PathBuf>,
    /// New topology generation.
    pub topology_generation: u64,
    /// Whether the removal was anchored in a committed root.
    pub committed_root_anchored: bool,
}

// ---------------------------------------------------------------------------
// DeviceRemovalExecutor — executes the evacuation plan
// ---------------------------------------------------------------------------

/// Executes a [`DeviceRemovalPlan`] by coordinating per-object evacuation.
///
/// The executor delegates the actual read/write I/O to caller-provided
/// closures. This keeps the executor decoupled from any specific storage
/// backend and allows it to work with local-object-store, in-memory test
/// stores, or network transports.
///
/// # Lifecycle
///
/// 1. Iterates over every [`EvacuationEntry`] in the plan.
/// 2. For each entry, calls `read_object` to fetch the object data.
/// 3. Calls `write_object` to place the data on the target device.
/// 4. On any failure, records the failure and refuses committed-root anchoring.
/// 5. Calls `anchor_removal` only after all objects are processed cleanly.
/// 6. Returns a [`DeviceRemovalResult`] summarising success/failure counts.
pub struct DeviceRemovalExecutor;

impl DeviceRemovalExecutor {
    /// Execute the provided removal plan.
    ///
    /// * `plan` - The evacuation plan computed by [`DeviceRemovalPlanner`].
    /// * `read_object` - Callback to read an object by its `object_id`.
    /// * `write_object` - Callback to write an object to a target device.
    /// * `anchor_removal` - Callback invoked after all objects are evacuated
    ///   to anchor the removal in a committed root.
    pub fn execute_plan(
        plan: &DeviceRemovalPlan,
        mut read_object: impl FnMut(u64) -> Result<Vec<u8>, DeviceRemovalError>,
        mut write_object: impl FnMut(u64, &[u8], &Path) -> Result<(), DeviceRemovalError>,
        anchor_removal: impl FnOnce(&DeviceRemovalResult) -> bool,
    ) -> DeviceRemovalResult {
        let mut objects_evacuated: u64 = 0;
        let mut bytes_evacuated: u64 = 0;
        let mut objects_failed: u64 = 0;

        for entry in &plan.objects_to_evacuate {
            match read_object(entry.object_id) {
                Ok(data) => match write_object(entry.object_id, &data, &entry.target_device) {
                    Ok(()) => {
                        objects_evacuated += 1;
                        bytes_evacuated += entry.size_bytes;
                    }
                    Err(_) => {
                        objects_failed += 1;
                    }
                },
                Err(_) => {
                    objects_failed += 1;
                }
            }
        }

        let result = DeviceRemovalResult {
            objects_evacuated,
            bytes_evacuated,
            objects_failed,
            removed_device: plan.target_device.clone(),
            surviving_devices: plan.surviving_devices.clone(),
            topology_generation: plan.topology_generation,
            committed_root_anchored: false,
        };

        let expected_objects = plan.objects_to_evacuate.len() as u64;
        let anchored = if objects_failed == 0 && objects_evacuated == expected_objects {
            anchor_removal(&result)
        } else {
            false
        };

        DeviceRemovalResult {
            committed_root_anchored: anchored,
            ..result
        }
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// VdevRemoveStats — per-device removal statistics
// ---------------------------------------------------------------------------

/// Statistics gathered during an online device removal.
///
/// Tracks the outcome of evacuating all objects from a departing device
/// and removing it from the pool.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VdevRemoveStats {
    /// Path of the device that was removed.
    pub device_path: PathBuf,
    /// Total bytes evacuated from the device to surviving pool members.
    pub bytes_evacuated: u64,
    /// Wall-clock duration of the evacuation in milliseconds.
    pub evacuation_time_ms: u64,
    /// Whether the device removal completed successfully.
    pub removal_success: bool,
}

impl VdevRemoveStats {
    /// Create a new stats record.
    #[must_use]
    pub const fn new(device_path: PathBuf) -> Self {
        Self {
            device_path,
            bytes_evacuated: 0,
            evacuation_time_ms: 0,
            removal_success: false,
        }
    }

    /// Mark the removal as successful with the given statistics.
    pub fn mark_success(&mut self, bytes_evacuated: u64, evacuation_time_ms: u64) {
        self.bytes_evacuated = bytes_evacuated;
        self.evacuation_time_ms = evacuation_time_ms;
        self.removal_success = true;
    }

    /// Mark the removal as failed (device not removed).
    pub fn mark_failed(&mut self) {
        self.removal_success = false;
    }
}

// ---------------------------------------------------------------------------
// check_removal_redundancy — validate that removing a device is safe
// ---------------------------------------------------------------------------

/// Check whether removing a device would leave the topology empty.
///
/// # Safety rules
///
/// * Pool-wide data set: removal is allowed as long as at least one member
///   remains. The caller's evacuation/placement validation owns policy
///   sufficiency.
/// * Legacy group nodes follow the same member-set rule for compatibility.
/// * Standalone leaf: refused because it would empty the pool.
///
/// # Errors
///
/// Returns [] if the removal
/// is unsafe, or [] if the
/// target path is not in the tree.
pub fn check_removal_redundancy(
    device_tree: &crate::DeviceType,
    target_path: &Path,
) -> Result<(), DeviceRemovalError> {
    match device_tree {
        crate::DeviceType::Leaf { device_path, .. } => {
            if device_path == target_path {
                return Err(DeviceRemovalError::WouldEmptyPool);
            }
            Err(DeviceRemovalError::TargetDeviceNotFound {
                path: target_path.to_path_buf(),
            })
        }
        crate::DeviceType::PoolWideData { children }
        | crate::DeviceType::Mirror { children }
        | crate::DeviceType::ParityRaid { children, .. } => {
            let child_count = children.len();
            for child in children {
                match child {
                    crate::DeviceType::Leaf { device_path, .. } => {
                        if device_path == target_path {
                            if child_count <= 1 {
                                return Err(DeviceRemovalError::WouldEmptyPool);
                            }
                            return Ok(());
                        }
                    }
                    _ => {
                        if let Ok(()) = check_removal_redundancy(child, target_path) {
                            return Ok(());
                        }
                    }
                }
            }
            Err(DeviceRemovalError::TargetDeviceNotFound {
                path: target_path.to_path_buf(),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// DeviceRemovalPhase — the four-phase removal lifecycle
// ---------------------------------------------------------------------------

/// Each phase in the device removal state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceRemovalPhase {
    /// Initial phase: stop new allocations on the target device.
    Quiesce,
    /// Move all objects off the target device.
    Evacuate,
    /// Confirm zero remaining objects on the departing device.
    Verify,
    /// Update pool metadata and anchor in a committed root.
    Commit,
    /// Removal completed successfully.
    Complete,
    /// Removal failed and cannot proceed.
    Failed,
}

impl DeviceRemovalPhase {
    /// Returns the next phase in the normal forward progression.
    #[must_use]
    pub const fn next_phase(self) -> Option<Self> {
        match self {
            Self::Quiesce => Some(Self::Evacuate),
            Self::Evacuate => Some(Self::Verify),
            Self::Verify => Some(Self::Commit),
            Self::Commit => Some(Self::Complete),
            Self::Complete | Self::Failed => None,
        }
    }

    /// Returns `true` if this is a terminal phase.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Failed)
    }
}

impl std::fmt::Display for DeviceRemovalPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Quiesce => f.write_str("quiesce"),
            Self::Evacuate => f.write_str("evacuate"),
            Self::Verify => f.write_str("verify"),
            Self::Commit => f.write_str("commit"),
            Self::Complete => f.write_str("complete"),
            Self::Failed => f.write_str("failed"),
        }
    }
}

// ---------------------------------------------------------------------------
// DeviceRemovalStateMachine — orchestrates the four-phase removal
// ---------------------------------------------------------------------------

/// Holds the live state of an in-progress (or completed) device removal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRemovalState {
    /// Current phase of the removal.
    pub phase: DeviceRemovalPhase,
    /// Path of the device being removed.
    pub target_device: PathBuf,
    /// GUID of the device being removed.
    pub target_device_guid: [u8; 16],
    /// Number of objects evacuated so far.
    pub objects_evacuated: u64,
    /// Number of objects that failed evacuation.
    pub objects_failed: u64,
    /// Human-readable error message if the removal entered the Failed phase.
    pub error: Option<String>,
    /// Typed refusal/failure evidence if the removal entered the Failed phase.
    pub failure_evidence: Option<DeviceRemovalRefusal>,
}

impl DeviceRemovalState {
    /// Create a new removal state at the Quiesce phase.
    #[must_use]
    pub fn new(target_device: PathBuf, target_device_guid: [u8; 16]) -> Self {
        Self {
            phase: DeviceRemovalPhase::Quiesce,
            target_device,
            target_device_guid,
            objects_evacuated: 0,
            objects_failed: 0,
            error: None,
            failure_evidence: None,
        }
    }

    /// Transition to the next phase.
    ///
    /// Returns an error if already in a terminal phase.
    pub fn advance(&mut self) -> Result<(), DeviceRemovalError> {
        match self.phase.next_phase() {
            Some(next) => {
                self.phase = next;
                Ok(())
            }
            None => Err(DeviceRemovalError::DomainConstraintViolation {
                details: format!("cannot advance from terminal phase {:?}", self.phase),
            }),
        }
    }

    /// Transition to the Failed phase with an error message.
    pub fn fail(&mut self, error: impl Into<String>) {
        self.phase = DeviceRemovalPhase::Failed;
        self.error = Some(error.into());
    }

    /// Transition to the Failed phase with typed refusal evidence.
    pub fn fail_with_evidence(&mut self, evidence: DeviceRemovalRefusal) {
        self.phase = DeviceRemovalPhase::Failed;
        self.error = Some(evidence.details.clone());
        self.failure_evidence = Some(evidence);
    }
}

/// Builder-style hooks for customising removal-phase behaviour.
///
/// Each hook receives a mutable reference to [`DeviceRemovalState`] and
/// returns `Ok(())` on success or `Err(DeviceRemovalError)` on failure.
pub trait DeviceRemovalHooks {
    /// Called during the Quiesce phase to stop allocations on the target
    /// device. The default implementation is a no-op.
    fn quiesce_device(
        &mut self,
        _state: &mut DeviceRemovalState,
    ) -> Result<(), DeviceRemovalError> {
        Ok(())
    }

    /// Called during the Verify phase to confirm zero remaining objects
    /// on the departing device. The default implementation returns `Ok(())`.
    fn verify_empty(&mut self, _state: &mut DeviceRemovalState) -> Result<(), DeviceRemovalError> {
        Ok(())
    }

    /// Called during the Commit phase after the pool metadata has been
    /// updated. The default implementation is a no-op.
    fn commit_removal(
        &mut self,
        _state: &mut DeviceRemovalState,
        _result: &DeviceRemovalResult,
    ) -> Result<(), DeviceRemovalError> {
        Ok(())
    }
}

/// A no-op implementation of [`DeviceRemovalHooks`] used when no
/// customisation is needed.
pub struct NoopDeviceRemovalHooks;

impl DeviceRemovalHooks for NoopDeviceRemovalHooks {}

/// Inputs for one run of the device-removal state machine.
pub struct DeviceRemovalRun<'a> {
    /// Device tree used to plan target evacuation.
    pub device_tree: &'a crate::DeviceType,
    /// Current object placement records.
    pub object_placements: &'a [ObjectPlacement],
    /// Replication policy that surviving placements must satisfy.
    pub intent: ReplicationIntent,
    /// Topology generation assigned to replacement placements.
    pub topology_generation: u64,
}

/// Runs the four-phase device removal state machine.
///
/// # Lifecycle
///
/// 1. **Quiesce** — calls `hooks.quiesce_device()`.
/// 2. **Evacuate** — computes a removal plan with
///    [`DeviceRemovalPlanner`] and executes it with
///    [`DeviceRemovalExecutor`].
/// 3. **Verify** — calls `hooks.verify_empty()`.
/// 4. **Commit** — calls `hooks.commit_removal()`.
///
/// If any phase returns an error the state transitions to `Failed` and
/// the error is returned.
///
/// # Panics
///
/// Panics if called when `state` is already in a terminal phase.
pub fn run_device_removal<R, W, A>(
    state: &mut DeviceRemovalState,
    hooks: &mut impl DeviceRemovalHooks,
    request: DeviceRemovalRun<'_>,
    read_object: R,
    write_object: W,
    anchor_removal: A,
) -> Result<DeviceRemovalResult, DeviceRemovalError>
where
    R: FnMut(u64) -> Result<Vec<u8>, DeviceRemovalError>,
    W: FnMut(u64, &[u8], &Path) -> Result<(), DeviceRemovalError>,
    A: FnOnce(&DeviceRemovalResult) -> bool,
{
    let DeviceRemovalRun {
        device_tree,
        object_placements,
        intent,
        topology_generation,
    } = request;

    assert!(
        !state.phase.is_terminal(),
        "run_device_removal called on terminal phase {:?}",
        state.phase
    );

    // --- Phase 1: Quiesce ---
    hooks.quiesce_device(state)?;
    state.advance()?;

    // --- Phase 2: Evacuate ---
    let plan = DeviceRemovalPlanner::plan_removal(
        device_tree,
        &state.target_device,
        object_placements,
        intent,
        topology_generation,
    )?;

    let result =
        DeviceRemovalExecutor::execute_plan(&plan, read_object, write_object, anchor_removal);

    state.objects_evacuated = result.objects_evacuated;
    state.objects_failed = result.objects_failed;
    if result.objects_failed > 0 || result.objects_evacuated != plan.object_count {
        let evidence = DeviceRemovalRefusal::new(
            DeviceRemovalRefusalClass::EvacuationFailed,
            state.target_device.clone(),
            format!(
                "evacuated {} of {} object(s); {} object(s) failed",
                result.objects_evacuated, plan.object_count, result.objects_failed
            ),
        );
        state.fail_with_evidence(evidence.clone());
        return Err(DeviceRemovalError::EvacuationFailed {
            details: evidence.details,
        });
    }
    state.advance()?;

    // --- Phase 3: Verify ---
    hooks.verify_empty(state)?;
    state.advance()?;

    // --- Phase 4: Commit ---
    hooks.commit_removal(state, &result)?;
    state.advance()?;

    Ok(result)
}

// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceType;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use tidefs_replication_model::FailureDomain;

    fn make_leaf(path: &str, guid_byte: u8, index: u32, capacity: u64) -> DeviceType {
        let mut guid = [0u8; 16];
        guid[0] = guid_byte;
        DeviceType::Leaf {
            device_path: PathBuf::from(path),
            device_guid: guid,
            device_index: index,
            capacity_bytes: capacity,
            device_class: tidefs_types_pool_label_core::DeviceClass::Hdd,
            health: crate::DeviceHealth::Online,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        }
    }

    fn make_pool_data(children: Vec<DeviceType>) -> DeviceType {
        DeviceType::PoolWideData { children }
    }

    fn make_object(id: u64, device: &str, size: u64) -> ObjectPlacement {
        ObjectPlacement::new(id, PathBuf::from(device), size)
    }

    // ---------- Planner: basic plan computation ----------

    #[test]
    fn plan_removal_three_device_pool_data_set() {
        let tree = make_pool_data(vec![
            make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024),
            make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024),
            make_leaf("/dev/disk2", 3, 2, 1024 * 1024 * 1024),
        ]);
        let placements = vec![
            make_object(100, "/dev/disk0", 4096),
            make_object(101, "/dev/disk0", 8192),
            make_object(200, "/dev/disk1", 4096),
            make_object(300, "/dev/disk2", 16384),
        ];
        let intent = ReplicationIntent::new_mirror(2, FailureDomain::Device).unwrap();
        let plan = DeviceRemovalPlanner::plan_removal(
            &tree,
            Path::new("/dev/disk0"),
            &placements,
            intent,
            5,
        )
        .unwrap();
        assert_eq!(plan.objects_to_evacuate.len(), 2);
        assert_eq!(plan.target_device, PathBuf::from("/dev/disk0"));
        assert_eq!(plan.device_count_before, 3);
        assert_eq!(plan.device_count_after, 2);
        assert_eq!(plan.topology_generation, 6);
        assert_eq!(plan.total_evacuation_bytes, 4096 + 8192);
        assert_eq!(plan.object_count, 2);
        assert_eq!(
            plan.evacuation_outcome,
            EvacuationPlanOutcome::ObjectsEnumerated
        );
        for entry in &plan.objects_to_evacuate {
            assert_ne!(entry.target_device, PathBuf::from("/dev/disk0"));
        }
    }

    #[test]
    fn plan_removal_no_objects_on_target() {
        let tree = make_pool_data(vec![
            make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024),
            make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024),
            make_leaf("/dev/disk2", 3, 2, 1024 * 1024 * 1024),
        ]);
        let placements = vec![make_object(200, "/dev/disk1", 4096)];
        let intent = ReplicationIntent::new_mirror(1, FailureDomain::Device).unwrap();
        let plan = DeviceRemovalPlanner::plan_removal(
            &tree,
            Path::new("/dev/disk0"),
            &placements,
            intent,
            1,
        )
        .unwrap();
        assert!(plan.is_empty());
        assert_eq!(plan.object_count, 0);
        assert_eq!(plan.evacuation_outcome, EvacuationPlanOutcome::EmptySuccess);
    }

    #[test]
    fn plan_removal_would_empty_pool() {
        let tree = DeviceType::Leaf {
            device_path: PathBuf::from("/dev/disk0"),
            device_guid: [1u8; 16],
            device_index: 0,
            capacity_bytes: 1024 * 1024 * 1024,
            device_class: tidefs_types_pool_label_core::DeviceClass::Hdd,
            health: crate::DeviceHealth::Online,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        };
        let placements = vec![make_object(100, "/dev/disk0", 4096)];
        let intent = ReplicationIntent::new_mirror(1, FailureDomain::Device).unwrap();
        let result = DeviceRemovalPlanner::plan_removal(
            &tree,
            Path::new("/dev/disk0"),
            &placements,
            intent,
            1,
        );
        assert!(matches!(result, Err(DeviceRemovalError::WouldEmptyPool)));
    }

    #[test]
    fn target_device_not_found() {
        let tree = make_pool_data(vec![
            make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024),
            make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024),
        ]);
        let placements = vec![make_object(100, "/dev/disk0", 4096)];
        let intent = ReplicationIntent::new_mirror(1, FailureDomain::Device).unwrap();
        let result = DeviceRemovalPlanner::plan_removal(
            &tree,
            Path::new("/dev/nonexistent"),
            &placements,
            intent,
            1,
        );
        assert!(matches!(
            result,
            Err(DeviceRemovalError::TargetDeviceNotFound { .. })
        ));
    }

    #[test]
    fn planner_refuses_stale_topology_generation_with_typed_class() {
        let tree = make_pool_data(vec![
            make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024),
            make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024),
        ]);
        let err = DeviceRemovalPlanner::plan_removal_with_expected_generation(
            &tree,
            Path::new("/dev/disk0"),
            &[],
            ReplicationIntent::new_mirror(1, FailureDomain::Device).unwrap(),
            7,
            6,
        )
        .unwrap_err();
        assert_eq!(
            err.refusal_class(),
            DeviceRemovalRefusalClass::StaleTopologyGeneration
        );
        let evidence = err.refusal_evidence(Path::new("/dev/disk0"));
        let json = serde_json::to_string(&evidence).unwrap();
        assert!(json.contains("stale-topology-generation"));
    }

    #[test]
    fn planner_refuses_insufficient_surviving_topology_with_typed_class() {
        let tree = make_pool_data(vec![
            make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024),
            make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024),
        ]);
        let placements = vec![
            make_object(100, "/dev/disk0", 4096),
            make_object(101, "/dev/disk0", 4096),
        ];
        let err = DeviceRemovalPlanner::plan_removal(
            &tree,
            Path::new("/dev/disk0"),
            &placements,
            ReplicationIntent::new_mirror(2, FailureDomain::Device).unwrap(),
            1,
        )
        .unwrap_err();
        assert_eq!(
            err.refusal_class(),
            DeviceRemovalRefusalClass::InsufficientSurvivingTopology
        );
    }

    #[test]
    fn planner_refuses_domain_constraint_violation_with_typed_class() {
        let tree = make_pool_data(vec![
            make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024),
            make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024),
            make_leaf("/dev/disk2", 3, 2, 1024 * 1024 * 1024),
        ]);
        let placements = vec![make_object(100, "/dev/disk0", 4096)];
        let err = DeviceRemovalPlanner::plan_removal(
            &tree,
            Path::new("/dev/disk0"),
            &placements,
            ReplicationIntent::new_mirror(2, FailureDomain::Device).unwrap(),
            1,
        )
        .unwrap_err();
        assert_eq!(
            err.refusal_class(),
            DeviceRemovalRefusalClass::DomainConstraintViolation
        );
    }

    // ---------- Planner: failure domain constraints ----------

    #[test]
    fn device_level_separation_single_object() {
        let tree = make_pool_data(vec![
            make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024),
            make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024),
        ]);
        let placements = vec![make_object(100, "/dev/disk0", 4096)];
        let intent = ReplicationIntent::new_mirror(1, FailureDomain::Device).unwrap();
        let plan = DeviceRemovalPlanner::plan_removal(
            &tree,
            Path::new("/dev/disk0"),
            &placements,
            intent,
            1,
        )
        .unwrap();
        assert_eq!(plan.objects_to_evacuate.len(), 1);
        assert_eq!(plan.device_count_after, 1);
    }

    #[test]
    fn full_stripe_validated() {
        let tree = make_pool_data(vec![
            make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024),
            make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024),
            make_leaf("/dev/disk2", 3, 2, 1024 * 1024 * 1024),
            make_leaf("/dev/disk3", 4, 3, 1024 * 1024 * 1024),
        ]);
        let placements: Vec<ObjectPlacement> = (0..3)
            .map(|i| make_object(100 + i, "/dev/disk0", 4096))
            .collect();
        let intent = ReplicationIntent::new_mirror(3, FailureDomain::Device).unwrap();
        let plan = DeviceRemovalPlanner::plan_removal(
            &tree,
            Path::new("/dev/disk0"),
            &placements,
            intent,
            1,
        )
        .unwrap();
        assert_eq!(plan.objects_to_evacuate.len(), 3);
        assert_eq!(plan.device_count_after, 3);
    }

    #[test]
    fn validated_when_enough_surviving_devices() {
        let tree = make_pool_data(vec![
            make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024),
            make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024),
            make_leaf("/dev/disk2", 3, 2, 1024 * 1024 * 1024),
            make_leaf("/dev/disk3", 4, 3, 1024 * 1024 * 1024),
        ]);
        let placements: Vec<ObjectPlacement> = (0..3)
            .map(|i| make_object(100 + i, "/dev/disk0", 4096))
            .collect();
        let intent = ReplicationIntent::new_mirror(3, FailureDomain::Device).unwrap();
        let plan = DeviceRemovalPlanner::plan_removal(
            &tree,
            Path::new("/dev/disk0"),
            &placements,
            intent,
            1,
        )
        .unwrap();
        assert_eq!(plan.objects_to_evacuate.len(), 3);
        assert_eq!(plan.device_count_after, 3);
        assert!(plan.plan_validated);
    }

    // ---------- Planner: round-robin distribution ----------

    #[test]
    fn round_robin_distribution_across_surviving() {
        let tree = make_pool_data(vec![
            make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024),
            make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024),
            make_leaf("/dev/disk2", 3, 2, 1024 * 1024 * 1024),
            make_leaf("/dev/disk3", 4, 3, 1024 * 1024 * 1024),
        ]);
        let placements: Vec<ObjectPlacement> = (0..8)
            .map(|i| make_object(100 + i, "/dev/disk0", 4096))
            .collect();
        let intent = ReplicationIntent::new_mirror(2, FailureDomain::Device).unwrap();
        let plan = DeviceRemovalPlanner::plan_removal(
            &tree,
            Path::new("/dev/disk0"),
            &placements,
            intent,
            1,
        )
        .unwrap();
        assert_eq!(plan.objects_to_evacuate.len(), 8);
        let mut counts: BTreeMap<PathBuf, usize> = BTreeMap::new();
        for entry in &plan.objects_to_evacuate {
            *counts.entry(entry.target_device.clone()).or_default() += 1;
        }
        let d1 = counts
            .get(&PathBuf::from("/dev/disk1"))
            .copied()
            .unwrap_or(0);
        let d2 = counts
            .get(&PathBuf::from("/dev/disk2"))
            .copied()
            .unwrap_or(0);
        let d3 = counts
            .get(&PathBuf::from("/dev/disk3"))
            .copied()
            .unwrap_or(0);
        assert_eq!(d1 + d2 + d3, 8);
        assert!((2..=3).contains(&d1));
        assert!((2..=3).contains(&d2));
        assert!((2..=3).contains(&d3));
    }

    // ---------- Serde roundtrip ----------

    #[test]
    fn serde_device_removal_plan_roundtrip() {
        let plan = DeviceRemovalPlan {
            target_device: PathBuf::from("/dev/disk0"),
            target_device_guid: [1u8; 16],
            target_device_index: 0,
            surviving_devices: vec![PathBuf::from("/dev/disk1"), PathBuf::from("/dev/disk2")],
            device_count_before: 3,
            device_count_after: 2,
            objects_to_evacuate: vec![EvacuationEntry {
                object_id: 100,
                source_device: PathBuf::from("/dev/disk0"),
                target_device: PathBuf::from("/dev/disk1"),
                size_bytes: 4096,
                target_device_index: 0,
            }],
            total_evacuation_bytes: 4096,
            object_count: 1,
            evacuation_outcome: EvacuationPlanOutcome::ObjectsEnumerated,
            topology_generation: 7,
            replication_intent: ReplicationIntent::new_mirror(2, FailureDomain::Device).unwrap(),
            plan_validated: true,
        };
        let json = serde_json::to_string(&plan).expect("serialize");
        let round: DeviceRemovalPlan = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(plan, round);
    }

    #[test]
    fn plan_is_empty() {
        let plan = DeviceRemovalPlan {
            target_device: PathBuf::from("/dev/disk0"),
            target_device_guid: [0u8; 16],
            target_device_index: 0,
            surviving_devices: vec![],
            device_count_before: 1,
            device_count_after: 0,
            objects_to_evacuate: vec![],
            total_evacuation_bytes: 0,
            object_count: 0,
            evacuation_outcome: EvacuationPlanOutcome::EmptySuccess,
            topology_generation: 1,
            replication_intent: ReplicationIntent::new_mirror(1, FailureDomain::Device).unwrap(),
            plan_validated: false,
        };
        assert!(plan.is_empty());
        assert_eq!(plan.object_count(), 0);
    }

    // ---------- Error display ----------

    #[test]
    fn error_display_target_not_found() {
        let err = DeviceRemovalError::TargetDeviceNotFound {
            path: PathBuf::from("/dev/missing"),
        };
        assert!(err.to_string().contains("/dev/missing"));
    }

    #[test]
    fn error_display_domain_violation() {
        let err = DeviceRemovalError::DomainConstraintViolation {
            details: "collision on device 1".to_string(),
        };
        assert!(err.to_string().contains("collision"));
    }

    #[test]
    fn error_display_would_empty_pool() {
        assert!(DeviceRemovalError::WouldEmptyPool
            .to_string()
            .contains("last device"));
    }

    #[test]
    fn refusal_evidence_serializes_stable_class() {
        let target = Path::new("/dev/disk0");
        let errors = vec![
            (
                DeviceRemovalError::TargetDeviceNotFound {
                    path: target.to_path_buf(),
                },
                DeviceRemovalRefusalClass::TargetNotFound,
            ),
            (
                DeviceRemovalError::WouldEmptyPool,
                DeviceRemovalRefusalClass::WouldEmptyPool,
            ),
            (
                DeviceRemovalError::DeviceNotHealthy {
                    path: target.to_path_buf(),
                    health: crate::DeviceHealth::Faulted,
                },
                DeviceRemovalRefusalClass::UnhealthyTarget,
            ),
            (
                DeviceRemovalError::InsufficientRedundancy {
                    details: "only one survivor".into(),
                },
                DeviceRemovalRefusalClass::InsufficientSurvivingTopology,
            ),
            (
                DeviceRemovalError::DomainConstraintViolation {
                    details: "failure domain collision".into(),
                },
                DeviceRemovalRefusalClass::DomainConstraintViolation,
            ),
            (
                DeviceRemovalError::StaleTopologyGeneration {
                    path: target.to_path_buf(),
                    expected: 7,
                    observed: 8,
                },
                DeviceRemovalRefusalClass::StaleTopologyGeneration,
            ),
        ];

        for (error, expected) in errors {
            assert_eq!(error.refusal_class(), expected);
            let evidence = error.refusal_evidence(target);
            assert_eq!(evidence.class, expected);
            let json = serde_json::to_string(&evidence).unwrap();
            assert!(json.contains(&expected.to_string()));
            let round: DeviceRemovalRefusal = serde_json::from_str(&json).unwrap();
            assert_eq!(round.class, expected);
        }
    }

    #[test]
    fn evacuation_entry_fields() {
        let entry = EvacuationEntry {
            object_id: 42,
            source_device: PathBuf::from("/dev/disk0"),
            target_device: PathBuf::from("/dev/disk1"),
            size_bytes: 8192,
            target_device_index: 1,
        };
        assert_eq!(entry.object_id, 42);
        assert_eq!(entry.source_device, PathBuf::from("/dev/disk0"));
        assert_eq!(entry.target_device, PathBuf::from("/dev/disk1"));
        assert_eq!(entry.size_bytes, 8192);
        assert_eq!(entry.target_device_index, 1);
    }

    // ---------- Executor tests ----------

    #[test]
    fn executor_evacuates_all_objects() {
        let plan = DeviceRemovalPlan {
            target_device: PathBuf::from("/dev/disk0"),
            target_device_guid: [1u8; 16],
            target_device_index: 0,
            surviving_devices: vec![PathBuf::from("/dev/disk1")],
            device_count_before: 2,
            device_count_after: 1,
            objects_to_evacuate: vec![
                EvacuationEntry {
                    object_id: 100,
                    source_device: PathBuf::from("/dev/disk0"),
                    target_device: PathBuf::from("/dev/disk1"),
                    size_bytes: 4096,
                    target_device_index: 0,
                },
                EvacuationEntry {
                    object_id: 101,
                    source_device: PathBuf::from("/dev/disk0"),
                    target_device: PathBuf::from("/dev/disk1"),
                    size_bytes: 8192,
                    target_device_index: 0,
                },
            ],
            total_evacuation_bytes: 12288,
            object_count: 2,
            evacuation_outcome: EvacuationPlanOutcome::ObjectsEnumerated,
            topology_generation: 2,
            replication_intent: ReplicationIntent::new_mirror(2, FailureDomain::Device).unwrap(),
            plan_validated: true,
        };
        let mut store: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        store.insert(100, vec![1u8; 4096]);
        store.insert(101, vec![2u8; 8192]);
        let mut written: BTreeMap<u64, (Vec<u8>, PathBuf)> = BTreeMap::new();
        let result = DeviceRemovalExecutor::execute_plan(
            &plan,
            |id| {
                store
                    .get(&id)
                    .cloned()
                    .ok_or(DeviceRemovalError::NoObjectsOnDevice)
            },
            |id, data, target| {
                written.insert(id, (data.to_vec(), target.to_path_buf()));
                Ok(())
            },
            |_| true,
        );
        assert_eq!(result.objects_evacuated, 2);
        assert_eq!(result.bytes_evacuated, 12288);
        assert_eq!(result.objects_failed, 0);
        assert!(result.committed_root_anchored);
        assert_eq!(written.len(), 2);
    }

    #[test]
    fn executor_handles_read_failure() {
        let plan = DeviceRemovalPlan {
            target_device: PathBuf::from("/dev/disk0"),
            target_device_guid: [1u8; 16],
            target_device_index: 0,
            surviving_devices: vec![PathBuf::from("/dev/disk1")],
            device_count_before: 2,
            device_count_after: 1,
            objects_to_evacuate: vec![
                EvacuationEntry {
                    object_id: 100,
                    source_device: PathBuf::from("/dev/disk0"),
                    target_device: PathBuf::from("/dev/disk1"),
                    size_bytes: 4096,
                    target_device_index: 0,
                },
                EvacuationEntry {
                    object_id: 101,
                    source_device: PathBuf::from("/dev/disk0"),
                    target_device: PathBuf::from("/dev/disk1"),
                    size_bytes: 8192,
                    target_device_index: 0,
                },
            ],
            total_evacuation_bytes: 12288,
            object_count: 2,
            evacuation_outcome: EvacuationPlanOutcome::ObjectsEnumerated,
            topology_generation: 2,
            replication_intent: ReplicationIntent::new_mirror(2, FailureDomain::Device).unwrap(),
            plan_validated: true,
        };
        let mut store: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        store.insert(100, vec![1u8; 4096]); // 101 missing
        let mut written: BTreeMap<u64, (Vec<u8>, PathBuf)> = BTreeMap::new();
        let result = DeviceRemovalExecutor::execute_plan(
            &plan,
            |id| {
                store
                    .get(&id)
                    .cloned()
                    .ok_or(DeviceRemovalError::NoObjectsOnDevice)
            },
            |id, data, target| {
                written.insert(id, (data.to_vec(), target.to_path_buf()));
                Ok(())
            },
            |_| true,
        );
        assert_eq!(result.objects_evacuated, 1);
        assert_eq!(result.bytes_evacuated, 4096);
        assert_eq!(result.objects_failed, 1);
        assert!(!result.committed_root_anchored);
        assert_eq!(written.len(), 1);
    }

    #[test]
    fn executor_handles_write_failure() {
        let plan = DeviceRemovalPlan {
            target_device: PathBuf::from("/dev/disk0"),
            target_device_guid: [1u8; 16],
            target_device_index: 0,
            surviving_devices: vec![PathBuf::from("/dev/disk1")],
            device_count_before: 2,
            device_count_after: 1,
            objects_to_evacuate: vec![EvacuationEntry {
                object_id: 100,
                source_device: PathBuf::from("/dev/disk0"),
                target_device: PathBuf::from("/dev/disk1"),
                size_bytes: 4096,
                target_device_index: 0,
            }],
            total_evacuation_bytes: 4096,
            object_count: 1,
            evacuation_outcome: EvacuationPlanOutcome::ObjectsEnumerated,
            topology_generation: 2,
            replication_intent: ReplicationIntent::new_mirror(2, FailureDomain::Device).unwrap(),
            plan_validated: true,
        };
        let mut store: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        store.insert(100, vec![1u8; 4096]);
        let result = DeviceRemovalExecutor::execute_plan(
            &plan,
            |id| {
                store
                    .get(&id)
                    .cloned()
                    .ok_or(DeviceRemovalError::NoObjectsOnDevice)
            },
            |_id, _data, _target| Err(DeviceRemovalError::NoObjectsOnDevice),
            |_| false,
        );
        assert_eq!(result.objects_evacuated, 0);
        assert_eq!(result.objects_failed, 1);
        assert!(!result.committed_root_anchored);
    }

    #[test]
    fn executor_empty_plan() {
        let plan = DeviceRemovalPlan {
            target_device: PathBuf::from("/dev/disk0"),
            target_device_guid: [1u8; 16],
            target_device_index: 0,
            surviving_devices: vec![],
            device_count_before: 1,
            device_count_after: 0,
            objects_to_evacuate: vec![],
            total_evacuation_bytes: 0,
            object_count: 0,
            evacuation_outcome: EvacuationPlanOutcome::EmptySuccess,
            topology_generation: 1,
            replication_intent: ReplicationIntent::new_mirror(1, FailureDomain::Device).unwrap(),
            plan_validated: false,
        };
        let result = DeviceRemovalExecutor::execute_plan(
            &plan,
            |_id| Err(DeviceRemovalError::NoObjectsOnDevice),
            |_id, _data, _target| Ok(()),
            |_| true,
        );
        assert_eq!(result.objects_evacuated, 0);
        assert_eq!(result.objects_failed, 0);
        assert_eq!(result.bytes_evacuated, 0);
    }

    // ---------- PoolConfig::remove_device tests ----------

    #[test]
    fn remove_device_from_mirror() {
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024);
        let leaf1 = make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024);
        let leaf2 = make_leaf("/dev/disk2", 3, 2, 1024 * 1024 * 1024);
        let mut config = crate::PoolConfig {
            pool_uuid: [0xAAu8; 16],
            pool_name: "test".to_string(),
            redundancy_policy: tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(1),
            device_tree: make_pool_data(vec![leaf0, leaf1, leaf2]),
            health: crate::DeviceHealth::Online,
            state: tidefs_types_pool_label_core::PoolState::Active,
            total_capacity_bytes: 3 * 1024 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 5,
            device_count: 3,
            missing_indices: vec![],
            removing_device_indices: vec![],
        };
        assert_eq!(config.device_count, 3);
        assert_eq!(config.topology_generation, 5);
        config.remove_device(Path::new("/dev/disk1")).unwrap();
        assert_eq!(config.device_count, 2);
        assert_eq!(config.topology_generation, 6);
        assert_eq!(config.device_tree.leaf_count(), 2);
        let leaves = DeviceRemovalPlanner::flatten_leaves(&config.device_tree);
        let paths: Vec<&PathBuf> = leaves.iter().map(|l| &l.device_path).collect();
        assert!(paths.contains(&&PathBuf::from("/dev/disk0")));
        assert!(paths.contains(&&PathBuf::from("/dev/disk2")));
        assert!(!paths.contains(&&PathBuf::from("/dev/disk1")));
    }

    #[test]
    fn remove_device_not_found() {
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024);
        let leaf1 = make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024);
        let mut config = crate::PoolConfig {
            pool_uuid: [0xAAu8; 16],
            pool_name: "test".to_string(),
            redundancy_policy: tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(1),
            device_tree: make_pool_data(vec![leaf0, leaf1]),
            health: crate::DeviceHealth::Online,
            state: tidefs_types_pool_label_core::PoolState::Active,
            total_capacity_bytes: 2 * 1024 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 1,
            device_count: 2,
            missing_indices: vec![],
            removing_device_indices: vec![],
        };
        let result = config.remove_device(Path::new("/dev/nonexistent"));
        assert!(matches!(
            result,
            Err(DeviceRemovalError::TargetDeviceNotFound { .. })
        ));
    }

    #[test]
    fn remove_last_device_refused() {
        let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024);
        let mut config = crate::PoolConfig {
            pool_uuid: [0xAAu8; 16],
            pool_name: "test".to_string(),
            redundancy_policy: tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(1),
            device_tree: leaf0,
            health: crate::DeviceHealth::Online,
            state: tidefs_types_pool_label_core::PoolState::Active,
            total_capacity_bytes: 1024 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 1,
            device_count: 1,
            missing_indices: vec![],
            removing_device_indices: vec![],
        };
        let result = config.remove_device(Path::new("/dev/disk0"));
        assert!(matches!(result, Err(DeviceRemovalError::WouldEmptyPool)));
    }

    // ---------- State machine: phase transitions ----------

    #[test]
    fn phase_progression_all_four() {
        assert_eq!(
            DeviceRemovalPhase::Quiesce.next_phase(),
            Some(DeviceRemovalPhase::Evacuate)
        );
        assert_eq!(
            DeviceRemovalPhase::Evacuate.next_phase(),
            Some(DeviceRemovalPhase::Verify)
        );
        assert_eq!(
            DeviceRemovalPhase::Verify.next_phase(),
            Some(DeviceRemovalPhase::Commit)
        );
        assert_eq!(
            DeviceRemovalPhase::Commit.next_phase(),
            Some(DeviceRemovalPhase::Complete)
        );
    }

    #[test]
    fn terminal_phases_have_no_next() {
        assert_eq!(DeviceRemovalPhase::Complete.next_phase(), None);
        assert_eq!(DeviceRemovalPhase::Failed.next_phase(), None);
    }

    #[test]
    fn phase_is_terminal() {
        assert!(!DeviceRemovalPhase::Quiesce.is_terminal());
        assert!(!DeviceRemovalPhase::Evacuate.is_terminal());
        assert!(!DeviceRemovalPhase::Verify.is_terminal());
        assert!(!DeviceRemovalPhase::Commit.is_terminal());
        assert!(DeviceRemovalPhase::Complete.is_terminal());
        assert!(DeviceRemovalPhase::Failed.is_terminal());
    }

    #[test]
    fn phase_display() {
        assert_eq!(format!("{}", DeviceRemovalPhase::Quiesce), "quiesce");
        assert_eq!(format!("{}", DeviceRemovalPhase::Evacuate), "evacuate");
        assert_eq!(format!("{}", DeviceRemovalPhase::Verify), "verify");
        assert_eq!(format!("{}", DeviceRemovalPhase::Commit), "commit");
        assert_eq!(format!("{}", DeviceRemovalPhase::Complete), "complete");
        assert_eq!(format!("{}", DeviceRemovalPhase::Failed), "failed");
    }

    // ---------- State machine: DeviceRemovalState ----------

    #[test]
    fn state_starts_in_quiesce() {
        let state = DeviceRemovalState::new(PathBuf::from("/dev/disk0"), [0xAAu8; 16]);
        assert_eq!(state.phase, DeviceRemovalPhase::Quiesce);
        assert_eq!(state.target_device, PathBuf::from("/dev/disk0"));
        assert_eq!(state.target_device_guid, [0xAAu8; 16]);
        assert_eq!(state.objects_evacuated, 0);
        assert_eq!(state.objects_failed, 0);
        assert!(state.error.is_none());
    }

    #[test]
    fn state_advances_through_all_phases() {
        let mut state = DeviceRemovalState::new(PathBuf::from("/dev/disk0"), [0xBBu8; 16]);
        assert!(state.advance().is_ok());
        assert_eq!(state.phase, DeviceRemovalPhase::Evacuate);
        assert!(state.advance().is_ok());
        assert_eq!(state.phase, DeviceRemovalPhase::Verify);
        assert!(state.advance().is_ok());
        assert_eq!(state.phase, DeviceRemovalPhase::Commit);
        assert!(state.advance().is_ok());
        assert_eq!(state.phase, DeviceRemovalPhase::Complete);
    }

    #[test]
    fn advance_from_terminal_returns_error() {
        let mut state = DeviceRemovalState::new(PathBuf::from("/dev/disk0"), [0xCCu8; 16]);
        state.phase = DeviceRemovalPhase::Complete;
        let result = state.advance();
        assert!(result.is_err());
    }

    #[test]
    fn advance_from_failed_returns_error() {
        let mut state = DeviceRemovalState::new(PathBuf::from("/dev/disk0"), [0xDDu8; 16]);
        state.phase = DeviceRemovalPhase::Failed;
        let result = state.advance();
        assert!(result.is_err());
    }

    #[test]
    fn fail_sets_phase_and_error() {
        let mut state = DeviceRemovalState::new(PathBuf::from("/dev/disk0"), [0xEEu8; 16]);
        state.fail("allocation quiesce timed out");
        assert_eq!(state.phase, DeviceRemovalPhase::Failed);
        assert_eq!(state.error.as_deref(), Some("allocation quiesce timed out"));
    }

    // ---------- State machine: run_device_removal integration ----------

    #[test]
    fn full_removal_pipeline_succeeds() {
        let tree = make_pool_data(vec![
            make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024),
            make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024),
        ]);
        let placements = vec![
            make_object(100, "/dev/disk0", 4096),
            make_object(101, "/dev/disk0", 8192),
        ];
        let intent = ReplicationIntent::new_mirror(1, FailureDomain::Device).unwrap();

        let mut state = DeviceRemovalState::new(PathBuf::from("/dev/disk0"), [0x01u8; 16]);

        let mut hooks = NoopDeviceRemovalHooks;

        let mut store: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        store.insert(100, vec![1u8; 4096]);
        store.insert(101, vec![2u8; 8192]);

        let result = run_device_removal(
            &mut state,
            &mut hooks,
            DeviceRemovalRun {
                device_tree: &tree,
                object_placements: &placements,
                intent,
                topology_generation: 1,
            },
            |id| {
                store
                    .get(&id)
                    .cloned()
                    .ok_or(DeviceRemovalError::NoObjectsOnDevice)
            },
            |_id, _data, _target| Ok(()),
            |_| true,
        );

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.objects_evacuated, 2);
        assert_eq!(result.objects_failed, 0);
        assert_eq!(state.phase, DeviceRemovalPhase::Complete);
        assert!(state.error.is_none());
    }

    #[test]
    fn removal_pipeline_quiesce_fails() {
        let tree = make_pool_data(vec![
            make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024),
            make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024),
        ]);
        let placements = vec![make_object(100, "/dev/disk0", 4096)];
        let intent = ReplicationIntent::new_mirror(1, FailureDomain::Device).unwrap();

        struct FailingQuiesceHooks;
        impl DeviceRemovalHooks for FailingQuiesceHooks {
            fn quiesce_device(
                &mut self,
                _state: &mut DeviceRemovalState,
            ) -> Result<(), DeviceRemovalError> {
                Err(DeviceRemovalError::DomainConstraintViolation {
                    details: "device is sole holder of critical metadata".into(),
                })
            }
        }

        let mut state = DeviceRemovalState::new(PathBuf::from("/dev/disk0"), [0x01u8; 16]);
        let mut hooks = FailingQuiesceHooks;

        let result = run_device_removal(
            &mut state,
            &mut hooks,
            DeviceRemovalRun {
                device_tree: &tree,
                object_placements: &placements,
                intent,
                topology_generation: 1,
            },
            |_id| Err(DeviceRemovalError::NoObjectsOnDevice),
            |_id, _data, _target| Ok(()),
            |_| false,
        );

        assert!(result.is_err());
    }

    #[test]
    fn removal_pipeline_verify_fails() {
        let tree = make_pool_data(vec![
            make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024),
            make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024),
        ]);
        let placements = vec![make_object(100, "/dev/disk0", 4096)];
        let intent = ReplicationIntent::new_mirror(1, FailureDomain::Device).unwrap();

        struct FailingVerifyHooks;
        impl DeviceRemovalHooks for FailingVerifyHooks {
            fn verify_empty(
                &mut self,
                _state: &mut DeviceRemovalState,
            ) -> Result<(), DeviceRemovalError> {
                Err(DeviceRemovalError::DomainConstraintViolation {
                    details: "3 objects remain on departing device".into(),
                })
            }
        }

        let mut state = DeviceRemovalState::new(PathBuf::from("/dev/disk0"), [0x01u8; 16]);
        let mut hooks = FailingVerifyHooks;

        let mut store: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        store.insert(100, vec![1u8; 4096]);

        let result = run_device_removal(
            &mut state,
            &mut hooks,
            DeviceRemovalRun {
                device_tree: &tree,
                object_placements: &placements,
                intent,
                topology_generation: 1,
            },
            |id| {
                store
                    .get(&id)
                    .cloned()
                    .ok_or(DeviceRemovalError::NoObjectsOnDevice)
            },
            |_id, _data, _target| Ok(()),
            |_| true,
        );

        assert!(result.is_err());
    }

    #[test]
    fn removal_pipeline_commit_fails() {
        let tree = make_pool_data(vec![
            make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024),
            make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024),
        ]);
        let placements = vec![make_object(100, "/dev/disk0", 4096)];
        let intent = ReplicationIntent::new_mirror(1, FailureDomain::Device).unwrap();

        struct FailingCommitHooks;
        impl DeviceRemovalHooks for FailingCommitHooks {
            fn commit_removal(
                &mut self,
                _state: &mut DeviceRemovalState,
                _result: &DeviceRemovalResult,
            ) -> Result<(), DeviceRemovalError> {
                Err(DeviceRemovalError::DomainConstraintViolation {
                    details: "pool label write failed".into(),
                })
            }
        }

        let mut state = DeviceRemovalState::new(PathBuf::from("/dev/disk0"), [0x01u8; 16]);
        let mut hooks = FailingCommitHooks;

        let mut store: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        store.insert(100, vec![1u8; 4096]);

        let result = run_device_removal(
            &mut state,
            &mut hooks,
            DeviceRemovalRun {
                device_tree: &tree,
                object_placements: &placements,
                intent,
                topology_generation: 1,
            },
            |id| {
                store
                    .get(&id)
                    .cloned()
                    .ok_or(DeviceRemovalError::NoObjectsOnDevice)
            },
            |_id, _data, _target| Ok(()),
            |_| true,
        );

        assert!(result.is_err());
    }

    #[test]
    fn removal_pipeline_no_objects_on_device_is_empty_success() {
        let tree = make_pool_data(vec![
            make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024),
            make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024),
        ]);
        // No objects on /dev/disk0.
        let placements = vec![make_object(200, "/dev/disk1", 4096)];
        let intent = ReplicationIntent::new_mirror(1, FailureDomain::Device).unwrap();

        let mut state = DeviceRemovalState::new(PathBuf::from("/dev/disk0"), [0x01u8; 16]);
        let mut hooks = NoopDeviceRemovalHooks;

        let result = run_device_removal(
            &mut state,
            &mut hooks,
            DeviceRemovalRun {
                device_tree: &tree,
                object_placements: &placements,
                intent,
                topology_generation: 1,
            },
            |_id| Err(DeviceRemovalError::NoObjectsOnDevice),
            |_id, _data, _target| Ok(()),
            |_| true,
        );

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.objects_evacuated, 0);
        assert_eq!(result.objects_failed, 0);
        assert_eq!(state.phase, DeviceRemovalPhase::Complete);
    }

    #[test]
    #[should_panic(expected = "run_device_removal called on terminal phase")]
    fn run_from_terminal_phase_panics() {
        let tree = make_pool_data(vec![
            make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024),
            make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024),
        ]);
        let placements = vec![];
        let intent = ReplicationIntent::new_mirror(2, FailureDomain::Device).unwrap();

        let mut state = DeviceRemovalState::new(PathBuf::from("/dev/disk0"), [0x01u8; 16]);
        state.phase = DeviceRemovalPhase::Complete;
        let mut hooks = NoopDeviceRemovalHooks;

        let _ = run_device_removal(
            &mut state,
            &mut hooks,
            DeviceRemovalRun {
                device_tree: &tree,
                object_placements: &placements,
                intent,
                topology_generation: 1,
            },
            |_id| Ok(vec![]),
            |_id, _data, _target| Ok(()),
            |_| false,
        );
    }

    // ---------- Serde roundtrip for phase and state ----------

    #[test]
    fn serde_phase_roundtrip() {
        for phase in &[
            DeviceRemovalPhase::Quiesce,
            DeviceRemovalPhase::Evacuate,
            DeviceRemovalPhase::Verify,
            DeviceRemovalPhase::Commit,
            DeviceRemovalPhase::Complete,
            DeviceRemovalPhase::Failed,
        ] {
            let json = serde_json::to_string(phase).expect("serialize");
            let round: DeviceRemovalPhase = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*phase, round);
        }
    }

    // ── Redundancy check tests ─────────────────────────────────────

    fn make_parity_raid(paths: &[&str], parity_count: u8) -> crate::DeviceType {
        let children: Vec<crate::DeviceType> = paths
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let mut guid = [0u8; 16];
                guid[0] = i as u8;
                crate::DeviceType::Leaf {
                    device_path: PathBuf::from(*p),
                    device_guid: guid,
                    device_index: i as u32,
                    capacity_bytes: 1024 * 1024 * 1024,
                    device_class: tidefs_types_pool_label_core::DeviceClass::Hdd,
                    health: crate::DeviceHealth::Online,
                    read_errors: 0,
                    write_errors: 0,
                    checksum_errors: 0,
                }
            })
            .collect();
        crate::DeviceType::ParityRaid {
            parity: parity_count,
            children,
        }
    }

    #[test]
    fn remove_pool_data_member_two_to_one_allowed() {
        let tree = make_pool_data(vec![
            make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024),
            make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024),
        ]);
        let result = check_removal_redundancy(&tree, Path::new("/dev/disk0"));
        assert!(result.is_ok(), "2-member pool data set can lose one member");
    }

    #[test]
    fn remove_legacy_parity_member_uses_pool_wide_rule() {
        let tree = make_parity_raid(&["/dev/disk0", "/dev/disk1", "/dev/disk2"], 1);
        let result = check_removal_redundancy(&tree, Path::new("/dev/disk0"));
        assert!(result.is_ok());
    }

    #[test]
    fn remove_legacy_two_parity_member_uses_pool_wide_rule() {
        let tree = make_parity_raid(
            &[
                "/dev/disk0",
                "/dev/disk1",
                "/dev/disk2",
                "/dev/disk3",
                "/dev/disk4",
            ],
            2,
        );
        let result = check_removal_redundancy(&tree, Path::new("/dev/disk2"));
        assert!(result.is_ok());
    }

    #[test]
    fn remove_with_insufficient_redundancy_last_pool_data_member() {
        let tree = make_pool_data(vec![make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024)]);
        let result = check_removal_redundancy(&tree, Path::new("/dev/disk0"));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DeviceRemovalError::WouldEmptyPool
        ));
    }

    #[test]
    fn remove_device_not_in_tree_by_redundancy_check() {
        let tree = make_pool_data(vec![
            make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024),
            make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024),
        ]);
        let result = check_removal_redundancy(&tree, Path::new("/dev/nonexistent"));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DeviceRemovalError::TargetDeviceNotFound { .. }
        ));
    }

    // ── VdevRemoveStats tests ───────────────────────────────────────

    #[test]
    fn vdev_remove_stats_new_defaults() {
        let stats = VdevRemoveStats::new(PathBuf::from("/dev/disk0"));
        assert_eq!(stats.device_path, PathBuf::from("/dev/disk0"));
        assert_eq!(stats.bytes_evacuated, 0);
        assert_eq!(stats.evacuation_time_ms, 0);
        assert!(!stats.removal_success);
    }

    #[test]
    fn vdev_remove_stats_mark_success() {
        let mut stats = VdevRemoveStats::new(PathBuf::from("/dev/disk1"));
        stats.mark_success(4096, 150);
        assert_eq!(stats.bytes_evacuated, 4096);
        assert_eq!(stats.evacuation_time_ms, 150);
        assert!(stats.removal_success);
    }

    #[test]
    fn vdev_remove_stats_mark_failed() {
        let mut stats = VdevRemoveStats::new(PathBuf::from("/dev/disk2"));
        stats.mark_success(1024, 50);
        assert!(stats.removal_success);
        stats.mark_failed();
        assert!(!stats.removal_success);
        // bytes/time preserved even on failure
        assert_eq!(stats.bytes_evacuated, 1024);
        assert_eq!(stats.evacuation_time_ms, 50);
    }

    #[test]
    fn evacuation_progress_tracking() {
        // Simulate a staged evacuation: evacuate 3 objects, track progress.
        let mut stats = VdevRemoveStats::new(PathBuf::from("/dev/disk0"));
        let total_bytes: u64 = 1000 + 2000 + 3000;
        let mut evacuated: u64 = 0;

        // Object 1: 1000 bytes
        evacuated += 1000;
        let bytes_remaining = total_bytes - evacuated;
        assert_eq!(bytes_remaining, 5000);
        assert_eq!(evacuated, 1000);

        // Object 2: 2000 bytes
        evacuated += 2000;
        let bytes_remaining = total_bytes - evacuated;
        assert_eq!(bytes_remaining, 3000);

        // Object 3: 3000 bytes — all done
        evacuated += 3000;
        let bytes_remaining = total_bytes - evacuated;
        assert_eq!(bytes_remaining, 0);

        stats.mark_success(evacuated, 300);
        assert_eq!(stats.bytes_evacuated, 6000);
        assert!(stats.removal_success);
    }

    #[test]
    fn vdev_remove_stats_clone_and_eq() {
        let stats = VdevRemoveStats {
            device_path: PathBuf::from("/dev/disk0"),
            bytes_evacuated: 8192,
            evacuation_time_ms: 200,
            removal_success: true,
        };
        let cloned = stats.clone();
        assert_eq!(stats, cloned);
        assert_eq!(cloned.bytes_evacuated, 8192);
    }

    // ── InsufficientRedundancy error display test ──────────────────

    #[test]
    fn insufficient_redundancy_error_display() {
        let err = DeviceRemovalError::InsufficientRedundancy {
            details: "pool-wide policy would not have enough surviving receipts".into(),
        };
        let displayed = format!("{err}");
        assert!(displayed.contains("insufficient redundancy"));
        assert!(displayed.contains("pool-wide policy"));
    }

    #[test]
    fn serde_state_roundtrip() {
        let state = DeviceRemovalState {
            phase: DeviceRemovalPhase::Evacuate,
            target_device: PathBuf::from("/dev/disk0"),
            target_device_guid: [0x42u8; 16],
            objects_evacuated: 5,
            objects_failed: 1,
            error: Some("transient I/O error on disk1".into()),
            failure_evidence: None,
        };
        let json = serde_json::to_string(&state).expect("serialize");
        let round: DeviceRemovalState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(state, round);
    }

    // ── PoolConfig::remove_device integration with redundancy ──────

    #[test]
    fn poolconfig_remove_device_updates_legacy_parity_tree_by_member_rule() {
        let tree = make_parity_raid(&["/dev/disk0", "/dev/disk1", "/dev/disk2"], 1);
        let mut config = crate::PoolConfig {
            pool_uuid: [0xAAu8; 16],
            pool_name: "test".to_string(),
            redundancy_policy: tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(1),
            device_tree: tree,
            health: crate::DeviceHealth::Online,
            state: tidefs_types_pool_label_core::PoolState::Active,
            total_capacity_bytes: 3 * 1024 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 1,
            device_count: 3,
            missing_indices: vec![],
            removing_device_indices: vec![],
        };
        let result = config.remove_device(Path::new("/dev/disk0"));
        assert!(result.is_ok());
        assert_eq!(config.device_count, 2);
        assert_eq!(config.topology_generation, 2);
    }
}

// Per-device object enumeration helpers
// ---------------------------------------------------------------------------

/// Maps each device path to its resident objects and their sizes.
///
/// Built by the low-level store after per-device key enumeration and
/// consumed by [`DeviceRemovalPlanner::plan_removal`] to compute an
/// evacuation plan.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeviceObjectMap {
    /// Per-device object lists, keyed by device path.
    pub devices: std::collections::BTreeMap<PathBuf, Vec<ObjectPlacement>>,
}

impl DeviceObjectMap {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self {
            devices: std::collections::BTreeMap::new(),
        }
    }

    /// Total number of objects across all devices.
    #[must_use]
    pub fn total_objects(&self) -> usize {
        self.devices.values().map(|v| v.len()).sum()
    }

    /// Total bytes across all objects.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.devices
            .values()
            .flat_map(|v| v.iter())
            .map(|p| p.size_bytes)
            .sum()
    }

    /// Insert a list of object placements for a device.
    pub fn insert_device(&mut self, device_path: PathBuf, placements: Vec<ObjectPlacement>) {
        self.devices.insert(device_path, placements);
    }

    /// Get objects resident on a specific device.
    #[must_use]
    pub fn objects_on_device(&self, device_path: &Path) -> Vec<&ObjectPlacement> {
        self.devices
            .get(device_path)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Flatten all object placements into a single list.
    #[must_use]
    pub fn all_placements(&self) -> Vec<ObjectPlacement> {
        self.devices
            .values()
            .flat_map(|v| v.iter().cloned())
            .collect()
    }

    /// Filter to objects on a specific device, returning owned placements.
    #[must_use]
    pub fn filter_by_device(&self, device_path: &Path) -> Vec<ObjectPlacement> {
        self.objects_on_device(device_path)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Returns `true` if any device has objects that must be evacuated.
    #[must_use]
    pub fn has_objects(&self, device_path: &Path) -> bool {
        self.devices.get(device_path).is_some_and(|v| !v.is_empty())
    }

    /// Remove all entries for a device after successful evacuation.
    pub fn clear_device(&mut self, device_path: &Path) {
        self.devices.remove(device_path);
    }

    /// Merge another `DeviceObjectMap` into this one, adding objects
    /// to the appropriate device lists.
    pub fn merge(&mut self, other: &DeviceObjectMap) {
        for (path, placements) in &other.devices {
            self.devices
                .entry(path.clone())
                .or_default()
                .extend(placements.iter().cloned());
        }
    }
}

/// Build a flat `Vec<ObjectPlacement>` from per-device object lists.
///
/// This bridges the gap between low-level per-device enumeration (e.g.
/// `LocalObjectStore::list_keys()` on each device) and the high-level
/// `DeviceRemovalPlanner::plan_removal()` which accepts a flat list.
///
/// Each entry in `device_objects` maps a device path to tuples of
/// `(object_id, size_bytes)`.
#[must_use]
pub fn build_object_placements(
    device_objects: &std::collections::BTreeMap<PathBuf, Vec<(u64, u64)>>,
) -> Vec<ObjectPlacement> {
    let mut out = Vec::new();
    for (device_path, objects) in device_objects {
        for &(object_id, size_bytes) in objects {
            out.push(ObjectPlacement::new(
                object_id,
                device_path.clone(),
                size_bytes,
            ));
        }
    }
    out
}

#[cfg(test)]
mod enumeration_tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn device_object_map_filter_and_merge() {
        let mut map = DeviceObjectMap::new();
        let disk0 = PathBuf::from("/dev/disk0");
        let disk1 = PathBuf::from("/dev/disk1");

        map.insert_device(
            disk0.clone(),
            vec![
                ObjectPlacement::new(1, disk0.clone(), 4096),
                ObjectPlacement::new(2, disk0.clone(), 8192),
            ],
        );
        map.insert_device(
            disk1.clone(),
            vec![ObjectPlacement::new(3, disk1.clone(), 16384)],
        );

        assert_eq!(map.total_objects(), 3);
        assert_eq!(map.total_bytes(), 4096 + 8192 + 16384);
        assert!(map.has_objects(&disk0));
        assert_eq!(map.filter_by_device(&disk0).len(), 2);
        assert_eq!(map.all_placements().len(), 3);

        // Merge another map.
        let mut map2 = DeviceObjectMap::new();
        map2.insert_device(
            disk0.clone(),
            vec![ObjectPlacement::new(4, disk0.clone(), 4096)],
        );
        map.merge(&map2);
        assert_eq!(map.filter_by_device(&disk0).len(), 3);

        // Clear a device.
        map.clear_device(&disk0);
        assert!(!map.has_objects(&disk0));
        assert_eq!(map.total_objects(), 1);
    }

    #[test]
    fn build_placements_from_device_map() {
        let mut device_objects = BTreeMap::new();
        device_objects.insert(PathBuf::from("/dev/disk0"), vec![(100, 4096), (101, 8192)]);
        device_objects.insert(PathBuf::from("/dev/disk1"), vec![(200, 16384)]);

        let placements = build_object_placements(&device_objects);
        assert_eq!(placements.len(), 3);
        assert!(placements.iter().any(|p| p.object_id == 100));
        assert!(placements.iter().any(|p| p.object_id == 200));
    }

    #[test]
    fn device_object_map_empty() {
        let map = DeviceObjectMap::new();
        assert_eq!(map.total_objects(), 0);
        assert_eq!(map.total_bytes(), 0);
        assert!(!map.has_objects(&PathBuf::from("/dev/disk0")));
        assert!(map.all_placements().is_empty());
    }
}
