// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Reconstruction planning with durability-layout constraint satisfaction
//! and failure-domain separation.
//!
//! The `plan_reconstruction()` function is the core algorithm: given a
//! durability layout, membership health state, failed node/device IDs,
//! current object placement, and already-in-flight rebuild objects, it
//! computes a deterministic, priority-ordered [`RebuildPlan`].

use std::collections::{BTreeMap, BTreeSet};

use tidefs_durability_layout::{DurabilityLayoutV1, DurabilityPolicy};
use tidefs_membership_epoch::{DomainId, HealthClass, MemberId};
use tidefs_replication_model::PlacementReceiptRef;

use crate::plan::{RebuildPlan, ReconstructionTask, ReconstructionTaskReceiptError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptBackedObjectPlacement {
    placement_receipt_ref: PlacementReceiptRef,
    members: BTreeSet<MemberId>,
}

impl ReceiptBackedObjectPlacement {
    pub fn new(
        placement_receipt_ref: PlacementReceiptRef,
        members: BTreeSet<MemberId>,
    ) -> Result<Self, ReconstructionTaskReceiptError> {
        ReconstructionTask::validate_receipt_ref(placement_receipt_ref)?;
        Ok(Self {
            placement_receipt_ref,
            members,
        })
    }

    #[must_use]
    pub fn placement_receipt_ref(&self) -> PlacementReceiptRef {
        self.placement_receipt_ref
    }

    #[must_use]
    pub fn members(&self) -> &BTreeSet<MemberId> {
        &self.members
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconstructionPlanningError {
    ReceiptObjectIdMismatch {
        object_id: u64,
        receipt_object_id: u64,
    },
    InvalidPlacementReceipt {
        object_id: u64,
        reason: ReconstructionTaskReceiptError,
    },
}

/// Input for reconstruction planning.
#[derive(Clone, Debug)]
pub struct ReconstructionInput {
    /// The durability layout defining minimum replicas per object.
    pub layout: DurabilityLayoutV1,
    /// Available member health: maps MemberId -> HealthClass.
    pub member_health: BTreeMap<MemberId, HealthClass>,
    /// Failed node IDs (these nodes are lost and cannot serve).
    pub failed_nodes: BTreeSet<MemberId>,
    /// Failed device count (local device failures).
    pub failed_device_count: u32,
    /// Current receipt-backed placement: object_id -> members holding it.
    pub object_placement: BTreeMap<u64, ReceiptBackedObjectPlacement>,
    /// In-flight rebuild object IDs (already being rebuilt, skip).
    pub in_flight_objects: BTreeSet<u64>,
    /// Failure-domain map: MemberId -> DomainId.
    pub failure_domains: BTreeMap<MemberId, DomainId>,
    /// Monotonic plan ID for the resulting plan.
    pub plan_id: u64,
    /// Current time in nanoseconds since epoch.
    pub now_ns: u64,
}

/// Compute a reconstruction plan from the given input.
///
/// # Algorithm
///
/// 1. Determine the minimum healthy replica count from the durability layout.
/// 2. For each object in placement:
///    - Count healthy replicas (member is healthy and not failed).
///    - If healthy replicas < minimum, object needs reconstruction.
///    - Skip objects already in `in_flight_objects`.
/// 3. For each object needing reconstruction:
///    - Source nodes: healthy members currently holding the object.
///    - Target nodes: healthy members not holding the object,
///      with failure-domain separation where possible.
/// 4. Assign priority: fewer healthy replicas = higher priority (lower u8).
/// 5. Sort tasks by priority, then by object_id for determinism.
/// 6. Return a [`RebuildPlan`] (caller can seal for BLAKE3 integrity).
pub fn plan_reconstruction(
    input: &ReconstructionInput,
) -> Result<RebuildPlan, ReconstructionPlanningError> {
    let min_replicas = minimum_replicas(&input.layout);
    let mut tasks: Vec<ReconstructionTask> = Vec::new();

    // Collect healthy, non-failed members
    let healthy_members: BTreeSet<MemberId> = input
        .member_health
        .iter()
        .filter(|(_, h)| matches!(h, HealthClass::Healthy))
        .map(|(m, _)| *m)
        .filter(|m| !input.failed_nodes.contains(m))
        .collect();

    for (&object_id, placement) in &input.object_placement {
        let placement_receipt_ref = placement.placement_receipt_ref();
        validate_receipt_for_object(object_id, placement_receipt_ref)?;
        let members = placement.members();

        // Skip objects already being rebuilt elsewhere
        if input.in_flight_objects.contains(&object_id) {
            continue;
        }

        // Count healthy replicas
        let healthy_count = members
            .iter()
            .filter(|m| healthy_members.contains(m))
            .count() as u32;

        if healthy_count >= min_replicas {
            continue; // Sufficient redundancy
        }

        // Source nodes: healthy members that hold this object
        let sources: Vec<u64> = members
            .iter()
            .filter(|m| healthy_members.contains(m))
            .map(|m| m.0)
            .collect();

        let needed = (min_replicas - healthy_count) as usize;

        // Target nodes: healthy members not holding this object,
        // with failure-domain separation
        let targets = select_targets_with_failure_domain_separation(
            members,
            &healthy_members,
            &input.failure_domains,
            needed,
        );

        // Priority: fewer healthy replicas = more urgent
        let priority = (healthy_count).min(255) as u8;

        tasks.push(
            ReconstructionTask::new_full_with_receipt(
                placement_receipt_ref,
                sources,
                targets,
                priority,
            )
            .map_err(|reason| {
                ReconstructionPlanningError::InvalidPlacementReceipt { object_id, reason }
            })?,
        );
    }

    // Sort deterministically: by priority (ascending), then by object_id
    tasks.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| a.object_id().cmp(&b.object_id()))
    });

    Ok(RebuildPlan::new(input.plan_id, tasks, input.now_ns))
}

fn validate_receipt_for_object(
    object_id: u64,
    placement_receipt_ref: PlacementReceiptRef,
) -> Result<(), ReconstructionPlanningError> {
    if placement_receipt_ref.object_id != object_id {
        return Err(ReconstructionPlanningError::ReceiptObjectIdMismatch {
            object_id,
            receipt_object_id: placement_receipt_ref.object_id,
        });
    }
    ReconstructionTask::validate_receipt_ref(placement_receipt_ref).map_err(|reason| {
        ReconstructionPlanningError::InvalidPlacementReceipt { object_id, reason }
    })
}

/// Select target nodes with failure-domain separation.
///
/// Prefers candidates from failure domains that do not already contain
/// a replica of this object. Falls back to same-domain candidates when
/// cross-domain candidates are exhausted.
fn select_targets_with_failure_domain_separation(
    current_holders: &BTreeSet<MemberId>,
    healthy_members: &BTreeSet<MemberId>,
    failure_domains: &BTreeMap<MemberId, DomainId>,
    needed: usize,
) -> Vec<u64> {
    if needed == 0 {
        return vec![];
    }

    // Candidates: healthy members that don't currently hold this object
    let mut candidates: Vec<MemberId> = healthy_members
        .difference(current_holders)
        .copied()
        .collect();

    // Domains already occupied by current holders
    let occupied_domains: BTreeSet<DomainId> = current_holders
        .iter()
        .filter_map(|m| failure_domains.get(m).copied())
        .collect();

    // Sort candidates: cross-domain first, same-domain after
    candidates.sort_by_key(|m| {
        let cross_domain = failure_domains
            .get(m)
            .is_none_or(|d| !occupied_domains.contains(d));
        if cross_domain {
            0u8
        } else {
            1u8
        }
    });

    let mut selected: Vec<u64> = Vec::new();
    let mut used_domains: BTreeSet<DomainId> = occupied_domains.clone();

    // First pass: prefer domain-separated candidates
    for &m in &candidates {
        if selected.len() >= needed {
            break;
        }
        let domain = failure_domains.get(&m).copied();
        if domain.is_none_or(|d| !used_domains.contains(&d)) {
            selected.push(m.0);
            if let Some(d) = domain {
                used_domains.insert(d);
            }
        }
    }

    // Second pass: fill remaining slots with any candidate
    if selected.len() < needed {
        for &m in &candidates {
            if selected.len() >= needed {
                break;
            }
            if !selected.contains(&m.0) {
                selected.push(m.0);
            }
        }
    }

    selected
}

/// Minimum number of healthy replicas required by a durability layout.
///
/// - Mirror{N}: N copies
/// - ErasureStyle{k,m}: k data shards
/// - Hybrid{mirror_copies, data_shards, _}: mirror_copies * data_shards
#[must_use]
pub fn minimum_replicas(layout: &DurabilityLayoutV1) -> u32 {
    match &layout.policy {
        DurabilityPolicy::Mirror { copies } => *copies as u32,
        DurabilityPolicy::ErasureStyle { data_shards, .. } => *data_shards as u32,
        DurabilityPolicy::Hybrid {
            data_shards,
            mirror_copies,
            ..
        } => (*mirror_copies as u32).max(1) * (*data_shards as u32),
    }
}

/// Target total replica count for a durability layout.
///
/// - Mirror{N}: N
/// - ErasureStyle{k,m}: k + m
/// - Hybrid{m, k, p}: m*k + p
#[must_use]
pub fn target_replica_count(layout: &DurabilityLayoutV1) -> u32 {
    match &layout.policy {
        DurabilityPolicy::Mirror { copies } => *copies as u32,
        DurabilityPolicy::ErasureStyle {
            data_shards,
            parity_shards,
        } => (*data_shards + *parity_shards) as u32,
        DurabilityPolicy::Hybrid {
            mirror_copies,
            data_shards,
            parity_shards,
        } => (*mirror_copies as u32) * (*data_shards as u32) + (*parity_shards as u32),
    }
}

#[cfg(test)]
mod tests;
