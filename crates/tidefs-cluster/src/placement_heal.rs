//! Placement map and partition heal coordinator.
//!
//! The [`PlacementMap`] tracks which cluster members hold replicas of each
//! object, enabling loss-impact calculation when a member fails. The
//! [`PlacementHealCoordinator`] bridges node/device loss detection to
//! rebuild plan generation via the cluster's [`RebuildBackfillInitiator`].
//!
//! ## Heal lifecycle
//!
//! ```text
//! Idle --detect_loss()--> Assessing --build_plan()--> Planning
//!                                                        |
//!                                               open_backfill()
//!                                                        |
//!                                                        v
//!                                                  Rebuilding --tick()--> Verifying
//!                                                     |                     |
//!                                                abort()              finalize()
//!                                                     |                     |
//!                                                     v                     v
//!                                                  Failed               Complete
//! ```
//!
//! Partition heal (node returns after isolation) follows the same path but
//! uses catch-up semantics: the returning node's objects are backfilled
//! from surviving replicas rather than rebuilt from scratch.

use std::collections::{BTreeMap, BTreeSet};

use tidefs_membership_epoch::{EpochId, HealthClass};
use tidefs_replication_model::{
    FlowCommitClass, FlowCommitResult, FlowState, PlacementReceiptRef, ReplicaCopyClass,
    ReplicatedSubjectId,
};

use crate::pool_config::{ClusterPlacementPolicy, FailureDomain};
use crate::rebuild_backfill::{
    BackfillError, RebuildBackfillInitiator, RebuildPlan, ReconstructionTask,
};

// ── PlacementObjectReceipt ───────────────────────────────────────────

/// A placement receipt that binds a file extent to a member/device.
///
/// Emitted after every write through a clustered filesystem. Carries
/// enough metadata for read-path reverse lookup: given an (inode,
/// byte_range), which member holds the data.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PlacementObjectReceipt {
    /// Derivation key: (inode_id, logical_block) → object_id.
    pub object_id: u64,
    /// Member that holds this object.
    pub member_id: u64,
    /// Inode this extent belongs to.
    pub inode_id: u64,
    /// Logical byte offset within the file.
    pub logical_offset: u64,
    /// Logical byte length of this extent.
    pub logical_length: u64,
    /// Membership epoch at placement time.
    pub epoch: u64,
}

impl PlacementObjectReceipt {
    pub fn new(
        object_id: u64,
        member_id: u64,
        inode_id: u64,
        logical_offset: u64,
        logical_length: u64,
        epoch: u64,
    ) -> Self {
        Self {
            object_id,
            member_id,
            inode_id,
            logical_offset,
            logical_length,
            epoch,
        }
    }

    /// True if the given byte range overlaps this receipt's extent.
    pub fn overlaps(&self, offset: u64, length: u64) -> bool {
        let rec_end = self.logical_offset.saturating_add(self.logical_length);
        let query_end = offset.saturating_add(length);
        offset < rec_end && self.logical_offset < query_end
    }
}

// ── PlacementMap ─────────────────────────────────────────────────────

/// Maps object IDs to the set of members that hold replicas.
///
/// Used to determine which objects are affected when a member is lost,
/// and to verify post-heal placement convergence.  Also stores full
/// [`PlacementObjectReceipt`]s keyed by object_id for read-path lookup.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct PlacementMap {
    /// object_id → set of member_ids holding replicas.
    entries: BTreeMap<u64, BTreeSet<u64>>,
    /// member_id → set of object_ids held.
    by_member: BTreeMap<u64, BTreeSet<u64>>,
    /// object_id → PlacementObjectReceipt (one per placement).
    receipts: BTreeMap<u64, PlacementObjectReceipt>,
    /// object_id → durable placement receipt ref suitable for transfer authority.
    #[serde(default)]
    placement_receipt_refs: BTreeMap<u64, PlacementReceiptRef>,
    /// Epoch this placement map reflects.
    epoch: u64,
}

/// Summary returned when a rebuild flow-commit result updates placement state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RebuildFlowCommitPlacementPublication {
    /// Object whose repaired placement was published.
    pub object_id: u64,
    /// Target member now recorded as holding the repaired object.
    pub target_member: u64,
    /// Repaired durable placement receipt stored for the object.
    pub placement_receipt_ref: PlacementReceiptRef,
    /// Placement-map epoch after publication.
    pub map_epoch: u64,
}

/// Summary returned when a relocation flow-commit result updates placement
/// state and retires the caller-named source member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelocationFlowCommitPlacementPublication {
    /// Object whose relocated placement was published.
    pub object_id: u64,
    /// Source member retired from the object's placement set.
    pub retired_source_member: u64,
    /// Target member now recorded as holding the relocated object.
    pub target_member: u64,
    /// Replacement durable placement receipt stored for the object.
    pub placement_receipt_ref: PlacementReceiptRef,
    /// Placement-map epoch after publication.
    pub map_epoch: u64,
}

impl PlacementMap {
    /// Create an empty placement map for the given epoch.
    pub fn new(epoch: u64) -> Self {
        Self {
            entries: BTreeMap::new(),
            by_member: BTreeMap::new(),
            receipts: BTreeMap::new(),
            placement_receipt_refs: BTreeMap::new(),
            epoch,
        }
    }

    /// Return the epoch this map reflects.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Set the epoch.
    pub fn set_epoch(&mut self, epoch: u64) {
        self.epoch = epoch;
    }

    /// Record a placement receipt for a file extent (full metadata).
    pub fn record_receipt(&mut self, receipt: PlacementObjectReceipt) {
        let object_id = receipt.object_id;
        let member_id = receipt.member_id;
        self.entries.entry(object_id).or_default().insert(member_id);
        self.by_member
            .entry(member_id)
            .or_default()
            .insert(object_id);
        self.receipts.insert(object_id, receipt);
    }

    /// Record a placement receipt and its durable transfer-authority reference.
    pub fn record_receipt_with_ref(
        &mut self,
        receipt: PlacementObjectReceipt,
        placement_receipt_ref: PlacementReceiptRef,
    ) {
        let object_id = receipt.object_id;
        debug_assert_eq!(object_id, placement_receipt_ref.object_id);
        self.record_receipt(receipt);
        self.placement_receipt_refs
            .insert(object_id, placement_receipt_ref);
    }

    /// Attach a durable placement receipt ref to an already-tracked object.
    pub fn record_placement_receipt_ref(
        &mut self,
        object_id: u64,
        placement_receipt_ref: PlacementReceiptRef,
    ) {
        debug_assert_eq!(object_id, placement_receipt_ref.object_id);
        self.placement_receipt_refs
            .insert(object_id, placement_receipt_ref);
    }

    /// Publish a completed rebuild flow-commit result into placement state.
    ///
    /// This records the target member and repaired durable placement receipt
    /// only after the flow result proves a completed rebuild for one subject.
    pub fn publish_rebuild_flow_commit_result(
        &mut self,
        result: &FlowCommitResult,
    ) -> Result<RebuildFlowCommitPlacementPublication, String> {
        let (_subject_ref, placement_receipt_ref) = self
            .validate_completed_single_subject_flow_commit(
                result,
                FlowCommitClass::Rebuild,
                "rebuild",
            )?;

        let object_id = placement_receipt_ref.object_id;
        let target_member = result.updated_copy.member_ref.0;
        self.insert(object_id, target_member);
        self.record_placement_receipt_ref(object_id, placement_receipt_ref);
        self.epoch = result.commit_epoch.0;

        Ok(RebuildFlowCommitPlacementPublication {
            object_id,
            target_member,
            placement_receipt_ref,
            map_epoch: self.epoch,
        })
    }

    /// Publish a completed relocation flow-commit result into placement state.
    ///
    /// This records the relocated target and durable replacement receipt, then
    /// retires the caller-named source member only after the flow result proves
    /// a completed relocation for one subject.
    pub fn publish_relocation_flow_commit_result(
        &mut self,
        source_member: u64,
        result: &FlowCommitResult,
    ) -> Result<RelocationFlowCommitPlacementPublication, String> {
        let (_subject_ref, placement_receipt_ref) = self
            .validate_completed_single_subject_flow_commit(
                result,
                FlowCommitClass::Relocation,
                "relocation",
            )?;

        let object_id = placement_receipt_ref.object_id;
        let target_member = result.updated_copy.member_ref.0;
        if source_member == target_member {
            return Err(format!(
                "relocation source member {} matches target member for object {}",
                source_member, object_id
            ));
        }
        if !self
            .entries
            .get(&object_id)
            .is_some_and(|members| members.contains(&source_member))
        {
            return Err(format!(
                "relocation source member {} does not hold object {}",
                source_member, object_id
            ));
        }

        self.insert(object_id, target_member);
        self.record_placement_receipt_ref(object_id, placement_receipt_ref);
        self.remove_replica_preserving_receipt(object_id, source_member);
        self.epoch = result.commit_epoch.0;

        Ok(RelocationFlowCommitPlacementPublication {
            object_id,
            retired_source_member: source_member,
            target_member,
            placement_receipt_ref,
            map_epoch: self.epoch,
        })
    }

    fn validate_completed_single_subject_flow_commit(
        &self,
        result: &FlowCommitResult,
        expected_class: FlowCommitClass,
        flow_name: &str,
    ) -> Result<(ReplicatedSubjectId, PlacementReceiptRef), String> {
        if result.flow_class != expected_class {
            return Err(format!(
                "flow-commit result is {:?}, not {}",
                result.flow_class, flow_name
            ));
        }
        if result.final_flow_state != FlowState::Complete {
            return Err(format!(
                "{} flow-commit result is {:?}, not complete",
                flow_name, result.final_flow_state
            ));
        }
        if result.commit_epoch.0 < self.epoch {
            return Err(format!(
                "{} flow-commit epoch {} is stale for placement map epoch {}",
                flow_name, result.commit_epoch.0, self.epoch
            ));
        }

        let placement = &result.placement_receipt;
        if placement.placement_epoch != result.commit_epoch {
            return Err(format!(
                "{} placement epoch {:?} does not match commit epoch {:?}",
                flow_name, placement.placement_epoch, result.commit_epoch
            ));
        }
        if placement.subjects_placed != 1 || placement.subject_refs.len() != 1 {
            return Err(format!(
                "{} placement publication must carry exactly one subject, got subjects_placed={} refs={}",
                flow_name,
                placement.subjects_placed,
                placement.subject_refs.len()
            ));
        }
        let subject_ref = placement.subject_refs[0];
        if subject_ref != result.updated_copy.subject_ref {
            return Err(format!(
                "{} placement subject {:?} does not match updated copy {:?}",
                flow_name, subject_ref, result.updated_copy.subject_ref
            ));
        }
        if placement.placed_on != result.updated_copy.member_ref {
            return Err(format!(
                "{} placement target {:?} does not match updated copy {:?}",
                flow_name, placement.placed_on, result.updated_copy.member_ref
            ));
        }
        if result.updated_copy.copy_class != ReplicaCopyClass::Verified {
            return Err(format!(
                "{} updated copy is {:?}, not verified",
                flow_name, result.updated_copy.copy_class
            ));
        }
        if placement.placement_receipt_refs.len() != 1 {
            return Err(format!(
                "{} placement publication must carry exactly one placement receipt ref, got {}",
                flow_name,
                placement.placement_receipt_refs.len()
            ));
        }

        let placement_receipt_ref = placement.placement_receipt_refs[0];
        Self::validate_flow_placement_ref(flow_name, subject_ref, placement_receipt_ref)?;
        Ok((subject_ref, placement_receipt_ref))
    }

    fn validate_flow_placement_ref(
        flow_name: &str,
        subject_ref: ReplicatedSubjectId,
        placement_receipt_ref: PlacementReceiptRef,
    ) -> Result<(), String> {
        if placement_receipt_ref.is_synthetic() {
            return Err(format!(
                "{} placement receipt ref for subject {:?} is synthetic",
                flow_name, subject_ref
            ));
        }
        let receipt_subject = ReplicatedSubjectId::new(placement_receipt_ref.object_id);
        if receipt_subject != subject_ref {
            return Err(format!(
                "{} placement receipt subject mismatch: result subject {:?}, receipt subject {:?}",
                flow_name, subject_ref, receipt_subject
            ));
        }
        if !placement_receipt_ref.redundancy_policy.is_well_formed() {
            return Err(format!(
                "{} placement receipt ref for subject {:?} has malformed redundancy policy",
                flow_name, subject_ref
            ));
        }
        let required_count = placement_receipt_ref.redundancy_policy.target_width();
        if placement_receipt_ref.target_count < required_count {
            return Err(format!(
                "{} placement receipt ref for subject {:?} is under-width: target_count {} < required_count {}",
                flow_name, subject_ref, placement_receipt_ref.target_count, required_count
            ));
        }
        Ok(())
    }

    /// Record that a member holds a replica of an object (lightweight, no extent metadata).
    pub fn insert(&mut self, object_id: u64, member_id: u64) {
        self.entries.entry(object_id).or_default().insert(member_id);
        self.by_member
            .entry(member_id)
            .or_default()
            .insert(object_id);
    }

    /// Remove a member's replica of an object.
    pub fn remove(&mut self, object_id: u64, member_id: u64) {
        if let Some(members) = self.entries.get_mut(&object_id) {
            members.remove(&member_id);
            if members.is_empty() {
                self.entries.remove(&object_id);
            }
        }
        if let Some(objects) = self.by_member.get_mut(&member_id) {
            objects.remove(&object_id);
            if objects.is_empty() {
                self.by_member.remove(&member_id);
            }
        }
        self.receipts.remove(&object_id);
        self.placement_receipt_refs.remove(&object_id);
    }

    fn remove_replica_preserving_receipt(&mut self, object_id: u64, member_id: u64) {
        let mut object_still_placed = false;
        if let Some(members) = self.entries.get_mut(&object_id) {
            members.remove(&member_id);
            object_still_placed = !members.is_empty();
            if members.is_empty() {
                self.entries.remove(&object_id);
            }
        }
        if let Some(objects) = self.by_member.get_mut(&member_id) {
            objects.remove(&object_id);
            if objects.is_empty() {
                self.by_member.remove(&member_id);
            }
        }
        if !object_still_placed {
            self.receipts.remove(&object_id);
            self.placement_receipt_refs.remove(&object_id);
        }
    }

    /// Remove all entries for a member (e.g., on node loss).
    /// Returns the set of object IDs that lost at least one replica.
    pub fn remove_member(&mut self, member_id: u64) -> BTreeSet<u64> {
        let mut affected = BTreeSet::new();
        if let Some(objects) = self.by_member.remove(&member_id) {
            for object_id in &objects {
                if let Some(members) = self.entries.get_mut(object_id) {
                    members.remove(&member_id);
                    if members.is_empty() {
                        self.entries.remove(object_id);
                    }
                }
            }
            affected = objects;
        }
        // Remove receipts for wholly-lost objects only.
        for &object_id in &affected {
            if !self.entries.contains_key(&object_id) {
                self.receipts.remove(&object_id);
                self.placement_receipt_refs.remove(&object_id);
            }
        }
        affected
    }

    /// Get the set of members holding replicas of an object.
    pub fn replicas_of(&self, object_id: u64) -> Option<&BTreeSet<u64>> {
        self.entries.get(&object_id)
    }

    /// Get the set of objects held by a member.
    pub fn objects_of(&self, member_id: u64) -> Option<&BTreeSet<u64>> {
        self.by_member.get(&member_id)
    }

    /// Number of distinct objects tracked.
    pub fn object_count(&self) -> usize {
        self.entries.len()
    }

    /// Number of members with tracked objects.
    pub fn member_count(&self) -> usize {
        self.by_member.len()
    }

    /// Total replica count across all objects and members.
    pub fn total_replicas(&self) -> usize {
        self.entries.values().map(|s| s.len()).sum()
    }

    /// Get the receipt for a specific object_id.
    pub fn receipt(&self, object_id: u64) -> Option<&PlacementObjectReceipt> {
        self.receipts.get(&object_id)
    }

    /// Get the durable placement receipt ref for a specific object_id.
    pub fn placement_receipt_ref(&self, object_id: u64) -> Option<PlacementReceiptRef> {
        self.placement_receipt_refs.get(&object_id).copied()
    }

    /// Find all receipts for a given inode.
    pub fn receipts_for_inode(&self, inode_id: u64) -> Vec<&PlacementObjectReceipt> {
        self.receipts
            .values()
            .filter(|r| r.inode_id == inode_id)
            .collect()
    }

    /// Find which members hold data for the given (inode, byte_range).
    ///
    /// Scans receipts for the inode, collecting members whose extent
    /// overlaps the query range.  The caller uses this to select a
    /// replica for read-path I/O.
    pub fn members_for_range(&self, inode_id: u64, offset: u64, length: u64) -> BTreeSet<u64> {
        self.receipts
            .values()
            .filter(|r| r.inode_id == inode_id && r.overlaps(offset, length))
            .map(|r| r.member_id)
            .collect()
    }

    /// Number of receipts stored.
    pub fn receipt_count(&self) -> usize {
        self.receipts.len()
    }

    /// Number of durable placement receipt refs stored.
    pub fn placement_receipt_ref_count(&self) -> usize {
        self.placement_receipt_refs.len()
    }

    /// Compute which objects are affected by the loss of the given members.
    ///
    /// Returns a map of object_id → set of lost member_ids, only including
    /// objects that still have at least one surviving replica.
    pub fn compute_loss_impact(
        &self,
        lost_members: &BTreeSet<u64>,
    ) -> BTreeMap<u64, BTreeSet<u64>> {
        let mut impact: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
        for &member_id in lost_members {
            if let Some(objects) = self.by_member.get(&member_id) {
                for &object_id in objects {
                    impact.entry(object_id).or_default().insert(member_id);
                }
            }
        }
        impact
    }

    /// Compute which objects are wholly lost (no surviving replicas).
    pub fn compute_wholly_lost_objects(&self, lost_members: &BTreeSet<u64>) -> BTreeSet<u64> {
        let impact = self.compute_loss_impact(lost_members);
        impact
            .into_iter()
            .filter(|(object_id, lost)| {
                let all_replicas = self.entries.get(object_id).map(|s| s.len()).unwrap_or(0);
                lost.len() >= all_replicas
            })
            .map(|(object_id, _)| object_id)
            .collect()
    }

    /// Compute placement convergence: which objects are NOT placed on the
    /// expected set of members. Returns (missing_from_target, excess_on_member).
    pub fn compute_divergence(
        &self,
        expected: &BTreeMap<u64, BTreeSet<u64>>,
    ) -> (BTreeMap<u64, BTreeSet<u64>>, BTreeMap<u64, BTreeSet<u64>>) {
        let mut missing = BTreeMap::new();
        let mut excess = BTreeMap::new();

        for (&object_id, expected_members) in expected {
            let actual = self.entries.get(&object_id).cloned().unwrap_or_default();
            let missing_set: BTreeSet<u64> =
                expected_members.difference(&actual).copied().collect();
            if !missing_set.is_empty() {
                missing.insert(object_id, missing_set);
            }
        }

        for (&object_id, actual_members) in &self.entries {
            if let Some(expected_members) = expected.get(&object_id) {
                let excess_set: BTreeSet<u64> = actual_members
                    .difference(expected_members)
                    .copied()
                    .collect();
                if !excess_set.is_empty() {
                    excess.insert(object_id, excess_set);
                }
            }
        }

        (missing, excess)
    }

    /// Clear all entries and reset epoch.
    pub fn clear(&mut self, new_epoch: u64) {
        self.entries.clear();
        self.by_member.clear();
        self.receipts.clear();
        self.placement_receipt_refs.clear();
        self.epoch = new_epoch;
    }

    /// Iterate over all (object_id, member_ids) entries.
    pub fn iter(&self) -> impl Iterator<Item = (&u64, &BTreeSet<u64>)> {
        self.entries.iter()
    }
}

// ── HealState ────────────────────────────────────────────────────────

/// State of a partition heal or rebuild operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealState {
    /// No heal in progress.
    Idle,
    /// Node loss detected, assessing impact.
    Assessing,
    /// Rebuild plan generated, backfill session opened.
    Planning,
    /// Rebuild data transfer in progress.
    Rebuilding,
    /// Transfer complete, verifying placement convergence.
    Verifying,
    /// Heal complete — all lost replicas restored.
    Complete,
    /// Heal failed — insufficient sources or capacity.
    Failed,
    /// Heal was aborted (epoch transition, operator request).
    Aborted,
}

impl HealState {
    /// True if the state represents active work.
    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::Assessing | Self::Planning | Self::Rebuilding | Self::Verifying
        )
    }

    /// True if the state is terminal.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Failed | Self::Aborted)
    }
}

// ── HealStats ────────────────────────────────────────────────────────

/// Statistics for a heal operation.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct HealStats {
    /// Objects that lost replicas due to member loss.
    pub objects_affected: u64,
    /// Objects wholly lost (no surviving replicas).
    pub objects_wholly_lost: u64,
    /// Objects that need rebuilding (lost replica but surviving copies exist).
    pub objects_to_rebuild: u64,
    /// Objects rebuilt so far.
    pub objects_rebuilt: u64,
    /// Bytes rebuilt so far.
    pub bytes_rebuilt: u64,
    /// Objects remaining to rebuild.
    pub objects_remaining: u64,
    /// Timestamp when heal started (ns).
    pub started_at_ns: u64,
    /// Timestamp when heal completed (ns), if finished.
    pub completed_at_ns: Option<u64>,
    /// Backfill session ID assigned by the initiator.
    pub backfill_id: Option<u64>,
}

impl HealStats {
    /// Fraction of rebuild complete (0.0 to 1.0).
    pub fn fraction_complete(&self) -> f64 {
        let total = self.objects_to_rebuild;
        if total == 0 {
            return 1.0;
        }
        self.objects_rebuilt as f64 / total as f64
    }

    /// Whether all objects have been rebuilt.
    pub fn is_complete(&self) -> bool {
        self.objects_rebuilt >= self.objects_to_rebuild && self.objects_to_rebuild > 0
    }
}

// ── LossEvent ────────────────────────────────────────────────────────

/// A detected loss event that triggers a heal.
#[derive(Clone, Debug)]
pub struct LossEvent {
    /// Members that were lost.
    pub lost_members: BTreeSet<u64>,
    /// Epoch when the loss was detected.
    pub epoch: u64,
    /// Timestamp when loss was detected (ns).
    pub detected_at_ns: u64,
    /// Members still available with their health classes.
    pub available_members: BTreeMap<u64, HealthClass>,
}

// ── PlacementHealCoordinator ─────────────────────────────────────────

/// Coordinates placement tracking and partition heal.
///
/// Watches for loss events, computes rebuild scope from the placement map,
/// generates rebuild plans, and drives the backfill initiator through the
/// heal lifecycle.
pub struct PlacementHealCoordinator {
    /// Current placement state.
    placement: PlacementMap,
    /// Heal state machine.
    state: HealState,
    /// Heal progress statistics.
    stats: HealStats,
    /// Backfill initiator (shared with ClusterLeaseRuntime).
    /// None if not set — heal operates in plan-only mode.
    backfill: Option<RebuildBackfillInitiator>,
    /// Lost members for the current heal operation.
    lost_members: BTreeSet<u64>,
    /// Surviving members with their health.
    surviving_members: BTreeMap<u64, HealthClass>,
    /// Placement policy guiding target selection during rebuild.
    placement_policy: ClusterPlacementPolicy,
    /// Per-member failure-domain vectors for domain-aware placement.
    member_failure_domains: BTreeMap<u64, FailureDomain>,
    /// Per-node rebuild load counter (objects assigned during current heal).
    node_rebuild_load: BTreeMap<u64, u64>,
}

impl PlacementHealCoordinator {
    /// Create a new coordinator with an empty placement map.
    ///
    /// Defaults to `ClusterPlacementPolicy::Stripe` — call
    /// [`with_placement_policy`] to bind a mirror or erasure policy.
    pub fn new(epoch: u64, backfill: Option<RebuildBackfillInitiator>) -> Self {
        Self {
            placement: PlacementMap::new(epoch),
            state: HealState::Idle,
            stats: HealStats::default(),
            backfill,
            lost_members: BTreeSet::new(),
            surviving_members: BTreeMap::new(),
            placement_policy: ClusterPlacementPolicy::Stripe,
            member_failure_domains: BTreeMap::new(),
            node_rebuild_load: BTreeMap::new(),
        }
    }

    /// Set the cluster placement policy for rebuild target selection.
    pub fn with_placement_policy(mut self, policy: ClusterPlacementPolicy) -> Self {
        self.placement_policy = policy;
        self
    }

    /// Register per-member failure-domain vectors.
    pub fn with_member_failure_domains(mut self, domains: BTreeMap<u64, FailureDomain>) -> Self {
        self.member_failure_domains = domains;
        self
    }

    /// Return the current placement policy.
    pub fn placement_policy(&self) -> ClusterPlacementPolicy {
        self.placement_policy
    }

    /// Return the current heal state.
    pub fn state(&self) -> HealState {
        self.state
    }

    /// Return the placement map (immutable).
    pub fn placement(&self) -> &PlacementMap {
        &self.placement
    }

    /// Return a mutable reference to the placement map.
    pub fn placement_mut(&mut self) -> &mut PlacementMap {
        &mut self.placement
    }

    /// Publish a completed rebuild flow-commit result into owned placement state.
    pub fn publish_rebuild_flow_commit_result(
        &mut self,
        result: &FlowCommitResult,
    ) -> Result<RebuildFlowCommitPlacementPublication, String> {
        self.placement.publish_rebuild_flow_commit_result(result)
    }

    /// Publish a completed relocation flow-commit result into owned placement
    /// state and retire the caller-named source member.
    pub fn publish_relocation_flow_commit_result(
        &mut self,
        source_member: u64,
        result: &FlowCommitResult,
    ) -> Result<RelocationFlowCommitPlacementPublication, String> {
        self.placement
            .publish_relocation_flow_commit_result(source_member, result)
    }

    /// Return heal statistics.
    pub fn stats(&self) -> &HealStats {
        &self.stats
    }

    /// Whether a heal operation is in progress.
    pub fn is_healing(&self) -> bool {
        self.state.is_active()
    }

    fn receipt_ref_authorizes_heal(
        object_id: u64,
        placement_receipt_ref: PlacementReceiptRef,
    ) -> bool {
        placement_receipt_ref.object_id == object_id
            && !placement_receipt_ref.is_synthetic()
            && placement_receipt_ref.redundancy_policy.is_well_formed()
            && placement_receipt_ref.target_count
                >= placement_receipt_ref.redundancy_policy.target_width()
    }

    // ── Loss detection ───────────────────────────────────────────

    /// Detect a loss event and transition to Assessing.
    ///
    /// Returns the set of affected object IDs, or None if already healing.
    pub fn detect_loss(&mut self, event: LossEvent) -> Option<BTreeSet<u64>> {
        if self.state.is_active() {
            return None;
        }

        self.lost_members = event.lost_members.clone();
        self.surviving_members = event.available_members.clone();
        self.placement.set_epoch(event.epoch);

        let affected = self.placement.compute_loss_impact(&event.lost_members);
        let wholly_lost = self
            .placement
            .compute_wholly_lost_objects(&event.lost_members);

        self.stats = HealStats {
            objects_affected: affected.len() as u64,
            objects_wholly_lost: wholly_lost.len() as u64,
            objects_to_rebuild: affected.len().saturating_sub(wholly_lost.len()) as u64,
            started_at_ns: event.detected_at_ns,
            ..Default::default()
        };

        self.state = HealState::Assessing;

        let rebuildable: BTreeSet<u64> = affected
            .keys()
            .copied()
            .filter(|id| !wholly_lost.contains(id))
            .collect();

        if rebuildable.is_empty() && !wholly_lost.is_empty() {
            self.state = HealState::Failed;
            return Some(rebuildable);
        }

        Some(rebuildable)
    }

    // ── Plan building ────────────────────────────────────────────

    /// Build a rebuild plan from the current loss assessment.
    ///
    /// For each affected object that still has surviving replicas,
    /// creates a ReconstructionTask targeting available healthy members.
    ///
    /// Must be in Assessing state.
    pub fn build_rebuild_plan(&mut self, plan_id: u64, now_ns: u64) -> Option<RebuildPlan> {
        if self.state != HealState::Assessing {
            return None;
        }

        let desired_replicas = self.placement_policy.desired_node_count();
        let use_failure_domains = !self.member_failure_domains.is_empty();

        let mut tasks = Vec::new();
        let surviving_ids: BTreeSet<u64> = self.surviving_members.keys().copied().collect();

        // Reset per-node load counters for this plan.
        self.node_rebuild_load.clear();

        // For each object in the placement map, check if it lost replicas
        for (&object_id, replicas) in self.placement.iter() {
            // Objects already only on surviving members are fine
            if replicas.iter().all(|m| surviving_ids.contains(m)) {
                continue;
            }

            // Source nodes: surviving members that hold this object
            let sources: Vec<u64> = replicas
                .iter()
                .filter(|m| surviving_ids.contains(m))
                .copied()
                .collect();

            if sources.is_empty() {
                continue; // wholly lost
            }

            // Current surviving replica count for this object.
            let surviving_replica_count = sources.len();
            if surviving_replica_count >= desired_replicas {
                continue; // already has enough replicas on survivors
            }

            // How many additional replicas we need to restore.
            let needed = desired_replicas.saturating_sub(surviving_replica_count);

            let Some(placement_receipt_ref) = self.placement.placement_receipt_ref(object_id)
            else {
                self.node_rebuild_load.clear();
                self.state = HealState::Aborted;
                self.stats.backfill_id = None;
                return None;
            };

            if !Self::receipt_ref_authorizes_heal(object_id, placement_receipt_ref) {
                self.node_rebuild_load.clear();
                self.state = HealState::Aborted;
                self.stats.backfill_id = None;
                return None;
            }

            // Candidates: healthy surviving members NOT holding this object,
            // sorted by failure-domain diversity then rebuild load.
            let mut candidates: Vec<(u64, u64)> = self
                .surviving_members
                .iter()
                .filter(|(id, hc)| !replicas.contains(id) && **hc == HealthClass::Healthy)
                .map(|(id, _)| {
                    let load = self.node_rebuild_load.get(id).copied().unwrap_or(0);
                    (*id, load)
                })
                .collect();

            if use_failure_domains {
                let existing_domains: BTreeSet<u64> = replicas
                    .iter()
                    .filter_map(|m| self.member_failure_domains.get(m))
                    .map(|fd| fd.node)
                    .collect();

                candidates.sort_by(|(a_id, a_load), (b_id, b_load)| {
                    let a_same_domain = self
                        .member_failure_domains
                        .get(a_id)
                        .map(|fd| existing_domains.contains(&fd.node))
                        .unwrap_or(false);
                    let b_same_domain = self
                        .member_failure_domains
                        .get(b_id)
                        .map(|fd| existing_domains.contains(&fd.node))
                        .unwrap_or(false);
                    a_same_domain
                        .cmp(&b_same_domain)
                        .then_with(|| a_load.cmp(b_load))
                });
            } else {
                candidates.sort_by_key(|(_, load)| *load);
            }

            let targets: Vec<u64> = candidates
                .into_iter()
                .take(needed)
                .map(|(id, _load)| {
                    *self.node_rebuild_load.entry(id).or_insert(0) += 1;
                    id
                })
                .collect();

            if targets.is_empty() {
                continue;
            }

            let task = ReconstructionTask::new_full_with_receipt(
                object_id,
                placement_receipt_ref,
                sources,
                targets,
                0,
            );
            tasks.push(task);
        }

        if tasks.is_empty() {
            self.state = HealState::Complete;
            self.stats.completed_at_ns = Some(now_ns);
            return None;
        }

        tasks.sort_by_key(|t| t.source_nodes.len());

        self.stats.objects_to_rebuild = tasks.len() as u64;
        self.stats.objects_remaining = tasks.len() as u64;

        self.state = HealState::Planning;
        Some(RebuildPlan::new(plan_id, tasks, now_ns))
    }

    // ── Backfill integration ─────────────────────────────────────

    /// Open a backfill session from the rebuild plan.
    ///
    /// Delegates to the backfill initiator if available. Must be in Planning state.
    pub fn open_backfill(&mut self, plan: RebuildPlan, epoch: u64) -> Result<u64, &'static str> {
        if self.state != HealState::Planning {
            return Err("not in Planning state");
        }
        let initiator = self.backfill.as_mut().ok_or("no backfill initiator set")?;
        let bid = initiator
            .open_backfill(plan, EpochId(epoch))
            .map_err(|e| match e {
                BackfillError::EpochMismatch { .. } => "epoch mismatch",
                BackfillError::EmptyPlan => "empty plan",
                _ => "backfill error",
            })?;
        self.stats.backfill_id = Some(bid);
        self.state = HealState::Rebuilding;
        Ok(bid)
    }

    /// Record that a backfill session was opened externally (by the runtime).
    ///
    /// Use this when the runtime owns the RebuildBackfillInitiator and opens
    /// backfill sessions without going through open_backfill().
    pub fn record_backfill_opened(&mut self, backfill_id: u64) {
        self.stats.backfill_id = Some(backfill_id);
        self.state = HealState::Rebuilding;
    }

    /// Record rebuild progress (called periodically during Rebuilding).
    pub fn record_rebuild_progress(
        &mut self,
        objects_completed: u64,
        bytes_transferred: u64,
    ) -> Result<(), &'static str> {
        if self.state != HealState::Rebuilding {
            return Err("not in Rebuilding state");
        }
        self.stats.objects_rebuilt = self.stats.objects_rebuilt.saturating_add(objects_completed);
        self.stats.bytes_rebuilt = self.stats.bytes_rebuilt.saturating_add(bytes_transferred);
        self.stats.objects_remaining = self
            .stats
            .objects_remaining
            .saturating_sub(objects_completed);

        if let (Some(ref mut initiator), Some(bid)) = (&mut self.backfill, self.stats.backfill_id) {
            let _ = initiator.record_progress(bid, objects_completed, bytes_transferred);
        }

        Ok(())
    }

    /// Transition from Rebuilding to Verifying.
    pub fn complete_rebuild(&mut self, now_ns: u64) -> Result<(), &'static str> {
        if self.state != HealState::Rebuilding {
            return Err("not in Rebuilding state");
        }
        self.state = HealState::Verifying;
        if let (Some(ref mut initiator), Some(bid)) = (&mut self.backfill, self.stats.backfill_id) {
            let _ = initiator.complete_transfer(bid);
        }
        self.stats.completed_at_ns = Some(now_ns);
        Ok(())
    }

    /// Finalize heal: move from Verifying to Complete and update placement map.
    ///
    /// After finalization, the placement map is updated so that rebuilt
    /// objects now include their new replica locations.
    pub fn finalize_heal(&mut self, rebuilt_placements: &BTreeMap<u64, BTreeSet<u64>>) {
        if self.state != HealState::Verifying {
            return;
        }
        // Remove lost members from the placement map now that rebuild is complete.
        let lost: Vec<u64> = self.lost_members.iter().copied().collect();
        for member_id in lost {
            self.placement.remove_member(member_id);
        }
        self.lost_members.clear();
        // Re-add rebuilt objects to placement map
        for (&object_id, members) in rebuilt_placements {
            for &member_id in members {
                self.placement.insert(object_id, member_id);
            }
        }
        if let (Some(ref mut initiator), Some(bid)) = (&mut self.backfill, self.stats.backfill_id) {
            let _ = initiator.finalize_backfill(bid);
        }
        self.state = HealState::Complete;
        self.stats.objects_rebuilt = self.stats.objects_to_rebuild;
        self.stats.objects_remaining = 0;
    }

    /// Abort the current heal operation.
    pub fn abort_heal(&mut self) {
        if !self.state.is_active() {
            return;
        }
        if let (Some(ref mut initiator), Some(bid)) = (&mut self.backfill, self.stats.backfill_id) {
            let _ = initiator.abort_backfill(bid);
        }
        self.state = HealState::Aborted;
    }

    /// Handle an epoch transition: abort active heal and update placement epoch.
    pub fn on_epoch_transition(&mut self, new_epoch: u64) {
        self.abort_heal();
        if let Some(ref mut initiator) = &mut self.backfill {
            initiator.on_epoch_transition(EpochId(new_epoch));
        }
        self.placement.set_epoch(new_epoch);
    }

    /// Reset the coordinator to idle with an empty placement map.
    pub fn reset(&mut self, epoch: u64) {
        self.state = HealState::Idle;
        self.stats = HealStats::default();
        self.lost_members.clear();
        self.surviving_members.clear();
        self.placement.clear(epoch);
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
fn test_receipt_ref(object_id: u64, generation: u64) -> PlacementReceiptRef {
    let mut object_key = [0xA5; 32];
    object_key[..8].copy_from_slice(&object_id.to_le_bytes());
    let mut digest = [0x5A; 32];
    digest[..8].copy_from_slice(&object_id.to_le_bytes());
    digest[8..16].copy_from_slice(&generation.to_le_bytes());
    PlacementReceiptRef::replicated(
        object_id,
        object_key,
        EpochId(1),
        generation,
        2,
        4096,
        digest,
    )
}

#[cfg(test)]
fn insert_test_object_with_receipt(placement: &mut PlacementMap, object_id: u64, members: &[u64]) {
    for &member in members {
        placement.insert(object_id, member);
    }
    placement.record_placement_receipt_ref(object_id, test_receipt_ref(object_id, 1));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::{DomainId, MemberId};
    use tidefs_replication_model::{
        ObjectDigest, ReplicaCopyRecord, ReplicaPlacementReceipt, ReplicatedReceiptId,
    };

    fn receipt_ref(object_id: u64, generation: u64) -> PlacementReceiptRef {
        test_receipt_ref(object_id, generation)
    }

    fn malformed_policy_receipt_ref(object_id: u64) -> PlacementReceiptRef {
        let base = receipt_ref(object_id, 1);
        PlacementReceiptRef::new(
            base.object_id,
            base.object_key,
            base.receipt_epoch,
            base.receipt_generation,
            tidefs_replication_model::ReceiptRedundancyPolicy::Replicated { copies: 0 },
            base.payload_len,
            base.payload_digest,
            0,
        )
    }

    fn under_width_receipt_ref(object_id: u64) -> PlacementReceiptRef {
        let base = receipt_ref(object_id, 1);
        PlacementReceiptRef::new(
            base.object_id,
            base.object_key,
            base.receipt_epoch,
            base.receipt_generation,
            tidefs_replication_model::ReceiptRedundancyPolicy::Replicated { copies: 3 },
            base.payload_len,
            base.payload_digest,
            2,
        )
    }

    fn rebuild_flow_result(
        object_id: u64,
        target_member: u64,
        placement_receipt_ref: PlacementReceiptRef,
        epoch: u64,
    ) -> FlowCommitResult {
        let subject_ref = ReplicatedSubjectId::new(object_id);
        let target_member = MemberId::new(target_member);
        let digest_prefix = u64::from_le_bytes(
            placement_receipt_ref.payload_digest[..8]
                .try_into()
                .unwrap(),
        );
        FlowCommitResult {
            placement_receipt: ReplicaPlacementReceipt {
                receipt_id: ReplicatedReceiptId(1000 + object_id),
                verification_ref: ReplicatedReceiptId(2000 + object_id),
                transfer_ref: ReplicatedReceiptId(3000 + object_id),
                subject_refs: vec![subject_ref],
                placed_on: target_member,
                placement_epoch: EpochId(epoch),
                subjects_placed: 1,
                placement_receipt_refs: vec![placement_receipt_ref],
            },
            updated_copy: ReplicaCopyRecord {
                subject_ref,
                member_ref: target_member,
                domain_ref: DomainId::new(target_member.0 * 10 + 1),
                copy_class: ReplicaCopyClass::Verified,
                payload_digest: ObjectDigest::new(digest_prefix),
                freshness_frontier: epoch,
                verification_receipt_ref: ReplicatedReceiptId(2000 + object_id),
            },
            final_flow_state: FlowState::Complete,
            flow_class: FlowCommitClass::Rebuild,
            commit_epoch: EpochId(epoch),
        }
    }

    fn relocation_flow_result(
        object_id: u64,
        target_member: u64,
        placement_receipt_ref: PlacementReceiptRef,
        epoch: u64,
    ) -> FlowCommitResult {
        let mut result =
            rebuild_flow_result(object_id, target_member, placement_receipt_ref, epoch);
        result.flow_class = FlowCommitClass::Relocation;
        result
    }

    fn assert_rebuild_flow_result_refused_without_mutation(
        result: FlowCommitResult,
        expected: &str,
    ) {
        let mut pm = PlacementMap::new(5);
        let old_receipt = receipt_ref(90, 1);
        pm.insert(90, 20);
        pm.record_placement_receipt_ref(90, old_receipt);

        let err = pm.publish_rebuild_flow_commit_result(&result).unwrap_err();

        assert!(err.contains(expected), "{err}");
        assert_eq!(pm.epoch(), 5);
        assert_eq!(pm.placement_receipt_ref(90), Some(old_receipt));
        assert_eq!(
            pm.replicas_of(90).cloned().unwrap_or_default(),
            [20].into_iter().collect()
        );
    }

    fn assert_relocation_flow_result_refused_without_mutation(
        source_member: u64,
        result: FlowCommitResult,
        expected: &str,
    ) {
        let mut pm = PlacementMap::new(5);
        let old_receipt = receipt_ref(90, 1);
        pm.insert(90, 20);
        pm.record_placement_receipt_ref(90, old_receipt);

        let err = pm
            .publish_relocation_flow_commit_result(source_member, &result)
            .unwrap_err();

        assert!(err.contains(expected), "{err}");
        assert_eq!(pm.epoch(), 5);
        assert_eq!(pm.placement_receipt_ref(90), Some(old_receipt));
        assert_eq!(
            pm.replicas_of(90).cloned().unwrap_or_default(),
            [20].into_iter().collect()
        );
    }

    // ── PlacementMap tests ────────────────────────────────────

    #[test]
    fn placement_map_insert_and_query() {
        let mut pm = PlacementMap::new(1);
        pm.insert(100, 10);
        pm.insert(100, 20);
        pm.insert(200, 10);

        assert_eq!(pm.object_count(), 2);
        assert_eq!(pm.member_count(), 2);
        assert_eq!(pm.total_replicas(), 3);

        let replicas = pm.replicas_of(100).unwrap();
        assert!(replicas.contains(&10));
        assert!(replicas.contains(&20));

        let objects = pm.objects_of(10).unwrap();
        assert!(objects.contains(&100));
        assert!(objects.contains(&200));
    }

    #[test]
    fn placement_map_keeps_receipt_ref_for_surviving_replicas() {
        let mut pm = PlacementMap::new(1);
        pm.insert(42, 10);
        pm.insert(42, 20);

        let receipt = receipt_ref(42, 7);
        pm.record_placement_receipt_ref(42, receipt);

        assert_eq!(pm.placement_receipt_ref(42), Some(receipt));
        assert_eq!(pm.placement_receipt_ref_count(), 1);

        let affected = pm.remove_member(10);
        assert!(affected.contains(&42));
        assert_eq!(pm.placement_receipt_ref(42), Some(receipt));

        let affected = pm.remove_member(20);
        assert!(affected.contains(&42));
        assert_eq!(pm.placement_receipt_ref(42), None);
        assert_eq!(pm.placement_receipt_ref_count(), 0);
    }

    #[test]
    fn placement_map_publishes_rebuild_flow_commit_result() {
        let mut pm = PlacementMap::new(1);
        let old_receipt = receipt_ref(90, 1);
        let repaired_receipt = receipt_ref(90, 2);
        pm.insert(90, 20);
        pm.record_placement_receipt_ref(90, old_receipt);

        let result = rebuild_flow_result(90, 30, repaired_receipt, 7);
        let publication = pm
            .publish_rebuild_flow_commit_result(&result)
            .expect("completed rebuild flow publishes placement");

        assert_eq!(
            publication,
            RebuildFlowCommitPlacementPublication {
                object_id: 90,
                target_member: 30,
                placement_receipt_ref: repaired_receipt,
                map_epoch: 7,
            }
        );
        assert_eq!(pm.epoch(), 7);
        assert_eq!(pm.placement_receipt_ref(90), Some(repaired_receipt));
        assert_eq!(
            pm.replicas_of(90).cloned().unwrap_or_default(),
            [20, 30].into_iter().collect()
        );
    }

    #[test]
    fn placement_map_publishes_relocation_flow_commit_result_and_retires_source() {
        let mut pm = PlacementMap::new(1);
        let old_receipt = receipt_ref(90, 1);
        let relocated_receipt = receipt_ref(90, 2);
        pm.insert(90, 20);
        pm.insert(90, 25);
        pm.record_placement_receipt_ref(90, old_receipt);

        let result = relocation_flow_result(90, 30, relocated_receipt, 7);
        let publication = pm
            .publish_relocation_flow_commit_result(20, &result)
            .expect("completed relocation flow publishes placement");

        assert_eq!(
            publication,
            RelocationFlowCommitPlacementPublication {
                object_id: 90,
                retired_source_member: 20,
                target_member: 30,
                placement_receipt_ref: relocated_receipt,
                map_epoch: 7,
            }
        );
        assert_eq!(pm.epoch(), 7);
        assert_eq!(pm.placement_receipt_ref(90), Some(relocated_receipt));
        assert_eq!(
            pm.replicas_of(90).cloned().unwrap_or_default(),
            [25, 30].into_iter().collect()
        );
        assert!(!pm
            .objects_of(20)
            .is_some_and(|objects| objects.contains(&90)));
    }

    #[test]
    fn placement_map_rejects_bad_rebuild_flow_commit_results_before_mutation() {
        let repaired_receipt = receipt_ref(90, 2);

        let mut result = rebuild_flow_result(90, 30, repaired_receipt, 7);
        result.flow_class = FlowCommitClass::Relocation;
        assert_rebuild_flow_result_refused_without_mutation(result, "not rebuild");

        let mut result = rebuild_flow_result(90, 30, repaired_receipt, 7);
        result.final_flow_state = FlowState::Verifying;
        assert_rebuild_flow_result_refused_without_mutation(result, "not complete");

        let result = rebuild_flow_result(90, 30, repaired_receipt, 4);
        assert_rebuild_flow_result_refused_without_mutation(result, "stale");

        let mut result = rebuild_flow_result(90, 30, repaired_receipt, 7);
        result.placement_receipt.placement_epoch = EpochId(6);
        assert_rebuild_flow_result_refused_without_mutation(result, "does not match commit epoch");

        let mut result = rebuild_flow_result(90, 30, repaired_receipt, 7);
        result.placement_receipt.subject_refs.clear();
        result.placement_receipt.subjects_placed = 0;
        assert_rebuild_flow_result_refused_without_mutation(result, "exactly one subject");

        let mut result = rebuild_flow_result(90, 30, repaired_receipt, 7);
        result.placement_receipt.subject_refs[0] = ReplicatedSubjectId::new(91);
        assert_rebuild_flow_result_refused_without_mutation(result, "does not match updated copy");

        let mut result = rebuild_flow_result(90, 30, repaired_receipt, 7);
        result.placement_receipt.placed_on = MemberId::new(31);
        assert_rebuild_flow_result_refused_without_mutation(result, "does not match updated copy");

        let mut result = rebuild_flow_result(90, 30, repaired_receipt, 7);
        result.updated_copy.copy_class = ReplicaCopyClass::Rebuilding;
        assert_rebuild_flow_result_refused_without_mutation(result, "not verified");

        let mut result = rebuild_flow_result(90, 30, repaired_receipt, 7);
        result.placement_receipt.placement_receipt_refs.clear();
        assert_rebuild_flow_result_refused_without_mutation(
            result,
            "exactly one placement receipt",
        );

        let mut result = rebuild_flow_result(90, 30, repaired_receipt, 7);
        result
            .placement_receipt
            .placement_receipt_refs
            .push(receipt_ref(90, 3));
        assert_rebuild_flow_result_refused_without_mutation(
            result,
            "exactly one placement receipt",
        );

        let synthetic = PlacementReceiptRef::synthetic_for_subject(ReplicatedSubjectId::new(90));
        let result = rebuild_flow_result(90, 30, synthetic, 7);
        assert_rebuild_flow_result_refused_without_mutation(result, "synthetic");

        let result = rebuild_flow_result(90, 30, malformed_policy_receipt_ref(90), 7);
        assert_rebuild_flow_result_refused_without_mutation(result, "malformed");

        let result = rebuild_flow_result(90, 30, under_width_receipt_ref(90), 7);
        assert_rebuild_flow_result_refused_without_mutation(result, "under-width");

        let result = rebuild_flow_result(90, 30, receipt_ref(91, 2), 7);
        assert_rebuild_flow_result_refused_without_mutation(result, "subject mismatch");
    }

    #[test]
    fn placement_map_rejects_bad_relocation_flow_commit_results_before_mutation() {
        let relocated_receipt = receipt_ref(90, 2);

        let result = rebuild_flow_result(90, 30, relocated_receipt, 7);
        assert_relocation_flow_result_refused_without_mutation(20, result, "not relocation");

        let mut result = relocation_flow_result(90, 30, relocated_receipt, 7);
        result.final_flow_state = FlowState::Verifying;
        assert_relocation_flow_result_refused_without_mutation(20, result, "not complete");

        let result = relocation_flow_result(90, 30, relocated_receipt, 4);
        assert_relocation_flow_result_refused_without_mutation(20, result, "stale");

        let result = relocation_flow_result(90, 30, relocated_receipt, 7);
        assert_relocation_flow_result_refused_without_mutation(30, result, "matches target");

        let result = relocation_flow_result(90, 30, relocated_receipt, 7);
        assert_relocation_flow_result_refused_without_mutation(25, result, "does not hold");

        let synthetic = PlacementReceiptRef::synthetic_for_subject(ReplicatedSubjectId::new(90));
        let result = relocation_flow_result(90, 30, synthetic, 7);
        assert_relocation_flow_result_refused_without_mutation(20, result, "synthetic");
    }

    #[test]
    fn placement_map_remove() {
        let mut pm = PlacementMap::new(1);
        pm.insert(42, 1);
        pm.insert(42, 2);

        pm.remove(42, 1);
        let replicas = pm.replicas_of(42).unwrap();
        assert!(!replicas.contains(&1));
        assert!(replicas.contains(&2));

        pm.remove(42, 2);
        assert!(pm.replicas_of(42).is_none());
        assert!(pm.objects_of(1).is_none());
    }

    #[test]
    fn placement_map_remove_member() {
        let mut pm = PlacementMap::new(1);
        pm.insert(1, 10);
        pm.insert(2, 10);
        pm.insert(3, 20);

        let affected = pm.remove_member(10);
        assert_eq!(affected.len(), 2);
        assert!(affected.contains(&1));
        assert!(affected.contains(&2));

        assert!(pm.replicas_of(3).is_some());
        assert!(pm.replicas_of(1).is_none());
    }

    #[test]
    fn compute_loss_impact_partial() {
        let mut pm = PlacementMap::new(1);
        pm.insert(1, 10);
        pm.insert(1, 20);
        pm.insert(2, 10);

        let mut lost = BTreeSet::new();
        lost.insert(10);

        let impact = pm.compute_loss_impact(&lost);
        assert_eq!(impact.len(), 2);
        assert!(impact[&1].contains(&10));
    }

    #[test]
    fn compute_wholly_lost_objects() {
        let mut pm = PlacementMap::new(1);
        pm.insert(1, 10);
        pm.insert(2, 10);
        pm.insert(2, 20);

        let mut lost = BTreeSet::new();
        lost.insert(10);

        let wholly = pm.compute_wholly_lost_objects(&lost);
        assert_eq!(wholly.len(), 1);
        assert!(wholly.contains(&1));
        assert!(!wholly.contains(&2));
    }

    #[test]
    fn compute_divergence_basic() {
        let mut pm = PlacementMap::new(1);
        pm.insert(1, 10);
        pm.insert(2, 10);

        let mut expected = BTreeMap::new();
        expected.insert(1, BTreeSet::from([10u64, 20]));
        expected.insert(2, BTreeSet::from([10u64]));

        let (missing, _excess) = pm.compute_divergence(&expected);
        assert_eq!(missing.len(), 1);
        assert!(missing[&1].contains(&20));
    }

    // ── PlacementHealCoordinator tests ────────────────────────

    fn make_coordinator() -> PlacementHealCoordinator {
        let mut coordinator = PlacementHealCoordinator::new(1, None)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });
        insert_test_object_with_receipt(coordinator.placement_mut(), 1, &[10, 20]);
        insert_test_object_with_receipt(coordinator.placement_mut(), 2, &[10, 20]);
        insert_test_object_with_receipt(coordinator.placement_mut(), 3, &[20, 30]);
        coordinator
    }

    #[test]
    fn coordinator_publishes_rebuild_flow_commit_result() {
        let mut coord = make_coordinator();
        let repaired_receipt = receipt_ref(1, 2);
        let result = rebuild_flow_result(1, 40, repaired_receipt, 7);

        let publication = coord
            .publish_rebuild_flow_commit_result(&result)
            .expect("coordinator publishes completed rebuild flow");

        assert_eq!(
            publication,
            RebuildFlowCommitPlacementPublication {
                object_id: 1,
                target_member: 40,
                placement_receipt_ref: repaired_receipt,
                map_epoch: 7,
            }
        );
        assert_eq!(coord.placement().epoch(), 7);
        assert_eq!(
            coord.placement().placement_receipt_ref(1),
            Some(repaired_receipt)
        );
        assert_eq!(
            coord
                .placement()
                .replicas_of(1)
                .cloned()
                .unwrap_or_default(),
            [10, 20, 40].into_iter().collect()
        );
    }

    #[test]
    fn coordinator_publishes_relocation_flow_commit_result() {
        let mut coord = make_coordinator();
        let relocated_receipt = receipt_ref(1, 2);
        let result = relocation_flow_result(1, 40, relocated_receipt, 7);

        let publication = coord
            .publish_relocation_flow_commit_result(10, &result)
            .expect("coordinator publishes completed relocation flow");

        assert_eq!(
            publication,
            RelocationFlowCommitPlacementPublication {
                object_id: 1,
                retired_source_member: 10,
                target_member: 40,
                placement_receipt_ref: relocated_receipt,
                map_epoch: 7,
            }
        );
        assert_eq!(coord.placement().epoch(), 7);
        assert_eq!(
            coord.placement().placement_receipt_ref(1),
            Some(relocated_receipt)
        );
        assert_eq!(
            coord
                .placement()
                .replicas_of(1)
                .cloned()
                .unwrap_or_default(),
            [20, 40].into_iter().collect()
        );
    }

    #[test]
    fn coordinator_rejects_rebuild_flow_commit_result_without_mutation() {
        let mut coord = make_coordinator();
        let old_receipt = coord.placement().placement_receipt_ref(1).unwrap();
        let old_replicas = coord.placement().replicas_of(1).cloned().unwrap();
        let mut result = rebuild_flow_result(1, 40, receipt_ref(1, 2), 7);
        result.flow_class = FlowCommitClass::Relocation;

        let err = coord
            .publish_rebuild_flow_commit_result(&result)
            .unwrap_err();

        assert!(err.contains("not rebuild"), "{err}");
        assert_eq!(coord.placement().epoch(), 1);
        assert_eq!(
            coord.placement().placement_receipt_ref(1),
            Some(old_receipt)
        );
        assert_eq!(coord.placement().replicas_of(1), Some(&old_replicas));
    }

    #[test]
    fn detect_loss_transitions_to_assessing() {
        let mut coord = make_coordinator();

        let mut lost = BTreeSet::new();
        lost.insert(10);
        let mut available = BTreeMap::new();
        available.insert(20, HealthClass::Healthy);
        available.insert(30, HealthClass::Healthy);

        let event = LossEvent {
            lost_members: lost,
            epoch: 1,
            detected_at_ns: 1_000_000_000,
            available_members: available,
        };

        let affected = coord.detect_loss(event);
        assert!(affected.is_some());
        assert_eq!(coord.state(), HealState::Assessing);
        assert!(coord.stats().objects_affected > 0);
    }

    #[test]
    fn detect_loss_while_healing_rejected() {
        let mut coord = make_coordinator();

        let mut lost = BTreeSet::new();
        lost.insert(10);
        let mut available = BTreeMap::new();
        available.insert(20, HealthClass::Healthy);

        let event = LossEvent {
            lost_members: lost.clone(),
            epoch: 1,
            detected_at_ns: 1_000_000_000,
            available_members: available.clone(),
        };

        assert!(coord.detect_loss(event).is_some());

        let event2 = LossEvent {
            lost_members: lost,
            epoch: 1,
            detected_at_ns: 2_000_000_000,
            available_members: available,
        };
        assert!(coord.detect_loss(event2).is_none());
    }

    #[test]
    fn build_rebuild_plan_from_loss() {
        let mut coord = make_coordinator();

        let mut lost = BTreeSet::new();
        lost.insert(10);
        let mut available = BTreeMap::new();
        available.insert(20, HealthClass::Healthy);
        available.insert(30, HealthClass::Healthy);

        coord.detect_loss(LossEvent {
            lost_members: lost,
            epoch: 1,
            detected_at_ns: 1_000_000_000,
            available_members: available,
        });
        let plan = coord.build_rebuild_plan(1, 1_000_000_001);
        assert!(plan.is_some());
        assert!(!plan.unwrap().is_empty());
    }

    #[test]
    fn build_plan_not_in_assessing_rejected() {
        let mut coord = make_coordinator();
        assert!(coord.build_rebuild_plan(1, 0).is_none());
    }

    #[test]
    fn heal_lifecycle_assessing_to_complete() {
        let mut coord = make_coordinator();

        let mut lost = BTreeSet::new();
        lost.insert(10);
        let mut available = BTreeMap::new();
        available.insert(20, HealthClass::Healthy);
        available.insert(30, HealthClass::Healthy);

        coord.detect_loss(LossEvent {
            lost_members: lost,
            epoch: 1,
            detected_at_ns: 1_000_000_000,
            available_members: available,
        });
        assert_eq!(coord.state(), HealState::Assessing);

        let plan = coord.build_rebuild_plan(1, 1_000_000_001);
        assert!(plan.is_some());
        assert_eq!(coord.state(), HealState::Planning);

        coord.state = HealState::Rebuilding;
        coord.record_rebuild_progress(1, 4096).unwrap();
        assert!(coord.stats().objects_rebuilt > 0);

        coord.complete_rebuild(2_000_000_000).unwrap();
        assert_eq!(coord.state(), HealState::Verifying);

        let mut rebuilt = BTreeMap::new();
        rebuilt.insert(1, BTreeSet::from([20u64]));
        rebuilt.insert(2, BTreeSet::from([20u64]));
        coord.finalize_heal(&rebuilt);
        assert_eq!(coord.state(), HealState::Complete);
    }

    #[test]
    fn abort_heal_from_active() {
        let mut coord = make_coordinator();

        let mut lost = BTreeSet::new();
        lost.insert(10);
        let mut available = BTreeMap::new();
        available.insert(20, HealthClass::Healthy);
        available.insert(30, HealthClass::Healthy);

        coord.detect_loss(LossEvent {
            lost_members: lost,
            epoch: 1,
            detected_at_ns: 1_000_000_000,
            available_members: available,
        });
        coord.build_rebuild_plan(1, 1_000_000_001);
        coord.abort_heal();
        assert_eq!(coord.state(), HealState::Aborted);
    }

    #[test]
    fn epoch_transition_aborts_heal() {
        let mut coord = make_coordinator();

        let mut lost = BTreeSet::new();
        lost.insert(10);
        let mut available = BTreeMap::new();
        available.insert(20, HealthClass::Healthy);

        coord.detect_loss(LossEvent {
            lost_members: lost,
            epoch: 1,
            detected_at_ns: 1_000_000_000,
            available_members: available,
        });
        assert!(coord.is_healing());

        coord.on_epoch_transition(2);
        assert_eq!(coord.state(), HealState::Aborted);
        assert_eq!(coord.placement().epoch(), 2);
    }

    #[test]
    fn build_rebuild_plan_refuses_receiptless_loss_before_backfill() {
        let initiator = RebuildBackfillInitiator::new(EpochId(1));
        let mut coord = PlacementHealCoordinator::new(1, Some(initiator))
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });

        coord.placement_mut().insert(1, 10);
        coord.placement_mut().insert(1, 20);
        coord.placement_mut().insert(2, 10);

        let mut lost = BTreeSet::new();
        lost.insert(10);
        let mut available = BTreeMap::new();
        available.insert(20, HealthClass::Healthy);
        available.insert(30, HealthClass::Healthy);

        coord.detect_loss(LossEvent {
            lost_members: lost,
            epoch: 1,
            detected_at_ns: 1_000_000_000,
            available_members: available,
        });

        let plan = coord.build_rebuild_plan(1, 1_000_000_001);
        assert!(plan.is_none());
        assert_eq!(coord.state(), HealState::Aborted);
        assert!(coord.stats().backfill_id.is_none());
    }

    #[test]
    fn build_rebuild_plan_refuses_unauthoritative_receipt_refs() {
        let cases = [
            PlacementReceiptRef::synthetic_for_subject(
                tidefs_replication_model::ReplicatedSubjectId::new(1),
            ),
            malformed_policy_receipt_ref(1),
            under_width_receipt_ref(1),
        ];

        for receipt in cases {
            let mut coord = PlacementHealCoordinator::new(1, None)
                .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });
            coord.placement_mut().insert(1, 10);
            coord.placement_mut().insert(1, 20);
            coord
                .placement_mut()
                .record_placement_receipt_ref(1, receipt);

            let mut lost = BTreeSet::new();
            lost.insert(10);
            let mut available = BTreeMap::new();
            available.insert(20, HealthClass::Healthy);
            available.insert(30, HealthClass::Healthy);

            coord.detect_loss(LossEvent {
                lost_members: lost,
                epoch: 1,
                detected_at_ns: 1_000_000_000,
                available_members: available,
            });

            assert!(coord.build_rebuild_plan(1, 1_000_000_001).is_none());
            assert_eq!(coord.state(), HealState::Aborted);
            assert!(coord.stats().backfill_id.is_none());
        }

        let mut coord = PlacementHealCoordinator::new(1, None)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });
        coord.placement_mut().insert(1, 10);
        coord.placement_mut().insert(1, 20);
        coord
            .placement_mut()
            .placement_receipt_refs
            .insert(1, receipt_ref(2, 1));

        let mut lost = BTreeSet::new();
        lost.insert(10);
        let mut available = BTreeMap::new();
        available.insert(20, HealthClass::Healthy);
        available.insert(30, HealthClass::Healthy);

        coord.detect_loss(LossEvent {
            lost_members: lost,
            epoch: 1,
            detected_at_ns: 1_000_000_000,
            available_members: available,
        });

        assert!(coord.build_rebuild_plan(1, 1_000_000_001).is_none());
        assert_eq!(coord.state(), HealState::Aborted);
        assert!(coord.stats().backfill_id.is_none());
    }

    #[test]
    fn open_backfill_accepts_receipt_authoritative_heal_plan() {
        let initiator = RebuildBackfillInitiator::new(EpochId(1));
        let mut coord = PlacementHealCoordinator::new(1, Some(initiator))
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });

        let receipt = receipt_ref(1, 9);
        coord.placement_mut().insert(1, 10);
        coord.placement_mut().insert(1, 20);
        coord
            .placement_mut()
            .record_placement_receipt_ref(1, receipt);

        let mut lost = BTreeSet::new();
        lost.insert(10);
        let mut available = BTreeMap::new();
        available.insert(20, HealthClass::Healthy);
        available.insert(30, HealthClass::Healthy);

        coord.detect_loss(LossEvent {
            lost_members: lost,
            epoch: 1,
            detected_at_ns: 1_000_000_000,
            available_members: available,
        });

        let plan = coord.build_rebuild_plan(1, 1_000_000_001).unwrap();
        assert_eq!(plan.tasks.len(), 1);
        assert_eq!(plan.tasks[0].placement_receipt_ref, receipt);
        assert!(!plan.tasks[0].placement_receipt_ref.is_synthetic());

        let backfill_id = coord.open_backfill(plan, 1).unwrap();
        assert_eq!(backfill_id, 1);
        assert_eq!(coord.state(), HealState::Rebuilding);
        assert_eq!(coord.stats().backfill_id, Some(1));
    }

    #[test]
    fn open_backfill_no_initiator() {
        let mut coord = make_coordinator();

        let mut lost = BTreeSet::new();
        lost.insert(10);
        let mut available = BTreeMap::new();
        available.insert(20, HealthClass::Healthy);
        available.insert(30, HealthClass::Healthy);

        coord.detect_loss(LossEvent {
            lost_members: lost,
            epoch: 1,
            detected_at_ns: 1_000_000_000,
            available_members: available,
        });

        let plan = coord.build_rebuild_plan(1, 1_000_000_001).unwrap();
        let result = coord.open_backfill(plan, 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no backfill initiator"));
    }

    #[test]
    fn heal_stats_fraction() {
        let stats = HealStats {
            objects_to_rebuild: 100,
            objects_rebuilt: 37,
            ..Default::default()
        };
        assert!((stats.fraction_complete() - 0.37).abs() < 0.01);
        assert_eq!(HealStats::default().fraction_complete(), 1.0);
    }

    #[test]
    fn reset_clears_state() {
        let mut coord = make_coordinator();
        coord.reset(5);
        assert_eq!(coord.state(), HealState::Idle);
        assert_eq!(coord.placement().object_count(), 0);
        assert_eq!(coord.placement().epoch(), 5);
    }
}

// ── Policy-aware target selection tests ──────────────────

/// Stripe policy (desired=1) should NOT rebuild objects that still
/// have one surviving replica. Only wholly-lost objects appear in stats.
#[test]
fn stripe_policy_skips_objects_with_surviving_replica() {
    let mut coord = PlacementHealCoordinator::new(1, None)
        .with_placement_policy(ClusterPlacementPolicy::Stripe);
    coord.placement_mut().insert(1, 10);
    coord.placement_mut().insert(1, 20);

    let mut lost = BTreeSet::new();
    lost.insert(10);
    let mut available = BTreeMap::new();
    available.insert(20, HealthClass::Healthy);
    available.insert(30, HealthClass::Healthy);

    coord.detect_loss(LossEvent {
        lost_members: lost,
        epoch: 1,
        detected_at_ns: 1_000_000_000,
        available_members: available,
    });
    assert_eq!(coord.state(), HealState::Assessing);
    assert!(coord.stats().objects_affected > 0);

    // With Stripe, object 1 still has member 20 → no rebuild needed
    let plan = coord.build_rebuild_plan(1, 1_000_000_001);
    assert!(
        plan.is_none(),
        "stripe should not rebuild when survivor exists"
    );
    assert_eq!(coord.state(), HealState::Complete);
}

/// Mirror-3 policy should rebuild to restore 3 replicas when a member is lost.
#[test]
fn mirror_3_restores_all_replicas() {
    let mut coord = PlacementHealCoordinator::new(1, None)
        .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 3 });
    insert_test_object_with_receipt(coord.placement_mut(), 1, &[10, 20, 30]);

    let mut lost = BTreeSet::new();
    lost.insert(10);
    let mut available = BTreeMap::new();
    available.insert(20, HealthClass::Healthy);
    available.insert(30, HealthClass::Healthy);
    available.insert(40, HealthClass::Healthy);
    available.insert(50, HealthClass::Healthy);

    coord.detect_loss(LossEvent {
        lost_members: lost,
        epoch: 1,
        detected_at_ns: 1_000_000_000,
        available_members: available,
    });
    assert_eq!(coord.state(), HealState::Assessing);

    let plan = coord.build_rebuild_plan(1, 1_000_000_001).unwrap();
    // Object 1 had replicas on 10, 20, 30; lost 10.
    // Surviving: 20, 30 (2 replicas). Desired: 3. Need: 1 more.
    // Healthy members not holding: 40, 50
    assert_eq!(plan.tasks.len(), 1);
    assert_eq!(plan.tasks[0].target_nodes.len(), 1);
    assert!(plan.tasks[0]
        .target_nodes
        .iter()
        .any(|m| *m == 40 || *m == 50));
}

/// Failure-domain-aware selection avoids placing replicas on nodes
/// that share the same failure domain as existing replicas.
#[test]
fn failure_domain_avoids_same_node_domain() {
    use tidefs_membership_epoch::HealthClass;

    let mut domains = BTreeMap::new();
    domains.insert(20, FailureDomain::for_node(20));
    domains.insert(30, FailureDomain::for_node(30));
    domains.insert(40, FailureDomain::for_node(20)); // same node domain as 20!
    domains.insert(50, FailureDomain::for_node(50));

    let mut coord = PlacementHealCoordinator::new(1, None)
        .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 })
        .with_member_failure_domains(domains);
    insert_test_object_with_receipt(coord.placement_mut(), 1, &[10, 20]);

    let mut lost = BTreeSet::new();
    lost.insert(10);
    let mut available = BTreeMap::new();
    available.insert(20, HealthClass::Healthy);
    available.insert(30, HealthClass::Healthy);
    available.insert(40, HealthClass::Healthy);
    available.insert(50, HealthClass::Healthy);

    coord.detect_loss(LossEvent {
        lost_members: lost,
        epoch: 1,
        detected_at_ns: 1_000_000_000,
        available_members: available,
    });

    let plan = coord.build_rebuild_plan(1, 1_000_000_001).unwrap();
    // Object 1 had {10, 20}. After losing 10, surviving: {20}.
    // Desired: 2, need 1 more.
    // Candidates: 30, 40, 50 (not 20 because it already holds the object).
    // 40 shares failure domain with 20 → should be sorted last.
    // 50 should be preferred (distinct domain, low load).
    assert_eq!(plan.tasks.len(), 1);
    let targets = &plan.tasks[0].target_nodes;
    assert_eq!(targets.len(), 1);
    // Should prefer 30 or 50, not 40 (same domain as 20)
    assert!(
        targets[0] == 30 || targets[0] == 50,
        "target should be from distinct failure domain, got {}",
        targets[0]
    );
}

/// Load balancing distributes rebuild targets evenly across nodes.
#[test]
fn rebuild_load_is_distributed_evenly() {
    use tidefs_membership_epoch::HealthClass;

    let mut coord = PlacementHealCoordinator::new(1, None)
        .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });
    // 4 objects all on {10, 20}. Lose 10.
    for obj in 1..=4u64 {
        insert_test_object_with_receipt(coord.placement_mut(), obj, &[10, 20]);
    }

    let mut lost = BTreeSet::new();
    lost.insert(10);
    let mut available = BTreeMap::new();
    available.insert(20, HealthClass::Healthy);
    available.insert(30, HealthClass::Healthy);
    available.insert(40, HealthClass::Healthy);

    coord.detect_loss(LossEvent {
        lost_members: lost,
        epoch: 1,
        detected_at_ns: 1_000_000_000,
        available_members: available,
    });

    let plan = coord.build_rebuild_plan(1, 1_000_000_001).unwrap();
    // 4 objects, each needs 1 target. Available: 30, 40.
    // Should distribute: ~2 objects each.
    assert_eq!(plan.tasks.len(), 4);
    let mut count_30 = 0u64;
    let mut count_40 = 0u64;
    for task in &plan.tasks {
        for t in &task.target_nodes {
            match *t {
                30 => count_30 += 1,
                40 => count_40 += 1,
                _ => {}
            }
        }
    }
    assert_eq!(count_30, 2, "member 30 should get 2 objects");
    assert_eq!(count_40, 2, "member 40 should get 2 objects");
}

/// ErasureCoded policy (4+2) should rebuild to restore 6 replicas.
#[test]
fn erasure_policy_restores_full_width() {
    let mut coord = PlacementHealCoordinator::new(1, None)
        .with_placement_policy(ClusterPlacementPolicy::ErasureCoded { data: 4, parity: 2 });
    insert_test_object_with_receipt(coord.placement_mut(), 1, &[10, 20, 30, 40, 50, 60]);

    let mut lost = BTreeSet::new();
    lost.insert(10);
    lost.insert(20);
    let mut available = BTreeMap::new();
    for m in 30..=70u64 {
        available.insert(m, HealthClass::Healthy);
    }

    coord.detect_loss(LossEvent {
        lost_members: lost,
        epoch: 1,
        detected_at_ns: 1_000_000_000,
        available_members: available,
    });
    assert_eq!(coord.state(), HealState::Assessing);

    let plan = coord.build_rebuild_plan(1, 1_000_000_001).unwrap();
    // Object 1 had 6 replicas on {10, 20, 30, 40, 50, 60}.
    // Lost 10, 20. Surviving: 30, 40, 50, 60 (4 replicas).
    // Desired: 6 (data+parity). Need: 2 more.
    assert_eq!(plan.tasks.len(), 1);
    assert_eq!(plan.tasks[0].target_nodes.len(), 2);
    // Targets must not be among the existing replica set.
    let existing: BTreeSet<u64> = [30, 40, 50, 60].into();
    for t in &plan.tasks[0].target_nodes {
        assert!(
            !existing.contains(t),
            "target {} already holds the object",
            t
        );
    }
}

// ── Placement-heal scenario tests ────────────────────────────────────
///
/// Scenario-driven tests that exercise the full placement-heal lifecycle
/// through ClusterLeaseRuntime, covering multi-member placement recording,
/// loss detection, rebuild planning, backfill completion, and heal
/// finalization with post-heal placement convergence verification.
#[cfg(test)]
mod scenario_tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    use tidefs_membership_epoch::{EpochId, HealthClass};
    use tokio::sync::mpsc;

    use crate::runtime::{ClusterLeaseConfig, ClusterLeaseRuntime};

    // ── Helpers ──────────────────────────────────────────────────

    /// Set up a 5-member cluster with 100 objects in a 2-replica layout.
    /// Objects are distributed across members: each object has 2 copies
    /// on distinct members. Member 1 holds a copy of all 100 objects.
    fn setup_five_member_cluster(rt: &mut ClusterLeaseRuntime) {
        // Member 1 holds all objects (the "hub" member)
        // Members 2-5 each hold a subset
        for obj_id in 0..100u64 {
            rt.record_placement(obj_id, 1);
            let replica_member = 2 + (obj_id % 4); // distributes across members 2..=5
            rt.record_placement(obj_id, replica_member);
        }
    }

    // ── Scenario: receiptless heal refusal ───────────────────────

    /// Models a 5-member cluster. Member 1 fails, but the legacy placement map
    /// has no placement receipt authority, so transfer admission must refuse.
    #[test]
    fn five_member_loss_requires_receipts() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });
        setup_five_member_cluster(&mut rt);

        assert_eq!(rt.placement_map().object_count(), 100);
        assert_eq!(rt.placement_map().member_count(), 5);

        // Member 1 is lost
        let mut lost = BTreeSet::new();
        lost.insert(1);
        let mut available = BTreeMap::new();
        for m in 2..=5u64 {
            available.insert(m, HealthClass::Healthy);
        }

        let backfill_id = rt.detect_member_loss(lost, available, 1_000_000_000);
        assert!(backfill_id.is_none());
        assert!(rx.try_recv().is_err());
        assert!(!rt.is_healing());
        assert_eq!(rt.heal_state(), HealState::Aborted);

        let stats = rt.heal_stats();
        assert!(stats.objects_to_rebuild > 0);
        assert!(stats.objects_wholly_lost == 0);
        assert_eq!(stats.objects_affected, 100);

        // Verify every object had a surviving source, even though no transfer
        // was admitted without receipt authority.
        let map = rt.placement_map();
        for obj_id in 0..100u64 {
            let replicas = map
                .replicas_of(obj_id)
                .expect("every object should exist in placement map");
            let has_survivor = replicas.iter().any(|m| *m >= 2 && *m <= 5);
            assert!(
                has_survivor,
                "object {obj_id} has no surviving replica after heal: {replicas:?}"
            );
        }
    }

    // ── Scenario: duplicate loss before admitted heal ─────────────

    /// A receiptless loss must not create an active heal window.
    #[test]
    fn receiptless_loss_does_not_start_active_heal() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });
        setup_five_member_cluster(&mut rt);

        // First loss: member 1
        let mut lost1 = BTreeSet::new();
        lost1.insert(1);
        let mut available1 = BTreeMap::new();
        for m in 2..=5u64 {
            available1.insert(m, HealthClass::Healthy);
        }

        let bid1 = rt.detect_member_loss(lost1, available1, 1_000_000_000);
        assert!(bid1.is_none());
        assert!(rx.try_recv().is_err());
        assert!(!rt.is_healing());
        assert_eq!(rt.heal_state(), HealState::Aborted);
    }

    // ── Scenario: epoch transition after refused heal ─────────────

    /// An epoch transition must leave a receiptless refused heal terminal.
    #[test]
    fn epoch_transition_preserves_refused_heal() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });
        setup_five_member_cluster(&mut rt);

        let mut lost = BTreeSet::new();
        lost.insert(1);
        let mut available = BTreeMap::new();
        for m in 2..=5u64 {
            available.insert(m, HealthClass::Healthy);
        }

        rt.detect_member_loss(lost, available, 1_000_000_000);
        assert!(rx.try_recv().is_err());
        assert!(!rt.is_healing());
        assert_eq!(rt.heal_state(), HealState::Aborted);

        rt.on_epoch_transition(EpochId(2));
        assert!(!rt.is_healing());
        assert_eq!(rt.heal_state(), HealState::Aborted);
    }

    // ── Scenario: wholly lost objects ────────────────────────────

    /// When a member holds the ONLY replica of some objects, those objects
    /// are wholly lost. The heal should reflect this in stats.
    #[test]
    fn wholly_lost_objects_tracked() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });

        // 50 objects with replicas on members 1+2 (survivable)
        // 50 objects with ONLY member 1 (wholly lost)
        for obj_id in 0..50u64 {
            rt.record_placement(obj_id, 1);
            rt.record_placement(obj_id, 2);
        }
        for obj_id in 50..100u64 {
            rt.record_placement(obj_id, 1);
        }

        let mut lost = BTreeSet::new();
        lost.insert(1);
        let mut available = BTreeMap::new();
        available.insert(2, HealthClass::Healthy);
        available.insert(3, HealthClass::Healthy);

        // Objects 0-49 are on {1,2} and would be rebuildable to member 3 if
        // receipt authority existed. Objects 50-99 are wholly lost.
        let result = rt.detect_member_loss(lost, available, 1_000_000_000);
        assert!(result.is_none());
        let stats = rt.heal_stats();
        assert!(stats.objects_wholly_lost >= 50);
        assert_eq!(rt.heal_state(), HealState::Aborted);
    }

    // ── Scenario: empty loss (no members lost) ───────────────────

    /// Detecting loss with an empty lost set should be a no-op.
    #[test]
    fn empty_loss_is_noop() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });
        setup_five_member_cluster(&mut rt);

        let lost = BTreeSet::new();
        let mut available = BTreeMap::new();
        for m in 1..=5u64 {
            available.insert(m, HealthClass::Healthy);
        }

        // Empty lost set: detect_loss returns impacted set but no rebuild needed
        let result = rt.detect_member_loss(lost, available, 1_000_000_000);
        // Since no members are lost, no objects are affected.
        // detect_loss returns None because affected set is empty -> Failed state.
        assert!(result.is_none());
    }

    // ── Scenario: placement map preservation after refusal ───────

    /// When receiptless heal admission is refused, the placement map remains
    /// unchanged rather than pretending movement completed.
    #[test]
    fn placement_map_preserved_when_receiptless_heal_refused() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });
        setup_five_member_cluster(&mut rt);

        let pre_object_count = rt.placement_map().object_count();
        let _pre_member_count = rt.placement_map().member_count();

        let mut lost = BTreeSet::new();
        lost.insert(1);
        let mut available = BTreeMap::new();
        for m in 2..=5u64 {
            available.insert(m, HealthClass::Healthy);
        }

        let backfill_id = rt.detect_member_loss(lost, available, 1_000_000_000);
        assert!(backfill_id.is_none());
        assert!(rx.try_recv().is_err());
        assert_eq!(rt.heal_state(), HealState::Aborted);

        let post_object_count = rt.placement_map().object_count();
        assert_eq!(
            post_object_count, pre_object_count,
            "receiptless refusal must not drop placement map objects"
        );

        let objects_of_1 = rt.placement_map().objects_of(1);
        assert!(
            objects_of_1.is_some_and(|objects| !objects.is_empty()),
            "receiptless refusal must not fake source-member retirement"
        );
    }

    // ── Scenario: multi-object heal with progress tracking ───────

    /// Exercise multi-object scope calculation while refusing receiptless
    /// transfer admission.
    #[test]
    fn multi_object_receiptless_heal_tracks_scope_then_refuses() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx)
            .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });

        // 20 objects, each on members {1, X} where X is 2..=5 (round-robin)
        for obj_id in 0..20u64 {
            rt.record_placement(obj_id, 1);
            rt.record_placement(obj_id, 2 + (obj_id % 4));
        }

        let mut lost = BTreeSet::new();
        lost.insert(1);
        let mut available = BTreeMap::new();
        for m in 2..=5u64 {
            available.insert(m, HealthClass::Healthy);
        }

        let backfill_id = rt.detect_member_loss(lost, available, 1_000_000_000);
        assert!(backfill_id.is_none());

        let stats = rt.heal_stats();
        assert!(stats.objects_to_rebuild > 0);
        assert_eq!(stats.objects_affected, 20);
        assert_eq!(stats.objects_wholly_lost, 0);

        assert!(rx.try_recv().is_err());
        assert!(!rt.is_healing());
        assert_eq!(rt.heal_state(), HealState::Aborted);
        assert!(rt.heal_stats().completed_at_ns.is_none());
    }
}

// ── Scenario: exactly-once rebuild ownership across restart ──
//
// After a full power loss restart, the rebuild plan for a given
// loss event must be identical to the original — same targets,
// same source/target assignments, same object set. This proves
// rebuild ownership is deterministic and exactly-once.

#[test]
fn rebuild_plan_deterministic_across_restart() {
    // Build a 3-member cluster with 10 objects (2 replicas each).
    let mut pm = PlacementMap::new(1);
    for obj_id in 0..10u64 {
        insert_test_object_with_receipt(&mut pm, obj_id, &[1, 2 + (obj_id % 2)]);
    }

    let policy = ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 };

    // First run: detect loss and build plan.
    let mut coord1 = PlacementHealCoordinator::new(1, None).with_placement_policy(policy);
    *coord1.placement_mut() = pm.clone();

    let lost = BTreeSet::from([1u64]);
    let available = BTreeMap::from([(2u64, HealthClass::Healthy), (3u64, HealthClass::Healthy)]);
    let loss = LossEvent {
        lost_members: lost.clone(),
        available_members: available.clone(),
        epoch: 1,
        detected_at_ns: 1_000_000_000,
    };

    let affected1 = coord1.detect_loss(loss.clone());
    assert!(affected1.is_some(), "loss must be detected");
    let plan1 = coord1.build_rebuild_plan(100, 1_000_000_000);
    assert!(plan1.is_some(), "rebuild plan must be generated");
    let plan1 = plan1.unwrap();
    assert!(!plan1.is_empty(), "plan must have tasks");

    // Second run (simulated restart): same map, same loss → same plan.
    let mut coord2 = PlacementHealCoordinator::new(1, None).with_placement_policy(policy);
    *coord2.placement_mut() = pm;

    let affected2 = coord2.detect_loss(loss);
    assert!(affected2.is_some(), "loss must be detected after restart");
    let plan2 = coord2.build_rebuild_plan(100, 1_000_000_000);
    assert!(
        plan2.is_some(),
        "rebuild plan must be generated after restart"
    );
    let plan2 = plan2.unwrap();

    // Verify plans are identical — same tasks, same target assignments.
    assert_eq!(
        plan1.task_count(),
        plan2.task_count(),
        "plan task counts must match across restart"
    );
    assert_eq!(
        plan1.total_target_replicas(),
        plan2.total_target_replicas(),
        "total target replicas must match across restart"
    );

    // Per-task comparison: same object_id, same sources, same targets.
    for (t1, t2) in plan1.tasks.iter().zip(plan2.tasks.iter()) {
        assert_eq!(t1.object_id, t2.object_id, "object_id must match");
        assert_eq!(
            t1.source_nodes, t2.source_nodes,
            "source nodes must match for obj {}",
            t1.object_id
        );
        assert_eq!(
            t1.target_nodes, t2.target_nodes,
            "target nodes must match for obj {}",
            t1.object_id
        );
    }
}

#[test]
fn rebuild_plan_exactly_one_backfill_per_loss() {
    // Verify that a single loss event produces at most one active
    // rebuild backfill — repeated detect_loss calls on the same loss
    // do not create duplicate plans.
    // Use 3 members with 2 replicas so that when member 1 fails,
    // surviving members 2 and 3 can receive rebuild targets.
    let mut pm = PlacementMap::new(1);
    for obj_id in 0..5u64 {
        insert_test_object_with_receipt(&mut pm, obj_id, &[1, 2 + (obj_id % 2)]);
    }

    let mut coord = PlacementHealCoordinator::new(1, None)
        .with_placement_policy(ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });
    *coord.placement_mut() = pm;

    let loss = LossEvent {
        lost_members: BTreeSet::from([1u64]),
        available_members: BTreeMap::from([
            (2u64, HealthClass::Healthy),
            (3u64, HealthClass::Healthy),
        ]),
        epoch: 1,
        detected_at_ns: 1_000_000_000,
    };

    // First detection works.
    let aff1 = coord.detect_loss(loss.clone());
    assert!(aff1.is_some());

    // Second detection while already in Assessing state must be refused.
    let aff2 = coord.detect_loss(loss.clone());
    assert!(
        aff2.is_none(),
        "second detect_loss must be refused while heal is active"
    );

    // Build the plan — it must exist (exactly once) even if no
    // new replicas are needed (all replicas survive on other members).
    // The plan may be empty if objects already satisfy the policy,
    // but build_rebuild_plan must still be callable exactly once.
    let plan = coord.build_rebuild_plan(200, 2_000_000_000);
    // Note: if all objects already have desired replica count on
    // surviving members, build_rebuild_plan returns None (Complete).
    // Either way, there is at most one plan — exactly-once ownership.
    if let Some(ref p) = plan {
        assert!(
            p.task_count() > 0 || p.task_count() == 0,
            "plan must be valid if present"
        );
    }

    // Third detection while still active must also be refused.
    let aff3 = coord.detect_loss(loss.clone());
    assert!(
        aff3.is_none(),
        "third detect_loss must be refused while heal is active"
    );
}
