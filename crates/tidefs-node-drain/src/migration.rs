// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Data migration driver for node drain.
//!
//! The [`MigrationDriver`] walks the object store on a draining node, groups
//! objects by durability-layout placement target, transfers each object via
//! send-stream to surviving peers, and tracks completion per placement group.
//!
//! Production implementations of [`MigrationOps`] wire this to the real
//! object-store, send-stream, and rebuild-planner infrastructure.
//! Test implementations use mocks.

use std::fmt;
use tidefs_membership_epoch::MemberId;
use tidefs_replication_model::ReplicatedReceiptId;

// ---------------------------------------------------------------------------
// PlacementTarget
// ---------------------------------------------------------------------------

/// A surviving node that receives migrated objects from the draining node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlacementTarget {
    /// Target node identifier.
    pub node_id: MemberId,
    /// Number of objects this target is expected to receive.
    pub expected_object_count: u64,
    /// Estimated total bytes this target will receive.
    pub estimated_bytes: u64,
}

impl PlacementTarget {
    #[must_use]
    pub fn new(node_id: MemberId) -> Self {
        Self {
            node_id,
            expected_object_count: 0,
            estimated_bytes: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// MigrationPlan
// ---------------------------------------------------------------------------

/// A plan describing what data must be migrated off a draining node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationPlan {
    /// The node being drained.
    pub source_node: MemberId,
    /// Surviving nodes that will receive migrated objects.
    pub targets: Vec<PlacementTarget>,
    /// Total number of objects to migrate.
    pub total_objects: u64,
    /// Total estimated bytes to transfer.
    pub total_bytes: u64,
    /// Whether to BLAKE3-verify each transferred object.
    pub verify_checksums: bool,
}

impl MigrationPlan {
    /// Create a new empty migration plan for the given source node.
    #[must_use]
    pub fn new(source_node: MemberId) -> Self {
        Self {
            source_node,
            targets: Vec::new(),
            total_objects: 0,
            total_bytes: 0,
            verify_checksums: true,
        }
    }

    /// Validate the plan: must have at least one target, source must not be
    /// in the target list, and total_objects must be consistent.
    pub fn validate(&self) -> Result<(), MigrationError> {
        if self.targets.is_empty() {
            return Err(MigrationError::NoTargets {
                source_node: self.source_node,
            });
        }

        for target in &self.targets {
            if target.node_id == self.source_node {
                return Err(MigrationError::SelfTarget {
                    source_node: self.source_node,
                });
            }
        }

        let claimed: u64 = self.targets.iter().map(|t| t.expected_object_count).sum();
        if claimed != self.total_objects {
            return Err(MigrationError::ObjectCountMismatch {
                total: self.total_objects,
                claimed,
            });
        }

        Ok(())
    }

    /// Return the list of target node IDs.
    #[must_use]
    pub fn target_ids(&self) -> Vec<MemberId> {
        self.targets.iter().map(|t| t.node_id).collect()
    }
}

// ---------------------------------------------------------------------------
// PerTargetProgress
// ---------------------------------------------------------------------------

/// Progress of migration to a single placement target.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PerTargetProgress {
    pub target: MemberId,
    pub objects_migrated: u64,
    pub objects_remaining: u64,
    pub bytes_transferred: u64,
    pub checksum_failures: u64,
}

impl PerTargetProgress {
    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.objects_remaining == 0
    }

    #[must_use]
    pub const fn fraction(self) -> f64 {
        let total = self.objects_migrated + self.objects_remaining;
        if total == 0 {
            return 1.0;
        }
        self.objects_migrated as f64 / total as f64
    }
}

// ---------------------------------------------------------------------------
// MigrationProgress
// ---------------------------------------------------------------------------

/// Aggregate progress of the data migration phase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationProgress {
    pub objects_migrated: u64,
    pub objects_remaining: u64,
    pub bytes_transferred: u64,
    pub bytes_remaining: u64,
    pub checksum_failures: u64,
    pub placement_receipt_refs: Vec<ReplicatedReceiptId>,
    pub per_target: std::collections::BTreeMap<u64, PerTargetProgress>,
}

impl MigrationProgress {
    #[must_use]
    pub fn new(plan: &MigrationPlan) -> Self {
        let mut per_target = std::collections::BTreeMap::new();
        for t in &plan.targets {
            per_target.insert(
                t.node_id.0,
                PerTargetProgress {
                    target: t.node_id,
                    objects_migrated: 0,
                    objects_remaining: t.expected_object_count,
                    bytes_transferred: 0,
                    checksum_failures: 0,
                },
            );
        }
        Self {
            objects_migrated: 0,
            objects_remaining: plan.total_objects,
            bytes_transferred: 0,
            bytes_remaining: plan.total_bytes,
            checksum_failures: 0,
            placement_receipt_refs: Vec::new(),
            per_target,
        }
    }

    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.objects_remaining == 0
    }

    #[must_use]
    pub fn fraction(&self) -> f64 {
        let total = self.objects_migrated + self.objects_remaining;
        if total == 0 {
            return 1.0;
        }
        self.objects_migrated as f64 / total as f64
    }

    /// Record a successful object migration to a target.
    pub fn record_migrated(
        &mut self,
        target: MemberId,
        bytes: u64,
        receipt_id: ReplicatedReceiptId,
    ) {
        self.objects_migrated = self.objects_migrated.saturating_add(1);
        self.objects_remaining = self.objects_remaining.saturating_sub(1);
        self.bytes_transferred = self.bytes_transferred.saturating_add(bytes);
        self.bytes_remaining = self.bytes_remaining.saturating_sub(bytes);
        self.placement_receipt_refs.push(receipt_id);

        if let Some(entry) = self.per_target.get_mut(&target.0) {
            entry.objects_migrated = entry.objects_migrated.saturating_add(1);
            entry.objects_remaining = entry.objects_remaining.saturating_sub(1);
            entry.bytes_transferred = entry.bytes_transferred.saturating_add(bytes);
        }
    }

    /// Record a checksum failure during migration.
    pub fn record_checksum_failure(&mut self, target: MemberId) {
        self.checksum_failures = self.checksum_failures.saturating_add(1);
        if let Some(entry) = self.per_target.get_mut(&target.0) {
            entry.checksum_failures = entry.checksum_failures.saturating_add(1);
        }
        // A checksum failure means the object still needs re-transfer
    }
}

// ---------------------------------------------------------------------------
// MigrationError
// ---------------------------------------------------------------------------

/// Errors specific to the data migration phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MigrationError {
    /// No placement targets were provided.
    NoTargets { source_node: MemberId },
    /// A target is the same as the source node.
    SelfTarget { source_node: MemberId },
    /// The claimed object counts across targets don't match the total.
    ObjectCountMismatch { total: u64, claimed: u64 },
    /// The migration has no objects to transfer (already complete or empty).
    NothingToMigrate { source_node: MemberId },
    /// A transfer to a specific target failed.
    TransferFailed {
        source_node: MemberId,
        target: MemberId,
        object_id: u64,
        reason: String,
    },
    /// Checksum verification failed for a transferred object.
    ChecksumMismatch {
        source_node: MemberId,
        target: MemberId,
        object_id: u64,
        expected: String,
        got: String,
    },
    /// Migration completed transfer, but no committed placement receipt was
    /// available for the relocated object.
    PlacementReceiptMissing {
        source_node: MemberId,
        target: MemberId,
        object_id: u64,
        reason: String,
    },
    /// The migration was cancelled mid-transfer.
    Cancelled {
        source_node: MemberId,
        objects_remaining: u64,
    },
}

impl fmt::Display for MigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTargets { source_node } => {
                write!(f, "node {} migration: no placement targets", source_node.0)
            }
            Self::SelfTarget { source_node } => {
                write!(
                    f,
                    "node {} migration: target list includes self",
                    source_node.0
                )
            }
            Self::ObjectCountMismatch { total, claimed } => {
                write!(
                    f,
                    "migration object count mismatch: total={total} but targets claim={claimed}",
                )
            }
            Self::NothingToMigrate { source_node } => {
                write!(f, "node {} migration: nothing to migrate", source_node.0)
            }
            Self::TransferFailed {
                source_node,
                target,
                object_id,
                reason,
            } => {
                write!(
                    f,
                    "node {} -> {} transfer failed for object {}: {}",
                    source_node.0, target.0, object_id, reason
                )
            }
            Self::ChecksumMismatch {
                source_node,
                target,
                object_id,
                expected,
                got,
            } => {
                write!(
                    f,
                    "node {} -> {} checksum mismatch for object {} (expected {}, got {})",
                    source_node.0, target.0, object_id, expected, got
                )
            }
            Self::PlacementReceiptMissing {
                source_node,
                target,
                object_id,
                reason,
            } => {
                write!(
                    f,
                    "node {} -> {} missing committed placement receipt for object {}: {}",
                    source_node.0, target.0, object_id, reason
                )
            }
            Self::Cancelled {
                source_node,
                objects_remaining,
            } => {
                write!(
                    f,
                    "node {} migration cancelled with {} objects remaining",
                    source_node.0, objects_remaining
                )
            }
        }
    }
}

impl std::error::Error for MigrationError {}

// ---------------------------------------------------------------------------
// MigrationOps trait
// ---------------------------------------------------------------------------

/// Operations the [`MigrationDriver`] calls to interact with the object store,
/// send-stream transport, and checksum verification.
///
/// Production implementations wire these to the real object-store enumerator,
/// send-stream sender, and BLAKE3 checksum verifier. Test implementations
/// use mocks.
pub trait MigrationOps {
    /// Enumerate all objects on the draining node, returning their IDs and
    /// sizes in bytes.
    fn enumerate_objects(&self, source_node: MemberId) -> Result<Vec<(u64, u64)>, String>;

    /// Determine which surviving node should receive a given object, based
    /// on durability-layout placement.
    fn placement_target_for(
        &self,
        source_node: MemberId,
        object_id: u64,
        targets: &[MemberId],
    ) -> Result<MemberId, String>;

    /// Transfer a single object from the source to the target via send-stream.
    ///
    /// Returns the number of bytes transferred on success.
    fn transfer_object(
        &mut self,
        source_node: MemberId,
        target: MemberId,
        object_id: u64,
    ) -> Result<u64, String>;

    /// Verify the BLAKE3 checksum of a transferred object on the target.
    ///
    /// Returns `Ok(())` if checksums match, or an error describing the
    /// mismatch.
    fn verify_checksum(&self, target: MemberId, object_id: u64) -> Result<(), String>;

    /// Return the committed placement receipt for a successfully relocated
    /// object.
    ///
    /// Production implementations must source this from the placement runtime
    /// after the placement receipt has committed. The default fails closed so
    /// callers cannot claim data relocation without receipt evidence.
    fn committed_placement_receipt_for(
        &self,
        source_node: MemberId,
        target: MemberId,
        object_id: u64,
    ) -> Result<ReplicatedReceiptId, String> {
        let _ = (source_node, target, object_id);
        Err("placement receipt integration not wired".to_string())
    }
}

// ---------------------------------------------------------------------------
// MigrationOutcome
// ---------------------------------------------------------------------------

/// Summary of a completed migration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationOutcome {
    pub source_node: MemberId,
    pub success: bool,
    pub objects_migrated: u64,
    pub bytes_transferred: u64,
    pub checksum_failures: u64,
    pub placement_receipt_refs: Vec<ReplicatedReceiptId>,
    pub per_target_results: std::collections::BTreeMap<u64, PerTargetProgress>,
}

impl MigrationOutcome {
    #[must_use]
    pub fn from_progress(
        source_node: MemberId,
        progress: &MigrationProgress,
        success: bool,
    ) -> Self {
        Self {
            source_node,
            success,
            objects_migrated: progress.objects_migrated,
            bytes_transferred: progress.bytes_transferred,
            checksum_failures: progress.checksum_failures,
            placement_receipt_refs: progress.placement_receipt_refs.clone(),
            per_target_results: progress.per_target.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// MigrationDriver
// ---------------------------------------------------------------------------

/// Orchestrates data migration from a draining node to surviving peers.
///
/// Usage:
/// 1. Call [`build_plan()`] to enumerate objects and determine placement.
/// 2. Call [`validate_plan()`] to verify the plan is sane.
/// 3. Call [`execute()`] to transfer all objects and verify checksums.
/// 4. Check [`outcome()`] for the migration summary.
pub struct MigrationDriver {
    plan: MigrationPlan,
    progress: MigrationProgress,
    cancelled: bool,
}

impl MigrationDriver {
    /// Create a new driver with an empty plan.
    #[must_use]
    pub fn new(source_node: MemberId) -> Self {
        let plan = MigrationPlan::new(source_node);
        let progress = MigrationProgress::new(&plan);
        Self {
            plan,
            progress,
            cancelled: false,
        }
    }

    // Accessors

    #[must_use]
    pub fn plan(&self) -> &MigrationPlan {
        &self.plan
    }

    #[must_use]
    pub fn progress(&self) -> &MigrationProgress {
        &self.progress
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// Build a migration plan by enumerating objects and computing placement.
    ///
    /// Calls `ops.enumerate_objects()` and `ops.placement_target_for()` to
    /// populate the plan's targets and object counts.
    pub fn build_plan(
        &mut self,
        ops: &dyn MigrationOps,
        targets: &[MemberId],
    ) -> Result<&MigrationPlan, MigrationError> {
        let objects = ops.enumerate_objects(self.plan.source_node).map_err(|e| {
            MigrationError::TransferFailed {
                source_node: self.plan.source_node,
                target: MemberId::ZERO,
                object_id: 0,
                reason: e,
            }
        })?;

        if objects.is_empty() {
            return Err(MigrationError::NothingToMigrate {
                source_node: self.plan.source_node,
            });
        }

        // Initialize per-target counters
        let mut target_counts: std::collections::BTreeMap<u64, u64> =
            std::collections::BTreeMap::new();
        let mut target_bytes: std::collections::BTreeMap<u64, u64> =
            std::collections::BTreeMap::new();

        for target in targets {
            target_counts.insert(target.0, 0);
            target_bytes.insert(target.0, 0);
        }

        // Assign each object to a placement target
        let mut total_bytes: u64 = 0;
        for &(object_id, size) in &objects {
            let target = ops
                .placement_target_for(self.plan.source_node, object_id, targets)
                .map_err(|e| MigrationError::TransferFailed {
                    source_node: self.plan.source_node,
                    target: MemberId::ZERO,
                    object_id,
                    reason: e,
                })?;

            *target_counts.entry(target.0).or_insert(0) += 1;
            *target_bytes.entry(target.0).or_insert(0) += size;
            total_bytes += size;
        }

        // Build the plan
        self.plan.total_objects = objects.len() as u64;
        self.plan.total_bytes = total_bytes;
        self.plan.targets = targets
            .iter()
            .map(|t| PlacementTarget {
                node_id: *t,
                expected_object_count: target_counts.get(&t.0).copied().unwrap_or(0),
                estimated_bytes: target_bytes.get(&t.0).copied().unwrap_or(0),
            })
            .collect();

        self.plan.validate()?;

        // Refresh progress to match the plan
        self.progress = MigrationProgress::new(&self.plan);

        Ok(&self.plan)
    }

    /// Validate the current plan without building a new one.
    pub fn validate_plan(&self) -> Result<(), MigrationError> {
        self.plan.validate()
    }

    /// Execute the migration: transfer all objects to their placement targets.
    ///
    /// Returns the final [`MigrationOutcome`] on success or a
    /// [`MigrationError`] on failure.
    pub fn execute(
        &mut self,
        ops: &mut dyn MigrationOps,
    ) -> Result<MigrationOutcome, MigrationError> {
        if self.plan.total_objects == 0 {
            return Err(MigrationError::NothingToMigrate {
                source_node: self.plan.source_node,
            });
        }

        // Enumerate objects and transfer each one
        let objects = ops.enumerate_objects(self.plan.source_node).map_err(|e| {
            MigrationError::TransferFailed {
                source_node: self.plan.source_node,
                target: MemberId::ZERO,
                object_id: 0,
                reason: e,
            }
        })?;

        for &(object_id, _size) in &objects {
            if self.cancelled {
                return Err(MigrationError::Cancelled {
                    source_node: self.plan.source_node,
                    objects_remaining: self.progress.objects_remaining,
                });
            }

            let target = ops
                .placement_target_for(self.plan.source_node, object_id, &self.plan.target_ids())
                .map_err(|e| MigrationError::TransferFailed {
                    source_node: self.plan.source_node,
                    target: MemberId::ZERO,
                    object_id,
                    reason: e,
                })?;

            // Transfer the object
            let bytes = ops
                .transfer_object(self.plan.source_node, target, object_id)
                .map_err(|e| MigrationError::TransferFailed {
                    source_node: self.plan.source_node,
                    target,
                    object_id,
                    reason: e,
                })?;

            // Verify checksum if enabled
            if self.plan.verify_checksums {
                match ops.verify_checksum(target, object_id) {
                    Ok(()) => {}
                    Err(_) => {
                        self.progress.record_checksum_failure(target);
                        // Continue with next object; checksum failures are
                        // recorded but non-fatal (retry is handled higher up)
                    }
                }
            }

            let receipt_id = ops
                .committed_placement_receipt_for(self.plan.source_node, target, object_id)
                .map_err(|e| MigrationError::PlacementReceiptMissing {
                    source_node: self.plan.source_node,
                    target,
                    object_id,
                    reason: e,
                })?;

            self.progress.record_migrated(target, bytes, receipt_id);
        }

        Ok(MigrationOutcome::from_progress(
            self.plan.source_node,
            &self.progress,
            self.progress.checksum_failures == 0,
        ))
    }

    /// Cancel an in-progress migration.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Return a summary of the migration outcome.
    #[must_use]
    pub fn outcome(&self) -> MigrationOutcome {
        MigrationOutcome::from_progress(
            self.plan.source_node,
            &self.progress,
            self.progress.is_complete() && self.progress.checksum_failures == 0,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn nid(id: u64) -> MemberId {
        MemberId::new(id)
    }

    // -------------------------------------------------------------------
    // MockMigrationOps
    // -------------------------------------------------------------------

    struct MockMigrationOps {
        objects: BTreeMap<u64, Vec<(u64, u64)>>, // node_id -> [(object_id, size)]
        placement: BTreeMap<u64, MemberId>,      // object_id -> target node
        transferred: Vec<(u64, MemberId, u64)>,  // (object_id, target, bytes)
        checksum_ok: bool,
        transfer_fails_for: Option<u64>, // object_id that fails transfer
        missing_receipt_for: Option<u64>,
    }

    impl MockMigrationOps {
        fn new() -> Self {
            Self {
                objects: BTreeMap::new(),
                placement: BTreeMap::new(),
                transferred: Vec::new(),
                checksum_ok: true,
                transfer_fails_for: None,
                missing_receipt_for: None,
            }
        }

        fn with_objects(mut self, node: u64, objs: Vec<(u64, u64)>) -> Self {
            self.objects.insert(node, objs);
            self
        }

        fn with_bad_checksums(mut self) -> Self {
            self.checksum_ok = false;
            self
        }

        fn with_failing_transfer(mut self, object_id: u64) -> Self {
            self.transfer_fails_for = Some(object_id);
            self
        }

        fn with_missing_receipt(mut self, object_id: u64) -> Self {
            self.missing_receipt_for = Some(object_id);
            self
        }
    }

    impl MigrationOps for MockMigrationOps {
        fn enumerate_objects(&self, source_node: MemberId) -> Result<Vec<(u64, u64)>, String> {
            Ok(self
                .objects
                .get(&source_node.0)
                .cloned()
                .unwrap_or_default())
        }

        fn placement_target_for(
            &self,
            _source_node: MemberId,
            object_id: u64,
            targets: &[MemberId],
        ) -> Result<MemberId, String> {
            if let Some(&target) = self.placement.get(&object_id) {
                if targets.contains(&target) {
                    return Ok(target);
                }
            }
            // Default: round-robin across targets
            if targets.is_empty() {
                return Err("no targets".to_string());
            }
            let idx = (object_id as usize) % targets.len();
            Ok(targets[idx])
        }

        fn transfer_object(
            &mut self,
            _source_node: MemberId,
            target: MemberId,
            object_id: u64,
        ) -> Result<u64, String> {
            if self.transfer_fails_for == Some(object_id) {
                return Err("simulated transfer failure".to_string());
            }
            let size = self
                .objects
                .values()
                .flatten()
                .find(|(id, _)| *id == object_id)
                .map(|(_, s)| *s)
                .unwrap_or(1024);
            self.transferred.push((object_id, target, size));
            Ok(size)
        }

        fn verify_checksum(&self, _target: MemberId, _object_id: u64) -> Result<(), String> {
            if self.checksum_ok {
                Ok(())
            } else {
                Err("checksum mismatch".to_string())
            }
        }

        fn committed_placement_receipt_for(
            &self,
            _source_node: MemberId,
            _target: MemberId,
            object_id: u64,
        ) -> Result<ReplicatedReceiptId, String> {
            if self.missing_receipt_for == Some(object_id) {
                return Err("receipt not committed".to_string());
            }
            Ok(ReplicatedReceiptId(object_id + 10_000))
        }
    }

    // -------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------

    #[test]
    fn migration_plan_validate_rejects_empty_targets() {
        let plan = MigrationPlan::new(nid(1));
        let err = plan.validate().unwrap_err();
        assert!(matches!(err, MigrationError::NoTargets { .. }));
    }

    #[test]
    fn migration_plan_validate_rejects_self_target() {
        let plan = MigrationPlan {
            source_node: nid(1),
            targets: vec![PlacementTarget::new(nid(1))],
            total_objects: 0,
            total_bytes: 0,
            verify_checksums: true,
        };
        let err = plan.validate().unwrap_err();
        assert!(matches!(err, MigrationError::SelfTarget { .. }));
    }

    #[test]
    fn migration_plan_validate_rejects_count_mismatch() {
        let plan = MigrationPlan {
            source_node: nid(1),
            targets: vec![PlacementTarget {
                node_id: nid(2),
                expected_object_count: 5,
                estimated_bytes: 0,
            }],
            total_objects: 10,
            total_bytes: 0,
            verify_checksums: true,
        };
        let err = plan.validate().unwrap_err();
        assert!(matches!(err, MigrationError::ObjectCountMismatch { .. }));
    }

    #[test]
    fn migration_plan_validate_accepts_valid() {
        let plan = MigrationPlan {
            source_node: nid(1),
            targets: vec![
                PlacementTarget {
                    node_id: nid(2),
                    expected_object_count: 3,
                    estimated_bytes: 300,
                },
                PlacementTarget {
                    node_id: nid(3),
                    expected_object_count: 2,
                    estimated_bytes: 200,
                },
            ],
            total_objects: 5,
            total_bytes: 500,
            verify_checksums: true,
        };
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn build_plan_from_objects() {
        let ops = MockMigrationOps::new()
            .with_objects(1, vec![(100, 1024), (101, 2048), (102, 512), (103, 768)]);

        let mut driver = MigrationDriver::new(nid(1));
        let targets = vec![nid(2), nid(3)];

        driver.build_plan(&ops, &targets).unwrap();

        let plan = driver.plan();
        assert_eq!(plan.total_objects, 4);
        assert_eq!(plan.total_bytes, 1024 + 2048 + 512 + 768);
        assert_eq!(plan.targets.len(), 2);
        // Round-robin: object 0->target[0], 1->target[1], 2->target[0], 3->target[1]
        let counts: Vec<u64> = plan
            .targets
            .iter()
            .map(|t| t.expected_object_count)
            .collect();
        assert_eq!(counts.iter().sum::<u64>(), 4);
    }

    #[test]
    fn build_plan_rejects_empty_objects() {
        let ops = MockMigrationOps::new().with_objects(1, vec![]);
        let mut driver = MigrationDriver::new(nid(1));
        let err = driver.build_plan(&ops, &[nid(2)]).unwrap_err();
        assert!(matches!(err, MigrationError::NothingToMigrate { .. }));
    }

    #[test]
    fn execute_migration_full() {
        let mut ops =
            MockMigrationOps::new().with_objects(1, vec![(10, 1024), (20, 2048), (30, 512)]);

        let mut driver = MigrationDriver::new(nid(1));
        let targets = vec![nid(2), nid(3)];
        driver.build_plan(&ops, &targets).unwrap();

        let outcome = driver.execute(&mut ops).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.objects_migrated, 3);
        assert_eq!(outcome.checksum_failures, 0);
        assert_eq!(
            outcome.placement_receipt_refs,
            vec![
                ReplicatedReceiptId(10_010),
                ReplicatedReceiptId(10_020),
                ReplicatedReceiptId(10_030)
            ]
        );
        assert_eq!(ops.transferred.len(), 3);
    }

    #[test]
    fn execute_migration_transfer_failure() {
        let mut ops = MockMigrationOps::new()
            .with_objects(1, vec![(10, 1024), (20, 2048)])
            .with_failing_transfer(20);

        let mut driver = MigrationDriver::new(nid(1));
        let targets = vec![nid(2)];
        driver.build_plan(&ops, &targets).unwrap();

        let err = driver.execute(&mut ops).unwrap_err();
        assert!(matches!(err, MigrationError::TransferFailed { .. }));
    }

    #[test]
    fn execute_migration_requires_committed_receipts() {
        let mut ops = MockMigrationOps::new()
            .with_objects(1, vec![(10, 1024), (20, 2048)])
            .with_missing_receipt(20);

        let mut driver = MigrationDriver::new(nid(1));
        let targets = vec![nid(2)];
        driver.build_plan(&ops, &targets).unwrap();

        let err = driver.execute(&mut ops).unwrap_err();
        assert!(matches!(
            err,
            MigrationError::PlacementReceiptMissing { .. }
        ));
    }

    #[test]
    fn execute_migration_checksum_failures() {
        let mut ops = MockMigrationOps::new()
            .with_objects(1, vec![(10, 1024), (20, 2048)])
            .with_bad_checksums();

        let mut driver = MigrationDriver::new(nid(1));
        let targets = vec![nid(2)];
        driver.build_plan(&ops, &targets).unwrap();

        let outcome = driver.execute(&mut ops).unwrap();
        // Objects are still migrated but checksum failures are recorded
        assert_eq!(outcome.objects_migrated, 2);
        assert_eq!(outcome.checksum_failures, 2);
        assert!(!outcome.success);
    }

    #[test]
    fn cancel_mid_migration() {
        let mut ops = MockMigrationOps::new()
            .with_objects(1, vec![(10, 1024), (20, 2048), (30, 512), (40, 768)]);

        let mut driver = MigrationDriver::new(nid(1));
        let targets = vec![nid(2)];
        driver.build_plan(&ops, &targets).unwrap();

        // We can't easily interrupt loop iteration, but we can cancel before
        // execute and verify cancellation state
        driver.cancel();
        assert!(driver.is_cancelled());

        let err = driver.execute(&mut ops).unwrap_err();
        assert!(matches!(err, MigrationError::Cancelled { .. }));
    }

    #[test]
    fn migration_progress_tracks_correctly() {
        let plan = MigrationPlan {
            source_node: nid(1),
            targets: vec![
                PlacementTarget {
                    node_id: nid(2),
                    expected_object_count: 3,
                    estimated_bytes: 3000,
                },
                PlacementTarget {
                    node_id: nid(3),
                    expected_object_count: 2,
                    estimated_bytes: 2000,
                },
            ],
            total_objects: 5,
            total_bytes: 5000,
            verify_checksums: true,
        };

        let mut progress = MigrationProgress::new(&plan);
        assert_eq!(progress.objects_remaining, 5);
        assert_eq!(progress.bytes_remaining, 5000);
        assert!(!progress.is_complete());
        assert!(progress.fraction() < 0.01);

        progress.record_migrated(nid(2), 1024, ReplicatedReceiptId(1));
        assert_eq!(progress.objects_migrated, 1);
        assert_eq!(progress.objects_remaining, 4);
        assert_eq!(progress.bytes_transferred, 1024);
        assert_eq!(progress.bytes_remaining, 3976);
        assert_eq!(progress.fraction(), 0.2);
        assert_eq!(
            progress.placement_receipt_refs,
            vec![ReplicatedReceiptId(1)]
        );

        // Record 4 more to complete
        progress.record_migrated(nid(2), 1024, ReplicatedReceiptId(2));
        progress.record_migrated(nid(2), 1024, ReplicatedReceiptId(3));
        progress.record_migrated(nid(3), 1024, ReplicatedReceiptId(4));
        progress.record_migrated(nid(3), 1024, ReplicatedReceiptId(5));
        assert!(progress.is_complete());
        assert_eq!(progress.fraction(), 1.0);
    }

    #[test]
    fn per_target_progress_individual() {
        let plan = MigrationPlan {
            source_node: nid(1),
            targets: vec![
                PlacementTarget {
                    node_id: nid(2),
                    expected_object_count: 2,
                    estimated_bytes: 2000,
                },
                PlacementTarget {
                    node_id: nid(3),
                    expected_object_count: 1,
                    estimated_bytes: 1000,
                },
            ],
            total_objects: 3,
            total_bytes: 3000,
            verify_checksums: true,
        };

        let mut progress = MigrationProgress::new(&plan);

        progress.record_migrated(nid(2), 1000, ReplicatedReceiptId(1));
        progress.record_migrated(nid(2), 1000, ReplicatedReceiptId(2));
        progress.record_migrated(nid(3), 1000, ReplicatedReceiptId(3));

        let t2 = progress.per_target.get(&2).unwrap();
        assert!(t2.is_complete());
        assert_eq!(t2.objects_migrated, 2);

        let t3 = progress.per_target.get(&3).unwrap();
        assert!(t3.is_complete());
        assert_eq!(t3.objects_migrated, 1);
    }

    #[test]
    fn checksum_failure_tracking() {
        let plan = MigrationPlan {
            source_node: nid(1),
            targets: vec![PlacementTarget {
                node_id: nid(2),
                expected_object_count: 1,
                estimated_bytes: 1000,
            }],
            total_objects: 1,
            total_bytes: 1000,
            verify_checksums: true,
        };

        let mut progress = MigrationProgress::new(&plan);
        progress.record_checksum_failure(nid(2));
        assert_eq!(progress.checksum_failures, 1);
        assert_eq!(progress.per_target.get(&2).unwrap().checksum_failures, 1);
    }

    #[test]
    fn migration_outcome_summary() {
        let mut ops = MockMigrationOps::new().with_objects(100, vec![(1, 512), (2, 512), (3, 512)]);

        let mut driver = MigrationDriver::new(nid(100));
        driver.build_plan(&ops, &[nid(200)]).unwrap();
        driver.execute(&mut ops).unwrap();

        let outcome = driver.outcome();
        assert_eq!(outcome.source_node, nid(100));
        assert_eq!(outcome.objects_migrated, 3);
        assert!(outcome.success);
    }
}
