//! PostHealPlacementRecompute: recomputes placement after partition healing,
//! triggers anti-entropy scan, and rebuilds replicas as needed.
//!
//! After a partition heals:
//! 1. Minority members rejoin as Learners, catch up, and are promoted to Voters
//! 2. Placement must be recomputed to include the rejoined members as targets
//! 3. An anti-entropy scan finds any stale or missing replicas
//! 4. Missing replicas are rebuilt on the rejoined members
//!
//! This module coordinates the post-heal workflow, deferring to the
//! anti-entropy auditor (#888) and rebuild planner (#893) for the
//! actual scan and rebuild operations.

use crate::types::{now_millis, ReconciliationStrategy};
use tidefs_membership_epoch::{EpochId, MemberId};

// ---------------------------------------------------------------------------
// PostHealPlacementRecompute
// ---------------------------------------------------------------------------

/// Coordinates post-heal placement recomputation, anti-entropy scan,
/// and replica rebuild.
///
/// ## Lifecycle
///
/// 1. **Placement recompute**: After healing completes, the full member set
///    is available again. Placement must recompute to include previously
///    partitioned members as replica targets.
/// 2. **Anti-entropy scan**: The anti-entropy auditor (#888) scans for
///    stale or missing replicas on rejoined members.
/// 3. **Rebuild**: The rebuild planner (#893) rebuilds any replicas that
///    are missing or stale after the partition.
/// 4. **Verification**: Rebuilt replicas are verified against quorum-side
///    state.
pub struct PostHealPlacementRecompute {
    /// My member ID.
    pub my_id: MemberId,
    /// The epoch after healing is complete (joint config epoch).
    pub post_heal_epoch: Option<EpochId>,
    /// Members that rejoined after the partition.
    pub rejoined_members: Vec<MemberId>,
    /// Full member set after healing (original + rejoined).
    pub full_member_set: Vec<MemberId>,
    /// Whether placement recompute is needed.
    pub placement_recompute_needed: bool,
    /// Whether anti-entropy scan is needed.
    pub anti_entropy_scan_needed: bool,
    /// Whether replica rebuild is needed.
    pub rebuild_needed: bool,
    /// The reconciliation strategy that was selected.
    pub reconciliation_strategy: Option<ReconciliationStrategy>,
    /// Whether placement recompute has been triggered.
    pub placement_recompute_triggered: bool,
    /// Whether anti-entropy scan has been triggered.
    pub anti_entropy_scan_triggered: bool,
    /// Whether rebuild has been triggered.
    pub rebuild_triggered: bool,
    /// Whether all post-heal operations have completed.
    pub all_complete: bool,
    /// Timestamps for tracking.
    pub started_at_millis: u64,
    pub completed_at_millis: u64,
}

impl PostHealPlacementRecompute {
    /// Create a new post-heal placement recompute instance.
    pub fn new(my_id: MemberId) -> Self {
        Self {
            my_id,
            post_heal_epoch: None,
            rejoined_members: Vec::new(),
            full_member_set: Vec::new(),
            placement_recompute_needed: false,
            anti_entropy_scan_needed: false,
            rebuild_needed: false,
            reconciliation_strategy: None,
            placement_recompute_triggered: false,
            anti_entropy_scan_triggered: false,
            rebuild_triggered: false,
            all_complete: false,
            started_at_millis: 0,
            completed_at_millis: 0,
        }
    }

    /// Begin post-heal operations after healing completes.
    ///
    /// Determines what needs to happen based on the reconciliation strategy
    /// and the set of rejoined members.
    pub fn begin(
        &mut self,
        post_heal_epoch: EpochId,
        rejoined_members: Vec<MemberId>,
        full_member_set: Vec<MemberId>,
        reconciliation_strategy: &ReconciliationStrategy,
    ) {
        self.post_heal_epoch = Some(post_heal_epoch);
        self.rejoined_members = rejoined_members;
        self.full_member_set = full_member_set;
        self.reconciliation_strategy = Some(reconciliation_strategy.clone());
        self.started_at_millis = now_millis();
        self.all_complete = false;

        // Always recompute placement after members rejoin
        self.placement_recompute_needed = !self.rejoined_members.is_empty();

        // Anti-entropy scan is needed if there was any divergence
        self.anti_entropy_scan_needed =
            !matches!(reconciliation_strategy, ReconciliationStrategy::NoneNeeded);

        // Rebuild is needed if there were conflicts or divergence
        self.rebuild_needed = matches!(
            reconciliation_strategy,
            ReconciliationStrategy::FullCatchup { .. } | ReconciliationStrategy::Scoped { .. }
        );

        // If nothing is needed, mark as complete immediately
        if !self.placement_recompute_needed
            && !self.anti_entropy_scan_needed
            && !self.rebuild_needed
        {
            self.all_complete = true;
            self.completed_at_millis = crate::types::now_millis();
        }
    }

    /// Mark placement recompute as triggered.
    ///
    /// Called when the placement planner (#892) has recomputed placement
    /// targets to include the rejoined members.
    pub fn placement_recomputed(&mut self) {
        self.placement_recompute_triggered = true;
        self.check_completion();
    }

    /// Mark anti-entropy scan as triggered.
    ///
    /// Called when the anti-entropy auditor (#888) has been instructed
    /// to scan rejoined members for stale/missing replicas.
    pub fn anti_entropy_scan_triggered(&mut self) {
        self.anti_entropy_scan_triggered = true;
        self.check_completion();
    }

    /// Mark rebuild as triggered.
    ///
    /// Called when the rebuild planner (#893) has been instructed to
    /// rebuild missing/stale replicas on rejoined members.
    pub fn rebuild_triggered(&mut self) {
        self.rebuild_triggered = true;
        self.check_completion();
    }

    /// Mark anti-entropy scan as complete (no issues found or all fixed).
    pub fn anti_entropy_scan_complete(&mut self) {
        self.anti_entropy_scan_triggered = true;
        self.check_completion();
    }

    /// Mark rebuild as complete.
    pub fn rebuild_complete(&mut self) {
        self.rebuild_triggered = true;
        // After rebuild, all operations should be complete
        self.placement_recompute_triggered = true;
        self.anti_entropy_scan_triggered = true;
        self.check_completion();
    }

    /// Whether all needed post-heal operations have been triggered.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.all_complete
    }

    /// Get a summary of what still needs to be done.
    #[must_use]
    pub fn pending_operations(&self) -> PostHealPending {
        PostHealPending {
            placement_needed: self.placement_recompute_needed
                && !self.placement_recompute_triggered,
            anti_entropy_needed: self.anti_entropy_scan_needed && !self.anti_entropy_scan_triggered,
            rebuild_needed: self.rebuild_needed && !self.rebuild_triggered,
        }
    }

    /// Whether witness-only members rejoined (no data to reconcile, just
    /// placement recompute).
    #[must_use]
    pub fn is_witness_only_rejoin(&self) -> bool {
        matches!(
            &self.reconciliation_strategy,
            Some(ReconciliationStrategy::NoneNeeded)
        ) && !self.rejoined_members.is_empty()
    }

    /// Get the list of members that need replica rebuilds targeting them.
    #[must_use]
    pub fn members_needing_rebuild(&self) -> Vec<MemberId> {
        if self.rebuild_needed {
            self.rejoined_members.clone()
        } else {
            Vec::new()
        }
    }

    /// Check completion and set flag if all done.
    fn check_completion(&mut self) {
        let placement_done = !self.placement_recompute_needed || self.placement_recompute_triggered;
        let ae_done = !self.anti_entropy_scan_needed || self.anti_entropy_scan_triggered;
        let rebuild_done = !self.rebuild_needed || self.rebuild_triggered;

        if placement_done && ae_done && rebuild_done && !self.all_complete {
            self.all_complete = true;
            self.completed_at_millis = now_millis();
        }
    }

    /// Reset for the next partition cycle.
    pub fn reset(&mut self) {
        self.post_heal_epoch = None;
        self.rejoined_members.clear();
        self.full_member_set.clear();
        self.placement_recompute_needed = false;
        self.anti_entropy_scan_needed = false;
        self.rebuild_needed = false;
        self.reconciliation_strategy = None;
        self.placement_recompute_triggered = false;
        self.anti_entropy_scan_triggered = false;
        self.rebuild_triggered = false;
        self.all_complete = false;
        self.started_at_millis = 0;
        self.completed_at_millis = 0;
    }
}

// ---------------------------------------------------------------------------
// PostHealPending
// ---------------------------------------------------------------------------

/// Summary of pending post-heal operations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PostHealPending {
    pub placement_needed: bool,
    pub anti_entropy_needed: bool,
    pub rebuild_needed: bool,
}

impl PostHealPending {
    /// Whether any operations are still pending.
    #[must_use]
    pub fn any_pending(&self) -> bool {
        self.placement_needed || self.anti_entropy_needed || self.rebuild_needed
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ReconciliationStrategy;

    #[test]
    fn test_initial_state() {
        let p = PostHealPlacementRecompute::new(MemberId::new(1));
        assert!(!p.is_complete());
        assert!(!p.pending_operations().any_pending());
    }

    #[test]
    fn test_begin_with_divergence_needs_all() {
        let mut p = PostHealPlacementRecompute::new(MemberId::new(1));
        p.begin(
            EpochId::new(5),
            vec![MemberId::new(2), MemberId::new(3)],
            vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
            &ReconciliationStrategy::FullCatchup {
                missed_epochs: vec![EpochId::new(3), EpochId::new(4)],
                estimated_receipts: 100,
            },
        );
        assert!(p.placement_recompute_needed);
        assert!(p.anti_entropy_scan_needed);
        assert!(p.rebuild_needed);
        assert!(!p.is_complete());
    }

    #[test]
    fn test_witness_only_rejoin() {
        let mut p = PostHealPlacementRecompute::new(MemberId::new(1));
        p.begin(
            EpochId::new(5),
            vec![MemberId::new(2)],
            vec![MemberId::new(1), MemberId::new(2)],
            &ReconciliationStrategy::NoneNeeded,
        );
        assert!(p.is_witness_only_rejoin());
        assert!(p.placement_recompute_needed);
        assert!(!p.anti_entropy_scan_needed);
        assert!(!p.rebuild_needed);
    }

    #[test]
    fn test_completion_after_all_triggered() {
        let mut p = PostHealPlacementRecompute::new(MemberId::new(1));
        p.begin(
            EpochId::new(5),
            vec![MemberId::new(2)],
            vec![MemberId::new(1), MemberId::new(2)],
            &ReconciliationStrategy::FullCatchup {
                missed_epochs: vec![EpochId::new(4)],
                estimated_receipts: 10,
            },
        );
        p.placement_recomputed();
        assert!(!p.is_complete());

        p.anti_entropy_scan_triggered();
        p.rebuild_triggered();
        assert!(p.is_complete());
    }

    #[test]
    fn test_no_pending_when_nothing_needed() {
        let mut p = PostHealPlacementRecompute::new(MemberId::new(1));
        p.begin(
            EpochId::new(5),
            vec![],
            vec![MemberId::new(1)],
            &ReconciliationStrategy::NoneNeeded,
        );
        assert!(!p.placement_recompute_needed);
        assert!(!p.anti_entropy_scan_needed);
        assert!(!p.rebuild_needed);
        assert!(p.is_complete());
    }

    #[test]
    fn test_members_needing_rebuild() {
        let mut p = PostHealPlacementRecompute::new(MemberId::new(1));
        p.begin(
            EpochId::new(5),
            vec![MemberId::new(3), MemberId::new(4)],
            vec![
                MemberId::new(1),
                MemberId::new(2),
                MemberId::new(3),
                MemberId::new(4),
            ],
            &ReconciliationStrategy::Scoped {
                receipts_to_ship: vec![10, 11],
                receipts_to_rollback: vec![8, 9],
            },
        );
        assert_eq!(
            p.members_needing_rebuild(),
            vec![MemberId::new(3), MemberId::new(4)]
        );
    }

    #[test]
    fn test_reset_clears_all() {
        let mut p = PostHealPlacementRecompute::new(MemberId::new(1));
        p.begin(
            EpochId::new(5),
            vec![MemberId::new(2)],
            vec![MemberId::new(1), MemberId::new(2)],
            &ReconciliationStrategy::FullCatchup {
                missed_epochs: vec![EpochId::new(4)],
                estimated_receipts: 10,
            },
        );
        p.placement_recomputed();
        p.anti_entropy_scan_complete();
        p.rebuild_complete();
        assert!(p.is_complete());

        p.reset();
        assert!(!p.is_complete());
        assert!(p.rejoined_members.is_empty());
        assert!(p.post_heal_epoch.is_none());
    }

    #[test]
    fn test_pending_operations_report() {
        let mut p = PostHealPlacementRecompute::new(MemberId::new(1));
        p.begin(
            EpochId::new(5),
            vec![MemberId::new(2)],
            vec![MemberId::new(1), MemberId::new(2)],
            &ReconciliationStrategy::FullCatchup {
                missed_epochs: vec![EpochId::new(4)],
                estimated_receipts: 10,
            },
        );

        let pending = p.pending_operations();
        assert!(pending.placement_needed);
        assert!(pending.anti_entropy_needed);
        assert!(pending.rebuild_needed);
        assert!(pending.any_pending());

        p.placement_recomputed();
        let pending2 = p.pending_operations();
        assert!(!pending2.placement_needed);
        assert!(pending2.any_pending());
    }
}
