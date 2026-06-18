// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Partition runtime types: hazard classes, partition state, audit records.

use serde::{Deserialize, Serialize};
use tidefs_membership_epoch::{EpochId, MemberId, SplitBrainHazardRecord};

// ---------------------------------------------------------------------------
// Hazard classification
// ---------------------------------------------------------------------------

/// Which side of a partition this node is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartitionHazardClass {
    /// This side holds quorum — continues operating.
    QuorumSide,
    /// This side is the minority — must freeze / quarantine.
    MinoritySide,
    /// Even split — neither side has quorum, escalate to operator.
    PartitionAmbiguous,
}

impl PartitionHazardClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QuorumSide => "hazard.partition_runtime.quorum_side.h0",
            Self::MinoritySide => "hazard.partition_runtime.minority_side.h1",
            Self::PartitionAmbiguous => "hazard.partition_runtime.partition_ambiguous.h2",
        }
    }
}

// ---------------------------------------------------------------------------
// Partition state
// ---------------------------------------------------------------------------

/// Runtime partition state for the local node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartitionState {
    /// No partition detected — cluster is fully connected.
    Connected,
    /// Partition suspected — gathering indirect confirmation.
    Suspecting {
        suspects: Vec<PartitionSuspect>,
        since_millis: u64,
    },
    /// Partition confirmed — this side is the quorum side.
    QuorumSideActive {
        minority_members: Vec<MemberId>,
        new_epoch: EpochId,
        since_millis: u64,
    },
    /// Partition confirmed — this side is minority; fenced.
    MinorityFenced {
        quorum_side_voter_count: usize,
        since_millis: u64,
    },
    /// Neither side has quorum — escalated to operator.
    AmbiguousHalted {
        sides: Vec<Vec<MemberId>>,
        since_millis: u64,
    },
    /// Partition healed — minority members rejoining as Learners.
    Healing {
        joint_epoch: EpochId,
        rejoining_members: Vec<MemberId>,
        since_millis: u64,
    },
}

impl PartitionState {
    #[must_use]
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected)
    }

    #[must_use]
    pub fn is_fenced(&self) -> bool {
        matches!(self, Self::MinorityFenced { .. })
    }

    #[must_use]
    pub fn can_accept_writes(&self) -> bool {
        matches!(self, Self::Connected | Self::QuorumSideActive { .. })
    }

    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Connected => "state.partition_runtime.connected.s0",
            Self::Suspecting { .. } => "state.partition_runtime.suspecting.s1",
            Self::QuorumSideActive { .. } => "state.partition_runtime.quorum_side_active.s2",
            Self::MinorityFenced { .. } => "state.partition_runtime.minority_fenced.s3",
            Self::AmbiguousHalted { .. } => "state.partition_runtime.ambiguous_halted.s4",
            Self::Healing { .. } => "state.partition_runtime.healing.s5",
        }
    }
}

/// A suspected partition member with validation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionSuspect {
    pub member_id: MemberId,
    pub missed_pings: u32,
    pub indirect_confirmations: u32,
    pub last_seen_millis: u64,
}

// ---------------------------------------------------------------------------
// Reachability matrix
// ---------------------------------------------------------------------------

/// Reachability matrix entry: which peers each known peer can reach.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachabilityEntry {
    pub observer: MemberId,
    pub reachable: Vec<MemberId>,
    pub observed_at_millis: u64,
    pub epoch: EpochId,
}

/// Full reachability matrix used to compute partition sides.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachabilityMatrix {
    pub entries: Vec<ReachabilityEntry>,
    pub computed_at_millis: u64,
}

impl ReachabilityMatrix {
    /// Compute connected components in the reachability graph.
    #[must_use]
    pub fn connected_components(&self) -> Vec<Vec<MemberId>> {
        let mut adjacency: std::collections::BTreeMap<MemberId, Vec<MemberId>> =
            std::collections::BTreeMap::new();
        for entry in &self.entries {
            adjacency
                .entry(entry.observer)
                .or_default()
                .extend(entry.reachable.iter().copied());
        }

        let mut visited = std::collections::BTreeSet::new();
        let mut components = Vec::new();

        for &node in adjacency.keys() {
            if visited.contains(&node) {
                continue;
            }
            let mut component = Vec::new();
            let mut stack = vec![node];
            while let Some(current) = stack.pop() {
                if visited.contains(&current) {
                    continue;
                }
                visited.insert(current);
                component.push(current);
                if let Some(neighbors) = adjacency.get(&current) {
                    for &neighbor in neighbors {
                        if !visited.contains(&neighbor) {
                            stack.push(neighbor);
                        }
                    }
                }
            }
            component.sort();
            components.push(component);
        }
        components.sort_by_key(|c| c.len());
        components.reverse();
        components
    }

    /// Determine the largest connected component.
    #[must_use]
    pub fn largest_component(&self) -> Option<Vec<MemberId>> {
        self.connected_components().into_iter().next()
    }
}

// ---------------------------------------------------------------------------
// Partition validation
// ---------------------------------------------------------------------------

/// Partition event emitted for operator visibility and audit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionEvent {
    pub event_id: u64,
    pub event_class: PartitionEventClass,
    pub hazard_class: PartitionHazardClass,
    pub epoch: EpochId,
    pub partition_members: Vec<MemberId>,
    pub quorum_side_members: Vec<MemberId>,
    pub minority_side_members: Vec<MemberId>,
    pub split_brain_hazard: Option<SplitBrainHazardRecord>,
    pub emitted_at_millis: u64,
    pub digest: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartitionEventClass {
    PartitionDetected,
    QuorumSideConfirmed,
    MinorityFenced,
    AmbiguousHalted,
    HealingStarted,
    HealingComplete,
    SplitBrainHazardEmitted,
}

impl PartitionEventClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PartitionDetected => "event.partition_runtime.partition_detected.e0",
            Self::QuorumSideConfirmed => "event.partition_runtime.quorum_side_confirmed.e1",
            Self::MinorityFenced => "event.partition_runtime.minority_fenced.e2",
            Self::AmbiguousHalted => "event.partition_runtime.ambiguous_halted.e3",
            Self::HealingStarted => "event.partition_runtime.healing_started.e4",
            Self::HealingComplete => "event.partition_runtime.healing_complete.e5",
            Self::SplitBrainHazardEmitted => {
                "event.partition_runtime.split_brain_hazard_emitted.e6"
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Reconciliation types
// ---------------------------------------------------------------------------

/// Divergence classification after partition heal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DivergenceClass {
    None,
    Conflicts {
        conflicting_receipts: Vec<u64>,
        conflict_count: usize,
    },
    Divergent {
        minority_receipt_count: usize,
        quorum_side_receipt_count: usize,
    },
}

/// Receipt frontier: the set of receipts known to a side.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptFrontier {
    pub side: PartitionHazardClass,
    pub members: Vec<MemberId>,
    pub receipt_ids: Vec<u64>,
    pub frontier_epoch: EpochId,
    pub frontier_millis: u64,
}

/// Reconciliation strategy selected after analyzing divergence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReconciliationStrategy {
    NoneNeeded,
    FullCatchup {
        missed_epochs: Vec<EpochId>,
        estimated_receipts: usize,
    },
    Scoped {
        receipts_to_ship: Vec<u64>,
        receipts_to_rollback: Vec<u64>,
    },
    OperatorEscalation {
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Partition fence state
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionFence {
    pub publication_frozen: bool,
    pub leases_frozen: bool,
    pub receipts_frozen: bool,
    pub authority_homes_invalidated: bool,
    pub fenced_heads: Vec<u64>,
    pub fenced_at_millis: u64,
}

impl PartitionFence {
    pub fn raise_all() -> Self {
        Self {
            publication_frozen: true,
            leases_frozen: true,
            receipts_frozen: true,
            authority_homes_invalidated: true,
            fenced_heads: Vec::new(),
            fenced_at_millis: now_millis(),
        }
    }

    pub fn lower_all(&mut self) {
        self.publication_frozen = false;
        self.leases_frozen = false;
        self.receipts_frozen = false;
        self.authority_homes_invalidated = false;
        self.fenced_heads.clear();
    }

    #[must_use]
    pub fn is_any_raised(&self) -> bool {
        self.publication_frozen
            || self.leases_frozen
            || self.receipts_frozen
            || self.authority_homes_invalidated
    }
}

// ---------------------------------------------------------------------------
// Drift-adaptive thresholds
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PartitionDetectionConfig {
    pub base_suspicion_timeout_ms: u64,
    pub drift_multiplier: f64,
    pub min_indirect_confirmations: u32,
    pub indirect_ping_count: usize,
    pub suspicion_rounds_before_partition: u32,
    pub heartbeat_epoch_window_ms: u64,
    pub deadline_escalation_factor: f64,
    pub max_timeout_ms: u64,
}

impl Default for PartitionDetectionConfig {
    fn default() -> Self {
        Self {
            base_suspicion_timeout_ms: 2_000,
            drift_multiplier: 1.5,
            min_indirect_confirmations: 2,
            indirect_ping_count: 3,
            suspicion_rounds_before_partition: 3,
            heartbeat_epoch_window_ms: 10_000,
            deadline_escalation_factor: 1.2,
            max_timeout_ms: 30_000,
        }
    }
}

impl PartitionDetectionConfig {
    #[must_use]
    pub fn effective_timeout_ms(&self, observed_drift_ppm: f64) -> u64 {
        let base = self.base_suspicion_timeout_ms as f64;
        let with_drift = base * self.drift_multiplier * (1.0 + observed_drift_ppm / 1_000_000.0);
        with_drift.min(self.max_timeout_ms as f64) as u64
    }

    #[must_use]
    pub fn escalated_deadline_ms(&self, round: u32, observed_drift_ppm: f64) -> u64 {
        let base = self.effective_timeout_ms(observed_drift_ppm) as f64;
        let escalated = base * self.deadline_escalation_factor.powi(round as i32);
        escalated.min(self.max_timeout_ms as f64) as u64
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) fn now_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub(crate) fn derive_record_id(a: u64, b: u64, c: u64) -> u64 {
    let mut s = a.wrapping_mul(0x9E3779B9);
    s = s.wrapping_add(b).wrapping_mul(0x9E3779B9);
    s = s.wrapping_add(c).wrapping_mul(0x9E3779B9);
    s
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── PartitionHazardClass ───────────────────────────────────────

    #[test]
    fn hazard_class_as_str() {
        assert_eq!(
            PartitionHazardClass::QuorumSide.as_str(),
            "hazard.partition_runtime.quorum_side.h0"
        );
        assert_eq!(
            PartitionHazardClass::MinoritySide.as_str(),
            "hazard.partition_runtime.minority_side.h1"
        );
        assert_eq!(
            PartitionHazardClass::PartitionAmbiguous.as_str(),
            "hazard.partition_runtime.partition_ambiguous.h2"
        );
    }

    // ── PartitionState predicates ──────────────────────────────────

    #[test]
    fn partition_state_is_connected() {
        assert!(PartitionState::Connected.is_connected());
        assert!(!PartitionState::Suspecting {
            suspects: vec![],
            since_millis: 0
        }
        .is_connected());
        assert!(!PartitionState::MinorityFenced {
            quorum_side_voter_count: 3,
            since_millis: 0
        }
        .is_connected());
    }

    #[test]
    fn partition_state_is_fenced() {
        assert!(PartitionState::MinorityFenced {
            quorum_side_voter_count: 3,
            since_millis: 0
        }
        .is_fenced());
        assert!(!PartitionState::Connected.is_fenced());
        assert!(!PartitionState::QuorumSideActive {
            minority_members: vec![],
            new_epoch: EpochId(1),
            since_millis: 0
        }
        .is_fenced());
    }

    #[test]
    fn partition_state_can_accept_writes() {
        assert!(PartitionState::Connected.can_accept_writes());
        assert!(PartitionState::QuorumSideActive {
            minority_members: vec![],
            new_epoch: EpochId(1),
            since_millis: 0
        }
        .can_accept_writes());
        assert!(!PartitionState::MinorityFenced {
            quorum_side_voter_count: 3,
            since_millis: 0
        }
        .can_accept_writes());
        assert!(!PartitionState::Suspecting {
            suspects: vec![],
            since_millis: 0
        }
        .can_accept_writes());
        assert!(!PartitionState::AmbiguousHalted {
            sides: vec![],
            since_millis: 0
        }
        .can_accept_writes());
        assert!(!PartitionState::Healing {
            joint_epoch: EpochId(1),
            rejoining_members: vec![],
            since_millis: 0
        }
        .can_accept_writes());
    }

    #[test]
    fn partition_state_as_str() {
        assert_eq!(
            PartitionState::Connected.as_str(),
            "state.partition_runtime.connected.s0"
        );
        assert_eq!(
            PartitionState::Suspecting {
                suspects: vec![],
                since_millis: 0
            }
            .as_str(),
            "state.partition_runtime.suspecting.s1"
        );
        assert_eq!(
            PartitionState::QuorumSideActive {
                minority_members: vec![],
                new_epoch: EpochId(1),
                since_millis: 0
            }
            .as_str(),
            "state.partition_runtime.quorum_side_active.s2"
        );
        assert_eq!(
            PartitionState::MinorityFenced {
                quorum_side_voter_count: 3,
                since_millis: 0
            }
            .as_str(),
            "state.partition_runtime.minority_fenced.s3"
        );
        assert_eq!(
            PartitionState::AmbiguousHalted {
                sides: vec![],
                since_millis: 0
            }
            .as_str(),
            "state.partition_runtime.ambiguous_halted.s4"
        );
        assert_eq!(
            PartitionState::Healing {
                joint_epoch: EpochId(1),
                rejoining_members: vec![],
                since_millis: 0
            }
            .as_str(),
            "state.partition_runtime.healing.s5"
        );
    }

    // ── ReachabilityMatrix ─────────────────────────────────────────

    #[test]
    fn reachability_matrix_empty() {
        let matrix = ReachabilityMatrix::default();
        let components = matrix.connected_components();
        assert!(components.is_empty());
    }

    #[test]
    fn reachability_matrix_single_component() {
        let matrix = ReachabilityMatrix {
            entries: vec![
                ReachabilityEntry {
                    observer: MemberId(1),
                    reachable: vec![MemberId(2), MemberId(3)],
                    observed_at_millis: 1000,
                    epoch: EpochId(1),
                },
                ReachabilityEntry {
                    observer: MemberId(2),
                    reachable: vec![MemberId(1), MemberId(3)],
                    observed_at_millis: 1000,
                    epoch: EpochId(1),
                },
                ReachabilityEntry {
                    observer: MemberId(3),
                    reachable: vec![MemberId(1)],
                    observed_at_millis: 1000,
                    epoch: EpochId(1),
                },
            ],
            computed_at_millis: 1000,
        };
        let components = matrix.connected_components();
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].len(), 3);
    }

    #[test]
    fn reachability_matrix_partition_two_components() {
        // Nodes 1 and 2 can reach each other; node 3 is isolated.
        let matrix = ReachabilityMatrix {
            entries: vec![
                ReachabilityEntry {
                    observer: MemberId(1),
                    reachable: vec![MemberId(2)],
                    observed_at_millis: 1000,
                    epoch: EpochId(1),
                },
                ReachabilityEntry {
                    observer: MemberId(2),
                    reachable: vec![MemberId(1)],
                    observed_at_millis: 1000,
                    epoch: EpochId(1),
                },
                ReachabilityEntry {
                    observer: MemberId(3),
                    reachable: vec![],
                    observed_at_millis: 1000,
                    epoch: EpochId(1),
                },
            ],
            computed_at_millis: 1000,
        };
        let components = matrix.connected_components();
        assert_eq!(components.len(), 2);
        let mut sizes: Vec<usize> = components.iter().map(|c| c.len()).collect();
        sizes.sort();
        assert_eq!(sizes, vec![1, 2]);
    }

    // ── PartitionFence ─────────────────────────────────────────────

    #[test]
    fn partition_fence_raise_all() {
        let fence = PartitionFence::raise_all();
        assert!(fence.publication_frozen);
        assert!(fence.leases_frozen);
        assert!(fence.receipts_frozen);
        assert!(fence.authority_homes_invalidated);
        assert!(fence.is_any_raised());
    }

    #[test]
    fn partition_fence_lower_all() {
        let mut fence = PartitionFence::raise_all();
        fence.lower_all();
        assert!(!fence.publication_frozen);
        assert!(!fence.leases_frozen);
        assert!(!fence.receipts_frozen);
        assert!(!fence.authority_homes_invalidated);
        assert!(!fence.is_any_raised());
    }

    #[test]
    fn partition_fence_is_any_raised_partial() {
        let mut fence = PartitionFence::default();
        assert!(!fence.is_any_raised());
        fence.publication_frozen = true;
        assert!(fence.is_any_raised());
        fence.publication_frozen = false;
        fence.receipts_frozen = true;
        assert!(fence.is_any_raised());
    }

    #[test]
    fn partition_fence_default_is_clear() {
        let fence = PartitionFence::default();
        assert!(!fence.is_any_raised());
        assert!(fence.fenced_heads.is_empty());
    }

    // ── PartitionDetectionConfig ───────────────────────────────────

    #[test]
    fn detection_config_defaults() {
        let cfg = PartitionDetectionConfig::default();
        assert_eq!(cfg.base_suspicion_timeout_ms, 2_000);
        assert_eq!(cfg.min_indirect_confirmations, 2);
        assert_eq!(cfg.indirect_ping_count, 3);
        assert_eq!(cfg.suspicion_rounds_before_partition, 3);
        assert_eq!(cfg.max_timeout_ms, 30_000);
    }

    #[test]
    fn effective_timeout_ms_no_drift() {
        let cfg = PartitionDetectionConfig::default();
        // base=2000, drift_multiplier=1.5 => 2000 * 1.5 * 1.0 = 3000
        let timeout = cfg.effective_timeout_ms(0.0);
        assert_eq!(timeout, 3000);
    }

    #[test]
    fn effective_timeout_ms_with_drift() {
        let cfg = PartitionDetectionConfig::default();
        // base=2000, drift_multiplier=1.5, observed_drift=1_000_000 ppm (100% drift)
        // => 2000 * 1.5 * (1.0 + 1.0) = 2000 * 1.5 * 2.0 = 6000
        let timeout = cfg.effective_timeout_ms(1_000_000.0);
        assert_eq!(timeout, 6000);
    }

    #[test]
    fn effective_timeout_ms_clamped_to_max() {
        let cfg = PartitionDetectionConfig::default();
        // Huge drift should be clamped to max_timeout_ms = 30_000
        let timeout = cfg.effective_timeout_ms(1_000_000_000.0);
        assert_eq!(timeout, 30_000);
    }

    #[test]
    fn escalated_deadline_ms_round_0() {
        let cfg = PartitionDetectionConfig::default();
        // Round 0: escalated = effective(0 drift) * 1.2^0 = 3000
        let deadline = cfg.escalated_deadline_ms(0, 0.0);
        assert_eq!(deadline, 3000);
    }

    #[test]
    fn escalated_deadline_ms_round_3() {
        let cfg = PartitionDetectionConfig::default();
        // Round 3: effective(0) = 3000; 3000 * 1.2^3 = 3000 * 1.728 = 5184
        let deadline = cfg.escalated_deadline_ms(3, 0.0);
        assert_eq!(deadline, 5184);
    }

    #[test]
    fn escalated_deadline_ms_clamped_to_max() {
        let cfg = PartitionDetectionConfig::default();
        // Many rounds with moderate drift should clamp to max
        let deadline = cfg.escalated_deadline_ms(20, 500_000.0);
        assert_eq!(deadline, 30_000);
    }

    // ── derive_record_id ───────────────────────────────────────────

    #[test]
    fn derive_record_id_deterministic() {
        let id1 = derive_record_id(1, 2, 3);
        let id2 = derive_record_id(1, 2, 3);
        assert_eq!(id1, id2);
    }

    #[test]
    fn derive_record_id_different_inputs_different_outputs() {
        let id1 = derive_record_id(1, 2, 3);
        let id2 = derive_record_id(1, 2, 4);
        assert_ne!(id1, id2);
    }

    #[test]
    fn derive_record_id_zero_inputs() {
        let id = derive_record_id(0, 0, 0);
        // 0 * 0x9E3779B9 = 0; all ops produce 0
        assert_eq!(id, 0);
    }

    // ── PartitionEvent / PartitionEventClass ───────────────────────

    #[test]
    fn partition_event_class_as_str() {
        assert_eq!(
            PartitionEventClass::PartitionDetected.as_str(),
            "event.partition_runtime.partition_detected.e0"
        );
        assert_eq!(
            PartitionEventClass::QuorumSideConfirmed.as_str(),
            "event.partition_runtime.quorum_side_confirmed.e1"
        );
        assert_eq!(
            PartitionEventClass::MinorityFenced.as_str(),
            "event.partition_runtime.minority_fenced.e2"
        );
        assert_eq!(
            PartitionEventClass::AmbiguousHalted.as_str(),
            "event.partition_runtime.ambiguous_halted.e3"
        );
        assert_eq!(
            PartitionEventClass::HealingStarted.as_str(),
            "event.partition_runtime.healing_started.e4"
        );
        assert_eq!(
            PartitionEventClass::HealingComplete.as_str(),
            "event.partition_runtime.healing_complete.e5"
        );
        assert_eq!(
            PartitionEventClass::SplitBrainHazardEmitted.as_str(),
            "event.partition_runtime.split_brain_hazard_emitted.e6"
        );
    }

    // ── Reconciliation types ───────────────────────────────────────

    #[test]
    fn divergence_class_none() {
        let dc = DivergenceClass::None;
        assert_eq!(dc, DivergenceClass::None);
    }

    #[test]
    fn divergence_class_conflicts_accessors() {
        let dc = DivergenceClass::Conflicts {
            conflicting_receipts: vec![10, 20, 30],
            conflict_count: 3,
        };
        match dc {
            DivergenceClass::Conflicts {
                conflicting_receipts,
                conflict_count,
            } => {
                assert_eq!(conflicting_receipts, vec![10, 20, 30]);
                assert_eq!(conflict_count, 3);
            }
            _ => panic!("expected Conflicts"),
        }
    }

    #[test]
    fn reconciliation_strategy_variants() {
        assert_eq!(
            ReconciliationStrategy::NoneNeeded,
            ReconciliationStrategy::NoneNeeded
        );
        let s = ReconciliationStrategy::FullCatchup {
            missed_epochs: vec![EpochId(1), EpochId(2)],
            estimated_receipts: 42,
        };
        match s {
            ReconciliationStrategy::FullCatchup {
                missed_epochs,
                estimated_receipts,
            } => {
                assert_eq!(missed_epochs, vec![EpochId(1), EpochId(2)]);
                assert_eq!(estimated_receipts, 42);
            }
            _ => panic!("expected FullCatchup"),
        }
    }
}
