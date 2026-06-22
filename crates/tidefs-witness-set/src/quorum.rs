// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Quorum availability evaluation and membership-change recommendations.
//
// Given a WitnessSetConfig and per-member health map, quorum_available()
// determines whether the set has enough healthy weight to make distributed
// decisions. recommend_membership_change() suggests member additions,
// removals, or weight adjustments when quorum health drops below the
// configured min_healthy_fraction.

use crate::config::WitnessSetConfig;
use crate::health::WitnessHealth;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// MembershipAction
// ---------------------------------------------------------------------------

/// Recommended membership change when quorum health is at risk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MembershipAction {
    /// Add a new member with the given node_id and voting weight.
    Add { node_id: u64, weight: u64 },
    /// Remove a member from the witness set.
    Remove { node_id: u64 },
    /// Adjust the voting weight of an existing member.
    AdjustWeight { node_id: u64, new_weight: u64 },
}

// ---------------------------------------------------------------------------
// quorum_available
// ---------------------------------------------------------------------------

impl WitnessSetConfig {
    /// Determine whether the witness set currently has a healthy quorum.
    ///
    /// Sums the weights of all members whose health is Online and checks
    /// whether the total meets the configured quorum threshold. Returns
    /// false for an empty witness set (no members means no quorum).
    pub fn quorum_available(&self, health: &HashMap<u64, WitnessHealth>) -> bool {
        let total_weight = self.total_weight();
        if total_weight == 0 {
            return false;
        }
        let healthy_weight = self.healthy_weight(health);
        self.threshold.is_satisfied(healthy_weight, total_weight)
    }

    /// Compute the total weight of members currently Online.
    pub fn healthy_weight(&self, health: &HashMap<u64, WitnessHealth>) -> u64 {
        self.members
            .iter()
            .filter_map(|m| {
                let h = health.get(&m.node_id).copied().unwrap_or_default();
                if h.is_healthy() {
                    Some(m.weight)
                } else {
                    None
                }
            })
            .sum()
    }

    /// Fraction of total weight that is currently healthy (0.0-1.0).
    pub fn healthy_fraction(&self, health: &HashMap<u64, WitnessHealth>) -> f64 {
        let total = self.total_weight();
        if total == 0 {
            return 0.0;
        }
        self.healthy_weight(health) as f64 / total as f64
    }

    /// True when the healthy fraction meets or exceeds the configured
    /// min_healthy_fraction (the witness set is operational).
    pub fn is_operational(&self, health: &HashMap<u64, WitnessHealth>) -> bool {
        self.healthy_fraction(health) >= self.min_healthy_fraction
    }
}

// ---------------------------------------------------------------------------
// recommend_membership_change
// ---------------------------------------------------------------------------

impl WitnessSetConfig {
    /// Suggest membership actions to restore or maintain quorum health.
    ///
    /// When healthy weight falls below the quorum threshold or
    /// min_healthy_fraction, this function returns a list of recommended
    /// actions: removing persistently Offline members, adjusting weights,
    /// or flagging the need for new members.
    ///
    /// Recommendations are ordered by priority: removals first (to clean up
    /// the roster), then weight adjustments, then addition suggestions.
    pub fn recommend_membership_change(
        &self,
        health: &HashMap<u64, WitnessHealth>,
    ) -> Vec<MembershipAction> {
        let total = self.total_weight();
        let healthy = self.healthy_weight(health);
        let mut actions = Vec::new();

        // 0. If the set is empty, recommend adding members.
        if total == 0 {
            actions.push(MembershipAction::Add {
                node_id: 0,
                weight: 1,
            });
            return actions;
        }

        // 1. If quorum is satisfied already and operational, no actions needed.
        if self.threshold.is_satisfied(healthy, total) && self.is_operational(health) {
            return actions;
        }

        // 2. Recommend removal of Offline members that are dragging down the
        //    roster. Removing an offline member reduces total_weight, which
        //    can make the threshold easier to reach.
        let offline_members: Vec<u64> = self
            .members
            .iter()
            .filter_map(|m| {
                let h = health.get(&m.node_id).copied().unwrap_or_default();
                if h == WitnessHealth::Offline {
                    Some(m.node_id)
                } else {
                    None
                }
            })
            .collect();

        if !offline_members.is_empty() {
            let offline_weight: u64 = offline_members
                .iter()
                .map(|id| {
                    self.members
                        .iter()
                        .find(|m| m.node_id == *id)
                        .map(|m| m.weight)
                        .unwrap_or(0)
                })
                .sum();
            let new_total = total - offline_weight;

            // Only recommend removal if it actually helps reach quorum,
            // and only if it doesn't leave an empty set.
            if new_total > 0 {
                let remaining_healthy = self
                    .members
                    .iter()
                    .filter_map(|m| {
                        if offline_members.contains(&m.node_id) {
                            return None;
                        }
                        let h = health.get(&m.node_id).copied().unwrap_or_default();
                        if h.is_healthy() {
                            Some(m.weight)
                        } else {
                            None
                        }
                    })
                    .sum::<u64>();

                if self.threshold.is_satisfied(remaining_healthy, new_total) {
                    for id in &offline_members {
                        actions.push(MembershipAction::Remove { node_id: *id });
                    }
                    return actions;
                }
            }
        }

        // 3. If removal alone doesn't fix quorum, recommend weight
        //    rebalancing from Suspect members to Online members.
        let suspect_members: Vec<(u64, u64)> = self
            .members
            .iter()
            .filter_map(|m| {
                let h = health.get(&m.node_id).copied().unwrap_or_default();
                if h == WitnessHealth::Suspect {
                    Some((m.node_id, m.weight))
                } else {
                    None
                }
            })
            .collect();

        if actions.is_empty() && !suspect_members.is_empty() && total > 0 {
            for (id, _) in &suspect_members {
                actions.push(MembershipAction::AdjustWeight {
                    node_id: *id,
                    new_weight: 0,
                });
            }
        }

        // 4. If still below threshold, suggest addition of new members.
        if actions.is_empty() {
            let required = self.threshold.required_weight(total);
            let gap = required.saturating_sub(healthy);
            if gap > 0 {
                actions.push(MembershipAction::Add {
                    node_id: 0,
                    weight: gap,
                });
            }
        }

        actions
    }
}

#[cfg(test)]
mod membership_tests {
    use super::*;
    use crate::config::{MembershipQuorum, WitnessMember, WitnessSetConfig};

    fn health_map(entries: &[(u64, WitnessHealth)]) -> HashMap<u64, WitnessHealth> {
        entries.iter().copied().collect()
    }

    // -- quorum_available ----------------------------------------------------

    #[test]
    fn test_quorum_available_all_online() {
        let cfg = WitnessSetConfig::new(
            vec![
                WitnessMember::new(1, 1),
                WitnessMember::new(2, 1),
                WitnessMember::new(3, 1),
            ],
            MembershipQuorum::StrictMajority,
        );
        let health = health_map(&[
            (1, WitnessHealth::Online),
            (2, WitnessHealth::Online),
            (3, WitnessHealth::Online),
        ]);
        assert!(cfg.quorum_available(&health));
    }

    #[test]
    fn test_quorum_available_below_majority() {
        let cfg = WitnessSetConfig::new(
            vec![
                WitnessMember::new(1, 1),
                WitnessMember::new(2, 1),
                WitnessMember::new(3, 1),
            ],
            MembershipQuorum::StrictMajority,
        );
        let health = health_map(&[
            (1, WitnessHealth::Online),
            (2, WitnessHealth::Suspect),
            (3, WitnessHealth::Offline),
        ]);
        assert!(!cfg.quorum_available(&health));
    }

    #[test]
    fn test_quorum_available_exactly_at_threshold() {
        let cfg = WitnessSetConfig::new(
            vec![
                WitnessMember::new(1, 1),
                WitnessMember::new(2, 1),
                WitnessMember::new(3, 1),
                WitnessMember::new(4, 1),
                WitnessMember::new(5, 1),
            ],
            MembershipQuorum::StrictMajority,
        );
        let health = health_map(&[
            (1, WitnessHealth::Online),
            (2, WitnessHealth::Online),
            (3, WitnessHealth::Online),
            (4, WitnessHealth::Suspect),
            (5, WitnessHealth::Offline),
        ]);
        assert!(cfg.quorum_available(&health));
    }

    #[test]
    fn test_quorum_available_empty_set() {
        let cfg = WitnessSetConfig::new(vec![], MembershipQuorum::StrictMajority);
        let health = health_map(&[]);
        assert!(!cfg.quorum_available(&health));
    }

    #[test]
    fn test_quorum_available_single_member() {
        let cfg = WitnessSetConfig::new(
            vec![WitnessMember::new(1, 1)],
            MembershipQuorum::StrictMajority,
        );
        let health = health_map(&[(1, WitnessHealth::Online)]);
        assert!(cfg.quorum_available(&health));
    }

    #[test]
    fn test_quorum_available_weighted() {
        let cfg = WitnessSetConfig::new(
            vec![
                WitnessMember::new(1, 5),
                WitnessMember::new(2, 1),
                WitnessMember::new(3, 1),
            ],
            MembershipQuorum::StrictMajority,
        );
        let health = health_map(&[
            (1, WitnessHealth::Online),
            (2, WitnessHealth::Offline),
            (3, WitnessHealth::Offline),
        ]);
        assert!(cfg.quorum_available(&health));
    }

    #[test]
    fn test_quorum_available_weighted_insufficient() {
        let cfg = WitnessSetConfig::new(
            vec![
                WitnessMember::new(1, 1),
                WitnessMember::new(2, 1),
                WitnessMember::new(3, 5),
            ],
            MembershipQuorum::StrictMajority,
        );
        let health = health_map(&[
            (1, WitnessHealth::Online),
            (2, WitnessHealth::Online),
            (3, WitnessHealth::Offline),
        ]);
        assert!(!cfg.quorum_available(&health));
    }

    #[test]
    fn test_quorum_available_super_majority() {
        let cfg = WitnessSetConfig::new(
            vec![
                WitnessMember::new(1, 1),
                WitnessMember::new(2, 1),
                WitnessMember::new(3, 1),
            ],
            MembershipQuorum::SuperMajority,
        );
        let health = health_map(&[
            (1, WitnessHealth::Online),
            (2, WitnessHealth::Online),
            (3, WitnessHealth::Offline),
        ]);
        assert!(cfg.quorum_available(&health));
    }

    #[test]
    fn test_quorum_available_super_majority_not_met() {
        let cfg = WitnessSetConfig::new(
            vec![
                WitnessMember::new(1, 1),
                WitnessMember::new(2, 1),
                WitnessMember::new(3, 1),
                WitnessMember::new(4, 1),
            ],
            MembershipQuorum::SuperMajority,
        );
        let health = health_map(&[
            (1, WitnessHealth::Online),
            (2, WitnessHealth::Online),
            (3, WitnessHealth::Offline),
            (4, WitnessHealth::Suspect),
        ]);
        assert!(!cfg.quorum_available(&health));
    }

    #[test]
    fn test_quorum_available_absolute_weight() {
        let cfg = WitnessSetConfig::new(
            vec![
                WitnessMember::new(1, 1),
                WitnessMember::new(2, 1),
                WitnessMember::new(3, 1),
                WitnessMember::new(4, 1),
            ],
            MembershipQuorum::AbsoluteWeight(2),
        );
        let health = health_map(&[
            (1, WitnessHealth::Online),
            (2, WitnessHealth::Online),
            (3, WitnessHealth::Offline),
            (4, WitnessHealth::Offline),
        ]);
        assert!(cfg.quorum_available(&health));
    }

    #[test]
    fn test_healthy_weight_with_default_online() {
        let cfg = WitnessSetConfig::new(
            vec![WitnessMember::new(1, 2), WitnessMember::new(2, 3)],
            MembershipQuorum::StrictMajority,
        );
        let health: HashMap<u64, WitnessHealth> = HashMap::new();
        assert_eq!(cfg.healthy_weight(&health), 5);
        assert!(cfg.quorum_available(&health));
    }

    // -- healthy_fraction / is_operational -----------------------------------

    #[test]
    fn test_healthy_fraction_full() {
        let cfg = WitnessSetConfig::new(
            vec![WitnessMember::new(1, 1), WitnessMember::new(2, 1)],
            MembershipQuorum::StrictMajority,
        );
        let health = health_map(&[(1, WitnessHealth::Online), (2, WitnessHealth::Online)]);
        assert_eq!(cfg.healthy_fraction(&health), 1.0);
        assert!(cfg.is_operational(&health));
    }

    #[test]
    fn test_healthy_fraction_half() {
        let cfg = WitnessSetConfig::new(
            vec![WitnessMember::new(1, 1), WitnessMember::new(2, 1)],
            MembershipQuorum::StrictMajority,
        );
        let health = health_map(&[(1, WitnessHealth::Online), (2, WitnessHealth::Offline)]);
        assert_eq!(cfg.healthy_fraction(&health), 0.5);
        assert!(cfg.is_operational(&health));
    }

    #[test]
    fn test_healthy_fraction_below_min() {
        let cfg = WitnessSetConfig::new(
            vec![WitnessMember::new(1, 1), WitnessMember::new(2, 1)],
            MembershipQuorum::StrictMajority,
        )
        .with_min_healthy_fraction(0.75);
        let health = health_map(&[(1, WitnessHealth::Online), (2, WitnessHealth::Offline)]);
        assert_eq!(cfg.healthy_fraction(&health), 0.5);
        assert!(!cfg.is_operational(&health));
    }

    #[test]
    fn test_healthy_fraction_empty() {
        let cfg = WitnessSetConfig::new(vec![], MembershipQuorum::StrictMajority);
        let health = health_map(&[]);
        assert_eq!(cfg.healthy_fraction(&health), 0.0);
        assert!(!cfg.is_operational(&health));
    }

    // -- recommend_membership_change -----------------------------------------

    #[test]
    fn test_recommend_no_change_when_healthy() {
        let cfg = WitnessSetConfig::new(
            vec![
                WitnessMember::new(1, 1),
                WitnessMember::new(2, 1),
                WitnessMember::new(3, 1),
            ],
            MembershipQuorum::StrictMajority,
        );
        let health = health_map(&[
            (1, WitnessHealth::Online),
            (2, WitnessHealth::Online),
            (3, WitnessHealth::Online),
        ]);
        let actions = cfg.recommend_membership_change(&health);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_recommend_no_change_quorum_met() {
        let cfg = WitnessSetConfig::new(
            vec![
                WitnessMember::new(1, 1),
                WitnessMember::new(2, 1),
                WitnessMember::new(3, 1),
                WitnessMember::new(4, 1),
            ],
            MembershipQuorum::StrictMajority,
        );
        let health = health_map(&[
            (1, WitnessHealth::Online),
            (2, WitnessHealth::Online),
            (3, WitnessHealth::Online),
            (4, WitnessHealth::Offline),
        ]);
        let actions = cfg.recommend_membership_change(&health);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_recommend_adjust_suspect_weights() {
        let cfg = WitnessSetConfig::new(
            vec![
                WitnessMember::new(1, 1),
                WitnessMember::new(2, 1),
                WitnessMember::new(3, 2), // suspect, heavy weight
            ],
            MembershipQuorum::StrictMajority,
        );
        let health = health_map(&[
            (1, WitnessHealth::Online),
            (2, WitnessHealth::Online),
            (3, WitnessHealth::Suspect),
        ]);
        let actions = cfg.recommend_membership_change(&health);
        assert!(!actions.is_empty());
        let has_adjust = actions.iter().any(|a| {
            matches!(
                a,
                MembershipAction::AdjustWeight {
                    node_id: 3,
                    new_weight: 0
                }
            )
        });
        assert!(has_adjust);
    }

    #[test]
    fn test_recommend_add_when_empty() {
        let cfg = WitnessSetConfig::new(vec![], MembershipQuorum::StrictMajority);
        let health = health_map(&[]);
        let actions = cfg.recommend_membership_change(&health);
        assert!(!actions.is_empty());
        let has_add = actions
            .iter()
            .any(|a| matches!(a, MembershipAction::Add { .. }));
        assert!(has_add);
    }

    #[test]
    fn test_recommend_add_when_all_offline() {
        let cfg = WitnessSetConfig::new(
            vec![WitnessMember::new(1, 1), WitnessMember::new(2, 1)],
            MembershipQuorum::StrictMajority,
        );
        let health = health_map(&[(1, WitnessHealth::Offline), (2, WitnessHealth::Offline)]);
        let actions = cfg.recommend_membership_change(&health);
        assert!(!actions.is_empty());
        let has_add = actions
            .iter()
            .any(|a| matches!(a, MembershipAction::Add { .. }));
        assert!(
            has_add,
            "should recommend adding new members when all are offline"
        );
    }

    #[test]
    fn test_recommend_remove_offline_when_quorum_still_possible() {
        let cfg = WitnessSetConfig::new(
            vec![
                WitnessMember::new(1, 1),
                WitnessMember::new(2, 1),
                WitnessMember::new(3, 1),
                WitnessMember::new(4, 1), // offline
            ],
            MembershipQuorum::StrictMajority,
        );
        let health = health_map(&[
            (1, WitnessHealth::Online),
            (2, WitnessHealth::Online),
            (3, WitnessHealth::Online),
            (4, WitnessHealth::Offline),
        ]);
        let actions = cfg.recommend_membership_change(&health);
        assert!(actions.is_empty());
    }
}

// ===========================================================================
// QuorumEvaluator — acknowledgment quorum evaluation for WitnessSet
// ===========================================================================

use crate::types::QuorumOutcome;
use crate::witness_set::QuorumThreshold;
use crate::witness_set::WitnessSet;

/// Configurable evaluator that checks whether a [`WitnessSet`] has collected
/// enough acknowledgments for a given operation to satisfy the quorum policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuorumEvaluator {
    threshold: QuorumThreshold,
}

impl QuorumEvaluator {
    /// Create an evaluator with the given threshold strategy.
    pub fn new(threshold: QuorumThreshold) -> Self {
        Self { threshold }
    }

    /// Evaluate whether the witness set has reached quorum for `operation_id`.
    ///
    /// Returns [`QuorumOutcome::Reached`] when enough witnesses have
    /// acknowledged, or [`QuorumOutcome::Shortfall`] with the number of
    /// additional acks needed.
    pub fn evaluate(&self, ws: &WitnessSet, operation_id: u64) -> QuorumOutcome {
        if ws.is_empty() {
            return QuorumOutcome::Shortfall(0);
        }
        let collected = ws.ack_count(operation_id);
        let required = self.threshold.required(ws.len());
        if collected >= required {
            QuorumOutcome::Reached
        } else {
            QuorumOutcome::Shortfall((required - collected) as u32)
        }
    }

    /// Return the underlying threshold configuration.
    pub fn threshold(&self) -> QuorumThreshold {
        self.threshold
    }
}

#[cfg(test)]
mod evaluator_tests {
    use super::*;
    use tidefs_membership_epoch::{EpochId, MemberId};

    fn add_voters(ws: &mut WitnessSet, ids: &[u64]) {
        let voter_ids: Vec<MemberId> = ids.iter().copied().map(MemberId::new).collect();
        ws.install_voter_ids_for_epoch(EpochId::new(ws.epoch()), &voter_ids);
        for id in ids {
            assert!(ws.add_witness(*id), "voter {id} must be accepted");
        }
    }

    fn make_ws(count: usize, threshold: QuorumThreshold) -> WitnessSet {
        let mut ws = WitnessSet::new(threshold);
        let ids: Vec<u64> = (1..=count as u64).collect();
        add_voters(&mut ws, &ids);
        ws
    }

    #[test]
    fn test_evaluate_majority_reached() {
        let mut ws = make_ws(3, QuorumThreshold::StrictMajority);
        ws.ack(1, 100);
        ws.ack(2, 100);
        let ev = QuorumEvaluator::new(QuorumThreshold::StrictMajority);
        assert_eq!(ev.evaluate(&ws, 100), QuorumOutcome::Reached);
    }

    #[test]
    fn test_evaluate_majority_shortfall() {
        let mut ws = make_ws(3, QuorumThreshold::StrictMajority);
        ws.ack(1, 100);
        let ev = QuorumEvaluator::new(QuorumThreshold::StrictMajority);
        assert_eq!(ev.evaluate(&ws, 100), QuorumOutcome::Shortfall(1));
    }

    #[test]
    fn test_evaluate_supermajority_reached() {
        let mut ws = make_ws(5, QuorumThreshold::SuperMajority);
        for i in 1..=4 {
            ws.ack(i, 200);
        }
        let ev = QuorumEvaluator::new(QuorumThreshold::SuperMajority);
        assert_eq!(ev.evaluate(&ws, 200), QuorumOutcome::Reached);
    }

    #[test]
    fn test_evaluate_supermajority_shortfall() {
        let mut ws = make_ws(5, QuorumThreshold::SuperMajority);
        for i in 1..=3 {
            ws.ack(i, 200);
        }
        let ev = QuorumEvaluator::new(QuorumThreshold::SuperMajority);
        assert_eq!(ev.evaluate(&ws, 200), QuorumOutcome::Shortfall(1));
    }

    #[test]
    fn test_evaluate_exact_reached() {
        let mut ws = make_ws(4, QuorumThreshold::Exact(2));
        ws.ack(1, 300);
        ws.ack(2, 300);
        let ev = QuorumEvaluator::new(QuorumThreshold::Exact(2));
        assert_eq!(ev.evaluate(&ws, 300), QuorumOutcome::Reached);
    }

    #[test]
    fn test_evaluate_exact_shortfall() {
        let mut ws = make_ws(4, QuorumThreshold::Exact(3));
        ws.ack(1, 300);
        let ev = QuorumEvaluator::new(QuorumThreshold::Exact(3));
        assert_eq!(ev.evaluate(&ws, 300), QuorumOutcome::Shortfall(2));
    }

    #[test]
    fn test_evaluate_empty_set() {
        let ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        let ev = QuorumEvaluator::new(QuorumThreshold::StrictMajority);
        assert_eq!(ev.evaluate(&ws, 999), QuorumOutcome::Shortfall(0));
    }

    #[test]
    fn test_evaluate_unknown_operation() {
        let ws = make_ws(3, QuorumThreshold::StrictMajority);
        let ev = QuorumEvaluator::new(QuorumThreshold::StrictMajority);
        assert_eq!(ev.evaluate(&ws, 999), QuorumOutcome::Shortfall(2));
    }

    #[test]
    fn test_evaluate_one_node_quorum() {
        let mut ws = make_ws(1, QuorumThreshold::StrictMajority);
        ws.ack(1, 42);
        let ev = QuorumEvaluator::new(QuorumThreshold::StrictMajority);
        assert_eq!(ev.evaluate(&ws, 42), QuorumOutcome::Reached);
    }
}
