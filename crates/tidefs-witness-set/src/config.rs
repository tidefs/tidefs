// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Witness set configuration: defines which nodes participate in distributed
// quorum decisions, their voting weights, and the quorum threshold parameters.
//
// The WitnessSetConfig is the persistent, committed-root-stable definition of
// a witness set. Node health is tracked separately via WitnessHealth per member
// and fed into quorum_available() for runtime quorum evaluation.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// WitnessSetConfig
// ---------------------------------------------------------------------------

/// Persistent configuration for a witness set: membership roster, voting
/// weights, and the quorum threshold required for distributed decisions.
///
/// Serialized via serde for committed-root persistence. The member list is
/// ordered for deterministic iteration; insertion order is preserved.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WitnessSetConfig {
    /// Ordered member list with per-member voting weight.
    pub members: Vec<WitnessMember>,
    /// Quorum threshold that defines when enough healthy weight exists to
    /// make a distributed decision.
    pub threshold: MembershipQuorum,
    /// Minimum fraction of total weight (0.0-1.0) that must be healthy for
    /// the witness set to be considered operational at all. Below this,
    /// membership_change actions should be recommended.
    pub min_healthy_fraction: f64,
}

impl WitnessSetConfig {
    /// Create a new witness set config with the given members and threshold.
    /// Defaults min_healthy_fraction to 0.5 (at least half of total weight).
    pub fn new(members: Vec<WitnessMember>, threshold: MembershipQuorum) -> Self {
        Self {
            members,
            threshold,
            min_healthy_fraction: 0.5,
        }
    }

    /// Set the minimum healthy fraction, clamped to [0.0, 1.0].
    pub fn with_min_healthy_fraction(mut self, fraction: f64) -> Self {
        self.min_healthy_fraction = fraction.clamp(0.0, 1.0);
        self
    }

    /// Total voting weight across all members (healthy or not).
    pub fn total_weight(&self) -> u64 {
        self.members.iter().map(|m| m.weight).sum()
    }

    /// Number of members in this witness set.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// True when the witness set has no members.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Look up a member by node_id.
    pub fn get_member(&self, node_id: u64) -> Option<&WitnessMember> {
        self.members.iter().find(|m| m.node_id == node_id)
    }
}

// ---------------------------------------------------------------------------
// WitnessMember
// ---------------------------------------------------------------------------

/// A single member in a witness set, identified by node_id with a voting
/// weight for weighted-quorum calculations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessMember {
    /// Unique node identifier.
    pub node_id: u64,
    /// Voting weight for this member (default 1; higher = more influence).
    pub weight: u64,
}

impl WitnessMember {
    pub const fn new(node_id: u64, weight: u64) -> Self {
        Self { node_id, weight }
    }
}

// ---------------------------------------------------------------------------
// MembershipQuorum
// ---------------------------------------------------------------------------

/// Quorum threshold for determining whether enough healthy witness members
/// exist to make a distributed decision. Operates on total healthy weight
/// rather than raw member count, supporting weighted voting.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum MembershipQuorum {
    /// Strict majority: >50% of total weight across all members.
    StrictMajority,
    /// Super-majority: >=2/3 of total weight.
    SuperMajority,
    /// Explicit minimum weight required (absolute count of weight units).
    AbsoluteWeight(u64),
}

impl MembershipQuorum {
    /// Compute the minimum healthy weight required given the total weight
    /// of the witness set.
    pub fn required_weight(self, total_weight: u64) -> u64 {
        if total_weight == 0 {
            return 0;
        }
        match self {
            Self::StrictMajority => (total_weight / 2) + 1,
            Self::SuperMajority => {
                // ceil(2 * total / 3)
                let n = 2 * total_weight;
                if n % 3 == 0 {
                    n / 3
                } else {
                    (n / 3) + 1
                }
            }
            Self::AbsoluteWeight(w) => w.min(total_weight),
        }
    }

    /// Check whether `healthy_weight` meets the quorum requirement for
    /// `total_weight`.
    pub fn is_satisfied(self, healthy_weight: u64, total_weight: u64) -> bool {
        healthy_weight >= self.required_weight(total_weight)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- MembershipQuorum arithmetic -----------------------------------------

    #[test]
    fn test_strict_majority_weights() {
        let q = MembershipQuorum::StrictMajority;
        assert_eq!(q.required_weight(0), 0);
        assert_eq!(q.required_weight(1), 1);
        assert_eq!(q.required_weight(2), 2);
        assert_eq!(q.required_weight(3), 2);
        assert_eq!(q.required_weight(4), 3);
        assert_eq!(q.required_weight(5), 3);
        assert_eq!(q.required_weight(10), 6);
    }

    #[test]
    fn test_super_majority_weights() {
        let q = MembershipQuorum::SuperMajority;
        assert_eq!(q.required_weight(0), 0);
        assert_eq!(q.required_weight(1), 1);
        assert_eq!(q.required_weight(2), 2);
        assert_eq!(q.required_weight(3), 2);
        assert_eq!(q.required_weight(4), 3);
        assert_eq!(q.required_weight(5), 4);
        assert_eq!(q.required_weight(6), 4);
    }

    #[test]
    fn test_absolute_weight() {
        assert_eq!(MembershipQuorum::AbsoluteWeight(3).required_weight(10), 3);
        assert_eq!(MembershipQuorum::AbsoluteWeight(5).required_weight(3), 3);
        assert_eq!(MembershipQuorum::AbsoluteWeight(0).required_weight(10), 0);
    }

    #[test]
    fn test_is_satisfied() {
        let q = MembershipQuorum::StrictMajority;
        assert!(q.is_satisfied(3, 5));
        assert!(!q.is_satisfied(2, 5));
        assert!(q.is_satisfied(5, 5));
    }

    // -- WitnessSetConfig construction ---------------------------------------

    #[test]
    fn test_new_config() {
        let members = vec![
            WitnessMember::new(1, 1),
            WitnessMember::new(2, 1),
            WitnessMember::new(3, 2),
        ];
        let cfg = WitnessSetConfig::new(members, MembershipQuorum::StrictMajority);
        assert_eq!(cfg.len(), 3);
        assert_eq!(cfg.total_weight(), 4);
        assert!(!cfg.is_empty());
        assert_eq!(cfg.min_healthy_fraction, 0.5);
    }

    #[test]
    fn test_empty_config() {
        let cfg = WitnessSetConfig::new(vec![], MembershipQuorum::StrictMajority);
        assert!(cfg.is_empty());
        assert_eq!(cfg.total_weight(), 0);
    }

    #[test]
    fn test_with_min_healthy_fraction() {
        let cfg = WitnessSetConfig::new(vec![], MembershipQuorum::StrictMajority)
            .with_min_healthy_fraction(0.75);
        assert_eq!(cfg.min_healthy_fraction, 0.75);
    }

    #[test]
    fn test_min_healthy_fraction_clamped() {
        let cfg = WitnessSetConfig::new(vec![], MembershipQuorum::StrictMajority)
            .with_min_healthy_fraction(1.5);
        assert_eq!(cfg.min_healthy_fraction, 1.0);
        let cfg = WitnessSetConfig::new(vec![], MembershipQuorum::StrictMajority)
            .with_min_healthy_fraction(-0.3);
        assert_eq!(cfg.min_healthy_fraction, 0.0);
    }

    #[test]
    fn test_get_member() {
        let members = vec![WitnessMember::new(10, 1), WitnessMember::new(20, 3)];
        let cfg = WitnessSetConfig::new(members, MembershipQuorum::StrictMajority);
        assert_eq!(cfg.get_member(10).unwrap().weight, 1);
        assert_eq!(cfg.get_member(20).unwrap().weight, 3);
        assert!(cfg.get_member(99).is_none());
    }

    // -- Serialization -------------------------------------------------------

    #[test]
    fn test_serialize_deserialize_config() {
        let cfg = WitnessSetConfig::new(
            vec![WitnessMember::new(1, 2), WitnessMember::new(2, 3)],
            MembershipQuorum::AbsoluteWeight(4),
        )
        .with_min_healthy_fraction(0.6);

        let json = serde_json::to_string(&cfg).unwrap();
        let cfg2: WitnessSetConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(cfg2.len(), 2);
        assert_eq!(cfg2.total_weight(), 5);
        assert_eq!(cfg2.min_healthy_fraction, 0.6);
        assert_eq!(cfg2.threshold, MembershipQuorum::AbsoluteWeight(4));
        assert_eq!(cfg2.members[0].node_id, 1);
        assert_eq!(cfg2.members[1].weight, 3);
    }
}
