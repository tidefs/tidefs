// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Replication policy selector: assigns Critical / Standard / BestEffort
//! quorum policies per chunk class as defined in PC-010.3.

use serde::{Deserialize, Serialize};

/// Quorum replication policy per chunk class.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicationPolicy {
    /// All-target quorum: every target must ACK.
    Critical,
    /// Majority quorum: N/2+1 must ACK.
    Standard,
    /// Single ACK: at least one target must ACK.
    BestEffort,
}

impl ReplicationPolicy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Standard => "standard",
            Self::BestEffort => "best_effort",
        }
    }

    /// Minimum ACKs required to achieve quorum given N targets.
    #[must_use]
    pub const fn min_quorum(self, target_count: usize) -> usize {
        match self {
            Self::Critical => target_count,
            Self::Standard => target_count / 2 + 1,
            Self::BestEffort => 1,
        }
    }

    /// Whether all targets are required.
    #[must_use]
    pub const fn requires_all(self) -> bool {
        matches!(self, Self::Critical)
    }

    /// Whether majority quorum applies.
    #[must_use]
    pub const fn requires_majority(self) -> bool {
        matches!(self, Self::Standard)
    }
}

/// Chunk classes used for policy selection (PC-010.3).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicationChunkClass {
    /// Metadata head chunk — requires all-target quorum.
    MetadataHead,
    /// Claim ledger chunk — requires all-target quorum.
    ClaimLedger,
    /// Content payload chunk — requires majority quorum.
    ContentPayload,
    /// Background data chunk — requires single ACK.
    BackgroundData,
    /// Projection root chunk — requires all-target quorum.
    ProjectionRoot,
}

impl ReplicationChunkClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MetadataHead => "metadata_head",
            Self::ClaimLedger => "claim_ledger",
            Self::ContentPayload => "content_payload",
            Self::BackgroundData => "background_data",
            Self::ProjectionRoot => "projection_root",
        }
    }
}

/// Selects quorum replication policy per chunk class.
///
/// - `MetadataHead`, `ClaimLedger`, `ProjectionRoot` → `Critical` (all-target quorum)
/// - `ContentPayload` → `Standard` (majority quorum)
/// - `BackgroundData` → `BestEffort` (single ACK)
#[derive(Debug, Default)]
pub struct ReplicationPolicySelector;

impl ReplicationPolicySelector {
    /// Assign the quorum policy for a given chunk class.
    #[must_use]
    pub const fn select(class: ReplicationChunkClass) -> ReplicationPolicy {
        match class {
            ReplicationChunkClass::MetadataHead
            | ReplicationChunkClass::ClaimLedger
            | ReplicationChunkClass::ProjectionRoot => ReplicationPolicy::Critical,
            ReplicationChunkClass::ContentPayload => ReplicationPolicy::Standard,
            ReplicationChunkClass::BackgroundData => ReplicationPolicy::BestEffort,
        }
    }

    /// Compute the minimum ACK count for a class and target count.
    #[must_use]
    pub fn min_quorum_for(class: ReplicationChunkClass, target_count: usize) -> usize {
        Self::select(class).min_quorum(target_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_policy_for_metadata_head() {
        assert_eq!(
            ReplicationPolicySelector::select(ReplicationChunkClass::MetadataHead),
            ReplicationPolicy::Critical
        );
    }

    #[test]
    fn critical_policy_for_claim_ledger() {
        assert_eq!(
            ReplicationPolicySelector::select(ReplicationChunkClass::ClaimLedger),
            ReplicationPolicy::Critical
        );
    }

    #[test]
    fn critical_policy_for_projection_root() {
        assert_eq!(
            ReplicationPolicySelector::select(ReplicationChunkClass::ProjectionRoot),
            ReplicationPolicy::Critical
        );
    }

    #[test]
    fn standard_policy_for_content_payload() {
        assert_eq!(
            ReplicationPolicySelector::select(ReplicationChunkClass::ContentPayload),
            ReplicationPolicy::Standard
        );
    }

    #[test]
    fn best_effort_policy_for_background_data() {
        assert_eq!(
            ReplicationPolicySelector::select(ReplicationChunkClass::BackgroundData),
            ReplicationPolicy::BestEffort
        );
    }

    #[test]
    fn min_quorum_computation() {
        assert_eq!(ReplicationPolicy::Critical.min_quorum(3), 3);
        assert_eq!(ReplicationPolicy::Critical.min_quorum(5), 5);
        assert_eq!(ReplicationPolicy::Standard.min_quorum(3), 2);
        assert_eq!(ReplicationPolicy::Standard.min_quorum(5), 3);
        assert_eq!(ReplicationPolicy::Standard.min_quorum(4), 3);
        assert_eq!(ReplicationPolicy::BestEffort.min_quorum(3), 1);
        assert_eq!(ReplicationPolicy::BestEffort.min_quorum(1), 1);
    }

    #[test]
    fn requires_all_only_for_critical() {
        assert!(ReplicationPolicy::Critical.requires_all());
        assert!(!ReplicationPolicy::Standard.requires_all());
        assert!(!ReplicationPolicy::BestEffort.requires_all());
    }

    #[test]
    fn requires_majority_only_for_standard() {
        assert!(!ReplicationPolicy::Critical.requires_majority());
        assert!(ReplicationPolicy::Standard.requires_majority());
        assert!(!ReplicationPolicy::BestEffort.requires_majority());
    }
}
