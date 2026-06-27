// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Relocation reason taxonomy consumed by the governor admission model.

use tidefs_storage_intent_core::RelocationReasonClass;

/// Governor-level relocation reason.
///
/// The governor unifies all relocation triggers into this single taxonomy.
/// Each variant maps to a [`RelocationReasonClass`] for storage-intent
/// record compatibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum GovernorRelocationReason {
    /// Placement no longer satisfies the authoritative placement policy.
    /// Triggered by policy-change or satisfaction-drift detection.
    PolicySatisfaction = 0,

    /// Degraded data must be rebuilt from surviving replicas or erasure
    /// shards. Always necessity-class, never optimization.
    Repair = 1,

    /// Member, device, or failure-domain evacuation. Urgency depends on
    /// drain deadline and remaining redundancy.
    Evacuation = 2,

    /// Rotational-media seek and scan locality improvement. HDD-only;
    /// must justify expected seek/scan reduction.
    HddDefrag = 3,

    /// Flash segment drain, reclaim-debt reduction, or write-amplification
    /// improvement via compaction. SSD/NVMe-only.
    SsdCompaction = 4,

    /// Data-shape transform: compression change, checksum-suite migration,
    /// erasure-shape rebuild, dedup-domain rebake.
    Rebake = 5,

    /// Promotion to a higher-performance or lower-latency tier.
    /// Requires authority-changing relocation with payback.
    Promotion = 6,

    /// Demotion to a lower-cost or higher-capacity tier.
    /// Must prove dataset service objective remains satisfied.
    Demotion = 7,

    /// WAN/internet replica RPO catch-up: batching, compression, delta
    /// transfer, congestion/cost awareness, explicit RPO lag receipts.
    GeoCatchup = 8,

    /// Flash/NVMe endurance-aware movement to balance wear across devices.
    /// Must cite wear-delta evidence and protected-reserve headroom.
    WearRebalance = 9,
}

impl GovernorRelocationReason {
    /// All governor relocation reasons in discriminant order.
    pub const ALL: [GovernorRelocationReason; 10] = [
        GovernorRelocationReason::PolicySatisfaction,
        GovernorRelocationReason::Repair,
        GovernorRelocationReason::Evacuation,
        GovernorRelocationReason::HddDefrag,
        GovernorRelocationReason::SsdCompaction,
        GovernorRelocationReason::Rebake,
        GovernorRelocationReason::Promotion,
        GovernorRelocationReason::Demotion,
        GovernorRelocationReason::GeoCatchup,
        GovernorRelocationReason::WearRebalance,
    ];

    /// Stable diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            GovernorRelocationReason::PolicySatisfaction => "policy-satisfaction",
            GovernorRelocationReason::Repair => "repair",
            GovernorRelocationReason::Evacuation => "evacuation",
            GovernorRelocationReason::HddDefrag => "hdd-defrag",
            GovernorRelocationReason::SsdCompaction => "ssd-compaction",
            GovernorRelocationReason::Rebake => "rebake",
            GovernorRelocationReason::Promotion => "promotion",
            GovernorRelocationReason::Demotion => "demotion",
            GovernorRelocationReason::GeoCatchup => "geo-catchup",
            GovernorRelocationReason::WearRebalance => "wear-rebalance",
        }
    }

    /// Returns true when this reason is necessity-class (repair, evacuation)
    /// rather than optimization-class.
    #[must_use]
    pub const fn is_necessity(self) -> bool {
        matches!(
            self,
            GovernorRelocationReason::Repair | GovernorRelocationReason::Evacuation
        )
    }

    /// Returns true when this reason changes authority (promotion, demotion,
    /// rebake, geo-catchup) rather than maintaining existing receipts.
    #[must_use]
    pub const fn changes_authority(self) -> bool {
        matches!(
            self,
            GovernorRelocationReason::Promotion
                | GovernorRelocationReason::Demotion
                | GovernorRelocationReason::Rebake
                | GovernorRelocationReason::GeoCatchup
                | GovernorRelocationReason::PolicySatisfaction
        )
    }

    /// Returns true when this reason requires flash/NVMe write-amplification
    /// justification before spending media lifetime.
    #[must_use]
    pub const fn requires_flash_wear_justification(self) -> bool {
        matches!(
            self,
            GovernorRelocationReason::SsdCompaction
                | GovernorRelocationReason::WearRebalance
                | GovernorRelocationReason::Promotion
                | GovernorRelocationReason::Rebake
        )
    }

    /// Returns true when this reason is HDD-specific.
    #[must_use]
    pub const fn is_hdd_only(self) -> bool {
        matches!(self, GovernorRelocationReason::HddDefrag)
    }

    /// Returns true when this reason is SSD/NVMe-specific.
    #[must_use]
    pub const fn is_ssd_only(self) -> bool {
        matches!(
            self,
            GovernorRelocationReason::SsdCompaction | GovernorRelocationReason::WearRebalance
        )
    }

    /// Returns true when this reason operates over WAN/internet.
    #[must_use]
    pub const fn is_wan(self) -> bool {
        matches!(self, GovernorRelocationReason::GeoCatchup)
    }

    /// Map to the storage-intent-core `RelocationReasonClass`.
    ///
    /// The governor taxonomy is richer than the core record taxonomy;
    /// multiple governor reasons may map to the same core class when the
    /// core type uses a coarser bucket. The governor preserves the finer
    /// reason in its own admission records.
    #[must_use]
    pub const fn to_storage_intent_reason_class(self) -> RelocationReasonClass {
        match self {
            GovernorRelocationReason::PolicySatisfaction => {
                RelocationReasonClass::AuthorityConvergence
            }
            GovernorRelocationReason::Repair => RelocationReasonClass::Repair,
            GovernorRelocationReason::Evacuation => RelocationReasonClass::Evacuation,
            GovernorRelocationReason::HddDefrag => RelocationReasonClass::DefragRotationalLocality,
            GovernorRelocationReason::SsdCompaction => RelocationReasonClass::ReclaimPressure,
            GovernorRelocationReason::Rebake => RelocationReasonClass::DataShapeRebake,
            GovernorRelocationReason::Promotion => RelocationReasonClass::FlashServingPromotion,
            GovernorRelocationReason::Demotion => RelocationReasonClass::ArchiveMigration,
            GovernorRelocationReason::GeoCatchup => RelocationReasonClass::GeoCatchup,
            GovernorRelocationReason::WearRebalance => RelocationReasonClass::ReclaimPressure,
        }
    }

    /// Try to map from a storage-intent-core `RelocationReasonClass`.
    ///
    /// Returns `None` when the core class is `Unknown` or cannot be
    /// disambiguated to a single governor reason without additional
    /// evidence.
    #[must_use]
    pub const fn from_storage_intent_reason_class(
        class: RelocationReasonClass,
    ) -> Option<GovernorRelocationReason> {
        match class {
            RelocationReasonClass::Unknown => None,
            RelocationReasonClass::DefragRotationalLocality => {
                Some(GovernorRelocationReason::HddDefrag)
            }
            RelocationReasonClass::ReclaimPressure => None, // ambiguous: could be SsdCompaction or WearRebalance
            RelocationReasonClass::FlashServingPromotion => {
                Some(GovernorRelocationReason::Promotion)
            }
            RelocationReasonClass::AuthorityConvergence => {
                Some(GovernorRelocationReason::PolicySatisfaction)
            }
            RelocationReasonClass::Evacuation => Some(GovernorRelocationReason::Evacuation),
            RelocationReasonClass::Repair => Some(GovernorRelocationReason::Repair),
            RelocationReasonClass::GeoCatchup => Some(GovernorRelocationReason::GeoCatchup),
            RelocationReasonClass::ArchiveMigration => Some(GovernorRelocationReason::Demotion),
            RelocationReasonClass::DataShapeRebake => Some(GovernorRelocationReason::Rebake),
        }
    }
}

impl core::fmt::Display for GovernorRelocationReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_reasons_have_unique_discriminants() {
        let mut seen = [false; 10];
        for reason in &GovernorRelocationReason::ALL {
            let idx = *reason as usize;
            assert!(!seen[idx], "duplicate discriminant for {reason}");
            seen[idx] = true;
        }
        assert!(seen.iter().all(|&x| x));
    }

    #[test]
    fn reason_display_nonempty() {
        for reason in &GovernorRelocationReason::ALL {
            assert!(!format!("{reason}").is_empty());
        }
    }

    #[test]
    fn necessity_reasons() {
        assert!(GovernorRelocationReason::Repair.is_necessity());
        assert!(GovernorRelocationReason::Evacuation.is_necessity());
        assert!(!GovernorRelocationReason::HddDefrag.is_necessity());
        assert!(!GovernorRelocationReason::Promotion.is_necessity());
    }

    #[test]
    fn authority_changing_reasons() {
        assert!(GovernorRelocationReason::Promotion.changes_authority());
        assert!(GovernorRelocationReason::Demotion.changes_authority());
        assert!(GovernorRelocationReason::Rebake.changes_authority());
        assert!(GovernorRelocationReason::GeoCatchup.changes_authority());
        assert!(GovernorRelocationReason::PolicySatisfaction.changes_authority());
        assert!(!GovernorRelocationReason::Repair.changes_authority());
        assert!(!GovernorRelocationReason::HddDefrag.changes_authority());
    }

    #[test]
    fn requires_flash_wear_justification() {
        assert!(GovernorRelocationReason::SsdCompaction.requires_flash_wear_justification());
        assert!(GovernorRelocationReason::WearRebalance.requires_flash_wear_justification());
        assert!(GovernorRelocationReason::Promotion.requires_flash_wear_justification());
        assert!(!GovernorRelocationReason::HddDefrag.requires_flash_wear_justification());
        assert!(!GovernorRelocationReason::Repair.requires_flash_wear_justification());
    }

    #[test]
    fn round_trip_to_storage_intent_class() {
        // Reasons that map unambiguously should round-trip through
        // from_storage_intent_reason_class.
        for reason in &GovernorRelocationReason::ALL {
            let class = reason.to_storage_intent_reason_class();
            let back = GovernorRelocationReason::from_storage_intent_reason_class(class);
            // Some governor reasons map to the same core class; only check
            // that the mapping is defined (Some) for unambiguous cases.
            if *reason == GovernorRelocationReason::SsdCompaction
                || *reason == GovernorRelocationReason::WearRebalance
            {
                // ReclaimPressure is ambiguous for these two
                assert_eq!(class, RelocationReasonClass::ReclaimPressure);
            } else {
                assert_eq!(back, Some(*reason));
            }
        }
    }

    #[test]
    fn media_specificity() {
        assert!(GovernorRelocationReason::HddDefrag.is_hdd_only());
        assert!(!GovernorRelocationReason::SsdCompaction.is_hdd_only());
        assert!(!GovernorRelocationReason::WearRebalance.is_hdd_only());

        assert!(GovernorRelocationReason::SsdCompaction.is_ssd_only());
        assert!(GovernorRelocationReason::WearRebalance.is_ssd_only());
        assert!(!GovernorRelocationReason::HddDefrag.is_ssd_only());

        assert!(GovernorRelocationReason::GeoCatchup.is_wan());
        assert!(!GovernorRelocationReason::Repair.is_wan());
    }
}
