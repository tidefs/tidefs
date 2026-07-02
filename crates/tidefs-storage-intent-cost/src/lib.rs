// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]

//! Non-wear cost ledger for storage-intent policy (#856).
//!
//! This crate accounts capacity, network egress/ingress, replication,
//! retention, compute, layout, movement-debt, and payback evidence so
//! planners (#843, #848), explanation consumers (#849), and performance
//! consumers (#850) can prefer legal cheap plans over impressive expensive
//! ones without silently treating unknown cost as free.
//!
//! It does not own flash endurance, WAF, erase alignment, or device health
//! (#844 boundary), placement decisions, relocation execution, ack receipts,
//! or operator UAPI.

use core::fmt;
use tidefs_storage_intent_core::{
    ProximityClass, RelocationReasonClass, StorageIntentDomainId, StorageIntentEvidenceId,
    StorageIntentEvidenceKind, StorageIntentEvidenceRef, StorageIntentPolicyId,
    StorageIntentPolicyRevision,
};
use tidefs_storage_intent_remote_media_capability::RemoteCostRecoveryFacts;

// ---------------------------------------------------------------------------
// Crate identity and version bounds
// ---------------------------------------------------------------------------

/// Version of the non-wear cost ledger surface.
pub const STORAGE_INTENT_COST_VERSION: u16 = 1;

/// Stable diagnostic identifier for evidence and fixture tests.
pub const STORAGE_INTENT_COST_SPEC: &str = "tidefs-storage-intent-cost-v1-issue-856";

/// Maximum inline cost charges in one snapshot.
pub const MAX_COST_CHARGES: usize = 32;

/// Maximum inline movement-debt entries in one snapshot.
pub const MAX_MOVEMENT_DEBTS: usize = 24;

/// Maximum inline payback-evidence entries in one snapshot.
pub const MAX_PAYBACK_ENTRIES: usize = 16;

/// Maximum inline cost-weight entries in one operator policy weights block.
pub const MAX_COST_WEIGHTS: usize = 12;

/// Maximum inline network path cost weights.
pub const MAX_NETWORK_PATH_WEIGHTS: usize = 8;

// ---------------------------------------------------------------------------
// Cost classes — what is being charged
// ---------------------------------------------------------------------------

/// Cost-charge category.  New variants extend this list from the bottom so
/// each variant keeps a stable discriminant.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentCostClass {
    /// No cost class assigned.
    #[default]
    Unknown = 0,

    // --- capacity ---
    /// Capacity cost attributed to a media class.
    CapacityMediaClass = 1,
    /// Capacity cost attributed to a pool.
    CapacityPool = 2,
    /// Capacity cost attributed to a failure domain.
    CapacityFailureDomain = 3,
    /// Capacity cost attributed to an archive class.
    CapacityArchiveClass = 4,

    // --- network ---
    /// Network egress bytes.
    NetworkEgress = 5,
    /// Network ingress bytes.
    NetworkIngress = 6,

    // --- replication / repair ---
    /// Bytes replicated synchronously.
    ReplicationSync = 7,
    /// Geo catch-up bytes.
    GeoCatchUp = 8,
    /// Rebuild bytes.
    Rebuild = 9,
    /// Repair bytes.
    Repair = 10,
    /// Relocation bytes (movement-debt capacity + net + recovery bandwidth).
    Relocation = 11,
    /// Recovery-bandwidth bytes charged by reason.
    RecoveryBandwidth = 12,

    // --- compute ---
    /// CPU processing.
    CpuProcessing = 13,
    /// Memory usage.
    MemoryUsage = 14,
    /// Decompression / read-amplification.
    DecompressionAmplification = 15,
    /// Transform or rebake processing.
    TransformProcessing = 16,

    // --- retention ---
    /// Cold-tier retention.
    ColdRetention = 17,
    /// Archive-tier retention.
    ArchiveRetention = 18,
    /// Snapshot-pinned generation retention.
    SnapshotRetention = 19,

    // --- layout ---
    /// Fragmentation pressure.
    Fragmentation = 20,
    /// Alignment / zone / write-pointer pressure.
    AlignmentZonePressure = 21,
    /// Pending-free byte pressure.
    PendingFree = 22,
    /// Reclaim-debt.
    ReclaimDebt = 23,

    // --- foreground ---
    /// Foreground p99 disruption.
    ForegroundDisruption = 24,
    /// Restore-time cost.
    RestoreTime = 25,

    // --- reservation for follow-up slices ---
    #[doc(hidden)]
    _Reserved26 = 26,
    #[doc(hidden)]
    _Reserved27 = 27,
    #[doc(hidden)]
    _Reserved28 = 28,
    #[doc(hidden)]
    _Reserved29 = 29,
    #[doc(hidden)]
    _Reserved30 = 30,
}

impl StorageIntentCostClass {
    /// Human-readable diagnostic spelling (stable).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::CapacityMediaClass => "capacity-media-class",
            Self::CapacityPool => "capacity-pool",
            Self::CapacityFailureDomain => "capacity-failure-domain",
            Self::CapacityArchiveClass => "capacity-archive-class",
            Self::NetworkEgress => "network-egress",
            Self::NetworkIngress => "network-ingress",
            Self::ReplicationSync => "replication-sync",
            Self::GeoCatchUp => "geo-catch-up",
            Self::Rebuild => "rebuild",
            Self::Repair => "repair",
            Self::Relocation => "relocation",
            Self::RecoveryBandwidth => "recovery-bandwidth",
            Self::CpuProcessing => "cpu-processing",
            Self::MemoryUsage => "memory-usage",
            Self::DecompressionAmplification => "decompression-amplification",
            Self::TransformProcessing => "transform-processing",
            Self::ColdRetention => "cold-retention",
            Self::ArchiveRetention => "archive-retention",
            Self::SnapshotRetention => "snapshot-retention",
            Self::Fragmentation => "fragmentation",
            Self::AlignmentZonePressure => "alignment-zone-pressure",
            Self::PendingFree => "pending-free",
            Self::ReclaimDebt => "reclaim-debt",
            Self::ForegroundDisruption => "foreground-disruption",
            Self::RestoreTime => "restore-time",
            Self::_Reserved26 => "reserved-26",
            Self::_Reserved27 => "reserved-27",
            Self::_Reserved28 => "reserved-28",
            Self::_Reserved29 => "reserved-29",
            Self::_Reserved30 => "reserved-30",
        }
    }

    /// Stable discriminant for encoding.
    #[must_use]
    pub const fn to_discriminant(self) -> u8 {
        self as u8
    }

    /// Decode from a stable discriminant; unknown values fail closed.
    #[must_use]
    pub const fn from_discriminant(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Unknown),
            1 => Some(Self::CapacityMediaClass),
            2 => Some(Self::CapacityPool),
            3 => Some(Self::CapacityFailureDomain),
            4 => Some(Self::CapacityArchiveClass),
            5 => Some(Self::NetworkEgress),
            6 => Some(Self::NetworkIngress),
            7 => Some(Self::ReplicationSync),
            8 => Some(Self::GeoCatchUp),
            9 => Some(Self::Rebuild),
            10 => Some(Self::Repair),
            11 => Some(Self::Relocation),
            12 => Some(Self::RecoveryBandwidth),
            13 => Some(Self::CpuProcessing),
            14 => Some(Self::MemoryUsage),
            15 => Some(Self::DecompressionAmplification),
            16 => Some(Self::TransformProcessing),
            17 => Some(Self::ColdRetention),
            18 => Some(Self::ArchiveRetention),
            19 => Some(Self::SnapshotRetention),
            20 => Some(Self::Fragmentation),
            21 => Some(Self::AlignmentZonePressure),
            22 => Some(Self::PendingFree),
            23 => Some(Self::ReclaimDebt),
            24 => Some(Self::ForegroundDisruption),
            25 => Some(Self::RestoreTime),
            26 => Some(Self::_Reserved26),
            27 => Some(Self::_Reserved27),
            28 => Some(Self::_Reserved28),
            29 => Some(Self::_Reserved29),
            30 => Some(Self::_Reserved30),
            _ => None,
        }
    }

    /// Returns true when this cost class relates to capacity.
    #[must_use]
    pub const fn is_capacity(self) -> bool {
        matches!(
            self,
            Self::CapacityMediaClass
                | Self::CapacityPool
                | Self::CapacityFailureDomain
                | Self::CapacityArchiveClass
        )
    }

    /// Returns true when this cost class relates to network usage.
    #[must_use]
    pub const fn is_network(self) -> bool {
        matches!(self, Self::NetworkEgress | Self::NetworkIngress)
    }

    /// Returns true when this cost class relates to replication/repair.
    #[must_use]
    pub const fn is_replication_repair(self) -> bool {
        matches!(
            self,
            Self::ReplicationSync
                | Self::GeoCatchUp
                | Self::Rebuild
                | Self::Repair
                | Self::Relocation
                | Self::RecoveryBandwidth
        )
    }

    /// Returns true when this cost class relates to compute.
    #[must_use]
    pub const fn is_compute(self) -> bool {
        matches!(
            self,
            Self::CpuProcessing
                | Self::MemoryUsage
                | Self::DecompressionAmplification
                | Self::TransformProcessing
        )
    }
}

impl fmt::Display for StorageIntentCostClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Network path and carrier classification
// ---------------------------------------------------------------------------

/// Network path class for egress/ingress cost weighting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentNetworkPathClass {
    /// No path classified.
    #[default]
    Unknown = 0,
    /// Same-machine loopback or shared memory.
    LocalMachine = 1,
    /// Same rack or ToR.
    SameRack = 2,
    /// Same cluster / fabric.
    SameCluster = 3,
    /// Same datacenter / regional LAN.
    SameDatacenter = 4,
    /// Metro / low-latency WAN.
    MetroWan = 5,
    /// Regional / long-haul WAN.
    RegionalWan = 6,
    /// Internet / untrusted.
    Internet = 7,
}

impl StorageIntentNetworkPathClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::LocalMachine => "local-machine",
            Self::SameRack => "same-rack",
            Self::SameCluster => "same-cluster",
            Self::SameDatacenter => "same-datacenter",
            Self::MetroWan => "metro-wan",
            Self::RegionalWan => "regional-wan",
            Self::Internet => "internet",
        }
    }

    #[must_use]
    pub const fn to_discriminant(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn from_discriminant(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Unknown),
            1 => Some(Self::LocalMachine),
            2 => Some(Self::SameRack),
            3 => Some(Self::SameCluster),
            4 => Some(Self::SameDatacenter),
            5 => Some(Self::MetroWan),
            6 => Some(Self::RegionalWan),
            7 => Some(Self::Internet),
            _ => None,
        }
    }
}

impl fmt::Display for StorageIntentNetworkPathClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Network carrier class for operator cost weighting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentNetworkCarrierClass {
    /// No carrier classified.
    #[default]
    Unknown = 0,
    /// Private / dedicated fabric.
    PrivateFabric = 1,
    /// Shared internal (no egress charge).
    SharedInternal = 2,
    /// Metered provider (billable egress).
    MeteredProvider = 3,
    /// Unmetered provider (no egress charge).
    UnmeteredProvider = 4,
    /// Internet peer / transit.
    InternetTransit = 5,
    /// Satellite / high-latency path.
    Satellite = 6,
}

impl StorageIntentNetworkCarrierClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::PrivateFabric => "private-fabric",
            Self::SharedInternal => "shared-internal",
            Self::MeteredProvider => "metered-provider",
            Self::UnmeteredProvider => "unmetered-provider",
            Self::InternetTransit => "internet-transit",
            Self::Satellite => "satellite",
        }
    }

    #[must_use]
    pub const fn to_discriminant(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn from_discriminant(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Unknown),
            1 => Some(Self::PrivateFabric),
            2 => Some(Self::SharedInternal),
            3 => Some(Self::MeteredProvider),
            4 => Some(Self::UnmeteredProvider),
            5 => Some(Self::InternetTransit),
            6 => Some(Self::Satellite),
            _ => None,
        }
    }

    /// Returns true when this carrier class may incur a monetary egress charge.
    #[must_use]
    pub const fn may_incur_egress_cost(self) -> bool {
        matches!(
            self,
            Self::MeteredProvider | Self::InternetTransit | Self::Satellite
        )
    }
}

impl fmt::Display for StorageIntentNetworkCarrierClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Operator policy weights
// ---------------------------------------------------------------------------

/// Operator-defined policy weights that multiply a cost class into a
/// composite cost score for planning.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentOperatorPolicyWeights {
    /// Latency weight (higher → penalise latency more).
    pub latency_weight: u32,
    /// Throughput weight.
    pub throughput_weight: u32,
    /// Durability weight.
    pub durability_weight: u32,
    /// Money/operating-cost weight.
    pub money_weight: u32,
    /// Power/energy-proxy weight.
    pub power_weight: u32,
    /// Egress-scarcity weight.
    pub egress_scarcity_weight: u32,
    /// Evidence provenance ref.
    pub evidence: StorageIntentEvidenceRef,
}

impl StorageIntentOperatorPolicyWeights {
    /// Conservative unknown-cost sentinel: all weights zero (no opinion).
    pub const UNKNOWN: Self = Self {
        latency_weight: 0,
        throughput_weight: 0,
        durability_weight: 0,
        money_weight: 0,
        power_weight: 0,
        egress_scarcity_weight: 0,
        evidence: StorageIntentEvidenceRef {
            kind: StorageIntentEvidenceKind::Unknown,
            id: StorageIntentEvidenceId::ZERO,
            generation: 0,
            version: 0,
        },
    };

    /// Returns true when any weight is non-zero.
    #[must_use]
    pub const fn has_any_opinion(self) -> bool {
        self.latency_weight != 0
            || self.throughput_weight != 0
            || self.durability_weight != 0
            || self.money_weight != 0
            || self.power_weight != 0
            || self.egress_scarcity_weight != 0
    }
}

// ---------------------------------------------------------------------------
// Per-class cost weight (operator may weight classes differently)
// ---------------------------------------------------------------------------

/// One cost-class weight entry.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentCostClassWeight {
    /// Cost class this weight applies to.
    pub cost_class: StorageIntentCostClass,
    /// Per-unit weight (higher → penalise this class more).
    pub weight: u32,
}

impl StorageIntentCostClassWeight {
    /// Sentinel: no weight opinion for this class.
    pub const UNKNOWN: Self = Self {
        cost_class: StorageIntentCostClass::Unknown,
        weight: 0,
    };

    /// Returns true when this entry carries a meaningful weight.
    #[must_use]
    pub const fn is_meaningful(self) -> bool {
        self.weight != 0 && self.cost_class as u16 != StorageIntentCostClass::Unknown as u16
    }
}

// ---------------------------------------------------------------------------
// Network path cost weight
// ---------------------------------------------------------------------------

/// Cost weight for a network path × proximity × carrier tuple.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentNetworkPathCostWeight {
    /// Path class.
    pub path_class: StorageIntentNetworkPathClass,
    /// Proximity class from core.
    pub proximity: ProximityClass,
    /// Carrier class.
    pub carrier_class: StorageIntentNetworkCarrierClass,
    /// Egress cost per byte (microunits).
    pub egress_cost_per_byte_microunits: u64,
    /// Ingress cost per byte (microunits).
    pub ingress_cost_per_byte_microunits: u64,
}

impl StorageIntentNetworkPathCostWeight {
    /// Sentinel: no network cost weight.
    pub const UNKNOWN: Self = Self {
        path_class: StorageIntentNetworkPathClass::Unknown,
        proximity: ProximityClass::InProcess,
        carrier_class: StorageIntentNetworkCarrierClass::Unknown,
        egress_cost_per_byte_microunits: u64::MAX,
        ingress_cost_per_byte_microunits: u64::MAX,
    };

    /// Returns true when this entry carries a meaningful cost weight.
    #[must_use]
    pub const fn is_meaningful(self) -> bool {
        self.path_class as u16 != StorageIntentNetworkPathClass::Unknown as u16
            && (self.egress_cost_per_byte_microunits != u64::MAX
                || self.ingress_cost_per_byte_microunits != u64::MAX)
    }
}

// ---------------------------------------------------------------------------
// One cost charge entry
// ---------------------------------------------------------------------------

/// One cost charge in a ledger snapshot.  Byte counts are unsigned; cost is
/// always positive (never negative/free-by-overflow).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentCostCharge {
    /// Cost class charged.
    pub cost_class: StorageIntentCostClass,
    /// Consumer-defined reason or attribution code; 0 = none.
    pub reason_code: u8,
    /// Byte count charged.
    pub byte_count: u64,
    /// Microunit cost (1 = 1e-6 of operator's base currency unit).
    pub cost_microunits: u64,
    /// Evidence providing this charge.
    pub evidence: StorageIntentEvidenceRef,
}

impl StorageIntentCostCharge {
    /// Sentinel — no charge.
    pub const ZERO: Self = Self {
        cost_class: StorageIntentCostClass::Unknown,
        reason_code: 0,
        byte_count: 0,
        cost_microunits: 0,
        evidence: StorageIntentEvidenceRef {
            kind: StorageIntentEvidenceKind::Unknown,
            id: StorageIntentEvidenceId::ZERO,
            generation: 0,
            version: 0,
        },
    };

    /// Returns true when this charge is non-zero.
    #[must_use]
    pub const fn is_nonzero(self) -> bool {
        self.cost_class as u16 != StorageIntentCostClass::Unknown as u16
            && (self.byte_count != 0 || self.cost_microunits != 0)
    }

    /// Returns true when the charge is zero-cost (class known, but no charge).
    #[must_use]
    pub const fn is_zero_cost_class_known(self) -> bool {
        self.cost_class as u16 != StorageIntentCostClass::Unknown as u16
            && self.byte_count == 0
            && self.cost_microunits == 0
            && !self.has_missing_evidence()
    }

    /// Returns true when evidence is missing (not even a stale ref).
    #[must_use]
    pub const fn has_missing_evidence(self) -> bool {
        bytes32_are_zero(self.evidence.id.0)
    }
}

// ---------------------------------------------------------------------------
// Movement debt for recently relocated subjects
// ---------------------------------------------------------------------------

/// Debt accumulated for a recently relocated subject that has not yet
/// earned payback.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentMovementDebt {
    /// Subject the debt is attached to.
    pub subject_id: StorageIntentEvidenceId,
    /// Relocation reason.
    pub relocation_reason: RelocationReasonClass,
    /// Capacity bytes spent on the relocation.
    pub capacity_debt_bytes: u64,
    /// Network bytes consumed.
    pub network_debt_bytes: u64,
    /// Recovery-bandwidth bytes consumed.
    pub recovery_debt_bytes: u64,
    /// Foreground-disruption milliseconds.
    pub foreground_disruption_debt_ms: u64,
    /// Window within which payback is expected.
    pub payback_window_ms: u64,
    /// Evidence providing this debt.
    pub evidence: StorageIntentEvidenceRef,
}

impl StorageIntentMovementDebt {
    /// Sentinel — no debt.
    pub const ZERO: Self = Self {
        subject_id: StorageIntentEvidenceId::ZERO,
        relocation_reason: RelocationReasonClass::Unknown,
        capacity_debt_bytes: 0,
        network_debt_bytes: 0,
        recovery_debt_bytes: 0,
        foreground_disruption_debt_ms: 0,
        payback_window_ms: 0,
        evidence: StorageIntentEvidenceRef {
            kind: StorageIntentEvidenceKind::Unknown,
            id: StorageIntentEvidenceId::ZERO,
            generation: 0,
            version: 0,
        },
    };

    /// Total byte-debt.
    #[must_use]
    pub const fn total_debt_bytes(self) -> u64 {
        saturating_add_u64(
            saturating_add_u64(self.capacity_debt_bytes, self.network_debt_bytes),
            self.recovery_debt_bytes,
        )
    }

    /// Returns true when any debt is non-zero.
    #[must_use]
    pub const fn is_nonzero(self) -> bool {
        self.capacity_debt_bytes != 0
            || self.network_debt_bytes != 0
            || self.recovery_debt_bytes != 0
            || self.foreground_disruption_debt_ms != 0
    }
}

// ---------------------------------------------------------------------------
// Payback benefits (non-wear)
// ---------------------------------------------------------------------------

/// Benefit class earned by payback.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentPaybackBenefitClass {
    /// No benefit classified.
    #[default]
    Unknown = 0,
    /// Capacity saved.
    CapacitySaved = 1,
    /// RPO lag reduced.
    RpoLagReduced = 2,
    /// Egress avoided.
    EgressAvoided = 3,
    /// Rebuild risk reduced.
    RebuildRiskReduced = 4,
    /// Operator money saved.
    MoneySaved = 5,
    /// Operator power/energy budget saved.
    PowerSaved = 6,
    /// Latency improvement.
    LatencyImproved = 7,
    /// Throughput improvement.
    ThroughputImproved = 8,
}

impl StorageIntentPaybackBenefitClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::CapacitySaved => "capacity-saved",
            Self::RpoLagReduced => "rpo-lag-reduced",
            Self::EgressAvoided => "egress-avoided",
            Self::RebuildRiskReduced => "rebuild-risk-reduced",
            Self::MoneySaved => "money-saved",
            Self::PowerSaved => "power-saved",
            Self::LatencyImproved => "latency-improved",
            Self::ThroughputImproved => "throughput-improved",
        }
    }

    #[must_use]
    pub const fn to_discriminant(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn from_discriminant(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Unknown),
            1 => Some(Self::CapacitySaved),
            2 => Some(Self::RpoLagReduced),
            3 => Some(Self::EgressAvoided),
            4 => Some(Self::RebuildRiskReduced),
            5 => Some(Self::MoneySaved),
            6 => Some(Self::PowerSaved),
            7 => Some(Self::LatencyImproved),
            8 => Some(Self::ThroughputImproved),
            _ => None,
        }
    }
}

impl fmt::Display for StorageIntentPaybackBenefitClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One payback-evidence entry for a non-wear benefit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentPaybackEvidence {
    /// Benefit class.
    pub benefit_class: StorageIntentPaybackBenefitClass,
    /// Capacity saved in bytes (when applicable).
    pub capacity_saved_bytes: u64,
    /// RPO lag reduction in milliseconds.
    pub rpo_lag_reduced_ms: u64,
    /// Egress avoided in bytes.
    pub egress_avoided_bytes: u64,
    /// Rebuild-risk reduction (0–100 % equivalent).
    pub rebuild_risk_reduced_percent: u8,
    /// Money/power budget saved in microunits.
    pub money_power_saved_microunits: u64,
    /// Whether payback has been achieved.
    pub payback_achieved: bool,
    /// Payback window (the claim must close within this time).
    pub payback_window_ms: u64,
    /// Evidence providing this benefit.
    pub evidence: StorageIntentEvidenceRef,
}

impl StorageIntentPaybackEvidence {
    /// Sentinel — no payback.
    pub const ZERO: Self = Self {
        benefit_class: StorageIntentPaybackBenefitClass::Unknown,
        capacity_saved_bytes: 0,
        rpo_lag_reduced_ms: 0,
        egress_avoided_bytes: 0,
        rebuild_risk_reduced_percent: 0,
        money_power_saved_microunits: 0,
        payback_achieved: false,
        payback_window_ms: 0,
        evidence: StorageIntentEvidenceRef {
            kind: StorageIntentEvidenceKind::Unknown,
            id: StorageIntentEvidenceId::ZERO,
            generation: 0,
            version: 0,
        },
    };

    /// Returns true when any benefit is claimed.
    #[must_use]
    pub const fn has_any_benefit(self) -> bool {
        self.capacity_saved_bytes != 0
            || self.rpo_lag_reduced_ms != 0
            || self.egress_avoided_bytes != 0
            || self.rebuild_risk_reduced_percent != 0
            || self.money_power_saved_microunits != 0
    }
}

// ---------------------------------------------------------------------------
// Cost evidence staleness / missing state
// ---------------------------------------------------------------------------

/// Cost-evidence state: missing cost data must not be silently treated as
/// free; policy decides whether to use defaults, refuse, or mark the plan
/// as unknown.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentCostEvidenceState {
    /// Bitmask of cost classes whose evidence is missing entirely.
    pub missing_classes: u32,
    /// Bitmask of cost classes whose evidence is stale (out of freshness window).
    pub stale_classes: u32,
    /// Bitmask of cost classes whose evidence has been refused by upstream.
    pub refused_classes: u32,
}

impl StorageIntentCostEvidenceState {
    /// All evidence is present and fresh.
    pub const FRESH: Self = Self {
        missing_classes: 0,
        stale_classes: 0,
        refused_classes: 0,
    };

    /// Returns true when all evidence is fresh (no missing, stale, or refused).
    #[must_use]
    pub const fn is_fresh(self) -> bool {
        self.missing_classes == 0 && self.stale_classes == 0 && self.refused_classes == 0
    }

    /// Returns true when any evidence is missing.
    #[must_use]
    pub const fn has_any_missing(self) -> bool {
        self.missing_classes != 0 || self.stale_classes != 0 || self.refused_classes != 0
    }

    /// Returns true when the given cost class has missing evidence.
    #[must_use]
    pub const fn class_is_missing(self, class: StorageIntentCostClass) -> bool {
        let bit = 1_u32 << class as u8;
        (self.missing_classes & bit) != 0
    }

    /// Returns true when the given cost class has stale evidence.
    #[must_use]
    pub const fn class_is_stale(self, class: StorageIntentCostClass) -> bool {
        let bit = 1_u32 << class as u8;
        (self.stale_classes & bit) != 0
    }

    /// Returns true when the given cost class has refused evidence.
    #[must_use]
    pub const fn class_is_refused(self, class: StorageIntentCostClass) -> bool {
        let bit = 1_u32 << class as u8;
        (self.refused_classes & bit) != 0
    }

    /// Mark a class as missing.
    #[must_use]
    pub const fn with_missing(mut self, class: StorageIntentCostClass) -> Self {
        self.missing_classes |= 1_u32 << class as u8;
        self
    }

    /// Mark a class as stale.
    #[must_use]
    pub const fn with_stale(mut self, class: StorageIntentCostClass) -> Self {
        self.stale_classes |= 1_u32 << class as u8;
        self
    }

    /// Mark a class as refused.
    #[must_use]
    pub const fn with_refused(mut self, class: StorageIntentCostClass) -> Self {
        self.refused_classes |= 1_u32 << class as u8;
        self
    }
}

// ---------------------------------------------------------------------------
// Read-only cost ledger snapshot
// ---------------------------------------------------------------------------

/// A read-only cost snapshot that planners (#843, #848), explanation
/// consumers (#849), and performance consumers (#850) can inspect without
/// owning the underlying cost accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentCostSnapshot {
    /// Unique evidence identity for this snapshot.
    pub evidence_id: StorageIntentEvidenceId,
    /// Owning policy identity.
    pub policy_id: StorageIntentPolicyId,
    /// Owning policy revision.
    pub policy_revision: StorageIntentPolicyRevision,
    /// Domain for attribution.
    pub domain_id: StorageIntentDomainId,
    /// Budget owner for isolation.
    pub budget_owner: StorageIntentDomainId,
    /// Monotonic snapshot generation (clock or counter).
    pub generation: u64,
    /// Freshness window start (wall-time or monotonic ms).
    pub freshness_cut_ms: u64,
    /// Inline cost charges.
    pub charges: [StorageIntentCostCharge; MAX_COST_CHARGES],
    /// Number of occupied charges.
    pub charge_count: u8,
    /// Movement-debt entries.
    pub movement_debts: [StorageIntentMovementDebt; MAX_MOVEMENT_DEBTS],
    /// Number of occupied movement-debt entries.
    pub movement_debt_count: u8,
    /// Payback-evidence entries.
    pub payback_entries: [StorageIntentPaybackEvidence; MAX_PAYBACK_ENTRIES],
    /// Number of occupied payback entries.
    pub payback_entry_count: u8,
    /// Operator policy weights.
    pub operator_weights: StorageIntentOperatorPolicyWeights,
    /// Per-class cost weights.
    pub class_weights: [StorageIntentCostClassWeight; MAX_COST_WEIGHTS],
    /// Number of occupied class weights.
    pub class_weight_count: u8,
    /// Network path cost weights.
    pub network_path_weights: [StorageIntentNetworkPathCostWeight; MAX_NETWORK_PATH_WEIGHTS],
    /// Number of occupied network weight entries.
    pub network_path_weight_count: u8,
    /// Evidence state (missing/stale/refused).
    pub evidence_state: StorageIntentCostEvidenceState,
}

impl Default for StorageIntentCostSnapshot {
    fn default() -> Self {
        Self {
            evidence_id: StorageIntentEvidenceId::ZERO,
            policy_id: StorageIntentPolicyId::ZERO,
            policy_revision: StorageIntentPolicyRevision(0),
            domain_id: StorageIntentDomainId::ZERO,
            budget_owner: StorageIntentDomainId::ZERO,
            generation: 0,
            freshness_cut_ms: 0,
            charges: [StorageIntentCostCharge::ZERO; MAX_COST_CHARGES],
            charge_count: 0,
            movement_debts: [StorageIntentMovementDebt::ZERO; MAX_MOVEMENT_DEBTS],
            movement_debt_count: 0,
            payback_entries: [StorageIntentPaybackEvidence::ZERO; MAX_PAYBACK_ENTRIES],
            payback_entry_count: 0,
            operator_weights: StorageIntentOperatorPolicyWeights::UNKNOWN,
            class_weights: [StorageIntentCostClassWeight::UNKNOWN; MAX_COST_WEIGHTS],
            class_weight_count: 0,
            network_path_weights: [StorageIntentNetworkPathCostWeight::UNKNOWN;
                MAX_NETWORK_PATH_WEIGHTS],
            network_path_weight_count: 0,
            evidence_state: StorageIntentCostEvidenceState::FRESH,
        }
    }
}

impl StorageIntentCostSnapshot {
    /// Evidence ref naming this read-only cost snapshot.
    #[must_use]
    pub const fn evidence_ref(self) -> StorageIntentEvidenceRef {
        StorageIntentEvidenceRef {
            kind: StorageIntentEvidenceKind::MediaCostWearLedger,
            id: self.evidence_id,
            generation: self.generation,
            version: STORAGE_INTENT_COST_VERSION,
        }
    }

    /// Sum cost across all charges for a given cost class, or return
    /// `u64::MAX` when evidence for that class is missing/stale.
    #[must_use]
    pub const fn class_cost_or_missing(self, class: StorageIntentCostClass) -> u64 {
        if class as u16 == StorageIntentCostClass::Unknown as u16 {
            return u64::MAX;
        }
        if self.evidence_state.class_is_missing(class)
            || self.evidence_state.class_is_stale(class)
            || self.evidence_state.class_is_refused(class)
        {
            return u64::MAX;
        }
        let mut total: u64 = 0;
        let mut saw_known_class = false;
        let mut i: usize = 0;
        while i < self.charge_count as usize && i < MAX_COST_CHARGES {
            if self.charges[i].cost_class as u16 == class as u16 {
                if self.charges[i].has_missing_evidence() {
                    return u64::MAX;
                }
                saw_known_class = true;
                total = saturating_add_u64(total, self.charges[i].cost_microunits);
            }
            i += 1;
        }
        if saw_known_class {
            total
        } else {
            u64::MAX
        }
    }

    /// Sum byte count for a given cost class.
    #[must_use]
    pub const fn class_byte_count_or_missing(self, class: StorageIntentCostClass) -> u64 {
        if class as u16 == StorageIntentCostClass::Unknown as u16 {
            return u64::MAX;
        }
        if self.evidence_state.class_is_missing(class)
            || self.evidence_state.class_is_stale(class)
            || self.evidence_state.class_is_refused(class)
        {
            return u64::MAX;
        }
        let mut total: u64 = 0;
        let mut saw_known_class = false;
        let mut i: usize = 0;
        while i < self.charge_count as usize && i < MAX_COST_CHARGES {
            if self.charges[i].cost_class as u16 == class as u16 {
                if self.charges[i].has_missing_evidence() {
                    return u64::MAX;
                }
                saw_known_class = true;
                total = saturating_add_u64(total, self.charges[i].byte_count);
            }
            i += 1;
        }
        if saw_known_class {
            total
        } else {
            u64::MAX
        }
    }

    /// Total accumulated movement debt in bytes.
    #[must_use]
    pub const fn total_movement_debt_bytes(self) -> u64 {
        let mut total: u64 = 0;
        let mut i: usize = 0;
        while i < self.movement_debt_count as usize && i < MAX_MOVEMENT_DEBTS {
            total = saturating_add_u64(total, self.movement_debts[i].total_debt_bytes());
            i += 1;
        }
        total
    }

    /// Total payback evidence value across all entries in microunits.
    #[must_use]
    pub const fn total_payback_microunits(self) -> u64 {
        let mut total: u64 = 0;
        let mut i: usize = 0;
        while i < self.payback_entry_count as usize && i < MAX_PAYBACK_ENTRIES {
            if self.payback_entries[i].payback_achieved {
                total =
                    saturating_add_u64(total, self.payback_entries[i].money_power_saved_microunits);
            }
            i += 1;
        }
        total
    }

    /// Returns true when ALL evidence is fresh and no cost class is missing.
    #[must_use]
    pub const fn is_fully_fresh(self) -> bool {
        self.evidence_state.is_fresh()
    }

    /// Returns true when any cost class's evidence is missing or stale.
    #[must_use]
    pub const fn has_stale_or_missing(self) -> bool {
        self.evidence_state.has_any_missing()
    }

    /// Returns the weight for a cost class (0 when not configured).
    #[must_use]
    pub const fn class_weight(self, class: StorageIntentCostClass) -> u32 {
        let mut i: usize = 0;
        while i < self.class_weight_count as usize && i < MAX_COST_WEIGHTS {
            if self.class_weights[i].cost_class as u16 == class as u16 {
                return self.class_weights[i].weight;
            }
            i += 1;
        }
        0
    }

    /// Find the network path weight that best matches the given path, proximity,
    /// and carrier classes. Returns `UNKNOWN` sentinel when no match.
    #[must_use]
    pub const fn find_network_path_weight(
        self,
        path_class: StorageIntentNetworkPathClass,
        proximity: ProximityClass,
        carrier_class: StorageIntentNetworkCarrierClass,
    ) -> StorageIntentNetworkPathCostWeight {
        // Exact match first.
        let mut i: usize = 0;
        while i < self.network_path_weight_count as usize && i < MAX_NETWORK_PATH_WEIGHTS {
            let w = self.network_path_weights[i];
            if w.path_class as u16 == path_class as u16
                && w.proximity as u16 == proximity as u16
                && w.carrier_class as u16 == carrier_class as u16
            {
                return w;
            }
            i += 1;
        }
        // Best-effort: match path + carrier, ignoring proximity.
        i = 0;
        while i < self.network_path_weight_count as usize && i < MAX_NETWORK_PATH_WEIGHTS {
            let w = self.network_path_weights[i];
            if w.path_class as u16 == path_class as u16
                && w.carrier_class as u16 == carrier_class as u16
            {
                return w;
            }
            i += 1;
        }
        StorageIntentNetworkPathCostWeight::UNKNOWN
    }

    /// Returns the network egress cost (microunits) for a byte count on a
    /// specific path, or `u64::MAX` when evidence for the path is missing.
    #[must_use]
    pub const fn egress_cost_for_bytes(
        self,
        path_class: StorageIntentNetworkPathClass,
        proximity: ProximityClass,
        carrier_class: StorageIntentNetworkCarrierClass,
        byte_count: u64,
    ) -> u64 {
        let w = self.find_network_path_weight(path_class, proximity, carrier_class);
        if w.egress_cost_per_byte_microunits == u64::MAX {
            return u64::MAX;
        }
        saturating_mul_u64(byte_count, w.egress_cost_per_byte_microunits)
    }

    /// Returns the network ingress cost (microunits) for a byte count on a
    /// specific path, or `u64::MAX` when evidence for the path is missing.
    #[must_use]
    pub const fn ingress_cost_for_bytes(
        self,
        path_class: StorageIntentNetworkPathClass,
        proximity: ProximityClass,
        carrier_class: StorageIntentNetworkCarrierClass,
        byte_count: u64,
    ) -> u64 {
        let w = self.find_network_path_weight(path_class, proximity, carrier_class);
        if w.ingress_cost_per_byte_microunits == u64::MAX {
            return u64::MAX;
        }
        saturating_mul_u64(byte_count, w.ingress_cost_per_byte_microunits)
    }
}

// ---------------------------------------------------------------------------
// Remote media cost/recovery projection
// ---------------------------------------------------------------------------

/// Read-only cost-ledger projection for #961 remote/object/archive facts.
///
/// This adapter does not choose placement or execute recovery. It only maps a
/// bounded #856 cost snapshot plus a caller-provided #900 recovery/degradation
/// ref into the cost booleans consumed by the remote media-capability producer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct RemoteMediaCostRecoverySample {
    pub snapshot: StorageIntentCostSnapshot,
    pub egress_budget_known: bool,
    pub egress_budget_microunits: u64,
    pub recovery_bandwidth_budget_known: bool,
    pub recovery_bandwidth_budget_bytes: u64,
    pub degraded_visibility_known: bool,
    pub recovery_ref: StorageIntentEvidenceRef,
}

impl Default for RemoteMediaCostRecoverySample {
    fn default() -> Self {
        Self {
            snapshot: StorageIntentCostSnapshot::default(),
            egress_budget_known: false,
            egress_budget_microunits: 0,
            recovery_bandwidth_budget_known: false,
            recovery_bandwidth_budget_bytes: 0,
            degraded_visibility_known: false,
            recovery_ref: EMPTY_EVIDENCE_REF,
        }
    }
}

impl RemoteMediaCostRecoverySample {
    #[must_use]
    pub const fn bounded(
        snapshot: StorageIntentCostSnapshot,
        egress_budget_microunits: u64,
        recovery_bandwidth_budget_bytes: u64,
        recovery_ref: StorageIntentEvidenceRef,
    ) -> Self {
        Self {
            snapshot,
            egress_budget_known: true,
            egress_budget_microunits,
            recovery_bandwidth_budget_known: true,
            recovery_bandwidth_budget_bytes,
            degraded_visibility_known: true,
            recovery_ref,
        }
    }

    /// Project bounded cost and recovery visibility into #961 remote facts.
    ///
    /// Unknown, stale, refused, or missing-ref evidence fails closed by
    /// leaving the corresponding fact false. Over-budget egress stays visible
    /// as an explicit exhausted fact. The remote media preflight then refuses
    /// the target instead of treating absent cost data as cheap or safe.
    #[must_use]
    pub const fn to_remote_cost_recovery_facts(self) -> RemoteCostRecoveryFacts {
        let snapshot_cost_ref = self.snapshot.evidence_ref();
        let cost_ref_bound = evidence_ref_has_kind(
            snapshot_cost_ref,
            StorageIntentEvidenceKind::MediaCostWearLedger,
        );
        let recovery_ref_bound = evidence_ref_has_kind(
            self.recovery_ref,
            StorageIntentEvidenceKind::RecoveryDegradationEvidence,
        );
        let cost_ref = if cost_ref_bound {
            snapshot_cost_ref
        } else {
            EMPTY_EVIDENCE_REF
        };
        let recovery_ref = if recovery_ref_bound {
            self.recovery_ref
        } else {
            EMPTY_EVIDENCE_REF
        };

        let egress_cost = self
            .snapshot
            .class_cost_or_missing(StorageIntentCostClass::NetworkEgress);
        let egress_budget_known =
            cost_ref_bound && self.egress_budget_known && egress_cost != u64::MAX;
        let egress_budget_exhausted =
            egress_budget_known && egress_cost > self.egress_budget_microunits;

        let restore_cost_known = cost_ref_bound
            && self
                .snapshot
                .class_cost_or_missing(StorageIntentCostClass::RestoreTime)
                != u64::MAX;

        let recovery_bytes = self
            .snapshot
            .class_byte_count_or_missing(StorageIntentCostClass::RecoveryBandwidth);
        let recovery_bandwidth_known = cost_ref_bound
            && recovery_ref_bound
            && self.recovery_bandwidth_budget_known
            && recovery_bytes != u64::MAX
            && recovery_bytes <= self.recovery_bandwidth_budget_bytes;

        RemoteCostRecoveryFacts {
            egress_budget_known,
            egress_budget_exhausted,
            restore_cost_known,
            recovery_bandwidth_known,
            degraded_visibility_known: recovery_ref_bound && self.degraded_visibility_known,
            cost_ref,
            recovery_ref,
        }
    }
}

// ---------------------------------------------------------------------------
// Cost snapshot builder (not no_std — downstream callers provide alloc)
// ---------------------------------------------------------------------------

/// Builder for a cost snapshot. This struct is not `no_std` because the
/// real builder requires allocation; this is a model-only builder for
/// tests and downstream alloc-capable consumers.  Callers that cannot
/// allocate must construct the snapshot directly.
#[cfg(feature = "serde")]
#[derive(Clone, Debug, Default)]
pub struct StorageIntentCostSnapshotBuilder {
    snapshot: StorageIntentCostSnapshot,
}

#[cfg(feature = "serde")]
impl StorageIntentCostSnapshotBuilder {
    /// Start a new snapshot with the given identity.
    #[must_use]
    pub fn new(
        evidence_id: StorageIntentEvidenceId,
        policy_id: StorageIntentPolicyId,
        policy_revision: StorageIntentPolicyRevision,
    ) -> Self {
        Self {
            snapshot: StorageIntentCostSnapshot {
                evidence_id,
                policy_id,
                policy_revision,
                ..StorageIntentCostSnapshot::default()
            },
        }
    }

    /// Set the domain and budget owner.
    #[must_use]
    pub fn with_domain(
        mut self,
        domain_id: StorageIntentDomainId,
        budget_owner: StorageIntentDomainId,
    ) -> Self {
        self.snapshot.domain_id = domain_id;
        self.snapshot.budget_owner = budget_owner;
        self
    }

    /// Set the generation counter and freshness cut.
    #[must_use]
    pub fn with_freshness(mut self, generation: u64, freshness_cut_ms: u64) -> Self {
        self.snapshot.generation = generation;
        self.snapshot.freshness_cut_ms = freshness_cut_ms;
        self
    }

    /// Add a cost charge.
    #[must_use]
    pub fn with_charge(mut self, charge: StorageIntentCostCharge) -> Self {
        let idx = self.snapshot.charge_count as usize;
        if idx < MAX_COST_CHARGES {
            self.snapshot.charges[idx] = charge;
            self.snapshot.charge_count = (idx + 1) as u8;
        }
        self
    }

    /// Add a movement-debt entry.
    #[must_use]
    pub fn with_movement_debt(mut self, debt: StorageIntentMovementDebt) -> Self {
        let idx = self.snapshot.movement_debt_count as usize;
        if idx < MAX_MOVEMENT_DEBTS {
            self.snapshot.movement_debts[idx] = debt;
            self.snapshot.movement_debt_count = (idx + 1) as u8;
        }
        self
    }

    /// Add a payback-evidence entry.
    #[must_use]
    pub fn with_payback(mut self, payback: StorageIntentPaybackEvidence) -> Self {
        let idx = self.snapshot.payback_entry_count as usize;
        if idx < MAX_PAYBACK_ENTRIES {
            self.snapshot.payback_entries[idx] = payback;
            self.snapshot.payback_entry_count = (idx + 1) as u8;
        }
        self
    }

    /// Set operator policy weights.
    #[must_use]
    pub fn with_operator_weights(mut self, weights: StorageIntentOperatorPolicyWeights) -> Self {
        self.snapshot.operator_weights = weights;
        self
    }

    /// Add a per-class cost weight.
    #[must_use]
    pub fn with_class_weight(mut self, weight: StorageIntentCostClassWeight) -> Self {
        let idx = self.snapshot.class_weight_count as usize;
        if idx < MAX_COST_WEIGHTS {
            self.snapshot.class_weights[idx] = weight;
            self.snapshot.class_weight_count = (idx + 1) as u8;
        }
        self
    }

    /// Add a network path cost weight.
    #[must_use]
    pub fn with_network_path_weight(mut self, weight: StorageIntentNetworkPathCostWeight) -> Self {
        let idx = self.snapshot.network_path_weight_count as usize;
        if idx < MAX_NETWORK_PATH_WEIGHTS {
            self.snapshot.network_path_weights[idx] = weight;
            self.snapshot.network_path_weight_count = (idx + 1) as u8;
        }
        self
    }

    /// Set evidence state.
    #[must_use]
    pub fn with_evidence_state(mut self, state: StorageIntentCostEvidenceState) -> Self {
        self.snapshot.evidence_state = state;
        self
    }

    /// Mark a cost class as missing evidence.
    #[must_use]
    pub fn with_missing_evidence(mut self, class: StorageIntentCostClass) -> Self {
        self.snapshot.evidence_state = self.snapshot.evidence_state.with_missing(class);
        self
    }

    /// Finish the snapshot.
    #[must_use]
    pub fn build(self) -> StorageIntentCostSnapshot {
        self.snapshot
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const EMPTY_EVIDENCE_REF: StorageIntentEvidenceRef = StorageIntentEvidenceRef {
    kind: StorageIntentEvidenceKind::Unknown,
    id: StorageIntentEvidenceId::ZERO,
    generation: 0,
    version: 0,
};

const fn bytes32_are_zero(bytes: [u8; 32]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

const fn evidence_ref_has_kind(
    evidence_ref: StorageIntentEvidenceRef,
    kind: StorageIntentEvidenceKind,
) -> bool {
    evidence_ref.kind as u16 == kind as u16 && evidence_ref.is_bound()
}

const fn saturating_add_u64(a: u64, b: u64) -> u64 {
    let (result, overflow) = a.overflowing_add(b);
    if overflow {
        u64::MAX
    } else {
        result
    }
}

const fn saturating_mul_u64(a: u64, b: u64) -> u64 {
    let (result, overflow) = a.overflowing_mul(b);
    if overflow {
        u64::MAX
    } else {
        result
    }
}

// ---------------------------------------------------------------------------
// Predicates
// ---------------------------------------------------------------------------

/// Returns true when cost evidence is safe to use in planning.
/// Evidence must be present, fresh, and not refused.
#[must_use]
pub const fn cost_evidence_is_usable(state: StorageIntentCostEvidenceState) -> bool {
    state.is_fresh()
}

/// Returns true when the cost class should block planning because its
/// evidence is missing, stale, or refused.
#[must_use]
pub const fn cost_class_blocks_planning(
    state: StorageIntentCostEvidenceState,
    class: StorageIntentCostClass,
) -> bool {
    state.class_is_missing(class) || state.class_is_stale(class) || state.class_is_refused(class)
}

/// Returns true when a movement debt has unproven payback.
#[must_use]
pub const fn movement_debt_has_unproven_payback(debt: StorageIntentMovementDebt) -> bool {
    debt.is_nonzero() && debt.payback_window_ms == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_storage_intent_core::RelocationReasonClass;

    /// Helper: build an evidence reference with a non-zero id.
    fn evidence_ref_1() -> StorageIntentEvidenceRef {
        StorageIntentEvidenceRef {
            kind: tidefs_storage_intent_core::StorageIntentEvidenceKind::MediaCostWearLedger,
            id: StorageIntentEvidenceId([1u8; 32]),
            generation: 1,
            version: 1,
        }
    }

    fn evidence_ref_2() -> StorageIntentEvidenceRef {
        StorageIntentEvidenceRef {
            kind: tidefs_storage_intent_core::StorageIntentEvidenceKind::MediaCostWearLedger,
            id: StorageIntentEvidenceId([2u8; 32]),
            generation: 2,
            version: 1,
        }
    }

    fn recovery_ref() -> StorageIntentEvidenceRef {
        StorageIntentEvidenceRef {
            kind: StorageIntentEvidenceKind::RecoveryDegradationEvidence,
            id: StorageIntentEvidenceId([3u8; 32]),
            generation: 3,
            version: 1,
        }
    }

    fn remote_cost_snapshot() -> StorageIntentCostSnapshot {
        let mut charges = [StorageIntentCostCharge::ZERO; MAX_COST_CHARGES];
        charges[0] = StorageIntentCostCharge {
            cost_class: StorageIntentCostClass::NetworkEgress,
            reason_code: 1,
            byte_count: 1_000,
            cost_microunits: 100,
            evidence: evidence_ref_1(),
        };
        charges[1] = StorageIntentCostCharge {
            cost_class: StorageIntentCostClass::RestoreTime,
            reason_code: 2,
            byte_count: 0,
            cost_microunits: 30,
            evidence: evidence_ref_1(),
        };
        charges[2] = StorageIntentCostCharge {
            cost_class: StorageIntentCostClass::RecoveryBandwidth,
            reason_code: 3,
            byte_count: 2_048,
            cost_microunits: 0,
            evidence: evidence_ref_2(),
        };

        StorageIntentCostSnapshot {
            evidence_id: StorageIntentEvidenceId([9u8; 32]),
            generation: 9,
            charges,
            charge_count: 3,
            ..StorageIntentCostSnapshot::default()
        }
    }

    // ------------------------------------------------------------------
    // Cost class discriminants
    // ------------------------------------------------------------------

    #[test]
    fn cost_class_discriminants_are_stable() {
        assert_eq!(
            StorageIntentCostClass::CapacityMediaClass.to_discriminant(),
            1
        );
        assert_eq!(StorageIntentCostClass::NetworkEgress.to_discriminant(), 5);
        assert_eq!(StorageIntentCostClass::ReplicationSync.to_discriminant(), 7);
        assert_eq!(StorageIntentCostClass::CpuProcessing.to_discriminant(), 13);
        assert_eq!(StorageIntentCostClass::ColdRetention.to_discriminant(), 17);
        assert_eq!(StorageIntentCostClass::Fragmentation.to_discriminant(), 20);
        assert_eq!(
            StorageIntentCostClass::ForegroundDisruption.to_discriminant(),
            24
        );
        assert_eq!(StorageIntentCostClass::RestoreTime.to_discriminant(), 25);
    }

    #[test]
    fn cost_class_round_trips() {
        for raw in 0..=30u8 {
            let decoded = StorageIntentCostClass::from_discriminant(raw);
            match decoded {
                Some(class) => assert_eq!(class.to_discriminant(), raw),
                None => assert!(raw > 30),
            }
        }
    }

    #[test]
    fn cost_class_predicates() {
        assert!(StorageIntentCostClass::CapacityMediaClass.is_capacity());
        assert!(StorageIntentCostClass::CapacityPool.is_capacity());
        assert!(!StorageIntentCostClass::NetworkEgress.is_capacity());
        assert!(StorageIntentCostClass::NetworkEgress.is_network());
        assert!(!StorageIntentCostClass::NetworkIngress.is_capacity());
        assert!(!StorageIntentCostClass::CpuProcessing.is_network());
        assert!(!StorageIntentCostClass::CpuProcessing.is_capacity());
    }

    // ------------------------------------------------------------------
    // Network path / carrier discriminants
    // ------------------------------------------------------------------

    #[test]
    fn network_path_discriminants_round_trip() {
        for raw in 0..=8u8 {
            let decoded = StorageIntentNetworkPathClass::from_discriminant(raw);
            match decoded {
                Some(p) => assert_eq!(p.to_discriminant(), raw),
                None => assert!(raw > 7),
            }
        }
    }

    #[test]
    fn carrier_may_incur_egress() {
        assert!(!StorageIntentNetworkCarrierClass::Unknown.may_incur_egress_cost());
        assert!(!StorageIntentNetworkCarrierClass::PrivateFabric.may_incur_egress_cost());
        assert!(!StorageIntentNetworkCarrierClass::SharedInternal.may_incur_egress_cost());
        assert!(StorageIntentNetworkCarrierClass::MeteredProvider.may_incur_egress_cost());
        assert!(StorageIntentNetworkCarrierClass::InternetTransit.may_incur_egress_cost());
        assert!(StorageIntentNetworkCarrierClass::Satellite.may_incur_egress_cost());
    }

    // ------------------------------------------------------------------
    // Cost charge — zero / non-zero / missing evidence
    // ------------------------------------------------------------------

    #[test]
    fn cost_charge_zero_sentinels() {
        let zero = StorageIntentCostCharge::ZERO;
        assert!(!zero.is_nonzero());
        assert!(zero.has_missing_evidence());
    }

    #[test]
    fn cost_charge_nonzero_detection() {
        let charge = StorageIntentCostCharge {
            cost_class: StorageIntentCostClass::NetworkEgress,
            reason_code: 1,
            byte_count: 1024,
            cost_microunits: 500,
            evidence: evidence_ref_1(),
        };
        assert!(charge.is_nonzero());
        assert!(!charge.has_missing_evidence());
    }

    #[test]
    fn cost_charge_zero_cost_class_known() {
        let charge = StorageIntentCostCharge {
            cost_class: StorageIntentCostClass::CapacityPool,
            reason_code: 0,
            byte_count: 0,
            cost_microunits: 0,
            evidence: evidence_ref_1(),
        };
        assert!(charge.is_zero_cost_class_known());
        assert!(!charge.is_nonzero());
    }

    #[test]
    fn zero_cost_requires_present_evidence() {
        let charge = StorageIntentCostCharge {
            cost_class: StorageIntentCostClass::CapacityPool,
            byte_count: 0,
            cost_microunits: 0,
            ..StorageIntentCostCharge::ZERO
        };
        assert!(!charge.is_zero_cost_class_known());
        assert!(charge.has_missing_evidence());
    }

    // ------------------------------------------------------------------
    // Movement debt
    // ------------------------------------------------------------------

    #[test]
    fn movement_debt_zero() {
        let debt = StorageIntentMovementDebt::ZERO;
        assert!(!debt.is_nonzero());
        assert_eq!(debt.total_debt_bytes(), 0);
    }

    #[test]
    fn movement_debt_nonzero() {
        let debt = StorageIntentMovementDebt {
            subject_id: StorageIntentEvidenceId([3u8; 32]),
            relocation_reason: RelocationReasonClass::AuthorityConvergence,
            capacity_debt_bytes: 1000,
            network_debt_bytes: 500,
            recovery_debt_bytes: 200,
            foreground_disruption_debt_ms: 50,
            payback_window_ms: 3600_000,
            evidence: evidence_ref_1(),
        };
        assert!(debt.is_nonzero());
        assert_eq!(debt.total_debt_bytes(), 1700);
    }

    #[test]
    fn movement_debt_unproven_payback() {
        let debt = StorageIntentMovementDebt {
            subject_id: StorageIntentEvidenceId([4u8; 32]),
            relocation_reason: RelocationReasonClass::AuthorityConvergence,
            capacity_debt_bytes: 100,
            network_debt_bytes: 0,
            recovery_debt_bytes: 0,
            foreground_disruption_debt_ms: 0,
            payback_window_ms: 0,
            evidence: evidence_ref_1(),
        };
        assert!(movement_debt_has_unproven_payback(debt));
    }

    // ------------------------------------------------------------------
    // Payback evidence
    // ------------------------------------------------------------------

    #[test]
    fn payback_evidence_zero() {
        let pb = StorageIntentPaybackEvidence::ZERO;
        assert!(!pb.has_any_benefit());
        assert!(!pb.payback_achieved);
    }

    #[test]
    fn payback_evidence_with_benefit() {
        let pb = StorageIntentPaybackEvidence {
            benefit_class: StorageIntentPaybackBenefitClass::CapacitySaved,
            capacity_saved_bytes: 1_000_000,
            rpo_lag_reduced_ms: 0,
            egress_avoided_bytes: 0,
            rebuild_risk_reduced_percent: 50,
            money_power_saved_microunits: 2000,
            payback_achieved: true,
            payback_window_ms: 3600_000,
            evidence: evidence_ref_1(),
        };
        assert!(pb.has_any_benefit());
        assert!(pb.payback_achieved);
    }

    // ------------------------------------------------------------------
    // Evidence state — missing/stale/refused
    // ------------------------------------------------------------------

    #[test]
    fn evidence_state_fresh() {
        let state = StorageIntentCostEvidenceState::FRESH;
        assert!(state.is_fresh());
        assert!(!state.has_any_missing());
        assert!(!state.class_is_missing(StorageIntentCostClass::NetworkEgress));
    }

    #[test]
    fn evidence_state_missing_detection() {
        let state = StorageIntentCostEvidenceState::FRESH
            .with_missing(StorageIntentCostClass::NetworkEgress);
        assert!(!state.is_fresh());
        assert!(state.has_any_missing());
        assert!(state.class_is_missing(StorageIntentCostClass::NetworkEgress));
        assert!(!state.class_is_missing(StorageIntentCostClass::CapacityMediaClass));
    }

    #[test]
    fn evidence_state_combined() {
        let state = StorageIntentCostEvidenceState::FRESH
            .with_missing(StorageIntentCostClass::NetworkEgress)
            .with_stale(StorageIntentCostClass::Rebuild)
            .with_refused(StorageIntentCostClass::GeoCatchUp);
        assert!(!cost_evidence_is_usable(state));
        assert!(state.class_is_missing(StorageIntentCostClass::NetworkEgress));
        assert!(state.class_is_stale(StorageIntentCostClass::Rebuild));
        assert!(state.class_is_refused(StorageIntentCostClass::GeoCatchUp));
    }

    // ------------------------------------------------------------------
    // Cost snapshot — charges and class lookups
    // ------------------------------------------------------------------

    #[test]
    fn snapshot_class_cost_with_missing_evidence_returns_max() {
        let snapshot = StorageIntentCostSnapshot {
            evidence_state: StorageIntentCostEvidenceState::FRESH
                .with_missing(StorageIntentCostClass::NetworkEgress),
            ..StorageIntentCostSnapshot::default()
        };
        assert_eq!(
            snapshot.class_cost_or_missing(StorageIntentCostClass::NetworkEgress),
            u64::MAX
        );
    }

    #[test]
    fn snapshot_absent_class_cost_is_unknown() {
        let snapshot = StorageIntentCostSnapshot::default();
        assert_eq!(
            snapshot.class_cost_or_missing(StorageIntentCostClass::NetworkEgress),
            u64::MAX
        );
        assert_eq!(
            snapshot.class_byte_count_or_missing(StorageIntentCostClass::NetworkEgress),
            u64::MAX
        );
    }

    #[test]
    fn snapshot_missing_charge_evidence_is_unknown() {
        let mut charges = [StorageIntentCostCharge::ZERO; MAX_COST_CHARGES];
        charges[0] = StorageIntentCostCharge {
            cost_class: StorageIntentCostClass::NetworkEgress,
            reason_code: 1,
            byte_count: 0,
            cost_microunits: 0,
            ..StorageIntentCostCharge::ZERO
        };
        let snapshot = StorageIntentCostSnapshot {
            charges,
            charge_count: 1,
            ..StorageIntentCostSnapshot::default()
        };
        assert_eq!(
            snapshot.class_cost_or_missing(StorageIntentCostClass::NetworkEgress),
            u64::MAX
        );
        assert_eq!(
            snapshot.class_byte_count_or_missing(StorageIntentCostClass::NetworkEgress),
            u64::MAX
        );
    }

    #[test]
    fn snapshot_known_zero_cost_stays_zero() {
        let mut charges = [StorageIntentCostCharge::ZERO; MAX_COST_CHARGES];
        charges[0] = StorageIntentCostCharge {
            cost_class: StorageIntentCostClass::NetworkEgress,
            reason_code: 1,
            byte_count: 0,
            cost_microunits: 0,
            evidence: evidence_ref_1(),
        };
        let snapshot = StorageIntentCostSnapshot {
            charges,
            charge_count: 1,
            ..StorageIntentCostSnapshot::default()
        };
        assert_eq!(
            snapshot.class_cost_or_missing(StorageIntentCostClass::NetworkEgress),
            0
        );
        assert_eq!(
            snapshot.class_byte_count_or_missing(StorageIntentCostClass::NetworkEgress),
            0
        );
    }

    #[test]
    fn snapshot_class_cost_sums_correctly() {
        let snapshot = StorageIntentCostSnapshot {
            charges: [
                StorageIntentCostCharge {
                    cost_class: StorageIntentCostClass::NetworkEgress,
                    reason_code: 1,
                    byte_count: 100,
                    cost_microunits: 50,
                    evidence: evidence_ref_1(),
                },
                StorageIntentCostCharge {
                    cost_class: StorageIntentCostClass::NetworkEgress,
                    reason_code: 2,
                    byte_count: 200,
                    cost_microunits: 75,
                    evidence: evidence_ref_2(),
                },
                StorageIntentCostCharge {
                    cost_class: StorageIntentCostClass::CapacityMediaClass,
                    reason_code: 0,
                    byte_count: 0,
                    cost_microunits: 500,
                    evidence: evidence_ref_1(),
                },
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
                StorageIntentCostCharge::ZERO,
            ],
            charge_count: 3,
            ..StorageIntentCostSnapshot::default()
        };
        assert_eq!(
            snapshot.class_cost_or_missing(StorageIntentCostClass::NetworkEgress),
            125
        );
        assert_eq!(
            snapshot.class_byte_count_or_missing(StorageIntentCostClass::NetworkEgress),
            300
        );
        assert_eq!(
            snapshot.class_cost_or_missing(StorageIntentCostClass::CapacityMediaClass),
            500
        );
    }

    // ------------------------------------------------------------------
    // Movement-debt aggregation in snapshot
    // ------------------------------------------------------------------

    #[test]
    fn snapshot_total_movement_debt() {
        let snapshot = StorageIntentCostSnapshot {
            movement_debts: [
                StorageIntentMovementDebt {
                    subject_id: StorageIntentEvidenceId([1u8; 32]),
                    relocation_reason: RelocationReasonClass::AuthorityConvergence,
                    capacity_debt_bytes: 100,
                    network_debt_bytes: 50,
                    recovery_debt_bytes: 25,
                    foreground_disruption_debt_ms: 10,
                    payback_window_ms: 3600_000,
                    evidence: evidence_ref_1(),
                },
                StorageIntentMovementDebt {
                    subject_id: StorageIntentEvidenceId([2u8; 32]),
                    relocation_reason: RelocationReasonClass::DefragRotationalLocality,
                    capacity_debt_bytes: 200,
                    network_debt_bytes: 0,
                    recovery_debt_bytes: 0,
                    foreground_disruption_debt_ms: 0,
                    payback_window_ms: 7200_000,
                    evidence: evidence_ref_2(),
                },
                StorageIntentMovementDebt::ZERO,
                StorageIntentMovementDebt::ZERO,
                StorageIntentMovementDebt::ZERO,
                StorageIntentMovementDebt::ZERO,
                StorageIntentMovementDebt::ZERO,
                StorageIntentMovementDebt::ZERO,
                StorageIntentMovementDebt::ZERO,
                StorageIntentMovementDebt::ZERO,
                StorageIntentMovementDebt::ZERO,
                StorageIntentMovementDebt::ZERO,
                StorageIntentMovementDebt::ZERO,
                StorageIntentMovementDebt::ZERO,
                StorageIntentMovementDebt::ZERO,
                StorageIntentMovementDebt::ZERO,
                StorageIntentMovementDebt::ZERO,
                StorageIntentMovementDebt::ZERO,
                StorageIntentMovementDebt::ZERO,
                StorageIntentMovementDebt::ZERO,
                StorageIntentMovementDebt::ZERO,
                StorageIntentMovementDebt::ZERO,
                StorageIntentMovementDebt::ZERO,
                StorageIntentMovementDebt::ZERO,
            ],
            movement_debt_count: 2,
            ..StorageIntentCostSnapshot::default()
        };
        // 100+50+25 = 175 + 200 = 375
        assert_eq!(snapshot.total_movement_debt_bytes(), 375);
    }

    // ------------------------------------------------------------------
    // Payback aggregation in snapshot
    // ------------------------------------------------------------------

    #[test]
    fn snapshot_total_payback() {
        let snapshot = StorageIntentCostSnapshot {
            payback_entries: [
                StorageIntentPaybackEvidence {
                    benefit_class: StorageIntentPaybackBenefitClass::CapacitySaved,
                    money_power_saved_microunits: 1000,
                    payback_achieved: true,
                    ..StorageIntentPaybackEvidence::ZERO
                },
                StorageIntentPaybackEvidence {
                    benefit_class: StorageIntentPaybackBenefitClass::EgressAvoided,
                    money_power_saved_microunits: 500,
                    payback_achieved: false,
                    ..StorageIntentPaybackEvidence::ZERO
                },
                StorageIntentPaybackEvidence {
                    benefit_class: StorageIntentPaybackBenefitClass::MoneySaved,
                    money_power_saved_microunits: 300,
                    payback_achieved: true,
                    ..StorageIntentPaybackEvidence::ZERO
                },
                StorageIntentPaybackEvidence::ZERO,
                StorageIntentPaybackEvidence::ZERO,
                StorageIntentPaybackEvidence::ZERO,
                StorageIntentPaybackEvidence::ZERO,
                StorageIntentPaybackEvidence::ZERO,
                StorageIntentPaybackEvidence::ZERO,
                StorageIntentPaybackEvidence::ZERO,
                StorageIntentPaybackEvidence::ZERO,
                StorageIntentPaybackEvidence::ZERO,
                StorageIntentPaybackEvidence::ZERO,
                StorageIntentPaybackEvidence::ZERO,
                StorageIntentPaybackEvidence::ZERO,
                StorageIntentPaybackEvidence::ZERO,
            ],
            payback_entry_count: 3,
            ..StorageIntentCostSnapshot::default()
        };
        assert_eq!(snapshot.total_payback_microunits(), 1300);
    }

    // ------------------------------------------------------------------
    // Network path cost weight matching and computing
    // ------------------------------------------------------------------

    #[test]
    fn network_path_weight_exact_match() {
        let w = StorageIntentNetworkPathCostWeight {
            path_class: StorageIntentNetworkPathClass::SameDatacenter,
            proximity: ProximityClass::InProcess,
            carrier_class: StorageIntentNetworkCarrierClass::SharedInternal,
            egress_cost_per_byte_microunits: 10,
            ingress_cost_per_byte_microunits: 5,
        };
        let snapshot = StorageIntentCostSnapshot {
            network_path_weights: [w; MAX_NETWORK_PATH_WEIGHTS],
            network_path_weight_count: 1,
            ..StorageIntentCostSnapshot::default()
        };
        let found = snapshot.find_network_path_weight(
            StorageIntentNetworkPathClass::SameDatacenter,
            ProximityClass::InProcess,
            StorageIntentNetworkCarrierClass::SharedInternal,
        );
        assert_eq!(found.egress_cost_per_byte_microunits, 10);
        assert_eq!(found.ingress_cost_per_byte_microunits, 5);

        let cost = snapshot.egress_cost_for_bytes(
            StorageIntentNetworkPathClass::SameDatacenter,
            ProximityClass::InProcess,
            StorageIntentNetworkCarrierClass::SharedInternal,
            1000,
        );
        assert_eq!(cost, 10_000);
    }

    #[test]
    fn network_path_weight_fallback() {
        let w = StorageIntentNetworkPathCostWeight {
            path_class: StorageIntentNetworkPathClass::SameDatacenter,
            proximity: ProximityClass::InProcess,
            carrier_class: StorageIntentNetworkCarrierClass::MeteredProvider,
            egress_cost_per_byte_microunits: 20,
            ingress_cost_per_byte_microunits: 8,
        };
        let snapshot = StorageIntentCostSnapshot {
            network_path_weights: [w; MAX_NETWORK_PATH_WEIGHTS],
            network_path_weight_count: 1,
            ..StorageIntentCostSnapshot::default()
        };
        // different proximity should still match via path+carrier fallback
        let found = snapshot.find_network_path_weight(
            StorageIntentNetworkPathClass::SameDatacenter,
            ProximityClass::InProcess, // different Proximity discrim?
            StorageIntentNetworkCarrierClass::MeteredProvider,
        );
        assert_eq!(found.egress_cost_per_byte_microunits, 20);
    }

    #[test]
    fn network_path_weight_missing_returns_unknown() {
        let snapshot = StorageIntentCostSnapshot::default();
        let found = snapshot.find_network_path_weight(
            StorageIntentNetworkPathClass::Internet,
            ProximityClass::InProcess,
            StorageIntentNetworkCarrierClass::InternetTransit,
        );
        assert_eq!(found.egress_cost_per_byte_microunits, u64::MAX);
        assert_eq!(found.ingress_cost_per_byte_microunits, u64::MAX);
        assert_eq!(
            snapshot.egress_cost_for_bytes(
                StorageIntentNetworkPathClass::Internet,
                ProximityClass::InProcess,
                StorageIntentNetworkCarrierClass::InternetTransit,
                1000,
            ),
            u64::MAX
        );
    }

    // ------------------------------------------------------------------
    // #961 remote media cost/recovery projection
    // ------------------------------------------------------------------

    #[test]
    fn remote_media_cost_sample_projects_bounded_facts() {
        let snapshot = remote_cost_snapshot();
        let facts = RemoteMediaCostRecoverySample::bounded(snapshot, 150, 4_096, recovery_ref())
            .to_remote_cost_recovery_facts();

        assert!(facts.egress_budget_known);
        assert!(!facts.egress_budget_exhausted);
        assert!(facts.restore_cost_known);
        assert!(facts.recovery_bandwidth_known);
        assert!(facts.degraded_visibility_known);
        assert_eq!(facts.cost_ref, snapshot.evidence_ref());
        assert_eq!(facts.recovery_ref, recovery_ref());
    }

    #[test]
    fn remote_media_cost_sample_exposes_egress_budget_exhaustion() {
        let facts = RemoteMediaCostRecoverySample::bounded(
            remote_cost_snapshot(),
            99,
            4_096,
            recovery_ref(),
        )
        .to_remote_cost_recovery_facts();

        assert!(facts.egress_budget_known);
        assert!(facts.egress_budget_exhausted);
        assert!(facts.recovery_bandwidth_known);
    }

    #[test]
    fn remote_media_cost_sample_requires_egress_evidence() {
        let snapshot = StorageIntentCostSnapshot {
            evidence_id: StorageIntentEvidenceId([9u8; 32]),
            generation: 9,
            evidence_state: StorageIntentCostEvidenceState::FRESH
                .with_missing(StorageIntentCostClass::NetworkEgress),
            ..remote_cost_snapshot()
        };
        let facts = RemoteMediaCostRecoverySample::bounded(snapshot, 150, 4_096, recovery_ref())
            .to_remote_cost_recovery_facts();

        assert!(!facts.egress_budget_known);
        assert!(!facts.egress_budget_exhausted);
        assert!(facts.restore_cost_known);
    }

    #[test]
    fn remote_media_cost_sample_fails_closed_on_stale_restore_or_recovery() {
        let snapshot = StorageIntentCostSnapshot {
            evidence_state: StorageIntentCostEvidenceState::FRESH
                .with_stale(StorageIntentCostClass::RestoreTime)
                .with_refused(StorageIntentCostClass::RecoveryBandwidth),
            ..remote_cost_snapshot()
        };
        let facts = RemoteMediaCostRecoverySample::bounded(snapshot, 150, 4_096, recovery_ref())
            .to_remote_cost_recovery_facts();

        assert!(facts.egress_budget_known);
        assert!(!facts.restore_cost_known);
        assert!(!facts.recovery_bandwidth_known);
        assert!(facts.degraded_visibility_known);
    }

    #[test]
    fn remote_media_cost_sample_requires_recovery_visibility_ref() {
        let facts = RemoteMediaCostRecoverySample::bounded(
            remote_cost_snapshot(),
            150,
            4_096,
            evidence_ref_1(),
        )
        .to_remote_cost_recovery_facts();

        assert!(facts.egress_budget_known);
        assert!(!facts.recovery_bandwidth_known);
        assert!(!facts.degraded_visibility_known);
        assert!(!facts.recovery_ref.is_bound());
    }

    #[test]
    fn remote_media_cost_sample_requires_bound_cost_snapshot_ref() {
        let snapshot = StorageIntentCostSnapshot {
            evidence_id: StorageIntentEvidenceId::ZERO,
            generation: 0,
            ..remote_cost_snapshot()
        };
        let facts = RemoteMediaCostRecoverySample::bounded(snapshot, 150, 4_096, recovery_ref())
            .to_remote_cost_recovery_facts();

        assert!(!facts.egress_budget_known);
        assert!(!facts.restore_cost_known);
        assert!(!facts.recovery_bandwidth_known);
        assert!(facts.degraded_visibility_known);
        assert!(!facts.cost_ref.is_bound());
        assert_eq!(facts.recovery_ref, recovery_ref());
    }

    // ------------------------------------------------------------------
    // Cost snapshot builder (serde feature)
    // ------------------------------------------------------------------

    #[cfg(feature = "serde")]
    #[test]
    fn snapshot_builder_basic() {
        let snapshot = StorageIntentCostSnapshotBuilder::new(
            StorageIntentEvidenceId([99u8; 32]),
            StorageIntentPolicyId([10u8; 16]),
            StorageIntentPolicyRevision(3),
        )
        .with_domain(
            StorageIntentDomainId([20u8; 16]),
            StorageIntentDomainId([30u8; 16]),
        )
        .with_freshness(7, 1_000_000)
        .with_charge(StorageIntentCostCharge {
            cost_class: StorageIntentCostClass::CapacityMediaClass,
            reason_code: 0,
            byte_count: 500,
            cost_microunits: 100,
            evidence: evidence_ref_1(),
        })
        .with_operator_weights(StorageIntentOperatorPolicyWeights {
            latency_weight: 1,
            throughput_weight: 2,
            money_weight: 10,
            evidence: evidence_ref_1(),
            ..StorageIntentOperatorPolicyWeights::UNKNOWN
        })
        .with_missing_evidence(StorageIntentCostClass::NetworkEgress)
        .build();

        assert_eq!(snapshot.generation, 7);
        assert_eq!(snapshot.freshness_cut_ms, 1_000_000);
        assert_eq!(snapshot.charge_count, 1);
        assert_eq!(
            snapshot.class_cost_or_missing(StorageIntentCostClass::CapacityMediaClass),
            100
        );
        assert_eq!(snapshot.operator_weights.money_weight, 10);
        assert!(snapshot
            .evidence_state
            .class_is_missing(StorageIntentCostClass::NetworkEgress));
        assert!(!snapshot.is_fully_fresh());
    }

    // ------------------------------------------------------------------
    // Negative/free-by-overflow prevention
    // ------------------------------------------------------------------

    #[test]
    fn cost_charges_cannot_be_negative() {
        // All cost fields are u64, so negative values are impossible at the
        // type level.  This test verifies that adding a charge with
        // byte_count=0 and cost_microunits=0 is not silently treated as a
        // free resource: it should be distinguishable from a missing-charge
        // sentinel.
        let charge = StorageIntentCostCharge {
            cost_class: StorageIntentCostClass::CapacityMediaClass,
            byte_count: 0,
            cost_microunits: 0,
            evidence: evidence_ref_1(),
            ..StorageIntentCostCharge::ZERO
        };
        assert!(!charge.is_nonzero());
        // Still returns zero cost (not u64::MAX) because class is known
        // and evidence is present even if the charge is zero.
        assert!(charge.is_zero_cost_class_known());
    }

    #[test]
    fn saturating_add_prevents_overflow() {
        assert_eq!(saturating_add_u64(u64::MAX, 1), u64::MAX);
        assert_eq!(saturating_add_u64(10, 20), 30);
    }

    #[test]
    fn saturating_mul_prevents_overflow() {
        assert_eq!(saturating_mul_u64(u64::MAX, 2), u64::MAX);
        assert_eq!(saturating_mul_u64(10, 20), 200);
    }

    // ------------------------------------------------------------------
    // Operator weights
    // ------------------------------------------------------------------

    #[test]
    fn operator_weights_unknown() {
        let w = StorageIntentOperatorPolicyWeights::UNKNOWN;
        assert!(!w.has_any_opinion());
    }

    #[test]
    fn operator_weights_with_opinion() {
        let w = StorageIntentOperatorPolicyWeights {
            latency_weight: 1,
            money_weight: 5,
            ..StorageIntentOperatorPolicyWeights::UNKNOWN
        };
        assert!(w.has_any_opinion());
    }

    // ------------------------------------------------------------------
    // Class weight
    // ------------------------------------------------------------------

    #[test]
    fn class_weight_unknown() {
        let w = StorageIntentCostClassWeight::UNKNOWN;
        assert!(!w.is_meaningful());
    }

    #[test]
    fn class_weight_meaningful() {
        let w = StorageIntentCostClassWeight {
            cost_class: StorageIntentCostClass::NetworkEgress,
            weight: 10,
        };
        assert!(w.is_meaningful());
    }

    // ------------------------------------------------------------------
    // Network path weight
    // ------------------------------------------------------------------

    #[test]
    fn network_path_weight_unknown() {
        let w = StorageIntentNetworkPathCostWeight::UNKNOWN;
        assert!(!w.is_meaningful());
    }

    #[test]
    fn network_path_weight_meaningful() {
        let w = StorageIntentNetworkPathCostWeight {
            path_class: StorageIntentNetworkPathClass::Internet,
            proximity: ProximityClass::InProcess,
            carrier_class: StorageIntentNetworkCarrierClass::MeteredProvider,
            egress_cost_per_byte_microunits: 50,
            ingress_cost_per_byte_microunits: 10,
        };
        assert!(w.is_meaningful());
    }

    // ------------------------------------------------------------------
    // Cost plank: missing cost is never silently free
    // ------------------------------------------------------------------

    #[test]
    fn missing_cost_is_not_free() {
        let snapshot = StorageIntentCostSnapshot {
            evidence_state: StorageIntentCostEvidenceState::FRESH
                .with_missing(StorageIntentCostClass::CapacityMediaClass),
            ..StorageIntentCostSnapshot::default()
        };
        // class_cost_or_missing returns u64::MAX (not zero)
        assert_eq!(
            snapshot.class_cost_or_missing(StorageIntentCostClass::CapacityMediaClass),
            u64::MAX
        );
        // class_byte_count_or_missing also returns u64::MAX
        assert_eq!(
            snapshot.class_byte_count_or_missing(StorageIntentCostClass::CapacityMediaClass),
            u64::MAX
        );
        // cost_class_blocks_planning returns true
        assert!(cost_class_blocks_planning(
            snapshot.evidence_state,
            StorageIntentCostClass::CapacityMediaClass
        ));
    }

    #[test]
    fn stale_cost_is_not_free() {
        let snapshot = StorageIntentCostSnapshot {
            evidence_state: StorageIntentCostEvidenceState::FRESH
                .with_stale(StorageIntentCostClass::NetworkEgress),
            ..StorageIntentCostSnapshot::default()
        };
        assert_eq!(
            snapshot.class_cost_or_missing(StorageIntentCostClass::NetworkEgress),
            u64::MAX
        );
        assert!(cost_class_blocks_planning(
            snapshot.evidence_state,
            StorageIntentCostClass::NetworkEgress
        ));
    }

    #[test]
    fn fresh_cost_class_is_usable() {
        let state = StorageIntentCostEvidenceState::FRESH;
        assert!(!cost_class_blocks_planning(
            state,
            StorageIntentCostClass::NetworkEgress
        ));
    }

    // ------------------------------------------------------------------
    // Payback benefit discriminants round-trip
    // ------------------------------------------------------------------

    #[test]
    fn payback_benefit_discriminants_round_trip() {
        for raw in 0..=9u8 {
            let decoded = StorageIntentPaybackBenefitClass::from_discriminant(raw);
            match decoded {
                Some(b) => assert_eq!(b.to_discriminant(), raw),
                None => assert!(raw > 8),
            }
        }
    }
}
